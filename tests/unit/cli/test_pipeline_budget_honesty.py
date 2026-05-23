"""Pipeline honesty for the L2 memory budget (FLAW-345).

A value-flow construction that would OOM-kill the process must instead fail
CLOSED: the pipeline catches :class:`ValueFlowBudgetError` next to the layer
timeout and emits an ``incomplete: true`` machine document — never an
uncatchable kill that a batch harness reads as a clean zero.

Hermetic: L1 and L2 are stubbed, so no real index is built and no tool is
spawned. Mirrors ``tests/external/test_pipeline_honesty.py`` for the timeout
path, but lives in the default tier because this fail-closed guarantee is core.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

from flawed._cli import pipeline
from flawed._cli.output import Console
from flawed._cli.rules import RuleDetector, RuleEntry
from flawed._config.paths import RepoIdentity
from flawed._config.schema import ResolvedConfig, RuleConfig
from flawed._semantic._budget import ValueFlowBudgetError

if TYPE_CHECKING:
    import pytest


def _stub_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        pipeline,
        "discover_rule_files",
        lambda _config: (RuleEntry(name="x", path=Path("x.py")),),
    )
    monkeypatch.setattr(
        pipeline,
        "load_configured_detectors",
        lambda _config, _files: (
            RuleDetector(rule_id="x", path=Path("x.py"), function=lambda _repo: iter(())),
        ),
    )


def test_l2_memory_budget_emits_incomplete_json_not_oom_kill(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _stub_rules(monkeypatch)
    # L1 succeeds (clean stub index); L2 trips the construction memory budget.
    monkeypatch.setattr(pipeline, "run_index", lambda **_k: SimpleNamespace(errors=()))

    def _over_budget(**_kwargs: object) -> object:
        raise ValueFlowBudgetError(kind="resident-memory", observed=10**10, limit=10**9)

    monkeypatch.setattr(pipeline, "run_semantic", _over_budget)

    exit_code = pipeline.run_scan(
        identity=RepoIdentity(canonical="t", path=tmp_path, hash="cafef00d"),
        config=ResolvedConfig(rules=RuleConfig(paths=(Path("rules"),))),
        console=Console(json_mode=True),
        semantic=True,
        use_cache=False,
    )
    out = capsys.readouterr().out
    assert out.strip(), "budget-capped scan produced 0-byte JSON — fail-open masking findings"

    metadata = json.loads(out)["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["incomplete"] is True
    assert "L2" in metadata["budget_capped_layers"]
    # Memory cap is NOT a timeout — kept on a distinct, honest field.
    assert "L2" not in metadata["timed_out_layers"]
    assert exit_code == pipeline.EXIT_TIMEOUT
