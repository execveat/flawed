"""End-to-end: every scan writes a durable observability record (FLAW-355).

Uses the fake-L1/L2 harness (only real L3 runs) so the test is fast and
subprocess-free.  Proves the two sinks are written and — crucially — that a warm
re-run whose findings are fully served from cache still records ``L2``/``L3``
phases flagged ``served_from_cache``.  This warm-path capture is exactly what
``--profile`` cannot do (it disables the results-cache fast path), so it is the
reason the always-on record exists.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest
from click.testing import CliRunner

import flawed._cli.app as cli_app
from flawed._cli import pipeline
from flawed._cli.app import cli
from flawed._cli.rules import iter_detector_findings

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from click.testing import Result

    from flawed.repo import RepoView

DEMO_RULES = "src/flawed/_rules"


class _NoopLock:
    def __init__(self, *_a: object, **_k: object) -> None: ...
    def __enter__(self) -> _NoopLock:
        return self

    def __exit__(self, *_e: object) -> None:
        return None


def _install_harness(monkeypatch: pytest.MonkeyPatch, repo_view: RepoView) -> None:
    def spy(repo: object, detector: object) -> Iterator[object]:
        return iter_detector_findings(repo, detector)  # type: ignore[arg-type]

    def fake_run_index(**_k: object) -> object:
        return SimpleNamespace(errors=())

    def fake_run_semantic(**_k: object) -> pipeline.SemanticResult:
        return pipeline.SemanticResult(repo_view=repo_view, active_provider_ids=("flask",))

    monkeypatch.setattr(cli_app, "RepoLock", _NoopLock)
    monkeypatch.setattr(pipeline, "run_index", fake_run_index)
    monkeypatch.setattr(pipeline, "run_semantic", fake_run_semantic)
    monkeypatch.setattr(pipeline, "iter_detector_findings", spy)


def _scan(target: Path, data_dir: Path) -> Result:
    return CliRunner().invoke(
        cli,
        [
            "scan",
            str(target),
            "--semantic",
            "--rules-dir",
            DEMO_RULES,
            "--output-format",
            "json",
            "--fail-on",
            "info",
            "--data-dir",
            str(data_dir),
        ],
    )


def _last_record(jsonl_path: Path) -> dict[str, Any]:
    lines = [ln for ln in jsonl_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return json.loads(lines[-1])


@pytest.mark.slow
def test_scan_writes_both_sinks_and_captures_warm_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flask_basic: RepoView
) -> None:
    _install_harness(monkeypatch, flask_basic)
    data_dir = tmp_path / "data"
    target = tmp_path / "repo"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n", encoding="utf-8")

    # -- Cold run: both sinks written, L3 executed (not cache-served). ----------
    first = _scan(target, data_dir)
    assert first.exit_code in (0, 1), first.output

    sidecars = list(data_dir.rglob("scan_metrics.jsonl"))
    assert sidecars, "cold scan must write a per-repo sidecar"
    central = list(tmp_path.rglob("runs.jsonl"))
    assert central, "cold scan must write the central run-log"

    cold = _last_record(sidecars[0])
    assert cold["schema_version"]
    assert cold["repo"] == "org/repo" or cold["repo"]  # display name present
    assert cold["flawed_version"]
    cold_phases = {p["name"]: p for p in cold["phases"]}
    assert "L3" in cold_phases
    assert cold_phases["L3"]["served_from_cache"] is False
    # The central log carries the same record shape.
    assert _last_record(central[0])["schema_version"] == cold["schema_version"]

    # -- Warm run: findings fully served from cache; L2/L3 still recorded. -------
    second = _scan(target, data_dir)
    assert second.exit_code in (0, 1), second.output

    warm = _last_record(sidecars[0])
    assert warm["cache"]["results_cache"] == "hit"
    warm_phases = {p["name"]: p for p in warm["phases"]}
    assert warm_phases["L2"]["served_from_cache"] is True
    assert warm_phases["L3"]["served_from_cache"] is True
