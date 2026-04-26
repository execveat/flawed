"""Pipeline honesty: incomplete analysis must never read as a clean "no findings".

Two FN-safety guarantees (the no-fail-open prime directive):

* FLAW-264 — one unparsable file is gapped and recorded, but does NOT abort the
  whole repo. The repo-level abort keys off the explicit ``aborts_pipeline``
  flag, not the per-file ``is_fatal``.
* A Layer-1/Layer-2 timeout still emits the machine document (carrying
  ``incomplete: true``) so a ``--json``/``--sarif`` consumer can tell an
  incomplete scan from a clean one — never 0-byte output.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

from flawed._cli import pipeline
from flawed._cli._observability import LayerTimeoutError
from flawed._cli.output import Console
from flawed._cli.rules import RuleDetector, RuleEntry
from flawed._config.paths import RepoIdentity
from flawed._config.schema import ResolvedConfig, RuleConfig
from flawed._index._pipeline import build_index
from flawed._index._types import ErrorKind, ExtractionError

if TYPE_CHECKING:
    import pytest


# --------------------------------------------------------------------------- #
# FLAW-264 — a single unparsable file must not gap the whole repo
# --------------------------------------------------------------------------- #


def _write_three_file_repo(root: Path) -> None:
    (root / "valid_a.py").write_text("def alpha():\n    return 1\n", encoding="utf-8")
    (root / "broken.py").write_text("def (:\n    pass\n", encoding="utf-8")  # unparsable
    (root / "valid_b.py").write_text("def beta():\n    return 2\n", encoding="utf-8")


def test_one_unparsable_file_is_gapped_not_repo_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_three_file_repo(tmp_path)
    idx = build_index(tmp_path)

    # Both valid files were analyzed despite the broken sibling.
    names = {fn.name for fn in idx.functions}
    assert {"alpha", "beta"} <= names

    # The broken file is recorded as exactly one explicit, per-file PARSE gap.
    parse_gaps = [e for e in idx.errors if e.error_kind is ErrorKind.PARSE]
    assert len(parse_gaps) == 1
    gap = parse_gaps[0]
    assert gap.file.endswith("broken.py")
    assert gap.is_fatal is True  # still per-file fatal …
    assert gap.aborts_pipeline is False  # … but must NOT abort the repo

    # This is the exact predicate the pipeline uses to decide a repo-level abort
    # (pipeline.run_index): with only a per-file parse gap, nothing aborts.
    assert [e for e in idx.errors if e.aborts_pipeline] == []


def test_extraction_error_is_per_file_by_default() -> None:
    # A new error is per-file (non-aborting) unless a repo-wide failure opts in,
    # keeping "file gapped" and "repo dead" as two distinct explicit states.
    err = ExtractionError(
        file="x.py",
        pass_name="structural",
        error_kind=ErrorKind.PARSE,
        message="Syntax error",
        is_fatal=True,
        location=None,
    )
    assert err.aborts_pipeline is False


# --------------------------------------------------------------------------- #
# A layer timeout must emit an incomplete machine doc, never 0 bytes
# --------------------------------------------------------------------------- #
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


def _run_and_capture_json(
    *, console: Console, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> tuple[int, dict[str, object]]:
    exit_code = pipeline.run_scan(
        identity=RepoIdentity(canonical="t", path=tmp_path, hash="cafef00d"),
        config=ResolvedConfig(rules=RuleConfig(paths=(Path("rules"),))),
        console=console,
        semantic=True,
        use_cache=False,
    )
    out = capsys.readouterr().out
    assert out.strip(), "incomplete scan produced 0-byte JSON — fail-open masking findings"
    return exit_code, json.loads(out)


def test_l1_timeout_emits_incomplete_json_not_zero_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _stub_rules(monkeypatch)

    def _timeout(**_kwargs: object) -> object:
        raise LayerTimeoutError("L1", 1)

    monkeypatch.setattr(pipeline, "run_index", _timeout)

    exit_code, payload = _run_and_capture_json(
        console=Console(json_mode=True), capsys=capsys, tmp_path=tmp_path
    )
    metadata = payload["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["incomplete"] is True
    assert "L1" in metadata["timed_out_layers"]
    assert exit_code == pipeline.EXIT_TIMEOUT


def test_l2_timeout_emits_incomplete_json_not_zero_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _stub_rules(monkeypatch)

    # L1 succeeds (a clean stub index), then L2 times out.
    monkeypatch.setattr(pipeline, "run_index", lambda **_k: SimpleNamespace(errors=()))

    def _timeout(**_kwargs: object) -> object:
        raise LayerTimeoutError("L2", 1)

    monkeypatch.setattr(pipeline, "run_semantic", _timeout)

    exit_code, payload = _run_and_capture_json(
        console=Console(json_mode=True), capsys=capsys, tmp_path=tmp_path
    )
    metadata = payload["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["incomplete"] is True
    assert "L2" in metadata["timed_out_layers"]
    assert exit_code == pipeline.EXIT_TIMEOUT
