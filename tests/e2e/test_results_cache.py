"""End-to-end results-cache behaviour through the ``flawed scan`` CLI (FLAW-137).

Uses the fake-L1/L2 harness so only the real L3 detectors execute against the
``flask_basic`` semantic fixture.  ``iter_detector_findings`` is spied to count
how many detectors actually *ran* (a cache hit must not call it).
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING

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


def _install_harness(monkeypatch: pytest.MonkeyPatch, repo_view: RepoView) -> list[str]:
    """Fake L1/L2, spy L3 dispatch; return a list that records each detector run."""
    runs: list[str] = []
    real_iter = iter_detector_findings

    def spy(repo: object, detector: object) -> Iterator[object]:
        runs.append(getattr(detector, "rule_id", "?"))
        return real_iter(repo, detector)  # type: ignore[arg-type]

    def fake_run_index(**_k: object) -> object:
        # run_scan reads index.errors (to surface L1 gaps in metrics); honour
        # that part of the CodeIndex contract rather than a bare object().
        return SimpleNamespace(errors=())

    def fake_run_semantic(**_k: object) -> pipeline.SemanticResult:
        return pipeline.SemanticResult(repo_view=repo_view, active_provider_ids=("flask",))

    monkeypatch.setattr(cli_app, "RepoLock", _NoopLock)
    monkeypatch.setattr(pipeline, "run_index", fake_run_index)
    monkeypatch.setattr(pipeline, "run_semantic", fake_run_semantic)
    monkeypatch.setattr(pipeline, "iter_detector_findings", spy)
    return runs


def _scan(target: Path, data_dir: Path, *extra: str) -> Result:
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
            *extra,
        ],
    )


@pytest.fixture
def target(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    return repo


@pytest.mark.slow
def test_unchanged_rerun_is_served_from_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flask_basic: RepoView, target: Path
) -> None:
    runs = _install_harness(monkeypatch, flask_basic)
    data_dir = tmp_path / "data"

    first = _scan(target, data_dir)
    assert first.exit_code == 1, first.output
    first_payload = json.loads(first.stdout)
    assert first_payload["finding_count"] > 0
    ran_first = len(runs)
    assert ran_first > 0

    runs.clear()
    second = _scan(target, data_dir)
    assert second.exit_code == 1, second.output
    second_payload = json.loads(second.stdout)

    # No detector executed on the second run — every result came from cache.
    assert runs == [], f"expected full cache hit, but these ran: {runs}"
    # And the rendered findings are byte-identical.
    assert second_payload["findings"] == first_payload["findings"]
    assert second_payload["finding_count"] == first_payload["finding_count"]


@pytest.mark.slow
def test_subset_rerun_hits_cache_for_shared_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flask_basic: RepoView, target: Path
) -> None:
    runs = _install_harness(monkeypatch, flask_basic)
    data_dir = tmp_path / "data"

    first = _scan(target, data_dir)
    assert first.exit_code == 1, first.output
    ran = set(runs)
    assert ran, "first run should have executed detectors"
    one = next(iter(sorted(ran)))

    runs.clear()
    subset = _scan(target, data_dir, "--include", one)
    assert subset.exit_code in (0, 1), subset.output
    assert runs == [], f"subset of a cached run should hit cache, but ran: {runs}"


@pytest.mark.slow
def test_no_cache_recomputes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flask_basic: RepoView, target: Path
) -> None:
    runs = _install_harness(monkeypatch, flask_basic)
    data_dir = tmp_path / "data"

    _scan(target, data_dir, "--no-cache")
    first = list(runs)
    assert first
    runs.clear()
    _scan(target, data_dir, "--no-cache")
    assert sorted(runs) == sorted(first), "--no-cache must recompute every run"


@pytest.mark.slow
def test_refresh_recomputes_then_repopulates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flask_basic: RepoView, target: Path
) -> None:
    runs = _install_harness(monkeypatch, flask_basic)
    data_dir = tmp_path / "data"

    _scan(target, data_dir)  # populate
    runs.clear()
    _scan(target, data_dir, "--refresh")  # ignore cache, recompute
    assert runs, "--refresh must recompute"
    runs.clear()
    _scan(target, data_dir)  # repopulated -> hit
    assert runs == [], "after --refresh the cache should be repopulated"


@pytest.mark.slow
def test_target_change_invalidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flask_basic: RepoView, target: Path
) -> None:
    runs = _install_harness(monkeypatch, flask_basic)
    data_dir = tmp_path / "data"

    _scan(target, data_dir)
    runs.clear()
    (target / "new.py").write_text("z = 3\n", encoding="utf-8")  # mutate target content
    _scan(target, data_dir)
    assert runs, "a changed target must invalidate the results cache"


@pytest.mark.slow
def test_cache_clear_forces_recompute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flask_basic: RepoView, target: Path
) -> None:
    runs = _install_harness(monkeypatch, flask_basic)
    data_dir = tmp_path / "data"

    _scan(target, data_dir)
    status = CliRunner().invoke(cli, ["cache", "status", str(target), "--data-dir", str(data_dir)])
    assert status.exit_code == 0, status.output

    cleared = CliRunner().invoke(cli, ["cache", "clear", str(target), "--data-dir", str(data_dir)])
    assert cleared.exit_code == 0, cleared.output

    runs.clear()
    _scan(target, data_dir)
    assert runs, "after `cache clear`, the next scan must recompute"
