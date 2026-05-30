"""CLI scan pipeline coverage for executing the shipped demo rules."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest
from click.testing import CliRunner

import flawed._cli.app as cli_app
from flawed._cli import pipeline
from flawed._cli.app import cli

if TYPE_CHECKING:
    from pathlib import Path

    from flawed._cli.profile import ScanProfiler
    from flawed.repo import RepoView


@pytest.mark.parametrize(
    ("rule_id", "summary_fragment"),
    [
        ("endpoints", "POST /login"),
        ("value-flow", "reaches a db_write operation"),
    ],
)
@pytest.mark.slow
def test_scan_pipeline_runs_representative_demo_rules(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    flask_basic: RepoView,
    rule_id: str,
    summary_fragment: str,
) -> None:
    """Each shipped demo rule should run through scan, not only direct calls."""
    _patch_scan_prerequisites(monkeypatch, flask_basic)

    result = CliRunner().invoke(
        cli,
        [
            "scan",
            str(tmp_path),
            "--semantic",
            "--rules-dir",
            "src/flawed/_rules",
            "--include",
            rule_id,
            "--output-format",
            "json",
            # The demo rules declare INFO severity; --fail-on info makes
            # "any finding -> exit 1" explicit under the FLAW-147 threshold
            # contract.
            "--fail-on",
            "info",
        ],
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    matching = [finding for finding in payload["findings"] if finding["rule_id"] == rule_id]

    assert payload["finding_count"] >= 1
    assert matching, payload
    assert any(summary_fragment in finding["summary"] for finding in matching)
    assert all(finding["location"]["file"] for finding in matching)


def test_scan_help_shows_rule_pipeline_options() -> None:
    result = CliRunner().invoke(cli, ["scan", "-h"])

    assert result.exit_code == 0
    assert "--rules-dir" in result.output
    assert "--output-format" in result.output


@pytest.mark.slow
def test_scan_pipeline_default_rule_set_runs_without_rule_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    flask_basic: RepoView,
) -> None:
    """The default src/flawed/_rules tree should produce findings, not rule crashes."""
    _patch_scan_prerequisites(monkeypatch, flask_basic)

    result = CliRunner().invoke(
        cli,
        [
            "scan",
            str(tmp_path),
            "--semantic",
            "--output-format",
            "json",
            # The default demo rule set is INFO severity; --fail-on info keeps
            # the "finding present -> exit 1" contract explicit here.
            "--fail-on",
            "info",
        ],
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)

    assert payload["finding_count"] > 0
    assert len({finding["rule_id"] for finding in payload["findings"]}) > 1


@pytest.mark.slow
def test_scan_profile_writes_structured_report_without_replacing_findings_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    flask_basic: RepoView,
) -> None:
    """--profile should write scan telemetry while stdout remains finding JSON."""
    _patch_scan_prerequisites(monkeypatch, flask_basic)
    report_path = tmp_path / "scan-profile.json"

    result = CliRunner().invoke(
        cli,
        [
            "scan",
            str(tmp_path),
            "--semantic",
            "--rules-dir",
            "src/flawed/_rules",
            "--include",
            "endpoints",
            "--output-format",
            "json",
            "--profile",
            str(report_path),
            # The demo rules declare INFO severity; --fail-on info keeps the
            # "finding present -> exit 1" contract explicit here.
            "--fail-on",
            "info",
        ],
    )

    assert result.exit_code == 1, result.output
    findings_payload = json.loads(result.stdout)
    profile_payload = json.loads(report_path.read_text(encoding="utf-8"))

    assert findings_payload["finding_count"] >= 1
    assert profile_payload["schema_version"] == 1
    assert profile_payload["status"] == "completed"
    assert profile_payload["exit_code"] == 1
    assert profile_payload["options"]["semantic"] is True
    assert profile_payload["options"]["profile_tracemalloc"] is False
    assert profile_payload["profiling"]["tracemalloc_enabled"] is False
    assert {phase["name"] for phase in profile_payload["phases"]} >= {
        "l1_index",
        "l2_provider_engine",
        "l2_conversion",
        "l3_rules",
    }
    assert profile_payload["l2"]["route_count"] == len(flask_basic.routes)
    assert profile_payload["l2"]["active_providers"] == ["flask"]
    assert profile_payload["l3"]["finding_count"] == findings_payload["finding_count"]

    timing = findings_payload["metadata"]["timing"]
    assert timing["l1_extraction"] > 0
    assert timing["l2_semantic"] > 0
    assert timing["l3_rules"] > 0
    assert timing["total"] > 0
    assert timing["index_seconds"] == timing["l1_extraction"]
    assert timing["semantic_seconds"] == timing["l2_semantic"]


def _patch_scan_prerequisites(
    monkeypatch: pytest.MonkeyPatch,
    repo_view: RepoView,
) -> None:
    class _NoopLock:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> _NoopLock:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

    def fake_run_index(**_kwargs: object) -> object:
        # run_scan reads index.errors (to surface L1 gaps in metrics); honour
        # that part of the CodeIndex contract rather than a bare object().
        return SimpleNamespace(errors=())

    def fake_run_semantic(**_kwargs: object) -> pipeline.SemanticResult:
        profiler = cast("ScanProfiler | None", _kwargs.get("profiler"))
        if profiler is not None:
            with profiler.phase("l2_provider_engine") as phase:
                phase.set("active_providers", ["flask"])
                phase.set("match_count", 0)
                phase.set("gap_count", 0)
            with profiler.phase("l2_conversion") as phase:
                phase.set("route_count", len(repo_view.routes))
                phase.set("gap_count", len(repo_view.gaps))
        return pipeline.SemanticResult(
            repo_view=repo_view,
            active_provider_ids=("flask",),
        )

    monkeypatch.setattr(cli_app, "RepoLock", _NoopLock)
    monkeypatch.setattr(pipeline, "run_index", fake_run_index)
    monkeypatch.setattr(pipeline, "run_semantic", fake_run_semantic)
