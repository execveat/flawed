from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import flawed._cli.app as cli_app
from flawed._cli import pipeline
from flawed._cli._observability import (
    OverallTimeoutError,
    ScanMetrics,
    layer_timeout,
    overall_timeout,
)
from flawed._cli.output import Console
from flawed._cli.rules import RuleDetector, RuleEntry, RuleFinding
from flawed._config.paths import RepoIdentity
from flawed._config.schema import ResolvedConfig, RuleConfig, TimeoutConfig
from flawed.evidence import Finding

if TYPE_CHECKING:
    from collections.abc import Iterator


def test_outer_deadline_wins_inside_longer_layer_timeout() -> None:
    with pytest.raises(OverallTimeoutError):
        _sleep_inside_nested_deadlines()


def _sleep_inside_nested_deadlines() -> None:
    with overall_timeout(0.02), layer_timeout("L1", 1):
        time.sleep(0.05)


def test_scan_overall_timeout_writes_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path = tmp_path / "scan-profile.json"

    class _NoopLock:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> _NoopLock:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

    def fake_load_config(**_kwargs: object) -> ResolvedConfig:
        return ResolvedConfig(timeouts=TimeoutConfig(overall=60))

    def fake_run_scan(**_kwargs: object) -> int:
        raise OverallTimeoutError(60)

    monkeypatch.setattr(cli_app, "RepoLock", _NoopLock)
    monkeypatch.setattr(cli_app, "load_config", fake_load_config)
    monkeypatch.setattr(cli_app, "run_scan", fake_run_scan)

    obj = cli_app._Ctx()  # type: ignore[attr-defined]
    # _do_scan now operates on an already-resolved repo path and *returns* the
    # exit code (the multi-target loop in scan_cmd owns the process exit), so a
    # timeout surfaces as a returned 124 rather than a raised SystemExit.
    exit_code = cli_app._do_scan(
        obj,
        repo_path=tmp_path,
        data_dir=None,
        rules_dirs=(),
        includes=(),
        include_regexes=(),
        excludes=(),
        exclude_regexes=(),
        force_providers=(),
        disable_providers=(),
        no_index=False,
        reindex=False,
        enable_mypy_batch=None,
        dry_run=False,
        semantic=True,
        profile_output=report_path,
        timeout_seconds=None,
        layer_timeout_seconds=None,
        rule_timeout_seconds=None,
        show_summary=False,
    )

    payload = json.loads(report_path.read_text(encoding="utf-8"))
    # FLAW-147: an overall-scan timeout exits 124 (GNU timeout), not the
    # generic usage code 2.
    assert exit_code == 124
    assert payload["status"] == "failed"
    assert payload["exit_code"] == 124
    assert payload["error"] == "Overall scan exceeded 60s timeout"


def test_l3_retains_bounded_findings_and_counts_actual_total(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Console:
        shown_metrics: ScanMetrics | None = None

        def status(self, _message: str) -> None:
            pass

        def warn(self, _message: str) -> None:
            pass

        def show_findings(
            self,
            _findings: tuple[object, ...],
            *,
            metrics: ScanMetrics | None = None,
        ) -> None:
            self.shown_metrics = metrics

    def noisy_detector(_repo: object) -> Iterator[Finding]:
        for index in range(5):
            yield Finding(route_endpoint="test", summary=f"finding {index}")

    monkeypatch.setattr(pipeline, "MAX_RETAINED_L3_FINDINGS", 3)
    monkeypatch.setattr(
        pipeline,
        "discover_rule_files",
        lambda _config: (RuleEntry(name="noisy", path=Path("noisy.py")),),
    )
    monkeypatch.setattr(
        pipeline,
        "load_configured_detectors",
        lambda _config, _rule_files: (
            RuleDetector(
                rule_id="noisy",
                path=Path("noisy.py"),
                function=noisy_detector,
            ),
        ),
    )

    metrics = ScanMetrics()
    findings = pipeline._run_l3_rules(
        object(),  # type: ignore[arg-type]
        config=ResolvedConfig(rules=RuleConfig(paths=(Path("rules"),))),
        console=_Console(),  # type: ignore[arg-type]
        metrics=metrics,
    )

    assert len(findings) == 3
    assert metrics.finding_count == 5
    assert metrics.retained_finding_count == 3
    assert metrics.findings_truncated is True


def test_empty_rule_set_fails_fast_before_indexing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # FLAW-123: rule resolution + filtering is pure config work, so an empty or
    # over-filtered rule set must short-circuit BEFORE L1 indexing and L2
    # semantic analysis — not after minutes of work that finds nothing.
    class _Console:
        def __init__(self) -> None:
            self.warned: list[str] = []

        def warn(self, message: str) -> None:
            self.warned.append(message)

        def show_scan_metrics(self, _metrics: object) -> None:
            pass

    def _fail_if_called(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("L1/L2 must not run when the resolved rule set is empty")

    monkeypatch.setattr(
        pipeline,
        "discover_rule_files",
        lambda _config: (RuleEntry(name="x", path=Path("x.py")),),
    )
    monkeypatch.setattr(pipeline, "load_configured_detectors", lambda _config, _files: ())
    monkeypatch.setattr(pipeline, "run_index", _fail_if_called)
    monkeypatch.setattr(pipeline, "run_semantic", _fail_if_called)

    console = _Console()
    exit_code = pipeline.run_scan(
        identity=RepoIdentity(canonical="t", path=tmp_path, hash="cafef00d"),
        config=ResolvedConfig(rules=RuleConfig(paths=(Path("rules"),))),
        console=console,  # type: ignore[arg-type]
        semantic=True,
    )

    assert exit_code == 0
    assert any("No detection rules matched" in message for message in console.warned)


def test_json_output_reports_truncation_metadata(capsys: pytest.CaptureFixture[str]) -> None:
    metrics = ScanMetrics(
        finding_count=5,
        retained_finding_count=3,
        findings_truncated=True,
    )
    retained = tuple(
        RuleFinding(
            rule_id="noisy",
            rule_path=Path("noisy.py"),
            finding=Finding(route_endpoint="test", summary=f"finding {index}"),
        )
        for index in range(3)
    )

    Console(json_mode=True).show_findings(retained, metrics=metrics)

    payload = json.loads(capsys.readouterr().out)
    assert payload["finding_count"] == 5
    assert payload["retained_finding_count"] == 3
    assert payload["findings_truncated"] is True
    assert payload["metadata"]["findings_truncated"] is True
