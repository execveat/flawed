"""Tests for SARIF 2.1.0 output (FLAW-146) and the --fail-on exit contract (FLAW-147).

SARIF must be COMPLETE regardless of severity filtering (the trivy footgun);
the exit code must be governed by --fail-on independently of what is displayed.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from flawed._cli.output import Console, build_sarif_log
from flawed._cli.pipeline import (
    EXIT_FINDINGS,
    EXIT_OK,
    EXIT_TIMEOUT,
    scan_exit_code,
)
from flawed._cli.rules import RuleFinding
from flawed.core import Location
from flawed.evidence import Finding
from flawed.severity import Severity


def _rf(
    rule_id: str,
    *,
    severity: Severity,
    file: str | None = "app/views.py",
    line: int = 10,
    col: int = 4,
) -> RuleFinding:
    location = (
        Location(file=file, line=line, column=col, end_line=line, end_column=col + 5)
        if file is not None
        else None
    )
    return RuleFinding(
        rule_id=rule_id,
        rule_path=Path(f"{rule_id}.py"),
        finding=Finding(
            route_endpoint="ep",
            summary=f"summary for {rule_id}",
            location=location,
            severity=severity,
        ),
    )


# ── SARIF structure & completeness (FLAW-146) ─────────────────────


def test_sarif_top_level_shape() -> None:
    log = build_sarif_log((_rf("demo-rule", severity=Severity.HIGH),))
    assert log["version"] == "2.1.0"
    assert "$schema" in log
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "flawed"
    assert isinstance(driver["version"], str)
    assert driver["rules"], "tool.driver.rules must list the rules"


def test_sarif_rule_and_result_levels_map_from_severity() -> None:
    findings = (
        _rf("crit", severity=Severity.CRITICAL),
        _rf("med", severity=Severity.MEDIUM),
        _rf("low", severity=Severity.LOW),
    )
    log = build_sarif_log(findings)
    rules = {r["id"]: r for r in log["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["crit"]["defaultConfiguration"]["level"] == "error"
    assert rules["med"]["defaultConfiguration"]["level"] == "warning"
    assert rules["low"]["defaultConfiguration"]["level"] == "note"
    results = {r["ruleId"]: r for r in log["runs"][0]["results"]}
    assert results["crit"]["level"] == "error"
    assert results["low"]["level"] == "note"


def test_sarif_result_has_location_and_fingerprint() -> None:
    (result,) = build_sarif_log((_rf("r1", severity=Severity.HIGH, line=42, col=7),))["runs"][0][
        "results"
    ]
    phys = result["locations"][0]["physicalLocation"]
    assert phys["artifactLocation"]["uri"] == "app/views.py"
    assert phys["region"]["startLine"] == 42
    assert phys["region"]["startColumn"] == 7
    assert result["partialFingerprints"], "results must carry a stable fingerprint"


def test_sarif_ruleindex_points_at_the_rule() -> None:
    log = build_sarif_log((_rf("a", severity=Severity.HIGH), _rf("b", severity=Severity.LOW)))
    rules = log["runs"][0]["tool"]["driver"]["rules"]
    for result in log["runs"][0]["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_sarif_is_complete_regardless_of_severity() -> None:
    # A low-severity finding must appear even though it is below any sane
    # --fail-on floor — SARIF is for the code-scanning backend, not the gate.
    findings = (
        _rf("crit", severity=Severity.CRITICAL),
        _rf("info", severity=Severity.INFO),
    )
    log = build_sarif_log(findings)
    assert {r["ruleId"] for r in log["runs"][0]["results"]} == {"crit", "info"}


def test_sarif_handles_missing_location() -> None:
    log = build_sarif_log((_rf("noloc", severity=Severity.HIGH, file=None),))
    assert log["runs"][0]["results"][0]["locations"] == []


def test_sarif_emitter_writes_only_sarif_to_stdout() -> None:
    out, err = io.StringIO(), io.StringIO()
    console = Console(color="never", sarif_mode=True, stdout=out, stderr=err)
    console.show_findings((_rf("r1", severity=Severity.HIGH),))
    payload = json.loads(out.getvalue())  # stdout is pure SARIF JSON
    assert payload["version"] == "2.1.0"


# ── Exit-code contract (FLAW-147) ─────────────────────────────────


def test_exit_zero_when_no_findings() -> None:
    assert scan_exit_code((), fail_on=Severity.MEDIUM) == EXIT_OK


def test_exit_one_when_finding_at_threshold() -> None:
    findings = (_rf("m", severity=Severity.MEDIUM),)
    assert scan_exit_code(findings, fail_on=Severity.MEDIUM) == EXIT_FINDINGS


def test_exit_zero_when_findings_below_threshold() -> None:
    findings = (_rf("low", severity=Severity.LOW),)
    assert scan_exit_code(findings, fail_on=Severity.MEDIUM) == EXIT_OK


def test_exit_one_only_above_threshold() -> None:
    findings = (_rf("h", severity=Severity.HIGH),)
    assert scan_exit_code(findings, fail_on=Severity.HIGH) == EXIT_FINDINGS
    assert scan_exit_code(findings, fail_on=Severity.CRITICAL) == EXIT_OK


def test_no_error_forces_success_even_with_critical() -> None:
    findings = (_rf("c", severity=Severity.CRITICAL),)
    assert scan_exit_code(findings, fail_on=Severity.MEDIUM, error=False) == EXIT_OK


def test_incomplete_scan_reports_timeout_not_clean() -> None:
    # No findings, but a layer timed out: must not read as a clean exit 0.
    assert scan_exit_code((), fail_on=Severity.MEDIUM, incomplete=True) == EXIT_TIMEOUT


def test_scan_without_target_exits_usage_through_main(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`flawed scan` with no TARGET must exit 2 through the real entry point.

    This guards a subtle bug: ``main()`` runs Click with
    ``standalone_mode=False``, which swallows ``ctx.exit()`` (it raises
    ``click.exceptions.Exit``, which Click catches and *returns*). The no-target
    path must use ``sys.exit`` so the usage code actually propagates — a
    CliRunner test (standalone_mode=True) cannot catch this regression.
    """
    import flawed._cli as cli_pkg

    monkeypatch.setattr("sys.argv", ["flawed", "scan"])
    with pytest.raises(SystemExit) as exc:
        cli_pkg.main()
    assert exc.value.code == 2
