"""Tests for the redesigned human findings output (FLAW-141/144/145/142).

Covers: severity-led sort order, file:line never truncated at narrow widths,
stdout/stderr discipline (findings -> stdout, headline/summary -> stderr),
colour control (--color / NO_COLOR / FORCE_COLOR), and the json
finding_count == len(findings) invariant when output is not truncated.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from flawed._cli._observability import ScanMetrics
from flawed._cli.output import Console
from flawed._cli.rules import RuleFinding
from flawed.core import Location
from flawed.evidence import Finding
from flawed.severity import Severity


def _rf(rule_id: str, *, severity: Severity, file: str, line: int, col: int = 0) -> RuleFinding:
    return RuleFinding(
        rule_id=rule_id,
        rule_path=Path(f"{rule_id}.py"),
        finding=Finding(
            route_endpoint="ep",
            summary=f"summary for {rule_id}",
            location=Location(file=file, line=line, column=col),
            severity=severity,
        ),
    )


def _console(
    *, color: str = "never", width: int = 120, **kw: object
) -> tuple[Console, io.StringIO, io.StringIO]:
    out, err = io.StringIO(), io.StringIO()
    console = Console(color=color, stdout=out, stderr=err, width=width, **kw)  # type: ignore[arg-type]
    return console, out, err


def test_findings_sorted_worst_first() -> None:
    console, out, _err = _console()
    findings = (
        _rf("low-rule", severity=Severity.LOW, file="a.py", line=1),
        _rf("crit-rule", severity=Severity.CRITICAL, file="a.py", line=2),
        _rf("med-rule", severity=Severity.MEDIUM, file="a.py", line=3),
    )
    console.show_findings(findings)
    body = out.getvalue()
    # Worst-first within the file group.
    assert body.index("crit-rule") < body.index("med-rule") < body.index("low-rule")


def test_location_not_truncated_at_narrow_width() -> None:
    console, out, _err = _console(width=80)
    long_file = "deeply/nested/package/long_module_name/views.py"
    console.show_findings((_rf("r1", severity=Severity.HIGH, file=long_file, line=84, col=12),))
    body = out.getvalue()
    assert long_file in body  # file header intact, never "long_module…"
    assert ":84:12" in body  # line:col intact
    assert "…" not in body


def test_findings_go_to_stdout_headline_to_stderr() -> None:
    console, out, err = _console()
    console.show_findings((_rf("r1", severity=Severity.HIGH, file="a.py", line=1),))
    assert "r1" in out.getvalue()  # the finding itself -> stdout
    assert "a.py" in out.getvalue()
    assert "1 finding" in err.getvalue()  # headline -> stderr
    assert "r1" not in err.getvalue()


def test_severity_breakdown_in_headline() -> None:
    console, _out, err = _console()
    findings = (
        _rf("h", severity=Severity.HIGH, file="a.py", line=1),
        _rf("m1", severity=Severity.MEDIUM, file="a.py", line=2),
        _rf("m2", severity=Severity.MEDIUM, file="b.py", line=3),
    )
    console.show_findings(findings)
    head = err.getvalue()
    assert "3 findings" in head
    assert "1 high" in head
    assert "2 medium" in head


def test_action_footer_present() -> None:
    console, out, _err = _console()
    console.show_findings((_rf("demo-rule", severity=Severity.HIGH, file="a.py", line=1),))
    body = out.getvalue()
    assert "flawed explain demo-rule" in body
    assert "flawed: ignore[demo-rule]" in body


def test_no_findings_reports_clean() -> None:
    console, out, err = _console()
    console.show_findings(())
    assert out.getvalue().strip() == ""  # clean stdout for `> out.txt`
    assert "No findings" in err.getvalue()


def test_color_never_strips_ansi() -> None:
    console, out, _err = _console(color="never")
    console.show_findings((_rf("r1", severity=Severity.CRITICAL, file="a.py", line=1),))
    assert "\x1b[" not in out.getvalue()


def test_color_always_emits_ansi_into_pipe() -> None:
    # StringIO is not a TTY; --color=always must still emit ANSI.
    console, out, _err = _console(color="always")
    console.show_findings((_rf("r1", severity=Severity.CRITICAL, file="a.py", line=1),))
    assert "\x1b[" in out.getvalue()


def test_no_color_env_forces_plain(monkeypatch: object) -> None:
    import os

    os.environ["NO_COLOR"] = "1"
    try:
        console, out, _err = _console(color="auto")
        console.show_findings((_rf("r1", severity=Severity.CRITICAL, file="a.py", line=1),))
        assert "\x1b[" not in out.getvalue()
    finally:
        del os.environ["NO_COLOR"]


def test_json_finding_count_equals_len_when_not_truncated() -> None:
    out, err = io.StringIO(), io.StringIO()
    console = Console(json_mode=True, stdout=out, stderr=err)
    metrics = ScanMetrics(finding_count=455, retained_finding_count=449, findings_truncated=False)
    findings = tuple(
        _rf(f"r{i}", severity=Severity.MEDIUM, file="a.py", line=i) for i in range(449)
    )
    console.show_findings(findings, metrics=metrics)
    payload = json.loads(out.getvalue())
    assert payload["finding_count"] == len(payload["findings"]) == 449


def test_json_finding_count_preserves_total_when_truncated() -> None:
    out, err = io.StringIO(), io.StringIO()
    console = Console(json_mode=True, stdout=out, stderr=err)
    metrics = ScanMetrics(finding_count=5, retained_finding_count=3, findings_truncated=True)
    findings = tuple(_rf(f"r{i}", severity=Severity.LOW, file="a.py", line=i) for i in range(3))
    console.show_findings(findings, metrics=metrics)
    payload = json.loads(out.getvalue())
    assert payload["finding_count"] == 5  # total detected, pre-truncation
    assert len(payload["findings"]) == 3
