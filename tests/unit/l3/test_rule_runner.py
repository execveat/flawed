from __future__ import annotations

from typing import TYPE_CHECKING

from flawed.evidence import Finding
from tests.helpers import rule_runner

if TYPE_CHECKING:
    from pathlib import Path


def test_run_rule_reports_pass_with_findings(tmp_path: Path) -> None:
    rule_path = _write_rule(
        tmp_path,
        "passing_rule.py",
        """
from flawed import detector
from flawed.evidence import Finding

@detector("example-rule")
def detect(repo):
    yield Finding(route_endpoint="users", summary="found user route")
""".strip(),
    )

    result = rule_runner.run_rule(object(), rule_path)

    assert result.status is rule_runner.RuleStatus.PASS
    assert result.rule_name == "example-rule"
    assert [finding.summary for finding in result.findings] == ["found user route"]


def test_run_rule_reports_no_findings(tmp_path: Path) -> None:
    rule_path = _write_rule(
        tmp_path,
        "empty_rule.py",
        """
def detect(repo):
    return []
""".strip(),
    )

    result = rule_runner.run_rule(object(), rule_path)

    assert result.status is rule_runner.RuleStatus.NO_FINDINGS
    assert result.succeeded


def test_run_rule_reports_fail_for_contract_violation(tmp_path: Path) -> None:
    rule_path = _write_rule(
        tmp_path,
        "bad_rule.py",
        """
def detect(repo):
    yield "not a finding"
""".strip(),
    )

    result = rule_runner.run_rule(object(), rule_path)

    assert result.status is rule_runner.RuleStatus.FAIL
    assert result.message == "detect(repo) yielded non-Finding object(s): str"
    assert not result.succeeded


def test_run_rule_reports_error_for_runtime_exception(tmp_path: Path) -> None:
    rule_path = _write_rule(
        tmp_path,
        "error_rule.py",
        """
def detect(repo):
    raise RuntimeError("boom")
    yield
""".strip(),
    )

    result = rule_runner.run_rule(object(), rule_path)

    assert result.status is rule_runner.RuleStatus.ERROR
    assert result.message == "detect() iteration failed: boom"
    assert result.traceback_text is not None


def test_format_report_includes_summary_statuses(tmp_path: Path) -> None:
    report = rule_runner.format_report(
        [
            rule_runner.RuleResult(
                rule_path=tmp_path / "pass.py",
                rule_name="pass-rule",
                status=rule_runner.RuleStatus.PASS,
                findings=(Finding(route_endpoint="users", summary="found"),),
            ),
            rule_runner.RuleResult(
                rule_path=tmp_path / "empty.py",
                rule_name="empty-rule",
                status=rule_runner.RuleStatus.NO_FINDINGS,
            ),
        ],
    )

    assert "Rule runner: 1 pass, 1 no-findings, 0 fail, 0 error" in report
    assert "PASS pass-rule" in report
    assert "NO-FINDINGS empty-rule" in report
    assert "  - users: found" in report


def test_main_analyzes_fixture_once_and_returns_success_for_no_findings(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    fixture_path = tmp_path / "fixture"
    fixture_path.mkdir()
    rule_path = _write_rule(
        tmp_path,
        "empty_rule.py",
        """
def detect(repo):
    assert repo == "fake-repo"
    return []
""".strip(),
    )
    opened_paths: list[str] = []

    def fake_open_repo(path: str) -> str:
        opened_paths.append(path)
        return "fake-repo"

    monkeypatch.setattr(rule_runner, "open_repo", fake_open_repo)

    exit_code = rule_runner.main([str(fixture_path), str(rule_path)])

    assert exit_code == 0
    assert opened_paths == [str(fixture_path)]
    assert "Rule runner: 0 pass, 1 no-findings, 0 fail, 0 error" in capsys.readouterr().out


def _write_rule(tmp_path: Path, name: str, source: str) -> Path:
    rule_path = tmp_path / name
    rule_path.write_text(f"{source}\n")
    return rule_path
