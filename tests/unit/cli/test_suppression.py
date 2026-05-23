"""Tests for finding fingerprints, deduplication, and suppression."""

from __future__ import annotations

from pathlib import Path

from flawed._cli.rules import RuleFinding
from flawed._cli.suppression import (
    deduplicate_findings,
    load_baseline,
    suppress_findings,
    write_baseline,
)
from flawed.core import Location
from flawed.evidence import Finding


def _loc(file: str = "app.py", line: int = 1) -> Location:
    return Location(file=file, line=line, column=0, end_line=line, end_column=10)


class TestFindingFingerprint:
    def test_stable_across_calls(self) -> None:
        f = Finding(route_endpoint="index", summary="test finding", location=_loc())
        assert f.fingerprint == f.fingerprint

    def test_different_summary_different_fingerprint(self) -> None:
        f1 = Finding(route_endpoint="index", summary="finding A", location=_loc())
        f2 = Finding(route_endpoint="index", summary="finding B", location=_loc())
        assert f1.fingerprint != f2.fingerprint

    def test_different_endpoint_different_fingerprint(self) -> None:
        f1 = Finding(route_endpoint="login", summary="same", location=_loc())
        f2 = Finding(route_endpoint="logout", summary="same", location=_loc())
        assert f1.fingerprint != f2.fingerprint

    def test_fingerprint_length(self) -> None:
        f = Finding(route_endpoint="ep", summary="s", location=_loc())
        assert len(f.fingerprint) == 16


def _rule_finding(
    rule_id: str = "test-rule",
    endpoint: str = "index",
    summary: str = "test",
    file: str = "app.py",
    line: int = 1,
) -> RuleFinding:
    finding = Finding(
        route_endpoint=endpoint,
        summary=summary,
        location=_loc(file, line),
    )
    return RuleFinding(rule_id=rule_id, rule_path=Path("rules/test.py"), finding=finding)


class TestRuleFindingFingerprint:
    def test_includes_rule_id(self) -> None:
        rf1 = _rule_finding(rule_id="rule-a")
        rf2 = _rule_finding(rule_id="rule-b")
        assert rf1.fingerprint != rf2.fingerprint

    def test_stable(self) -> None:
        rf = _rule_finding()
        assert rf.fingerprint == rf.fingerprint


class TestDeduplication:
    def test_removes_duplicates(self) -> None:
        rf1 = _rule_finding(endpoint="login", summary="dup")
        rf2 = _rule_finding(endpoint="login", summary="dup")
        assert rf1.fingerprint == rf2.fingerprint
        result = deduplicate_findings([rf1, rf2])
        assert len(result) == 1

    def test_keeps_distinct(self) -> None:
        rf1 = _rule_finding(endpoint="login", summary="A")
        rf2 = _rule_finding(endpoint="login", summary="B")
        result = deduplicate_findings([rf1, rf2])
        assert len(result) == 2

    def test_preserves_first_occurrence(self) -> None:
        rf1 = _rule_finding(endpoint="x", summary="dup")
        rf2 = _rule_finding(endpoint="x", summary="dup")
        result = deduplicate_findings([rf1, rf2])
        assert result[0] is rf1

    def test_empty(self) -> None:
        assert deduplicate_findings([]) == ()


class TestBaseline:
    def test_write_and_load(self, tmp_path: Path) -> None:
        rf = _rule_finding()
        baseline_file = tmp_path / "baseline.json"
        write_baseline(baseline_file, [rf])
        suppressed = load_baseline(baseline_file)
        assert rf.fingerprint in suppressed

    def test_load_missing_file(self, tmp_path: Path) -> None:
        assert load_baseline(tmp_path / "nope.json") == frozenset()

    def test_load_invalid_json(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not json")
        assert load_baseline(bad) == frozenset()


class TestSuppression:
    def test_suppresses_matching(self) -> None:
        rf = _rule_finding()
        suppressed = frozenset({rf.fingerprint})
        result = suppress_findings([rf], suppressed)
        assert len(result) == 0

    def test_keeps_non_matching(self) -> None:
        rf = _rule_finding()
        suppressed = frozenset({"0000000000000000"})
        result = suppress_findings([rf], suppressed)
        assert len(result) == 1

    def test_round_trip_suppression(self, tmp_path: Path) -> None:
        rf1 = _rule_finding(endpoint="a", summary="keep")
        rf2 = _rule_finding(endpoint="b", summary="suppress")
        baseline_file = tmp_path / "baseline.json"
        write_baseline(baseline_file, [rf2])
        suppressed = load_baseline(baseline_file)
        result = suppress_findings([rf1, rf2], suppressed)
        assert len(result) == 1
        assert result[0].finding.summary == "keep"
