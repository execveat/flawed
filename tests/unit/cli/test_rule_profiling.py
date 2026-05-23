"""Tests for per-rule L3 profiling."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

from flawed._cli.rules import (
    RuleDetector,
    run_detectors_profiled,
)
from flawed.evidence import Finding

if TYPE_CHECKING:
    from flawed.repo import RepoView


class _FakeRepo:
    """Minimal stand-in for RepoView (no flow telemetry)."""


class _FlowRepo:
    """RepoView stand-in exposing scan-cumulative flow telemetry (FLAW-194).

    ``queries``/``bfs`` advance as detectors do flow work; ``flow_query_stats``
    is the cumulative snapshot the detector loop reads before/after each rule.
    """

    def __init__(self) -> None:
        self.queries = 0
        self.bfs = 0

    @property
    def flow_query_stats(self) -> tuple[int, int]:
        return (self.queries, self.bfs)


def _finding(summary: str) -> Finding:
    return Finding(route_endpoint="test", summary=summary)


def _detector(rule_id: str, findings: tuple[Finding, ...] = ()) -> RuleDetector:
    def detect(_repo: object) -> list[Finding]:
        return list(findings)

    return RuleDetector(rule_id=rule_id, path=Path(f"{rule_id}.py"), function=detect)


def test_profiled_returns_findings_and_profiles() -> None:
    finding = _finding("example")
    detectors = [
        _detector("rule-a", (finding,)),
        _detector("rule-b"),
    ]

    findings, profiles = run_detectors_profiled(cast("RepoView", _FakeRepo()), detectors)

    assert len(findings) == 1
    assert findings[0].rule_id == "rule-a"
    assert len(profiles) == 2
    assert profiles[0].rule_id == "rule-a"
    assert profiles[0].finding_count == 1
    assert profiles[0].wall_ms >= 0
    assert profiles[1].rule_id == "rule-b"
    assert profiles[1].finding_count == 0


def test_profiled_counts_finding_gaps() -> None:
    from flawed.core import AnalysisGap, GapKind

    gap = AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message="test gap",
        origin_phase="rule_execution",
    )
    finding_with_gaps = Finding(
        route_endpoint="test",
        summary="gapped",
        gaps=(gap, gap),
    )
    detectors = [_detector("gappy-rule", (finding_with_gaps,))]

    _findings, profiles = run_detectors_profiled(cast("RepoView", _FakeRepo()), detectors)

    assert profiles[0].finding_gap_count == 2


def test_profiled_measures_nonzero_wall_time() -> None:
    """Verify wall_ms is populated (not hardcoded to zero)."""
    import time

    def slow_detect(_repo: object) -> list[Finding]:
        time.sleep(0.005)
        return [_finding("slow")]

    detector = RuleDetector(
        rule_id="slow-rule",
        path=Path("slow.py"),
        function=slow_detect,
    )
    _findings, profiles = run_detectors_profiled(cast("RepoView", _FakeRepo()), [detector])

    assert profiles[0].wall_ms >= 4.0  # at least 4ms from 5ms sleep


def test_profiled_flow_stats_default_zero_without_telemetry() -> None:
    """A repo view lacking flow telemetry yields zero flow cost, not an error."""
    _findings, profiles = run_detectors_profiled(
        cast("RepoView", _FakeRepo()), [_detector("rule-a", (_finding("x"),))]
    )

    assert profiles[0].flow_query_count == 0
    assert profiles[0].bfs_count == 0


def test_profiled_attributes_flow_cost_to_the_rule_that_incurred_it() -> None:
    """Each rule's profile carries the delta of flow work done during its run."""
    repo = _FlowRepo()

    def heavy(_r: object) -> list[Finding]:
        repo.queries += 5
        repo.bfs += 3
        return [_finding("heavy")]

    def light(_r: object) -> list[Finding]:
        return [_finding("light")]  # issues no flow queries

    detectors = [
        RuleDetector(rule_id="heavy", path=Path("heavy.py"), function=heavy),
        RuleDetector(rule_id="light", path=Path("light.py"), function=light),
    ]

    _findings, profiles = run_detectors_profiled(cast("RepoView", repo), detectors)
    by_id = {p.rule_id: p for p in profiles}

    assert (by_id["heavy"].flow_query_count, by_id["heavy"].bfs_count) == (5, 3)
    # The light rule gets zero even though the cumulative counter is now nonzero —
    # the delta isolates each rule's own cost.
    assert (by_id["light"].flow_query_count, by_id["light"].bfs_count) == (0, 0)
