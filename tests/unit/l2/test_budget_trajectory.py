"""The FLAW-345 budget sampler also records an L2 RSS trajectory (FLAW-355).

``check_active_budget`` is called from the hot L2 construction loops; besides
failing closed on an over-budget RSS it now appends each sampled reading to a
bounded, per-construction trajectory that the CLI drains into the durable scan
record.  These tests are hermetic — they drive the budget machinery directly
with no scan, no subprocess.
"""

from __future__ import annotations

from flawed._semantic import _budget
from flawed._semantic._budget import (
    ConstructionBudget,
    check_active_budget,
    construction_budget,
    current_trajectory,
)


def test_trajectory_empty_outside_a_construction() -> None:
    assert current_trajectory() == ()


def test_samples_are_recorded_inside_a_construction() -> None:
    # A zero ceiling disables the fail-closed check but must NOT disable sampling:
    # the trajectory is observability, independent of the guard firing.
    with construction_budget(ConstructionBudget(max_rss_bytes=0)):
        check_active_budget()
        check_active_budget()
        samples = current_trajectory()

    assert len(samples) == 2
    for elapsed_ms, rss_bytes, source in samples:
        assert elapsed_ms >= 0.0
        assert rss_bytes > 0
        assert source == "rusage_maxrss_peak"


def test_trajectory_resets_between_constructions() -> None:
    with construction_budget(ConstructionBudget(max_rss_bytes=0)):
        check_active_budget()
        assert len(current_trajectory()) == 1
    # Context reset on exit — a fresh construction starts from an empty trajectory.
    with construction_budget(ConstructionBudget(max_rss_bytes=0)):
        assert current_trajectory() == ()


def test_trajectory_is_bounded() -> None:
    cap = _budget._TRAJECTORY_CAP
    with construction_budget(ConstructionBudget(max_rss_bytes=0)):
        for _ in range(cap + 50):
            check_active_budget()
        samples = current_trajectory()
    # The ring buffer caps retained samples — a multi-million-edge construction
    # cannot grow the in-memory trajectory without bound.
    assert len(samples) == cap


def test_budgeted_loop_feeds_the_trajectory() -> None:
    # The real call path: a budgeted() hot loop samples every ``stride`` items.
    with construction_budget(ConstructionBudget(max_rss_bytes=0)):
        list(_budget.budgeted(range(10_000), stride=1_000))
        samples = current_trajectory()
    assert len(samples) >= 1
