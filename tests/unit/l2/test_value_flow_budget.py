"""Unit tests for the L2 construction memory/size budget (FLAW-345).

The guard exists to convert the one *uncatchable* L2 failure mode — a value-flow
graph that grows until the OS SIGKILLs the process, leaving no result document at
all (a silent zero / false negative) — into a catchable, typed
``ValueFlowBudgetError`` that the pipeline turns into an honest ``incomplete``.

These tests are fully hermetic: they drive the budget primitives directly with an
injected RSS reading, so nothing has to actually allocate gigabytes.
"""

from __future__ import annotations

import pytest

from flawed._semantic import _budget
from flawed._semantic._budget import (
    ConstructionBudget,
    ValueFlowBudgetError,
    budgeted,
    check_active_budget,
    construction_budget,
)


def test_disabled_budget_is_a_noop() -> None:
    # Zero ceilings (the "no limit" sentinel) never raise, regardless of RSS.
    budget = ConstructionBudget(max_rss_bytes=0, max_value_flow_edges=0)
    budget.check_rss()  # must not raise
    budget.check_edges(10**9)  # must not raise


def test_rss_ceiling_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_budget, "_maxrss_bytes", lambda: 2_000)
    budget = ConstructionBudget(max_rss_bytes=1_000)
    with pytest.raises(ValueFlowBudgetError) as excinfo:
        budget.check_rss()
    assert excinfo.value.kind == "resident-memory"
    assert excinfo.value.observed == 2_000
    assert excinfo.value.limit == 1_000


def test_rss_under_ceiling_is_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_budget, "_maxrss_bytes", lambda: 500)
    ConstructionBudget(max_rss_bytes=1_000).check_rss()  # must not raise


def test_edge_ceiling_fails_closed() -> None:
    budget = ConstructionBudget(max_value_flow_edges=10)
    budget.check_edges(10)  # at the ceiling: ok
    with pytest.raises(ValueFlowBudgetError) as excinfo:
        budget.check_edges(11)
    assert excinfo.value.kind == "value-flow-edge-count"


def test_active_budget_is_scoped_to_the_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_budget, "_maxrss_bytes", lambda: 10_000)
    # No budget installed → the hot-loop hook is a silent no-op.
    check_active_budget()
    # Installed and over budget → fails closed.
    with (
        construction_budget(ConstructionBudget(max_rss_bytes=1)),
        pytest.raises(ValueFlowBudgetError),
    ):
        check_active_budget()
    # Context exited → no-op again (the ContextVar was reset).
    check_active_budget()


def test_budgeted_yields_everything_when_unbounded() -> None:
    items = list(budgeted(range(5)))
    assert items == [0, 1, 2, 3, 4]


def test_budgeted_fails_closed_mid_iteration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_budget, "_maxrss_bytes", lambda: 10_000)
    consumed: list[int] = []

    def drain() -> None:
        # stride=1 → the very first element triggers the check and raises,
        # proving a runaway loop is stopped *before* it can exhaust memory.
        consumed.extend(budgeted(range(1000), stride=1))

    with (
        construction_budget(ConstructionBudget(max_rss_bytes=1)),
        pytest.raises(ValueFlowBudgetError),
    ):
        drain()
    assert consumed == []  # stopped before yielding anything


def test_resolved_reads_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FLAWED_L2_MAX_RSS_BYTES", "424242")
    monkeypatch.setenv("FLAWED_L2_MAX_VALUE_FLOW_EDGES", "99")
    budget = ConstructionBudget.resolved()
    assert budget.max_rss_bytes == 424242
    assert budget.max_value_flow_edges == 99


def test_resolved_defaults_to_a_fraction_of_physical_ram(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FLAWED_L2_MAX_RSS_BYTES", raising=False)
    monkeypatch.delenv("FLAWED_L2_MAX_VALUE_FLOW_EDGES", raising=False)
    monkeypatch.setattr(_budget, "_physical_ram_bytes", lambda: 1_000_000)
    budget = ConstructionBudget.resolved()
    # Adaptive default: never the full RAM (leaves headroom before the OOM kill).
    assert 0 < budget.max_rss_bytes < 1_000_000
    assert budget.max_value_flow_edges == 0  # edge ceiling off unless configured


def test_resolved_rss_disabled_when_ram_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FLAWED_L2_MAX_RSS_BYTES", raising=False)
    monkeypatch.setattr(_budget, "_physical_ram_bytes", lambda: None)
    # If physical RAM cannot be read we cannot pick an honest ceiling; the guard
    # goes inert rather than guessing a wrong limit (no false incompletes).
    assert ConstructionBudget.resolved().max_rss_bytes == 0
