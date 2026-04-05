"""Spike coverage for the experimental taint prototype."""

from __future__ import annotations

from flawed._semantic._taint_prototype import TaintGraph


def test_taint_propagates_through_assignment() -> None:
    g = TaintGraph()
    g.mark_source("user_input", origin="request.args")
    g.propagate("query", ["user_input"])
    assert g.is_tainted("query")


def test_untainted_value_stays_clean() -> None:
    g = TaintGraph()
    g.propagate("x", ["y"])
    assert not g.is_tainted("x")
