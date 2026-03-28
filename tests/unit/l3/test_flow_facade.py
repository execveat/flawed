"""Unit tests for the gap-carrying flow-query facade on ``ValueHandle`` (FLAW-220).

The boolean ``flows_to`` / ``flows_from`` facades collapse the underlying
:class:`~flawed.flow.FlowTrace`, discarding the ``gaps`` tuple that tells
"proven no flow" apart from "engine could not analyze this path" -- a
false-negative hazard.  These tests pin the behaviour of the gap-exposing
siblings :meth:`~flawed.flow.ValueHandle.trace_flow_to` /
:meth:`~flawed.flow.ValueHandle.trace_flow_from` and that the bool facade is
their faithful projection.

Flow context is faked (no Semantic Layer) so the tests exercise the facade
contract, not the flow engine -- mirroring ``tests/unit/test_correlation.py``.
"""

from __future__ import annotations

from flawed.core import AnalysisGap, GapKind, Location
from flawed.flow import FlowStep, FlowTrace, ValueHandle, attach_flow_context


def _loc(line: int = 1) -> Location:
    return Location(file="t.py", line=line, column=0)


_GAP = AnalysisGap(
    kind=GapKind.VALUE_FLOW_INCOMPLETE,
    message="unresolved callee on the flow path",
)


def _handle(expression: str, *, line: int = 1) -> ValueHandle:
    """A bare handle with no flow context (test/helper-constructed)."""
    return ValueHandle(location=_loc(line), expression=expression)


def _handle_tracing_to(expression: str, *, result: FlowTrace, line: int = 1) -> ValueHandle:
    """A handle whose ``_trace_flow`` callback returns a fixed *result*.

    The callback is keyed only on identity here: it returns *result* for any
    (source, sink) pair, which is enough to pin how the facade forwards the
    trace.
    """
    handle = ValueHandle(location=_loc(line), expression=expression)

    def _trace_flow(_source: ValueHandle, _sink: ValueHandle) -> FlowTrace:
        return result

    return attach_flow_context(handle, trace_flow=_trace_flow)


class TestTraceFlowToReachable:
    def test_reachable_trace_is_forwarded_with_path_and_no_gaps(self) -> None:
        src = _handle("data")
        sink = _handle("query", line=9)
        reached = FlowTrace(
            source=src,
            sink=sink,
            steps=(FlowStep(_loc(5), "data", "assignment"),),
            reachable=True,
            gaps=(),
        )
        traced = _handle_tracing_to("data", result=reached)

        trace = traced.trace_flow_to(sink)

        assert trace is reached
        assert trace.reachable is True
        assert trace.gaps == ()
        assert len(trace.steps) == 1
        # The bool facade is the faithful projection of the trace.
        assert traced.flows_to(sink) is True


class TestTraceFlowToGapCarrying:
    def test_unreachable_trace_surfaces_gaps_while_bool_is_false(self) -> None:
        """The core FN-hazard distinction: a gap-carrying *unreachable* trace.

        ``flows_to`` collapses to ``False`` (indistinguishable from "proven
        no flow"); ``trace_flow_to`` preserves the gap so a rule can treat it
        as an AnalysisGap instead of a confident negative.
        """
        sink = _handle("sink", line=9)
        incomplete = FlowTrace(
            source=_handle("src"),
            sink=sink,
            steps=(),
            reachable=False,
            gaps=(_GAP,),
        )
        traced = _handle_tracing_to("src", result=incomplete)

        trace = traced.trace_flow_to(sink)

        assert trace.reachable is False
        assert trace.gaps == (_GAP,)
        # The bool projection cannot see the gap -- exactly why the sibling exists.
        assert traced.flows_to(sink) is False

    def test_proven_no_flow_has_no_gaps(self) -> None:
        sink = _handle("sink", line=9)
        no_flow = FlowTrace(source=_handle("src"), sink=sink, steps=(), reachable=False, gaps=())
        traced = _handle_tracing_to("src", result=no_flow)

        trace = traced.trace_flow_to(sink)

        assert trace.reachable is False
        assert trace.gaps == ()


class TestTraceFlowToShortCircuits:
    def test_same_origin_returns_reachable_gap_free_trace(self) -> None:
        handle = _handle("value", line=3)
        same = ValueHandle(location=_loc(3), expression="value")

        trace = handle.trace_flow_to(same)

        assert trace.reachable is True
        assert trace.gaps == ()
        assert trace.steps == ()
        assert trace.source is handle
        assert trace.sink is same
        assert handle.flows_to(same) is True

    def test_same_origin_does_not_invoke_the_engine(self) -> None:
        # A same-origin query must not touch the (potentially expensive) tracer.
        def _boom(_source: ValueHandle, _sink: ValueHandle) -> FlowTrace:
            raise AssertionError("trace_flow must not run for a same-origin query")

        handle = attach_flow_context(
            ValueHandle(location=_loc(3), expression="value"), trace_flow=_boom
        )
        same = ValueHandle(location=_loc(3), expression="value")

        assert handle.trace_flow_to(same).reachable is True

    def test_no_flow_context_yields_gap_free_unreachable_trace(self) -> None:
        # Bare handles (no Semantic Layer) carry no analysis to be incomplete,
        # mirroring preserves_whole_value_to's conservative-but-honest default.
        src = _handle("a")
        sink = _handle("b", line=2)

        trace = src.trace_flow_to(sink)

        assert trace.reachable is False
        assert trace.gaps == ()
        assert src.flows_to(sink) is False


class TestTraceFlowFrom:
    def test_trace_flow_from_is_the_reverse_of_trace_flow_to(self) -> None:
        sink = _handle("sink", line=9)
        incomplete = FlowTrace(
            source=_handle("src"), sink=sink, steps=(), reachable=False, gaps=(_GAP,)
        )
        source_handle = _handle_tracing_to("src", result=incomplete)

        # sink.trace_flow_from(source) == source.trace_flow_to(sink)
        assert sink.trace_flow_from(source_handle) is incomplete
        assert sink.flows_from(source_handle) is False

    def test_trace_flow_from_same_origin(self) -> None:
        handle = _handle("value", line=3)
        same = ValueHandle(location=_loc(3), expression="value")

        assert handle.trace_flow_from(same).reachable is True
