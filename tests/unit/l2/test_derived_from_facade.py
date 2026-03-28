"""Tests for the gap-carrying ``derived_from`` provenance query (FLAW-236).

The boolean ``derived_from`` facade collapses the underlying provenance trace,
discarding the ``gaps`` tuple that tells "no matching provenance" apart from
"engine could not analyze the provenance" -- a false-negative hazard mirroring
the one FLAW-220 closed for ``flows_to``.  These tests pin:

1. the Layer-3 :meth:`~flawed.flow.ValueHandle.trace_derived_from` facade and
   that bool ``derived_from`` is its faithful projection (flow context faked, so
   the facade contract is exercised, not the engine), and
2. the Layer-2 :meth:`~flawed._semantic._SemanticFlowEngine.trace_derived_from`
   gap accumulation over per-read flow traces (built on a minimal engine).
"""

from __future__ import annotations

from flawed._index._graphs import CallGraph
from flawed._index._types import ExtractionProvenance, FlowKind, SourceSpan, ValueFlowEdge
from flawed._semantic import _SemanticFlowEngine  # type: ignore[attr-defined]
from flawed._semantic._collections import ConcreteFunctionCollection, ConcreteRouteCollection
from flawed.core import AnalysisGap, GapKind, Location
from flawed.flow import FlowStep, FlowTrace, ValueHandle, attach_flow_context
from flawed.inputs import PathParam, Query


def _loc(line: int = 1) -> Location:
    return Location(file="t.py", line=line, column=0)


_GAP = AnalysisGap(
    kind=GapKind.VALUE_FLOW_INCOMPLETE,
    message="unresolved callee on the provenance path",
)


def _handle(expression: str, *, line: int = 1) -> ValueHandle:
    """A bare handle with no flow context (test/helper-constructed)."""
    return ValueHandle(location=_loc(line), expression=expression)


def _handle_with_provenance(expression: str, *, result: FlowTrace) -> ValueHandle:
    """A handle whose ``_trace_derived_from`` callback returns a fixed *result*."""
    handle = ValueHandle(location=_loc(), expression=expression)

    def _trace_derived_from(_handle: ValueHandle, _source: object) -> FlowTrace:
        return result

    return attach_flow_context(handle, trace_derived_from=_trace_derived_from)


class TestFacadeReachable:
    def test_reachable_trace_forwarded_and_bool_is_true(self) -> None:
        src = _handle("request.args['q']", line=5)
        target = _handle("dest", line=9)
        reached = FlowTrace(
            source=src,
            sink=target,
            steps=(FlowStep(_loc(7), "dest", "assignment"),),
            reachable=True,
            gaps=(),
        )
        traced = _handle_with_provenance("dest", result=reached)

        trace = traced.trace_derived_from(Query())

        assert trace is reached
        assert trace.reachable is True
        assert trace.gaps == ()
        assert traced.derived_from(Query()) is True


class TestFacadeGapCarrying:
    def test_unreachable_trace_surfaces_gaps_while_bool_is_false(self) -> None:
        """The core FN-hazard distinction: a gap-carrying *unreachable* trace.

        ``derived_from`` collapses to ``False`` (indistinguishable from "no
        matching provenance"); ``trace_derived_from`` preserves the gap so a
        rule can treat it as an AnalysisGap instead of a confident negative.
        """
        target = _handle("dest", line=9)
        incomplete = FlowTrace(source=target, sink=target, steps=(), reachable=False, gaps=(_GAP,))
        traced = _handle_with_provenance("dest", result=incomplete)

        trace = traced.trace_derived_from(Query())

        assert trace.reachable is False
        assert trace.gaps == (_GAP,)
        # The bool projection cannot see the gap -- exactly why the sibling exists.
        assert traced.derived_from(Query()) is False

    def test_proven_no_provenance_has_no_gaps(self) -> None:
        target = _handle("dest", line=9)
        no_prov = FlowTrace(source=target, sink=target, steps=(), reachable=False, gaps=())
        traced = _handle_with_provenance("dest", result=no_prov)

        trace = traced.trace_derived_from(Query())

        assert trace.reachable is False
        assert trace.gaps == ()
        assert traced.derived_from(Query()) is False


class TestFacadeShortCircuits:
    def test_handle_that_is_itself_the_source_is_reachable_gap_free(self) -> None:
        # A handle carrying a matching ``_input_source`` IS the input; provenance
        # is trivially proven without invoking the engine.
        handle = attach_flow_context(
            ValueHandle(location=_loc(), expression="request.args['q']"),
            input_source=Query(),
        )

        trace = handle.trace_derived_from(Query())

        assert trace.reachable is True
        assert trace.gaps == ()
        assert trace.source is handle
        assert handle.derived_from(Query()) is True
        # A non-matching source type still defers to (here absent) provenance.
        assert handle.derived_from(PathParam()) is False

    def test_no_flow_context_yields_gap_free_unreachable_trace(self) -> None:
        handle = _handle("dest")

        trace = handle.trace_derived_from(Query())

        assert trace.reachable is False
        assert trace.gaps == ()
        assert handle.derived_from(Query()) is False

    def test_legacy_bool_callback_only_still_answers(self) -> None:
        # If only the legacy boolean ``_derived_from`` callback is attached (no
        # gap-carrying sibling), ``derived_from`` must not regress to False.
        handle = ValueHandle(location=_loc(), expression="dest")

        def _derived_from(_handle: ValueHandle, _source: object) -> bool:
            return True

        attach_flow_context(handle, derived_from=_derived_from)

        trace = handle.trace_derived_from(Query())

        assert trace.reachable is True
        assert trace.gaps == ()  # bool callback cannot report gaps
        assert handle.derived_from(Query()) is True


# --- Engine-level (Layer 2) gap accumulation -------------------------------


def _prov() -> ExtractionProvenance:
    return ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="test")


def _span(line: int) -> SourceSpan:
    return SourceSpan(file="app.py", line=line, column=0, end_line=line, end_column=5)


def _edge(target_expr: str) -> ValueFlowEdge:
    return ValueFlowEdge(
        source_expr="seed",
        source_location=_span(1),
        target_expr=target_expr,
        target_location=_span(2),
        kind=FlowKind.ASSIGN,
        containing_function_fqn="app.handler",
        provenance=_prov(),
    )


class _FlowGraph:
    def __init__(self, edges: tuple[ValueFlowEdge, ...]) -> None:
        self._edges = edges

    @property
    def edges(self) -> tuple[ValueFlowEdge, ...]:
        return self._edges


class _FakeRead:
    """Minimal stand-in for an InputRead with a matching source and a value
    handle whose ``trace_flow_to`` returns a fixed trace."""

    def __init__(self, source: object, value: ValueHandle) -> None:
        self.source = source
        self.value = value


def _read_tracing_to(result: FlowTrace, *, source: object) -> _FakeRead:
    value = ValueHandle(location=_loc(), expression="seed")

    def _trace_flow(_source: ValueHandle, _sink: ValueHandle) -> FlowTrace:
        return result

    attach_flow_context(value, trace_flow=_trace_flow)
    return _FakeRead(source=source, value=value)


def _engine_with_reads(reads: tuple[_FakeRead, ...]) -> _SemanticFlowEngine:
    # An edge whose target_expr is "dest" puts "dest" in _target_expr_keys, so a
    # query against a "dest" handle skips the FLAW-200 same-origin prefilter and
    # exercises the per-read trace_flow_to path (where gaps live).
    engine = _SemanticFlowEngine(
        value_flow=_FlowGraph((_edge("dest"),)),  # type: ignore[arg-type]
        call_graph=CallGraph(()),
        function_records=(),
        functions=ConcreteFunctionCollection(()),
        routes=ConcreteRouteCollection(()),
    )
    engine._input_reads = reads  # type: ignore[assignment]
    return engine


class TestEngineGapAccumulation:
    def test_accumulates_gaps_from_unreachable_matching_reads(self) -> None:
        target = _handle("dest", line=9)
        unreachable = FlowTrace(
            source=_handle("seed"), sink=target, steps=(), reachable=False, gaps=(_GAP,)
        )
        engine = _engine_with_reads((_read_tracing_to(unreachable, source=Query()),))

        trace = engine.trace_derived_from(target, Query())

        assert trace.reachable is False
        assert trace.gaps == (_GAP,)
        # Bool projection is byte-identical to the old derived_from: still False.
        assert engine.derived_from(target, Query()) is False

    def test_returns_reaching_read_trace_without_gaps(self) -> None:
        target = _handle("dest", line=9)
        reached = FlowTrace(source=_handle("seed"), sink=target, steps=(), reachable=True, gaps=())
        engine = _engine_with_reads((_read_tracing_to(reached, source=Query()),))

        trace = engine.trace_derived_from(target, Query())

        assert trace.reachable is True
        assert engine.derived_from(target, Query()) is True

    def test_non_matching_source_is_not_traced(self) -> None:
        target = _handle("dest", line=9)
        unreachable = FlowTrace(
            source=_handle("seed"), sink=target, steps=(), reachable=False, gaps=(_GAP,)
        )
        # The only read matches Query(), so a PathParam() query matches no read:
        # no trace attempted, no gaps, proven-absent.
        engine = _engine_with_reads((_read_tracing_to(unreachable, source=Query()),))

        trace = engine.trace_derived_from(target, PathParam())

        assert trace.reachable is False
        assert trace.gaps == ()
