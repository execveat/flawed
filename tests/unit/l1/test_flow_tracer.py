"""Unit tests for the intra-function flow tracer.

Tests that ``trace_intra_function`` correctly follows L1 ``ValueFlowEdge``
chains within a single function, producing ``FlowStep`` and ``FlowTrace``
objects with the correct reachability, step ordering, and descriptions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed._index._graphs import CallGraph, ValueFlowGraph
from flawed._index._types import (
    CallArgument,
    CallEdge,
    EdgeSource,
    ExtractionProvenance,
    FlowKind,
    FunctionKind,
    FunctionRecord,
    Parameter,
    ParameterKind,
    ResolutionStatus,
    SourceSpan,
    ValueFlowEdge,
)
from flawed._semantic._flow_tracer import (
    FlowQueryCounter,
    IntraFunctionFlowTracer,
    _unresolved_callee_gap,
)
from flawed.core import AnalysisGap, GapKind

if TYPE_CHECKING:
    from flawed.flow import FlowTrace


def _prov() -> ExtractionProvenance:
    return ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="test")


def _span(file: str, line: int, col: int = 0) -> SourceSpan:
    return SourceSpan(file=file, line=line, column=col, end_line=line, end_column=col + 5)


def _edge(
    src_expr: str,
    src_line: int,
    tgt_expr: str,
    tgt_line: int,
    kind: FlowKind = FlowKind.ASSIGN,
    fn_fqn: str | None = "mod.func",
    file: str = "app.py",
) -> ValueFlowEdge:
    return ValueFlowEdge(
        source_expr=src_expr,
        source_location=_span(file, src_line),
        target_expr=tgt_expr,
        target_location=_span(file, tgt_line),
        kind=kind,
        containing_function_fqn=fn_fqn,
        provenance=_prov(),
    )


def _function(
    fqn: str,
    *,
    params: tuple[Parameter, ...] = (),
    file: str = "app.py",
    line: int = 1,
) -> FunctionRecord:
    return FunctionRecord(
        fqn=fqn,
        name=fqn.rsplit(".", 1)[-1],
        file=file,
        line=line,
        params=params,
        decorator_names=(),
        decorator_fqns=(),
        kind=FunctionKind.TOP_LEVEL,
        is_method=False,
        is_nested=False,
        is_async=False,
        parent_class=None,
        location=_span(file, line),
        provenance=_prov(),
    )


def _param(name: str, position: int, *, line: int) -> Parameter:
    return Parameter(
        name=name,
        annotation=None,
        default=None,
        kind=ParameterKind.POSITIONAL_OR_KEYWORD,
        position=position,
        location=_span("app.py", line),
    )


def _call_arg(expr: str, line: int, position: int = 0) -> CallArgument:
    return CallArgument(
        position=position,
        keyword=None,
        expression=expr,
        location=_span("app.py", line),
    )


def _call_edge(
    caller_fqn: str,
    callee_fqn: str | None,
    *,
    line: int,
    call_expression: str,
    arguments: tuple[CallArgument, ...] = (),
) -> CallEdge:
    return CallEdge(
        caller_fqn=caller_fqn,
        callee_fqn=callee_fqn,
        arguments=arguments,
        resolution=ResolutionStatus.RESOLVED
        if callee_fqn is not None
        else ResolutionStatus.UNRESOLVED,
        source=EdgeSource.AST,
        unresolved_reason=None if callee_fqn is not None else "test unresolved",
        location=_span("app.py", line),
        provenance=_prov(),
        call_expression=call_expression,
    )


# =====================================================================
# Basic reachability
# =====================================================================


class TestIntraFunctionReachability:
    """Test that the tracer correctly determines reachability."""

    def test_direct_assignment_reachable(self) -> None:
        """x = expr; value flows from expr to x on the same line."""
        edges = (_edge("request.args['q']", 5, "query", 5),)
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="request.args['q']",
            sink_location=_span("app.py", 5),
            sink_expr="query",
            fn_fqn="mod.func",
        )

        assert trace.reachable is True
        assert len(trace.steps) >= 2  # at least source and sink
        assert trace.steps[-1].kind == FlowKind.ASSIGN.value

    def test_exact_source_does_not_relax_to_same_line_expression(self) -> None:
        """Whole-value tracing requires the exact source expression."""
        edges = (_edge("url_for('dashboard') + suffix", 5, "target", 5),)
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="url_for('dashboard')",
            sink_location=_span("app.py", 5),
            sink_expr="target",
            fn_fqn="mod.func",
            exact_source=True,
        )

        assert trace.reachable is False
        assert len(trace.gaps) == 1
        assert "source node" in trace.gaps[0].message

    def test_two_hop_chain_reachable(self) -> None:
        """x = expr; y = x; flow from expr to y via x."""
        edges = (
            _edge("request.args['q']", 5, "query", 5),
            _edge("query", 6, "sql", 6),
        )
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="request.args['q']",
            sink_location=_span("app.py", 6),
            sink_expr="sql",
            fn_fqn="mod.func",
        )

        assert trace.reachable is True
        assert len(trace.steps) >= 3  # source, intermediate, sink

    def test_assignment_flows_to_variable_use_at_call_argument(self) -> None:
        """x = source; sink(x) reaches the argument value, not just the call."""
        edges = (
            _edge('request.form["query"]', 10, "query", 10),
            _edge("query", 12, "text", 12, kind=FlowKind.ARGUMENT),
        )
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 10),
            source_expr='request.form["query"]',
            sink_location=_span("app.py", 12),
            sink_expr="query",
            fn_fqn="mod.func",
        )

        assert trace.reachable is True
        assert [step.expression for step in trace.steps] == [
            'request.form["query"]',
            "query",
            "query",
        ]
        assert trace.steps[-1].location.line == 12

    def test_unreachable_returns_empty_trace(self) -> None:
        """Disconnected nodes produce reachable=False."""
        edges = (
            _edge("request.args['q']", 5, "query", 5),
            _edge("literal", 10, "other", 10),
        )
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="request.args['q']",
            sink_location=_span("app.py", 10),
            sink_expr="other",
            fn_fqn="mod.func",
        )

        assert trace.reachable is False
        assert trace.steps == ()
        assert trace.gaps == ()

    def test_empty_graph_not_reachable(self) -> None:
        """No function edges records a gap instead of silently failing open."""
        vfg = ValueFlowGraph(())
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="request.args['q']",
            sink_location=_span("app.py", 10),
            sink_expr="db.execute(query)",
            fn_fqn="mod.func",
        )

        assert trace.reachable is False
        assert trace.steps == ()
        assert len(trace.gaps) == 1
        assert trace.gaps[0].kind == GapKind.VALUE_FLOW_INCOMPLETE
        assert trace.gaps[0].affected_file == "app.py"
        assert trace.gaps[0].affected_function == "mod.func"
        assert "no value-flow edges" in trace.gaps[0].message

    def test_missing_source_node_records_gap(self) -> None:
        """Missing source nodes are analysis gaps, not proven non-reachability."""
        edges = (_edge("known", 5, "sink", 10),)
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 99),
            source_expr="missing",
            sink_location=_span("app.py", 10),
            sink_expr="sink",
            fn_fqn="mod.func",
        )

        assert trace.reachable is False
        assert trace.steps == ()
        assert len(trace.gaps) == 1
        assert trace.gaps[0].kind == GapKind.VALUE_FLOW_INCOMPLETE
        assert "source node" in trace.gaps[0].message

    def test_missing_sink_node_records_gap(self) -> None:
        """Missing sink nodes are analysis gaps, not proven non-reachability."""
        edges = (_edge("source", 5, "known", 5),)
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="source",
            sink_location=_span("app.py", 99),
            sink_expr="missing",
            fn_fqn="mod.func",
        )

        assert trace.reachable is False
        assert trace.steps == ()
        assert len(trace.gaps) == 1
        assert trace.gaps[0].kind == GapKind.VALUE_FLOW_INCOMPLETE
        assert "sink node" in trace.gaps[0].message


# =====================================================================
# Step ordering and content
# =====================================================================


class TestFlowStepContent:
    """Test that FlowStep objects have correct content."""

    def test_step_locations_ordered(self) -> None:
        """Steps are ordered from source to sink."""
        edges = (
            _edge("request.args['q']", 5, "query", 5),
            _edge("query", 6, "sql", 6),
            _edge("sql", 7, "result", 7),
        )
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="request.args['q']",
            sink_location=_span("app.py", 7),
            sink_expr="result",
            fn_fqn="mod.func",
        )

        assert trace.reachable is True
        lines = [step.location.line for step in trace.steps]
        assert lines == sorted(lines), "steps should be in source order"

    def test_step_expressions_present(self) -> None:
        """Each step carries the expression text."""
        edges = (_edge("request.args['q']", 5, "query", 5),)
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="request.args['q']",
            sink_location=_span("app.py", 5),
            sink_expr="query",
            fn_fqn="mod.func",
        )

        assert trace.reachable is True
        expressions = [step.expression for step in trace.steps]
        assert "request.args['q']" in expressions
        assert "query" in expressions

    def test_step_descriptions_describe_flow_kind(self) -> None:
        """Step descriptions mention the flow kind."""
        edges = (_edge("request.args['q']", 5, "query", 5, kind=FlowKind.ASSIGN),)
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="request.args['q']",
            sink_location=_span("app.py", 5),
            sink_expr="query",
            fn_fqn="mod.func",
        )

        assert trace.reachable is True
        # At least the non-source steps should have meaningful descriptions
        assert any(step.description for step in trace.steps)


# =====================================================================
# FlowTrace source/sink handles
# =====================================================================


class TestFlowTraceHandles:
    """Test that FlowTrace carries correct ValueHandle objects."""

    def test_source_handle_matches_input(self) -> None:
        """FlowTrace.source matches the requested source."""
        edges = (_edge("request.args['q']", 5, "query", 5),)
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="request.args['q']",
            sink_location=_span("app.py", 5),
            sink_expr="query",
            fn_fqn="mod.func",
        )

        assert trace.source.expression == "request.args['q']"
        assert trace.source.location.line == 5

    def test_sink_handle_matches_input(self) -> None:
        """FlowTrace.sink matches the requested sink."""
        edges = (_edge("request.args['q']", 5, "query", 5),)
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="request.args['q']",
            sink_location=_span("app.py", 5),
            sink_expr="query",
            fn_fqn="mod.func",
        )

        assert trace.sink.expression == "query"
        assert trace.sink.location.line == 5


# =====================================================================
# Edge case: cycles and depth limits
# =====================================================================


class TestEdgeCases:
    """Test cycle handling and depth limits."""

    def test_cycle_does_not_loop_infinitely(self) -> None:
        """A cycle in the flow graph terminates without hanging."""
        edges = (
            _edge("x", 5, "y", 6),
            _edge("y", 6, "x", 5),  # cycle back
        )
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        # Source is x at line 5, sink is y at line 6 — reachable through direct edge
        trace = tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="x",
            sink_location=_span("app.py", 6),
            sink_expr="y",
            fn_fqn="mod.func",
        )

        assert trace.reachable is True

    def test_self_loop_handled(self) -> None:
        """A self-referencing edge doesn't cause infinite recursion."""
        edges = (_edge("x", 5, "x", 5, kind=FlowKind.AUGMENTED_ASSIGN),)
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="x",
            sink_location=_span("app.py", 5),
            sink_expr="x",
            fn_fqn="mod.func",
        )

        assert trace.reachable is True

    def test_long_chain_respects_depth_limit(self) -> None:
        """A very long chain still terminates (bounded BFS)."""
        edges = tuple(_edge(f"v{i}", i + 5, f"v{i + 1}", i + 6) for i in range(100))
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="v0",
            sink_location=_span("app.py", 105),
            sink_expr="v100",
            fn_fqn="mod.func",
        )

        # Regardless of whether it reaches, it must terminate
        assert isinstance(trace.reachable, bool)


# =====================================================================
# Function scoping
# =====================================================================


class TestFunctionScoping:
    """Test that tracing respects function boundaries."""

    def test_only_edges_in_same_function(self) -> None:
        """Edges from other functions are ignored in intra-function tracing."""
        edges = (
            _edge("x", 5, "y", 5, fn_fqn="mod.func_a"),
            _edge("y", 6, "z", 6, fn_fqn="mod.func_b"),  # different function
        )
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="x",
            sink_location=_span("app.py", 6),
            sink_expr="z",
            fn_fqn="mod.func_a",
        )

        assert trace.reachable is False


# =====================================================================
# One-hop interprocedural stitching
# =====================================================================


class TestOneHopInterproceduralFlow:
    """Test P6.2 one-hop argument/return stitching across call boundaries."""

    def test_caller_argument_flows_to_callee_parameter(self) -> None:
        """Call argument values bridge to the matching callee parameter."""
        call = _call_edge(
            "mod.caller",
            "mod.helper",
            line=6,
            call_expression="helper",
            arguments=(_call_arg("user_input", 6),),
        )
        vfg = ValueFlowGraph(
            (
                _edge(
                    "user_input",
                    6,
                    "helper",
                    6,
                    kind=FlowKind.ARGUMENT,
                    fn_fqn="mod.caller",
                ),
            )
        )
        tracer = IntraFunctionFlowTracer(
            vfg,
            call_graph=CallGraph((call,)),
            functions=(_function("mod.helper", params=(_param("query", 0, line=10),)),),
        )

        trace = tracer.trace_one_hop(
            source_location=_span("app.py", 6),
            source_expr="user_input",
            sink_location=_span("app.py", 10),
            sink_expr="query",
            source_fn_fqn="mod.caller",
            sink_fn_fqn="mod.helper",
        )

        assert trace.reachable is True
        assert [step.expression for step in trace.steps] == ["user_input", "query"]
        assert "passed as argument to" in trace.steps[-1].description

    def test_callee_return_flows_to_caller_assignment(self) -> None:
        """A callee return bridges to the caller expression assigned from the call."""
        call = _call_edge(
            "mod.caller",
            "mod.helper",
            line=5,
            call_expression="helper",
        )
        vfg = ValueFlowGraph(
            (
                _edge("data", 12, "return", 13, kind=FlowKind.RETURN, fn_fqn="mod.helper"),
                _edge("helper()", 5, "result", 5, fn_fqn="mod.caller"),
            )
        )
        tracer = IntraFunctionFlowTracer(
            vfg,
            call_graph=CallGraph((call,)),
            functions=(_function("mod.helper"), _function("mod.caller")),
        )

        trace = tracer.trace_one_hop(
            source_location=_span("app.py", 12),
            source_expr="data",
            sink_location=_span("app.py", 5),
            sink_expr="result",
            source_fn_fqn="mod.helper",
            sink_fn_fqn="mod.caller",
        )

        assert trace.reachable is True
        assert [step.expression for step in trace.steps] == [
            "data",
            "return",
            "helper()",
            "result",
        ]
        assert "returned from" in trace.steps[2].description

    def test_caller_argument_round_trips_through_callee_return(self) -> None:
        """One direct call can carry a caller value through callee return to caller assignment."""
        call = _call_edge(
            "mod.caller",
            "mod.identity",
            line=5,
            call_expression="identity",
            arguments=(_call_arg("user_input", 5),),
        )
        vfg = ValueFlowGraph(
            (
                _edge(
                    "user_input",
                    5,
                    "identity",
                    5,
                    kind=FlowKind.ARGUMENT,
                    fn_fqn="mod.caller",
                ),
                _edge("payload", 12, "return", 13, kind=FlowKind.RETURN, fn_fqn="mod.identity"),
                _edge("identity()", 5, "result", 5, fn_fqn="mod.caller"),
            )
        )
        tracer = IntraFunctionFlowTracer(
            vfg,
            call_graph=CallGraph((call,)),
            functions=(
                _function("mod.identity", params=(_param("payload", 0, line=10),)),
                _function("mod.caller"),
            ),
        )

        trace = tracer.trace_one_hop(
            source_location=_span("app.py", 5),
            source_expr="user_input",
            sink_location=_span("app.py", 5),
            sink_expr="result",
            source_fn_fqn="mod.caller",
            sink_fn_fqn="mod.caller",
        )

        assert trace.reachable is True
        assert [step.expression for step in trace.steps] == [
            "user_input",
            "payload",
            "return",
            "identity()",
            "result",
        ]

    def test_missing_call_graph_records_gap(self) -> None:
        """Cross-function traces need a call graph; absence is an analysis gap."""
        tracer = IntraFunctionFlowTracer(ValueFlowGraph(()))

        trace = tracer.trace_one_hop(
            source_location=_span("app.py", 1),
            source_expr="x",
            sink_location=_span("app.py", 2),
            sink_expr="y",
            source_fn_fqn="mod.caller",
            sink_fn_fqn="mod.helper",
        )

        assert trace.reachable is False
        assert len(trace.gaps) == 1
        assert trace.gaps[0].kind == GapKind.VALUE_FLOW_INCOMPLETE
        assert "call graph" in trace.gaps[0].message

    def test_unmapped_argument_records_gap(self) -> None:
        """Arguments that cannot be mapped to callee parameters do not fail open."""
        call = _call_edge(
            "mod.caller",
            "mod.helper",
            line=6,
            call_expression="helper",
            arguments=(_call_arg("user_input", 6),),
        )
        vfg = ValueFlowGraph(
            (
                _edge(
                    "user_input",
                    6,
                    "helper",
                    6,
                    kind=FlowKind.ARGUMENT,
                    fn_fqn="mod.caller",
                ),
            )
        )
        tracer = IntraFunctionFlowTracer(
            vfg,
            call_graph=CallGraph((call,)),
            functions=(_function("mod.helper"),),
        )

        trace = tracer.trace_one_hop(
            source_location=_span("app.py", 6),
            source_expr="user_input",
            sink_location=_span("app.py", 10),
            sink_expr="query",
            source_fn_fqn="mod.caller",
            sink_fn_fqn="mod.helper",
        )

        assert trace.reachable is False
        assert len(trace.gaps) == 1
        assert trace.gaps[0].kind == GapKind.VALUE_FLOW_INCOMPLETE
        assert "argument" in trace.gaps[0].message


# =====================================================================
# Multiple flow kinds
# =====================================================================


class TestFlowKinds:
    """Test that different FlowKind values are handled correctly."""

    def test_argument_flow(self) -> None:
        """Argument edges are traced."""
        edges = (_edge("query", 5, "db.execute(query)", 6, kind=FlowKind.ARGUMENT),)
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="query",
            sink_location=_span("app.py", 6),
            sink_expr="db.execute(query)",
            fn_fqn="mod.func",
        )

        assert trace.reachable is True

    def test_return_flow(self) -> None:
        """Return edges are traced."""
        edges = (_edge("result", 10, "return", 11, kind=FlowKind.RETURN),)
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 10),
            source_expr="result",
            sink_location=_span("app.py", 11),
            sink_expr="return",
            fn_fqn="mod.func",
        )

        assert trace.reachable is True

    def test_attribute_write_flow(self) -> None:
        """Attribute-write edges are traced."""
        edges = (_edge("value", 5, "self.name", 5, kind=FlowKind.ATTRIBUTE_WRITE),)
        vfg = ValueFlowGraph(edges)
        tracer = IntraFunctionFlowTracer(vfg)

        trace = tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="value",
            sink_location=_span("app.py", 5),
            sink_expr="self.name",
            fn_fqn="mod.func",
        )

        assert trace.reachable is True


# =====================================================================
# Same-function one-hop gap paths (FLAW-235)
# =====================================================================


class TestSameFunctionOneHopGaps:
    """trace_one_hop with source_fn == sink_fn surfaces unresolved callees.

    FLAW-235 closes the last instance of the FLAW-217 silent-skip class:
    ``_same_function_one_hop_edges`` previously dropped a call whose target L1
    could not resolve (``callee_fqn is None``), hiding an intra-function flow
    carried through unresolved dispatch.
    """

    def test_unresolved_callee_in_same_function_records_gap(self) -> None:
        """An unresolved intra-function call emits a VALUE_FLOW_INCOMPLETE gap.

        The endpoints exist in the VFG but are disconnected, so the intra-function
        ``trace()`` returns clean-unreachable (no missing-node gap) and execution
        reaches ``_same_function_one_hop_edges``, where the unresolved call lives.
        """
        call = _call_edge(
            "mod.handler",
            None,
            line=7,
            call_expression="dispatch[name](user_input)",
            arguments=(_call_arg("user_input", 7),),
        )
        # source ("user_input"@6) and sink ("result"@8) present but disconnected
        vfg = ValueFlowGraph(
            (
                _edge("user_input", 6, "scratch", 6, fn_fqn="mod.handler"),
                _edge("scratch2", 8, "result", 8, fn_fqn="mod.handler"),
            )
        )
        tracer = IntraFunctionFlowTracer(
            vfg,
            call_graph=CallGraph((call,)),
        )

        trace = tracer.trace_one_hop(
            source_location=_span("app.py", 6),
            source_expr="user_input",
            sink_location=_span("app.py", 8),
            sink_expr="result",
            source_fn_fqn="mod.handler",
            sink_fn_fqn="mod.handler",
        )

        assert trace.reachable is False
        unresolved = [g for g in trace.gaps if "unresolved call target" in g.message]
        assert len(unresolved) == 1
        gap = unresolved[0]
        assert gap.kind == GapKind.VALUE_FLOW_INCOMPLETE
        assert "dispatch[name](user_input)" in gap.message  # call-site preserved
        assert "test unresolved" in gap.message  # L1 unresolved_reason threaded
        assert gap.affected_function == "mod.handler"
        assert gap.affected_file == "app.py"

    def test_resolved_same_function_callees_emit_no_unresolved_gap(self) -> None:
        """Byte-identical guard on the same-function path: resolved targets add no gap.

        With ``source_fn == sink_fn == mod.handler`` (the
        ``_same_function_one_hop_edges`` path), a resolved helper call and a
        self-recursive call must BOTH stay free of an ``unresolved call target``
        gap — the emission fires only on ``callee_fqn is None``, and
        self-recursion (``callee_fqn == fn_fqn``) is a resolved target, not a gap.
        """
        calls = (
            _call_edge(
                "mod.handler",
                "mod.helper",
                line=7,
                call_expression="helper",
                arguments=(_call_arg("user_input", 7),),
            ),
            # self-recursion: resolved target, must not emit an unresolved gap
            _call_edge("mod.handler", "mod.handler", line=7, call_expression="handler"),
        )
        # endpoints present but disconnected -> reaches _same_function_one_hop_edges
        vfg = ValueFlowGraph(
            (
                _edge("user_input", 6, "scratch", 6, fn_fqn="mod.handler"),
                _edge("scratch2", 8, "result", 8, fn_fqn="mod.handler"),
            )
        )
        tracer = IntraFunctionFlowTracer(
            vfg,
            call_graph=CallGraph(calls),
            functions=(_function("mod.helper", params=(_param("query", 0, line=10),)),),
        )

        trace = tracer.trace_one_hop(
            source_location=_span("app.py", 6),
            source_expr="user_input",
            sink_location=_span("app.py", 8),
            sink_expr="result",
            source_fn_fqn="mod.handler",
            sink_fn_fqn="mod.handler",
        )

        assert not any("unresolved call target" in g.message for g in trace.gaps)


# =====================================================================
# Multi-hop interprocedural gap paths
# =====================================================================


class TestMultiHopGaps:
    """Unit tests for trace_multi_hop error and bound paths."""

    def test_missing_call_graph_records_gap(self) -> None:
        """trace_multi_hop without call graph → VALUE_FLOW_INCOMPLETE gap."""
        tracer = IntraFunctionFlowTracer(ValueFlowGraph(()))

        trace = tracer.trace_multi_hop(
            source_location=_span("app.py", 1),
            source_expr="x",
            sink_location=_span("app.py", 10),
            sink_expr="y",
            source_fn_fqn="mod.caller",
            sink_fn_fqn="mod.helper",
        )

        assert trace.reachable is False
        assert len(trace.gaps) == 1
        assert trace.gaps[0].kind == GapKind.VALUE_FLOW_INCOMPLETE
        assert "call graph" in trace.gaps[0].message

    def test_sink_unreachable_records_gap(self) -> None:
        """Sink function not in reachable_from() → gap."""
        # a→b exists, but c is unreachable from a
        call = _call_edge("mod.a", "mod.b", line=5, call_expression="b")
        cg = CallGraph((call,))
        tracer = IntraFunctionFlowTracer(ValueFlowGraph(()), call_graph=cg)

        trace = tracer.trace_multi_hop(
            source_location=_span("app.py", 1),
            source_expr="x",
            sink_location=_span("app.py", 20),
            sink_expr="y",
            source_fn_fqn="mod.a",
            sink_fn_fqn="mod.c",
        )

        assert trace.reachable is False
        assert len(trace.gaps) == 1
        assert trace.gaps[0].kind == GapKind.VALUE_FLOW_INCOMPLETE
        assert "not reachable within" in trace.gaps[0].message

    def test_timeout_records_gap(self) -> None:
        """Exceeding timeout → gap appended."""
        # a→b→c: sink IS reachable (passes fast check), but timeout=0 triggers immediately
        calls = (
            _call_edge("mod.a", "mod.b", line=5, call_expression="b"),
            _call_edge("mod.b", "mod.c", line=10, call_expression="c"),
        )
        cg = CallGraph(calls)
        tracer = IntraFunctionFlowTracer(ValueFlowGraph(()), call_graph=cg)

        trace = tracer.trace_multi_hop(
            source_location=_span("app.py", 1),
            source_expr="x",
            sink_location=_span("app.py", 20),
            sink_expr="y",
            source_fn_fqn="mod.a",
            sink_fn_fqn="mod.c",
            timeout=0.0,
        )

        assert trace.reachable is False
        assert any("timed out" in gap.message for gap in trace.gaps)

    def test_no_edges_on_path_records_gap(self) -> None:
        """Functions on call-graph path have no value-flow edges → gap.

        When there are no VFG edges and no function metadata, bridge
        construction fails with specific gaps (missing callee metadata,
        missing return edges).  The tracer must still return unreachable
        with diagnostic gaps rather than silently failing open.
        """
        call = _call_edge("mod.a", "mod.b", line=5, call_expression="b")
        cg = CallGraph((call,))
        tracer = IntraFunctionFlowTracer(ValueFlowGraph(()), call_graph=cg)

        trace = tracer.trace_multi_hop(
            source_location=_span("app.py", 1),
            source_expr="x",
            sink_location=_span("app.py", 10),
            sink_expr="y",
            source_fn_fqn="mod.a",
            sink_fn_fqn="mod.b",
        )

        assert trace.reachable is False
        assert len(trace.gaps) >= 1
        assert all(gap.kind == GapKind.VALUE_FLOW_INCOMPLETE for gap in trace.gaps)

    def test_unresolved_callee_on_path_records_gap(self) -> None:
        """FLAW-217: an unresolved call on a candidate path is surfaced.

        ``mod.a`` calls both ``mod.b`` (resolved — keeps the sink reachable so
        the fast check passes) and a dynamic-dispatch target L1 could not
        resolve (``callee_fqn is None``). Previously the unresolved call was
        skipped silently, making a flow missed via that call indistinguishable
        from a proven absence of flow. Now it emits a VALUE_FLOW_INCOMPLETE gap
        carrying the call-site expression and L1's unresolved reason.
        """
        calls = (
            _call_edge("mod.a", "mod.b", line=5, call_expression="b"),
            _call_edge("mod.a", None, line=6, call_expression="handlers[name]()"),
        )
        cg = CallGraph(calls)
        tracer = IntraFunctionFlowTracer(ValueFlowGraph(()), call_graph=cg)

        trace = tracer.trace_multi_hop(
            source_location=_span("app.py", 1),
            source_expr="x",
            sink_location=_span("app.py", 10),
            sink_expr="y",
            source_fn_fqn="mod.a",
            sink_fn_fqn="mod.b",
        )

        assert trace.reachable is False
        unresolved = [g for g in trace.gaps if "unresolved call target" in g.message]
        assert len(unresolved) == 1
        gap = unresolved[0]
        assert gap.kind == GapKind.VALUE_FLOW_INCOMPLETE
        assert "handlers[name]()" in gap.message  # call-site expression preserved
        assert "test unresolved" in gap.message  # L1 unresolved_reason threaded through
        assert gap.affected_function == "mod.a"
        assert gap.affected_file == "app.py"

    def test_resolved_callee_emits_no_unresolved_gap(self) -> None:
        """FLAW-217 byte-identical guard: a fully-resolved path adds no new gap.

        A reachable arg→param flow through a resolved callee must not grow an
        ``unresolved call target`` gap — the new emission fires only when L1
        could not resolve a callee, leaving resolvable-callee traces unchanged.
        """
        call = _call_edge(
            "mod.a",
            "mod.b",
            line=6,
            call_expression="b",
            arguments=(_call_arg("user_input", 6),),
        )
        vfg = ValueFlowGraph(
            (
                _edge(
                    "user_input",
                    6,
                    "b",
                    6,
                    kind=FlowKind.ARGUMENT,
                    fn_fqn="mod.a",
                ),
            )
        )
        tracer = IntraFunctionFlowTracer(
            vfg,
            call_graph=CallGraph((call,)),
            functions=(_function("mod.b", params=(_param("query", 0, line=10),)),),
        )

        trace = tracer.trace_multi_hop(
            source_location=_span("app.py", 6),
            source_expr="user_input",
            sink_location=_span("app.py", 10),
            sink_expr="query",
            source_fn_fqn="mod.a",
            sink_fn_fqn="mod.b",
        )

        assert trace.reachable is True
        assert not any("unresolved call target" in g.message for g in trace.gaps)


# =====================================================================
# Scan-scoped caching (FLAW-106)
# =====================================================================


class TestScanScopedCaching:
    """The tracer reuses per-function indexes and memoizes intra-function traces.

    These are pure-precompute optimizations: repeated source→sink queries — the
    dominant cost in reads x effects / args x reads rule loops on large repos —
    collapse to a single computation without changing any result.
    """

    def _two_hop_tracer(self) -> IntraFunctionFlowTracer:
        edges = (
            _edge("request.args['q']", 5, "query", 5),
            _edge("query", 6, "sql", 6),
            _edge("sql", 7, "result", 7),
        )
        return IntraFunctionFlowTracer(ValueFlowGraph(edges))

    def _trace(
        self, tracer: IntraFunctionFlowTracer, *, sink_line: int, sink_expr: str
    ) -> FlowTrace:
        return tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="request.args['q']",
            sink_location=_span("app.py", sink_line),
            sink_expr=sink_expr,
            fn_fqn="mod.func",
        )

    def test_identical_query_returns_memoized_result(self) -> None:
        """A repeated identical intra trace returns the cached object, not a recompute."""
        tracer = self._two_hop_tracer()
        first = self._trace(tracer, sink_line=6, sink_expr="sql")
        second = self._trace(tracer, sink_line=6, sink_expr="sql")

        assert first.reachable is True
        assert second is first  # served from _intra_trace_cache, not recomputed
        assert len(tracer._intra_trace_cache) == 1

    def test_function_index_reused_across_distinct_sinks(self) -> None:
        """Different sinks in the same function share one precomputed index."""
        tracer = self._two_hop_tracer()
        a = self._trace(tracer, sink_line=6, sink_expr="sql")
        b = self._trace(tracer, sink_line=7, sink_expr="result")

        assert a.reachable is True
        assert b.reachable is True
        # Distinct queries -> two memo entries, but a single shared function index.
        assert len(tracer._intra_trace_cache) == 2
        assert len(tracer._fn_index_cache) == 1

    def test_cached_result_equals_fresh_tracer_result(self) -> None:
        """The memoized answer is identical to a cold tracer's answer (no drift)."""
        warm = self._two_hop_tracer()
        # Prime, then query again through the cache.
        self._trace(warm, sink_line=7, sink_expr="result")
        cached = self._trace(warm, sink_line=7, sink_expr="result")

        cold = self._two_hop_tracer()
        fresh = self._trace(cold, sink_line=7, sink_expr="result")

        assert cached.reachable == fresh.reachable
        assert [s.expression for s in cached.steps] == [s.expression for s in fresh.steps]
        assert [s.kind for s in cached.steps] == [s.kind for s in fresh.steps]


class TestFlowQueryTelemetry:
    """FLAW-194: the tracer tallies flow queries + BFS traversals for per-rule
    budget telemetry. The counters are pure observation — they must never change
    a FlowTrace result, only describe the work it took to produce it.
    """

    def _two_hop_tracer(self, counter: FlowQueryCounter | None = None) -> IntraFunctionFlowTracer:
        edges = (
            _edge("request.args['q']", 5, "query", 5),
            _edge("query", 6, "sql", 6),
            _edge("sql", 7, "result", 7),
        )
        return IntraFunctionFlowTracer(ValueFlowGraph(edges), counter=counter)

    def _trace(
        self, tracer: IntraFunctionFlowTracer, *, sink_line: int, sink_expr: str
    ) -> FlowTrace:
        return tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="request.args['q']",
            sink_location=_span("app.py", sink_line),
            sink_expr=sink_expr,
            fn_fqn="mod.func",
        )

    def test_reachable_query_counts_one_query_and_one_bfs(self) -> None:
        tracer = self._two_hop_tracer()
        assert tracer.flow_query_stats == (0, 0)

        trace = self._trace(tracer, sink_line=6, sink_expr="sql")

        assert trace.reachable is True
        assert tracer.flow_query_stats == (1, 1)  # one query, one real BFS

    def test_cache_hit_counts_query_but_not_bfs(self) -> None:
        """A repeated identical query is counted (work the rule issued) but the
        intra-trace cache means no second BFS runs."""
        tracer = self._two_hop_tracer()
        first = self._trace(tracer, sink_line=6, sink_expr="sql")
        second = self._trace(tracer, sink_line=6, sink_expr="sql")

        # Result is stable across the cache (no drift from counting).
        assert second is first
        # Two queries issued, only one BFS performed.
        assert tracer.flow_query_stats == (2, 1)

    def test_empty_function_short_circuits_before_bfs(self) -> None:
        """A query into a function with no value-flow edges returns a gap without
        ever running BFS, so it counts a query but no traversal."""
        tracer = self._two_hop_tracer()
        trace = tracer.trace(
            source_location=_span("app.py", 5),
            source_expr="request.args['q']",
            sink_location=_span("app.py", 7),
            sink_expr="result",
            fn_fqn="mod.no_such_function",  # no edges -> empty index, no BFS
        )

        assert trace.reachable is False
        assert tracer.flow_query_stats == (1, 0)  # query counted, no BFS

    def test_counter_instance_is_shared(self) -> None:
        """A counter passed in is the live instance the tracer mutates — this is
        how the per-scan engine reads one cumulative tally across all rules."""
        counter = FlowQueryCounter()
        tracer = self._two_hop_tracer(counter=counter)

        self._trace(tracer, sink_line=6, sink_expr="sql")

        assert counter.flow_query_count == 1
        assert counter.bfs_count == 1
        assert tracer.flow_query_stats == (1, 1)

    def test_counting_does_not_change_trace_result(self) -> None:
        """The FlowTrace is byte-identical whether or not a shared counter is
        attached — counting is observation, not logic."""
        plain = self._trace(self._two_hop_tracer(), sink_line=7, sink_expr="result")
        counted = self._trace(
            self._two_hop_tracer(counter=FlowQueryCounter()),
            sink_line=7,
            sink_expr="result",
        )

        assert plain.reachable == counted.reachable is True
        assert [s.expression for s in plain.steps] == [s.expression for s in counted.steps]
        assert [s.kind for s in plain.steps] == [s.kind for s in counted.steps]


# =====================================================================
# FLAW-261: _one_hop_edges indexed lookup preserves exact behavior
# =====================================================================


def _reference_one_hop_edges(
    tracer: IntraFunctionFlowTracer,
    *,
    source_fn_fqn: str,
    sink_fn_fqn: str,
) -> tuple[tuple[ValueFlowEdge, ...], list[AnalysisGap], bool]:
    """Golden reference: the pre-FLAW-261 full-scan implementation.

    Reuses the tracer's own bridge-construction helpers, so the ONLY thing
    that differs from the production ``_one_hop_edges`` is the edge-selection
    strategy — a full linear scan of every call edge here, versus the new
    once-built ``(caller_fqn, callee_fqn)`` index in production.  Any drift in
    the returned edges, their order, the gaps, or ``has_direct_call`` is a
    behavior change and therefore a bug in the optimization.
    """
    source_edges = tracer._edges_by_fn.get(source_fn_fqn, ())
    sink_edges = tracer._edges_by_fn.get(sink_fn_fqn, ())
    relevant_edges = (*source_edges, *sink_edges)
    bridge_edges: list[ValueFlowEdge] = []
    gaps: list[AnalysisGap] = []
    has_direct_call = False
    assert tracer._call_graph is not None
    for call in tracer._call_graph.edges:
        if call.callee_fqn is None:
            continue
        if call.caller_fqn == source_fn_fqn and call.callee_fqn == sink_fn_fqn:
            has_direct_call = True
            param_edges, param_gaps = tracer._argument_parameter_edges(call)
            bridge_edges.extend(param_edges)
            gaps.extend(param_gaps)
        if call.caller_fqn == sink_fn_fqn and call.callee_fqn == source_fn_fqn:
            has_direct_call = True
            return_edges, return_gaps = tracer._return_call_edges(
                call, callee_edges=source_edges, caller_edges=sink_edges
            )
            bridge_edges.extend(return_edges)
            gaps.extend(return_gaps)
    return (*relevant_edges, *bridge_edges), gaps, has_direct_call


class TestOneHopEdgesIndexEquivalence:
    """FLAW-261: ``_one_hop_edges`` swaps a per-query O(edges) scan for a
    once-built ``(caller, callee)`` index.  These tests pin that it is a pure
    performance refactor — the indexed result is identical, edge-for-edge and
    in the same order, to the old full scan (the golden reference above).  Edge
    order is load-bearing: ``FunctionFlowIndex.bfs_path`` tie-breaks on it, so a
    reordering would silently change which flow path a rule reports.
    """

    def _assert_equivalent(
        self,
        tracer: IntraFunctionFlowTracer,
        *,
        source_fn_fqn: str,
        sink_fn_fqn: str,
    ) -> tuple[tuple[ValueFlowEdge, ...], list[AnalysisGap], bool]:
        expected_edges, expected_gaps, expected_direct = _reference_one_hop_edges(
            tracer, source_fn_fqn=source_fn_fqn, sink_fn_fqn=sink_fn_fqn
        )
        actual_edges, actual_gaps, actual_direct = tracer._one_hop_edges(
            source_fn_fqn=source_fn_fqn, sink_fn_fqn=sink_fn_fqn
        )
        # Exact equality including order — frozen dataclasses compare by value.
        assert actual_edges == expected_edges
        assert actual_gaps == expected_gaps
        assert actual_direct == expected_direct
        return actual_edges, actual_gaps, actual_direct

    def test_forward_call_matches_reference(self) -> None:
        """A single source→sink call: arg→param bridge identical to the scan."""
        call = _call_edge(
            "mod.a",
            "mod.b",
            line=5,
            call_expression="b",
            arguments=(_call_arg("ua", 5),),
        )
        vfg = ValueFlowGraph((_edge("ua", 5, "b", 5, kind=FlowKind.ARGUMENT, fn_fqn="mod.a"),))
        tracer = IntraFunctionFlowTracer(
            vfg,
            call_graph=CallGraph((call,)),
            functions=(_function("mod.b", params=(_param("pb", 0, line=10),)),),
        )
        edges, gaps, direct = self._assert_equivalent(
            tracer, source_fn_fqn="mod.a", sink_fn_fqn="mod.b"
        )
        assert direct is True
        # The arg→param bridge is present (ua reaches pb).
        assert any(e.source_expr == "ua" and e.target_expr == "pb" for e in edges)
        assert gaps == []

    def test_reverse_call_matches_reference(self) -> None:
        """A single sink→source call: return→result bridge identical to the scan."""
        call = _call_edge("mod.b", "mod.a", line=20, call_expression="a")
        vfg = ValueFlowGraph(
            (
                _edge("payload", 30, "ret", 31, kind=FlowKind.RETURN, fn_fqn="mod.a"),
                _edge("a()", 20, "res", 20, fn_fqn="mod.b"),
            )
        )
        tracer = IntraFunctionFlowTracer(
            vfg,
            call_graph=CallGraph((call,)),
            functions=(_function("mod.a"), _function("mod.b")),
        )
        _edges, _gaps, direct = self._assert_equivalent(
            tracer, source_fn_fqn="mod.a", sink_fn_fqn="mod.b"
        )
        assert direct is True

    def test_bidirectional_calls_preserve_global_bridge_order(self) -> None:
        """Mutual calls (a→b AND b→a) — the order-sensitive case.

        The reverse call sits at global index 0 and the forward call at index 2
        (a noise call between).  The old scan appended bridges in global edge
        order (return bridge first), so the index must merge its two direction
        buckets back into that order — not group all forward bridges then all
        reverse.  If the merge were dropped, ``edges`` would reorder and this
        equality (and the BFS path it feeds) would break.
        """
        calls = (
            _call_edge("mod.b", "mod.a", line=20, call_expression="a"),  # idx 0 reverse
            _call_edge("mod.c", "mod.d", line=99, call_expression="d"),  # idx 1 noise
            _call_edge(  # idx 2 forward
                "mod.a",
                "mod.b",
                line=5,
                call_expression="b",
                arguments=(_call_arg("ua", 5),),
            ),
        )
        vfg = ValueFlowGraph(
            (
                _edge("ua", 5, "b", 5, kind=FlowKind.ARGUMENT, fn_fqn="mod.a"),
                _edge("payload", 30, "ret", 31, kind=FlowKind.RETURN, fn_fqn="mod.a"),
                _edge("a()", 20, "res", 20, fn_fqn="mod.b"),
            )
        )
        tracer = IntraFunctionFlowTracer(
            vfg,
            call_graph=CallGraph(calls),
            functions=(
                _function("mod.b", params=(_param("pb", 0, line=10),)),
                _function("mod.a"),
            ),
        )
        edges, _gaps, direct = self._assert_equivalent(
            tracer, source_fn_fqn="mod.a", sink_fn_fqn="mod.b"
        )
        assert direct is True
        # Both bridges present; the reverse (return→result) bridge precedes the
        # forward (arg→param) bridge, matching the global call order.
        bridge_pairs = [
            (e.source_expr, e.target_expr) for e in edges if e.containing_function_fqn is None
        ]
        assert bridge_pairs.index(("ret", "a()")) < bridge_pairs.index(("ua", "pb"))

    def test_noise_and_unresolved_calls_excluded(self) -> None:
        """Unrelated calls and unresolved (callee=None) calls never leak in.

        The index keys on resolved ``(caller, callee)`` pairs only; an
        unresolved call from the source function is skipped exactly as the old
        ``callee_fqn is None: continue`` did, and calls between other functions
        are simply absent from the two looked-up buckets.
        """
        calls = (
            _call_edge("mod.x", "mod.y", line=1, call_expression="y"),  # unrelated
            _call_edge("mod.a", None, line=2, call_expression="dyn[k]()"),  # unresolved
            _call_edge(
                "mod.a",
                "mod.b",
                line=5,
                call_expression="b",
                arguments=(_call_arg("ua", 5),),
            ),
            _call_edge("mod.b", "mod.z", line=8, call_expression="z"),  # unrelated
        )
        vfg = ValueFlowGraph(
            (
                _edge("ua", 5, "b", 5, kind=FlowKind.ARGUMENT, fn_fqn="mod.a"),
                _edge("noise", 1, "n2", 1, fn_fqn="mod.x"),
            )
        )
        tracer = IntraFunctionFlowTracer(
            vfg,
            call_graph=CallGraph(calls),
            functions=(_function("mod.b", params=(_param("pb", 0, line=10),)),),
        )
        edges, gaps, direct = self._assert_equivalent(
            tracer, source_fn_fqn="mod.a", sink_fn_fqn="mod.b"
        )
        assert direct is True
        # No edge from the unrelated mod.x / mod.y / mod.z functions sneaks in.
        assert all("dyn[k]" not in e.source_expr for e in edges)
        assert gaps == []

    def test_no_direct_call_returns_no_bridges(self) -> None:
        """Two functions with no direct call between them: no bridges, not direct."""
        calls = (
            _call_edge("mod.a", "mod.c", line=5, call_expression="c"),
            _call_edge("mod.d", "mod.b", line=8, call_expression="b"),
        )
        vfg = ValueFlowGraph(
            (
                _edge("p", 5, "q", 5, fn_fqn="mod.a"),
                _edge("r", 8, "s", 8, fn_fqn="mod.b"),
            )
        )
        tracer = IntraFunctionFlowTracer(
            vfg,
            call_graph=CallGraph(calls),
            functions=(_function("mod.b"), _function("mod.c")),
        )
        edges, gaps, direct = self._assert_equivalent(
            tracer, source_fn_fqn="mod.a", sink_fn_fqn="mod.b"
        )
        assert direct is False
        # Only the two functions' own VFG edges, no synthetic bridges.
        assert all(e.containing_function_fqn is not None for e in edges)
        assert gaps == []

    def test_pair_index_built_once_and_reused(self) -> None:
        """The index is lazy, then memoized and shared across queries."""
        calls = (
            _call_edge(
                "mod.a",
                "mod.b",
                line=5,
                call_expression="b",
                arguments=(_call_arg("ua", 5),),
            ),
        )
        vfg = ValueFlowGraph((_edge("ua", 5, "b", 5, kind=FlowKind.ARGUMENT, fn_fqn="mod.a"),))
        tracer = IntraFunctionFlowTracer(
            vfg,
            call_graph=CallGraph(calls),
            functions=(_function("mod.b", params=(_param("pb", 0, line=10),)),),
        )
        assert tracer._calls_by_pair is None  # not built until first use
        tracer._one_hop_edges(source_fn_fqn="mod.a", sink_fn_fqn="mod.b")
        built = tracer._calls_by_pair
        assert built is not None
        assert ("mod.a", "mod.b") in built
        tracer._one_hop_edges(source_fn_fqn="mod.a", sink_fn_fqn="mod.b")
        assert tracer._calls_by_pair is built  # reused, not rebuilt


# =====================================================================
# FLAW-283: same-function one-hop edge set + index memoization
# =====================================================================


def _reference_same_function_one_hop_edges(
    tracer: IntraFunctionFlowTracer,
    *,
    fn_fqn: str,
) -> tuple[tuple[ValueFlowEdge, ...], tuple[AnalysisGap, ...], bool]:
    """Golden reference: the pre-FLAW-283 uncached same-function computation.

    A faithful reimplementation of the original ``_same_function_one_hop_edges``
    body, reusing the tracer's own bridge helpers.  The ONLY thing that differs
    from the production memoized method is that this recomputes from scratch on
    every call instead of returning a cached entry.  Any drift in the edges,
    their order, the gaps, or ``has_direct_call`` is a behavior change and
    therefore a bug in the optimization.
    """
    caller_edges = tracer._edges_by_fn.get(fn_fqn, ())
    relevant_edges: list[ValueFlowEdge] = [*caller_edges]
    bridge_edges: list[ValueFlowEdge] = []
    gaps: list[AnalysisGap] = []
    has_direct_call = False
    assert tracer._call_graph is not None
    for call in tracer._call_graph.edges_from(fn_fqn):
        if call.callee_fqn is None:
            gaps.append(_unresolved_callee_gap(call, caller_fqn=fn_fqn))
            continue
        if call.callee_fqn == fn_fqn:
            continue  # self-recursion: resolved target, no new frame to bridge
        has_direct_call = True
        callee_edges = tracer._edges_by_fn.get(call.callee_fqn, ())
        relevant_edges.extend(callee_edges)
        param_edges, param_gaps = tracer._argument_parameter_edges(call)
        return_edges, return_gaps = tracer._return_call_edges(
            call, callee_edges=callee_edges, caller_edges=caller_edges
        )
        bridge_edges.extend(param_edges)
        bridge_edges.extend(return_edges)
        gaps.extend(param_gaps)
        gaps.extend(return_gaps)
    return (*relevant_edges, *bridge_edges), tuple(gaps), has_direct_call


class TestSameFunctionOneHopMemoization:
    """FLAW-283: the same-function one-hop branch (``source_fn == sink_fn``)
    memoizes its edge set and the ``FunctionFlowIndex`` over it by ``fn_fqn``.

    These pin that it is a pure performance refactor: the memoized result is
    identical — edge-for-edge, in the same order, plus gaps and
    ``has_direct_call`` — to a fresh full recompute (the golden reference), and
    the caches are built once then reused.  Edge order is load-bearing
    (``FunctionFlowIndex.bfs_path`` tie-breaks on it), so a reordering would
    silently change which flow path a rule reports.
    """

    def _build_tracer(self) -> IntraFunctionFlowTracer:
        """``mod.handler`` calls a resolved helper, an unresolved dynamic target
        (a gap), and itself (self-recursion, skipped) — exercising every branch
        of the same-function edge computation.  Its source and sink endpoints
        are present-but-disconnected so the intra-function trace falls through
        to the one-hop path."""
        calls = (
            _call_edge(
                "mod.handler",
                "mod.helper",
                line=7,
                call_expression="helper",
                arguments=(_call_arg("user_input", 7),),
            ),
            _call_edge(
                "mod.handler",
                None,
                line=8,
                call_expression="dispatch[name](x)",
                arguments=(_call_arg("x", 8),),
            ),
            _call_edge("mod.handler", "mod.handler", line=9, call_expression="handler"),
        )
        vfg = ValueFlowGraph(
            (
                _edge("user_input", 6, "scratch", 6, fn_fqn="mod.handler"),
                _edge("scratch2", 8, "result", 8, fn_fqn="mod.handler"),
                _edge("payload", 30, "ret", 31, kind=FlowKind.RETURN, fn_fqn="mod.helper"),
            )
        )
        return IntraFunctionFlowTracer(
            vfg,
            call_graph=CallGraph(calls),
            functions=(
                _function("mod.helper", params=(_param("query", 0, line=10),)),
                _function("mod.handler"),
            ),
        )

    def test_edges_match_reference(self) -> None:
        """The memoized edge set equals the golden reference (edges, order, gaps,
        has_direct_call)."""
        tracer = self._build_tracer()
        expected = _reference_same_function_one_hop_edges(tracer, fn_fqn="mod.handler")
        actual = tracer._same_function_one_hop_edges(fn_fqn="mod.handler")
        # Exact equality including order — frozen dataclasses compare by value.
        assert actual == expected
        edges, gap_tuple, direct = expected
        assert direct is True
        # The unresolved dynamic call surfaces an explicit gap (FN-safety).
        assert any("unresolved call target" in g.message for g in gap_tuple)
        # The arg→param bridge (user_input → query) is present.
        assert any(e.source_expr == "user_input" and e.target_expr == "query" for e in edges)
        # Gaps are an immutable tuple, not a mutable list.
        assert isinstance(gap_tuple, tuple)

    def test_edges_cache_built_once_and_reused(self) -> None:
        """The edge set is memoized: a second query returns the same object."""
        tracer = self._build_tracer()
        assert tracer._same_fn_one_hop_cache == {}  # lazy
        first = tracer._same_function_one_hop_edges(fn_fqn="mod.handler")
        assert "mod.handler" in tracer._same_fn_one_hop_cache
        second = tracer._same_function_one_hop_edges(fn_fqn="mod.handler")
        assert second is first  # reused, not recomputed

    def test_index_cache_built_once_and_reused(self) -> None:
        """The same-function ``FunctionFlowIndex`` is memoized by fn_fqn."""
        tracer = self._build_tracer()
        edges, _gaps, _direct = tracer._same_function_one_hop_edges(fn_fqn="mod.handler")
        assert tracer._same_fn_one_hop_index_cache == {}  # lazy
        idx1 = tracer._same_function_one_hop_index("mod.handler", edges)
        assert tracer._same_fn_one_hop_index_cache.get("mod.handler") is idx1
        idx2 = tracer._same_function_one_hop_index("mod.handler", edges)
        assert idx2 is idx1  # reused, not rebuilt

    def test_trace_one_hop_reuses_index_across_queries(self) -> None:
        """Repeated same-function one-hop queries share one cached index.

        Both queries reach the ``has_direct_call`` branch (the resolved
        ``mod.helper`` call), which builds and caches the index for the
        function; the second must reuse it rather than rebuild.
        """
        tracer = self._build_tracer()

        def _query() -> FlowTrace:
            return tracer.trace_one_hop(
                source_location=_span("app.py", 6),
                source_expr="user_input",
                sink_location=_span("app.py", 8),
                sink_expr="result",
                source_fn_fqn="mod.handler",
                sink_fn_fqn="mod.handler",
            )

        _query()
        idx = tracer._same_fn_one_hop_index_cache.get("mod.handler")
        assert idx is not None  # built on the first one-hop query
        _query()
        assert tracer._same_fn_one_hop_index_cache.get("mod.handler") is idx  # reused

    def test_memoized_result_identical_across_multiple_functions(self) -> None:
        """Each function gets its own correct cached entry (no cross-talk)."""
        tracer = self._build_tracer()
        for fqn in ("mod.handler", "mod.helper", "mod.absent"):
            expected = _reference_same_function_one_hop_edges(tracer, fn_fqn=fqn)
            assert tracer._same_function_one_hop_edges(fn_fqn=fqn) == expected
