"""Repository-local flow query engine (``_SemanticFlowEngine``).

Extracted from ``flawed._semantic.__init__`` (FLAW-078) with no behaviour
change: this is the proxy/flow-engine assembly that backs public
``ValueHandle`` flow queries, plus the module-level helpers it relies on.
``ConcreteRepoView`` constructs ``_SemanticFlowEngine`` and is re-exported,
along with ``_merge_auth_inference``, back into the package ``__init__``.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from typing import TYPE_CHECKING

from flawed._index._graphs import ValueFlowGraph
from flawed._index._types import ExtractionProvenance, FlowKind, SourceSpan, ValueFlowEdge
from flawed._semantic._auth_inference import infer_custom_auth_checks
from flawed._semantic._collections import (
    ConcreteFunctionCollection,
    ConcreteRouteCollection,
    _source_matches,
)
from flawed._semantic._conversion_utils import dedupe_domain as _dedupe_domain
from flawed._semantic._expr_cache import parse_expression as _parse_expression
from flawed._semantic._flow_tracer import IntraFunctionFlowTracer
from flawed._semantic._provider_engine import (
    ProviderEngineResult,
    ProviderPhase,
)
from flawed._semantic._scope import dedupe_gaps
from flawed.flow import (
    FlowTrace,
    ValueHandle,
    ValuePreservationResult,
    attach_flow_context,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flawed._index import CodeIndex
    from flawed._index._graphs import CallGraph
    from flawed._index._types import FunctionRecord
    from flawed._semantic._flow_propagation import (
        FlowPropagationEdge,
    )
    from flawed.conditions import Condition
    from flawed.core import AnalysisGap, Location
    from flawed.effects import Effect
    from flawed.function import Function
    from flawed.inputs import InputRead, InputSource


class _SemanticFlowEngine:
    """Repository-local flow query service used by public ValueHandles."""

    __slots__ = (
        "_derived_from_trace_cache",
        "_edges_by_file_line",
        "_input_reads",
        "_preservation_gap_cache",
        "_sink_expression_cache",
        "_source_expression_cache",
        "_target_expr_keys",
        "_trace_cache",
        "_tracer",
    )

    def __init__(
        self,
        *,
        value_flow: ValueFlowGraph,
        call_graph: CallGraph,
        function_records: tuple[FunctionRecord, ...],
        functions: ConcreteFunctionCollection,
        routes: ConcreteRouteCollection,
        flow_propagators: tuple[FlowPropagationEdge, ...] = (),
    ) -> None:
        value_flow = _with_flow_propagators(value_flow, flow_propagators)
        self._edges_by_file_line = _index_value_flow_edges_by_line(value_flow.edges)
        self._target_expr_keys = _index_target_expr_keys(value_flow.edges)
        self._source_expression_cache: dict[tuple[str, int, str], tuple[str, ...]] = {}
        self._sink_expression_cache: dict[tuple[str, int, str, bool], tuple[str, ...]] = {}
        self._trace_cache: dict[
            tuple[
                tuple[Location, str, str | None, bool],
                tuple[Location, str, str | None, bool],
            ],
            FlowTrace,
        ] = {}
        self._derived_from_trace_cache: dict[
            tuple[tuple[Location, str, str | None, bool], InputSource], FlowTrace
        ] = {}
        self._preservation_gap_cache: dict[
            tuple[str, int, str, str, int, str], tuple[AnalysisGap, ...]
        ] = {}
        self._tracer = IntraFunctionFlowTracer(
            value_flow,
            call_graph=call_graph,
            functions=function_records,
        )
        self._input_reads = _collect_input_reads(functions, routes)
        self._attach_context(functions, routes)

    @property
    def flow_query_stats(self) -> tuple[int, int]:
        """``(flow_query_count, bfs_count)`` for per-rule flow telemetry (FLAW-194).

        Delegates to the scan-scoped tracer counter; pure observation, never
        affects a trace result.
        """
        return self._tracer.flow_query_stats

    def trace(self, source: ValueHandle, sink: ValueHandle) -> FlowTrace:
        """Trace between two handles, conservatively returning unreachable."""
        cache_key = (_handle_cache_key(source), _handle_cache_key(sink))
        cached = self._trace_cache.get(cache_key)
        if cached is not None:
            return cached

        source_fqn = _handle_function_fqn(source)
        sink_fqn = _handle_function_fqn(sink)
        if source_fqn is not None and sink_fqn is not None:
            trace = self._trace_one_hop(source, sink, source_fqn, sink_fqn)
            self._trace_cache[cache_key] = trace
            return trace

        fn_fqns = self._candidate_function_fqns(source, sink, source_fqn, sink_fqn)
        if not fn_fqns:
            trace = _unreachable_trace(source, sink)
            self._trace_cache[cache_key] = trace
            return trace

        source_span = _span_from_location(source.location)
        sink_span = _span_from_location(sink.location)
        gaps: list[AnalysisGap] = []
        for fn_fqn in fn_fqns:
            for source_expr in self._source_expressions(source):
                for sink_expr in self._sink_expressions(sink):
                    trace = self._tracer.trace(
                        source_location=source_span,
                        source_expr=source_expr,
                        sink_location=sink_span,
                        sink_expr=sink_expr,
                        fn_fqn=fn_fqn,
                    )
                    if trace.reachable:
                        self._trace_cache[cache_key] = trace
                        return trace
                    gaps.extend(trace.gaps)
        trace = _unreachable_trace(source, sink, gaps=dedupe_gaps(tuple(gaps)))
        self._trace_cache[cache_key] = trace
        return trace

    def _trace_one_hop(
        self,
        source: ValueHandle,
        sink: ValueHandle,
        source_fqn: str,
        sink_fqn: str,
    ) -> FlowTrace:
        """Trace cross-function flow, escalating from one-hop to multi-hop."""
        source_span = _span_from_location(source.location)
        sink_span = _span_from_location(sink.location)
        gaps: list[AnalysisGap] = []
        for source_expr in self._source_expressions(source):
            for sink_expr in self._sink_expressions(sink):
                trace = self._tracer.trace_one_hop(
                    source_location=source_span,
                    source_expr=source_expr,
                    sink_location=sink_span,
                    sink_expr=sink_expr,
                    source_fn_fqn=source_fqn,
                    sink_fn_fqn=sink_fqn,
                )
                if trace.reachable:
                    return trace
                gaps.extend(trace.gaps)

        # Escalate to multi-hop when one-hop fails across different functions.
        if source_fqn != sink_fqn:
            for source_expr in self._source_expressions(source):
                for sink_expr in self._sink_expressions(sink):
                    trace = self._tracer.trace_multi_hop(
                        source_location=source_span,
                        source_expr=source_expr,
                        sink_location=sink_span,
                        sink_expr=sink_expr,
                        source_fn_fqn=source_fqn,
                        sink_fn_fqn=sink_fqn,
                    )
                    if trace.reachable:
                        return trace
                    gaps.extend(trace.gaps)

        return _unreachable_trace(source, sink, gaps=dedupe_gaps(tuple(gaps)))

    def trace_locations(self, source: Location, sink: Location) -> FlowTrace:
        """Trace by locations, inferring source/sink expressions from L1 edges."""
        source_handle = attach_flow_context(
            ValueHandle(location=source, expression=_first_source_expr(self._edges_at(source))),
            trace_flow=self.trace,
            derived_from=self.derived_from,
            trace_derived_from=self.trace_derived_from,
            broad_sink=True,
        )
        sink_handle = attach_flow_context(
            ValueHandle(location=sink, expression=_first_sink_expr(self._edges_at(sink))),
            trace_flow=self.trace,
            derived_from=self.derived_from,
            trace_derived_from=self.trace_derived_from,
            broad_sink=True,
        )
        return self.trace(source_handle, sink_handle)

    def derived_from(self, handle: ValueHandle, source: InputSource) -> bool:
        """Return True when any matching input read reaches *handle*.

        Boolean projection of :meth:`trace_derived_from` (one source of truth):
        a rule that needs to tell "no matching provenance" apart from "could
        not analyze the provenance" calls :meth:`trace_derived_from` and
        inspects :attr:`~flawed.flow.FlowTrace.gaps`.
        """
        return self.trace_derived_from(handle, source).reachable

    def trace_derived_from(self, handle: ValueHandle, source: InputSource) -> FlowTrace:
        """Gap-carrying provenance: trace matching input reads to *handle*.

        The ``reachable`` flag is byte-identical to :meth:`derived_from`, but
        the trace additionally carries the :class:`~flawed.core.AnalysisGap`
        objects hit while attempting the per-read flow traces.  When a matching
        read is proven to reach *handle* the result is that read's
        :meth:`~flawed.flow.ValueHandle.trace_flow_to` trace (real source and
        path); when none reach, the gaps from every attempted matching read are
        accumulated so a rule can surface an honest gap instead of a confident
        negative (false-negative-first).
        """
        cache_key = (_handle_cache_key(handle), source)
        cached = self._derived_from_trace_cache.get(cache_key)
        if cached is not None:
            return cached

        # FLAW-200 prefilter. ``flows_to(handle)`` answers
        # ``same_origin(handle) OR <BFS reachable>``. The tracer's BFS only ever
        # arrives at a node by traversing an edge that *targets* it, and a node
        # is recognised as the sink (whether matched as a target or, via
        # ``_is_sink_use``, as a later source) only once arrival has happened.
        # So an expression that is never any edge's ``target_expr`` has nothing
        # flowing into it at any site and the BFS cannot reach it; the only way
        # ``flows_to`` can still be True is the seed-coincides-with-sink case,
        # i.e. ``same_origin``. When that holds, the per-read interprocedural BFS
        # cannot change the answer, so we replace it with ``same_origin`` —
        # byte-identical, and it removes the dominant pairwise-correlation cost: a Cartesian
        # of BFS traces over every call argument, most of which are
        # literals/constants/unconnected values that provably cannot derive from
        # an input source. Broad-sink handles expand their sink-expression set
        # beyond ``handle.expression`` and so keep the full check.
        #
        # ``same_origin`` carries no analysis that could be incomplete, so the
        # prefilter path can never hide a gap — preserving the byte-identical
        # answer while keeping ``trace_derived_from``'s gap accounting honest.
        bfs_unreachable = (
            not _handle_broad_sink(handle) and handle.expression not in self._target_expr_keys
        )

        gaps: list[AnalysisGap] = []
        result: FlowTrace | None = None
        for read in self._input_reads:
            if not _source_matches(read.source, source):
                continue
            if bfs_unreachable:
                if read.value.same_origin(handle):
                    result = FlowTrace(source=read.value, sink=handle, steps=(), reachable=True)
                    break
                continue
            trace = read.value.trace_flow_to(handle)
            if trace.reachable:
                result = trace
                break
            gaps.extend(trace.gaps)

        if result is None:
            result = FlowTrace(
                source=handle,
                sink=handle,
                steps=(),
                reachable=False,
                gaps=dedupe_gaps(tuple(gaps)),
            )
        self._derived_from_trace_cache[cache_key] = result
        return result

    def preserves_whole_value(
        self, source: ValueHandle, sink: ValueHandle
    ) -> ValuePreservationResult:
        """Return whether *source* reaches *sink* through preserving edges only."""
        source_fqn = _handle_function_fqn(source)
        sink_fqn = _handle_function_fqn(sink)
        if source_fqn is not None and sink_fqn is not None:
            return self._preserves_whole_value_one_hop(source, sink, source_fqn, sink_fqn)

        fn_fqns = self._candidate_function_fqns(source, sink, source_fqn, sink_fqn)
        if not fn_fqns:
            return ValuePreservationResult(preserved=False)

        source_span = _span_from_location(source.location)
        sink_span = _span_from_location(sink.location)
        gaps: list[AnalysisGap] = []
        for fn_fqn in fn_fqns:
            for sink_expr in self._sink_expressions(sink):
                trace = self._tracer.trace(
                    source_location=source_span,
                    source_expr=source.expression,
                    sink_location=sink_span,
                    sink_expr=sink_expr,
                    fn_fqn=fn_fqn,
                    exact_source=True,
                )
                if _trace_preserves_whole_value(trace, sink):
                    return ValuePreservationResult(preserved=True)
                gaps.extend(trace.gaps)
        return ValuePreservationResult(
            preserved=False, gaps=self._preservation_gaps(source, sink, gaps)
        )

    def _preserves_whole_value_one_hop(
        self,
        source: ValueHandle,
        sink: ValueHandle,
        source_fqn: str,
        sink_fqn: str,
    ) -> ValuePreservationResult:
        """Check preserving flow with exact source expression across call edges."""
        source_span = _span_from_location(source.location)
        sink_span = _span_from_location(sink.location)
        gaps: list[AnalysisGap] = []
        for sink_expr in self._sink_expressions(sink):
            trace = self._tracer.trace_one_hop(
                source_location=source_span,
                source_expr=source.expression,
                sink_location=sink_span,
                sink_expr=sink_expr,
                source_fn_fqn=source_fqn,
                sink_fn_fqn=sink_fqn,
                exact_source=True,
            )
            if _trace_preserves_whole_value(trace, sink):
                return ValuePreservationResult(preserved=True)
            gaps.extend(trace.gaps)

        if source_fqn != sink_fqn:
            for sink_expr in self._sink_expressions(sink):
                trace = self._tracer.trace_multi_hop(
                    source_location=source_span,
                    source_expr=source.expression,
                    sink_location=sink_span,
                    sink_expr=sink_expr,
                    source_fn_fqn=source_fqn,
                    sink_fn_fqn=sink_fqn,
                    exact_source=True,
                )
                if _trace_preserves_whole_value(trace, sink):
                    return ValuePreservationResult(preserved=True)
                gaps.extend(trace.gaps)

        return ValuePreservationResult(
            preserved=False, gaps=self._preservation_gaps(source, sink, gaps)
        )

    def _preservation_gaps(
        self,
        source: ValueHandle,
        sink: ValueHandle,
        gaps: list[AnalysisGap],
    ) -> tuple[AnalysisGap, ...]:
        """Dedupe and memoize preservation gaps for repeated collection filtering."""
        key = (
            source.location.file,
            source.location.line,
            source.expression,
            sink.location.file,
            sink.location.line,
            sink.expression,
        )
        cached = self._preservation_gap_cache.get(key)
        if cached is not None:
            return cached
        result = dedupe_gaps(tuple(gaps))
        self._preservation_gap_cache[key] = result
        return result

    def _attach_context(
        self,
        functions: ConcreteFunctionCollection,
        routes: ConcreteRouteCollection,
    ) -> None:
        for fn in functions:
            object.__setattr__(fn, "_trace_flow", self.trace)
            object.__setattr__(fn, "_preserves_whole_value", self.preserves_whole_value)
            object.__setattr__(fn, "_derived_from", self.derived_from)
            object.__setattr__(fn, "_trace_derived_from", self.trace_derived_from)
        for read in self._input_reads:
            _attach_read_context(read, self)
        for effect in _collect_effects(functions, routes):
            _attach_effect_context(effect, self)

    def _candidate_function_fqns(
        self,
        source: ValueHandle,
        sink: ValueHandle,
        source_fqn: str | None,
        sink_fqn: str | None,
    ) -> tuple[str, ...]:
        if source_fqn is not None and source_fqn == sink_fqn:
            return (source_fqn,)
        if source_fqn is not None and sink_fqn is None:
            return (source_fqn,)
        if sink_fqn is not None and source_fqn is None:
            return (sink_fqn,)
        source_fqns = {
            edge.containing_function_fqn
            for edge in self._edges_at(source.location)
            if edge.containing_function_fqn is not None
        }
        sink_fqns = {
            edge.containing_function_fqn
            for edge in self._edges_at(sink.location)
            if edge.containing_function_fqn is not None
        }
        return tuple(sorted(source_fqns & sink_fqns))

    def _source_expressions(self, handle: ValueHandle) -> tuple[str, ...]:
        key = _expression_cache_key(handle)
        cached = self._source_expression_cache.get(key)
        if cached is not None:
            return cached

        expressions = [handle.expression]
        for edge in self._edges_at(handle.location):
            if _same_line(edge.source_location, handle.location):
                expressions.append(edge.source_expr)
            if _same_line(edge.target_location, handle.location):
                expressions.append(edge.target_expr)
        result = _dedupe_strings(expressions)
        self._source_expression_cache[key] = result
        return result

    def _sink_expressions(self, handle: ValueHandle) -> tuple[str, ...]:
        broad_sink = _handle_broad_sink(handle)
        key = (*_expression_cache_key(handle), broad_sink)
        cached = self._sink_expression_cache.get(key)
        if cached is not None:
            return cached

        expressions = [handle.expression]
        if broad_sink:
            expressions.extend(_embedded_value_names(handle.expression))
            for edge in self._edges_at(handle.location):
                if _same_line(edge.target_location, handle.location):
                    expressions.append(edge.target_expr)
                if _same_line(edge.source_location, handle.location):
                    expressions.append(edge.source_expr)
        result = _dedupe_strings(expressions)
        self._sink_expression_cache[key] = result
        return result

    def _edges_at(self, location: Location) -> tuple[ValueFlowEdge, ...]:
        return self._edges_by_file_line.get((location.file, location.line), ())


def _with_flow_propagators(
    value_flow: ValueFlowGraph,
    propagators: tuple[FlowPropagationEdge, ...],
) -> ValueFlowGraph:
    if not propagators:
        return value_flow
    return ValueFlowGraph(
        (
            *value_flow.edges,
            *(_flow_propagator_to_value_flow_edge(edge) for edge in propagators),
        )
    )


def _flow_propagator_to_value_flow_edge(edge: FlowPropagationEdge) -> ValueFlowEdge:
    return ValueFlowEdge(
        source_expr=edge.source_expression,
        source_location=edge.source_location,
        target_expr=edge.target_expression,
        target_location=edge.target_location,
        kind=FlowKind.ALIAS,
        containing_function_fqn=edge.containing_function_fqn,
        provenance=ExtractionProvenance(
            producer="semantic_flow_propagator",
            producer_version="1",
            artifact=edge.provider_id,
        ),
        callsite_callee_fqn=edge.canonical_fqn,
        callsite_expr=edge.observed_fqn,
    )


def _index_value_flow_edges_by_line(
    edges: tuple[ValueFlowEdge, ...],
) -> dict[tuple[str, int], tuple[ValueFlowEdge, ...]]:
    grouped: dict[tuple[str, int], list[ValueFlowEdge]] = defaultdict(list)
    for edge in edges:
        source_key = (edge.source_location.file, edge.source_location.line)
        target_key = (edge.target_location.file, edge.target_location.line)
        grouped[source_key].append(edge)
        if target_key != source_key:
            grouped[target_key].append(edge)
    return {key: tuple(bucket) for key, bucket in grouped.items()}


def _index_target_expr_keys(
    edges: tuple[ValueFlowEdge, ...],
) -> frozenset[str]:
    """Index every expression that appears as a value-flow edge *target*.

    Keyed by expression text alone (not location): the tracer links edges by
    name across lines, so a variable that is a target at its definition line is
    reachable at every *use* line (via ``_is_sink_use``). An expression that is
    **never** any edge's target therefore has nothing flowing into it anywhere —
    a literal, an unassigned constant/global, or an unconnected value — and so
    cannot be reached by the BFS at any site. This is intentionally
    over-inclusive (a name that is a target in one function is treated as
    connected everywhere): that only ever causes the full check to run, never a
    wrongful skip, keeping :meth:`_SemanticFlowEngine.derived_from` byte-identical.
    """
    return frozenset(edge.target_expr for edge in edges)


def _expression_cache_key(handle: ValueHandle) -> tuple[str, int, str]:
    return (handle.location.file, handle.location.line, handle.expression)


def _collect_input_reads(
    functions: ConcreteFunctionCollection,
    routes: ConcreteRouteCollection,
) -> tuple[InputRead, ...]:
    reads: list[InputRead] = []
    for fn in functions:
        reads.extend(fn.body.reads())
        reads.extend(fn.reachable.reads())
    for route in routes:
        reads.extend(route.body.reads())
        reads.extend(route.full_stack.reads())
    return _dedupe_domain(reads)


def _collect_effects(
    functions: ConcreteFunctionCollection,
    routes: ConcreteRouteCollection,
) -> tuple[Effect, ...]:
    effects: list[Effect] = []
    for fn in functions:
        effects.extend(fn.body.effects())
        effects.extend(fn.reachable.effects())
    for route in routes:
        effects.extend(route.body.effects())
        effects.extend(route.full_stack.effects())
    return _dedupe_domain(effects)


def _attach_read_context(read: InputRead, engine: _SemanticFlowEngine) -> None:
    object.__setattr__(read, "_trace_flow", engine.trace)
    object.__setattr__(read, "_derived_from", engine.derived_from)
    object.__setattr__(read, "_trace_derived_from", engine.trace_derived_from)
    attach_flow_context(
        read.value,
        trace_flow=engine.trace,
        derived_from=engine.derived_from,
        trace_derived_from=engine.trace_derived_from,
        function_fqn=read.function.fqn,
        input_source=read.source,
    )


def _attach_effect_context(effect: Effect, engine: _SemanticFlowEngine) -> None:
    object.__setattr__(effect, "_trace_flow", engine.trace)
    object.__setattr__(effect, "_derived_from", engine.derived_from)
    object.__setattr__(effect, "_trace_derived_from", engine.trace_derived_from)


def _span_from_location(location: Location) -> SourceSpan:
    return SourceSpan(
        file=location.file,
        line=location.line,
        column=location.column,
        end_line=location.end_line or location.line,
        end_column=location.end_column or location.column,
    )


def _same_line(span: SourceSpan, location: Location) -> bool:
    return span.file == location.file and span.line == location.line


def _handle_cache_key(handle: ValueHandle) -> tuple[Location, str, str | None, bool]:
    """Stable key for repository-local flow query memoization."""
    return (
        handle.location,
        handle.expression,
        _handle_function_fqn(handle),
        _handle_broad_sink(handle),
    )


def _handle_function_fqn(handle: ValueHandle) -> str | None:
    try:
        value = object.__getattribute__(handle, "_function_fqn")
    except AttributeError:
        return None
    return value if isinstance(value, str) else None


def _handle_broad_sink(handle: ValueHandle) -> bool:
    try:
        value = object.__getattribute__(handle, "_broad_sink")
    except AttributeError:
        return False
    return value is True


_WHOLE_VALUE_PRESERVING_STEP_KINDS = frozenset(
    {
        "alias",
        "assign",
        "annotated_assign",
        "chain",
        "return",
    }
)


def _trace_preserves_whole_value(trace: FlowTrace, sink: ValueHandle) -> bool:
    """Return true when a reachable trace contains only preserving steps."""
    if not trace.reachable:
        return False
    if not all(
        step.kind is None or step.kind in _WHOLE_VALUE_PRESERVING_STEP_KINDS
        for step in trace.steps
    ):
        return False

    definition_location = _handle_definition_location(sink)
    if definition_location is None:
        return True
    preserved_location = _preserved_target_definition_location(trace)
    return preserved_location == definition_location


def _handle_definition_location(handle: ValueHandle) -> object | None:
    try:
        value: object = object.__getattribute__(handle, "_definition_location")
    except AttributeError:
        return None
    return value


def _preserved_target_definition_location(trace: FlowTrace) -> object | None:
    edge_steps = tuple(step for step in trace.steps if step.kind is not None)
    if not edge_steps:
        return None
    final_step = edge_steps[-1]
    if (
        final_step.kind == "alias"
        and final_step.location == trace.sink.location
        and len(edge_steps) >= 2
    ):
        return edge_steps[-2].location
    return final_step.location


def _dedupe_strings(expressions: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(expr for expr in expressions if expr))


def _embedded_value_names(expression: str) -> tuple[str, ...]:
    """Names embedded inside a broad sink expression, e.g. ``[email]``."""
    tree = _parse_expression(expression)
    if tree is None:
        return ()
    return tuple(dict.fromkeys(node.id for node in ast.walk(tree) if isinstance(node, ast.Name)))


def _first_source_expr(edges: tuple[ValueFlowEdge, ...]) -> str:
    if not edges:
        return ""
    return edges[0].source_expr


def _first_sink_expr(edges: tuple[ValueFlowEdge, ...]) -> str:
    if not edges:
        return ""
    return edges[-1].target_expr


def _unreachable_trace(
    source: ValueHandle,
    sink: ValueHandle,
    *,
    gaps: tuple[AnalysisGap, ...] = (),
) -> FlowTrace:
    return FlowTrace(source=source, sink=sink, steps=(), reachable=False, gaps=gaps)


def _merge_auth_inference(
    idx: CodeIndex,
    fn_by_fqn: Mapping[str, Function],
    engine_result: ProviderEngineResult,
    conditions_by_function: dict[str, list[Condition]],
    semantic_gaps: list[AnalysisGap],
) -> None:
    """Run custom auth decorator inference and merge results (DISC-090)."""
    auth_inference = infer_custom_auth_checks(
        idx,
        functions_by_fqn=fn_by_fqn,
        matched_check_fqns=_collect_matched_check_fqns(engine_result),
        known_auth_fqns=_collect_known_auth_fqns(engine_result),
    )
    for fqn, inferred_conditions in auth_inference.conditions_by_function.items():
        conditions_by_function.setdefault(fqn, []).extend(inferred_conditions)
    semantic_gaps.extend(auth_inference.gaps)


def _collect_matched_check_fqns(engine_result: ProviderEngineResult) -> frozenset[str]:
    """Collect canonical FQNs of decorators matched as provider security checks."""
    fqns: set[str] = set()
    for match in engine_result.matches:
        if match.phase == ProviderPhase.CHECKS:
            fqns.add(match.canonical_fqn)
            # Also include the observed FQN (pre-alias) so we don't
            # re-analyze something already matched under a different name.
            fqns.add(match.observed_fqn)
    return frozenset(fqns)


def _collect_known_auth_fqns(engine_result: ProviderEngineResult) -> frozenset[str]:
    """Collect FQNs of all known auth-related callees from provider patterns.

    These are used to detect delegation: if a custom decorator calls
    ``login_required`` internally, it's an auth check.
    """
    from flawed._semantic.providers import SecurityCheckPattern

    fqns: set[str] = set()
    for match in engine_result.matches:
        if match.phase == ProviderPhase.CHECKS:
            descriptor = match.descriptor
            if isinstance(descriptor, SecurityCheckPattern):
                pattern_fqn = descriptor.fqn
                if isinstance(pattern_fqn, str):
                    fqns.add(pattern_fqn)
                else:
                    fqns.update(pattern_fqn)
    return frozenset(fqns)
