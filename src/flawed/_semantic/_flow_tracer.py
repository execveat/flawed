"""Interprocedural value-flow tracer.

Traces data flow within and across function bodies using L1 ``ValueFlowGraph``
edges and the L1 call graph.  Produces L3 ``FlowStep`` and ``FlowTrace``
domain objects.

Three levels of tracing, from narrowest to broadest:

  * **Intra-function** (:meth:`trace`): BFS within a single function's
    value-flow edges.
  * **One-hop** (:meth:`trace_one_hop`): one direct call-boundary crossing —
    caller argument→callee parameter, callee return→caller call result.
  * **Multi-hop** (:meth:`trace_multi_hop`): bounded BFS over the call graph,
    stitching arg→param and return→result bridges at each boundary.  Enforces
    depth, visited-set, and timeout bounds to prevent unbounded traversal.

The tracer uses breadth-first search over a name-connected graph derived
from ``ValueFlowEdge`` records scoped to a single function, with cycle
detection and a configurable depth limit.

**Graph model**: L1 value-flow edges connect a *source expression* to a
*target expression* on the same or different lines.  Across lines, the
same variable name links edges: if edge A targets expression ``query``
and edge B sources expression ``query``, those edges are connected
regardless of their line numbers.  The BFS follows these name-based
links to trace multi-hop chains.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

from flawed._index._types import FlowKind, ValueFlowEdge
from flawed._semantic._conversion_utils import location
from flawed._semantic._flow_index import FunctionFlowIndex
from flawed._semantic._scope import dedupe_gaps
from flawed.core import AnalysisGap, GapKind
from flawed.flow import FlowStep, FlowTrace, ValueHandle

if TYPE_CHECKING:
    from collections.abc import Sequence

    from flawed._index._graphs import CallGraph, ValueFlowGraph
    from flawed._index._types import (
        CallArgument,
        CallEdge,
        FunctionRecord,
        Parameter,
        SourceSpan,
    )

_FLOW_KIND_DESCRIPTIONS: dict[str, str] = {
    "assign": "assigned to",
    "argument": "passed as argument to",
    "return": "returned from",
    "alias": "aliased as",
    "unpack": "unpacked into",
    "augmented_assign": "augmented-assigned to",
    "annotated_assign": "annotated-assigned to",
    "chain": "chained to",
    "comprehension_binding": "bound in comprehension to",
    "attribute_write": "written to attribute",
    "yield": "yielded as",
    "transform_input": "transformed into",
}


@dataclass
class FlowQueryCounter:
    """Scan-scoped tally of flow-query activity, for per-rule telemetry (FLAW-194).

    Pure observation: incrementing these counters never affects a ``FlowTrace``
    or any finding. One instance is owned by the per-scan flow engine (via the
    tracer); the L3 detector loop reads ``(flow_query_count, bfs_count)`` deltas
    around each rule to attribute flow cost to the rule that incurred it.

    * ``flow_query_count`` counts tracer entrypoint invocations (``trace`` /
      ``trace_one_hop`` / ``trace_multi_hop``) that actually reach the tracer.
      Queries the engine serves from its own handle-pair cache never get here,
      so a rule's delta reflects the *new* (uncached) flow work it triggered —
      the meaningful per-rule budget signal.
    * ``bfs_count`` counts real BFS traversals (``FunctionFlowIndex.bfs_path``
      calls), the dominant cost the FLAW-106 profiling identified (g071's ~25k
      provenance traversals). A query that short-circuits on a missing node or
      an empty function never reaches BFS, so ``bfs_count <= flow_query_count``
      is the expected shape and a high ratio flags an expensive rule.
    """

    flow_query_count: int = 0
    bfs_count: int = 0


_MAX_HOP_DEPTH = 5
"""Maximum call-graph hops for multi-hop traversal."""

_MULTI_HOP_TIMEOUT_S = 2.0
"""Wall-clock timeout in seconds for multi-hop traversal."""


class IntraFunctionFlowTracer:
    """Traces value flow within a single function using L1 edges.

    Constructed with a ``ValueFlowGraph`` (from ``CodeIndex.value_flow``).
    The :meth:`trace` method answers whether a value at a source location
    reaches a sink location within the same function, and if so, returns
    the chain of ``FlowStep`` objects describing the path.
    """

    __slots__ = (
        "_call_graph",
        "_calls_by_pair",
        "_counter",
        "_edges_by_fn",
        "_fn_index_cache",
        "_functions_by_fqn",
        "_intra_trace_cache",
        "_same_fn_one_hop_cache",
        "_same_fn_one_hop_index_cache",
        "_vfg",
    )

    def __init__(
        self,
        vfg: ValueFlowGraph,
        *,
        call_graph: CallGraph | None = None,
        functions: tuple[FunctionRecord, ...] = (),
        counter: FlowQueryCounter | None = None,
    ) -> None:
        self._vfg = vfg
        self._call_graph = call_graph
        # Scan-scoped flow-query telemetry (FLAW-194). Defaults to a private
        # counter so standalone construction (tests) works unchanged; the
        # per-scan engine passes its shared instance so the detector loop can
        # read per-rule deltas.
        self._counter = counter if counter is not None else FlowQueryCounter()
        self._functions_by_fqn = {fn.fqn: fn for fn in functions}
        # Pre-index edges by containing function for O(1) lookup.
        grouped: dict[str | None, list[ValueFlowEdge]] = {}
        for edge in vfg.edges:
            grouped.setdefault(edge.containing_function_fqn, []).append(edge)
        self._edges_by_fn: dict[str | None, tuple[ValueFlowEdge, ...]] = {
            k: tuple(v) for k, v in grouped.items()
        }
        # Scan-scoped caches (FLAW-106).  The tracer is constructed once per
        # scan and its inputs are immutable, so every query is a pure function
        # of its arguments — these caches only remove redundant work, never
        # change a result.  ``_fn_index_cache`` holds one precomputed lookup
        # index per function (built lazily); ``_intra_trace_cache`` memoizes the
        # deterministic intra-function ``trace`` result so the repeated
        # identical sub-queries issued by reads x effects / args x reads rule
        # loops collapse to a single computation.
        self._fn_index_cache: dict[str | None, FunctionFlowIndex] = {}
        self._intra_trace_cache: dict[
            tuple[str, SourceSpan, str, SourceSpan, str, bool], FlowTrace
        ] = {}
        # Lazily-built index of call edges keyed by ``(caller_fqn, callee_fqn)``
        # for O(1) direct-call lookup in ``_one_hop_edges`` (FLAW-261).  Built
        # once on first use and reused across all one-hop queries, replacing a
        # per-query linear scan of the entire call graph (O(hops x edges)).
        # Each entry preserves the call's global insertion order via a sequence
        # number so the bridge-edge ordering — which is BFS-significant — is
        # byte-for-byte identical to the old full-scan implementation.
        self._calls_by_pair: dict[tuple[str, str], list[tuple[int, CallEdge]]] | None = None
        # Same-function one-hop caches (FLAW-283).  When ``source_fn == sink_fn``
        # the one-hop edge set (``_same_function_one_hop_edges``) and the
        # ``FunctionFlowIndex`` over it are pure functions of ``fn_fqn`` plus the
        # tracer's immutable inputs — yet ``reads_flowing_to`` re-issued this on
        # every (read x sink) query across every route, making it O(queries x
        # edges).  Like ``_fn_index_cache``/``_calls_by_pair``, these memoize the
        # pure result keyed by ``fn_fqn``.  The *interprocedural* branch is
        # deliberately not cached here: its stitched edge set carries synthetic
        # bridges specific to the (source, sink) pair and so varies per query.
        self._same_fn_one_hop_cache: dict[
            str, tuple[tuple[ValueFlowEdge, ...], tuple[AnalysisGap, ...], bool]
        ] = {}
        self._same_fn_one_hop_index_cache: dict[str, FunctionFlowIndex] = {}

    @property
    def flow_query_stats(self) -> tuple[int, int]:
        """``(flow_query_count, bfs_count)`` snapshot for telemetry (FLAW-194)."""
        return (self._counter.flow_query_count, self._counter.bfs_count)

    def _function_index(self, fn_fqn: str | None) -> FunctionFlowIndex:
        """Return the cached per-function flow index, building it on first use."""
        index = self._fn_index_cache.get(fn_fqn)
        if index is None:
            index = FunctionFlowIndex(self._edges_by_fn.get(fn_fqn, ()))
            self._fn_index_cache[fn_fqn] = index
        return index

    def trace(
        self,
        *,
        source_location: SourceSpan,
        source_expr: str,
        sink_location: SourceSpan,
        sink_expr: str,
        fn_fqn: str,
        exact_source: bool = False,
    ) -> FlowTrace:
        """Trace intra-function flow from *source* to *sink*.

        Returns a ``FlowTrace`` with ``reachable=True`` and an ordered
        sequence of ``FlowStep`` objects if a path exists.  Returns
        ``reachable=False`` with empty steps otherwise.

        The trace is scoped to edges whose ``containing_function_fqn``
        matches *fn_fqn*.  Edges from other functions are ignored.
        """
        self._counter.flow_query_count += 1  # FLAW-194 telemetry (pure observation)
        cache_key = (
            fn_fqn,
            source_location,
            source_expr,
            sink_location,
            sink_expr,
            exact_source,
        )
        cached = self._intra_trace_cache.get(cache_key)
        if cached is not None:
            return cached

        result = self._trace_uncached(
            source_location=source_location,
            source_expr=source_expr,
            sink_location=sink_location,
            sink_expr=sink_expr,
            fn_fqn=fn_fqn,
            exact_source=exact_source,
        )
        self._intra_trace_cache[cache_key] = result
        return result

    def _trace_uncached(
        self,
        *,
        source_location: SourceSpan,
        source_expr: str,
        sink_location: SourceSpan,
        sink_expr: str,
        fn_fqn: str,
        exact_source: bool,
    ) -> FlowTrace:
        source_handle = ValueHandle(
            location=location(source_location),
            expression=source_expr,
        )
        sink_handle = ValueHandle(
            location=location(sink_location),
            expression=sink_expr,
        )

        index = self._function_index(fn_fqn)
        if index.is_empty:
            return FlowTrace(
                source=source_handle,
                sink=sink_handle,
                steps=(),
                reachable=False,
                gaps=(
                    _gap(
                        "no value-flow edges are available for function",
                        affected_location=source_location,
                        fn_fqn=fn_fqn,
                    ),
                ),
            )

        missing_node_gap = _missing_node_gap(
            index,
            source_location=source_location,
            source_expr=source_expr,
            sink_location=sink_location,
            sink_expr=sink_expr,
            fn_fqn=fn_fqn,
            exact_source=exact_source,
        )
        if missing_node_gap is not None:
            return FlowTrace(
                source=source_handle,
                sink=sink_handle,
                steps=(),
                reachable=False,
                gaps=(missing_node_gap,),
            )

        self._counter.bfs_count += 1  # FLAW-194: a real BFS traversal follows
        path = index.bfs_path(
            source_location=source_location,
            source_expr=source_expr,
            sink_location=sink_location,
            sink_expr=sink_expr,
            exact_source=exact_source,
        )

        if path is None:
            return FlowTrace(
                source=source_handle,
                sink=sink_handle,
                steps=(),
                reachable=False,
            )

        steps = _path_to_steps(path)
        return FlowTrace(
            source=source_handle,
            sink=sink_handle,
            steps=steps,
            reachable=True,
        )

    def trace_one_hop(
        self,
        *,
        source_location: SourceSpan,
        source_expr: str,
        sink_location: SourceSpan,
        sink_expr: str,
        source_fn_fqn: str,
        sink_fn_fqn: str,
        exact_source: bool = False,
    ) -> FlowTrace:
        """Trace flow with at most one direct call-boundary crossing.

        Supports the P6.2 stitches:

        - caller argument → matching callee parameter
        - callee return → caller expression receiving the call result

        This does not perform recursive call-graph traversal; for bounded
        multi-hop traversal see :meth:`trace_multi_hop`.
        """
        self._counter.flow_query_count += 1  # FLAW-194 telemetry (pure observation)
        if source_fn_fqn == sink_fn_fqn:
            intra_trace = self.trace(
                source_location=source_location,
                source_expr=source_expr,
                sink_location=sink_location,
                sink_expr=sink_expr,
                fn_fqn=source_fn_fqn,
                exact_source=exact_source,
            )
            if intra_trace.reachable or intra_trace.gaps:
                return intra_trace
            if self._call_graph is None:
                source_handle = ValueHandle(
                    location=location(source_location),
                    expression=source_expr,
                )
                sink_handle = ValueHandle(
                    location=location(sink_location),
                    expression=sink_expr,
                )
                return FlowTrace(
                    source=source_handle,
                    sink=sink_handle,
                    steps=(),
                    reachable=False,
                    gaps=(
                        _gap(
                            "call graph is unavailable for one-hop interprocedural tracing",
                            affected_location=source_location,
                            fn_fqn=source_fn_fqn,
                        ),
                    ),
                )

        source_handle = ValueHandle(
            location=location(source_location),
            expression=source_expr,
        )
        sink_handle = ValueHandle(
            location=location(sink_location),
            expression=sink_expr,
        )

        if self._call_graph is None:
            return FlowTrace(
                source=source_handle,
                sink=sink_handle,
                steps=(),
                reachable=False,
                gaps=(
                    _gap(
                        "call graph is unavailable for one-hop interprocedural tracing",
                        affected_location=source_location,
                        fn_fqn=f"{source_fn_fqn}->{sink_fn_fqn}",
                    ),
                ),
            )

        # The same-function branch returns immutable (cached) gaps; the
        # interprocedural branch returns a freshly-built list — both are consumed
        # uniformly via ``tuple(bridge_gaps)`` below.
        bridge_gaps: Sequence[AnalysisGap]
        same_function = source_fn_fqn == sink_fn_fqn
        if same_function:
            edges, bridge_gaps, has_direct_call = self._same_function_one_hop_edges(
                fn_fqn=source_fn_fqn,
            )
        else:
            edges, bridge_gaps, has_direct_call = self._one_hop_edges(
                source_fn_fqn=source_fn_fqn,
                sink_fn_fqn=sink_fn_fqn,
            )

        path = None
        gaps = dedupe_gaps(tuple(bridge_gaps))
        if has_direct_call:
            if same_function:
                # The same-function edge set is a pure function of ``fn_fqn``, so
                # its index is cached and reused across queries (FLAW-283).
                index = self._same_function_one_hop_index(source_fn_fqn, edges)
            else:
                # Interprocedural edge sets are stitched per query (they include
                # synthetic bridge edges) and so cannot be cached by function, but
                # a transient index still avoids rescanning the edge list twice.
                index = FunctionFlowIndex(edges)
            missing_node_gap = _missing_node_gap(
                index,
                source_location=source_location,
                source_expr=source_expr,
                sink_location=sink_location,
                sink_expr=sink_expr,
                fn_fqn=f"{source_fn_fqn}->{sink_fn_fqn}",
                exact_source=exact_source,
            )
            if missing_node_gap is not None:
                return FlowTrace(
                    source=source_handle,
                    sink=sink_handle,
                    steps=(),
                    reachable=False,
                    gaps=gaps or (missing_node_gap,),
                )

            self._counter.bfs_count += 1  # FLAW-194: a real BFS traversal follows
            path = index.bfs_path(
                source_location=source_location,
                source_expr=source_expr,
                sink_location=sink_location,
                sink_expr=sink_expr,
                exact_source=exact_source,
            )
        if path is None:
            return FlowTrace(
                source=source_handle,
                sink=sink_handle,
                steps=(),
                reachable=False,
                gaps=gaps,
            )

        return FlowTrace(
            source=source_handle,
            sink=sink_handle,
            steps=_path_to_steps(path),
            reachable=True,
        )

    def trace_multi_hop(
        self,
        *,
        source_location: SourceSpan,
        source_expr: str,
        sink_location: SourceSpan,
        sink_expr: str,
        source_fn_fqn: str,
        sink_fn_fqn: str,
        max_hops: int = _MAX_HOP_DEPTH,
        timeout: float = _MULTI_HOP_TIMEOUT_S,
        exact_source: bool = False,
    ) -> FlowTrace:
        """Trace flow across multiple call-graph boundaries.

        Performs bounded BFS over the call graph from *source_fn_fqn*
        toward *sink_fn_fqn*, stitching argument→parameter and
        return→call-result bridges at each boundary.  All value-flow
        edges from functions on the discovered path are unified, and a
        single name-connected BFS determines reachability.

        Bounds enforced:

        * **max_hops**: maximum call-graph edges to traverse (default 5).
        * **visited**: each function is entered at most once (cycle-free).
        * **timeout**: wall-clock limit in seconds (default 2.0).
        """
        self._counter.flow_query_count += 1  # FLAW-194 telemetry (pure observation)
        source_handle = ValueHandle(
            location=location(source_location),
            expression=source_expr,
        )
        sink_handle = ValueHandle(
            location=location(sink_location),
            expression=sink_expr,
        )

        if self._call_graph is None:
            return FlowTrace(
                source=source_handle,
                sink=sink_handle,
                steps=(),
                reachable=False,
                gaps=(
                    _gap(
                        "call graph is unavailable for multi-hop tracing",
                        affected_location=source_location,
                        fn_fqn=f"{source_fn_fqn}->{sink_fn_fqn}",
                    ),
                ),
            )

        # Fast reachability check before expensive path expansion.
        reachable_fqns = self._call_graph.reachable_from(
            source_fn_fqn,
            max_depth=max_hops,
        )
        if sink_fn_fqn not in reachable_fqns:
            return FlowTrace(
                source=source_handle,
                sink=sink_handle,
                steps=(),
                reachable=False,
                gaps=(
                    _gap(
                        f"sink function is not reachable within {max_hops} hops",
                        affected_location=sink_location,
                        fn_fqn=f"{source_fn_fqn}->{sink_fn_fqn}",
                    ),
                ),
            )

        edges, gaps = self._multi_hop_edges(
            source_fn_fqn=source_fn_fqn,
            sink_fn_fqn=sink_fn_fqn,
            source_location=source_location,
            max_hops=max_hops,
            timeout=timeout,
        )

        if not edges:
            return FlowTrace(
                source=source_handle,
                sink=sink_handle,
                steps=(),
                reachable=False,
                gaps=dedupe_gaps(tuple(gaps))
                or (
                    _gap(
                        "no value-flow edges found along multi-hop path",
                        affected_location=source_location,
                        fn_fqn=f"{source_fn_fqn}->{sink_fn_fqn}",
                    ),
                ),
            )

        self._counter.bfs_count += 1  # FLAW-194: a real BFS traversal follows
        path = FunctionFlowIndex(edges).bfs_path(
            source_location=source_location,
            source_expr=source_expr,
            sink_location=sink_location,
            sink_expr=sink_expr,
            exact_source=exact_source,
        )

        if path is None:
            return FlowTrace(
                source=source_handle,
                sink=sink_handle,
                steps=(),
                reachable=False,
                gaps=dedupe_gaps(tuple(gaps)),
            )

        return FlowTrace(
            source=source_handle,
            sink=sink_handle,
            steps=_path_to_steps(path),
            reachable=True,
            gaps=dedupe_gaps(tuple(gaps)),
        )

    def _multi_hop_edges(
        self,
        *,
        source_fn_fqn: str,
        sink_fn_fqn: str,
        source_location: SourceSpan,
        max_hops: int,
        timeout: float,
    ) -> tuple[tuple[ValueFlowEdge, ...], list[AnalysisGap]]:
        """Collect VFG + bridge edges along all call-graph paths to the sink.

        BFS-expands the call graph from *source_fn_fqn*, collecting
        value-flow edges and arg→param / return→result bridge edges for
        every function and call boundary encountered.  Stops when:

        * *sink_fn_fqn* is included in the collected set, or
        * *max_hops* depth is exhausted, or
        * wall-clock *timeout* is exceeded.
        """
        assert self._call_graph is not None
        deadline = time.monotonic() + timeout

        all_edges: list[ValueFlowEdge] = []
        all_gaps: list[AnalysisGap] = []
        visited_fqns: set[str] = set()

        # BFS frontier: (function_fqn, depth)
        frontier: deque[tuple[str, int]] = deque([(source_fn_fqn, 0)])
        visited_fqns.add(source_fn_fqn)

        # Always include source and sink function edges.
        all_edges.extend(self._edges_by_fn.get(source_fn_fqn, ()))
        all_edges.extend(self._edges_by_fn.get(sink_fn_fqn, ()))
        visited_fqns.add(sink_fn_fqn)

        while frontier:
            if time.monotonic() > deadline:
                all_gaps.append(
                    _gap(
                        "multi-hop traversal timed out",
                        affected_location=source_location,
                        fn_fqn=f"{source_fn_fqn}->{sink_fn_fqn}",
                    ),
                )
                break

            current_fqn, depth = frontier.popleft()
            if depth >= max_hops:
                continue

            for call in self._call_graph.edges_from(current_fqn):
                callee_fqn = call.callee_fqn
                if callee_fqn is None:
                    # L1 could not resolve this call's target. The call may
                    # carry the traced value toward the sink, so a silent skip
                    # would make a flow *missed* because of unresolved
                    # dispatch indistinguishable from a flow that provably
                    # does not exist. Per the project's top priority
                    # (eliminate false negatives), surface an explicit gap so
                    # the bool facades' caller can tell "couldn't analyze"
                    # from "no flow" (FLAW-217).
                    all_gaps.append(_unresolved_callee_gap(call, caller_fqn=current_fqn))
                    continue

                # Stitch arg→param bridge at this call boundary.
                param_edges, param_gaps = self._argument_parameter_edges(call)
                all_edges.extend(param_edges)
                all_gaps.extend(param_gaps)

                # Stitch return→call-result bridge.
                callee_edges = self._edges_by_fn.get(callee_fqn, ())
                caller_edges = self._edges_by_fn.get(current_fqn, ())
                return_edges, return_gaps = self._return_call_edges(
                    call,
                    callee_edges=callee_edges,
                    caller_edges=caller_edges,
                )
                all_edges.extend(return_edges)
                all_gaps.extend(return_gaps)

                if callee_fqn not in visited_fqns:
                    visited_fqns.add(callee_fqn)
                    all_edges.extend(callee_edges)
                    frontier.append((callee_fqn, depth + 1))

        return tuple(all_edges), all_gaps

    def _one_hop_edges(
        self,
        *,
        source_fn_fqn: str,
        sink_fn_fqn: str,
    ) -> tuple[tuple[ValueFlowEdge, ...], list[AnalysisGap], bool]:
        """Return VFG plus direct-call bridge edges for the two functions."""
        source_edges = self._edges_by_fn.get(source_fn_fqn, ())
        sink_edges = self._edges_by_fn.get(sink_fn_fqn, ())
        relevant_edges = (*source_edges, *sink_edges)
        bridge_edges: list[ValueFlowEdge] = []
        gaps: list[AnalysisGap] = []
        has_direct_call = False

        # O(1) lookup of the direct calls between these two functions, instead
        # of rescanning the whole call graph per query (FLAW-261).  Forward
        # calls (source→sink) contribute arg→param bridges; reverse calls
        # (sink→source) contribute return→result bridges.  source != sink here
        # (the caller dispatches to ``_same_function_one_hop_edges`` otherwise),
        # so the two buckets are disjoint — but the old full scan appended their
        # bridges interleaved by global call order, and ``bfs_path`` tie-breaks
        # on edge order, so merge the buckets back into that order before
        # emitting to keep the result byte-for-byte identical.
        pair_index = self._call_pair_index()
        forward = pair_index.get((source_fn_fqn, sink_fn_fqn), ())
        reverse = pair_index.get((sink_fn_fqn, source_fn_fqn), ())
        if forward or reverse:
            has_direct_call = True
            for _seq, call in sorted((*forward, *reverse), key=lambda item: item[0]):
                if call.caller_fqn == source_fn_fqn:
                    param_edges, param_gaps = self._argument_parameter_edges(call)
                    bridge_edges.extend(param_edges)
                    gaps.extend(param_gaps)
                else:
                    return_edges, return_gaps = self._return_call_edges(
                        call,
                        callee_edges=source_edges,
                        caller_edges=sink_edges,
                    )
                    bridge_edges.extend(return_edges)
                    gaps.extend(return_gaps)

        return (*relevant_edges, *bridge_edges), gaps, has_direct_call

    def _call_pair_index(self) -> dict[tuple[str, str], list[tuple[int, CallEdge]]]:
        """Index resolved call edges by ``(caller_fqn, callee_fqn)``, built once.

        Replaces the per-query linear scan of the entire call graph that
        :meth:`_one_hop_edges` previously performed (O(hops x edges)) with an
        O(1) keyed lookup.  Built lazily on first use and reused across every
        one-hop query for the life of the tracer (its inputs are immutable).

        Unresolved calls (``callee_fqn is None``) are omitted — they can never
        form a direct caller→callee bridge — exactly mirroring the ``continue``
        the old scan applied.  Each call keeps its global insertion index so
        callers can restore the original cross-direction edge ordering, which
        BFS path selection depends on.  Memory is bounded by the edge count.
        """
        index = self._calls_by_pair
        if index is None:
            assert self._call_graph is not None
            index = {}
            for seq, call in enumerate(self._call_graph.edges):
                if call.callee_fqn is None:
                    continue
                index.setdefault((call.caller_fqn, call.callee_fqn), []).append((seq, call))
            self._calls_by_pair = index
        return index

    def _same_function_one_hop_edges(
        self,
        *,
        fn_fqn: str,
    ) -> tuple[tuple[ValueFlowEdge, ...], tuple[AnalysisGap, ...], bool]:
        """Return caller→callee→caller bridge edges for direct calls in *fn_fqn*.

        Memoized by ``fn_fqn`` (FLAW-283): the edge set, gaps, and
        ``has_direct_call`` are a pure function of ``fn_fqn`` plus the tracer's
        immutable inputs, yet ``reads_flowing_to`` re-issued this on every
        (read x sink) query across every route.  Caching collapses the repeated
        O(edges) recompute to one per function.  Gaps are stored as an immutable
        tuple so the cached entry can be returned directly without aliasing a
        mutable list.
        """
        cached = self._same_fn_one_hop_cache.get(fn_fqn)
        if cached is not None:
            return cached
        result = self._compute_same_function_one_hop_edges(fn_fqn)
        self._same_fn_one_hop_cache[fn_fqn] = result
        return result

    def _same_function_one_hop_index(
        self,
        fn_fqn: str,
        edges: tuple[ValueFlowEdge, ...],
    ) -> FunctionFlowIndex:
        """Cached ``FunctionFlowIndex`` over the same-function one-hop edge set.

        Keyed by ``fn_fqn`` (FLAW-283).  ``edges`` is the memoized output of
        :meth:`_same_function_one_hop_edges`, itself a pure function of
        ``fn_fqn``, so the index is too — safe to build once and reuse for the
        function's lifetime in the scan.  (The interprocedural branch cannot do
        this: its stitched edge set varies per source/sink pair.)
        """
        index = self._same_fn_one_hop_index_cache.get(fn_fqn)
        if index is None:
            index = FunctionFlowIndex(edges)
            self._same_fn_one_hop_index_cache[fn_fqn] = index
        return index

    def _compute_same_function_one_hop_edges(
        self,
        fn_fqn: str,
    ) -> tuple[tuple[ValueFlowEdge, ...], tuple[AnalysisGap, ...], bool]:
        """Compute the same-function one-hop edge set (the memoized body)."""
        caller_edges = self._edges_by_fn.get(fn_fqn, ())
        relevant_edges: list[ValueFlowEdge] = [*caller_edges]
        bridge_edges: list[ValueFlowEdge] = []
        gaps: list[AnalysisGap] = []
        has_direct_call = False
        assert self._call_graph is not None

        for call in self._call_graph.edges_from(fn_fqn):
            if call.callee_fqn is None:
                # L1 could not resolve this intra-function call's target. The
                # call may carry the traced value toward the sink within this
                # function, so a silent skip would make a flow *missed* via
                # unresolved dispatch indistinguishable from one that provably
                # does not exist. Surface an explicit gap — the same failure
                # class FLAW-217 closed on the multi-hop path (:603) and that the
                # endpoint-missing path emits at :847/:587 (FLAW-235).
                gaps.append(_unresolved_callee_gap(call, caller_fqn=fn_fqn))
                continue
            if call.callee_fqn == fn_fqn:
                # Direct self-recursion: the callee *is* the function being
                # traced, so there is no new frame to bridge into. This is a
                # resolved target, not an analysis gap — skip without a gap.
                continue
            has_direct_call = True
            callee_edges = self._edges_by_fn.get(call.callee_fqn, ())
            relevant_edges.extend(callee_edges)
            param_edges, param_gaps = self._argument_parameter_edges(call)
            return_edges, return_gaps = self._return_call_edges(
                call,
                callee_edges=callee_edges,
                caller_edges=caller_edges,
            )
            bridge_edges.extend(param_edges)
            bridge_edges.extend(return_edges)
            gaps.extend(param_gaps)
            gaps.extend(return_gaps)

        return (*relevant_edges, *bridge_edges), tuple(gaps), has_direct_call

    def _argument_parameter_edges(
        self,
        call: CallEdge,
    ) -> tuple[list[ValueFlowEdge], list[AnalysisGap]]:
        """Create synthetic argument→parameter bridge edges for *call*."""
        callee = self._functions_by_fqn.get(call.callee_fqn or "")
        if callee is None:
            return [], [
                _gap(
                    "callee function metadata is unavailable for argument mapping",
                    affected_location=call.location,
                    fn_fqn=call.caller_fqn,
                )
            ]

        edges: list[ValueFlowEdge] = []
        gaps: list[AnalysisGap] = []
        for argument in call.arguments:
            param = _matching_parameter(callee.params, argument)
            if param is None:
                gaps.append(
                    _gap(
                        f"argument {argument.expression!r} cannot be mapped to a parameter",
                        affected_location=argument.location,
                        fn_fqn=call.callee_fqn or call.caller_fqn,
                    )
                )
                continue
            edges.append(
                ValueFlowEdge(
                    source_expr=argument.expression,
                    source_location=argument.location,
                    target_expr=param.name,
                    target_location=param.location,
                    kind=FlowKind.ARGUMENT,
                    containing_function_fqn=None,
                    provenance=call.provenance,
                    callsite_callee_fqn=call.callee_fqn,
                    callsite_expr=call.call_expression,
                    argument_position=argument.position,
                    argument_keyword=argument.keyword,
                )
            )
        return edges, gaps

    def _return_call_edges(
        self,
        call: CallEdge,
        *,
        callee_edges: tuple[ValueFlowEdge, ...],
        caller_edges: tuple[ValueFlowEdge, ...],
    ) -> tuple[list[ValueFlowEdge], list[AnalysisGap]]:
        """Create synthetic callee-return→caller-call-result bridge edges."""
        return_edges = tuple(edge for edge in callee_edges if edge.kind == FlowKind.RETURN)
        if not return_edges:
            return [], [
                _gap(
                    "callee return edges are unavailable for return mapping",
                    affected_location=call.location,
                    fn_fqn=call.callee_fqn or call.caller_fqn,
                )
            ]

        result_exprs = _call_result_expressions(call, caller_edges)
        if not result_exprs:
            return [], [
                _gap(
                    "caller call-result expression is unavailable for return mapping",
                    affected_location=call.location,
                    fn_fqn=call.caller_fqn,
                )
            ]

        edges: list[ValueFlowEdge] = []
        for return_edge in return_edges:
            edges.extend(
                ValueFlowEdge(
                    source_expr=return_edge.target_expr,
                    source_location=return_edge.target_location,
                    target_expr=result_expr,
                    target_location=call.location,
                    kind=FlowKind.RETURN,
                    containing_function_fqn=None,
                    provenance=call.provenance,
                    callsite_callee_fqn=call.callee_fqn,
                    callsite_expr=call.call_expression,
                )
                for result_expr in result_exprs
            )
        return edges, []


# -- Internal helpers -------------------------------------------------


def _matching_parameter(
    params: tuple[Parameter, ...],
    argument: CallArgument,
) -> Parameter | None:
    """Return the callee parameter receiving *argument*."""
    if argument.keyword is not None:
        return next((param for param in params if param.name == argument.keyword), None)
    if argument.position is None:
        return None

    positional_params = tuple(param for param in params if _accepts_positional(param))
    offset = 1 if _has_implicit_receiver(positional_params) else 0
    index = argument.position + offset
    if index < len(positional_params):
        return positional_params[index]
    return None


def _accepts_positional(param: Parameter) -> bool:
    return param.kind.value in {
        "positional_only",
        "positional_or_keyword",
        "var_positional",
    }


def _has_implicit_receiver(params: tuple[Parameter, ...]) -> bool:
    return bool(params) and params[0].name in {"self", "cls"}


def _call_result_expressions(
    call: CallEdge,
    caller_edges: tuple[ValueFlowEdge, ...],
) -> tuple[str, ...]:
    """Return caller-side expressions representing *call*'s return value."""
    call_expression = call.call_expression or ""
    expressions: list[str] = []
    for edge in caller_edges:
        if edge.kind == FlowKind.ARGUMENT:
            continue
        if not _same_line(edge.source_location, call.location):
            continue
        if _looks_like_call_result(edge.source_expr, call_expression):
            expressions.append(edge.source_expr)
    return tuple(dict.fromkeys(expressions))


def _looks_like_call_result(expression: str, call_expression: str) -> bool:
    if not call_expression:
        return False
    return (
        expression == call_expression
        or expression.startswith(f"{call_expression}(")
        or f"{call_expression}(" in expression
    )


def _missing_node_gap(
    index: FunctionFlowIndex,
    *,
    source_location: SourceSpan,
    source_expr: str,
    sink_location: SourceSpan,
    sink_expr: str,
    fn_fqn: str,
    exact_source: bool = False,
) -> AnalysisGap | None:
    """Return a gap when either requested endpoint is absent from the graph."""
    if not index.has_source_node(source_location, source_expr, exact=exact_source):
        return _gap(
            f"source node {source_expr!r} is missing from value-flow graph",
            affected_location=source_location,
            fn_fqn=fn_fqn,
        )
    if not index.has_sink_node(sink_location, sink_expr):
        return _gap(
            f"sink node {sink_expr!r} is missing from value-flow graph",
            affected_location=sink_location,
            fn_fqn=fn_fqn,
        )
    return None


def _unresolved_callee_gap(call: CallEdge, *, caller_fqn: str) -> AnalysisGap:
    """Gap for a call on a candidate path whose target L1 could not resolve.

    Carries the call-site expression and L1's ``unresolved_reason`` so a
    researcher can see *which* call broke the trace and why, rather than the
    flow simply vanishing (FLAW-217).
    """
    call_desc = call.call_expression or "<unresolved call>"
    reason = f" ({call.unresolved_reason})" if call.unresolved_reason else ""
    return _gap(
        f"unresolved call target {call_desc!r}{reason} cannot be followed for value flow",
        affected_location=call.location,
        fn_fqn=caller_fqn,
    )


def _same_line(left: SourceSpan, right: SourceSpan) -> bool:
    return left.file == right.file and left.line == right.line


def _gap(message: str, *, affected_location: SourceSpan, fn_fqn: str) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.VALUE_FLOW_INCOMPLETE,
        message=f"{fn_fqn}: {message}",
        affected_file=affected_location.file,
        affected_function=fn_fqn,
        origin_phase="flow_tracing",
    )


def _flow_description(edge: ValueFlowEdge) -> str:
    """Human-readable description for a flow step."""
    kind_name = edge.kind.value
    verb = _FLOW_KIND_DESCRIPTIONS.get(kind_name, kind_name)
    return f"{edge.source_expr} {verb} {edge.target_expr}"


def _path_to_steps(
    path: list[ValueFlowEdge],
) -> tuple[FlowStep, ...]:
    """Convert a BFS edge path into ordered ``FlowStep`` objects."""
    if not path:
        return ()

    steps: list[FlowStep] = []

    # First step: the source value
    first_edge = path[0]
    steps.append(
        FlowStep(
            location=location(first_edge.source_location),
            expression=first_edge.source_expr,
            description="source value",
            kind=None,
        )
    )

    # Intermediate and final steps from each edge's target
    steps.extend(
        FlowStep(
            location=location(edge.target_location),
            expression=edge.target_expr,
            description=_flow_description(edge),
            kind=edge.kind.value,
        )
        for edge in path
    )

    return tuple(steps)
