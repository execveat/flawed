"""Per-edge-set value-flow lookup index (FLAW-106).

The flow tracer answers thousands of source→sink reachability queries per
scan; on large repos this is the dominant Layer 3 cost.  Every query used to
(1) rebuild a ``source_expr → edges`` adjacency map and (2) linearly rescan the
full edge list twice to check that the requested endpoints are present in the
graph.  For a route handler with a large value-flow graph that work was
repeated on *every one* of the (reads x effects) and (calls x args x reads)
queries the comparative/gadget rules issue — including the tens of thousands of
inference-gap queries that never even reach the BFS.

``FunctionFlowIndex`` precomputes those structures **once** for a fixed edge
set.  The tracer caches one index per function for the lifetime of a scan
(:class:`~flawed._semantic._flow_tracer.IntraFunctionFlowTracer`), so the
per-query rebuild/rescan collapses to O(1) dictionary/set lookups.

This is a pure precompute: every method returns exactly what the previous
per-call scan returned.  Findings are unchanged — only redundant work is
removed.  The interprocedural paths build a *transient* index over their
dynamically-stitched edge set (which includes synthetic bridge edges and so
cannot be cached by function), still avoiding the double rescan.
"""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING

from flawed._index._types import FlowKind, ValueFlowEdge

if TYPE_CHECKING:
    from flawed._index._types import SourceSpan

_MAX_TRACE_DEPTH = 50
"""Maximum BFS depth to prevent unbounded traversal."""


class FunctionFlowIndex:
    """Precomputed source/target lookup structures over a fixed edge set.

    Built once per function (or once per transient interprocedural edge set)
    and reused across the many trace queries a single scan issues.  All
    queries are pure functions of the edge set, so the index is safe to share
    for the lifetime of a scan.
    """

    __slots__ = (
        "_by_source_expr",
        "_edges",
        "_source_expr_lines",
        "_source_lines",
        "_target_expr_lines",
        "_target_lines",
    )

    def __init__(self, edges: tuple[ValueFlowEdge, ...]) -> None:
        self._edges = edges
        by_source_expr: dict[str, list[ValueFlowEdge]] = {}
        source_lines: set[tuple[str, int]] = set()
        source_expr_lines: set[tuple[str, int, str]] = set()
        target_lines: set[tuple[str, int]] = set()
        target_expr_lines: set[tuple[str, int, str]] = set()
        for edge in edges:
            by_source_expr.setdefault(edge.source_expr, []).append(edge)
            src = (edge.source_location.file, edge.source_location.line)
            source_lines.add(src)
            source_expr_lines.add((src[0], src[1], edge.source_expr))
            tgt = (edge.target_location.file, edge.target_location.line)
            target_lines.add(tgt)
            target_expr_lines.add((tgt[0], tgt[1], edge.target_expr))
        self._by_source_expr = by_source_expr
        self._source_lines = source_lines
        self._source_expr_lines = source_expr_lines
        self._target_lines = target_lines
        self._target_expr_lines = target_expr_lines

    @property
    def is_empty(self) -> bool:
        """Return whether the index holds no edges."""
        return not self._edges

    def has_source_node(
        self,
        source_location: SourceSpan,
        source_expr: str,
        *,
        exact: bool = False,
    ) -> bool:
        """Return whether the requested source can seed tracing.

        Mirrors the previous linear scan: an *exact* match requires an edge on
        the same line whose source expression matches (or an empty requested
        expression); a relaxed match additionally accepts any edge originating
        on the same line.
        """
        key = (source_location.file, source_location.line)
        if source_expr:
            exact_match = (key[0], key[1], source_expr) in self._source_expr_lines
        else:
            exact_match = key in self._source_lines
        if exact:
            return exact_match
        return exact_match or key in self._source_lines

    def has_sink_node(self, sink_location: SourceSpan, sink_expr: str) -> bool:
        """Return whether the requested sink is represented in the graph.

        A sink is present when it appears as some edge's target *or* as some
        edge's source (a variable use), on the same line, with a matching (or
        empty) expression.
        """
        key = (sink_location.file, sink_location.line)
        if sink_expr:
            target_hit = (key[0], key[1], sink_expr) in self._target_expr_lines
            source_hit = (key[0], key[1], sink_expr) in self._source_expr_lines
        else:
            target_hit = key in self._target_lines
            source_hit = key in self._source_lines
        return target_hit or source_hit

    def bfs_path(
        self,
        *,
        source_location: SourceSpan,
        source_expr: str,
        sink_location: SourceSpan,
        sink_expr: str,
        exact_source: bool = False,
    ) -> list[ValueFlowEdge] | None:
        """BFS over the indexed edges to find a path from source to sink.

        The graph connects edges by *expression name*: if edge A targets
        expression ``x`` and edge B sources expression ``x``, B is reachable
        from A.  This handles multi-line variable chains where L1 does not emit
        explicit def→use edges.

        Returns the ordered list of edges forming the path, or ``None`` if no
        path exists.
        """
        by_source_expr = self._by_source_expr
        sink_key = (sink_location.file, sink_location.line)

        def _visited_key(expr: str, loc: SourceSpan) -> tuple[str, str, int]:
            return (expr, loc.file, loc.line)

        def _is_sink(edge: ValueFlowEdge) -> bool:
            tgt_key = (edge.target_location.file, edge.target_location.line)
            return tgt_key == sink_key and edge.target_expr == sink_expr

        def _is_sink_use(edge: ValueFlowEdge) -> bool:
            src_key = (edge.source_location.file, edge.source_location.line)
            return src_key == sink_key and edge.source_expr == sink_expr

        def _sink_use_edge(
            use_expr: str,
            use_location: SourceSpan,
            prototype: ValueFlowEdge,
        ) -> ValueFlowEdge:
            """Represent reaching a variable use that is the source of another edge."""
            return ValueFlowEdge(
                source_expr=use_expr,
                source_location=use_location,
                target_expr=sink_expr,
                target_location=sink_location,
                kind=FlowKind.ALIAS,
                containing_function_fqn=prototype.containing_function_fqn,
                provenance=prototype.provenance,
            )

        # Seed: edges whose source_expr matches the requested source, further
        # filtered to the source location.
        start_edges = [
            edge
            for edge in by_source_expr.get(source_expr, ())
            if (edge.source_location.file, edge.source_location.line)
            == (source_location.file, source_location.line)
        ]

        if not start_edges and not exact_source:
            # Relaxed: any edge from the source location.
            start_edges = [
                edge
                for edge in self._edges
                if (edge.source_location.file, edge.source_location.line)
                == (source_location.file, source_location.line)
            ]

        visited: set[tuple[str, str, int]] = {
            _visited_key(source_expr, source_location),
        }

        queue: deque[tuple[str, SourceSpan, list[ValueFlowEdge]]] = deque()

        for edge in start_edges:
            if _is_sink_use(edge):
                return [_sink_use_edge(source_expr, source_location, edge)]
            if _is_sink(edge):
                return [edge]
            vk = _visited_key(edge.target_expr, edge.target_location)
            if vk not in visited:
                visited.add(vk)
                queue.append((edge.target_expr, edge.target_location, [edge]))

        depth = 0
        while queue and depth < _MAX_TRACE_DEPTH:
            level_size = len(queue)
            for _ in range(level_size):
                current_expr, current_loc, path = queue.popleft()

                # Follow edges whose source_expr matches the current target_expr
                for edge in by_source_expr.get(current_expr, ()):
                    if _is_sink_use(edge):
                        return [
                            *path,
                            _sink_use_edge(current_expr, current_loc, edge),
                        ]
                    new_path = [*path, edge]

                    if _is_sink(edge):
                        return new_path

                    vk = _visited_key(edge.target_expr, edge.target_location)
                    if vk not in visited:
                        visited.add(vk)
                        queue.append((edge.target_expr, edge.target_location, new_path))
            depth += 1

        return None
