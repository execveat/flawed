"""Shared callee-graph construction and BFS reachability.

Used by ``__init__``, ``_branch``, and any module that needs to traverse
the call graph for scope construction.  Building the graph and computing
reachable sets are the most-repeated operations during semantic conversion,
so this module provides caching to avoid redundant work.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flawed._index import CodeIndex
    from flawed._semantic._dispatch_conversion import DispatchEdge

_MAX_CALLEE_DEPTH = 5


def build_callee_graph(
    idx: CodeIndex,
    dispatch_edges: tuple[DispatchEdge, ...] = (),
) -> dict[str, set[str]]:
    """Build a caller -> callees adjacency map from L1 and L2 dispatch edges."""
    graph: dict[str, set[str]] = {}
    for edge in idx.call_graph.edges:
        if edge.callee_fqn is not None:
            graph.setdefault(edge.caller_fqn, set()).add(edge.callee_fqn)
    for dispatch_edge in dispatch_edges:
        graph.setdefault(dispatch_edge.caller_fqn, set()).add(dispatch_edge.target.fqn)
    return graph


def reachable_callees(
    root_fqn: str,
    callee_graph: dict[str, set[str]],
    *,
    cache: dict[str, tuple[str, ...]] | None = None,
) -> tuple[str, ...]:
    """Return the FQNs reachable from *root_fqn* via call edges, in a stable order.

    Includes *root_fqn* itself (always first).  Bounded by
    ``_MAX_CALLEE_DEPTH`` to prevent unbounded traversal on recursive or
    deeply nested call chains.

    The result is an ordered tuple in deterministic breadth-first discovery
    order: each frontier is expanded in ``sorted()`` order and each node's
    neighbours are visited sorted.  This matters for correctness, not just
    tidiness — downstream the *first* reachable effect/read becomes a
    finding's representative evidence (``effects[0]``), which feeds
    ``Finding.fingerprint``.  Returning a ``frozenset`` here leaked
    PYTHONHASHSEED-randomized iteration order into that representative, so
    repeated scans of an unchanged repo produced different fingerprints and
    therefore different deduplicated finding counts (FLAW-161).  A stable
    order makes scans reproducible regardless of hash seed.

    When *cache* is provided, memoizes results so repeated queries for
    the same root against the same graph avoid redundant BFS traversal.
    """
    if cache is not None:
        cached = cache.get(root_fqn)
        if cached is not None:
            return cached

    order: list[str] = [root_fqn]
    visited: set[str] = {root_fqn}
    frontier = [root_fqn]
    for _ in range(_MAX_CALLEE_DEPTH):
        next_frontier: list[str] = []
        for fn_fqn in sorted(frontier):
            for callee in sorted(callee_graph.get(fn_fqn, ())):
                if callee not in visited:
                    visited.add(callee)
                    order.append(callee)
                    next_frontier.append(callee)
        if not next_frontier:
            break
        frontier = next_frontier

    result = tuple(order)
    if cache is not None:
        cache[root_fqn] = result
    return result
