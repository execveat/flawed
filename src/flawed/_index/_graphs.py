"""Graph query objects — call graph, CFG, value-flow, and symbol index.

These are regular (non-frozen) classes that provide typed query APIs over
Layer 1 relationship facts.  Query-heavy graphs keep lightweight adjacency
indexes instead of third-party graph objects.
"""

from __future__ import annotations

from collections import deque
from itertools import pairwise
from typing import TYPE_CHECKING

from flawed._index._types import (
    BranchCondition,
    CallEdge,
    CFGBlock,
    CFGEdge,
    CFGPath,
    SourceSpan,
    SymbolRef,
    TryExceptRegion,
    ValueFlowEdge,
)

if TYPE_CHECKING:
    from flawed._index._collections import (
        SymbolRefCollection,
        ValueFlowEdgeCollection,
    )


# =====================================================================
# CallGraph
# =====================================================================


class CallGraph:
    """Merged call graph over all extraction sources.

    Answers both *who* questions (``callees``, ``callers``, ``reachable_from``)
    and *how* questions (``edges_from``, ``edges_to``, ``edge``).
    """

    __slots__ = (
        "_callees_by_caller",
        "_callers_by_callee",
        "_edge_list",
        "_edges_by_callee",
        "_edges_by_caller",
        "_node_count",
        "_resolved_edge_count",
        "_resolved_nodes",
    )

    def __init__(self, edges: tuple[CallEdge, ...]) -> None:
        self._edge_list = edges
        self._edges_by_caller: dict[str, list[CallEdge]] = {}
        self._edges_by_callee: dict[str, list[CallEdge]] = {}
        callees_by_caller: dict[str, set[str]] = {}
        callers_by_callee: dict[str, set[str]] = {}
        resolved_nodes: set[str] = set()
        resolved_edges: set[tuple[str, str]] = set()

        for e in edges:
            self._edges_by_caller.setdefault(e.caller_fqn, []).append(e)
            if e.callee_fqn is None:
                continue
            self._edges_by_callee.setdefault(e.callee_fqn, []).append(e)
            callees_by_caller.setdefault(e.caller_fqn, set()).add(e.callee_fqn)
            callers_by_callee.setdefault(e.callee_fqn, set()).add(e.caller_fqn)
            resolved_nodes.add(e.caller_fqn)
            resolved_nodes.add(e.callee_fqn)
            resolved_edges.add((e.caller_fqn, e.callee_fqn))

        self._callees_by_caller: dict[str, frozenset[str]] = {
            caller: frozenset(callees) for caller, callees in callees_by_caller.items()
        }
        self._callers_by_callee: dict[str, frozenset[str]] = {
            callee: frozenset(callers) for callee, callers in callers_by_callee.items()
        }
        self._resolved_nodes: frozenset[str] = frozenset(resolved_nodes)
        self._node_count = len(resolved_nodes)
        self._resolved_edge_count = len(resolved_edges)

    # -- WHO questions ------------------------------------------------

    def callees(self, fqn: str) -> frozenset[str]:
        """Direct callees of *fqn*."""
        if fqn not in self._resolved_nodes:
            return frozenset()
        return self._callees_by_caller.get(fqn, frozenset())

    def callers(self, fqn: str) -> frozenset[str]:
        """Direct callers of *fqn*."""
        if fqn not in self._resolved_nodes:
            return frozenset()
        return self._callers_by_callee.get(fqn, frozenset())

    def reachable_from(self, fqn: str, *, max_depth: int | None = None) -> frozenset[str]:
        """Transitive closure of callees from *fqn*.

        If *max_depth* is given, limits the BFS to that many hops.
        The starting *fqn* is NOT included in the result.
        """
        if fqn not in self._resolved_nodes:
            return frozenset()
        reachable: set[str] = set()
        frontier = {fqn}
        depth = 0
        while frontier and (max_depth is None or depth < max_depth):
            next_frontier: set[str] = set()
            for node in frontier:
                for succ in self._callees_by_caller.get(node, ()):
                    if succ == fqn or succ in reachable:
                        continue
                    reachable.add(succ)
                    next_frontier.add(succ)
            frontier = next_frontier
            depth += 1
        return frozenset(reachable)

    # -- HOW questions ------------------------------------------------

    @property
    def edges(self) -> tuple[CallEdge, ...]:
        """All call edges, including unresolved edges."""
        return self._edge_list

    def edges_from(self, fqn: str) -> tuple[CallEdge, ...]:
        """All outgoing call edges from *fqn*."""
        return tuple(self._edges_by_caller.get(fqn, ()))

    def edges_to(self, fqn: str) -> tuple[CallEdge, ...]:
        """All incoming call edges to *fqn*."""
        return tuple(self._edges_by_callee.get(fqn, ()))

    def edge(self, caller_fqn: str, callee_fqn: str) -> CallEdge | None:
        """Specific edge between caller and callee, or ``None``."""
        for e in self._edges_by_caller.get(caller_fqn, ()):
            if e.callee_fqn == callee_fqn:
                return e
        return None

    def __contains__(self, fqn: str) -> bool:
        return fqn in self._resolved_nodes

    def __repr__(self) -> str:
        return f"CallGraph({self._node_count} nodes, {self._resolved_edge_count} edges)"


# =====================================================================
# ControlFlowGraph (per-function)
# =====================================================================


class ControlFlowGraph:
    """Per-function control-flow graph with dominance queries.

    All ``loc_*`` parameters accept ``SourceSpan`` — the CFG resolves
    locations to block IDs internally via ``block_for()``.
    """

    __slots__ = (
        "_block_list",
        "_blocks_by_id",
        "_edge_list",
        "_edges_by_pair",
        "_entry_id",
        "_idom",
        "_predecessors_by_id",
        "_successors_by_id",
        "_try_regions",
    )

    def __init__(
        self,
        blocks: tuple[CFGBlock, ...],
        edges: tuple[CFGEdge, ...],
        *,
        try_regions: tuple[TryExceptRegion, ...] = (),
    ) -> None:
        self._block_list = blocks
        self._edge_list = edges
        self._try_regions = try_regions
        self._blocks_by_id: dict[int, CFGBlock] = {b.id: b for b in blocks}
        self._successors_by_id, self._predecessors_by_id, self._edges_by_pair = (
            _build_cfg_adjacency(blocks, edges)
        )
        self._entry_id = self._find_entry()
        self._idom = _immediate_dominators(
            self._entry_id,
            tuple(self._blocks_by_id),
            self._successors_by_id,
            self._predecessors_by_id,
        )

    def _find_entry(self) -> int | None:
        for b in self._block_list:
            if not b.predecessors:
                return b.id
        return self._block_list[0].id if self._block_list else None

    # -- structure ----------------------------------------------------

    @property
    def blocks(self) -> tuple[CFGBlock, ...]:
        """All basic blocks."""
        return self._block_list

    @property
    def edges(self) -> tuple[CFGEdge, ...]:
        """All CFG edges."""
        return self._edge_list

    @property
    def entry(self) -> CFGBlock | None:
        """The entry block (no predecessors)."""
        return self._blocks_by_id.get(self._entry_id) if self._entry_id is not None else None

    @property
    def exits(self) -> tuple[CFGBlock, ...]:
        """Exit blocks (no successors)."""
        return tuple(b for b in self._block_list if not b.successors)

    @property
    def try_regions(self) -> tuple[TryExceptRegion, ...]:
        """Structured metadata for try/except/finally regions."""
        return self._try_regions

    # -- query methods ------------------------------------------------

    def block_for(self, location: SourceSpan) -> CFGBlock | None:
        """Find the block containing *location*."""
        for b in self._block_list:
            if b.condition_location is not None and _span_contains_start(
                b.condition_location, location
            ):
                return b
            for stmt in b.statements:
                if _span_contains_start(stmt, location):
                    return b
        return None

    def successors(self, block_id: int) -> tuple[CFGBlock, ...]:
        """Successor blocks of *block_id*."""
        block = self._blocks_by_id.get(block_id)
        if block is None:
            return ()
        return tuple(
            self._blocks_by_id[sid]
            for sid in self._successors_by_id.get(block_id, ())
            if sid in self._blocks_by_id
        )

    def predecessors(self, block_id: int) -> tuple[CFGBlock, ...]:
        """Predecessor blocks of *block_id*."""
        block = self._blocks_by_id.get(block_id)
        if block is None:
            return ()
        return tuple(
            self._blocks_by_id[pid]
            for pid in self._predecessors_by_id.get(block_id, ())
            if pid in self._blocks_by_id
        )

    def dominates(self, loc_a: SourceSpan, loc_b: SourceSpan) -> bool:
        """``True`` if every path from entry to *loc_b* passes through *loc_a*.

        Returns ``False`` conservatively when either location cannot be
        resolved to a block.
        """
        block_a = self.block_for(loc_a)
        block_b = self.block_for(loc_b)
        if block_a is None or block_b is None:
            return False
        return self._block_dominates(block_a.id, block_b.id)

    def _block_dominates(self, a_id: int, b_id: int) -> bool:
        """Check dominance using the pre-computed dominator tree."""
        if a_id == b_id:
            return True
        current = b_id
        while current in self._idom:
            parent = self._idom[current]
            if parent == a_id:
                return True
            if parent == current:
                break  # reached root
            current = parent
        return False

    def precedes(self, loc_a: SourceSpan, loc_b: SourceSpan) -> bool:
        """``True`` if *loc_a* executes before *loc_b* on EVERY path.

        This is stronger than dominance: loc_a dominates loc_b AND
        loc_a appears before loc_b in execution order.  For now this
        uses a conservative approximation: dominance + topological order.
        """
        block_a = self.block_for(loc_a)
        block_b = self.block_for(loc_b)
        if block_a is None or block_b is None:
            return False
        if block_a.id == block_b.id:
            return loc_a.line < loc_b.line or (
                loc_a.line == loc_b.line and loc_a.column < loc_b.column
            )
        return self._block_dominates(block_a.id, block_b.id)

    def paths_between(self, loc_a: SourceSpan, loc_b: SourceSpan) -> tuple[CFGPath, ...]:
        """All simple paths between the blocks containing the two locations."""
        block_a = self.block_for(loc_a)
        block_b = self.block_for(loc_b)
        if block_a is None or block_b is None:
            return ()
        if block_a.id == block_b.id:
            return (CFGPath(blocks=(block_a,), conditions=()),)
        result: list[CFGPath] = []
        for path_ids in _all_simple_paths(
            block_a.id,
            block_b.id,
            self._successors_by_id,
            cutoff=20,
        ):
            blocks = tuple(
                self._blocks_by_id[bid] for bid in path_ids if bid in self._blocks_by_id
            )
            result.append(CFGPath(blocks=blocks, conditions=self._path_conditions(path_ids)))
        return tuple(result)

    def reachable_between(self, loc_a: SourceSpan, loc_b: SourceSpan) -> bool:
        """Return whether any CFG path connects the two locations.

        This boolean query intentionally avoids materializing concrete paths;
        callers that only need reachability should not pay the cost of
        enumerating every simple path through a branching CFG.
        """
        block_a = self.block_for(loc_a)
        block_b = self.block_for(loc_b)
        if block_a is None or block_b is None:
            return False
        if block_a.id == block_b.id:
            return True
        return _has_path(block_a.id, block_b.id, self._successors_by_id)

    def _path_conditions(self, path_ids: tuple[int, ...]) -> tuple[BranchCondition, ...]:
        """Branch conditions traversed by a path of block IDs."""
        conditions: list[BranchCondition] = []
        for source_id, target_id in pairwise(path_ids):
            edge = self._edge_between(source_id, target_id)
            if edge is None or edge.label not in {"true", "false"}:
                continue
            block = self._blocks_by_id.get(source_id)
            if block is None or block.condition_expr is None or block.condition_location is None:
                continue
            conditions.append(
                BranchCondition(
                    condition_expr=block.condition_expr,
                    direction=edge.label == "true",
                    location=block.condition_location,
                )
            )
        return tuple(conditions)

    def _edge_between(self, source_id: int, target_id: int) -> CFGEdge | None:
        """Return the first edge from *source_id* to *target_id*, if any."""
        return self._edges_by_pair.get((source_id, target_id))

    def __repr__(self) -> str:
        return f"ControlFlowGraph({len(self._block_list)} blocks, {len(self._edge_list)} edges)"


def _build_cfg_adjacency(
    blocks: tuple[CFGBlock, ...],
    edges: tuple[CFGEdge, ...],
) -> tuple[dict[int, tuple[int, ...]], dict[int, tuple[int, ...]], dict[tuple[int, int], CFGEdge]]:
    """Build compact deterministic adjacency indexes for CFG queries."""
    block_ids = {block.id for block in blocks}
    successors: dict[int, list[int]] = {block.id: [] for block in blocks}
    predecessors: dict[int, list[int]] = {block.id: [] for block in blocks}
    edges_by_pair: dict[tuple[int, int], CFGEdge] = {}

    for edge in edges:
        if edge.source_id not in block_ids or edge.target_id not in block_ids:
            continue
        if edge.target_id not in successors[edge.source_id]:
            successors[edge.source_id].append(edge.target_id)
        if edge.source_id not in predecessors[edge.target_id]:
            predecessors[edge.target_id].append(edge.source_id)
        edges_by_pair.setdefault((edge.source_id, edge.target_id), edge)

    return (
        {block_id: tuple(ids) for block_id, ids in successors.items()},
        {block_id: tuple(ids) for block_id, ids in predecessors.items()},
        edges_by_pair,
    )


def _immediate_dominators(
    entry_id: int | None,
    block_ids: tuple[int, ...],
    successors_by_id: dict[int, tuple[int, ...]],
    predecessors_by_id: dict[int, tuple[int, ...]],
) -> dict[int, int]:
    """Compute immediate dominators for blocks reachable from *entry_id*."""
    if entry_id is None:
        return {}

    reachable = _reachable_block_ids(entry_id, successors_by_id)
    if not reachable:
        return {}

    all_reachable = set(reachable)
    dominators = _initial_dominators(entry_id, block_ids, all_reachable)
    while _refine_dominators(entry_id, block_ids, all_reachable, predecessors_by_id, dominators):
        pass
    return _collapse_immediate_dominators(entry_id, block_ids, all_reachable, dominators)


def _initial_dominators(
    entry_id: int,
    block_ids: tuple[int, ...],
    reachable: set[int],
) -> dict[int, set[int]]:
    """Return conservative dominator sets before fixed-point refinement."""
    dominators: dict[int, set[int]] = {}
    for block_id in block_ids:
        if block_id == entry_id:
            dominators[block_id] = {entry_id}
        elif block_id in reachable:
            dominators[block_id] = set(reachable)
    return dominators


def _refine_dominators(
    entry_id: int,
    block_ids: tuple[int, ...],
    reachable: set[int],
    predecessors_by_id: dict[int, tuple[int, ...]],
    dominators: dict[int, set[int]],
) -> bool:
    """Run one dominator fixed-point pass and return whether anything changed."""
    changed = False
    for block_id in block_ids:
        if block_id == entry_id or block_id not in reachable:
            continue
        reachable_predecessors = tuple(
            pred_id for pred_id in predecessors_by_id.get(block_id, ()) if pred_id in reachable
        )
        new_dominators = _updated_dominators(
            block_id,
            reachable_predecessors,
            dominators,
        )
        if new_dominators != dominators[block_id]:
            dominators[block_id] = new_dominators
            changed = True
    return changed


def _updated_dominators(
    block_id: int,
    reachable_predecessors: tuple[int, ...],
    dominators: dict[int, set[int]],
) -> set[int]:
    """Return the next dominator set for one block."""
    if not reachable_predecessors:
        return {block_id}

    common = set(dominators[reachable_predecessors[0]])
    for pred_id in reachable_predecessors[1:]:
        common.intersection_update(dominators[pred_id])
    common.add(block_id)
    return common


def _collapse_immediate_dominators(
    entry_id: int,
    block_ids: tuple[int, ...],
    reachable: set[int],
    dominators: dict[int, set[int]],
) -> dict[int, int]:
    """Collapse full dominator sets into immediate-dominator links."""
    idom: dict[int, int] = {entry_id: entry_id}
    for block_id in block_ids:
        if block_id == entry_id or block_id not in reachable:
            continue
        strict_dominators = dominators[block_id] - {block_id}
        if strict_dominators:
            idom[block_id] = max(
                strict_dominators,
                key=lambda dominator: len(dominators[dominator]),
            )
    return idom


def _reachable_block_ids(
    start_id: int,
    successors_by_id: dict[int, tuple[int, ...]],
) -> tuple[int, ...]:
    """Return block IDs reachable from *start_id* in breadth-first order."""
    seen = {start_id}
    ordered: list[int] = []
    queue: deque[int] = deque((start_id,))
    while queue:
        block_id = queue.popleft()
        ordered.append(block_id)
        for successor_id in successors_by_id.get(block_id, ()):
            if successor_id in seen:
                continue
            seen.add(successor_id)
            queue.append(successor_id)
    return tuple(ordered)


def _all_simple_paths(
    source_id: int,
    target_id: int,
    successors_by_id: dict[int, tuple[int, ...]],
    *,
    cutoff: int,
) -> tuple[tuple[int, ...], ...]:
    """Return all simple paths from *source_id* to *target_id* up to *cutoff* edges."""
    if cutoff < 0:
        return ()
    paths: list[tuple[int, ...]] = []
    stack: list[tuple[int, tuple[int, ...], frozenset[int]]] = [
        (source_id, (source_id,), frozenset({source_id}))
    ]
    while stack:
        current_id, path, seen = stack.pop()
        if len(path) - 1 >= cutoff:
            continue
        for successor_id in reversed(successors_by_id.get(current_id, ())):
            if successor_id in seen:
                continue
            next_path = (*path, successor_id)
            if successor_id == target_id:
                paths.append(next_path)
            else:
                stack.append((successor_id, next_path, seen | {successor_id}))
    return tuple(paths)


def _has_path(
    source_id: int,
    target_id: int,
    successors_by_id: dict[int, tuple[int, ...]],
) -> bool:
    """Return whether *target_id* is reachable from *source_id*."""
    seen = {source_id}
    queue: deque[int] = deque((source_id,))
    while queue:
        current_id = queue.popleft()
        for successor_id in successors_by_id.get(current_id, ()):
            if successor_id == target_id:
                return True
            if successor_id in seen:
                continue
            seen.add(successor_id)
            queue.append(successor_id)
    return False


def _span_contains_start(span: SourceSpan, location: SourceSpan) -> bool:
    """Return whether *location* starts inside *span*."""
    if span.file != location.file:
        return False
    if location.line < span.line or location.line > span.end_line:
        return False
    if location.line == span.line and location.column < span.column:
        return False
    return not (location.line == span.end_line and location.column > span.end_column)


# =====================================================================
# ValueFlowGraph
# =====================================================================


class ValueFlowGraph:
    """Pre-computed intra-function value-flow edges.

    Structural foundation for Layer 2's cross-project flow tracing.
    """

    __slots__ = ("_by_source_file_line", "_by_target_file_line", "_edges", "_nodes")

    def __init__(self, edges: tuple[ValueFlowEdge, ...]) -> None:
        self._edges = edges
        self._by_source_file_line: dict[tuple[str, int], list[ValueFlowEdge]] = {}
        self._by_target_file_line: dict[tuple[str, int], list[ValueFlowEdge]] = {}
        nodes: set[tuple[str, int]] = set()

        for e in edges:
            src_key = (e.source_location.file, e.source_location.line)
            tgt_key = (e.target_location.file, e.target_location.line)
            self._by_source_file_line.setdefault(src_key, []).append(e)
            self._by_target_file_line.setdefault(tgt_key, []).append(e)
            nodes.add(src_key)
            nodes.add(tgt_key)
        self._nodes: frozenset[tuple[str, int]] = frozenset(nodes)

    @property
    def edges(self) -> tuple[ValueFlowEdge, ...]:
        """All value-flow edges in deterministic extraction order."""
        return self._edges

    def flows_from(self, location: SourceSpan) -> ValueFlowEdgeCollection:
        """Outgoing edges from *location*."""
        from flawed._index._collections import ValueFlowEdgeCollection

        key = (location.file, location.line)
        return ValueFlowEdgeCollection(tuple(self._by_source_file_line.get(key, ())))

    def flows_to(self, location: SourceSpan) -> ValueFlowEdgeCollection:
        """Incoming edges to *location*."""
        from flawed._index._collections import ValueFlowEdgeCollection

        key = (location.file, location.line)
        return ValueFlowEdgeCollection(tuple(self._by_target_file_line.get(key, ())))

    def assignments_to(self, name: str, fn_fqn: str) -> ValueFlowEdgeCollection:
        """All edges targeting *name* within function *fn_fqn*."""
        from flawed._index._collections import ValueFlowEdgeCollection

        return ValueFlowEdgeCollection(
            tuple(
                e
                for e in self._edges
                if e.containing_function_fqn == fn_fqn and e.target_expr == name
            )
        )

    def connected(self, source: SourceSpan, target: SourceSpan) -> bool:
        """``True`` if a value-flow path exists from *source* to *target*."""
        src_key = (source.file, source.line)
        tgt_key = (target.file, target.line)
        if src_key not in self._nodes or tgt_key not in self._nodes:
            return False
        if src_key == tgt_key:
            return True

        visited = {src_key}
        frontier = deque((src_key,))
        while frontier:
            node = frontier.popleft()
            for edge in self._by_source_file_line.get(node, ()):
                next_key = (edge.target_location.file, edge.target_location.line)
                if next_key == tgt_key:
                    return True
                if next_key in visited:
                    continue
                visited.add(next_key)
                frontier.append(next_key)
        return False

    def __repr__(self) -> str:
        return f"ValueFlowGraph({len(self._edges)} edges)"


# =====================================================================
# SymbolIndex
# =====================================================================


class SymbolIndex:
    """Index for symbol resolution and FQN lookups."""

    __slots__ = ("_by_fqn", "_by_name_in_file", "_defined_fqns", "_refs")

    def __init__(self, refs: tuple[SymbolRef, ...]) -> None:
        self._refs = refs
        self._by_fqn: dict[str, list[SymbolRef]] = {}
        self._by_name_in_file: dict[tuple[str, str], list[SymbolRef]] = {}
        self._defined_fqns: set[str] = set()

        for r in refs:
            key = (r.name, r.location.file)
            self._by_name_in_file.setdefault(key, []).append(r)
            if r.fqn is not None:
                self._by_fqn.setdefault(r.fqn, []).append(r)
                self._defined_fqns.add(r.fqn)

    def resolve(self, name: str, file: str) -> str | None:
        """Resolve *name* used in *file* to its FQN.

        Returns the first resolved FQN found, or ``None``.
        """
        for ref in self._by_name_in_file.get((name, file), ()):
            if ref.fqn is not None:
                return ref.fqn
        return None

    def fqn_exists(self, fqn: str) -> bool:
        """``True`` if *fqn* appears in any resolved reference."""
        return fqn in self._defined_fqns

    @property
    def refs(self) -> tuple[SymbolRef, ...]:
        """All symbol references, including unresolved references."""
        return self._refs

    def usages(self, fqn: str) -> tuple[SourceSpan, ...]:
        """All source locations where *fqn* is referenced."""
        return tuple(r.location for r in self._by_fqn.get(fqn, ()))

    def unresolved(self) -> SymbolRefCollection:
        """All symbol references that could not be resolved."""
        from flawed._index._collections import SymbolRefCollection
        from flawed._index._types import ResolutionStatus

        return SymbolRefCollection(
            tuple(r for r in self._refs if r.resolution == ResolutionStatus.UNRESOLVED)
        )

    def __len__(self) -> int:
        return len(self._refs)

    def __repr__(self) -> str:
        return f"SymbolIndex({len(self._refs)} refs, {len(self._defined_fqns)} resolved FQNs)"
