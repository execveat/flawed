"""Layer 1 dominance analysis.

This module adapts the Code Index ``ControlFlowGraph`` representation to the
vendored Numba dominance algorithms.  The vendored ``CFGraph`` is a mutable
implementation detail: Layer 1 builds it, snapshots the derived facts into
frozen/query-only objects, and exposes only those objects through
``CodeIndex.dominance()``.

The public boundary is intentionally block-oriented and framework-neutral.
Callers ask dominance questions over Layer 1 block IDs; they never receive
Numba graph objects, mutable dominance maps, or mutable node sets.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, cast

from flawed._index._vendor import CFGraph as _CFGraph
from flawed._index._vendor import Loop as _Loop

if TYPE_CHECKING:
    from collections.abc import Hashable, Mapping

    from flawed._index._graphs import ControlFlowGraph


__all__ = [
    "DominanceGap",
    "DominanceGraph",
    "DominanceLoop",
    "GuardResult",
    "check_guard_dominance",
    "dominance_from_cfg",
]


@dataclass(frozen=True, slots=True)
class DominanceGap:
    """Layer 1 dominance-analysis gap.

    Layer 1 cannot import the Rule API ``AnalysisGap`` type without violating
    import-linter contracts.  This frozen local gap preserves the same no
    fail-open invariant at the structural boundary; downstream conversion can
    map it to the public gap model when dominance data crosses layers.
    """

    message: str
    """Human-readable reason the dominance result is incomplete."""


@dataclass(frozen=True, slots=True)
class DominanceLoop:
    """Frozen loop metadata derived from dominance analysis."""

    header: Hashable
    """Loop header block ID."""

    body: frozenset[Hashable]
    """Blocks that belong to the loop."""

    entries: frozenset[Hashable]
    """Blocks outside the loop that enter through the header."""

    exits: frozenset[Hashable]
    """Blocks outside the loop reachable from the loop body."""


@dataclass(frozen=True, slots=True)
class GuardResult:
    """Result of checking whether a guard block dominates a sensitive block."""

    guard_block: Hashable
    """Block representing the guard or authorization check."""

    sensitive_block: Hashable
    """Block representing the sensitive operation being protected."""

    is_sufficient: bool
    """``True`` when every entry-to-sensitive path passes through the guard."""

    dominance_frontier: frozenset[Hashable]
    """Merge points for paths dominated by the guard when the guard is insufficient."""

    gaps: tuple[DominanceGap, ...] = ()
    """Structural gaps that make the result incomplete."""


@dataclass(frozen=True, slots=True)
class DominanceGraph:
    """Frozen/query-only dominance facts for one Layer 1 control-flow graph."""

    entry_block_id: Hashable
    """Entry block ID for the function CFG."""

    block_ids: frozenset[Hashable]
    """Live block IDs after unreachable blocks are eliminated."""

    dead_block_ids: frozenset[Hashable]
    """Block IDs eliminated as unreachable during dominance processing."""

    exit_block_ids: frozenset[Hashable]
    """Live blocks with no outgoing edges."""

    _dominators: Mapping[Hashable, frozenset[Hashable]]
    _immediate_dominators: Mapping[Hashable, Hashable]
    _post_dominators: Mapping[Hashable, frozenset[Hashable]]
    _dominance_frontiers: Mapping[Hashable, frozenset[Hashable]]
    _loops_by_header: Mapping[Hashable, DominanceLoop]
    _loops_by_member: Mapping[Hashable, tuple[DominanceLoop, ...]]
    _successors: Mapping[Hashable, frozenset[Hashable]]

    def contains(self, block_id: Hashable) -> bool:
        """Return ``True`` when *block_id* is present and live."""
        return block_id in self.block_ids

    def dominates(self, dominator: Hashable, block: Hashable) -> bool:
        """Return whether *dominator* dominates *block*."""
        return dominator in self.dominators(block)

    def dominators(self, block: Hashable) -> frozenset[Hashable]:
        """Frozen set of blocks that dominate *block*."""
        return self._dominators.get(block, frozenset())

    def immediate_dominator(self, block: Hashable) -> Hashable | None:
        """Immediate dominator for *block*, or ``None`` when unknown."""
        return self._immediate_dominators.get(block)

    def post_dominates(self, post_dominator: Hashable, block: Hashable) -> bool:
        """Return whether *post_dominator* post-dominates *block*."""
        return post_dominator in self.post_dominators(block)

    def post_dominators(self, block: Hashable) -> frozenset[Hashable]:
        """Frozen set of blocks that post-dominate *block*."""
        return self._post_dominators.get(block, frozenset())

    def dominance_frontier(self, block: Hashable) -> frozenset[Hashable]:
        """Frozen dominance frontier for *block*."""
        return self._dominance_frontiers.get(block, frozenset())

    def loop(self, header: Hashable) -> DominanceLoop | None:
        """Loop metadata for *header*, or ``None`` if no loop starts there."""
        return self._loops_by_header.get(header)

    def loops(self) -> tuple[DominanceLoop, ...]:
        """All detected loops."""
        return tuple(self._loops_by_header.values())

    def loops_containing(self, block: Hashable) -> tuple[DominanceLoop, ...]:
        """Loops containing *block*, from innermost to outermost."""
        return self._loops_by_member.get(block, ())

    def successors(self, block: Hashable) -> frozenset[Hashable]:
        """Frozen set of successor block IDs for *block*."""
        return self._successors.get(block, frozenset())

    def check_guard(self, guard_block: Hashable, sensitive_block: Hashable) -> GuardResult:
        """Check whether ``guard_block`` dominates ``sensitive_block``.

        The result is explicit about incomplete analysis.  Unknown or
        unreachable blocks return a ``GuardResult`` with ``gaps`` populated
        instead of silently producing a negative dominance answer.
        """
        gaps = _dominance_input_gaps(self, guard_block, sensitive_block)
        if gaps:
            return GuardResult(
                guard_block=guard_block,
                sensitive_block=sensitive_block,
                is_sufficient=False,
                dominance_frontier=frozenset(),
                gaps=gaps,
            )

        is_sufficient = self.dominates(guard_block, sensitive_block)
        frontier: frozenset[Hashable] = frozenset()
        if not is_sufficient:
            frontier = self.dominance_frontier(guard_block)

        return GuardResult(
            guard_block=guard_block,
            sensitive_block=sensitive_block,
            is_sufficient=is_sufficient,
            dominance_frontier=frontier,
        )


def dominance_from_cfg(cfg: ControlFlowGraph) -> DominanceGraph:
    """Build a frozen dominance query object from a Layer 1 CFG.

    Invalid structural input raises ``ValueError`` rather than returning a
    partially populated graph, so callers cannot accidentally treat missing
    dominance data as a successful analysis.
    """
    return _snapshot_dominance(_cfgraph_from_cfg(cfg))


def _cfgraph_from_cfg(cfg: ControlFlowGraph) -> _CFGraph:
    """Build a processed vendored graph from a Layer 1 CFG.

    ``CFGraph`` requires an explicit entry point and registered endpoints for
    every edge.  The returned graph must remain private to Layer 1
    implementation code because it exposes mutators and mutable query maps.
    """
    _validate_cfg(cfg)

    graph = _CFGraph()  # type: ignore[no-untyped-call]
    for block in cfg.blocks:
        graph.add_node(block.id)  # type: ignore[no-untyped-call]

    entry = cfg.entry
    if entry is None:
        raise ValueError("cannot build dominance graph for empty CFG")
    graph.set_entry_point(entry.id)  # type: ignore[no-untyped-call]

    for edge in cfg.edges:
        graph.add_edge(edge.source_id, edge.target_id, edge)  # type: ignore[no-untyped-call]

    graph.process()  # type: ignore[no-untyped-call]
    return graph


def check_guard_dominance(
    dominance: DominanceGraph,
    guard_block: Hashable,
    sensitive_block: Hashable,
) -> GuardResult:
    """Check whether ``guard_block`` dominates ``sensitive_block``."""
    return dominance.check_guard(guard_block, sensitive_block)


def _snapshot_dominance(graph: _CFGraph) -> DominanceGraph:
    """Copy a processed vendored graph into immutable dominance facts."""
    if not hasattr(graph, "_dead_nodes"):
        raise ValueError("cannot snapshot unprocessed dominance graph")

    block_ids = frozenset(cast("set[Hashable]", graph.nodes()))  # type: ignore[no-untyped-call]
    dead_block_ids = frozenset(
        cast("set[Hashable]", graph.dead_nodes())  # type: ignore[no-untyped-call]
    )
    entry_block_id = cast("Hashable", graph.entry_point())  # type: ignore[no-untyped-call]
    exit_block_ids = frozenset(
        cast("set[Hashable]", graph.exit_points())  # type: ignore[no-untyped-call]
    )

    dominators = _freeze_set_mapping(
        block_ids,
        cast(
            "Mapping[Hashable, set[Hashable]]",
            graph.dominators(),  # type: ignore[no-untyped-call]
        ),
    )
    immediate_dominators = _freeze_value_mapping(
        cast(
            "Mapping[Hashable, Hashable]",
            graph.immediate_dominators(),  # type: ignore[no-untyped-call]
        )
    )
    post_dominators = _freeze_set_mapping(
        block_ids,
        cast(
            "Mapping[Hashable, set[Hashable]]",
            graph.post_dominators(),  # type: ignore[no-untyped-call]
        ),
    )
    frontiers = _freeze_set_mapping(
        block_ids,
        cast(
            "Mapping[Hashable, set[Hashable]]",
            graph.dominance_frontier(),  # type: ignore[no-untyped-call]
        ),
    )

    loops_by_header = {
        header: _freeze_loop(loop)
        for header, loop in cast(
            "Mapping[Hashable, _Loop]",
            graph.loops(),  # type: ignore[no-untyped-call]
        ).items()
    }
    loops_by_member = {
        block: tuple(
            loops_by_header[cast("Hashable", loop.header)]
            for loop in graph.in_loops(block)  # type: ignore[no-untyped-call]
        )
        for block in block_ids
    }
    successors = {
        block: frozenset(
            successor
            for successor, _edge_data in graph.successors(block)  # type: ignore[no-untyped-call]
        )
        for block in block_ids
    }

    return DominanceGraph(
        entry_block_id=entry_block_id,
        block_ids=block_ids,
        dead_block_ids=dead_block_ids,
        exit_block_ids=exit_block_ids,
        _dominators=_freeze_value_mapping(dominators),
        _immediate_dominators=immediate_dominators,
        _post_dominators=_freeze_value_mapping(post_dominators),
        _dominance_frontiers=_freeze_value_mapping(frontiers),
        _loops_by_header=_freeze_value_mapping(loops_by_header),
        _loops_by_member=_freeze_value_mapping(loops_by_member),
        _successors=_freeze_value_mapping(successors),
    )


def _freeze_loop(loop: _Loop) -> DominanceLoop:
    return DominanceLoop(
        header=cast("Hashable", loop.header),
        body=frozenset(cast("set[Hashable]", loop.body)),
        entries=frozenset(cast("set[Hashable]", loop.entries)),
        exits=frozenset(cast("set[Hashable]", loop.exits)),
    )


def _freeze_set_mapping(
    keys: frozenset[Hashable],
    values: Mapping[Hashable, set[Hashable]],
) -> dict[Hashable, frozenset[Hashable]]:
    return {key: frozenset(values.get(key, set())) for key in keys}


def _freeze_value_mapping[K, V](values: Mapping[K, V]) -> Mapping[K, V]:
    return MappingProxyType(dict(values))


def _validate_cfg(cfg: ControlFlowGraph) -> None:
    block_ids = tuple(block.id for block in cfg.blocks)
    if not block_ids:
        raise ValueError("cannot build dominance graph for empty CFG")

    unique_block_ids = set(block_ids)
    if len(unique_block_ids) != len(block_ids):
        raise ValueError("cannot build dominance graph for CFG with duplicate block ids")

    for edge in cfg.edges:
        if edge.source_id not in unique_block_ids:
            raise ValueError(
                "cannot build dominance graph for CFG edge "
                f"with unknown source block {edge.source_id}"
            )
        if edge.target_id not in unique_block_ids:
            raise ValueError(
                "cannot build dominance graph for CFG edge "
                f"with unknown target block {edge.target_id}"
            )


def _dominance_input_gaps(
    dominance: DominanceGraph,
    guard_block: Hashable,
    sensitive_block: Hashable,
) -> tuple[DominanceGap, ...]:
    gaps: list[DominanceGap] = []
    for role, block in (("guard", guard_block), ("sensitive", sensitive_block)):
        if block in dominance.dead_block_ids:
            gaps.append(DominanceGap(f"{role} block {block!r} was eliminated as unreachable"))
        elif block not in dominance.block_ids:
            gaps.append(DominanceGap(f"{role} block {block!r} is not present in the graph"))
    return tuple(gaps)
