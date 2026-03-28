"""Layer 2 control-flow query view backed by the Layer 1 CFG."""

from __future__ import annotations

from itertools import pairwise
from typing import TYPE_CHECKING

from flawed._index._types import ResolutionStatus, SourceSpan
from flawed._semantic._conversion_utils import location as _location

if TYPE_CHECKING:
    from flawed._index import CodeIndex
    from flawed._index._graphs import ControlFlowGraph
    from flawed._index._types import CFGBlock, TryExceptRegion
    from flawed.core import AnalysisGap, Location


class ControlFlowView:
    """Concrete control-flow query surface for a code scope.

    The view owns the boundary from public source locations to the L1 CFG
    query API. Missing CFG data returns conservative answers rather than
    fabricating ordering or reachability.
    """

    __slots__ = ("_block_filter", "_gaps", "_graph")

    def __init__(
        self,
        graph: ControlFlowGraph | None,
        *,
        block_filter: frozenset[int] | None = None,
        gaps: tuple[AnalysisGap, ...] = (),
    ) -> None:
        self._graph = graph
        self._block_filter = block_filter
        self._gaps = gaps

    @classmethod
    def unavailable(cls, *, gaps: tuple[AnalysisGap, ...] = ()) -> ControlFlowView:
        """Build a conservative view when no single CFG backs the scope."""
        return cls(None, gaps=gaps)

    def restricted_to(self, block_ids: frozenset[int]) -> ControlFlowView:
        """Build a view that exposes only the given CFG block IDs."""
        if self._graph is None:
            return self
        return ControlFlowView(self._graph, block_filter=block_ids, gaps=self._gaps)

    @property
    def blocks(self) -> tuple[CFGBlock, ...]:
        """Basic blocks for the backing CFG, or empty when unavailable."""
        if self._graph is None:
            return ()
        if self._block_filter is None:
            return self._graph.blocks
        return tuple(block for block in self._graph.blocks if block.id in self._block_filter)

    @property
    def gaps(self) -> tuple[AnalysisGap, ...]:
        """Analysis gaps affecting this CFG view."""
        return self._gaps

    def dominates(self, a: Location, b: Location) -> bool:
        """Return whether every path to ``b`` passes through ``a``."""
        if self._graph is None:
            return False
        if not self._contains_locations(a, b):
            return False
        return self._graph.dominates(_source_span(a), _source_span(b))

    def precedes(self, a: Location, b: Location) -> bool:
        """Return whether ``a`` executes before ``b`` on all paths."""
        if self._graph is None:
            return False
        if not self._contains_locations(a, b):
            return False
        return self._graph.precedes(_source_span(a), _source_span(b))

    def ordered(self, *locations: Location) -> bool:
        """Return whether all locations appear in the given order."""
        return all(self.precedes(a, b) for a, b in pairwise(locations))

    def reachable_between(self, a: Location, b: Location) -> bool:
        """Return whether any execution path exists from ``a`` to ``b``."""
        if self._graph is None:
            return False
        if not self._contains_locations(a, b):
            return False
        return self._graph.reachable_between(_source_span(a), _source_span(b))

    @property
    def try_regions(self) -> tuple[TryExceptRegion, ...]:
        """Structured try/except/finally region metadata, or empty if unavailable."""
        if self._graph is None:
            return ()
        return self._graph.try_regions

    def raise_edges(self) -> tuple[tuple[int, Location], ...]:
        """``(source block id, source location)`` for each ``raise``-labelled CFG edge.

        A ``raise`` statement emits a CFG edge labelled ``"raise"`` from its block. This is
        the only place the ``raise`` keyword survives: at the call-site level ``raise X(...)``
        and a bare ``X(...)`` call look identical. It lets :meth:`swallowed_rejections`
        tell a *rejection* raise inside a ``try`` body from a *re-raising* handler. FLAW-319.
        """
        if self._graph is None:
            return ()
        out: list[tuple[int, Location]] = []
        for edge in self._graph.edges:
            if edge.label != "raise":
                continue
            locations = self.statement_locations(edge.source_id)
            if locations:
                out.append((edge.source_id, locations[-1]))
        return tuple(out)

    def statement_locations(self, block_id: int) -> tuple[Location, ...]:
        """Return the source location of each statement in block *block_id*.

        Projects the Layer-1 ``CFGBlock.statements`` spans into public
        :class:`~flawed.core.Location` objects. This bridges the L1/L3 shape
        gap that keeps ``statements`` off the public :class:`CFGBlock`
        protocol (its element type is a Layer-1 span with no L3 equivalent).

        Returns an empty tuple when no block with that ID is visible in this
        view -- an unknown ID, a block outside a restricted scope, or a view
        with no backing CFG. It never fabricates spans.
        """
        for block in self.blocks:
            if block.id == block_id:
                return tuple(_location(span) for span in block.statements)
        return ()

    def block_id_for(self, location: Location) -> int | None:
        """Return the block ID containing *location*, or ``None``."""
        if self._graph is None:
            return None
        block = self._graph.block_for(_source_span(location))
        if (
            block is not None
            and self._block_filter is not None
            and block.id not in self._block_filter
        ):
            return None
        return block.id if block is not None else None

    def _contains_locations(self, *locations: Location) -> bool:
        if self._block_filter is None:
            return True
        for location in locations:
            block = (
                self._graph.block_for(_source_span(location)) if self._graph is not None else None
            )
            if block is None or block.id not in self._block_filter:
                return False
        return True

    def branch_arm_block_ids(self, location: Location, *, direction: bool) -> frozenset[int]:
        """Return CFG blocks that belong only to one arm of a branch.

        The selected arm is the ``true`` or ``false`` edge leaving the branch
        block at *location*. Blocks shared after the arms rejoin are excluded.
        """
        return self._branch_block_ids(location, direction=direction, include_join=False)

    def branch_path_block_ids(self, location: Location, *, direction: bool) -> frozenset[int]:
        """Return CFG blocks reachable after taking one branch direction.

        Unlike :meth:`branch_arm_block_ids`, this includes blocks after the
        branch rejoins when those blocks are reachable from the selected edge.
        It still blocks traversal into the opposite branch's entry block.
        """
        return self._branch_block_ids(location, direction=direction, include_join=True)

    def _branch_block_ids(
        self,
        location: Location,
        *,
        direction: bool,
        include_join: bool,
    ) -> frozenset[int]:
        if self._graph is None:
            return frozenset()
        block = self._graph.block_for(_source_span(location))
        if block is None:
            return frozenset()

        selected_targets = self._branch_targets(block.id, direction=direction)
        if not selected_targets:
            return frozenset()
        opposite_targets = self._branch_targets(block.id, direction=not direction)

        selected = self._reachable_block_ids(
            selected_targets,
            blocked=frozenset(opposite_targets),
        )
        if include_join:
            return selected

        opposite = self._reachable_block_ids(
            opposite_targets,
            blocked=frozenset(selected_targets),
        )
        return selected - opposite

    def _branch_targets(self, block_id: int, *, direction: bool) -> tuple[int, ...]:
        if self._graph is None:
            return ()
        label = "true" if direction else "false"
        return tuple(
            edge.target_id
            for edge in self._graph.edges
            if edge.source_id == block_id and edge.label == label
        )

    def _reachable_block_ids(
        self,
        starts: tuple[int, ...],
        *,
        blocked: frozenset[int],
    ) -> frozenset[int]:
        if self._graph is None:
            return frozenset()

        seen: set[int] = set()
        pending = list(starts)
        while pending:
            block_id = pending.pop()
            if block_id in seen or block_id in blocked:
                continue
            seen.add(block_id)
            pending.extend(block.id for block in self._graph.successors(block_id))
        return frozenset(seen)


def _source_span(location: Location) -> SourceSpan:
    """Convert a public location to the L1 span shape expected by CFG queries."""
    return SourceSpan(
        file=location.file,
        line=location.line,
        column=location.column,
        end_line=location.end_line if location.end_line is not None else location.line,
        end_column=location.end_column if location.end_column is not None else location.column,
    )


class InterproceduralControlFlowView(ControlFlowView):
    """Cross-frame ordering view over a reachable scope (root + its callees).

    Backed by the *root handler's* own CFG (``index.cfg(root_fqn)``), so every
    inherited graph query (``dominates``, ``block_id_for``, ``blocks``, the
    guarded-branch checks ``_sink_in_guarded_branch`` consumes) answers exactly
    as it did before this view replaced the handler-local ``ControlFlowView`` --
    for handler-frame locations -- and conservatively (``None``/``False``) for
    helper-frame locations not in the root graph. This makes the interproc view
    a true *superset* of the old reachable cfg: same intra-handler behaviour,
    plus the cross-frame :meth:`precedes` below. (Backing it with no graph
    silenced URL-guard suppression -> FLAW-242b OPEN_REDIRECT false positives.)

    :meth:`precedes` (and :meth:`ordered`, which delegates to it) is the only
    query that reasons *across* frames, by stitching per-function CFGs at
    *uniquely resolved* single call sites -- it is independent of the backing
    graph (it owns ``_owning_fqn`` + ``index.cfg`` + call-site stitching).
    ``dominates`` and ``reachable_between`` stay at their inherited (root-frame)
    semantics: an auth-ordering rule needs only ``precedes``, and a sound
    *cross-frame* dominance query is out of scope here.

    Lazy by construction: stores only the root fqn, an index reference, and the
    reachable fqn set. All CFG access happens on demand inside ``precedes`` via
    the memoized ``index.cfg(fqn)`` -- no eager graph stitching, so per-scope
    construction stays O(1) (the build-time perf risk FLAW-242 gates on).

    Soundness contract (priority #1, no false negatives via fabricated order):
    a ``True`` result is only ever the *root's* intra-procedural ``precedes``
    confirming the representative ordering. Every uncertain case -- unknown
    owner, missing CFG, deeper-than-one-hop chain, ambiguous fan-in, unresolved
    callee -- returns ``False``, leaving the rule's existing gap intact. It can
    never silence a finding or invent an ordering.
    """

    __slots__ = ("_index", "_reachable_fqns", "_root_fqn")

    def __init__(
        self,
        *,
        root_fqn: str,
        index: CodeIndex,
        reachable_fqns: tuple[str, ...],
        gaps: tuple[AnalysisGap, ...] = (),
    ) -> None:
        # Back the view with the root handler's own CFG: root_fqn == handler.fqn,
        # so inherited graph queries (dominates/block_id_for/blocks, used by
        # _sink_in_guarded_branch) behave identically to the old handler-local
        # reachable cfg for handler-frame locations, and conservatively for
        # helper-frame locations absent from the root graph. precedes() overrides
        # cross-frame reasoning independently. (None backing -> FLAW-242b FPs.)
        super().__init__(index.cfg(root_fqn), gaps=gaps)
        self._root_fqn = root_fqn
        self._index = index
        self._reachable_fqns = reachable_fqns

    def precedes(self, a: Location, b: Location) -> bool:
        """Return whether ``a`` provably executes before ``b`` on all paths,
        across at most a single resolved call hop. Any uncertainty -> ``False``."""
        fn_a = self._owning_fqn(a)
        fn_b = self._owning_fqn(b)
        if fn_a is None or fn_b is None:
            return False
        if fn_a == fn_b:  # same frame -> that function's own CFG decides
            graph = self._index.cfg(fn_a)
            return graph is not None and graph.precedes(_source_span(a), _source_span(b))
        rep_a = self._representative_in_root(a, fn_a)  # cross frame, single hop
        rep_b = self._representative_in_root(b, fn_b)
        if rep_a is None or rep_b is None:
            return False
        root_cfg = self._index.cfg(self._root_fqn)
        return root_cfg is not None and root_cfg.precedes(rep_a, rep_b)

    def _owning_fqn(self, location: Location) -> str | None:
        """Return the reachable function whose CFG contains *location*, or ``None``.

        Reuses the L1 ``block_for`` query -- no new index API. Functions occupy
        disjoint source spans, so the first containing CFG is unambiguous.
        """
        span = _source_span(location)
        for fqn in (self._root_fqn, *self._reachable_fqns):
            graph = self._index.cfg(fqn)
            if graph is not None and graph.block_for(span) is not None:
                return fqn
        return None

    def _representative_in_root(self, location: Location, fqn: str) -> SourceSpan | None:
        """Map *location* (owned by *fqn*) to a span orderable by the root's CFG.

        - ``fqn`` is the root          -> the operand's own span.
        - ``fqn`` is a helper called from the root by exactly ONE resolved edge
          -> that call site's span (a call site totally orders the callee body
          against the caller's statements on every path).
        - 0 or >=2 resolved call sites, or only unresolved edges -> ``None``
          (bail; the rule's gap stays).
        """
        if fqn == self._root_fqn:
            return _source_span(location)
        sites = [
            edge.location
            for edge in self._index.call_graph.edges_from(self._root_fqn)
            if edge.callee_fqn == fqn and edge.resolution is ResolutionStatus.RESOLVED
        ]
        return sites[0] if len(sites) == 1 else None
