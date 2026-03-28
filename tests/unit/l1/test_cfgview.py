"""Tests for the Layer 2 control-flow view boundary."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from flawed._index._types import CFGBlock, ResolutionStatus, SourceSpan
from flawed._semantic._cfgview import ControlFlowView, InterproceduralControlFlowView
from flawed.core import Location

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flawed._index import CodeIndex
    from flawed._index._graphs import ControlFlowGraph
    from flawed.core import AnalysisGap


def _loc(line: int) -> Location:
    return Location(file="app.py", line=line, column=0, end_line=line, end_column=10)


def _span(line: int) -> SourceSpan:
    return SourceSpan(file="app.py", line=line, column=0, end_line=line, end_column=10)


def _block(block_id: int, *lines: int) -> CFGBlock:
    return CFGBlock(
        id=block_id,
        statements=tuple(_span(line) for line in lines),
        successors=(),
        predecessors=(),
        condition_expr=None,
    )


class _BlockGraph:
    """Minimal fake exposing the ``blocks`` surface the view reads."""

    def __init__(self, *blocks: CFGBlock) -> None:
        self._blocks = blocks

    @property
    def blocks(self) -> tuple[CFGBlock, ...]:
        return self._blocks


class _ReachabilityOnlyGraph:
    def __init__(self) -> None:
        self.queried_spans: tuple[SourceSpan, SourceSpan] | None = None

    def reachable_between(self, loc_a: SourceSpan, loc_b: SourceSpan) -> bool:
        self.queried_spans = (loc_a, loc_b)
        return True

    def paths_between(self, loc_a: SourceSpan, loc_b: SourceSpan) -> object:
        raise AssertionError("reachable_between must not enumerate concrete CFG paths")


def test_reachable_between_delegates_to_boolean_graph_query() -> None:
    graph = _ReachabilityOnlyGraph()
    view = ControlFlowView(cast("ControlFlowGraph", graph))

    assert view.reachable_between(_loc(1), _loc(2))
    assert graph.queried_spans == (
        SourceSpan(file="app.py", line=1, column=0, end_line=1, end_column=10),
        SourceSpan(file="app.py", line=2, column=0, end_line=2, end_column=10),
    )


def test_statement_locations_projects_l1_spans_to_public_locations() -> None:
    graph = _BlockGraph(_block(0, 3, 4), _block(1, 7))
    view = ControlFlowView(cast("ControlFlowGraph", graph))

    assert view.statement_locations(0) == (_loc(3), _loc(4))
    assert view.statement_locations(1) == (_loc(7),)


def test_statement_locations_unknown_block_returns_empty() -> None:
    graph = _BlockGraph(_block(0, 3))
    view = ControlFlowView(cast("ControlFlowGraph", graph))

    assert view.statement_locations(99) == ()


def test_statement_locations_respects_block_filter_scope() -> None:
    graph = _BlockGraph(_block(0, 3), _block(1, 7))
    view = ControlFlowView(cast("ControlFlowGraph", graph), block_filter=frozenset({1}))

    # Block 0 is outside this restricted view -> no fabricated spans.
    assert view.statement_locations(0) == ()
    assert view.statement_locations(1) == (_loc(7),)


def test_statement_locations_unavailable_view_returns_empty() -> None:
    view = ControlFlowView.unavailable()

    assert view.statement_locations(0) == ()


# --- Interprocedural view (FLAW-242a) -------------------------------------
#
# Fake the minimal L1 surface the cross-frame ``precedes`` algorithm touches:
# per-function CFGs keyed by fqn, line-range ownership, intra-CFG line order,
# and a call graph whose ``edges_from`` lists resolved/unresolved call sites.
# Functions occupy disjoint line ranges so ``_owning_fqn`` is unambiguous.

_ROOT = "mod.root"  # lines 10-20, calls helper at line 15
_HELPER = "mod.helper"  # lines 30-40, calls deep at line 35
_DEEP = "mod.deep"  # lines 50-60 (reached only via helper -> depth 2)

_RANGES = {_ROOT: (10, 20), _HELPER: (30, 40), _DEEP: (50, 60)}


@dataclass(frozen=True)
class _FakeEdge:
    """Duck-typed CallEdge: only the fields the algorithm reads."""

    callee_fqn: str | None
    resolution: ResolutionStatus
    location: SourceSpan


@dataclass(frozen=True)
class _FakeBlock:
    """Minimal CFGBlock stand-in: an ``id`` and projectable ``statements``."""

    id: int
    statements: tuple[SourceSpan, ...] = ()


class _FakeCFG:
    """Per-function CFG over one disjoint line range, modelled as a single
    straight-line basic block (id 0).

    ``precedes`` / ``dominates`` / ``reachable_between`` hold for owned operands
    in source order -- the linear-block contract of the real L1 CFG, close
    enough to exercise the inherited ControlFlowView query surface now that
    :class:`InterproceduralControlFlowView` is backed by the root's CFG. Spans
    outside the owned range answer conservatively (``False``/``None``)."""

    def __init__(self, lo: int, hi: int) -> None:
        self._lo = lo
        self._hi = hi

    def _owns(self, span: SourceSpan) -> bool:
        return self._lo <= span.line <= self._hi

    @property
    def blocks(self) -> tuple[_FakeBlock, ...]:
        return (_FakeBlock(0),)

    @property
    def try_regions(self) -> tuple[object, ...]:
        return ()

    def block_for(self, span: SourceSpan) -> _FakeBlock | None:
        return _FakeBlock(0) if self._owns(span) else None

    def precedes(self, a: SourceSpan, b: SourceSpan) -> bool:
        # Mirror the real contract: both must resolve to a block here.
        return self._owns(a) and self._owns(b) and a.line < b.line

    def dominates(self, a: SourceSpan, b: SourceSpan) -> bool:
        # Single linear block: every path to b passes through an earlier-or-equal a.
        return self._owns(a) and self._owns(b) and a.line <= b.line

    def reachable_between(self, a: SourceSpan, b: SourceSpan) -> bool:
        return self._owns(a) and self._owns(b) and a.line <= b.line


class _FakeCallGraph:
    def __init__(self, edges_by_caller: Mapping[str, tuple[_FakeEdge, ...]]) -> None:
        self._edges = edges_by_caller

    def edges_from(self, fqn: str) -> tuple[_FakeEdge, ...]:
        return self._edges.get(fqn, ())


class _FakeIndex:
    def __init__(self, edges_by_caller: Mapping[str, tuple[_FakeEdge, ...]]) -> None:
        self._call_graph = _FakeCallGraph(edges_by_caller)

    def cfg(self, fqn: str) -> _FakeCFG | None:
        rng = _RANGES.get(fqn)
        return _FakeCFG(*rng) if rng is not None else None

    @property
    def call_graph(self) -> _FakeCallGraph:
        return self._call_graph


def _resolved_edge(callee: str, line: int) -> _FakeEdge:
    return _FakeEdge(callee, ResolutionStatus.RESOLVED, _span(line))


def _interproc(
    edges_by_caller: Mapping[str, tuple[_FakeEdge, ...]],
    *,
    reachable: tuple[str, ...] = (_HELPER, _DEEP),
    gaps: tuple[object, ...] = (),
) -> InterproceduralControlFlowView:
    return InterproceduralControlFlowView(
        root_fqn=_ROOT,
        index=cast("CodeIndex", _FakeIndex(edges_by_caller)),
        reachable_fqns=reachable,
        gaps=cast("tuple[AnalysisGap, ...]", gaps),
    )


# root calls helper once (line 15); helper calls deep once (line 35).
_SINGLE_CALL = {
    _ROOT: (_resolved_edge(_HELPER, 15),),
    _HELPER: (_resolved_edge(_DEEP, 35),),
}


def test_interproc_same_frame_delegates_to_owning_cfg() -> None:
    view = _interproc(_SINGLE_CALL)
    # Both operands in root (lines 12, 18).
    assert view.precedes(_loc(12), _loc(18)) is True
    assert view.precedes(_loc(18), _loc(12)) is False


def test_interproc_cross_frame_orders_through_single_call_site() -> None:
    view = _interproc(_SINGLE_CALL)
    # A in root @12 (before call site @15); B in helper @35.
    assert view.precedes(_loc(12), _loc(35)) is True
    # Reverse: helper write cannot precede the earlier root read.
    assert view.precedes(_loc(35), _loc(12)) is False


def test_interproc_both_operands_in_helper_use_helper_cfg() -> None:
    view = _interproc(_SINGLE_CALL)
    assert view.precedes(_loc(32), _loc(38)) is True
    assert view.precedes(_loc(38), _loc(32)) is False


def test_interproc_helper_called_twice_is_ambiguous_gap() -> None:
    edges = {_ROOT: (_resolved_edge(_HELPER, 15), _resolved_edge(_HELPER, 16))}
    view = _interproc(edges)
    # Two resolved call sites -> cannot pick a single ordering point -> False.
    assert view.precedes(_loc(12), _loc(35)) is False


def test_interproc_unresolved_callee_is_gap() -> None:
    edges = {_ROOT: (_FakeEdge(_HELPER, ResolutionStatus.UNRESOLVED, _span(15)),)}
    view = _interproc(edges)
    assert view.precedes(_loc(12), _loc(35)) is False


def test_interproc_depth_two_chain_stays_gap() -> None:
    # deep is owned + reachable, but called by helper, not root -> no direct edge.
    view = _interproc(_SINGLE_CALL)
    assert view.precedes(_loc(12), _loc(55)) is False


def test_interproc_operand_in_no_reachable_function_is_false() -> None:
    view = _interproc(_SINGLE_CALL)
    assert view.precedes(_loc(12), _loc(999)) is False


def test_interproc_ordered_picks_up_overridden_precedes() -> None:
    view = _interproc(_SINGLE_CALL)
    # ordered() delegates to the overridden precedes across frames.
    assert view.ordered(_loc(12), _loc(35)) is True
    assert view.ordered(_loc(35), _loc(12)) is False


def test_interproc_surface_is_root_backed_superset() -> None:
    # Backed by the ROOT handler's CFG (FLAW-242b): inherited graph queries are
    # REAL for root-frame (handler) locations -- so URL-guard suppression keeps
    # working -- and conservative for helper-frame locations not in the root
    # graph. cross-frame ordering still routes through the precedes override.
    sentinel_gaps: tuple[object, ...] = ("gap-a", "gap-b")
    view = _interproc(_SINGLE_CALL, gaps=sentinel_gaps)
    assert view.gaps == sentinel_gaps
    # Root-frame (lines 10-20): the surface answers from the root CFG, not None.
    assert view.blocks != ()
    assert view.block_id_for(_loc(12)) == 0
    assert view.dominates(_loc(12), _loc(18)) is True
    assert view.dominates(_loc(18), _loc(12)) is False
    assert view.reachable_between(_loc(12), _loc(18)) is True
    # Helper-frame (line 35) is absent from the root graph -> conservative.
    assert view.block_id_for(_loc(35)) is None
    assert view.dominates(_loc(32), _loc(38)) is False
    # No statements modelled on block 0 -> projection is empty, never fabricated.
    assert view.statement_locations(0) == ()
