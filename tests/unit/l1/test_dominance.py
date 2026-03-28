"""Layer 1 dominance analysis tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flawed._index._dominance import (
    DominanceGraph,
    _cfgraph_from_cfg,
    _snapshot_dominance,
    check_guard_dominance,
    dominance_from_cfg,
)
from flawed._index._graphs import ControlFlowGraph
from flawed._index._types import CFGBlock, CFGEdge
from flawed._index._vendor import CFGraph

if TYPE_CHECKING:
    from collections.abc import Hashable, Iterable


def _processed_graph(
    *,
    nodes: Iterable[Hashable],
    edges: Iterable[tuple[Hashable, Hashable]],
    entry: Hashable,
) -> CFGraph:
    graph = CFGraph()
    for node in nodes:
        graph.add_node(node)
    graph.set_entry_point(entry)
    for source, target in edges:
        graph.add_edge(source, target)
    graph.process()
    return graph


def _processed_dominance(
    *,
    nodes: Iterable[Hashable],
    edges: Iterable[tuple[Hashable, Hashable]],
    entry: Hashable,
) -> DominanceGraph:
    return _snapshot_dominance(_processed_graph(nodes=nodes, edges=edges, entry=entry))


def _block(
    block_id: int,
    *,
    successors: tuple[int, ...] = (),
    predecessors: tuple[int, ...] = (),
) -> CFGBlock:
    return CFGBlock(
        id=block_id,
        statements=(),
        successors=successors,
        predecessors=predecessors,
        condition_expr=None,
    )


def _edge(source: int, target: int, label: str = "fallthrough") -> CFGEdge:
    return CFGEdge(
        source_id=source,
        target_id=target,
        label=label,
        is_exceptional=False,
    )


def _cfg(blocks: tuple[CFGBlock, ...], edges: tuple[CFGEdge, ...]) -> ControlFlowGraph:
    return ControlFlowGraph(blocks, edges)


class TestBasicGraphOperations:
    def test_entry_only_graph_dominates_itself(self) -> None:
        graph = _processed_graph(nodes=("entry",), edges=(), entry="entry")

        assert graph.entry_point() == "entry"
        assert graph.dominators() == {"entry": {"entry"}}
        assert graph.immediate_dominators() == {"entry": "entry"}
        assert graph.dominance_frontier() == {"entry": set()}

    def test_linear_chain_dominators_accumulate(self) -> None:
        graph = _processed_graph(
            nodes=("A", "B", "C", "D"),
            edges=(("A", "B"), ("B", "C"), ("C", "D")),
            entry="A",
        )

        assert graph.dominators() == {
            "A": {"A"},
            "B": {"A", "B"},
            "C": {"A", "B", "C"},
            "D": {"A", "B", "C", "D"},
        }
        assert graph.immediate_dominators() == {
            "A": "A",
            "B": "A",
            "C": "B",
            "D": "C",
        }

    def test_dead_nodes_are_eliminated_during_processing(self) -> None:
        graph = _processed_graph(
            nodes=("entry", "live", "dead"),
            edges=(("entry", "live"),),
            entry="entry",
        )

        assert graph.nodes() == {"entry", "live"}
        assert graph.dead_nodes() == {"dead"}
        assert "dead" not in graph.dominators()


class TestBranchAnalysis:
    def test_diamond_merge_is_in_each_branch_frontier(self) -> None:
        graph = _processed_graph(
            nodes=("A", "B", "C", "D"),
            edges=(("A", "B"), ("A", "C"), ("B", "D"), ("C", "D")),
            entry="A",
        )

        assert graph.dominators()["D"] == {"A", "D"}
        assert graph.dominance_frontier()["B"] == {"D"}
        assert graph.dominance_frontier()["C"] == {"D"}

    def test_if_elif_else_merge_has_three_branch_frontiers(self) -> None:
        graph = _processed_graph(
            nodes=("A", "B", "C", "D", "E"),
            edges=(
                ("A", "B"),
                ("A", "C"),
                ("A", "D"),
                ("B", "E"),
                ("C", "E"),
                ("D", "E"),
            ),
            entry="A",
        )

        assert graph.immediate_dominators() == {
            "A": "A",
            "B": "A",
            "C": "A",
            "D": "A",
            "E": "A",
        }
        assert graph.dominance_frontier()["B"] == {"E"}
        assert graph.dominance_frontier()["C"] == {"E"}
        assert graph.dominance_frontier()["D"] == {"E"}


class TestAuthGuardPatterns:
    def test_guard_before_sensitive_operation_is_sufficient(self) -> None:
        graph = _processed_dominance(
            nodes=("entry", "auth_check", "sensitive_op", "return"),
            edges=(
                ("entry", "auth_check"),
                ("auth_check", "sensitive_op"),
                ("sensitive_op", "return"),
            ),
            entry="entry",
        )

        result = check_guard_dominance(graph, "auth_check", "sensitive_op")

        assert result.is_sufficient
        assert result.dominance_frontier == frozenset()
        assert result.gaps == ()

    def test_bypass_path_reports_sensitive_operation_as_merge_frontier(self) -> None:
        graph = _processed_dominance(
            nodes=("entry", "auth_check", "sensitive_op"),
            edges=(
                ("entry", "auth_check"),
                ("auth_check", "sensitive_op"),
                ("entry", "sensitive_op"),
            ),
            entry="entry",
        )

        result = check_guard_dominance(graph, "auth_check", "sensitive_op")

        assert not result.is_sufficient
        assert result.dominance_frontier == frozenset({"sensitive_op"})
        assert result.gaps == ()

    def test_early_return_guard_dominates_denial_and_proceed_paths(self) -> None:
        graph = _processed_dominance(
            nodes=("entry", "guard", "return_403", "proceed", "sensitive"),
            edges=(
                ("entry", "guard"),
                ("guard", "return_403"),
                ("guard", "proceed"),
                ("proceed", "sensitive"),
            ),
            entry="entry",
        )

        assert graph.dominates("guard", "return_403")
        assert check_guard_dominance(graph, "guard", "sensitive").is_sufficient

    def test_unknown_guard_block_returns_gap_instead_of_fail_open_result(self) -> None:
        graph = _processed_dominance(
            nodes=("entry", "sensitive"),
            edges=(("entry", "sensitive"),),
            entry="entry",
        )

        result = check_guard_dominance(graph, "missing_guard", "sensitive")

        assert not result.is_sufficient
        assert result.dominance_frontier == frozenset()
        assert len(result.gaps) == 1
        assert "missing_guard" in result.gaps[0].message


class TestLoopAnalysis:
    def test_simple_loop_detects_header_body_and_exit(self) -> None:
        graph = _processed_graph(
            nodes=("A", "B", "C"),
            edges=(("A", "B"), ("B", "A"), ("A", "C")),
            entry="A",
        )

        loop = graph.loops()["A"]

        assert loop.header == "A"
        assert loop.body == {"A", "B"}
        assert loop.entries == set()
        assert loop.exits == {"C"}

    def test_nested_loops_preserve_inner_to_outer_membership(self) -> None:
        graph = _processed_graph(
            nodes=("A", "B", "C", "D", "E", "F"),
            edges=(
                ("A", "B"),
                ("B", "C"),
                ("C", "B"),
                ("C", "D"),
                ("D", "E"),
                ("E", "D"),
                ("E", "B"),
                ("B", "F"),
            ),
            entry="A",
        )

        assert graph.loops()["B"].body == {"B", "C", "D", "E"}
        assert graph.loops()["D"].body == {"D", "E"}
        assert [loop.header for loop in graph.in_loops("E")] == ["D", "B"]


class TestPostDominatorAnalysis:
    def test_multiple_return_paths_do_not_share_a_concrete_post_dominator(self) -> None:
        graph = _processed_graph(
            nodes=("entry", "left", "right", "ret1", "ret2"),
            edges=(
                ("entry", "left"),
                ("entry", "right"),
                ("left", "ret1"),
                ("right", "ret2"),
            ),
            entry="entry",
        )

        post_dominators = graph.post_dominators()

        assert post_dominators["entry"] == {"entry"}
        assert post_dominators["left"] == {"left", "ret1"}
        assert post_dominators["right"] == {"right", "ret2"}

    def test_error_handler_does_not_post_dominate_when_success_path_exists(self) -> None:
        graph = _processed_graph(
            nodes=("risky_op", "handler", "success"),
            edges=(("risky_op", "handler"), ("risky_op", "success")),
            entry="risky_op",
        )

        assert "handler" not in graph.post_dominators()["risky_op"]


class TestDominanceBridge:
    def test_layer1_cfg_edges_are_mapped_to_processed_cfgraph(self) -> None:
        cfg_edge = _edge(1, 3)
        cfg = _cfg(
            (
                _block(0, successors=(1, 2)),
                _block(1, successors=(3,), predecessors=(0,)),
                _block(2, successors=(3,), predecessors=(0,)),
                _block(3, predecessors=(1, 2)),
            ),
            (
                _edge(0, 1, "true"),
                _edge(0, 2, "false"),
                cfg_edge,
                _edge(2, 3),
            ),
        )

        graph = dominance_from_cfg(cfg)
        raw_graph = _cfgraph_from_cfg(cfg)

        assert graph.entry_block_id == 0
        assert graph.dominance_frontier(1) == frozenset({3})
        assert graph.successors(1) == frozenset({3})
        assert dict(raw_graph.successors(1)) == {3: cfg_edge}

    def test_empty_cfg_is_explicit_invalid_input(self) -> None:
        cfg = _cfg((), ())

        with pytest.raises(ValueError, match="empty CFG"):
            dominance_from_cfg(cfg)

    def test_edge_to_unknown_block_is_explicit_invalid_input(self) -> None:
        cfg = _cfg(
            (
                _block(0, successors=(2,)),
                _block(1),
            ),
            (_edge(0, 2),),
        )

        with pytest.raises(ValueError, match="unknown target block 2"):
            dominance_from_cfg(cfg)
