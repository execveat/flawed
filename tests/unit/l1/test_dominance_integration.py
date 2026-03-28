"""Integration tests for dominance analysis on real LibCST-parsed CFGs.

Unlike ``test_dominance.py`` which uses manually constructed block/edge tuples,
these tests parse real Python snippets through the full ``build_cfg`` pipeline
and then run ``dominance_from_cfg`` on the resulting ``ControlFlowGraph``.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, is_dataclass
from pathlib import Path

import libcst as cst
import pytest
from libcst.metadata import MetadataWrapper

from flawed._index import CodeIndex
from flawed._index._cfg import build_cfg
from flawed._index._dominance import check_guard_dominance, dominance_from_cfg
from flawed._index._vendor import CFGraph


def _build(source: str) -> tuple:
    """Parse *source* as a function body, build the CFG.

    Returns ``(cfg, errors)``.  The source is wrapped in
    ``def _test_fn():\\n    <source>`` automatically.
    """
    indented = "\n".join(f"    {line}" for line in source.splitlines())
    full = f"def _test_fn():\n{indented}\n"
    mod = cst.parse_module(full)
    wrapper = MetadataWrapper(mod, unsafe_skip_copy=True)
    func = mod.body[0]
    assert isinstance(func, cst.FunctionDef)
    return build_cfg(func, "module._test_fn", Path("test.py"), wrapper)


def _build_dominance(source: str):
    """Parse source, build CFG, then build dominance graph.

    Returns ``(dom_graph, cfg, errors)``.
    """
    cfg, errors = _build(source)
    dom = dominance_from_cfg(cfg)
    return dom, cfg, errors


class TestLinearCodeDominance:
    """Entry block dominates all blocks in straight-line code."""

    def test_entry_dominates_all_blocks(self) -> None:
        dom, _cfg, errors = _build_dominance("x = 1\ny = 2\nreturn x + y")
        assert not errors

        entry = dom.entry_block_id
        for node in dom.block_ids:
            assert dom.dominates(entry, node), f"entry {entry} should dominate {node}"

    def test_linear_code_has_no_dead_nodes(self) -> None:
        dom, _cfg, _errors = _build_dominance("x = 1\ny = 2\nreturn x + y")

        assert dom.dead_block_ids == frozenset()


class TestBranchDominanceFrontier:
    """If/else branches produce merge points in dominance frontiers."""

    def test_if_else_branch_blocks_have_merge_in_frontier(self) -> None:
        dom, _cfg, _errors = _build_dominance("if cond:\n    x = 1\nelse:\n    x = 2\nreturn x")
        entry = dom.entry_block_id

        # Entry dominates all blocks
        for node in dom.block_ids:
            assert dom.dominates(entry, node)

        # At least two non-entry blocks have a shared merge point in their frontier
        non_entry_frontiers = {
            block: dom.dominance_frontier(block)
            for block in dom.block_ids
            if block != entry and dom.dominance_frontier(block)
        }
        assert len(non_entry_frontiers) >= 2, "if/else must produce at least 2 branch frontiers"

        # All non-entry blocks with a frontier share the same merge point
        merge_points = set()
        for targets in non_entry_frontiers.values():
            merge_points.update(targets)
        assert len(merge_points) == 1, "if/else has exactly one merge point"

        # The merge point is immediately dominated by entry, not by either branch
        (merge_block,) = merge_points
        assert dom.immediate_dominator(merge_block) == entry


class TestAuthGuardDominance:
    """Auth guard patterns using early return produce correct dominance."""

    def test_early_return_guard_dominates_sensitive_code(self) -> None:
        """An ``if not auth: return`` guard means entry dominates the sensitive path."""
        dom, _cfg, _errors = _build_dominance(
            "if not is_admin:\n    return forbidden()\ndelete_user()"
        )
        # block 0 = branch (guard condition), block 3 = true (return forbidden),
        # block 2 = false (delete_user — sensitive), block 1 = exit
        guard_block = 0
        sensitive_block = 2

        result = check_guard_dominance(dom, guard_block, sensitive_block)
        assert result.is_sufficient
        assert result.gaps == ()

    def test_conditional_guard_does_not_dominate_when_bypassed(self) -> None:
        """When the guard is behind a condition, it doesn't dominate the sensitive op."""
        dom, _cfg, _errors = _build_dominance("if flag:\n    check_auth()\ndo_sensitive()")
        # block 0 = branch (flag), block 3 = true (check_auth),
        # block 2 = after-if (do_sensitive — reached from both paths)
        guard_block = 3  # check_auth() call
        sensitive_block = 2  # do_sensitive() — merge point

        result = check_guard_dominance(dom, guard_block, sensitive_block)
        assert not result.is_sufficient
        # The sensitive block is in the guard's dominance frontier
        assert sensitive_block in result.dominance_frontier
        assert result.gaps == ()


class TestLoopDominance:
    """While loops produce detectable loop structures in dominance analysis."""

    def test_while_loop_header_and_body_detected(self) -> None:
        dom, _cfg, _errors = _build_dominance("while cond:\n    body()")
        # block 0 = entry, block 2 = loop header (cond), block 4 = body, block 3 = after
        loops = dom.loops()

        assert len(loops) == 1
        loop = loops[0]
        loop_header = loop.header

        # The header is a block that is both a predecessor and successor of the body
        assert loop.header == loop_header
        assert loop_header in loop.body

    def test_while_loop_entry_dominates_all_live_nodes(self) -> None:
        dom, _cfg, _errors = _build_dominance("while cond:\n    body()")

        entry = dom.entry_block_id
        for node in dom.block_ids:
            assert dom.dominates(entry, node)


class TestTryExceptDominance:
    """Try/except blocks maintain dominance from entry through both paths."""

    def test_entry_dominates_return_through_try_except(self) -> None:
        dom, _cfg, _errors = _build_dominance("try:\n    x = f()\nexcept:\n    pass\nreturn x")

        entry = dom.entry_block_id

        # Entry dominates all live nodes — exception path doesn't break this
        for node in dom.block_ids:
            assert dom.dominates(entry, node), f"entry {entry} should dominate {node}"

        # No dead nodes
        assert dom.dead_block_ids == frozenset()

    def test_not_all_blocks_dominate_the_exit(self) -> None:
        """In try/except, exception-handler blocks don't dominate the join point."""
        dom, _cfg, _errors = _build_dominance("try:\n    x = f()\nexcept:\n    pass\nreturn x")
        entry = dom.entry_block_id

        # The graph has a join point where try and except paths merge.
        # Not every non-entry block dominates the exit — the except handler
        # is on an alternate path, so it doesn't dominate the continuation.
        non_entry = dom.block_ids - {entry}
        exit_points = dom.exit_block_ids
        assert exit_points, "graph must have at least one exit"
        exit_node = next(iter(exit_points))
        blocks_dominating_exit = dom.dominators(exit_node) - {entry, exit_node}
        assert blocks_dominating_exit < non_entry, (
            "not all non-entry blocks should dominate the exit in a try/except"
        )


class TestMultiBranchDominance:
    """Multi-branch patterns (if/elif/else) produce correct dominance."""

    def test_elif_branches_have_shared_merge_frontier(self) -> None:
        dom, _cfg, _errors = _build_dominance(
            "if a:\n    x = 1\nelif b:\n    x = 2\nelse:\n    x = 3\nreturn x"
        )

        entry = dom.entry_block_id

        # Entry dominates everything
        for node in dom.block_ids:
            assert dom.dominates(entry, node)

        # No dead nodes
        assert dom.dead_block_ids == frozenset()

        # There must be at least one non-empty dominance frontier (a merge point)
        non_empty_frontiers = {
            block: dom.dominance_frontier(block)
            for block in dom.block_ids
            if dom.dominance_frontier(block)
        }
        assert non_empty_frontiers, "elif/else must produce merge point frontiers"


class TestCodeIndexDominanceAccess:
    """CodeIndex exposes frozen/query-only dominance facts."""

    def test_code_index_dominance_returns_query_object_not_raw_cfgraph(self) -> None:
        cfg, _errors = _build("x = 1\nreturn x")
        dom = dominance_from_cfg(cfg)

        idx = CodeIndex(
            repo_root=Path("/tmp/test"),
            functions=(),
            classes=(),
            decorators=(),
            imports=(),
            attributes=(),
            call_edges=(),
            cfgs={},
            value_flow_edges=(),
            symbol_refs=(),
            errors=(),
            provenance=CodeIndex.empty(Path("/tmp/test")).provenance,
            dominance_graphs={"module._test_fn": dom},
        )

        result = idx.dominance("module._test_fn")
        assert result is not None
        assert not isinstance(result, CFGraph)
        assert result.entry_block_id == dom.entry_block_id
        assert is_dataclass(result)

        for mutator in ("add_node", "add_edge", "set_entry_point", "process"):
            assert not hasattr(result, mutator)
        for raw_map_accessor in ("nodes", "dead_nodes", "entry_point"):
            assert not hasattr(result, raw_map_accessor)

    def test_public_dominance_collections_are_immutable_snapshots(self) -> None:
        dom, _cfg, _errors = _build_dominance("if cond:\n    x = 1\nelse:\n    x = 2\nreturn x")
        entry = dom.entry_block_id
        branch = next(block for block in dom.block_ids if dom.dominance_frontier(block))
        frontier_before = dom.dominance_frontier(branch)

        with pytest.raises(AttributeError):
            dom.block_ids.add("evil")
        with pytest.raises(AttributeError):
            dom.dominators(entry).add("evil")
        with pytest.raises(AttributeError):
            dom.dominance_frontier(branch).clear()
        with pytest.raises(FrozenInstanceError):
            dom.entry_block_id = "evil"

        assert dom.dominance_frontier(branch) == frontier_before
        assert dom.dominates(entry, entry)

        loop_dom, _loop_cfg, _loop_errors = _build_dominance("while cond:\n    body()")
        (loop,) = loop_dom.loops()
        with pytest.raises(AttributeError):
            loop.body.add("evil")
        with pytest.raises(FrozenInstanceError):
            loop.header = "evil"

    def test_code_index_snapshots_dominance_mapping_inputs(self) -> None:
        cfg, _errors = _build("x = 1\nreturn x")
        dom = dominance_from_cfg(cfg)
        dominance_graphs = {"module._test_fn": dom}

        idx = CodeIndex(
            repo_root=Path("/tmp/test"),
            functions=(),
            classes=(),
            decorators=(),
            imports=(),
            attributes=(),
            call_edges=(),
            cfgs={},
            value_flow_edges=(),
            symbol_refs=(),
            errors=(),
            provenance=CodeIndex.empty(Path("/tmp/test")).provenance,
            dominance_graphs=dominance_graphs,
        )

        dominance_graphs["added_later"] = dom

        assert idx.dominance("added_later") is None
        assert idx.dominance("module._test_fn") is dom

    def test_code_index_returns_none_for_unknown_function(self) -> None:
        idx = CodeIndex.empty(Path("/tmp/test"))
        assert idx.dominance("nonexistent") is None
