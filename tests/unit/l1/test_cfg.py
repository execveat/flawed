"""Tests for the L1 CFG builder.

Each test parses a small Python snippet, builds the CFG, and verifies
the block/edge structure.  We use a helper that wraps the snippet in a
module and function, then calls build_cfg on it.
"""

from __future__ import annotations

from pathlib import Path

import libcst as cst
from libcst.metadata import MetadataWrapper

from flawed._index._cfg import build_cfg
from flawed._index._types import BranchCondition, ErrorKind, SourceSpan


def _build(source: str) -> tuple:
    """Parse *source* as a function body, build the CFG.

    Returns (cfg, errors).  The source is wrapped in
    ``def _test_fn():\\n    <source>`` automatically.
    """
    indented = "\n".join(f"    {line}" for line in source.splitlines())
    full = f"def _test_fn():\n{indented}\n"
    mod = cst.parse_module(full)
    wrapper = MetadataWrapper(mod, unsafe_skip_copy=True)
    func = mod.body[0]
    assert isinstance(func, cst.FunctionDef)
    return build_cfg(func, "module._test_fn", Path("test.py"), wrapper)


def _edge_labels(cfg):
    """Return set of (source_id, target_id, label) for all edges."""
    return {(e.source_id, e.target_id, e.label) for e in cfg.edges}


def _block_ids(cfg):
    """Return sorted block IDs."""
    return sorted(b.id for b in cfg.blocks)


def _span(line: int, column: int, end_column: int, *, end_line: int | None = None) -> SourceSpan:
    """Create a test SourceSpan in the wrapped test.py fixture."""
    return SourceSpan(
        file="test.py",
        line=line,
        column=column,
        end_line=line if end_line is None else end_line,
        end_column=end_column,
    )


def _expected_branch(
    condition_expr: str, *, direction: bool, location: SourceSpan
) -> BranchCondition:
    """Build an expected branch condition for path assertions."""
    return BranchCondition(
        condition_expr=condition_expr,
        direction=direction,
        location=location,
    )


# =====================================================================
# 1. Linear code
# =====================================================================


class TestLinearCode:
    def test_simple_assignment_and_return(self):
        cfg, errors = _build("a = 1\nb = 2\nreturn a + b")
        assert not errors
        # Should have entry block (with statements) + exit block
        assert len(cfg.blocks) >= 2
        # Entry has statements
        entry = cfg.entry
        assert entry is not None
        assert len(entry.statements) > 0

    def test_single_return(self):
        cfg, errors = _build("return 42")
        assert not errors
        assert cfg.entry is not None


# =====================================================================
# 2-3. If / Else
# =====================================================================


class TestIfElse:
    def test_if_else(self):
        cfg, errors = _build("if x:\n    a = 1\nelse:\n    a = 2\nreturn a")
        assert not errors
        # Should have: entry(condition) → true, entry → false, true → join, false → join
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "true" in labels
        assert "false" in labels

    def test_if_no_else(self):
        cfg, errors = _build("if x:\n    a = 1\nreturn a")
        assert not errors
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "true" in labels
        assert "false" in labels

    def test_nested_if(self):
        cfg, errors = _build(
            "if x:\n    if y:\n        a = 1\n    else:\n        a = 2\nelse:\n    a = 3\nreturn a"
        )
        assert not errors
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "true" in labels
        assert "false" in labels

    def test_elif(self):
        cfg, errors = _build("if x:\n    a = 1\nelif y:\n    a = 2\nelse:\n    a = 3\nreturn a")
        assert not errors
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "true" in labels
        assert "false" in labels


class TestDepthBudget:
    @staticmethod
    def _depth_budget_errors(errors):
        return [
            error
            for error in errors
            if error.error_kind == ErrorKind.CFG and "CFG depth budget" in error.message
        ]

    def test_deep_nested_if_degrades_to_cfg_error(self):
        lines = []
        indent = ""
        for index in range(70):
            lines.append(f"{indent}if cond_{index}:")
            indent += "    "
        lines.append(f"{indent}return 1")

        cfg, errors = _build("\n".join(lines))

        budget_errors = self._depth_budget_errors(errors)
        assert cfg.entry is not None
        assert budget_errors
        assert not budget_errors[0].is_fatal

    def test_long_elif_chain_degrades_to_cfg_error(self):
        lines = ["if cond_0:", "    value = 0"]
        for index in range(1, 80):
            lines.extend((f"elif cond_{index}:", f"    value = {index}"))
        lines.extend(("else:", "    value = -1", "return value"))

        cfg, errors = _build("\n".join(lines))

        budget_errors = self._depth_budget_errors(errors)
        assert cfg.entry is not None
        assert budget_errors
        assert not budget_errors[0].is_fatal


class TestBranchConditionMetadata:
    def test_if_block_records_condition_span(self):
        cfg, errors = _build("if user:\n    allow()\nelse:\n    deny()\nreturn done")
        assert not errors

        condition = _span(line=2, column=7, end_column=11)
        condition_blocks = [b for b in cfg.blocks if b.condition_expr == "user"]
        assert len(condition_blocks) == 1
        block = condition_blocks[0]
        assert block.condition_location == condition
        assert cfg.block_for(condition) == block

    def test_if_paths_include_true_and_false_branch_conditions(self):
        cfg, errors = _build("if user:\n    allow()\nelse:\n    deny()\nreturn done")
        assert not errors

        condition = _span(line=2, column=7, end_column=11)
        true_paths = cfg.paths_between(condition, _span(line=3, column=8, end_column=15))
        false_paths = cfg.paths_between(condition, _span(line=5, column=8, end_column=14))

        assert len(true_paths) == 1
        assert true_paths[0].conditions == (
            _expected_branch("user", direction=True, location=condition),
        )
        assert len(false_paths) == 1
        assert false_paths[0].conditions == (
            _expected_branch("user", direction=False, location=condition),
        )

    def test_elif_path_records_false_then_true_conditions(self):
        cfg, errors = _build(
            "if is_admin:\n"
            "    allow()\n"
            "elif has_token:\n"
            "    allow()\n"
            "else:\n"
            "    deny()\n"
            "return done"
        )
        assert not errors

        first_condition = _span(line=2, column=7, end_column=15)
        second_condition = _span(line=4, column=9, end_column=18)
        paths = cfg.paths_between(first_condition, _span(line=5, column=8, end_column=15))

        assert len(paths) == 1
        assert paths[0].conditions == (
            _expected_branch("is_admin", direction=False, location=first_condition),
            _expected_branch("has_token", direction=True, location=second_condition),
        )

    def test_while_exit_path_records_false_condition(self):
        cfg, errors = _build("while keep_running:\n    work()\nreturn done")
        assert not errors

        condition = _span(line=2, column=10, end_column=22)
        paths = cfg.paths_between(condition, _span(line=4, column=4, end_column=15))

        assert len(paths) == 1
        assert paths[0].conditions == (
            _expected_branch("keep_running", direction=False, location=condition),
        )

    def test_for_body_path_uses_iterable_condition_location(self):
        cfg, errors = _build("for item in items:\n    process(item)\nreturn done")
        assert not errors

        iterable = _span(line=2, column=16, end_column=21)
        paths = cfg.paths_between(iterable, _span(line=3, column=8, end_column=21))

        assert len(paths) == 1
        assert paths[0].conditions == (
            _expected_branch("items", direction=True, location=iterable),
        )

    def test_linear_path_does_not_fabricate_branch_conditions(self):
        cfg, errors = _build("a = 1\nb = 2\nreturn a + b")
        assert not errors

        paths = cfg.paths_between(
            _span(line=2, column=4, end_column=9),
            _span(line=4, column=4, end_column=16),
        )

        assert len(paths) == 1
        assert paths[0].conditions == ()


# =====================================================================
# 5. While loop
# =====================================================================


class TestWhile:
    def test_simple_while(self):
        cfg, errors = _build("while x:\n    x = x - 1\nreturn x")
        assert not errors
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "true" in labels
        assert "back" in labels or "false" in labels

    def test_while_else(self):
        cfg, errors = _build("while x:\n    x -= 1\nelse:\n    y = 0\nreturn y")
        assert not errors
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "false" in labels  # condition → else block


# =====================================================================
# 7-8. For loop
# =====================================================================


class TestFor:
    def test_simple_for(self):
        cfg, errors = _build("for i in items:\n    process(i)\nreturn done")
        assert not errors
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "true" in labels
        assert "back" in labels or "false" in labels

    def test_for_else(self):
        _cfg, errors = _build("for i in items:\n    process(i)\nelse:\n    cleanup()\nreturn done")
        assert not errors


# =====================================================================
# 9. Return in middle
# =====================================================================


class TestReturn:
    def test_return_in_middle(self):
        cfg, errors = _build("a = 1\nreturn a\nb = 2")
        assert not errors
        # The return should create an edge to exit
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "return" in labels

    def test_return_in_if(self):
        cfg, errors = _build("if x:\n    return 1\nreturn 2")
        assert not errors
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "return" in labels


# =====================================================================
# 10. Raise
# =====================================================================


class TestRaise:
    def test_raise(self):
        cfg, errors = _build("if not x:\n    raise ValueError('bad')\nreturn x")
        assert not errors
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "raise" in labels


# =====================================================================
# 11-12. Break / Continue
# =====================================================================


class TestBreakContinue:
    def test_break_in_loop(self):
        cfg, errors = _build("while True:\n    if done:\n        break\n    work()\nreturn result")
        assert not errors
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "break" in labels

    def test_continue_in_loop(self):
        cfg, errors = _build(
            "for i in items:\n    if skip(i):\n        continue\n    process(i)\nreturn done"
        )
        assert not errors
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "continue" in labels


# =====================================================================
# 13. With statement
# =====================================================================


class TestWith:
    def test_with(self):
        cfg, errors = _build("with open('f') as fh:\n    data = fh.read()\nreturn data")
        assert not errors
        assert cfg.entry is not None


# =====================================================================
# 14. Try / except
# =====================================================================


class TestTryExcept:
    def test_basic_try_except(self):
        cfg, errors = _build("try:\n    risky()\nexcept ValueError:\n    handle()\nreturn done")
        assert not errors
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "exception" in labels

    def test_try_except_else(self):
        _cfg, errors = _build(
            "try:\n    risky()\nexcept ValueError:\n    handle()\nelse:\n    good()\nreturn done"
        )
        assert not errors


# =====================================================================
# 15. Query semantics: dominates, precedes, paths_between
# =====================================================================


class TestQuerySemantics:
    """Substantive tests for CFG query method behavior on real patterns."""

    @staticmethod
    def _diamond_cfg():
        """Diamond: entry → true/false → join.

        Source layout (after wrapping):
            line 2: x = 1
            line 3: if cond:
            line 4:     a = 1
            line 5: else:
            line 6:     a = 2
            line 7: result = a
        """
        return _build("x = 1\nif cond:\n    a = 1\nelse:\n    a = 2\nresult = a")

    # -- dominates -----------------------------------------------------

    def test_entry_dominates_join_in_diamond(self):
        cfg, errors = self._diamond_cfg()
        assert not errors
        entry_span = _span(line=2, column=4, end_column=9)
        join_span = _span(line=7, column=4, end_column=14)
        assert cfg.dominates(entry_span, join_span)

    def test_true_branch_does_not_dominate_false_branch(self):
        cfg, errors = self._diamond_cfg()
        assert not errors
        true_span = _span(line=4, column=8, end_column=13)
        false_span = _span(line=6, column=8, end_column=13)
        assert not cfg.dominates(true_span, false_span)

    def test_join_does_not_dominate_entry(self):
        cfg, errors = self._diamond_cfg()
        assert not errors
        entry_span = _span(line=2, column=4, end_column=9)
        join_span = _span(line=7, column=4, end_column=14)
        assert not cfg.dominates(join_span, entry_span)

    # -- precedes ------------------------------------------------------

    def test_precedes_same_block_line_order(self):
        cfg, errors = _build("a = 1\nb = 2\nreturn a + b")
        assert not errors
        a_span = _span(line=2, column=4, end_column=9)
        b_span = _span(line=3, column=4, end_column=9)
        assert cfg.precedes(a_span, b_span)
        assert not cfg.precedes(b_span, a_span)

    def test_precedes_cross_block_entry_to_join(self):
        cfg, errors = self._diamond_cfg()
        assert not errors
        entry_span = _span(line=2, column=4, end_column=9)
        join_span = _span(line=7, column=4, end_column=14)
        assert cfg.precedes(entry_span, join_span)

    def test_precedes_branch_does_not_precede_sibling(self):
        cfg, errors = self._diamond_cfg()
        assert not errors
        true_span = _span(line=4, column=8, end_column=13)
        false_span = _span(line=6, column=8, end_column=13)
        assert not cfg.precedes(true_span, false_span)
        assert not cfg.precedes(false_span, true_span)

    # -- paths_between -------------------------------------------------

    def test_paths_between_diamond_has_two_paths(self):
        cfg, errors = _build("if cond:\n    a = 1\nelse:\n    a = 2\nresult = a")
        assert not errors
        cond_span = _span(line=2, column=7, end_column=11)
        join_span = _span(line=6, column=4, end_column=14)
        paths = cfg.paths_between(cond_span, join_span)
        assert len(paths) == 2

    def test_paths_between_early_return_reduces_paths(self):
        cfg, errors = _build("if done:\n    return None\nresult = compute()\nreturn result")
        assert not errors
        cond_span = _span(line=2, column=7, end_column=11)
        result_span = _span(line=4, column=4, end_column=14)
        paths = cfg.paths_between(cond_span, result_span)
        assert len(paths) == 1


# =====================================================================
# 16. Deferred constructs
# =====================================================================


class TestDeferred:
    """Tests for the deferred-construct warning mechanism.

    Most constructs that were formerly deferred are now fully handled
    (yield, async for/with, walrus, try/finally).  ``except*`` remains
    the sole deferred construct.
    """

    @staticmethod
    def _cfg_error_containing(errors, text: str):
        return next(
            e
            for e in errors
            if e.error_kind == ErrorKind.CFG and text.lower() in e.message.lower()
        )

    def test_yield_no_longer_deferred(self):
        _cfg, errors = _build("yield 42\nreturn")
        assert not errors

    def test_try_finally_no_longer_deferred(self):
        _cfg, errors = _build("try:\n    risky()\nfinally:\n    cleanup()\nreturn done")
        assert not errors

    def test_async_for_no_longer_deferred(self):
        _cfg, errors = _build("async for item in items:\n    process(item)\nreturn done")
        assert not errors

    def test_async_with_no_longer_deferred(self):
        _cfg, errors = _build("async with manager:\n    work()\nreturn done")
        assert not errors

    def test_except_star_still_deferred(self):
        """except* (ExceptionGroup) remains deferred."""
        _cfg, errors = _build("try:\n    risky()\nexcept* ValueError:\n    handle()\nreturn done")
        error = self._cfg_error_containing(errors, "except*")
        assert error.pass_name == "cfg_builder"
        assert not error.is_fatal

    def test_cfg_still_built_with_deferred(self):
        """Deferred constructs don't prevent the rest of the CFG from building."""
        cfg, errors = _build("a = 1\nif x:\n    b = 2\nreturn a")
        assert not errors  # no deferred constructs here
        assert cfg.entry is not None
        assert len(cfg.blocks) >= 2


# =====================================================================
# 17. match/case reduction
# =====================================================================


class TestMatchCase:
    """Tests for match/case CFG branching (Python 3.10+).

    These tests define the target behavior.  Current code defers match/case
    to a single straight-line statement; these will fail until match/case
    reduction is implemented.
    """

    def test_match_case_builds_branches(self):
        cfg, errors = _build(
            "match command:\n"
            "    case 'start':\n"
            "        begin()\n"
            "    case 'stop':\n"
            "        end()\n"
            "return done"
        )
        assert not errors, "match/case should not produce deferred errors"
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "true" in labels, "match/case should produce branching edges"
        assert len(cfg.blocks) >= 5, "expected entry + 2 case blocks + join + exit"

    def test_match_case_with_default_has_three_paths(self):
        cfg, errors = _build(
            "match value:\n"
            "    case 1:\n"
            "        a = 10\n"
            "    case 2:\n"
            "        a = 20\n"
            "    case _:\n"
            "        a = 0\n"
            "return a"
        )
        assert not errors
        # Subject span resolves to the match condition block
        subject_span = _span(line=2, column=10, end_column=15)
        # Join block: return a (line 9 after wrapping)
        join_span = _span(line=9, column=4, end_column=12)
        paths = cfg.paths_between(subject_span, join_span)
        assert len(paths) >= 3, "3 cases should produce at least 3 paths to join"

    def test_match_case_with_guard(self):
        cfg, errors = _build(
            "match point:\n"
            "    case Point(x, y) if x > 0:\n"
            "        positive()\n"
            "    case Point(x, y):\n"
            "        other()\n"
            "return done"
        )
        assert not errors, "guarded match/case should not produce deferred errors"
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "true" in labels

    def test_match_case_entry_dominates_join(self):
        cfg, errors = _build(
            "x = setup()\n"
            "match x:\n"
            "    case 1:\n"
            "        a = 10\n"
            "    case 2:\n"
            "        a = 20\n"
            "result = a"
        )
        assert not errors
        entry_span = _span(line=2, column=4, end_column=15)
        join_span = _span(line=8, column=4, end_column=14)
        assert cfg.dominates(entry_span, join_span)
        # Sibling case bodies do not dominate each other
        case1_span = _span(line=5, column=12, end_column=18)
        case2_span = _span(line=7, column=12, end_column=18)
        assert not cfg.dominates(case1_span, case2_span)


# =====================================================================
# 18. Yield / yield from
# =====================================================================


class TestYield:
    def test_yield_creates_suspend_edge(self):
        cfg, errors = _build("yield 42\nreturn")
        assert not errors, f"yield should not produce deferred errors: {errors}"
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "yield" in labels, f"expected 'yield' edge, got labels: {labels}"

    def test_yield_from_creates_suspend_edge(self):
        cfg, errors = _build("yield from gen()\nreturn")
        assert not errors, f"yield from should not produce deferred errors: {errors}"
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "yield" in labels, f"expected 'yield' edge, got labels: {labels}"

    def test_yield_in_assignment(self):
        cfg, errors = _build("x = yield value\nreturn x")
        assert not errors, f"yield in assignment should not produce deferred errors: {errors}"
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "yield" in labels, f"expected 'yield' edge, got labels: {labels}"

    def test_multiple_yields_create_multiple_suspend_points(self):
        cfg, errors = _build("yield 1\nyield 2\nreturn")
        assert not errors
        edges = _edge_labels(cfg)
        yield_edges = [(s, t, lab) for s, t, lab in edges if lab == "yield"]
        assert len(yield_edges) == 2, (
            f"expected 2 yield edges, got {len(yield_edges)}: {yield_edges}"
        )

    def test_yield_in_loop(self):
        cfg, errors = _build("for i in items:\n    yield i\nreturn")
        assert not errors
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "yield" in labels
        assert "back" in labels or "true" in labels


# =====================================================================
# 19. Async for / async with
# =====================================================================


class TestAsyncForWith:
    def test_async_for_builds_loop_cfg(self):
        cfg, errors = _build("async for item in items:\n    process(item)\nreturn done")
        assert not errors, f"async for should not produce deferred errors: {errors}"
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "true" in labels
        assert "back" in labels or "false" in labels

    def test_async_for_with_else(self):
        cfg, errors = _build(
            "async for item in items:\n    process(item)\nelse:\n    cleanup()\nreturn done"
        )
        assert not errors
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "false" in labels

    def test_async_for_break_continue(self):
        cfg, errors = _build(
            "async for item in items:\n    if done:\n        break\n    continue\nreturn result"
        )
        assert not errors
        edges = _edge_labels(cfg)
        labels = {label for _, _, label in edges}
        assert "break" in labels
        assert "continue" in labels

    def test_async_with_builds_body_cfg(self):
        cfg, errors = _build("async with manager:\n    work()\nreturn done")
        assert not errors, f"async with should not produce deferred errors: {errors}"
        assert cfg.entry is not None


# =====================================================================
# 20. Walrus operator
# =====================================================================


class TestWalrus:
    def test_walrus_in_for_iterable_no_deferred(self):
        _cfg, errors = _build("for x in (y := compute()):\n    use(x)\nreturn y")
        assert not errors, f"walrus should not produce deferred errors: {errors}"

    def test_walrus_in_while_condition_no_deferred(self):
        _cfg, errors = _build("while (chunk := read()):\n    process(chunk)\nreturn")
        assert not errors, f"walrus should not produce deferred errors: {errors}"


# =====================================================================
# 21. Try/finally exception propagation
# =====================================================================


class TestTryFinally:
    def test_try_finally_no_deferred(self):
        _cfg, errors = _build("try:\n    risky()\nfinally:\n    cleanup()\nreturn done")
        assert not errors, f"try/finally should not produce deferred errors: {errors}"

    def test_try_except_finally_all_paths_through_finally(self):
        """All paths (try body normal + handler) pass through finally block."""
        cfg, errors = _build(
            "try:\n    risky()\nexcept ValueError:\n    handle()\n"
            "finally:\n    cleanup()\nreturn done"
        )
        assert not errors
        # Find the finally block: it should have predecessors from both
        # the try body's normal completion and the handler's completion
        edges = _edge_labels(cfg)
        finally_edges = [(s, t, lab) for s, t, lab in edges if lab == "finally"]
        assert len(finally_edges) >= 1, f"expected finally edges, got: {edges}"
        # The finally block target should have multiple predecessors
        finally_target = finally_edges[0][1]
        finally_block = next(b for b in cfg.blocks if b.id == finally_target)
        assert len(finally_block.predecessors) >= 2, (
            f"finally block should have >=2 predecessors (try + handler), "
            f"got {len(finally_block.predecessors)}: {finally_block.predecessors}"
        )

    def test_try_except_else_finally_paths(self):
        """With all four clauses, the else path also goes through finally."""
        cfg, errors = _build(
            "try:\n    risky()\nexcept ValueError:\n    handle()\n"
            "else:\n    good()\nfinally:\n    cleanup()\nreturn done"
        )
        assert not errors
        edges = _edge_labels(cfg)
        finally_edges = [(s, t, lab) for s, t, lab in edges if lab == "finally"]
        assert len(finally_edges) >= 1
        # The finally block should have predecessors from handler + else
        finally_target = finally_edges[0][1]
        finally_block = next(b for b in cfg.blocks if b.id == finally_target)
        assert len(finally_block.predecessors) >= 2


# =====================================================================
# Structural invariants
# =====================================================================


class TestStructuralInvariants:
    def test_entry_has_no_predecessors(self):
        cfg, _ = _build("return 1")
        entry = cfg.entry
        assert entry is not None
        assert len(entry.predecessors) == 0

    def test_exit_has_no_successors(self):
        cfg, _ = _build("return 1")
        for exit_block in cfg.exits:
            assert len(exit_block.successors) == 0

    def test_edges_reference_valid_blocks(self):
        cfg, _ = _build("if x:\n    return 1\nelse:\n    return 2")
        block_ids = {b.id for b in cfg.blocks}
        for edge in cfg.edges:
            assert edge.source_id in block_ids, f"edge source {edge.source_id} not in blocks"
            assert edge.target_id in block_ids, f"edge target {edge.target_id} not in blocks"

    def test_successor_predecessor_consistency(self):
        """Every successor/predecessor relationship matches an edge."""
        cfg, _ = _build("for i in items:\n    if done:\n        break\n    work()\nreturn i")
        edge_set = {(e.source_id, e.target_id) for e in cfg.edges}
        for block in cfg.blocks:
            for s in block.successors:
                assert (block.id, s) in edge_set, (
                    f"block {block.id} has successor {s} but no matching edge"
                )
            for p in block.predecessors:
                assert (p, block.id) in edge_set, (
                    f"block {block.id} has predecessor {p} but no matching edge"
                )
