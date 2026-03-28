"""CFG builder — per-function control-flow graph construction (v1).

Builds a control-flow graph from a LibCST function body.  Each basic
block is a maximal straight-line sequence of statements with no
branches or branch targets in the middle.

v1 supported constructs:
  if/elif/else, while(/else), for(/else), async for(/else),
  return, raise, break, continue, with (entry/exit only),
  async with, try/except (basic), try/except/finally,
  match/case (Python 3.10+, including guards and wildcards),
  yield/yield from (suspend-point edges).

Deferred constructs (recorded as ExtractionError(error_kind=CFG)):
  except*.

Known modeling limitation not yet separately classified:
  nested exception handlers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

import libcst as cst
from libcst.metadata import MetadataWrapper, PositionProvider

from flawed._index._spans import SpanInterner
from flawed._index._types import (
    CFGBlock,
    CFGEdge,
    ErrorKind,
    ExceptHandler,
    ExtractionError,
    SourceSpan,
    TryExceptRegion,
    ValuePredicate,
)

if TYPE_CHECKING:
    from pathlib import Path

    from flawed._index._graphs import ControlFlowGraph


CFG_DEPTH_BUDGET = 64

ValuePredicateLiteral = Literal["return", "assign", "ternary"]


# =====================================================================
# Internal mutable block used during construction
# =====================================================================


class _MutableBlock:
    """Mutable block accumulated during the walk, frozen at the end."""

    __slots__ = (
        "block_id",
        "condition_expr",
        "condition_location",
        "preds",
        "statements",
        "succs",
        "value_predicates",
    )

    def __init__(self, block_id: int) -> None:
        self.block_id = block_id
        self.statements: list[SourceSpan] = []
        self.succs: list[int] = []
        self.preds: list[int] = []
        self.condition_expr: str | None = None
        self.condition_location: SourceSpan | None = None
        self.value_predicates: list[ValuePredicate] = []

    def freeze(self) -> CFGBlock:
        return CFGBlock(
            id=self.block_id,
            statements=tuple(self.statements),
            successors=tuple(dict.fromkeys(self.succs)),
            predecessors=tuple(dict.fromkeys(self.preds)),
            condition_expr=self.condition_expr,
            condition_location=self.condition_location,
            value_predicates=tuple(self.value_predicates),
        )


# =====================================================================
# CFGBuilder
# =====================================================================


class CFGBuilder:
    """Builds a ``ControlFlowGraph`` from a LibCST function body.

    Usage::

        blocks, edges, regions, errors = CFGBuilder(wrapper, file_path).build(func_node)
    """

    def __init__(
        self,
        wrapper: MetadataWrapper,
        file_path: str,
        *,
        span_interner: SpanInterner | None = None,
        depth_budget: int = CFG_DEPTH_BUDGET,
    ) -> None:
        self._wrapper = wrapper
        self._file = file_path
        self._span_interner = span_interner or SpanInterner()
        self._depth_budget = depth_budget
        self._depth_budget_reported = False
        self._blocks: dict[int, _MutableBlock] = {}
        self._edges: list[CFGEdge] = []
        self._errors: list[ExtractionError] = []
        self._try_regions: list[TryExceptRegion] = []
        self._next_id = 0
        self._loop_stack: list[tuple[int, int]] = []  # (continue_target, break_target)

    # -- block management ---------------------------------------------

    def _new_block(self) -> _MutableBlock:
        bid = self._next_id
        self._next_id += 1
        block = _MutableBlock(bid)
        self._blocks[bid] = block
        return block

    def _add_edge(
        self, src: int, tgt: int, label: str = "fallthrough", *, exceptional: bool = False
    ) -> None:
        self._edges.append(
            CFGEdge(
                source_id=src,
                target_id=tgt,
                label=label,
                is_exceptional=exceptional,
            )
        )
        if tgt in self._blocks:
            self._blocks[tgt].preds.append(src)
        if src in self._blocks:
            self._blocks[src].succs.append(tgt)

    def _span(self, node: cst.CSTNode) -> SourceSpan:
        """Extract a SourceSpan for *node* using position metadata."""
        try:
            pos = self._wrapper.resolve(PositionProvider)[node]
        except KeyError:
            return self._span_interner.intern(
                file=self._file,
                line=0,
                column=0,
                end_line=0,
                end_column=0,
            )
        return self._span_interner.intern(
            file=self._file,
            line=pos.start.line,
            column=pos.start.column,
            end_line=pos.end.line,
            end_column=pos.end.column,
        )

    def _src_text(self, node: cst.CSTNode) -> str:
        """Best-effort source text for a node."""
        mod = cst.parse_module("")
        try:
            return mod.code_for_node(node)
        except Exception:  # pragma: no cover
            return "<unknown>"

    def _deferred(self, construct: str, node: cst.CSTNode) -> None:
        """Record a deferred (unsupported) construct."""
        span = self._span(node)
        self._errors.append(
            ExtractionError(
                file=self._file,
                pass_name="cfg_builder",
                error_kind=ErrorKind.CFG,
                message=f"Deferred construct: {construct}",
                is_fatal=False,
                location=span,
            )
        )

    def _degrade_depth_budget(self, node: cst.CSTNode, current: _MutableBlock) -> int:
        """Treat *node* as opaque once CFG recursive descent exceeds its budget."""
        span = self._span(node)
        if not self._depth_budget_reported:
            self._errors.append(
                ExtractionError(
                    file=self._file,
                    pass_name="cfg_builder",
                    error_kind=ErrorKind.CFG,
                    message=(
                        "CFG depth budget exceeded; treating the remaining subtree as "
                        "opaque control flow"
                    ),
                    is_fatal=False,
                    location=span,
                )
            )
            self._depth_budget_reported = True
        current.statements.append(span)
        return current.block_id

    # -- public entry point -------------------------------------------

    def build(
        self,
        func: cst.FunctionDef,
    ) -> tuple[
        tuple[CFGBlock, ...],
        tuple[CFGEdge, ...],
        tuple[TryExceptRegion, ...],
        tuple[ExtractionError, ...],
    ]:
        """Build the CFG for *func*.

        Returns ``(blocks, edges, try_regions, errors)``.
        """
        entry = self._new_block()
        exit_block = self._new_block()

        body_suite = func.body
        stmts: list[cst.BaseStatement | cst.BaseCompoundStatement]
        if isinstance(body_suite, cst.IndentedBlock):
            stmts = list(body_suite.body)
        else:
            stmts = [body_suite]  # type: ignore[list-item]

        tail = self._process_stmts(stmts, entry, exit_block)
        if tail is not None and tail != exit_block.block_id:
            self._add_edge(tail, exit_block.block_id, "implicit_return")

        frozen_blocks = tuple(b.freeze() for b in self._blocks.values())
        return frozen_blocks, tuple(self._edges), tuple(self._try_regions), tuple(self._errors)

    # -- statement dispatch -------------------------------------------

    def _process_stmts(
        self,
        stmts: list[cst.BaseStatement | cst.BaseCompoundStatement],
        current: _MutableBlock,
        exit_block: _MutableBlock,
        *,
        depth: int = 0,
    ) -> int | None:
        """Walk *stmts* appending to *current*.

        Returns the block ID that falls through at the end, or ``None``
        if all paths terminated (return/raise/break/continue).
        """
        for stmt in stmts:
            if current is None:
                break

            result = self._process_one(stmt, current, exit_block, depth=depth)
            if result is None:
                return None  # all paths terminated
            if result != current.block_id:
                current = self._blocks[result]
        return current.block_id if current is not None else None

    def _process_one(  # noqa: PLR0911
        self,
        stmt: cst.BaseStatement | cst.BaseCompoundStatement,
        current: _MutableBlock,
        exit_block: _MutableBlock,
        *,
        depth: int,
    ) -> int | None:
        """Process a single statement.  Returns fall-through block ID or None."""
        if depth > self._depth_budget:
            return self._degrade_depth_budget(stmt, current)

        # Unwrap simple statement suites to get individual small stmts
        if isinstance(stmt, cst.SimpleStatementLine):
            return self._process_simple_line(stmt, current, exit_block)

        if isinstance(stmt, cst.If):
            return self._process_if(stmt, current, exit_block, depth=depth)
        if isinstance(stmt, cst.While):
            return self._process_while(stmt, current, exit_block, depth=depth)
        if isinstance(stmt, cst.For):
            return self._process_for(stmt, current, exit_block, depth=depth)
        if isinstance(stmt, cst.Try):
            return self._process_try(stmt, current, exit_block, depth=depth)
        if isinstance(stmt, cst.TryStar):
            self._deferred("except*", stmt)
            current.statements.append(self._span(stmt))
            return current.block_id
        if isinstance(stmt, cst.With):
            return self._process_with(stmt, current, exit_block, depth=depth)
        if isinstance(stmt, cst.Match):
            return self._process_match(stmt, current, exit_block, depth=depth)

        # Class/function definitions: treat as single statements
        if isinstance(stmt, (cst.ClassDef, cst.FunctionDef)):
            current.statements.append(self._span(stmt))
            return current.block_id

        # Fallback: unrecognised compound statement
        current.statements.append(self._span(stmt))
        return current.block_id

    # -- simple statements -------------------------------------------

    def _process_simple_line(
        self,
        line: cst.SimpleStatementLine,
        current: _MutableBlock,
        exit_block: _MutableBlock,
    ) -> int | None:
        for small in line.body:
            if isinstance(small, cst.Return):
                current.statements.append(self._span(line))
                if small.value is not None:
                    self._capture_value_predicates(small.value, "return", current)
                self._add_edge(current.block_id, exit_block.block_id, "return")
                return None

            if (
                isinstance(small, (cst.Assign, cst.AnnAssign, cst.AugAssign))
                and small.value is not None
            ):
                # Not a terminator: fall through to the trailing span append.
                self._capture_value_predicates(small.value, "assign", current)

            if isinstance(small, cst.Raise):
                current.statements.append(self._span(line))
                self._add_edge(current.block_id, exit_block.block_id, "raise")
                return None

            if isinstance(small, (cst.Break,)):
                if self._loop_stack:
                    _, break_target = self._loop_stack[-1]
                    self._add_edge(current.block_id, break_target, "break")
                current.statements.append(self._span(line))
                return None

            if isinstance(small, (cst.Continue,)):
                if self._loop_stack:
                    continue_target, _ = self._loop_stack[-1]
                    self._add_edge(current.block_id, continue_target, "continue")
                current.statements.append(self._span(line))
                return None

            # yield / yield from — suspend point
            if self._contains_yield(small):
                current.statements.append(self._span(line))
                resume = self._new_block()
                self._add_edge(current.block_id, resume.block_id, "yield")
                current = resume
                continue

        current.statements.append(self._span(line))
        return current.block_id

    # -- predicate-as-value capture ----------------------------------

    def _capture_value_predicates(
        self,
        value: cst.BaseExpression,
        position: ValuePredicateLiteral,
        block: _MutableBlock,
    ) -> None:
        """Record predicate-shaped expressions produced as a value.

        Captures comparison / membership / identity / boolean / negated
        expressions in ``return`` / assignment / ternary value position so
        Layer 2 can lift them as ``predicates()`` facts.  Unlike a branch
        test, these carry **no** CFG edges — they are pure source-text +
        span records, leaving ``conditions()`` strictly branch-only.

        Ternaries (``a if cond else b``) recurse into the value operands so
        ``return (x is None) if flag else (y is None)`` records both arms;
        the ternary ``test`` is left to the branch machinery, never recorded
        here as a value predicate.
        """
        if isinstance(value, cst.IfExp):
            self._capture_value_predicates(value.body, "ternary", block)
            self._capture_value_predicates(value.orelse, "ternary", block)
            return
        if self._is_predicate_expression(value):
            block.value_predicates.append(
                ValuePredicate(
                    expression=self._src_text(value),
                    location=self._span(value),
                    position=position,
                )
            )

    @staticmethod
    def _is_predicate_expression(value: cst.BaseExpression) -> bool:
        """True for comparison / membership / identity / boolean / negated nodes.

        These are the value-position shapes that classify as a meaningful
        predicate (MEMBERSHIP / COMPARISON / IDENTITY / TRUTHINESS) in
        Layer 2.  Plain names, calls, and literals are excluded: a bare
        ``return token`` is not a predicate, and call results are already
        modeled elsewhere.
        """
        if isinstance(value, (cst.Comparison, cst.BooleanOperation)):
            return True
        return isinstance(value, cst.UnaryOperation) and isinstance(value.operator, cst.Not)

    # -- if / elif / else -------------------------------------------

    def _process_if(
        self,
        node: cst.If,
        current: _MutableBlock,
        exit_block: _MutableBlock,
        *,
        depth: int,
    ) -> int | None:
        join = self._new_block()
        condition_block = current
        current_if: cst.If | None = node
        chain_depth = 0

        while current_if is not None:
            if depth + chain_depth > self._depth_budget:
                degraded = self._new_block()
                self._add_edge(condition_block.block_id, degraded.block_id, "false")
                tail = self._degrade_depth_budget(current_if, degraded)
                self._add_edge(tail, join.block_id, "fallthrough")
                break

            condition_location = self._span(current_if.test)
            condition_block.statements.append(condition_location)
            condition_block.condition_expr = self._src_text(current_if.test)
            condition_block.condition_location = condition_location

            true_block = self._new_block()
            self._add_edge(condition_block.block_id, true_block.block_id, "true")
            true_body = _body_stmts(current_if.body)
            true_tail = self._process_stmts(
                true_body,
                true_block,
                exit_block,
                depth=depth + chain_depth + 1,
            )
            if true_tail is not None:
                self._add_edge(true_tail, join.block_id, "fallthrough")

            if current_if.orelse is None:
                self._add_edge(condition_block.block_id, join.block_id, "false")
                break

            if isinstance(current_if.orelse, cst.If):
                next_condition = self._new_block()
                self._add_edge(condition_block.block_id, next_condition.block_id, "false")
                condition_block = next_condition
                current_if = current_if.orelse
                chain_depth += 1
                continue

            false_block = self._new_block()
            self._add_edge(condition_block.block_id, false_block.block_id, "false")
            false_body = _body_stmts(current_if.orelse.body)
            false_tail = self._process_stmts(
                false_body,
                false_block,
                exit_block,
                depth=depth + chain_depth + 1,
            )
            if false_tail is not None:
                self._add_edge(false_tail, join.block_id, "fallthrough")
            break

        # If ALL branches terminated (return/raise/etc), join is unreachable.
        # Check whether any branch actually connected to the join block.
        if join.preds:
            return join.block_id
        return None

    # -- while -------------------------------------------------------

    def _process_while(
        self,
        node: cst.While,
        current: _MutableBlock,
        exit_block: _MutableBlock,
        *,
        depth: int,
    ) -> int | None:
        cond = self._new_block()
        self._add_edge(current.block_id, cond.block_id, "fallthrough")
        condition_location = self._span(node.test)
        cond.statements.append(condition_location)
        cond.condition_expr = self._src_text(node.test)
        cond.condition_location = condition_location

        after_loop = self._new_block()

        # Body
        body_block = self._new_block()
        self._add_edge(cond.block_id, body_block.block_id, "true")

        self._loop_stack.append((cond.block_id, after_loop.block_id))
        body_stmts = _body_stmts(node.body)
        body_tail = self._process_stmts(body_stmts, body_block, exit_block, depth=depth + 1)
        self._loop_stack.pop()

        if body_tail is not None:
            self._add_edge(body_tail, cond.block_id, "back")

        # Else clause (runs if loop completes normally, not on break)
        if node.orelse is not None and isinstance(node.orelse, cst.Else):
            else_block = self._new_block()
            self._add_edge(cond.block_id, else_block.block_id, "false")
            else_body = _body_stmts(node.orelse.body)
            else_tail = self._process_stmts(else_body, else_block, exit_block, depth=depth + 1)
            if else_tail is not None:
                self._add_edge(else_tail, after_loop.block_id, "fallthrough")
        else:
            self._add_edge(cond.block_id, after_loop.block_id, "false")

        if after_loop.preds:
            return after_loop.block_id
        return None

    # -- for ---------------------------------------------------------

    def _process_for(
        self,
        node: cst.For,
        current: _MutableBlock,
        exit_block: _MutableBlock,
        *,
        depth: int,
    ) -> int | None:
        cond = self._new_block()
        self._add_edge(current.block_id, cond.block_id, "fallthrough")
        condition_location = self._span(node.iter)
        cond.statements.append(self._span(node.target))
        cond.condition_expr = self._src_text(node.iter)
        cond.condition_location = condition_location

        after_loop = self._new_block()

        body_block = self._new_block()
        self._add_edge(cond.block_id, body_block.block_id, "true")

        self._loop_stack.append((cond.block_id, after_loop.block_id))
        body_stmts = _body_stmts(node.body)
        body_tail = self._process_stmts(body_stmts, body_block, exit_block, depth=depth + 1)
        self._loop_stack.pop()

        if body_tail is not None:
            self._add_edge(body_tail, cond.block_id, "back")

        # Else clause
        if node.orelse is not None and isinstance(node.orelse, cst.Else):
            else_block = self._new_block()
            self._add_edge(cond.block_id, else_block.block_id, "false")
            else_body = _body_stmts(node.orelse.body)
            else_tail = self._process_stmts(else_body, else_block, exit_block, depth=depth + 1)
            if else_tail is not None:
                self._add_edge(else_tail, after_loop.block_id, "fallthrough")
        else:
            self._add_edge(cond.block_id, after_loop.block_id, "false")

        if after_loop.preds:
            return after_loop.block_id
        return None

    # -- with --------------------------------------------------------

    def _process_with(
        self,
        node: cst.With,
        current: _MutableBlock,
        exit_block: _MutableBlock,
        *,
        depth: int,
    ) -> int | None:
        # Entry edge: current flows into the body
        current.statements.append(self._span(node))
        body_stmts = _body_stmts(node.body)
        return self._process_stmts(body_stmts, current, exit_block, depth=depth + 1)

    # -- try / except ------------------------------------------------

    def _process_try(  # noqa: PLR0912
        self,
        node: cst.Try,
        current: _MutableBlock,
        exit_block: _MutableBlock,
        *,
        depth: int,
    ) -> int | None:
        # When finalbody is present, ALL non-terminating paths (handler
        # tails, try-body normal completion, else tail) flow into the
        # finally block instead of after_try.  The finally block then
        # falls through to after_try.
        has_finally = node.finalbody is not None

        after_try = self._new_block()
        # join_target is where handler/else tails connect.  When finally
        # is present, this is the finally block; otherwise after_try.
        if has_finally:
            finally_block = self._new_block()
            join_target = finally_block
        else:
            finally_block = None
            join_target = after_try

        join_label = "finally" if has_finally else "fallthrough"

        # Build handler blocks first so we can connect them
        handler_entries: list[int] = []
        handler_metadata: list[ExceptHandler] = []
        for handler in node.handlers:
            hblock = self._new_block()
            handler_entries.append(hblock.block_id)
            handler_metadata.append(
                ExceptHandler(
                    exception_types=_extract_exception_types(handler.type),
                    entry_block_id=hblock.block_id,
                    name=_extract_handler_name(handler.name),
                )
            )
            h_stmts = _body_stmts(handler.body)
            htail = self._process_stmts(h_stmts, hblock, exit_block, depth=depth + 1)
            if htail is not None:
                self._add_edge(htail, join_target.block_id, join_label)

        # Try body: each statement can potentially jump to any handler
        try_block = self._new_block()
        self._add_edge(current.block_id, try_block.block_id, "fallthrough")
        try_body_block_ids: list[int] = [try_block.block_id]

        try_stmts = _body_stmts(node.body)
        for try_stmt in try_stmts:
            result = self._process_one(try_stmt, try_block, exit_block, depth=depth + 1)
            if result is None:
                # Statement terminated (return/raise) — still connect to handlers
                for hid in handler_entries:
                    self._add_edge(try_block.block_id, hid, "exception", exceptional=True)
                try_block = None  # type: ignore[assignment]
                break
            if result != try_block.block_id:
                try_body_block_ids.append(result)
            try_block = self._blocks[result]

        if try_block is not None:
            # Normal completion of try body
            for hid in handler_entries:
                self._add_edge(try_block.block_id, hid, "exception", exceptional=True)
            self._add_edge(try_block.block_id, join_target.block_id, join_label)

        # Else clause (runs only if no exception)
        else_block_id: int | None = None
        if node.orelse is not None and isinstance(node.orelse, cst.Else):
            else_block_id = self._process_try_else(
                node.orelse,
                try_block,
                join_target,
                join_label,
                exit_block,
                depth=depth + 1,
            )

        # Finally body: process the statements and flow to after_try
        if finally_block is not None:
            assert node.finalbody is not None
            finally_stmts = _body_stmts(node.finalbody.body)
            fin_tail = self._process_stmts(
                finally_stmts,
                finally_block,
                exit_block,
                depth=depth + 1,
            )
            if fin_tail is not None:
                self._add_edge(fin_tail, after_try.block_id, "fallthrough")

        # Record the try/except region metadata
        self._try_regions.append(
            TryExceptRegion(
                try_body_block_ids=tuple(try_body_block_ids),
                handlers=tuple(handler_metadata),
                finally_block_id=finally_block.block_id if finally_block is not None else None,
                else_block_id=else_block_id,
                location=self._span(node),
            )
        )

        if after_try.preds:
            return after_try.block_id
        return None

    def _process_try_else(
        self,
        orelse: cst.Else,
        try_block: _MutableBlock | None,
        join_target: _MutableBlock,
        join_label: str,
        exit_block: _MutableBlock,
        *,
        depth: int,
    ) -> int:
        """Wire the ``else`` clause of a ``try`` statement.

        Returns the block ID of the else entry block.
        """
        else_block = self._new_block()
        if try_block is not None:
            # Remove the direct edge from try → join, replace with try → else
            target_id = join_target.block_id
            self._edges = [
                e
                for e in self._edges
                if not (
                    e.source_id == try_block.block_id
                    and e.target_id == target_id
                    and e.label == join_label
                )
            ]
            if target_id in try_block.succs:
                try_block.succs.remove(target_id)
            if try_block.block_id in join_target.preds:
                join_target.preds.remove(try_block.block_id)
            self._add_edge(try_block.block_id, else_block.block_id, "no_exception")

        else_body = _body_stmts(orelse.body)
        else_tail = self._process_stmts(else_body, else_block, exit_block, depth=depth)
        if else_tail is not None:
            self._add_edge(else_tail, join_target.block_id, join_label)
        return else_block.block_id

    # -- match / case --------------------------------------------------

    def _process_match(
        self,
        node: cst.Match,
        current: _MutableBlock,
        exit_block: _MutableBlock,
        *,
        depth: int,
    ) -> int | None:
        """Build branching CFG for ``match/case`` (Python 3.10+).

        Each case becomes a condition-test → body branch, chained like
        if/elif/else.  A wildcard ``case _:`` acts as the final else.
        """
        # Record the subject expression in the current block.
        subject_location = self._span(node.subject)
        current.statements.append(subject_location)
        current.condition_expr = self._src_text(node.subject)
        current.condition_location = subject_location

        join = self._new_block()
        prev_block = current

        for case in node.cases:
            is_wildcard = self._is_wildcard_pattern(case.pattern)

            # Body block for this case.
            body_block = self._new_block()
            self._add_edge(prev_block.block_id, body_block.block_id, "true")
            body_stmts = _body_stmts(case.body)
            body_tail = self._process_stmts(body_stmts, body_block, exit_block, depth=depth + 1)
            if body_tail is not None:
                self._add_edge(body_tail, join.block_id, "fallthrough")

            if is_wildcard:
                # Wildcard always matches — no false branch.
                prev_block = None  # type: ignore[assignment]
                break

            # Non-wildcard: false branch → next case's check block.
            next_check = self._new_block()
            self._add_edge(prev_block.block_id, next_check.block_id, "false")
            # Record the pattern as the condition for the check block.
            pattern_location = self._span(case.pattern)
            next_check.statements.append(pattern_location)
            next_check.condition_expr = self._src_text(case.pattern)
            next_check.condition_location = pattern_location
            prev_block = next_check

        # If no wildcard consumed all paths, the last false branch → join.
        if prev_block is not None:
            self._add_edge(prev_block.block_id, join.block_id, "false")

        if join.preds:
            return join.block_id
        return None

    @staticmethod
    def _is_wildcard_pattern(pattern: cst.MatchPattern) -> bool:
        """``True`` for the irrefutable ``case _:`` or ``case _ as name:``."""
        if isinstance(pattern, cst.MatchAs):
            return pattern.pattern is None
        return False

    # -- helpers -----------------------------------------------------

    @staticmethod
    def _contains_yield(node: cst.BaseSmallStatement) -> bool:
        """Return True if *node* contains a ``yield`` or ``yield from``."""
        # Bare yield expression: `yield value` or `yield from gen()`
        if isinstance(node, cst.Expr) and isinstance(node.value, cst.Yield):
            return True
        # Yield in assignment: `x = yield value`
        if isinstance(node, (cst.Assign, cst.AugAssign, cst.AnnAssign)):
            from libcst import matchers as m

            return bool(m.findall(node, m.Yield()))
        return False


# =====================================================================
# Module-level helpers
# =====================================================================


def _body_stmts(
    body: cst.BaseSuite,
) -> list[cst.BaseStatement | cst.BaseCompoundStatement]:
    """Extract the statement list from a suite."""
    if isinstance(body, cst.IndentedBlock):
        return list(body.body)
    if isinstance(body, cst.SimpleStatementSuite):
        return [body]  # type: ignore[list-item]
    return []


def _extract_exception_types(type_node: cst.BaseExpression | None) -> tuple[str, ...]:
    """Extract exception type names from an except clause's type annotation.

    Returns an empty tuple for bare ``except:``.
    """
    if type_node is None:
        return ()
    mod = cst.parse_module("")
    if isinstance(type_node, cst.Tuple):
        return tuple(mod.code_for_node(el.value).strip() for el in type_node.elements)
    return (mod.code_for_node(type_node).strip(),)


def _extract_handler_name(name: cst.AsName | None) -> str | None:
    """Extract the bound variable name from ``except X as e``."""
    if name is None:
        return None
    # name.name is a Name node
    if isinstance(name.name, cst.Name):
        return name.name.value
    return None


# =====================================================================
# Public entry point
# =====================================================================


def build_cfg(
    function_node: cst.FunctionDef,
    function_fqn: str,  # noqa: ARG001  # reserved for error reporting
    module_path: Path,
    metadata: MetadataWrapper,
    *,
    span_interner: SpanInterner | None = None,
) -> tuple[ControlFlowGraph, tuple[ExtractionError, ...]]:
    """Build a control-flow graph for a single function.

    Parameters
    ----------
    function_node:
        The LibCST ``FunctionDef`` node to build the CFG for.
    function_fqn:
        Fully qualified name of the function (for error reporting).
    module_path:
        Relative file path within the repository.
    metadata:
        LibCST ``MetadataWrapper`` that provides position information.

    Returns
    -------
    tuple of (ControlFlowGraph, errors)
        The constructed CFG and any extraction errors from deferred
        constructs.
    """
    from flawed._index._graphs import ControlFlowGraph

    builder = CFGBuilder(metadata, str(module_path), span_interner=span_interner)
    blocks, edges, try_regions, errors = builder.build(function_node)
    cfg = ControlFlowGraph(blocks, edges, try_regions=try_regions)
    return cfg, errors
