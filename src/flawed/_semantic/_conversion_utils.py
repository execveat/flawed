"""Shared utilities for L2 conversion modules.

Small helpers used across semantic conversion modules.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

from flawed._index._types import AttributeAccess, CallArgument, CallEdge, SourceSpan
from flawed._semantic._expr_cache import parse_expression as _parse_expression
from flawed.core import AnalysisGap, GapKind, Location

if TYPE_CHECKING:
    from flawed._semantic._provider_engine import ProviderMatch


def literal_string(expression: str) -> str | None:
    """Parse a string literal from an expression, or ``None`` if not literal."""
    try:
        value = ast.literal_eval(expression)
    except (SyntaxError, ValueError):
        return None
    return value if isinstance(value, str) else None


def simple_name(expression: str) -> str | None:
    """Return a bare-name expression, or ``None`` for anything more complex."""
    tree = _parse_expression(expression)
    if tree is None:
        return None
    node = tree.body
    return node.id if isinstance(node, ast.Name) else None


def call_expression(edge: CallEdge) -> str:
    """Reconstruct a call expression string from a ``CallEdge``."""
    callee = edge.call_expression or edge.callee_fqn or "<unknown>"
    if call_target_expression(callee) is not None:
        return callee
    args = []
    for arg in edge.arguments:
        if arg.keyword is None:
            args.append(arg.expression)
        else:
            args.append(f"{arg.keyword}={arg.expression}")
    return f"{callee}({', '.join(args)})"


def call_target_expression(expression: str) -> str | None:
    """Extract the function target from a call expression, or ``None``."""
    tree = _parse_expression(expression)
    if tree is None:
        return None
    node = tree.body
    if isinstance(node, ast.Call):
        return ast.unparse(node.func)
    return None


def location(span: SourceSpan) -> Location:
    """Convert an L1 ``SourceSpan`` to a public ``Location``."""
    return Location(
        file=span.file,
        line=span.line,
        column=span.column,
        end_line=span.end_line,
        end_column=span.end_column,
    )


def span_starts_not_after(left: SourceSpan, right: SourceSpan) -> bool:
    """True when *left* begins at or before *right* in source order."""
    return (left.line, left.column) <= (right.line, right.column)


def fact_function(match: ProviderMatch) -> str | None:
    """Extract the containing function FQN from a provider match's source fact."""
    from flawed._semantic._provider_engine import ParameterFact

    fact = match.source_fact
    if isinstance(fact, CallEdge):
        return fact.caller_fqn
    if isinstance(fact, AttributeAccess):
        return fact.containing_function_fqn
    if isinstance(fact, ParameterFact):
        return fact.function_fqn
    return None


def conversion_gap(
    match: ProviderMatch,
    message: str,
    *,
    origin_phase: str,
    kind: GapKind = GapKind.INTERPRETER_ERROR,
    source_error: str | None = None,
) -> AnalysisGap:
    """Build an AnalysisGap for a conversion-phase issue on a provider match."""
    return AnalysisGap(
        kind=kind,
        message=f"{type(match.descriptor).__name__} {match.canonical_fqn}: {message}",
        affected_file=match.location.file,
        affected_function=fact_function(match),
        source_error=source_error or f"{origin_phase}: {message}",
        origin_phase=origin_phase,
        origin_provider=match.provider_id,
    )


def find_argument(
    edge: CallEdge,
    *,
    position: int | None,
    keyword: str | None,
) -> CallArgument | None:
    """Look up a call argument by keyword and/or position.

    Keyword match takes priority; falls back to positional when both are
    given and keyword is not found.
    """
    for arg in edge.arguments:
        if keyword is not None and arg.keyword == keyword:
            return arg
        if keyword is None and position is not None and arg.position == position:
            return arg
    if keyword is not None and position is not None:
        for arg in edge.arguments:
            if arg.position == position:
                return arg
    return None


def argument_target_description(position: int | None, keyword: str | None) -> str:
    """Human-readable description of an expected argument position/keyword."""
    if keyword is not None and position is not None:
        return f"{keyword!r}/position {position}"
    if keyword is not None:
        return repr(keyword)
    if position is not None:
        return str(position)
    return "<unspecified>"


def dedupe_domain[T](items: Sequence[T]) -> tuple[T, ...]:
    """Deduplicate domain objects by (type, location, expression, function)."""
    result: list[T] = []
    seen: set[tuple[object, ...]] = set()
    for item in items:
        key = (
            type(item),
            getattr(getattr(item, "location", None), "file", None),
            getattr(getattr(item, "location", None), "line", None),
            getattr(item, "expression", None),
            getattr(getattr(item, "function", None), "fqn", None),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return tuple(result)
