"""Helpers for resolving the current definition of a simple expression."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed._semantic._cfgview import ControlFlowView
from flawed._semantic._conversion_utils import location as _location
from flawed._semantic._conversion_utils import simple_name as _simple_name

if TYPE_CHECKING:
    from flawed._index import CodeIndex
    from flawed._index._types import SourceSpan
    from flawed.core import Location


def definition_location_for_expression(
    idx: CodeIndex,
    *,
    function_fqn: str,
    expression: str,
    before: SourceSpan,
) -> Location | None:
    """Return the latest simple assignment definition before *before*, if known."""
    name = _simple_name(expression)
    if name is None:
        return None

    cfg = ControlFlowView(idx.cfg(function_fqn))
    candidates: list[SourceSpan] = []
    for edge in idx.value_flow.assignments_to(name, function_fqn):
        if edge.target_location.file != before.file:
            continue
        if _definition_precedes(edge.target_location, before, cfg):
            candidates.append(edge.target_location)
    if not candidates:
        return None
    return _location(max(candidates, key=lambda span: (span.line, span.column)))


def _definition_precedes(
    definition: SourceSpan,
    use: SourceSpan,
    cfg: ControlFlowView,
) -> bool:
    if cfg.blocks:
        return cfg.precedes(_location(definition), _location(use))
    return _source_precedes(definition, use)


def _source_precedes(left: SourceSpan, right: SourceSpan) -> bool:
    if left.line != right.line:
        return left.line < right.line
    return left.column < right.column
