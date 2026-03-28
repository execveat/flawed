"""Process-wide memoization cache for ``ast.parse(..., mode='eval')``.

P10.5 memray profiling found ``ast.parse()`` allocating 2.2 GB during
semantic no-rule scans due to repeated parsing of identical expression
strings across provider matching and conversion phases.  This module
caches parsed ``ast.Expression`` trees keyed by source string so each
unique expression is parsed at most once per process.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING

from flawed._index._parsing import parse_analyzed_expression

if TYPE_CHECKING:
    import ast

_MAX_CACHE_SIZE = 8192
_CACHE: OrderedDict[str, ast.Expression | None] = OrderedDict()


def parse_expression(expression: str) -> ast.Expression | None:
    """Parse *expression* in eval mode, returning a cached AST or ``None``."""
    try:
        tree = _CACHE[expression]
    except KeyError:
        pass
    else:
        _CACHE.move_to_end(expression)
        return tree
    try:
        tree = parse_analyzed_expression(expression)
    except SyntaxError:
        _CACHE[expression] = None
        _trim_cache()
        return None
    _CACHE[expression] = tree
    _trim_cache()
    return tree


def _trim_cache() -> None:
    while len(_CACHE) > _MAX_CACHE_SIZE:
        _CACHE.popitem(last=False)


def clear_expression_cache() -> None:
    """Drop all cached parse trees (for test isolation)."""
    _CACHE.clear()
