"""Tests for the analyzed-source parsing chokepoint (FLAW-124).

Parsing the analyzed repo's own source must NOT leak the *target* project's
``SyntaxWarning``s (invalid escape sequences, ``is`` with a literal, ...) onto
flawed's stderr. These are lint-level issues in the code under analysis, not
defects in the engine, so the engine stays quiet about them.
"""

from __future__ import annotations

import ast
import warnings

import pytest

from flawed._index._parsing import parse_analyzed_expression, parse_analyzed_module

# A non-raw string literal with an invalid escape sequence. Embedded here via an
# escaped backslash so the *source we parse* contains the literal text ``"\s+"``,
# which Python flags with ``SyntaxWarning: invalid escape sequence '\s'``.
_MODULE_WITH_BAD_ESCAPE = 'PATTERN = "\\s+"\n'
_EXPR_WITH_BAD_ESCAPE = '"\\s+"'


def _syntax_warnings(record: list[warnings.WarningMessage]) -> list[warnings.WarningMessage]:
    return [w for w in record if issubclass(w.category, SyntaxWarning)]


def test_stdlib_ast_parse_leaks_target_syntaxwarning() -> None:
    """Guard: the bare stdlib call DOES leak — proving the test is meaningful."""
    with warnings.catch_warnings(record=True) as record:
        warnings.simplefilter("always")
        ast.parse(_MODULE_WITH_BAD_ESCAPE)
    assert _syntax_warnings(record), "expected stdlib ast.parse to emit a SyntaxWarning"


def test_parse_analyzed_module_suppresses_syntaxwarning() -> None:
    with warnings.catch_warnings(record=True) as record:
        warnings.simplefilter("always")
        tree = parse_analyzed_module(_MODULE_WITH_BAD_ESCAPE)
    assert isinstance(tree, ast.Module)
    assert not _syntax_warnings(record)


def test_parse_analyzed_expression_suppresses_syntaxwarning() -> None:
    with warnings.catch_warnings(record=True) as record:
        warnings.simplefilter("always")
        tree = parse_analyzed_expression(_EXPR_WITH_BAD_ESCAPE)
    assert isinstance(tree, ast.Expression)
    assert not _syntax_warnings(record)


def test_parse_analyzed_module_threads_filename_into_errors() -> None:
    """The real target path is attributed instead of Python's ``<unknown>``."""
    with pytest.raises(SyntaxError) as exc_info:
        parse_analyzed_module("def broken(:\n", filename="target/app.py")
    assert exc_info.value.filename == "target/app.py"


def test_parse_analyzed_module_supports_type_comments() -> None:
    tree = parse_analyzed_module("x = []  # type: list[int]\n", type_comments=True)
    assert isinstance(tree, ast.Module)


def test_parse_analyzed_module_does_not_suppress_unrelated_warnings() -> None:
    """Only SyntaxWarning is muted; the engine's own warnings still surface."""
    with warnings.catch_warnings(record=True) as record:
        warnings.simplefilter("always")
        parse_analyzed_module("x = 1\n")
        warnings.warn("engine warning", UserWarning, stacklevel=1)
    assert any(issubclass(w.category, UserWarning) for w in record)
