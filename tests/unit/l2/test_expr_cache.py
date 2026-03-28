"""Tests for expression parse cache and canonicalize_fqn memoization."""

from __future__ import annotations

import ast

import pytest

from flawed._semantic._expr_cache import clear_expression_cache, parse_expression
from flawed._semantic._provider_engine import (
    _CANONICALIZE_CACHE,
    canonicalize_fqn,
    clear_canonicalize_cache,
)


@pytest.fixture(autouse=True)
def _clear_caches() -> None:
    clear_expression_cache()
    clear_canonicalize_cache()


# -- parse_expression --------------------------------------------------------


def test_parse_expression_returns_ast_expression() -> None:
    result = parse_expression("x + 1")
    assert isinstance(result, ast.Expression)
    assert isinstance(result.body, ast.BinOp)


def test_parse_expression_returns_none_for_syntax_error() -> None:
    assert parse_expression("def x:") is None


def test_parse_expression_caches_valid_result() -> None:
    first = parse_expression("foo.bar")
    second = parse_expression("foo.bar")
    assert first is second


def test_parse_expression_caches_none_for_invalid() -> None:
    first = parse_expression("not valid python +++")
    second = parse_expression("not valid python +++")
    assert first is None
    assert second is None


def test_parse_expression_different_strings_cached_independently() -> None:
    a = parse_expression("x")
    b = parse_expression("y")
    assert a is not b
    assert isinstance(a, ast.Expression)
    assert isinstance(b, ast.Expression)


def test_clear_expression_cache_resets_state() -> None:
    first = parse_expression("obj.attr")
    clear_expression_cache()
    second = parse_expression("obj.attr")
    assert first is not second
    assert isinstance(second, ast.Expression)


# -- canonicalize_fqn --------------------------------------------------------


def test_canonicalize_fqn_sorts_by_longest_prefix_first() -> None:
    aliases = {
        "a": "short",
        "a.b": "medium",
        "a.b.c": "long",
    }
    assert canonicalize_fqn("a.b.c.d", aliases) == "long.d"


def test_canonicalize_fqn_exact_match() -> None:
    aliases = {"flask.Flask": "flask.app.Flask"}
    assert canonicalize_fqn("flask.Flask", aliases) == "flask.app.Flask"


def test_canonicalize_fqn_no_match_returns_original() -> None:
    aliases = {"flask": "flask.app"}
    assert canonicalize_fqn("django.views", aliases) == "django.views"


def test_canonicalize_fqn_caches_result() -> None:
    aliases = {"pkg": "canonical.pkg"}
    canonicalize_fqn("pkg.Cls.method", aliases)
    assert any(k[0] == "pkg.Cls.method" for k in _CANONICALIZE_CACHE)
    # Second call returns from cache (no way to observe the skip directly,
    # but coverage of the early-return branch confirms it).
    assert canonicalize_fqn("pkg.Cls.method", aliases) == "canonical.pkg.Cls.method"


def test_canonicalize_fqn_detects_dict_mutation() -> None:
    aliases: dict[str, str] = {"unrelated": "other"}
    assert canonicalize_fqn("app.config", aliases) == "app.config"

    aliases["app"] = "myframework.App"
    assert canonicalize_fqn("app.config", aliases) == "myframework.App.config"


def test_canonicalize_fqn_different_dicts_cached_independently() -> None:
    a = {"pkg": "canonical_a"}
    b = {"pkg": "canonical_b"}
    assert canonicalize_fqn("pkg.Cls", a) == "canonical_a.Cls"
    assert canonicalize_fqn("pkg.Cls", b) == "canonical_b.Cls"


def test_clear_canonicalize_cache_resets() -> None:
    aliases = {"x": "y"}
    canonicalize_fqn("x.z", aliases)
    assert len(_CANONICALIZE_CACHE) > 0
    clear_canonicalize_cache()
    assert len(_CANONICALIZE_CACHE) == 0
