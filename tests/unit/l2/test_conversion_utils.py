"""Tests for shared semantic conversion utilities."""

from __future__ import annotations

import pytest

from flawed._semantic._conversion_utils import simple_name


@pytest.mark.parametrize("expression", ["name", "_private", "name_1"])
def test_simple_name_accepts_bare_names(expression: str) -> None:
    assert simple_name(expression) == expression


@pytest.mark.parametrize(
    "expression",
    [
        "",
        "pkg.name",
        "name()",
        "items[0]",
        "'literal'",
        "None",
        "class",
    ],
)
def test_simple_name_rejects_non_name_expressions(expression: str) -> None:
    assert simple_name(expression) is None
