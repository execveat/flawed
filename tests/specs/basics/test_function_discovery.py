"""Specs: function discovery and filtering.

Fixture: tests/fixtures/apps/functions/ (session-scoped via root conftest)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flawed.function import FunctionKind

if TYPE_CHECKING:
    from flawed.repo import RepoView


class TestFunctionDiscovery:
    """The repo view discovers all functions in the fixture."""

    def test_discovers_top_level_functions(self, functions_app: RepoView) -> None:
        fns = functions_app.functions.where(lambda f: f.kind == FunctionKind.TOP_LEVEL)
        names = {f.name for f in fns}
        assert "top_level" in names
        assert "with_nested" in names
        assert "with_lambda" in names
        assert "with_closure" in names

    def test_discovers_methods(self, functions_app: RepoView) -> None:
        methods = functions_app.functions.where(lambda f: f.kind == FunctionKind.METHOD)
        names = {f.name for f in methods}
        assert "add" in names
        assert "multiply" in names

    def test_discovers_nested_functions(self, functions_app: RepoView) -> None:
        nested = functions_app.functions.where(lambda f: f.kind == FunctionKind.NESTED)
        names = {f.name for f in nested}
        assert "inner" in names

    def test_discovers_lambdas(self, functions_app: RepoView) -> None:
        lambdas = functions_app.functions.where(lambda f: f.kind == FunctionKind.LAMBDA)
        assert len(lambdas) >= 1

    def test_discovers_static_methods(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("zero").one()
        assert fn.parent_class is not None

    def test_discovers_class_methods(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("from_value").one()
        assert fn.parent_class is not None

    def test_cross_file_discovery(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("validate_positive").one()
        assert "helpers.py" in fn.location.file

    def test_total_function_count(self, functions_app: RepoView) -> None:
        # top_level, with_nested, with_lambda, with_closure,
        # inner (nested), lambda, inner (closure),
        # add, multiply, zero, from_value,
        # validate_positive, format_result
        assert len(functions_app.functions) >= 13


class TestFunctionFiltering:
    """Collection filters return the correct subsets."""

    def test_named_filter(self, functions_app: RepoView) -> None:
        fns = functions_app.functions.named("add")
        assert len(fns) == 1
        assert fns.one().name == "add"

    def test_with_fqn_filter(self, functions_app: RepoView) -> None:
        # FQN depends on how the fixture is indexed
        fn = functions_app.functions.named("add").one()
        result = functions_app.functions.with_fqn(fn.fqn)
        assert len(result) == 1

    def test_in_file_filter(self, functions_app: RepoView) -> None:
        fns = functions_app.functions.in_file("helpers.py")
        names = {f.name for f in fns}
        assert "validate_positive" in names
        assert "format_result" in names
        assert "top_level" not in names

    def test_in_dir_filter(self, functions_app: RepoView) -> None:
        # All functions should be in the fixture dir
        all_fns = functions_app.functions.in_dir(".")
        assert len(all_fns) == len(functions_app.functions)

    def test_decorated_with_filter(self, functions_app: RepoView) -> None:
        decorated = functions_app.functions.decorated_with("staticmethod")
        names = {f.name for f in decorated}
        assert "zero" in names

    def test_chained_filters(self, functions_app: RepoView) -> None:
        result = functions_app.functions.in_file("main.py").named("top_level")
        assert len(result) == 1

    def test_where_predicate(self, functions_app: RepoView) -> None:
        fns = functions_app.functions.where(lambda f: len(f.params) > 1)
        for fn in fns:
            assert len(fn.params) > 1

    def test_first_returns_none_on_empty(self, functions_app: RepoView) -> None:
        result = functions_app.functions.named("nonexistent").first()
        assert result is None

    def test_one_raises_on_multiple(self, functions_app: RepoView) -> None:
        # "inner" appears in both with_nested and with_closure
        with pytest.raises(ValueError, match="expected exactly 1 item"):
            functions_app.functions.named("inner").one()


class TestFunctionProperties:
    """Individual function properties are correctly populated."""

    def test_fqn_is_nonempty(self, functions_app: RepoView) -> None:
        for fn in functions_app.functions:
            assert fn.fqn, f"{fn.name} has empty fqn"

    def test_name_matches_declaration(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("top_level").one()
        assert fn.name == "top_level"

    def test_file_is_set(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("top_level").one()
        assert fn.location.file.endswith("main.py")

    def test_line_is_positive(self, functions_app: RepoView) -> None:
        for fn in functions_app.functions:
            assert fn.location.line > 0, f"{fn.name} has line {fn.location.line}"

    def test_params_include_defaults(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("top_level").one()
        assert len(fn.params) == 2
        assert fn.params[0].name == "x"
        assert fn.params[1].name == "y"
        assert fn.params[1].default == "10"

    def test_method_has_parent_class(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("add").one()
        assert fn.parent_class is not None
        assert "Calculator" in fn.parent_class

    def test_nested_has_parent_function(self, functions_app: RepoView) -> None:
        # The inner function inside with_nested
        inners = functions_app.functions.named("inner")
        for inner in inners:
            assert inner.parent_function is not None

    def test_top_level_has_no_parent(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("top_level").one()
        assert fn.parent_class is None
        assert fn.parent_function is None

    def test_location_spans_declaration(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("top_level").one()
        assert fn.location.line > 0
        assert fn.location.column >= 0
