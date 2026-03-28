"""Specs: decorator discovery and properties.

Fixture: tests/fixtures/apps/decorators/ (session-scoped via root conftest)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed.function import FunctionKind

if TYPE_CHECKING:
    from flawed.repo import RepoView


class TestDecoratorDiscovery:
    def test_discovers_simple_decorator(self, decorators_app: RepoView) -> None:
        fn = decorators_app.functions.named("plain").one()
        decs = fn.decorators
        assert len(decs) == 1
        assert decs.one().name == "simple_decorator"

    def test_discovers_parameterized_decorator(self, decorators_app: RepoView) -> None:
        fn = decorators_app.functions.named("admin_only").one()
        decs = fn.decorators
        assert len(decs) == 1
        dec = decs.one()
        assert dec.name == "requires_role"
        assert any('"admin"' in a or "'admin'" in a for a in dec.arguments)

    def test_discovers_stacked_decorators(self, decorators_app: RepoView) -> None:
        fn = decorators_app.functions.named("stacked").one()
        assert len(fn.decorators) == 3

    def test_decorator_order(self, decorators_app: RepoView) -> None:
        fn = decorators_app.functions.named("stacked").one()
        names = [d.name for d in fn.decorators]
        # Application order: innermost first (simple_decorator applied first)
        # Source order: top to bottom (log_calls, requires_role, simple_decorator)
        assert "log_calls" in names
        assert "requires_role" in names
        assert "simple_decorator" in names

    def test_decorated_with_filter(self, decorators_app: RepoView) -> None:
        fns = decorators_app.functions.decorated_with("requires_role")
        names = {f.name for f in fns}
        assert "admin_only" in names
        assert "stacked" in names
        assert "restricted" in names
        assert "plain" not in names

    def test_method_decorators(self, decorators_app: RepoView) -> None:
        fn = decorators_app.functions.named("restricted").one()
        assert fn.decorators.named("requires_role")

    def test_decorator_fqn_lookup(self, decorators_app: RepoView) -> None:
        """DecoratorCollection.named() searches by short name."""
        fn = decorators_app.functions.named("stacked").one()
        matches = fn.decorators.named("log_calls")
        assert len(matches) == 1

    def test_method_function_kind(self, decorators_app: RepoView) -> None:
        """Methods inside classes have FunctionKind.METHOD."""
        fn = decorators_app.functions.named("restricted").one()
        assert fn.kind == FunctionKind.METHOD

    def test_staticmethod_decorator(self, decorators_app: RepoView) -> None:
        """@staticmethod is discovered as a decorator."""
        fn = decorators_app.functions.named("public").one()
        decs = fn.decorators
        assert any(d.name == "staticmethod" for d in decs)

    def test_class_decorated_with_filter(self, decorators_app: RepoView) -> None:
        classes = decorators_app.classes.decorated_with("class_marker")
        assert [klass.name for klass in classes] == ["MarkedView"]
        assert classes.one().decorators.one().name == "class_marker"
