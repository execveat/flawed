"""Tests: ConcreteCodeScope.decorators() returns decorator union."""

from __future__ import annotations

import pytest

from flawed import open_repo
from flawed._semantic._collections import ConcreteDecoratorCollection
from flawed._semantic._scope import ConcreteCodeScope
from flawed.core import Location
from flawed.function import Decorator


def _make_decorator(name: str, fqn: str = "") -> Decorator:
    return Decorator(
        name=name,
        fqn=fqn or f"mod.{name}",
        arguments=(),
        location=Location(file="test.py", line=1, column=0),
    )


class TestScopeDecoratorsUnit:
    """Unit tests for ConcreteCodeScope.decorators()."""

    def test_empty_scope_returns_empty_collection(self) -> None:
        scope = ConcreteCodeScope()
        decs = scope.decorators()
        assert isinstance(decs, ConcreteDecoratorCollection)
        assert len(decs) == 0

    def test_scope_with_decorators_returns_them(self) -> None:
        d1 = _make_decorator("login_required")
        d2 = _make_decorator("requires_role")
        scope = ConcreteCodeScope(decorators=(d1, d2))
        decs = scope.decorators()
        assert len(decs) == 2
        names = {d.name for d in decs}
        assert names == {"login_required", "requires_role"}

    def test_scope_decorators_named_filter(self) -> None:
        d1 = _make_decorator("login_required")
        d2 = _make_decorator("requires_role")
        d3 = _make_decorator("log_calls")
        scope = ConcreteCodeScope(decorators=(d1, d2, d3))
        filtered = scope.decorators().named("requires_role")
        assert len(filtered) == 1
        first = filtered.first()
        assert first is not None
        assert first.name == "requires_role"

    def test_scope_decorators_with_fqn_filter(self) -> None:
        d1 = _make_decorator("login_required", fqn="auth.login_required")
        d2 = _make_decorator("login_required", fqn="other.login_required")
        scope = ConcreteCodeScope(decorators=(d1, d2))
        filtered = scope.decorators().with_fqn("auth.login_required")
        assert len(filtered) == 1


class TestRouteBodyDecorators:
    """Integration test: route body scope includes handler decorators."""

    def test_route_body_decorators_populated(self, decorators_app) -> None:
        """Route body scope should expose handler function's decorators."""
        kb = decorators_app
        # The decorators fixture has functions with decorators but no routes.
        # Use function body scope instead.
        fn = kb.functions.named("stacked").one()
        body_decs = fn.body.decorators()
        assert len(body_decs) == 3
        names = {d.name for d in body_decs}
        assert "log_calls" in names
        assert "requires_role" in names
        assert "simple_decorator" in names

    def test_function_body_decorators_named_filter(self, decorators_app) -> None:
        """Decorator collection from scope supports named() filtering."""
        kb = decorators_app
        fn = kb.functions.named("admin_only").one()
        body_decs = fn.body.decorators()
        assert len(body_decs) == 1
        assert body_decs.named("requires_role").first().name == "requires_role"

    def test_undecorated_function_body_returns_empty(self, decorators_app) -> None:
        """Functions without decorators return empty collection from scope."""
        kb = decorators_app
        # simple_decorator is itself a plain function with no decorators
        fn = kb.functions.named("simple_decorator").one()
        body_decs = fn.body.decorators()
        assert len(body_decs) == 0

    # TODO(artifact): live-builds an inline app -> spawns analysis tools. Extract
    # the app to a committed fixture + load_fixture(); marked @slow until then so
    # the subprocess guard (tests/_guards) tolerates it and it stays out of the
    # fast default run.
    @pytest.mark.slow
    def test_function_reachable_decorators_include_callees(self, tmp_path) -> None:
        """Reachable scope returns decorators from transitively called functions."""
        (tmp_path / "app.py").write_text(
            """def audit(fn):
    return fn

@audit
def helper():
    return "ok"

def handler():
    return helper()
"""
        )

        kb = open_repo(str(tmp_path))
        fn = kb.functions.named("handler").one()

        reachable_decs = fn.reachable.decorators()
        assert len(reachable_decs) == 1
        assert reachable_decs.named("audit").one().name == "audit"
