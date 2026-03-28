"""EP-6: Lifecycle hook resolution tests.

Tests that the Semantic API correctly detects lifecycle hooks declared
by providers.

Pattern types under test:
  - LifecycleDecoratorPattern (@app.before_request)
  - LifecycleRegistrationPattern (LoginManager.init_app)
  - MiddlewareClassPattern (Django MiddlewareMixin subclasses)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from flawed.repo import RepoView
    from flawed.route import Route


def _route(repo: RepoView, endpoint: str) -> Route:
    matches = tuple(route for route in repo.routes if route.endpoint == endpoint)
    assert matches, f"route endpoint {endpoint!r} was not discovered"
    assert len(matches) == 1, f"expected one route for endpoint {endpoint!r}, got {len(matches)}"
    return matches[0]


def _full_stack_decorator_names(repo: RepoView, endpoint: str = "index") -> tuple[str, ...]:
    return tuple(decorator.name for decorator in _route(repo, endpoint).full_stack.decorators())


def _full_stack_effect_expressions(repo: RepoView, endpoint: str = "index") -> tuple[str, ...]:
    return tuple(effect.expression for effect in _route(repo, endpoint).full_stack.effects())


def _full_stack_call_expressions(repo: RepoView, endpoint: str = "index") -> tuple[str, ...]:
    return tuple(call.target_expression for call in _route(repo, endpoint).full_stack.calls())


def _full_stack_call_arg_expressions(repo: RepoView, endpoint: str = "index") -> tuple[str, ...]:
    return tuple(
        arg.expression
        for call in _route(repo, endpoint).full_stack.calls()
        for arg in call.arguments
    )


# =====================================================================
# LifecycleDecoratorPattern — @app.before_request
# =====================================================================


class TestLifecycleDecoratorPattern:
    """Test detection of decorator-based lifecycle hooks.

    Provider declaration:
        LifecycleDecoratorPattern(
            fqn="flask.Flask.before_request",
            hook_type=HookType.BEFORE_REQUEST,
        )
    """

    def test_l0_before_request(self, flask_basic: RepoView) -> None:
        """@app.before_request → BEFORE_REQUEST hook detected.

        Fixture: flask_basic/app.py::lifecycle_before()
        EXPECT: hook with type=BEFORE_REQUEST, handler=lifecycle_before
        """
        assert "app.before_request" in _full_stack_decorator_names(flask_basic)

    def test_l0_after_request(self, flask_basic: RepoView) -> None:
        """@app.after_request → AFTER_REQUEST hook detected.

        Fixture: flask_basic/app.py::lifecycle_after()
        """
        assert "app.after_request" in _full_stack_decorator_names(flask_basic)

    def test_l0_teardown_request(self, flask_basic: RepoView) -> None:
        """@app.teardown_request → TEARDOWN_REQUEST hook detected.

        Fixture: flask_basic/app.py::lifecycle_teardown()
        """
        assert "app.teardown_request" in _full_stack_decorator_names(flask_basic)

    def test_l0_error_handler(self, flask_basic: RepoView) -> None:
        """@app.errorhandler(404) → ERROR_HANDLER hook detected.

        Fixture: flask_basic/app.py::lifecycle_error()
        """
        assert "app.errorhandler" in _full_stack_decorator_names(flask_basic)

    def test_l1_aliased_before_request(self, flask_aliased: RepoView) -> None:
        """@my_app.before_request (aliased app) → still detected.

        Fixture: flask_aliased/app.py::lifecycle_before()
        """
        assert "my_app.before_request" in _full_stack_decorator_names(flask_aliased)

    def test_l0_hook_included_in_route_scope(self, flask_basic: RepoView) -> None:
        """before_request handler body is in every route's full_stack scope.

        EXPECT: lifecycle_before() effects appear in route.full_stack
                for all routes in the app
        """
        assert "g.request_start" in _full_stack_effect_expressions(flask_basic)
        assert "g.request_start" not in tuple(
            effect.expression for effect in _route(flask_basic, "index").body.effects()
        )


class TestNestedBlueprintLifecycle:
    """FLAW-114: parent-blueprint before_request hooks reach nested routes.

    Fixture: flask_nested_blueprint/ — a parent Blueprint registers child
    blueprints via ``bp.register_blueprint(child.bp)``.  A hook on the parent
    must be attributed to every nested child route's full_stack, while a
    child's own group-scoped hook must reach only that child (no sibling leak).
    """

    @staticmethod
    def _route_call_fqns(repo: RepoView, endpoint: str) -> frozenset[str]:
        route = _route(repo, endpoint)
        fqns: set[str] = set()
        for call in route.full_stack.calls():
            target = getattr(call, "target", None)
            if target is not None:
                fqns.add(target.fqn)
            fqns.add(call.target_expression)
        return frozenset(fqns)

    def test_parent_hook_reaches_first_child(self, flask_nested_blueprint: RepoView) -> None:
        """Parent ``root_guard`` + its callee reach the 'alpha' child route."""
        fqns = self._route_call_fqns(flask_nested_blueprint, "alpha_info")
        assert "flask_nested_blueprint.read_forbidden_param" in fqns

    def test_parent_hook_reaches_sibling_child(self, flask_nested_blueprint: RepoView) -> None:
        """Parent ``root_guard`` + its callee reach the 'beta' child route too."""
        fqns = self._route_call_fqns(flask_nested_blueprint, "beta_info")
        assert "flask_nested_blueprint.read_forbidden_param" in fqns

    def test_child_own_hook_applies_to_own_route(self, flask_nested_blueprint: RepoView) -> None:
        """Alpha's own group hook ``alpha_guard`` reaches alpha's route."""
        fqns = self._route_call_fqns(flask_nested_blueprint, "alpha_info")
        assert "flask_nested_blueprint.children.alpha.read_alpha_secret" in fqns

    def test_child_hook_does_not_leak_to_sibling(self, flask_nested_blueprint: RepoView) -> None:
        """Alpha's hook MUST NOT attach to sibling 'beta' routes (non-leakage)."""
        fqns = self._route_call_fqns(flask_nested_blueprint, "beta_info")
        assert "flask_nested_blueprint.children.alpha.read_alpha_secret" not in fqns
        assert "flask_nested_blueprint.children.alpha.alpha_guard" not in fqns


# =====================================================================
# LifecycleRegistrationPattern — LoginManager.init_app
# =====================================================================


class TestLifecycleRegistrationPattern:
    """Test detection of init_app-style lifecycle registration.

    Provider declaration:
        LifecycleRegistrationPattern(
            registration_fqn="flask_login.LoginManager.init_app",
            hook_type=HookType.AFTER_REQUEST,
        )

    Note: this is tested indirectly — the LoginManager registration
    isn't in the fixture yet. This test documents expected behavior.
    """

    @pytest.mark.xfail(
        reason=(
            "P8.1a-LC-01 [blocked-on: DISC-021]: implicit lifecycle "
            "registrations require invocation semantics for "
            "framework-owned callbacks"
        ),
        strict=True,
    )
    def test_l0_init_app_registration(self) -> None:
        """LoginManager.init_app(app) → AFTER_REQUEST hook.

        EXPECT: engine detects init_app() call and registers the
                implicit lifecycle hook
        """
        raise NotImplementedError


# =====================================================================
# MiddlewareClassPattern — Django middleware
# =====================================================================


class TestMiddlewareClassPattern:
    """Test detection of class-based middleware hooks.

    Provider declaration:
        MiddlewareClassPattern(
            base_class_fqn="django.utils.deprecation.MiddlewareMixin",
            method_hooks={
                "process_request": HookType.BEFORE_HANDLER,
                "process_response": HookType.AFTER_HANDLER,
                "process_view": HookType.BEFORE_HANDLER,
                "process_exception": HookType.ON_ERROR,
            },
        )
    """

    def test_l5_middleware_request_hook(self, django_basic: RepoView) -> None:
        """AuthMiddleware.process_request() → BEFORE_HANDLER hook.

        Fixture: django_basic/middleware.py::AuthMiddleware
        EXPECT: engine detects AuthMiddleware as MiddlewareMixin subclass,
                maps process_request → BEFORE_HANDLER
        """
        assert "request.META.get" in _full_stack_call_expressions(django_basic)
        assert '"HTTP_AUTHORIZATION"' in _full_stack_call_arg_expressions(django_basic)

    def test_l5_middleware_response_hook(self, django_basic: RepoView) -> None:
        """LoggingMiddleware.process_response() → AFTER_HANDLER hook.

        Fixture: django_basic/middleware.py::LoggingMiddleware
        """
        assert "response.setdefault" in _full_stack_call_expressions(django_basic)
        assert '"X-Logged"' in _full_stack_call_arg_expressions(django_basic)

    def test_l5_middleware_both_hooks(self, django_basic: RepoView) -> None:
        """LoggingMiddleware has both request and response hooks.

        Fixture: django_basic/middleware.py::LoggingMiddleware
        EXPECT: both BEFORE_HANDLER and AFTER_HANDLER hooks detected
        """
        expressions = _full_stack_call_expressions(django_basic)
        args = _full_stack_call_arg_expressions(django_basic)
        assert "request.META.get" in expressions
        assert "response.setdefault" in expressions
        assert '"PATH_INFO"' in args

    def test_l5_middleware_in_route_scope(self, django_basic: RepoView) -> None:
        """Middleware hooks are included in route full_stack scope.

        EXPECT: AuthMiddleware.process_request effects appear in
                the full_stack scope of every Django route
        """
        route = _route(django_basic, "index")
        full_stack_args = tuple(
            arg.expression for call in route.full_stack.calls() for arg in call.arguments
        )
        body_args = tuple(arg.expression for call in route.body.calls() for arg in call.arguments)
        assert '"HTTP_AUTHORIZATION"' in full_stack_args
        assert '"HTTP_AUTHORIZATION"' not in body_args
