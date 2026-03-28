"""DI resolution tests for FastAPI/Litestar dependency injection.

Tests that the Semantic API correctly resolves DependencyPattern
declarations and includes dependency call trees in route scopes.

Pattern type under test:
  - DependencyPattern (Depends, Security)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed.core import Key
from flawed.inputs import DependencyInput

if TYPE_CHECKING:
    from flawed.repo import RepoView
    from flawed.route import Route


def _routes_by_endpoint(repo: RepoView) -> dict[str, Route]:
    return {route.endpoint: route for route in repo.routes}


def _dependency_providers(route: Route) -> set[str | None]:
    return {
        getattr(read.source, "provider_fqn", None)
        for read in route.reachable.reads(DependencyInput())
    }


def _call_origin_fqns(route: Route) -> set[str]:
    return {call.function.fqn for call in route.reachable.calls()}


def _guard_categories(route: Route) -> set[str | None]:
    return {getattr(condition, "category", None) for condition in route.reachable.conditions()}


# =====================================================================
# Basic DI resolution
# =====================================================================


class TestDependencyResolution:
    """Test that Depends() parameters are resolved and included in scope.

    Provider declaration:
        DependencyPattern(
            inject_fqn="fastapi.Depends",
            callable_arg=0,
            scope="lifecycle_and_input",
        )
    """

    def test_l0_depends_resolved(self, fastapi_basic: RepoView) -> None:
        """Depends(get_db) → get_db is included in route's reachable scope.

        Fixture: fastapi_basic/app.py::get_db_item()
        EXPECT: get_db() function body is reachable from the route
        EXPECT: effects inside get_db are attributed to the route
        """
        route = _routes_by_endpoint(fastapi_basic)["get_db_item"]

        assert "fastapi_basic.deps.get_db" in _call_origin_fqns(route)

    def test_l0_depends_return_as_input(self, fastapi_basic: RepoView) -> None:
        """Depends(get_db) → get_db's return value flows to handler param.

        Fixture: fastapi_basic/app.py::get_db_item()
        EXPECT: the 'db' parameter carries get_db's return value
        """
        route = _routes_by_endpoint(fastapi_basic)["get_db_item"]
        reads = list(route.body.reads(DependencyInput(parameter=Key("db"))))

        assert len(reads) == 1
        assert reads[0].source == DependencyInput(
            parameter=Key("db"),
            provider_fqn="fastapi_basic.deps.get_db",
        )
        assert reads[0].expression == "db"

    def test_l0_security_depends(self, fastapi_basic: RepoView) -> None:
        """Depends(get_current_user) → security guard on route.

        Fixture: fastapi_basic/app.py::protected()
        EXPECT: route has a security check (get_current_user can raise 401)
        """
        route = _routes_by_endpoint(fastapi_basic)["protected"]

        assert "AUTHENTICATION" in _guard_categories(route)
        assert "fastapi_basic.auth.get_current_user" in _dependency_providers(route)


# =====================================================================
# Nested DI resolution
# =====================================================================


class TestNestedDependencies:
    """Test recursive DI graph resolution.

    FastAPI allows Depends() inside Depends():
      handler → Depends(get_settings) → Depends(get_db)

    The engine must resolve the full chain.
    """

    def test_nested_dependency_chain(self, fastapi_basic: RepoView) -> None:
        """get_settings depends on get_db → both in route scope.

        Fixture: fastapi_basic/app.py::with_settings()
        Fixture: fastapi_basic/deps.py::get_settings(db=Depends(get_db))
        EXPECT: both get_settings and get_db are in reachable scope
        """
        route = _routes_by_endpoint(fastapi_basic)["with_settings"]
        providers = _dependency_providers(route)

        assert "fastapi_basic.deps.get_settings" in providers
        assert "fastapi_basic.deps.get_db" in providers
        assert "fastapi_basic.deps.get_db" in _call_origin_fqns(route)

    def test_nested_security_chain(self, fastapi_basic: RepoView) -> None:
        """require_admin → get_current_user → oauth2_scheme.

        Fixture: fastapi_basic/auth.py
        EXPECT: full DI chain resolved, all three functions in scope
        EXPECT: route gets AUTHENTICATION check from the chain
        """
        route = _routes_by_endpoint(fastapi_basic)["admin_panel"]
        providers = _dependency_providers(route)
        origins = _call_origin_fqns(route)

        assert "fastapi_basic.auth.require_admin" in providers
        assert "fastapi_basic.auth.get_current_user" in providers
        assert "fastapi_basic.auth.oauth2_scheme" in providers
        assert "fastapi_basic.auth.require_admin" in origins
        assert "fastapi_basic.auth.get_current_user" in origins
        assert "AUTHENTICATION" in _guard_categories(route)


# =====================================================================
# Security scheme detection via DI
# =====================================================================


class TestSecuritySchemesViaDI:
    """Test that OAuth2 security schemes are detected through DI.

    Provider declarations:
        SecurityCheckPattern(
            fqn="fastapi.security.OAuth2PasswordBearer",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
        )
        DependencyPattern(
            inject_fqn="fastapi.Security",
            callable_arg=0,
            scope="guard",
        )
    """

    def test_l0_oauth2_scheme(self, fastapi_basic: RepoView) -> None:
        """Security(oauth2_scheme) → AUTHENTICATION check on route.

        Fixture: fastapi_basic/app.py::oauth2_protected()
        EXPECT: OAuth2PasswordBearer check detected via Security() DI
        """
        route = _routes_by_endpoint(fastapi_basic)["oauth2_protected"]

        assert "AUTHENTICATION" in _guard_categories(route)
        assert list(route.body.reads(DependencyInput(parameter=Key("token"))))
        assert "fastapi_basic.auth.oauth2_scheme" in _dependency_providers(route)

    def test_l4_transitive_auth(self, fastapi_basic: RepoView) -> None:
        """Depends(get_current_user) which depends on oauth2_scheme.

        Fixture: fastapi_basic/app.py::protected()
        EXPECT: AUTHENTICATION propagates through DI chain
        """
        route = _routes_by_endpoint(fastapi_basic)["protected"]

        assert "AUTHENTICATION" in _guard_categories(route)
        assert "fastapi_basic.auth.oauth2_scheme" in _dependency_providers(route)
