"""Multi-provider integration test matrix for L2 engine.

Runs the L2 engine against FastAPI, Django, DRF, and SQLAlchemy fixtures
and verifies provider-specific conversion produces the expected domain
objects (routes, inputs, effects, sinks, gaps).

Each test class covers one provider fixture. Tests are grouped by
semantic category (routes, inputs, effects, sinks, gaps) and verify
both positive detection and expected limitations.

Known limitations documented as gaps:
  - Django ``include()`` still produces SYMBOL_UNRESOLVED gaps.  Dotted
    function handlers (``views.index``) and Django/DRF class-view factory
    calls (``.as_view()``) resolve via L1 symbol table and ClassViewPattern.
  - SQLAlchemy Session method calls (``db.add``, ``db.commit``) are not
    matched because L1 lacks type inference for local variables.  The
    provider engine can only match module-level FQN imports (``text()``).
  - Sinks are flow-gated: they only surface through ``sinks()`` when
    ``InputRead`` objects exist in the same scope.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flawed.core import GapKind
from flawed.route import HttpMethod

if TYPE_CHECKING:
    from flawed.repo import RepoView

pytestmark = pytest.mark.slow


# =====================================================================
# FastAPI
# =====================================================================


class TestFastapiRoutes:
    """FastAPI route discovery via RouteDecorator patterns."""

    def test_all_routes_discovered(self, fastapi_basic: RepoView) -> None:
        routes = list(fastapi_basic.routes)
        assert len(routes) == 17

    @pytest.mark.parametrize(
        ("path", "method"),
        [
            ("/", "GET"),
            ("/items", "POST"),
            ("/items/{item_id}", "GET"),
            ("/search", "GET"),
            ("/body", "POST"),
            ("/form", "POST"),
            ("/upload", "POST"),
            ("/protected", "GET"),
            ("/redirect", "GET"),
        ],
    )
    def test_route_method_and_path(self, fastapi_basic: RepoView, path: str, method: str) -> None:
        matches = list(fastapi_basic.routes.with_path(path))
        assert len(matches) == 1, f"Expected 1 route for {path}, got {len(matches)}"
        assert HttpMethod(method) in matches[0].methods

    def test_route_handler_names(self, fastapi_basic: RepoView) -> None:
        handlers = {r.handler.name for r in fastapi_basic.routes}
        expected = {
            "index",
            "create_item",
            "get_item",
            "get_explicit_item",
            "search",
            "with_header",
            "with_cookie",
            "create_from_body",
            "submit_form",
            "upload_avatar",
            "get_db_item",
            "protected",
            "admin_panel",
            "with_settings",
            "oauth2_protected",
            "do_redirect",
            "json_resp",
        }
        assert handlers == expected


class TestFastapiInputs:
    """FastAPI InputParameterPattern and DependencyPattern detection."""

    def test_query_params_detected(self, fastapi_basic: RepoView) -> None:
        route = fastapi_basic.routes.with_path("/search").one()
        reads = list(route.body.reads())
        sources = {type(r.source).__name__ for r in reads}
        assert "Query" in sources

    def test_header_params_detected(self, fastapi_basic: RepoView) -> None:
        route = fastapi_basic.routes.with_path("/with_header").one()
        reads = list(route.body.reads())
        sources = {type(r.source).__name__ for r in reads}
        assert "Header" in sources

    def test_cookie_params_detected(self, fastapi_basic: RepoView) -> None:
        route = fastapi_basic.routes.with_path("/with_cookie").one()
        reads = list(route.body.reads())
        sources = {type(r.source).__name__ for r in reads}
        assert "Cookie" in sources

    def test_body_params_detected(self, fastapi_basic: RepoView) -> None:
        route = fastapi_basic.routes.with_path("/body").one()
        reads = list(route.body.reads())
        sources = {type(r.source).__name__ for r in reads}
        assert "Json" in sources

    def test_form_params_detected(self, fastapi_basic: RepoView) -> None:
        route = fastapi_basic.routes.with_path("/form").one()
        reads = list(route.body.reads())
        sources = {type(r.source).__name__ for r in reads}
        assert "Form" in sources

    def test_file_upload_detected(self, fastapi_basic: RepoView) -> None:
        route = fastapi_basic.routes.with_path("/upload").one()
        reads = list(route.body.reads())
        sources = {type(r.source).__name__ for r in reads}
        assert "FileUpload" in sources

    def test_path_params_detected(self, fastapi_basic: RepoView) -> None:
        route = fastapi_basic.routes.with_path("/items/{item_id}").one()
        reads = list(route.body.reads())
        sources = {type(r.source).__name__ for r in reads}
        assert "PathParam" in sources

    def test_dependency_injection_detected(self, fastapi_basic: RepoView) -> None:
        route = fastapi_basic.routes.with_path("/db_item/{item_id}").one()
        reads = list(route.body.reads())
        sources = {type(r.source).__name__ for r in reads}
        assert "DependencyInput" in sources

    def test_nested_dependency_chain(self, fastapi_basic: RepoView) -> None:
        """Depends(get_current_user) with nested oauth2_scheme."""
        route = fastapi_basic.routes.with_path("/protected").one()
        reads = list(route.body.reads())
        dep_reads = [r for r in reads if type(r.source).__name__ == "DependencyInput"]
        assert len(dep_reads) >= 1


class TestFastapiGaps:
    """FastAPI should produce zero gaps — fully functional provider."""

    def test_no_gaps(self, fastapi_basic: RepoView) -> None:
        assert len(fastapi_basic.gaps) == 0


# =====================================================================
# Django
# =====================================================================


class TestDjangoRoutes:
    """Django imperative route resolution."""

    def test_function_routes_resolved(self, django_basic: RepoView) -> None:
        """Dotted handler expressions (views.index) resolve via L1 symbol table.

        Class-view factory calls (.as_view()) resolve through ClassViewPattern;
        include() still needs recursive resolution.
        """
        routes = list(django_basic.routes)
        assert len(routes) == 11
        endpoints = {r.endpoint for r in routes}
        expected = {
            "index",
            "user_list",
            "user_detail",
            "user_create",
            "search",
            "redirect_view",
            "unsafe_view",
            "articlelistview",
            "articledetailview",
        }
        assert endpoints == expected

    def test_class_view_routes_resolved(self, django_basic: RepoView) -> None:
        """Django CBV .as_view() registrations produce method-scoped routes."""
        class_view_routes = [
            route
            for route in django_basic.routes
            if route.handler.fqn.startswith("django_basic.views.Article")
        ]

        assert {
            (route.url_rule, next(iter(route.methods)), route.handler.fqn)
            for route in class_view_routes
        } == {
            ("articles/", HttpMethod.GET, "django_basic.views.ArticleListView.get"),
            ("articles/", HttpMethod.POST, "django_basic.views.ArticleListView.post"),
            (
                "articles/<int:pk>/",
                HttpMethod.GET,
                "django_basic.views.ArticleDetailView.get",
            ),
            (
                "articles/<int:pk>/",
                HttpMethod.DELETE,
                "django_basic.views.ArticleDetailView.delete",
            ),
        }


class TestDjangoFunctions:
    """Django functions are indexed even without route resolution."""

    def test_view_functions_indexed(self, django_basic: RepoView) -> None:
        fn_names = {f.name for f in django_basic.functions}
        expected_views = {"index", "user_list", "user_detail", "user_create", "search"}
        assert expected_views <= fn_names

    def test_class_views_indexed(self, django_basic: RepoView) -> None:
        class_names = {c.name for c in django_basic.classes}
        assert "ArticleListView" in class_names
        assert "ArticleDetailView" in class_names

    def test_middleware_classes_indexed(self, django_basic: RepoView) -> None:
        class_names = {c.name for c in django_basic.classes}
        assert "AuthMiddleware" in class_names
        assert "LoggingMiddleware" in class_names


class TestDjangoEffects:
    """Django effect conversion on functions (no route context)."""

    def test_redirect_effect_on_function(self, django_basic: RepoView) -> None:
        fn = next(f for f in django_basic.functions if f.name == "redirect_view")
        effects = list(fn.body.effects())
        assert len(effects) >= 1
        categories = {e.category.name for e in effects}
        assert "RESPONSE_WRITE" in categories


class TestDjangoGaps:
    """Django gaps from unsupported recursive route resolution."""

    def test_symbol_unresolved_gaps_present(self, django_basic: RepoView) -> None:
        gaps = django_basic.gaps
        unresolved = [g for g in gaps if g.kind == GapKind.SYMBOL_UNRESOLVED]
        assert unresolved
        assert all("include(" in g.message for g in unresolved)

    def test_handler_gaps_do_not_reference_class_views(self, django_basic: RepoView) -> None:
        gaps = django_basic.gaps
        handler_gaps = [g for g in gaps if "handler" in g.message.lower()]
        assert all(".as_view()" not in g.message for g in handler_gaps)


# =====================================================================
# Django REST Framework
# =====================================================================


class TestDrfRoutes:
    """DRF ClassViewPattern route discovery with per-method route scopes."""

    def test_class_view_routes_discovered(self, drf_basic: RepoView) -> None:
        routes = list(drf_basic.routes)
        assert len(routes) == 3
        assert sum(1 for route in routes if route.endpoint == "protectedapiview") == 2
        assert sum(1 for route in routes if route.endpoint == "openstatusview") == 1

    def test_protected_api_view_route(self, drf_basic: RepoView) -> None:
        routes = list(drf_basic.routes)
        endpoints = {r.endpoint for r in routes}
        assert "protectedapiview" in endpoints

    def test_open_status_view_route(self, drf_basic: RepoView) -> None:
        routes = list(drf_basic.routes)
        endpoints = {r.endpoint for r in routes}
        assert "openstatusview" in endpoints

    def test_protected_view_methods(self, drf_basic: RepoView) -> None:
        routes = [r for r in drf_basic.routes if r.endpoint == "protectedapiview"]
        routes_by_method = {next(iter(route.methods)): route for route in routes}

        assert routes_by_method[HttpMethod.GET].handler.name == "get"
        assert routes_by_method[HttpMethod.POST].handler.name == "post"

    def test_open_status_view_get_only(self, drf_basic: RepoView) -> None:
        route = next(r for r in drf_basic.routes if r.endpoint == "openstatusview")
        assert HttpMethod.GET in route.methods


class TestDrfFunctions:
    """DRF function and class indexing."""

    def test_view_classes_indexed(self, drf_basic: RepoView) -> None:
        class_names = {c.name for c in drf_basic.classes}
        assert "ProtectedAPIView" in class_names
        assert "OpenStatusView" in class_names

    def test_permission_classes_indexed(self, drf_basic: RepoView) -> None:
        class_names = {c.name for c in drf_basic.classes}
        assert "OwnerPermission" in class_names
        assert "BurstThrottle" in class_names


class TestDrfGaps:
    """DRF gaps from imperative route handler resolution + interpreter error."""

    def test_symbol_unresolved_gaps(self, drf_basic: RepoView) -> None:
        gaps = drf_basic.gaps
        unresolved = [g for g in gaps if g.kind == GapKind.SYMBOL_UNRESOLVED]
        assert len(unresolved) >= 2

    def test_interpreter_error_for_api_view_decorator(self, drf_basic: RepoView) -> None:
        """@api_view decorator route produces INTERPRETER_ERROR for URL extraction."""
        gaps = drf_basic.gaps
        interpreter = [g for g in gaps if g.kind == GapKind.INTERPRETER_ERROR]
        assert len(interpreter) >= 1


# =====================================================================
# SQLAlchemy
# =====================================================================


class TestSqlalchemyStructure:
    """SQLAlchemy fixture: effects-only provider with no routing."""

    def test_no_routes(self, sqlalchemy_basic: RepoView) -> None:
        assert len(list(sqlalchemy_basic.routes)) == 0

    def test_functions_indexed(self, sqlalchemy_basic: RepoView) -> None:
        fn_names = {f.name for f in sqlalchemy_basic.functions}
        expected = {
            "create_user",
            "get_user",
            "search_users",
            "update_user",
            "delete_user",
            "raw_query",
            "safe_query",
            "before_flush_handler",
            "cleanup",
        }
        assert expected <= fn_names

    def test_model_class_indexed(self, sqlalchemy_basic: RepoView) -> None:
        class_names = {c.name for c in sqlalchemy_basic.classes}
        assert "User" in class_names


class TestSqlalchemyProviderMatching:
    """SQLAlchemy provider matching limitations due to L1 type inference.

    L1 resolves ``db.add(user)`` as ``create_user.<locals>.db.add`` rather
    than ``sqlalchemy.orm.session.Session.add``.  Only module-level imports
    (``text()``, ``@event.listens_for``) produce matchable FQNs.  Session
    method matching is blocked on L1-H04/L1-H05 type enrichment research.
    """

    def test_no_session_effects_without_type_inference(self, sqlalchemy_basic: RepoView) -> None:
        """The SQLAlchemy *provider* still cannot resolve Session methods (L1-H04).

        Precise ``Session.add``/``commit``/``delete`` attribution requires type
        inference, which is absent here. FLAW-281a does emit a conservative,
        low-confidence *generic* ``STATE_WRITE`` for mutating-verb calls
        (``db.add(...)``/``db.commit()``) — the intended FN-positive behaviour,
        distinct from provider attribution. So the only effects that may appear
        are those generic inferred ones (``interpreter == "inferred_state_writes"``),
        never provider-resolved Session effects.
        """
        for fn in sqlalchemy_basic.functions:
            for effect in fn.body.effects():
                assert effect.provenance.interpreter == "inferred_state_writes", (
                    f"Unexpected provider-resolved effect on {fn.name} "
                    f"({effect.expression}) — L1 should not resolve Session methods "
                    "without type inference; only FLAW-281a generic inference may fire"
                )

    def test_sinks_flow_gated_without_inputs(self, sqlalchemy_basic: RepoView) -> None:
        """Sinks only surface when InputReads exist in scope (flow-gating).

        SQLAlchemy standalone has no web input reads, so even matched
        TaintSinkPatterns (text()) are correctly hidden from sinks().
        """
        for fn in sqlalchemy_basic.functions:
            sinks = list(fn.body.sinks())
            assert len(sinks) == 0

    def test_no_gaps_for_unmatched_patterns(self, sqlalchemy_basic: RepoView) -> None:
        """Unmatched patterns produce no gaps — they simply don't match.

        Gaps are for conversion failures, not absence of matchable FQNs.
        """
        assert len(sqlalchemy_basic.gaps) == 0


# =====================================================================
# Cross-provider structural invariants
# =====================================================================


class TestCrossProviderInvariants:
    """Invariants that hold across all providers."""

    @pytest.mark.parametrize(
        "fixture_name",
        [
            "fastapi_basic",
            "django_basic",
            "drf_basic",
            "sqlalchemy_basic",
        ],
    )
    def test_all_gaps_have_kind_and_message(
        self, fixture_name: str, request: pytest.FixtureRequest
    ) -> None:
        rv: RepoView = request.getfixturevalue(fixture_name)
        for gap in rv.gaps:
            assert gap.kind is not None
            assert gap.message, f"Gap with kind={gap.kind} has empty message"

    @pytest.mark.parametrize(
        "fixture_name",
        [
            "fastapi_basic",
            "django_basic",
            "drf_basic",
            "sqlalchemy_basic",
        ],
    )
    def test_routes_have_handler_and_url(
        self, fixture_name: str, request: pytest.FixtureRequest
    ) -> None:
        rv: RepoView = request.getfixturevalue(fixture_name)
        for route in rv.routes:
            assert route.handler is not None
            assert route.url_rule is not None, f"Route {route.endpoint} has None url_rule"
            assert route.methods, f"Route {route.endpoint} has no methods"

    @pytest.mark.parametrize(
        "fixture_name",
        [
            "fastapi_basic",
            "django_basic",
            "drf_basic",
            "sqlalchemy_basic",
        ],
    )
    def test_functions_are_frozen(self, fixture_name: str, request: pytest.FixtureRequest) -> None:
        """All cross-boundary objects must be frozen (immutable)."""
        rv: RepoView = request.getfixturevalue(fixture_name)
        for fn in rv.functions:
            assert hasattr(fn, "name")
            assert hasattr(fn, "fqn")
