"""Semantic spec: real-world engine gaps identified in a real Flask app evaluation.

Fixture: tests/fixtures/apps/semantic/flask_real_world_gaps/

Each test models a specific false-positive root cause from a real-world
Flask app gap analysis.  All tests are written to fail before the
corresponding engine gap is fixed.  Keep ``xfail(strict=True)`` only on
gaps that remain open.

Gap references:
  - Gap 1 (72+ FPs): MethodView ``decorators`` class attribute
  - Gap 2 (47+ FPs): Global CSRFProtect via ``init_app``
  - Gap 3 (8 FPs):   Blueprint-level rate limiting
  - Gap 4 (22 FPs):  ``url_for()`` redirect classification
  - Gap 5 (7 FPs):   Custom validation function as check
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed.route import HttpMethod

if TYPE_CHECKING:
    from flawed.repo import RepoView
    from flawed.route import Route


def _route(repo: RepoView, endpoint: str, method: HttpMethod | None = None) -> Route:
    matches = [
        r
        for r in repo.routes
        if _route_endpoint_matches(r, endpoint) and (method is None or method in r.methods)
    ]
    assert matches, f"route endpoint {endpoint!r} not found in {[r.endpoint for r in repo.routes]}"
    assert len(matches) == 1, f"multiple routes for {endpoint!r}: {matches}"
    return matches[0]


def _route_endpoint_matches(route: Route, endpoint: str) -> bool:
    if route.endpoint == endpoint:
        return True
    return route.group is not None and f"{route.group}.{route.endpoint}" == endpoint


# =====================================================================
# P28: flask-allows authorization decorator
# =====================================================================


class TestFlaskAllowsAuthorization:
    """Engine must recognize ``@allows.requires(...)`` as an AUTHORIZATION check.

    Flask-Allows is the authorization framework used by real-world
    Flask apps.  Routes guarded by ``@allows.requires(IsAdmin)`` should
    have an AUTHORIZATION check in their scope, preventing false positives
    in auth-coverage rules.
    """

    def test_allows_requires_detected_as_authorization(
        self,
        flask_real_world_gaps: RepoView,
    ) -> None:
        """@allows.requires(IsAdmin) on route -> AUTHORIZATION check.

        Fixture: flask_real_world_gaps/app.py::management_panel()
        EXPECT: route "/management" has AUTHORIZATION guard
        """
        route = _route(flask_real_world_gaps, "management_panel")
        checks = list(route.reachable.checks(category="AUTHORIZATION"))
        assert len(checks) >= 1, (
            "@allows.requires(IsAdmin) should produce an "
            "AUTHORIZATION check visible on the management_panel route"
        )

    def test_unguarded_route_has_no_allows_check(
        self,
        flask_real_world_gaps: RepoView,
    ) -> None:
        """Route without @allows.requires -> no AUTHORIZATION check.

        Fixture: flask_real_world_gaps/app.py::redirect_unsafe()
        EXPECT: route "/redirect/unsafe" has NO AUTHORIZATION check
        """
        route = _route(flask_real_world_gaps, "redirect_unsafe")
        checks = list(route.reachable.checks(category="AUTHORIZATION"))
        assert checks == [], "unguarded route should not have AUTHORIZATION check"


# =====================================================================
# Gap 1: MethodView ``decorators`` class attribute (DISC-047)
# =====================================================================


class TestMethodViewDecoratorsClassAttribute:
    """Engine must extract decorators from MethodView ``decorators = [...]``.

    Flask's MethodView applies decorators listed in the ``decorators``
    class attribute to every HTTP method handler.  The engine currently
    only recognizes ``@decorator`` syntax on individual functions — it
    misses the class-level attribute entirely.

    This was the #1 false-positive source in the real-world evaluation,
    causing 72+ incorrect "missing auth" findings on routes whose
    MethodView classes had ``decorators = [login_required]``.
    """

    def test_methodview_decorators_class_attribute_visible_to_semantic_layer(
        self,
        flask_real_world_gaps: RepoView,
    ) -> None:
        """AdminDashboard has ``decorators = [login_required]``.

        The engine must detect login_required as an AUTHENTICATION check
        on both GET and POST methods of the AdminDashboard view.
        """
        for method in (HttpMethod.GET, HttpMethod.POST):
            route = _route(flask_real_world_gaps, "admin_dashboard", method)
            checks = list(route.reachable.checks(category="AUTHENTICATION"))
            assert len(checks) >= 1, (
                "AdminDashboard.decorators = [login_required] should produce "
                f"an AUTHENTICATION check on the {method.value} route"
            )

    def test_class_without_decorators_has_no_auth(
        self,
        flask_real_world_gaps: RepoView,
    ) -> None:
        """EditProfile has no decorators attribute — should have no auth.

        This is the complementary test: a MethodView WITHOUT the
        ``decorators`` attribute should correctly show NO auth checks,
        confirming the detection is specific and not a blanket override.
        """
        route = _route(flask_real_world_gaps, "edit_profile", HttpMethod.POST)
        checks = list(route.reachable.checks(category="AUTHENTICATION"))
        assert len(checks) == 0, "EditProfile has no decorators — should have no auth check"


# =====================================================================
# Gap 2: CSRFProtect global guard via init_app (DISC-048)
# =====================================================================


class TestGlobalCSRFProtection:
    """Engine must recognize ``CSRFProtect().init_app(app)`` as global CSRF.

    Flask-WTF's CSRFProtect registers a ``before_request`` hook that
    validates CSRF tokens on ALL non-safe-method requests.  The engine's
    ``full_stack`` scope should include this lifecycle guard, so that
    ``route.full_stack.checks(category="CSRF")`` returns the global
    CSRFProtect check for every POST route.

    This gap caused ALL 36 "missing CSRF" findings in the real-world
    evaluation to be false positives.
    """

    def test_csrf_visible_in_full_stack(
        self,
        flask_real_world_gaps: RepoView,
    ) -> None:
        """POST route should show CSRF check via full_stack scope.

        CSRFProtect.init_app(app) applies to ALL routes — the engine
        must trace this lifecycle registration into per-route full_stack.
        """
        route = _route(flask_real_world_gaps, "edit_profile")
        checks = list(route.full_stack.checks(category="CSRF"))
        assert len(checks) >= 1, (
            "CSRFProtect.init_app(app) should produce a CSRF check "
            "visible via route.full_stack.checks(category='CSRF')"
        )


# =====================================================================
# Gap 3: Blueprint-level rate limiting (DISC-049)
# =====================================================================


class TestBlueprintLevelRateLimiting:
    """Engine must propagate blueprint-level guards to individual routes.

    ``limiter.limit("5/minute")(auth)`` applies rate limiting to all
    routes registered on the ``auth`` blueprint.  The engine must
    propagate this guard to individual blueprint routes so that
    ``route.full_stack.checks(category="RATE_LIMITING")`` finds it.

    This gap caused 6 of 8 "missing rate limit" FPs in a real app.
    """

    def test_blueprint_rate_limit_visible_on_login(
        self,
        flask_real_world_gaps: RepoView,
    ) -> None:
        """Login route should show RATE_LIMITING from blueprint-level guard."""
        route = _route(flask_real_world_gaps, "auth.login")
        checks = list(route.full_stack.checks(category="RATE_LIMITING"))
        assert len(checks) >= 1, (
            "limiter.limit('5/minute')(auth) should produce a "
            "RATE_LIMITING check visible on auth.login via full_stack"
        )

    def test_blueprint_rate_limit_visible_on_register(
        self,
        flask_real_world_gaps: RepoView,
    ) -> None:
        """Register route should also inherit blueprint-level rate limit."""
        route = _route(flask_real_world_gaps, "auth.register")
        checks = list(route.full_stack.checks(category="RATE_LIMITING"))
        assert len(checks) >= 1, (
            "limiter.limit('5/minute')(auth) should propagate to auth.register"
        )

    def test_blueprint_rate_limit_does_not_apply_to_other_routes(
        self,
        flask_real_world_gaps: RepoView,
    ) -> None:
        """Auth blueprint limiter should not be treated as app-global.

        ``limiter.limit("5/min")(auth)`` must resolve as a blueprint-scoped
        guard, not an application-scoped guard.
        """
        route = _route(flask_real_world_gaps, "redirect_unsafe")
        checks = list(route.full_stack.checks(category="RATE_LIMITING"))
        assert checks == []


# =====================================================================
# Gap 4: url_for() redirect target classification (DISC-050)
# =====================================================================


class TestRedirectTargetClassification:
    """Engine must distinguish safe vs unsafe redirect targets.

    ``redirect(url_for("endpoint"))`` uses a server-generated URL —
    it cannot be an open redirect.  ``redirect(user_input)`` is a
    genuine risk.  The engine currently treats both the same.

    This gap caused 22 of 29 "open redirect" findings in a real app
    to be false positives (redirects to url_for() or model.url).
    """

    def test_url_for_redirect_not_flagged(
        self,
        flask_real_world_gaps: RepoView,
    ) -> None:
        """redirect(url_for(...)) should NOT be flagged as open redirect.

        The redirect target is a server-generated URL.  It should still be
        visible as a response-write effect, but not as a reachable
        OPEN_REDIRECT sink.
        """
        from flawed.effects import Response

        route = _route(flask_real_world_gaps, "redirect_safe")
        effects = list(route.reachable.effects(Response.write()))
        sinks = list(route.reachable.sinks(kind="OPEN_REDIRECT"))
        assert len(effects) >= 1
        assert sinks == []

    def test_user_input_redirect_is_detected(
        self,
        flask_real_world_gaps: RepoView,
    ) -> None:
        """redirect(request.args.get("next")) IS a genuine open redirect.

        This test should pass now — the engine correctly detects the
        redirect/response-write effect.  It serves as a regression guard.
        """
        from flawed.effects import Response

        route = _route(flask_real_world_gaps, "redirect_unsafe")
        effects = list(route.reachable.effects(Response.write()))
        sinks = list(route.reachable.sinks(kind="OPEN_REDIRECT"))
        assert len(effects) >= 1, (
            "redirect(request.args.get('next')) should produce a "
            "response-write effect detectable by the engine"
        )
        assert len(sinks) >= 1, "user-controlled redirect target should remain reportable"


# =====================================================================
# Gap 5: custom validation functions as checks (DISC-051)
# =====================================================================


class TestCustomRedirectValidation:
    """Engine must treat local URL validators as redirect safety guards."""

    def test_is_safe_url_guarded_redirect_not_flagged(
        self,
        flask_real_world_gaps: RepoView,
    ) -> None:
        """redirect(target) guarded by is_safe_url(target) is not an open redirect."""
        from flawed.effects import Response

        route = _route(flask_real_world_gaps, "redirect_validated")
        effects = list(route.reachable.effects(Response.write()))
        sinks = list(route.reachable.sinks(kind="OPEN_REDIRECT"))
        checks = list(route.reachable.checks(category="URL_VALIDATION"))

        assert len(effects) >= 1
        assert checks, "is_safe_url(target) should be exposed as a URL validation check"
        assert sinks == []

    def test_validated_redirect_helper_return_not_flagged(
        self,
        flask_real_world_gaps: RepoView,
    ) -> None:
        """redirect helper return is safe when helper returns only guarded candidates."""
        from flawed.effects import Response

        route = _route(flask_real_world_gaps, "login_redirect")
        effects = list(route.reachable.effects(Response.write()))
        sinks = list(route.reachable.sinks(kind="OPEN_REDIRECT"))
        checks = list(route.reachable.checks(category="URL_VALIDATION"))

        assert len(effects) >= 1
        assert checks, "helper-local URL validation should be visible in reachable scope"
        assert sinks == []


# =====================================================================
# Scope API completeness: validated_values() and generated_urls()
# =====================================================================


class TestScopeAPICompleteness:
    """New L3 domain types must be accessible via the standard scope API."""

    def test_validated_values_exposed_on_scope(
        self,
        flask_real_world_gaps: RepoView,
    ) -> None:
        """validated_values() returns collection on route scope."""
        route = _route(flask_real_world_gaps, "redirect_validated")
        # Method must exist and return a collection (possibly empty
        # if the conversion isn't wired yet for this fixture)
        result = route.reachable.validated_values()
        assert hasattr(result, "__iter__")
        assert hasattr(result, "__len__")

    def test_generated_urls_exposed_on_scope(
        self,
        flask_real_world_gaps: RepoView,
    ) -> None:
        """generated_urls() returns collection on route scope."""
        route = _route(flask_real_world_gaps, "redirect_safe")
        result = route.reachable.generated_urls()
        assert hasattr(result, "__iter__")
        assert hasattr(result, "__len__")
