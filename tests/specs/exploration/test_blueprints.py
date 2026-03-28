"""Blueprint accessor specs (FLAW-129: repo.blueprints / route.blueprint).

Exercises the first-class ``Blueprint`` route-group object surfaced for
interactive exploration:

- ``RepoView.blueprints`` -- every route group as a navigable collection.
- ``Blueprint.name`` / ``Blueprint.url_prefix`` / ``Blueprint.routes``.
- ``Route.blueprint`` -- the owning group (or ``None`` for top-level routes).

Uses session-scoped fixtures from the root conftest so individual tests do not
re-analyze (the timing guard fails direct open_repo/build_index calls).

The ``flask_blueprints`` fixture declares three groups:
``admin`` (url_prefix ``/admin``, 2 routes), ``api`` (url_prefix ``/api/v1``
applied at registration, 2 routes), and ``public`` (no prefix, 1 route).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flawed.repo import RepoView as RepoViewProto


class TestRepoBlueprints:
    """``RepoView.blueprints`` exposes the repo's route groups."""

    def test_all_groups_present(self, flask_blueprints: RepoViewProto) -> None:
        names = {bp.name for bp in flask_blueprints.blueprints}
        assert names == {"admin", "api", "public"}

    def test_constructor_url_prefix(self, flask_blueprints: RepoViewProto) -> None:
        admin = flask_blueprints.blueprints.named("admin").one()
        assert admin.url_prefix == "/admin"

    def test_registration_url_prefix(self, flask_blueprints: RepoViewProto) -> None:
        api = flask_blueprints.blueprints.named("api").one()
        assert api.url_prefix == "/api/v1"

    def test_missing_prefix_is_none_not_fabricated(self, flask_blueprints: RepoViewProto) -> None:
        public = flask_blueprints.blueprints.named("public").one()
        assert public.url_prefix is None

    def test_blueprint_routes_count(self, flask_blueprints: RepoViewProto) -> None:
        admin = flask_blueprints.blueprints.named("admin").one()
        assert len(admin.routes) == 2
        assert {r.endpoint.rsplit(".", 1)[-1] for r in admin.routes} == {
            "admin_dashboard",
            "admin_users",
        }

    def test_blueprints_collection_repr_is_concise(self, flask_blueprints: RepoViewProto) -> None:
        text = repr(flask_blueprints.blueprints)
        assert text.startswith("BlueprintCollection(3)")
        assert len(text) < 400

    def test_deterministic_order(self, flask_blueprints: RepoViewProto) -> None:
        first = [bp.name for bp in flask_blueprints.blueprints]
        second = [bp.name for bp in flask_blueprints.blueprints]
        assert first == second


class TestRouteBlueprintBacklink:
    """``Route.blueprint`` links a route back to its owning group."""

    def test_route_resolves_to_blueprint(self, flask_blueprints: RepoViewProto) -> None:
        route = next(r for r in flask_blueprints.routes if r.endpoint.endswith("admin_dashboard"))
        assert route.blueprint is not None
        assert route.blueprint.name == "admin"
        assert route.blueprint.url_prefix == "/admin"

    def test_backlink_round_trips(self, flask_blueprints: RepoViewProto) -> None:
        route = next(r for r in flask_blueprints.routes if r.endpoint.endswith("admin_users"))
        assert route.blueprint is not None
        sibling_endpoints = {r.endpoint for r in route.blueprint.routes}
        assert route.endpoint in sibling_endpoints

    def test_blueprint_repr(self, flask_blueprints: RepoViewProto) -> None:
        admin = flask_blueprints.blueprints.named("admin").one()
        assert repr(admin) == "Blueprint(admin, /admin, 2 routes)"

    def test_top_level_route_has_no_blueprint(self, flask_basic: RepoViewProto) -> None:
        # flask_basic declares routes directly on the app (no blueprints).
        assert all(bp is None for bp in (r.blueprint for r in flask_basic.routes))
        assert len(flask_basic.blueprints) == 0


class TestFactoryPatternBlueprintDiscovery:
    """FLAW-164: blueprints constructed *inside* a factory function.

    The ``flask_factory_blueprint`` fixture mirrors a factory
    ``load_blueprints(app)`` pattern: the ``Blueprint`` is a
    function-local (constructed inside the factory, not at module level),
    routes are registered with ``add_url_rule`` / a ``register_view`` wrapper,
    and the URL prefix is supplied at ``register_blueprint`` time.

    Before this fix, ``_extract_router_group_info`` scanned only module-level
    constructor assignments, so factory-pattern blueprints were invisible and
    ``repo.blueprints`` was empty on real apps (e.g. 0 of 4 blueprints found).

    Route -> blueprint *attribution* for this pattern is covered separately by
    ``TestFactoryPatternBlueprintAttribution`` (FLAW-166); this class asserts
    only the discovery win.
    """

    def test_factory_blueprint_is_discovered(self, flask_factory_blueprint: RepoViewProto) -> None:
        names = {bp.name for bp in flask_factory_blueprint.blueprints}
        assert "auth" in names

    def test_factory_blueprints_collection_non_empty(
        self, flask_factory_blueprint: RepoViewProto
    ) -> None:
        # Regression guard: was empty (0 blueprints) before the in-function
        # constructor scan landed.
        assert len(flask_factory_blueprint.blueprints) >= 1


class TestFactoryPatternBlueprintAttribution:
    """FLAW-166: factory-registered routes attribute to their blueprint group.

    Extends FLAW-164 discovery. In ``flask_factory_blueprint`` the
    function-local ``auth`` blueprint registers routes two ways, both of which
    must attribute to the ``auth`` group (real apps saw 0/75 attributed):

    1. direct ``auth.add_url_rule(View.as_view(...))`` (class-view receiver),
    2. the ``register_view(auth, routes=[...], view_func=...)`` wrapper, where
       the blueprint is the first positional argument at the call site.

    Attribution resolves the registration receiver / blueprint argument to the
    discovered router-group ``variable_fqn``; it does not depend on the URL
    prefix (which here is supplied to a function-parameter app and stays
    unresolved -- a separate mount-resolution concern).
    """

    def test_direct_class_view_route_attributes_to_blueprint(
        self, flask_factory_blueprint: RepoViewProto
    ) -> None:
        login_routes = [r for r in flask_factory_blueprint.routes if r.endpoint == "login"]
        assert login_routes
        assert all(r.group == "auth" for r in login_routes)
        assert all(r.blueprint is not None and r.blueprint.name == "auth" for r in login_routes)

    def test_wrapper_registered_route_attributes_to_blueprint(
        self, flask_factory_blueprint: RepoViewProto
    ) -> None:
        profile_routes = [r for r in flask_factory_blueprint.routes if r.endpoint == "profile"]
        assert profile_routes
        assert all(r.group == "auth" for r in profile_routes)

    def test_blueprint_routes_collection_complete(
        self, flask_factory_blueprint: RepoViewProto
    ) -> None:
        auth = flask_factory_blueprint.blueprints.named("auth").one()
        assert {r.endpoint for r in auth.routes} == {"login", "logout", "profile"}


class TestCallRouteGroupAttribution:
    """FLAW-166: plain-function ``bp.add_url_rule`` call routes carry group.

    The ``flask_call_route_group`` fixture registers a plain-function route
    ``bp.add_url_rule("/items", "list_items", list_items)`` on a module-level
    ``shop`` blueprint with ``url_prefix="/shop"``. Before this fix the
    ``_convert_call_route`` path hard-coded ``group=None`` and dropped the
    blueprint prefix, so plain call routes never attributed to their group.
    """

    def test_call_route_attributes_to_blueprint(
        self, flask_call_route_group: RepoViewProto
    ) -> None:
        items = next(r for r in flask_call_route_group.routes if r.endpoint == "list_items")
        assert items.group == "shop"
        assert items.blueprint is not None and items.blueprint.name == "shop"

    def test_call_route_inherits_group_prefix(self, flask_call_route_group: RepoViewProto) -> None:
        items = next(r for r in flask_call_route_group.routes if r.endpoint == "list_items")
        assert items.url_rule == "/shop/items"


class TestFactoryLocalBlueprintDetection:
    """FLAW-169: plain-function call routes on a *function-local* blueprint.

    The ``flask_factory_local_blueprint`` fixture constructs ``bp`` inside the
    ``create_app`` factory, then registers ``bp.add_url_rule("/items",
    "list_items", list_items)``. L1 resolves the receiver as the unresolvable
    ``create_app.<locals>.bp.add_url_rule`` and type enrichment reports the
    local ``bp`` as ``Unknown`` -- so before this fix the route was not detected
    *at all*. The receiver-type resolution now falls back to the local
    constructor assignment (``bp = Blueprint(...)``), making detection
    independent of whether the blueprint is bound at module or function scope.
    """

    def test_local_blueprint_route_is_detected(
        self, flask_factory_local_blueprint: RepoViewProto
    ) -> None:
        endpoints = {r.endpoint for r in flask_factory_local_blueprint.routes}
        assert "list_items" in endpoints

    def test_local_blueprint_route_attributes_to_group(
        self, flask_factory_local_blueprint: RepoViewProto
    ) -> None:
        items = next(r for r in flask_factory_local_blueprint.routes if r.endpoint == "list_items")
        assert items.group == "shop"
        assert items.blueprint is not None and items.blueprint.name == "shop"

    def test_local_blueprint_route_inherits_group_prefix(
        self, flask_factory_local_blueprint: RepoViewProto
    ) -> None:
        items = next(r for r in flask_factory_local_blueprint.routes if r.endpoint == "list_items")
        assert items.url_rule == "/shop/items"
