"""EP-1: Route resolution tests.

Tests that the Semantic API correctly detects route registrations
declared by providers.

Pattern types under test:
  - RouteDecorator (@app.route, @app.get, etc.)
  - RouteCallPattern (app.add_url_rule)
  - ClassViewPattern (MethodView subclasses)
  - RouterGroupPattern / RouterGroupMountPattern (blueprint groups)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed.inputs import Json
from flawed.route import HttpMethod

if TYPE_CHECKING:
    from flawed.repo import RepoView
    from flawed.route import Route


def _by_endpoint(repo: RepoView) -> dict[str, Route]:
    """Index routes by endpoint name for targeted assertions."""
    return {r.endpoint: r for r in repo.routes}


def _route_for_method(repo: RepoView, endpoint: str, method: HttpMethod) -> Route:
    """Return the single route for an endpoint/method pair."""
    matches = [r for r in repo.routes if r.endpoint == endpoint and method in r.methods]
    assert len(matches) == 1, (
        f"expected one {method.value} route for {endpoint!r}; "
        f"got {[(r.endpoint, r.methods, r.handler.fqn) for r in matches]}"
    )
    return matches[0]


# =====================================================================
# RouteDecorator — @app.route("/path")
# =====================================================================


class TestRouteDecorator:
    """Test detection of decorator-based route registration.

    Provider declaration:
        RouteDecorator(
            fqn="flask.Flask.route",
            rule_arg=0,
            methods_kwarg="methods",
            default_methods=("GET",),
        )
    """

    def test_l0_basic_route(self, flask_basic: RepoView) -> None:
        """@app.route("/") -> route with path="/", methods=["GET"]."""
        routes = _by_endpoint(flask_basic)
        assert "index" in routes
        assert routes["index"].url_rule == "/"
        assert routes["index"].methods == frozenset({HttpMethod.GET})

    def test_l0_multi_method_route(self, flask_basic: RepoView) -> None:
        """@app.route("/users", methods=["GET", "POST"]) -> both methods."""
        routes = _by_endpoint(flask_basic)
        assert "users" in routes
        assert routes["users"].url_rule == "/users"
        assert routes["users"].methods == frozenset({HttpMethod.GET, HttpMethod.POST})

    def test_l0_shorthand_get(self, flask_basic: RepoView) -> None:
        """@app.get("/items") -> implied_method="GET"."""
        routes = _by_endpoint(flask_basic)
        assert "items_get" in routes
        assert routes["items_get"].url_rule == "/items"
        assert routes["items_get"].methods == frozenset({HttpMethod.GET})

    def test_l0_shorthand_post(self, flask_basic: RepoView) -> None:
        """@app.post("/items") -> implied_method="POST"."""
        routes = _by_endpoint(flask_basic)
        assert "items_post" in routes
        assert routes["items_post"].url_rule == "/items"
        assert routes["items_post"].methods == frozenset({HttpMethod.POST})

    def test_l0_route_with_path_param(self, flask_basic: RepoView) -> None:
        """@app.route("/inputs/path/<int:item_id>") -> path param captured."""
        routes = _by_endpoint(flask_basic)
        assert "input_path" in routes
        assert routes["input_path"].url_rule == "/inputs/path/<int:item_id>"
        assert routes["input_path"].methods == frozenset({HttpMethod.GET})

    def test_l0_total_route_count(self, flask_basic: RepoView) -> None:
        """Flask basic fixture should have a known number of routes."""
        # flask_basic has 41 decorator routes across app.py, auth.py, models.py
        assert len(flask_basic.routes) >= 34

    def test_l1_aliased_app_route(self, flask_aliased: RepoView) -> None:
        """my_app = WebApp(__name__); @my_app.route("/") -> detected."""
        routes = _by_endpoint(flask_aliased)
        assert "index" in routes
        assert routes["index"].url_rule == "/"
        assert routes["index"].methods == frozenset({HttpMethod.GET})
        assert routes["index"].handler.fqn == "flask_aliased.app.index"

    def test_l1_aliased_shorthand(self, flask_aliased: RepoView) -> None:
        """@my_app.get("/items") -- aliased app, shorthand."""
        routes = _by_endpoint(flask_aliased)
        assert "items_get" in routes
        assert routes["items_get"].url_rule == "/items"
        assert routes["items_get"].methods == frozenset({HttpMethod.GET})


# =====================================================================
# RouteCallPattern — app.add_url_rule("/path", view_func=fn)
# =====================================================================


class TestRouteCallPattern:
    """Test detection of imperative route registration.

    Provider declaration:
        RouteCallPattern(
            fqn="flask.Flask.add_url_rule",
            rule_arg=0,
            view_func_kwarg="view_func",
        )
    """

    def test_l0_add_url_rule_view_func_kwarg(self, flask_add_url_rule: RepoView) -> None:
        """app.add_url_rule("/health", view_func=health) -> GET route."""
        routes = _by_endpoint(flask_add_url_rule)
        assert "health" in routes
        assert routes["health"].url_rule == "/health"
        assert routes["health"].methods == frozenset({HttpMethod.GET})
        assert routes["health"].handler.fqn == "flask_add_url_rule.app.health"

    def test_l0_add_url_rule_positional_endpoint(self, flask_add_url_rule: RepoView) -> None:
        """app.add_url_rule("/users", "endpoint", fn, methods=["POST"])."""
        routes = _by_endpoint(flask_add_url_rule)
        assert "create_user_endpoint" in routes
        assert routes["create_user_endpoint"].url_rule == "/users"
        assert routes["create_user_endpoint"].methods == frozenset({HttpMethod.POST})
        assert routes["create_user_endpoint"].handler.fqn == "flask_add_url_rule.app.create_user"

    def test_l0_add_url_rule_endpoint_kwarg(self, flask_add_url_rule: RepoView) -> None:
        """app.add_url_rule(..., endpoint="user_detail", methods=("GET", "DELETE"))."""
        routes = _by_endpoint(flask_add_url_rule)
        assert "user_detail" in routes
        assert routes["user_detail"].url_rule == "/users/<int:user_id>"
        assert routes["user_detail"].methods == frozenset({HttpMethod.GET, HttpMethod.DELETE})
        assert routes["user_detail"].handler.fqn == "flask_add_url_rule.app.user_detail"


# =====================================================================
# ClassViewPattern — MethodView subclasses
# =====================================================================


class TestClassViewPattern:
    """Test detection of class-based view dispatch.

    Provider declaration:
        ClassViewPattern(
            base_class_fqn="flask.views.MethodView",
            method_map={"get": "GET", "post": "POST", ...},
        )
    """

    def test_l5_method_view_collection_route(self, flask_subclassed: RepoView) -> None:
        """ItemAPI.as_view("items") -> GET route scoped to get()."""
        items = _route_for_method(flask_subclassed, "items", HttpMethod.GET)
        assert items.url_rule == "/api/items"
        assert items.methods == frozenset({HttpMethod.GET})
        assert items.handler.fqn == "flask_subclassed.views.ItemAPI.get"

    def test_l5_method_view_collection_post_method(self, flask_subclassed: RepoView) -> None:
        """POST collection route is scoped to post(), not get()."""
        items = _route_for_method(flask_subclassed, "items", HttpMethod.POST)
        assert items.methods == frozenset({HttpMethod.POST})
        assert items.handler.fqn == "flask_subclassed.views.ItemAPI.post"
        assert list(items.reachable.reads(Json()))

    def test_l5_method_view_body_scopes_are_split_by_method(
        self,
        flask_subclassed: RepoView,
    ) -> None:
        """GET and POST routes expose only their method-specific handler bodies."""
        get_items = _route_for_method(flask_subclassed, "items", HttpMethod.GET)
        post_items = _route_for_method(flask_subclassed, "items", HttpMethod.POST)

        assert get_items.url_rule == post_items.url_rule == "/api/items"
        assert get_items.endpoint == post_items.endpoint == "items"
        assert get_items.handler.fqn.endswith(".get")
        assert post_items.handler.fqn.endswith(".post")
        assert list(get_items.body.reads(Json())) == []
        assert list(post_items.body.reads(Json()))

    def test_l5_method_view_detail_route(self, flask_subclassed: RepoView) -> None:
        """ItemAPI.as_view("item_detail") -> GET route scoped to get()."""
        detail = _route_for_method(flask_subclassed, "item_detail", HttpMethod.GET)
        assert detail.url_rule == "/api/items/<int:item_id>"
        assert detail.methods == frozenset({HttpMethod.GET})
        assert detail.handler.fqn == "flask_subclassed.views.ItemAPI.get"

    def test_l5_method_view_detail_delete_method(self, flask_subclassed: RepoView) -> None:
        """DELETE detail route is scoped to delete(), not get()."""
        detail = _route_for_method(flask_subclassed, "item_detail", HttpMethod.DELETE)
        assert detail.methods == frozenset({HttpMethod.DELETE})
        assert detail.handler.fqn == "flask_subclassed.views.ItemAPI.delete"
        assert list(detail.body.reads(Json())) == []
        assert list(detail.reachable.reads(Json())) == []

    def test_l5_method_view_registration_level_routes(self, flask_subclassed: RepoView) -> None:
        """Class-view registrations produce one route per registered method."""
        class_view_routes = [
            r
            for r in flask_subclassed.routes
            if r.handler.fqn.startswith("flask_subclassed.views.ItemAPI.")
        ]
        assert {r.endpoint for r in class_view_routes} == {"items", "item_detail"}
        assert len(class_view_routes) == 5


# =====================================================================
# ClassViewPattern — factory-registered MethodViews (factory pattern)
# =====================================================================


class TestClassViewFactoryPattern:
    """MethodView registered inside a factory function (factory pattern).

    Covers two patterns:
    1. Direct ``add_url_rule`` inside a factory function.
    2. A ``register_view()`` wrapper that receives URLs in a list arg
       (``routes=["/path"]``) — a list-arg registration idiom.
    """

    def test_factory_registered_login_route(self, flask_class_view_factory: RepoView) -> None:
        """LoginView.as_view("login") inside register_auth_views() -> GET/POST routes."""
        login = _route_for_method(flask_class_view_factory, "login", HttpMethod.GET)
        assert login.url_rule == "/login"
        assert login.methods == frozenset({HttpMethod.GET})
        assert _route_for_method(
            flask_class_view_factory,
            "login",
            HttpMethod.POST,
        ).handler.fqn.endswith(".post")

    def test_factory_registered_logout_route(self, flask_class_view_factory: RepoView) -> None:
        """LogoutView.as_view("logout") inside register_auth_views() -> route."""
        logout = _route_for_method(flask_class_view_factory, "logout", HttpMethod.POST)
        assert logout.url_rule == "/logout"
        assert logout.methods == frozenset({HttpMethod.POST})

    def test_wrapper_registered_profile_route(self, flask_class_view_factory: RepoView) -> None:
        """ProfileView via register_view(routes=["/profile"]) -> route.

        The URL is inside a list arg, not a bare string — this is the
        pattern that blocked 69 MethodView routes on a real app.
        """
        profile = _route_for_method(flask_class_view_factory, "profile", HttpMethod.GET)
        assert profile.url_rule == "/profile"

    def test_factory_class_view_route_count(self, flask_class_view_factory: RepoView) -> None:
        """Factory pattern produces one route per registered class-view method."""
        class_view_routes = [
            r
            for r in flask_class_view_factory.routes
            if r.handler.fqn.startswith("flask_class_view_factory.views.")
        ]
        assert len(class_view_routes) == 4
        assert {r.endpoint for r in class_view_routes} == {
            "login",
            "logout",
            "profile",
        }


# =====================================================================
# RouterGroupPattern — blueprint route groups
# =====================================================================


class TestRouterGroupPattern:
    """Test detection of grouped routes and mount prefixes.

    Provider declarations:
        RouterGroupPattern(
            constructor_fqn="flask.Blueprint",
            name_arg=0,
            url_prefix_kwarg="url_prefix",
        )
        RouterGroupMountPattern(
            mount_method="register_blueprint",
            url_prefix_kwarg="url_prefix",
        )
    """

    def test_l0_blueprint_constructor_group_and_prefix(self, flask_blueprints: RepoView) -> None:
        """Blueprint("admin", ..., url_prefix="/admin") prefixes routes."""
        routes = _by_endpoint(flask_blueprints)
        assert "admin_dashboard" in routes
        assert routes["admin_dashboard"].group == "admin"
        assert routes["admin_dashboard"].url_rule == "/admin/dashboard"

    def test_l0_blueprint_multi_method_route(self, flask_blueprints: RepoView) -> None:
        """Blueprint route methods are preserved after prefix enrichment."""
        routes = _by_endpoint(flask_blueprints)
        assert "admin_users" in routes
        assert routes["admin_users"].group == "admin"
        assert routes["admin_users"].url_rule == "/admin/users"
        assert routes["admin_users"].methods == frozenset({HttpMethod.GET, HttpMethod.POST})

    def test_l0_blueprint_registration_prefix(self, flask_blueprints: RepoView) -> None:
        """register_blueprint(..., url_prefix="/api/v1") supplies mount prefix."""
        routes = _by_endpoint(flask_blueprints)
        assert "api_items" in routes
        assert routes["api_items"].group == "api"
        assert routes["api_items"].url_rule == "/api/v1/items"

    def test_l0_blueprint_parameterized_detail_route(self, flask_blueprints: RepoView) -> None:
        """Parameterized blueprint routes keep params, group, and methods."""
        routes = _by_endpoint(flask_blueprints)
        assert "api_item_detail" in routes
        assert routes["api_item_detail"].group == "api"
        assert routes["api_item_detail"].url_rule == "/api/v1/items/<int:item_id>"
        assert routes["api_item_detail"].methods == frozenset({HttpMethod.GET, HttpMethod.DELETE})

    def test_l0_blueprint_without_prefix(self, flask_blueprints: RepoView) -> None:
        """Blueprint without constructor or mount prefix keeps original rule."""
        routes = _by_endpoint(flask_blueprints)
        assert "about" in routes
        assert routes["about"].group == "public"
        assert routes["about"].url_rule == "/about"

    def test_l1_package_init_blueprint_receiver(
        self,
        flask_package_blueprint: RepoView,
    ) -> None:
        """from . import bp; @bp.route resolves package-level Blueprint constructor."""
        routes = _by_endpoint(flask_package_blueprint)
        assert "package_items" in routes
        assert routes["package_items"].group == "package"
        assert routes["package_items"].url_rule == "/pkg/items"
        assert routes["package_items"].methods == frozenset({HttpMethod.GET, HttpMethod.POST})

    def test_l1_package_relative_blueprint_lifecycle_receiver(
        self,
        flask_package_blueprint: RepoView,
    ) -> None:
        """from .. import bp; @bp.before_request attaches to package Blueprint routes."""
        route = _by_endpoint(flask_package_blueprint)["package_items"]

        lifecycle_writes = tuple(route.full_stack.effects())

        assert any(
            effect.function.fqn.endswith("package_auth_middleware") for effect in lifecycle_writes
        )
