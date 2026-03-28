"""Flask route-resolution vertical-slice tests.

These tests exercise the L2 provider engine through ``WebApp.from_index``
against real L1 fixture indexes.  They intentionally cover Flask instance
receiver aliases (``app = Flask(...)`` / ``my_app = WebApp(...)``), because
the Code Index records those decorators structurally as application-instance
method calls rather than provider class method FQNs.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from flawed._index import CodeIndex
from flawed._index._types import (
    CallArgument,
    CallEdge,
    ClassRecord,
    DecoratorFact,
    EdgeSource,
    ExtractionProvenance,
    FlowKind,
    FunctionRecord,
    ImportFact,
    ResolutionStatus,
    SourceSpan,
    SymbolRef,
    ValueFlowEdge,
)
from flawed._index._types import FunctionKind as L1FunctionKind
from flawed._index._types import Parameter as L1Parameter
from flawed._index._types import ParameterKind as L1ParameterKind
from flawed._semantic import WebApp
from flawed.core import GapKind
from flawed.route import HttpMethod

if TYPE_CHECKING:
    from flawed.repo import RepoView
    from flawed.route import Route

_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="")
_ROOT = Path("/tmp/test-repo")


def _routes_by_endpoint(repo: RepoView) -> dict[str, Route]:
    return {route.endpoint: route for route in repo.routes}


def _route_for_method(routes: tuple[Any, ...], endpoint: str, method: HttpMethod) -> Any:
    matches = [route for route in routes if route.endpoint == endpoint and method in route.methods]
    assert len(matches) == 1, (
        f"expected one {method.value} route for {endpoint!r}; "
        f"got {[(r.endpoint, r.methods, r.handler.fqn) for r in matches]}"
    )
    return matches[0]


class TestFlaskFixtureRouteResolution:
    """Real Flask semantic fixtures produce public Route objects."""

    def test_flask_basic_decorator_routes_resolve_from_app_instance(
        self, flask_basic: RepoView
    ) -> None:
        routes = _routes_by_endpoint(flask_basic)

        assert routes["index"].url_rule == "/"
        assert routes["index"].methods == frozenset({HttpMethod.GET})
        assert routes["index"].handler.fqn == "flask_basic.app.index"

    def test_flask_basic_preserves_multi_method_and_shorthand_routes(
        self, flask_basic: RepoView
    ) -> None:
        routes = _routes_by_endpoint(flask_basic)

        assert routes["users"].url_rule == "/users"
        assert routes["users"].methods == frozenset({HttpMethod.GET, HttpMethod.POST})
        assert routes["items_get"].methods == frozenset({HttpMethod.GET})
        assert routes["items_post"].methods == frozenset({HttpMethod.POST})

    def test_flask_aliased_routes_resolve_from_constructor_alias(
        self, flask_aliased: RepoView
    ) -> None:
        routes = _routes_by_endpoint(flask_aliased)

        assert routes["index"].url_rule == "/"
        assert routes["users"].methods == frozenset({HttpMethod.GET, HttpMethod.POST})
        assert routes["items_get"].url_rule == "/items"
        assert routes["items_get"].methods == frozenset({HttpMethod.GET})


class TestAddUrlRuleFixtureRouteResolution:
    """Plain function add_url_rule registrations produce routes."""

    def test_add_url_rule_view_func_kwarg_route(self, flask_add_url_rule: RepoView) -> None:
        routes = _routes_by_endpoint(flask_add_url_rule)

        assert routes["health"].url_rule == "/health"
        assert routes["health"].methods == frozenset({HttpMethod.GET})
        assert routes["health"].handler.fqn == "flask_add_url_rule.app.health"

    def test_add_url_rule_positional_endpoint_and_handler_route(
        self, flask_add_url_rule: RepoView
    ) -> None:
        routes = _routes_by_endpoint(flask_add_url_rule)

        assert routes["create_user_endpoint"].url_rule == "/users"
        assert routes["create_user_endpoint"].methods == frozenset({HttpMethod.POST})
        assert routes["create_user_endpoint"].handler.fqn == "flask_add_url_rule.app.create_user"

    def test_add_url_rule_endpoint_kwarg_and_tuple_methods_route(
        self, flask_add_url_rule: RepoView
    ) -> None:
        routes = _routes_by_endpoint(flask_add_url_rule)

        assert routes["user_detail"].url_rule == "/users/<int:user_id>"
        assert routes["user_detail"].methods == frozenset({HttpMethod.GET, HttpMethod.DELETE})
        assert routes["user_detail"].handler.fqn == "flask_add_url_rule.app.user_detail"


class TestRouteMerge:
    """Duplicate decorator registrations merge before reaching RepoView."""

    def test_duplicate_route_registrations_union_methods_deterministically(self) -> None:
        handler = _function("app.handler")
        idx = _make_index(
            functions=(handler,),
            decorators=(
                _decorator(
                    "app.route",
                    target_fqn="app.handler",
                    args=('"/same"',),
                    kwargs=(("methods", '["POST"]'),),
                    line=20,
                ),
                _decorator(
                    "app.route",
                    target_fqn="app.handler",
                    args=('"/same"',),
                    kwargs=(("methods", '["GET"]'),),
                    line=10,
                ),
            ),
            symbols=(
                _symbol("Flask", "flask.Flask", line=1),
                _symbol("app.route", "app.app.route", line=10),
                _symbol("app.route", "app.app.route", line=20),
            ),
            value_flow_edges=(
                _module_assignment(
                    source_expr="Flask(__name__)",
                    target_expr="app",
                    line=1,
                ),
            ),
        )

        routes = tuple(WebApp.from_index(idx).repo_view().routes)

        assert len(routes) == 1
        assert routes[0].url_rule == "/same"
        assert routes[0].methods == frozenset({HttpMethod.GET, HttpMethod.POST})
        assert routes[0].location.line == 10

    def test_dynamic_method_gap_is_attached_to_merged_route(self) -> None:
        handler = _function("app.handler")
        idx = _make_index(
            functions=(handler,),
            decorators=(
                _decorator(
                    "app.route",
                    target_fqn="app.handler",
                    args=('"/same"',),
                    kwargs=(("methods", "allowed_methods"),),
                    line=10,
                ),
                _decorator(
                    "app.route",
                    target_fqn="app.handler",
                    args=('"/same"',),
                    kwargs=(("methods", '["POST"]'),),
                    line=20,
                ),
            ),
            symbols=(
                _symbol("Flask", "flask.Flask", line=1),
                _symbol("app.route", "app.app.route", line=10),
                _symbol("app.route", "app.app.route", line=20),
            ),
            value_flow_edges=(
                _module_assignment(
                    source_expr="Flask(__name__)",
                    target_expr="app",
                    line=1,
                ),
            ),
        )

        route = WebApp.from_index(idx).repo_view().routes.one()

        assert route.methods == frozenset({HttpMethod.GET, HttpMethod.POST})
        assert [gap.kind for gap in route.gaps] == [GapKind.INFERENCE_FAILURE]


def _span(line: int, *, file: str = "app.py") -> SourceSpan:
    return SourceSpan(file=file, line=line, column=0, end_line=line, end_column=10)


def _function(fqn: str) -> FunctionRecord:
    return FunctionRecord(
        fqn=fqn,
        name=fqn.rsplit(".", 1)[-1],
        file="app.py",
        line=30,
        params=(
            L1Parameter(
                name="request",
                annotation=None,
                default=None,
                kind=L1ParameterKind.POSITIONAL_OR_KEYWORD,
                position=0,
                location=_span(30),
            ),
        ),
        decorator_names=(),
        decorator_fqns=(),
        kind=L1FunctionKind.TOP_LEVEL,
        is_method=False,
        is_nested=False,
        is_async=False,
        parent_class=None,
        location=_span(30),
        provenance=_PROV,
    )


def _decorator(
    fqn: str,
    *,
    target_fqn: str,
    args: tuple[str, ...],
    kwargs: tuple[tuple[str, str], ...],
    line: int,
) -> DecoratorFact:
    return DecoratorFact(
        name=fqn,
        fqn=fqn,
        args=args,
        kwargs=kwargs,
        target_fqn=target_fqn,
        application_order=0,
        location=_span(line),
        provenance=_PROV,
    )


def _symbol(name: str, fqn: str, *, line: int) -> SymbolRef:
    return SymbolRef(
        name=name,
        fqn=fqn,
        resolution=ResolutionStatus.RESOLVED,
        location=_span(line),
        provenance=_PROV,
    )


def _module_assignment(
    *,
    source_expr: str,
    target_expr: str,
    line: int,
) -> ValueFlowEdge:
    return ValueFlowEdge(
        source_expr=source_expr,
        source_location=_span(line),
        target_expr=target_expr,
        target_location=_span(line),
        kind=FlowKind.ASSIGN,
        containing_function_fqn=None,
        provenance=_PROV,
    )


def _call_edge(
    *,
    caller_fqn: str,
    callee_fqn: str,
    arguments: tuple[CallArgument, ...] = (),
    line: int,
) -> CallEdge:
    return CallEdge(
        caller_fqn=caller_fqn,
        callee_fqn=callee_fqn,
        arguments=arguments,
        resolution=ResolutionStatus.RESOLVED,
        source=EdgeSource.AST,
        unresolved_reason=None,
        location=_span(line),
        provenance=_PROV,
    )


def _call_arg(
    *,
    position: int | None = None,
    keyword: str | None = None,
    expression: str,
    line: int = 1,
) -> CallArgument:
    return CallArgument(
        position=position,
        keyword=keyword,
        expression=expression,
        location=_span(line),
    )


def _make_index(
    *,
    functions: tuple[FunctionRecord, ...],
    decorators: tuple[DecoratorFact, ...],
    symbols: tuple[SymbolRef, ...],
    value_flow_edges: tuple[ValueFlowEdge, ...],
    call_edges: tuple[CallEdge, ...] = (),
    classes: tuple[ClassRecord, ...] = (),
    imports: tuple[ImportFact, ...] | None = None,
) -> CodeIndex:
    if imports is None:
        imports = (
            ImportFact(
                module="flask",
                names=("Flask",),
                aliases=(),
                is_from_import=True,
                location=_span(1),
                provenance=_PROV,
            ),
        )
    return CodeIndex(
        repo_root=_ROOT,
        functions=functions,
        classes=classes,
        decorators=decorators,
        imports=imports,
        attributes=(),
        call_edges=call_edges,
        cfgs={},
        value_flow_edges=value_flow_edges,
        symbol_refs=symbols,
        errors=(),
        provenance=_PROV,
    )


# =====================================================================
# Helpers for blueprint test indexes
# =====================================================================


def _flask_blueprint_imports() -> tuple[ImportFact, ...]:
    return (
        ImportFact(
            module="flask",
            names=("Flask", "Blueprint"),
            aliases=(),
            is_from_import=True,
            location=_span(1),
            provenance=_PROV,
        ),
    )


def _blueprint_index(
    *,
    handler_fqn: str = "app.dashboard",
    bp_name: str = '"admin"',
    bp_url_prefix_kwarg: str | None = '"/admin"',
    register_url_prefix: str | None = None,
    decorator_fqn: str = "bp.route",
    decorator_symbol_fqn: str = "app.bp.route",
    route_rule: str = '"/dashboard"',
    route_methods: tuple[tuple[str, str], ...] | None = None,
) -> CodeIndex:
    """Build a synthetic index representing a blueprint route pattern."""
    bp_constructor_args: list[str] = [bp_name, "__name__"]
    bp_kwargs = ""
    if bp_url_prefix_kwarg is not None:
        bp_kwargs = f", url_prefix={bp_url_prefix_kwarg}"
    bp_constructor_expr = f"Blueprint({', '.join(bp_constructor_args)}{bp_kwargs})"

    handler = _function(handler_fqn)
    kwargs = route_methods if route_methods is not None else ()

    call_edges: list[CallEdge] = []
    if register_url_prefix is not None:
        call_edges.append(
            _call_edge(
                caller_fqn="app",
                callee_fqn="app.app.register_blueprint",
                arguments=(
                    _call_arg(position=0, expression="bp", line=50),
                    _call_arg(
                        keyword="url_prefix",
                        expression=register_url_prefix,
                        line=50,
                    ),
                ),
                line=50,
            )
        )

    return _make_index(
        functions=(handler,),
        decorators=(
            _decorator(
                decorator_fqn,
                target_fqn=handler_fqn,
                args=(route_rule,),
                kwargs=kwargs,
                line=10,
            ),
        ),
        symbols=(
            _symbol("Blueprint", "flask.Blueprint", line=1),
            _symbol("Flask", "flask.Flask", line=1),
            _symbol(decorator_fqn, decorator_symbol_fqn, line=10),
        ),
        value_flow_edges=(
            _module_assignment(
                source_expr="Flask(__name__)",
                target_expr="app",
                line=2,
            ),
            _module_assignment(
                source_expr=bp_constructor_expr,
                target_expr="bp",
                line=3,
            ),
        ),
        call_edges=tuple(call_edges),
        imports=_flask_blueprint_imports(),
    )


class TestBlueprintRouteResolution:
    """Blueprint routes get group names and URL prefix prepending."""

    def test_blueprint_route_gets_group_from_constructor_name(self) -> None:
        """bp = Blueprint("admin", ...) → routes get group="admin"."""
        idx = _blueprint_index(bp_name='"admin"', bp_url_prefix_kwarg=None)
        routes = tuple(WebApp.from_index(idx).repo_view().routes)

        assert len(routes) == 1
        assert routes[0].group == "admin"

    def test_blueprint_constructor_prefix_prepended_to_url_rule(self) -> None:
        """Blueprint(..., url_prefix="/admin") → "/admin" + "/dashboard"."""
        idx = _blueprint_index(
            bp_name='"admin"',
            bp_url_prefix_kwarg='"/admin"',
        )
        routes = tuple(WebApp.from_index(idx).repo_view().routes)

        assert len(routes) == 1
        assert routes[0].url_rule == "/admin/dashboard"
        assert routes[0].group == "admin"

    def test_registration_prefix_overrides_constructor_prefix(self) -> None:
        """register_blueprint(bp, url_prefix="/api/v1") overrides constructor."""
        idx = _blueprint_index(
            bp_name='"api"',
            bp_url_prefix_kwarg='"/old"',
            register_url_prefix='"/api/v1"',
        )
        routes = tuple(WebApp.from_index(idx).repo_view().routes)

        assert len(routes) == 1
        assert routes[0].url_rule == "/api/v1/dashboard"
        assert routes[0].group == "api"

    def test_registration_prefix_applied_when_constructor_has_none(self) -> None:
        """Blueprint without url_prefix + register_blueprint(url_prefix=...)."""
        idx = _blueprint_index(
            bp_name='"api"',
            bp_url_prefix_kwarg=None,
            register_url_prefix='"/api/v1"',
        )
        routes = tuple(WebApp.from_index(idx).repo_view().routes)

        assert len(routes) == 1
        assert routes[0].url_rule == "/api/v1/dashboard"
        assert routes[0].group == "api"

    def test_blueprint_no_prefix_preserves_original_url_rule(self) -> None:
        """Blueprint with no prefix at all → url_rule unchanged."""
        idx = _blueprint_index(
            bp_name='"public"',
            bp_url_prefix_kwarg=None,
            register_url_prefix=None,
        )
        routes = tuple(WebApp.from_index(idx).repo_view().routes)

        assert len(routes) == 1
        assert routes[0].url_rule == "/dashboard"
        assert routes[0].group == "public"

    def test_dynamic_blueprint_name_produces_gap(self) -> None:
        """bp = Blueprint(name_var, ...) → group=None, gap produced."""
        idx = _blueprint_index(
            bp_name="config.BP_NAME",
            bp_url_prefix_kwarg=None,
        )
        webapp = WebApp.from_index(idx)
        routes = tuple(webapp.repo_view().routes)

        assert len(routes) == 1
        assert routes[0].group is None
        assert any(
            gap.kind == GapKind.INFERENCE_FAILURE and "router group" in gap.message.lower()
            for gap in routes[0].gaps
        )

    def test_dynamic_blueprint_prefix_produces_gap(self) -> None:
        """Blueprint(url_prefix=variable) → no prefix applied, gap produced."""
        idx = _blueprint_index(
            bp_name='"admin"',
            bp_url_prefix_kwarg="config.PREFIX",
        )
        webapp = WebApp.from_index(idx)
        routes = tuple(webapp.repo_view().routes)

        assert len(routes) == 1
        assert routes[0].group == "admin"
        assert routes[0].url_rule == "/dashboard"
        assert any(
            gap.kind == GapKind.INFERENCE_FAILURE and "prefix" in gap.message.lower()
            for gap in routes[0].gaps
        )


class TestBlueprintFixtureRouteResolution:
    """Real Flask blueprint fixture produces correct Route objects."""

    def test_flask_blueprints_admin_routes_have_group_and_prefix(
        self, flask_blueprints: RepoView
    ) -> None:
        routes = _routes_by_endpoint(flask_blueprints)

        assert "admin_dashboard" in routes
        assert routes["admin_dashboard"].group == "admin"
        assert routes["admin_dashboard"].url_rule == "/admin/dashboard"

    def test_flask_blueprints_admin_multi_method_route(self, flask_blueprints: RepoView) -> None:
        routes = _routes_by_endpoint(flask_blueprints)

        assert "admin_users" in routes
        assert routes["admin_users"].group == "admin"
        assert routes["admin_users"].url_rule == "/admin/users"
        assert routes["admin_users"].methods == frozenset({HttpMethod.GET, HttpMethod.POST})

    def test_flask_blueprints_api_prefix_from_registration(
        self, flask_blueprints: RepoView
    ) -> None:
        routes = _routes_by_endpoint(flask_blueprints)

        assert "api_items" in routes
        assert routes["api_items"].group == "api"
        assert routes["api_items"].url_rule == "/api/v1/items"

    def test_flask_blueprints_public_no_prefix(self, flask_blueprints: RepoView) -> None:
        routes = _routes_by_endpoint(flask_blueprints)

        assert "about" in routes
        assert routes["about"].group == "public"
        assert routes["about"].url_rule == "/about"


# =====================================================================
# MethodView class-based view tests
# =====================================================================


def _method_function(fqn: str, *, line: int = 30, file: str = "views.py") -> FunctionRecord:
    """Create a method FunctionRecord (is_method=True)."""
    name = fqn.rsplit(".", 1)[-1]
    parent_class = fqn.rsplit(".", 1)[0]
    return FunctionRecord(
        fqn=fqn,
        name=name,
        file=file,
        line=line,
        params=(
            L1Parameter(
                name="self",
                annotation=None,
                default=None,
                kind=L1ParameterKind.POSITIONAL_OR_KEYWORD,
                position=0,
                location=_span(line, file=file),
            ),
        ),
        decorator_names=(),
        decorator_fqns=(),
        kind=L1FunctionKind.METHOD,
        is_method=True,
        is_nested=False,
        is_async=False,
        parent_class=parent_class,
        location=_span(line, file=file),
        provenance=_PROV,
    )


def _class_record(
    fqn: str,
    *,
    bases: tuple[str, ...],
    method_names: tuple[str, ...],
    line: int = 10,
    file: str = "views.py",
) -> ClassRecord:
    return ClassRecord(
        fqn=fqn,
        name=fqn.rsplit(".", 1)[-1],
        file=file,
        bases=bases,
        mro_chain=(fqn,),
        mro_complete=False,
        method_names=method_names,
        class_var_names=(),
        is_abstract=False,
        metaclass=None,
        subclasses=(),
        all_subclasses=(),
        inherited_methods=(),
        hierarchy_gaps=(),
        location=_span(line, file=file),
        provenance=_PROV,
    )


def _flask_views_imports() -> tuple[ImportFact, ...]:
    return (
        ImportFact(
            module="flask",
            names=("Flask",),
            aliases=(),
            is_from_import=True,
            location=_span(1),
            provenance=_PROV,
        ),
        ImportFact(
            module="flask.views",
            names=("MethodView",),
            aliases=(),
            is_from_import=True,
            location=_span(2, file="views.py"),
            provenance=_PROV,
        ),
    )


def _methodview_index(
    *,
    class_fqn: str = "views.ItemAPI",
    method_names: tuple[str, ...] = ("get", "post"),
    registrations: tuple[tuple[str, str, tuple[str, ...]], ...] = (
        ("/api/items", "items", ("GET", "POST")),
    ),
) -> CodeIndex:
    """Build a synthetic index for a MethodView subclass.

    Each registration tuple is (url_rule, endpoint_name, methods).
    """
    class_name = class_fqn.rsplit(".", 1)[-1]
    methods = tuple(
        _method_function(f"{class_fqn}.{m}", line=20 + i) for i, m in enumerate(method_names)
    )
    klass = _class_record(
        class_fqn,
        bases=("MethodView",),
        method_names=method_names,
    )

    # Build value-flow edges for module-level add_url_rule calls.
    # L1 records module-level calls as ARGUMENT value-flow edges.
    vf_edges: list[ValueFlowEdge] = [
        _module_assignment(source_expr="Flask(__name__)", target_expr="app", line=1),
    ]
    for i, (url_rule, endpoint, reg_methods) in enumerate(registrations):
        reg_line = 40 + i * 3
        as_view_expr = f'{class_name}.as_view("{endpoint}")'
        methods_expr = "[" + ", ".join(f'"{m}"' for m in reg_methods) + "]"
        # Module-level arguments appear as ARGUMENT flows targeting the callee.
        vf_edges.append(
            ValueFlowEdge(
                source_expr=f'"{url_rule}"',
                source_location=_span(reg_line),
                target_expr="app.add_url_rule",
                target_location=_span(reg_line),
                kind=FlowKind.ARGUMENT,
                containing_function_fqn=None,
                provenance=_PROV,
            )
        )
        vf_edges.append(
            ValueFlowEdge(
                source_expr=as_view_expr,
                source_location=_span(reg_line),
                target_expr="app.add_url_rule",
                target_location=_span(reg_line),
                kind=FlowKind.ARGUMENT,
                containing_function_fqn=None,
                provenance=_PROV,
            )
        )
        vf_edges.append(
            ValueFlowEdge(
                source_expr=methods_expr,
                source_location=_span(reg_line),
                target_expr="app.add_url_rule",
                target_location=_span(reg_line),
                kind=FlowKind.ARGUMENT,
                containing_function_fqn=None,
                provenance=_PROV,
            )
        )

    symbols = (
        _symbol("Flask", "flask.Flask", line=1),
        SymbolRef(
            name="MethodView",
            fqn="flask.views.MethodView",
            resolution=ResolutionStatus.RESOLVED,
            location=_span(2, file="views.py"),
            provenance=_PROV,
        ),
    )

    return _make_index(
        functions=methods,
        classes=(klass,),
        decorators=(),
        symbols=symbols,
        value_flow_edges=tuple(vf_edges),
        imports=_flask_views_imports(),
    )


def _class_view_registration_arg(source_expr: str, *, line: int) -> ValueFlowEdge:
    return ValueFlowEdge(
        source_expr=source_expr,
        source_location=_span(line),
        target_expr="app.add_url_rule",
        target_location=_span(line),
        kind=FlowKind.ARGUMENT,
        containing_function_fqn=None,
        provenance=_PROV,
    )


def _colliding_methodview_index(*, resolve_registration: bool) -> CodeIndex:
    """Build two MethodView classes with the same short name and one registration."""
    one = _class_record(
        "pkg.one.Search",
        bases=("flask.views.MethodView",),
        method_names=("get",),
        file="pkg/one.py",
    )
    two = _class_record(
        "pkg.two.Search",
        bases=("flask.views.MethodView",),
        method_names=("get",),
        file="pkg/two.py",
    )
    symbols: list[SymbolRef] = [_symbol("Flask", "flask.Flask", line=1)]
    if resolve_registration:
        symbols.append(_symbol("Search", "pkg.one.Search", line=4))

    return _make_index(
        functions=(
            _method_function("pkg.one.Search.get", line=20, file="pkg/one.py"),
            _method_function("pkg.two.Search.get", line=20, file="pkg/two.py"),
        ),
        classes=(one, two),
        decorators=(),
        symbols=tuple(symbols),
        value_flow_edges=(
            _module_assignment(source_expr="Flask(__name__)", target_expr="app", line=1),
            _class_view_registration_arg('"/search"', line=40),
            _class_view_registration_arg('Search.as_view("search")', line=40),
        ),
        imports=_flask_views_imports(),
    )


class TestMethodViewRouteResolution:
    """MethodView subclass routes resolve through ClassViewPattern."""

    def test_methodview_basic_get_post_routes(self) -> None:
        """ItemAPI with get/post methods registered at /api/items."""
        idx = _methodview_index(
            method_names=("get", "post"),
            registrations=(("/api/items", "items", ("GET", "POST")),),
        )
        routes = tuple(WebApp.from_index(idx).repo_view().routes)

        get_route = _route_for_method(routes, "items", HttpMethod.GET)
        post_route = _route_for_method(routes, "items", HttpMethod.POST)
        assert get_route.url_rule == "/api/items"
        assert get_route.methods == frozenset({HttpMethod.GET})
        assert get_route.handler.fqn == "views.ItemAPI.get"
        assert post_route.url_rule == "/api/items"
        assert post_route.methods == frozenset({HttpMethod.POST})
        assert post_route.handler.fqn == "views.ItemAPI.post"

    def test_methodview_methods_constrained_by_registration(self) -> None:
        """Class has get/post/put/delete but registration limits to GET only."""
        idx = _methodview_index(
            method_names=("get", "post", "put", "delete"),
            registrations=(("/api/items", "items", ("GET",)),),
        )
        routes = tuple(WebApp.from_index(idx).repo_view().routes)

        items_routes = [r for r in routes if r.endpoint == "items"]
        assert len(items_routes) == 1
        assert items_routes[0].methods == frozenset({HttpMethod.GET})
        assert items_routes[0].handler.fqn == "views.ItemAPI.get"

    def test_methodview_multiple_registrations(self) -> None:
        """Same class registered at two different URLs."""
        idx = _methodview_index(
            method_names=("get", "post", "put", "delete"),
            registrations=(
                ("/api/items", "items", ("GET", "POST")),
                ("/api/items/<int:item_id>", "item_detail", ("GET", "PUT", "DELETE")),
            ),
        )
        routes = tuple(WebApp.from_index(idx).repo_view().routes)

        assert _route_for_method(routes, "items", HttpMethod.GET).handler.fqn == (
            "views.ItemAPI.get"
        )
        assert _route_for_method(routes, "items", HttpMethod.POST).handler.fqn == (
            "views.ItemAPI.post"
        )
        assert _route_for_method(routes, "item_detail", HttpMethod.GET).url_rule == (
            "/api/items/<int:item_id>"
        )
        assert _route_for_method(routes, "item_detail", HttpMethod.PUT).handler.fqn == (
            "views.ItemAPI.put"
        )
        assert _route_for_method(routes, "item_detail", HttpMethod.DELETE).handler.fqn == (
            "views.ItemAPI.delete"
        )

    def test_methodview_handler_is_class_method(self) -> None:
        """Handler FQN should reference the class method, not the class itself."""
        idx = _methodview_index(
            method_names=("get",),
            registrations=(("/api/items", "items", ("GET",)),),
        )
        routes = tuple(WebApp.from_index(idx).repo_view().routes)

        handler_fqn = _route_for_method(routes, "items", HttpMethod.GET).handler.fqn
        # Handler should be the class's get method, not a standalone function
        assert "get" in handler_fqn

    def test_methodview_no_registration_produces_gap(self) -> None:
        """MethodView with no add_url_rule produces a gap, no route."""
        klass = _class_record(
            "views.OrphanAPI",
            bases=("MethodView",),
            method_names=("get",),
        )
        get_method = _method_function("views.OrphanAPI.get", line=20)

        idx = _make_index(
            functions=(get_method,),
            classes=(klass,),
            decorators=(),
            symbols=(
                SymbolRef(
                    name="MethodView",
                    fqn="flask.views.MethodView",
                    resolution=ResolutionStatus.RESOLVED,
                    location=_span(2, file="views.py"),
                    provenance=_PROV,
                ),
            ),
            value_flow_edges=(),
            imports=_flask_views_imports(),
        )
        webapp = WebApp.from_index(idx)
        routes = tuple(webapp.repo_view().routes)

        # No route should be created for an orphan MethodView
        orphan_routes = [r for r in routes if "OrphanAPI" in getattr(r.handler, "fqn", "")]
        assert len(orphan_routes) == 0
        # But a gap should exist
        assert any("OrphanAPI" in g.message for g in webapp._gaps)

    def test_methodview_registration_uses_resolved_class_fqn_for_short_name_collision(
        self,
    ) -> None:
        """Search.as_view() resolves to the imported class, not every Search class."""
        idx = _colliding_methodview_index(resolve_registration=True)

        routes = tuple(WebApp.from_index(idx).repo_view().routes)

        route = _route_for_method(routes, "search", HttpMethod.GET)
        assert route.url_rule == "/search"
        assert route.handler.fqn == "pkg.one.Search.get"
        assert all(route.handler.fqn != "pkg.two.Search.get" for route in routes)

    def test_methodview_unresolved_short_name_collision_records_ambiguity_gap(self) -> None:
        """Short-name fallback refuses ambiguous registrations instead of mis-associating."""
        idx = _colliding_methodview_index(resolve_registration=False)

        repo = WebApp.from_index(idx).repo_view()

        assert all(route.endpoint != "search" for route in repo.routes)
        assert any(
            gap.source_error == "class_view_conversion: ambiguous short-name registration"
            for gap in repo.gaps
        )


class TestMethodViewFixtureResolution:
    """Real Flask subclassed fixture produces MethodView routes."""

    def test_flask_subclassed_methodview_items_route(self, flask_subclassed: RepoView) -> None:
        routes = _routes_by_endpoint(flask_subclassed)

        assert "items" in routes
        assert routes["items"].url_rule == "/api/items"
        all_routes = tuple(flask_subclassed.routes)
        assert _route_for_method(all_routes, "items", HttpMethod.GET).handler.fqn.endswith(".get")
        assert _route_for_method(all_routes, "items", HttpMethod.POST).handler.fqn.endswith(
            ".post"
        )

    def test_flask_subclassed_methodview_item_detail_route(
        self, flask_subclassed: RepoView
    ) -> None:
        routes = _routes_by_endpoint(flask_subclassed)

        assert "item_detail" in routes
        assert routes["item_detail"].url_rule == "/api/items/<int:item_id>"
        all_routes = tuple(flask_subclassed.routes)
        assert _route_for_method(all_routes, "item_detail", HttpMethod.GET).handler.fqn.endswith(
            ".get"
        )
        assert _route_for_method(all_routes, "item_detail", HttpMethod.PUT).handler.fqn.endswith(
            ".put"
        )
        assert _route_for_method(
            all_routes,
            "item_detail",
            HttpMethod.DELETE,
        ).handler.fqn.endswith(".delete")
