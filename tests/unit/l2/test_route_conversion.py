"""Tests for provider-match-to-Route domain object conversion.

L2-003b: Verifies that ProviderMatch records carrying route descriptors
(RouteDecorator, RouteCallPattern) convert into Route domain objects with
correct fields, and that missing/dynamic arguments produce AnalysisGap
records instead of silent omissions.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from flawed._index import CodeIndex
from flawed._index._types import (
    CallArgument,
    CallEdge,
    DecoratorFact,
    EdgeSource,
    ExtractionProvenance,
    FunctionRecord,
    ImportFact,
    ResolutionStatus,
    SourceSpan,
    SymbolRef,
)
from flawed._index._types import FunctionKind as L1FunctionKind
from flawed._index._types import (
    Parameter as L1Parameter,
)
from flawed._index._types import (
    ParameterKind as L1ParameterKind,
)
from flawed._semantic import _merge_routes
from flawed._semantic._provider_engine import (
    ProviderMatch,
    ProviderPhase,
)
from flawed._semantic._route_conversion import (
    _is_url_list,
    _parse_class_view_registration_args,
    convert_route_match,
)
from flawed._semantic.providers import (
    ImperativeRoutePattern,
    Provider,
    ProviderMeta,
    RouteCallPattern,
    RouteDecorator,
)
from flawed.core import AnalysisGap, GapKind, Location, Provenance
from flawed.route import HttpMethod, Route

if TYPE_CHECKING:
    from flawed.function import Function

_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="")
_SPAN = SourceSpan(file="app.py", line=10, column=0, end_line=10, end_column=30)
_ROOT = Path("/tmp/test-repo")


def _decorator(
    fqn: str,
    *,
    target_fqn: str = "app.handler",
    args: tuple[str, ...] = (),
    kwargs: tuple[tuple[str, str], ...] = (),
) -> DecoratorFact:
    return DecoratorFact(
        name=fqn.rsplit(".", 1)[-1],
        fqn=fqn,
        args=args,
        kwargs=kwargs,
        target_fqn=target_fqn,
        application_order=0,
        location=_SPAN,
        provenance=_PROV,
    )


def _function(fqn: str, *, file: str = "app.py", line: int = 15) -> FunctionRecord:
    name = fqn.rsplit(".", 1)[-1]
    return FunctionRecord(
        fqn=fqn,
        name=name,
        file=file,
        line=line,
        params=(
            L1Parameter(
                name="self" if "." in name else "request",
                annotation=None,
                default=None,
                kind=L1ParameterKind.POSITIONAL_OR_KEYWORD,
                position=0,
                location=SourceSpan(file=file, line=line, column=0, end_line=line, end_column=10),
            ),
        ),
        decorator_names=(),
        decorator_fqns=(),
        kind=L1FunctionKind.TOP_LEVEL,
        is_method=False,
        is_nested=False,
        is_async=False,
        parent_class=None,
        location=SourceSpan(file=file, line=line, column=0, end_line=line + 5, end_column=0),
        provenance=_PROV,
    )


def _call(
    fqn: str,
    *,
    caller_fqn: str = "app.<module>",
    args: tuple[CallArgument, ...] = (),
) -> CallEdge:
    return CallEdge(
        caller_fqn=caller_fqn,
        callee_fqn=fqn,
        arguments=args,
        resolution=ResolutionStatus.RESOLVED,
        source=EdgeSource.AST,
        unresolved_reason=None,
        location=_SPAN,
        provenance=_PROV,
        call_expression=f"{fqn}()",
    )


def _arg(position: int | None, expression: str, *, keyword: str | None = None) -> CallArgument:
    return CallArgument(
        position=position,
        keyword=keyword,
        expression=expression,
        location=_SPAN,
    )


def _make_match(
    *,
    descriptor: RouteDecorator | RouteCallPattern | ImperativeRoutePattern,
    source_fact: DecoratorFact | CallEdge | SymbolRef,
    provider_id: str = "flask",
) -> ProviderMatch:
    if isinstance(source_fact, SymbolRef | DecoratorFact):
        fqn = source_fact.fqn
    else:
        fqn = source_fact.callee_fqn
    assert fqn is not None
    return ProviderMatch(
        provider_id=provider_id,
        phase=ProviderPhase.ROUTES,
        descriptor=descriptor,
        source_fact=source_fact,
        observed_fqn=fqn,
        canonical_fqn=fqn,
        location=source_fact.location,
    )


# =====================================================================
# RouteDecorator conversion — happy path
# =====================================================================


class TestRouteDecoratorConversion:
    """Route decorator matches produce Route domain objects."""

    def test_basic_route_with_literal_url_rule(self) -> None:
        """@app.route("/") → Route(url_rule="/", methods={GET})."""
        dec = _decorator(
            "flask.Flask.route",
            target_fqn="app.index",
            args=('"/",',),
        )
        handler = _function("app.index")
        fn_by_fqn = {handler.fqn: handler}
        match = _make_match(
            descriptor=RouteDecorator(fqn="flask.Flask.route"),
            source_fact=dec,
        )

        result = convert_route_match(match, fn_by_fqn)

        assert result is not None
        route, gaps = result
        assert route is not None
        assert route.url_rule == "/"
        assert route.methods == frozenset({HttpMethod.GET})
        assert route.handler.fqn == "app.index"
        assert route.endpoint == "index"
        assert route.group is None
        assert route.location.file == "app.py"
        assert gaps == ()

    def test_multi_method_route_from_methods_kwarg(self) -> None:
        """@app.route("/users", methods=["GET", "POST"]) → both methods."""
        dec = _decorator(
            "flask.Flask.route",
            target_fqn="app.users",
            args=('"/users"',),
            kwargs=(("methods", '["GET", "POST"]'),),
        )
        handler = _function("app.users")
        fn_by_fqn = {handler.fqn: handler}
        match = _make_match(
            descriptor=RouteDecorator(fqn="flask.Flask.route"),
            source_fact=dec,
        )

        result = convert_route_match(match, fn_by_fqn)
        assert result is not None
        route, gaps = result
        assert route is not None
        assert route.methods == frozenset({HttpMethod.GET, HttpMethod.POST})
        assert gaps == ()

    def test_shorthand_implied_method(self) -> None:
        """@app.post("/items") → Route with methods={POST}."""
        dec = _decorator(
            "flask.Flask.post",
            target_fqn="app.create_item",
            args=('"/items"',),
        )
        handler = _function("app.create_item")
        fn_by_fqn = {handler.fqn: handler}
        match = _make_match(
            descriptor=RouteDecorator(fqn="flask.Flask.post", implied_method="POST"),
            source_fact=dec,
        )

        result = convert_route_match(match, fn_by_fqn)
        assert result is not None
        route, _gaps = result
        assert route is not None
        assert route.methods == frozenset({HttpMethod.POST})

    def test_url_rule_with_path_params_preserved(self) -> None:
        """@app.route("/users/<int:id>") preserves path params in url_rule."""
        dec = _decorator(
            "flask.Flask.route",
            target_fqn="app.user_detail",
            args=('"/users/<int:id>"',),
        )
        handler = _function("app.user_detail")
        fn_by_fqn = {handler.fqn: handler}
        match = _make_match(
            descriptor=RouteDecorator(fqn="flask.Flask.route"),
            source_fact=dec,
        )

        result = convert_route_match(match, fn_by_fqn)
        assert result is not None
        route, _ = result
        assert route is not None
        assert route.url_rule == "/users/<int:id>"

    def test_endpoint_derived_from_handler_name(self) -> None:
        """Endpoint defaults to handler function short name."""
        dec = _decorator(
            "flask.Flask.route",
            target_fqn="myapp.views.create_user",
            args=('"/create"',),
        )
        handler = _function("myapp.views.create_user")
        fn_by_fqn = {handler.fqn: handler}
        match = _make_match(
            descriptor=RouteDecorator(fqn="flask.Flask.route"),
            source_fact=dec,
        )

        result = convert_route_match(match, fn_by_fqn)
        assert result is not None
        route, _ = result
        assert route is not None
        assert route.endpoint == "create_user"


# =====================================================================
# RouteDecorator conversion — gap cases
# =====================================================================


class TestRouteDecoratorGaps:
    """Missing or dynamic arguments produce gaps, not silent omissions."""

    def test_dynamic_url_rule_produces_gap(self) -> None:
        """@app.route(some_variable) → gap (non-literal URL)."""
        dec = _decorator(
            "flask.Flask.route",
            target_fqn="app.handler",
            args=("some_variable",),
        )
        handler = _function("app.handler")
        fn_by_fqn = {handler.fqn: handler}
        match = _make_match(
            descriptor=RouteDecorator(fqn="flask.Flask.route"),
            source_fact=dec,
        )

        result = convert_route_match(match, fn_by_fqn)
        assert result is not None
        route, gaps = result
        assert route is None
        assert len(gaps) == 1
        assert gaps[0].kind == GapKind.INTERPRETER_ERROR
        assert "url rule" in gaps[0].message.lower() or "URL" in gaps[0].message

    def test_missing_url_rule_arg_produces_gap(self) -> None:
        """@app.route() with no positional args → gap."""
        dec = _decorator(
            "flask.Flask.route",
            target_fqn="app.handler",
            args=(),
        )
        handler = _function("app.handler")
        fn_by_fqn = {handler.fqn: handler}
        match = _make_match(
            descriptor=RouteDecorator(fqn="flask.Flask.route"),
            source_fact=dec,
        )

        result = convert_route_match(match, fn_by_fqn)
        assert result is not None
        route, gaps = result
        assert route is None
        assert len(gaps) >= 1

    def test_missing_handler_function_produces_gap(self) -> None:
        """Match for handler FQN not in function map → gap."""
        dec = _decorator(
            "flask.Flask.route",
            target_fqn="app.unknown_handler",
            args=('"/test"',),
        )
        fn_by_fqn: dict[str, FunctionRecord] = {}
        match = _make_match(
            descriptor=RouteDecorator(fqn="flask.Flask.route"),
            source_fact=dec,
        )

        result = convert_route_match(match, fn_by_fqn)
        assert result is not None
        route, gaps = result
        assert route is None
        assert len(gaps) >= 1
        assert any(g.kind == GapKind.SYMBOL_UNRESOLVED for g in gaps)

    def test_dynamic_methods_kwarg_uses_defaults_with_gap(self) -> None:
        """methods=some_var → fall back to defaults but emit gap."""
        dec = _decorator(
            "flask.Flask.route",
            target_fqn="app.handler",
            args=('"/test"',),
            kwargs=(("methods", "allowed_methods"),),
        )
        handler = _function("app.handler")
        fn_by_fqn = {handler.fqn: handler}
        match = _make_match(
            descriptor=RouteDecorator(fqn="flask.Flask.route"),
            source_fact=dec,
        )

        result = convert_route_match(match, fn_by_fqn)
        assert result is not None
        route, gaps = result
        # Route is still created with defaults, but gap records imprecision
        assert route is not None
        assert route.methods == frozenset({HttpMethod.GET})
        assert len(gaps) == 1
        assert gaps[0].kind == GapKind.INFERENCE_FAILURE


# =====================================================================
# RouteCallPattern conversion
# =====================================================================


class TestRouteCallPatternConversion:
    """RouteCallPattern matches produce Route domain objects."""

    def test_add_url_rule_with_literal_args(self) -> None:
        """add_url_rule("/api", view_func=handler) → Route."""
        handler = _function("app.handler")
        fn_by_fqn = {handler.fqn: handler}
        edge = _call(
            "flask.Flask.add_url_rule",
            args=(
                _arg(0, '"/api"'),
                _arg(None, "app.handler", keyword="view_func"),
            ),
        )
        match = _make_match(
            descriptor=RouteCallPattern(fqn="flask.Flask.add_url_rule"),
            source_fact=edge,
        )

        result = convert_route_match(match, fn_by_fqn)
        assert result is not None
        route, gaps = result
        assert route is not None
        assert route.url_rule == "/api"
        assert route.handler.fqn == "app.handler"
        assert gaps == ()

    def test_add_url_rule_with_positional_endpoint_and_handler(self) -> None:
        """add_url_rule("/create", "create_user", handler) uses positional args."""
        handler = _function("app.create_user")
        fn_by_fqn = {handler.fqn: handler}
        edge = _call(
            "flask.Flask.add_url_rule",
            args=(
                _arg(0, '"/create"'),
                _arg(1, '"create_user"'),
                _arg(2, "app.create_user"),
            ),
        )
        match = _make_match(
            descriptor=RouteCallPattern(fqn="flask.Flask.add_url_rule"),
            source_fact=edge,
        )

        result = convert_route_match(match, fn_by_fqn)
        assert result is not None
        route, gaps = result
        assert route is not None
        assert route.url_rule == "/create"
        assert route.endpoint == "create_user"
        assert route.handler.fqn == "app.create_user"
        assert route.methods == frozenset({HttpMethod.GET})
        assert gaps == ()

    def test_add_url_rule_endpoint_kwarg_and_methods_kwarg(self) -> None:
        """endpoint= and methods= literals are preserved for call routes."""
        handler = _function("app.delete_user")
        fn_by_fqn = {handler.fqn: handler}
        edge = _call(
            "flask.Flask.add_url_rule",
            args=(
                _arg(0, '"/users/<int:user_id>"'),
                _arg(None, '"user_detail"', keyword="endpoint"),
                _arg(None, "app.delete_user", keyword="view_func"),
                _arg(None, '["GET", "DELETE"]', keyword="methods"),
            ),
        )
        match = _make_match(
            descriptor=RouteCallPattern(fqn="flask.Flask.add_url_rule"),
            source_fact=edge,
        )

        result = convert_route_match(match, fn_by_fqn)
        assert result is not None
        route, gaps = result
        assert route is not None
        assert route.endpoint == "user_detail"
        assert route.url_rule == "/users/<int:user_id>"
        assert route.methods == frozenset({HttpMethod.GET, HttpMethod.DELETE})
        assert gaps == ()

    def test_add_url_rule_simple_name_handler_resolves_in_call_file_module(self) -> None:
        """view_func=handler source text resolves to the function in the same file."""
        handler = _function("app.health")
        fn_by_fqn = {handler.fqn: handler}
        edge = _call(
            "flask.Flask.add_url_rule",
            args=(
                _arg(0, '"/health"'),
                _arg(None, "health", keyword="view_func"),
            ),
        )
        match = _make_match(
            descriptor=RouteCallPattern(fqn="flask.Flask.add_url_rule"),
            source_fact=edge,
        )

        result = convert_route_match(match, fn_by_fqn)
        assert result is not None
        route, gaps = result
        assert route is not None
        assert route.endpoint == "health"
        assert route.handler.fqn == "app.health"
        assert gaps == ()

    def test_add_url_rule_dynamic_methods_uses_default_with_gap(self) -> None:
        """Dynamic methods= keeps the route but records inference loss."""
        handler = _function("app.handler")
        fn_by_fqn = {handler.fqn: handler}
        edge = _call(
            "flask.Flask.add_url_rule",
            args=(
                _arg(0, '"/dynamic-methods"'),
                _arg(None, "app.handler", keyword="view_func"),
                _arg(None, "allowed_methods", keyword="methods"),
            ),
        )
        match = _make_match(
            descriptor=RouteCallPattern(fqn="flask.Flask.add_url_rule"),
            source_fact=edge,
        )

        result = convert_route_match(match, fn_by_fqn)
        assert result is not None
        route, gaps = result
        assert route is not None
        assert route.methods == frozenset({HttpMethod.GET})
        assert len(gaps) == 1
        assert gaps[0].kind == GapKind.INFERENCE_FAILURE

    def test_add_url_rule_unresolved_handler_produces_gap(self) -> None:
        """Dynamic view_func expressions are explicit gaps, not silent omissions."""
        handler = _function("app.handler")
        fn_by_fqn = {handler.fqn: handler}
        edge = _call(
            "flask.Flask.add_url_rule",
            args=(
                _arg(0, '"/factory"'),
                _arg(None, "make_handler()", keyword="view_func"),
            ),
        )
        match = _make_match(
            descriptor=RouteCallPattern(fqn="flask.Flask.add_url_rule"),
            source_fact=edge,
        )

        result = convert_route_match(match, fn_by_fqn)
        assert result is not None
        route, gaps = result
        assert route is None
        assert len(gaps) == 1
        assert gaps[0].kind == GapKind.SYMBOL_UNRESOLVED


# =====================================================================
# ImperativeRoutePattern conversion
# =====================================================================


def _imperative_source_fact(
    call_expression: str,
    *,
    entry_fqn: str = "starlette.routing.Route",
    file: str = "app.py",
    line: int = 10,
) -> SymbolRef:
    """Create a synthetic SymbolRef carrying an imperative route call expression."""
    return SymbolRef(
        name=call_expression,
        fqn=entry_fqn,
        resolution=ResolutionStatus.RESOLVED,
        location=SourceSpan(file=file, line=line, column=0, end_line=line, end_column=50),
        provenance=_PROV,
    )


class TestImperativeRouteConversion:
    """ImperativeRoutePattern matches produce Route domain objects."""

    _DESCRIPTOR = ImperativeRoutePattern(
        entry_fqn="starlette.routing.Route",
        rule_arg=0,
        view_arg=1,
        view_kwarg="endpoint",
        methods_kwarg="methods",
    )

    def test_basic_route_entry_produces_enriched_route(self) -> None:
        """Route("/users", list_users) → EnrichedRoute with url_rule and handler."""
        handler = _function("app.list_users")
        fn_by_fqn = {handler.fqn: handler}
        fact = _imperative_source_fact('Route("/users", list_users)')
        match = _make_match(
            descriptor=self._DESCRIPTOR,
            source_fact=fact,
            provider_id="starlette",
        )

        route, _gaps = convert_route_match(match, fn_by_fqn)
        assert route is not None
        assert route.url_rule == "/users"
        assert route.handler.fqn == "app.list_users"
        assert route.methods == frozenset({HttpMethod.GET})
        assert route.endpoint == "list_users"

    def test_route_with_literal_methods(self) -> None:
        """Route("/submit", handler, methods=["POST"]) → methods={POST}."""
        handler = _function("app.submit")
        fn_by_fqn = {handler.fqn: handler}
        fact = _imperative_source_fact(
            'Route("/submit", submit, methods=["POST"])',
        )
        match = _make_match(
            descriptor=self._DESCRIPTOR,
            source_fact=fact,
            provider_id="starlette",
        )

        route, _gaps = convert_route_match(match, fn_by_fqn)
        assert route is not None
        assert route.url_rule == "/submit"
        assert route.methods == frozenset({HttpMethod.POST})

    def test_route_with_kwarg_handler(self) -> None:
        """Route("/items", endpoint=get_items) uses view_kwarg for handler."""
        handler = _function("app.get_items")
        fn_by_fqn = {handler.fqn: handler}
        fact = _imperative_source_fact('Route("/items", endpoint=get_items)')
        match = _make_match(
            descriptor=self._DESCRIPTOR,
            source_fact=fact,
            provider_id="starlette",
        )

        route, _gaps = convert_route_match(match, fn_by_fqn)
        assert route is not None
        assert route.handler.fqn == "app.get_items"

    def test_dynamic_url_rule_produces_gap(self) -> None:
        """Route(url_var, handler) → gap for non-literal URL."""
        handler = _function("app.handler")
        fn_by_fqn = {handler.fqn: handler}
        fact = _imperative_source_fact("Route(url_var, handler)")
        match = _make_match(
            descriptor=self._DESCRIPTOR,
            source_fact=fact,
            provider_id="starlette",
        )

        route, gaps = convert_route_match(match, fn_by_fqn)
        assert route is None
        assert len(gaps) >= 1
        assert any(g.kind == GapKind.INTERPRETER_ERROR for g in gaps)

    def test_unresolvable_handler_produces_gap(self) -> None:
        """Route("/path", unknown_func) → gap when handler not in index."""
        fn_by_fqn: dict[str, FunctionRecord] = {}
        fact = _imperative_source_fact('Route("/path", unknown_func)')
        match = _make_match(
            descriptor=self._DESCRIPTOR,
            source_fact=fact,
            provider_id="starlette",
        )

        route, gaps = convert_route_match(match, fn_by_fqn)
        assert route is None
        assert len(gaps) >= 1
        assert any(g.kind == GapKind.SYMBOL_UNRESOLVED for g in gaps)

    def test_nested_entry_produces_gap(self) -> None:
        """Mount("/api", routes=[...]) deferred → gap for nested routing."""
        handler = _function("app.handler")
        fn_by_fqn = {handler.fqn: handler}
        descriptor = ImperativeRoutePattern(
            entry_fqn="starlette.routing.Route",
            rule_arg=0,
            view_arg=1,
            view_kwarg="endpoint",
            methods_kwarg="methods",
            nested_fqn="starlette.routing.Mount",
        )
        # Source fact uses the nested_fqn constructor
        fact = _imperative_source_fact(
            'Mount("/api", routes=[Route("/items", handler)])',
            entry_fqn="starlette.routing.Mount",
        )
        match = _make_match(
            descriptor=descriptor,
            source_fact=fact,
            provider_id="starlette",
        )

        route, gaps = convert_route_match(match, fn_by_fqn)
        assert route is None
        assert len(gaps) >= 1
        assert any("nested" in g.message.lower() or "mount" in g.message.lower() for g in gaps)


# =====================================================================
# Dotted handler resolution (DISC-022)
# =====================================================================


def _make_idx(
    *,
    symbol_refs: tuple[SymbolRef, ...] = (),
    functions: tuple[FunctionRecord, ...] = (),
) -> CodeIndex:
    """Build a minimal CodeIndex with symbol resolution support."""
    return CodeIndex(
        repo_root=_ROOT,
        functions=functions,
        classes=(),
        decorators=(),
        imports=(),
        attributes=(),
        call_edges=(),
        cfgs={},
        value_flow_edges=(),
        symbol_refs=symbol_refs,
        errors=(),
        provenance=_PROV,
    )


class TestDottedHandlerResolution:
    """Dotted handler expressions resolve through the L1 symbol table."""

    _DESCRIPTOR = ImperativeRoutePattern(
        entry_fqn="django.urls.path",
        rule_arg=0,
        view_arg=1,
        view_kwarg="view",
        methods_kwarg=None,
    )

    def test_dotted_handler_resolves_via_symbol_table(self) -> None:
        """path("", views.index) resolves 'views' → module FQN → views.index."""
        handler = _function("myapp.views.index", file="views.py")
        fn_by_fqn = {handler.fqn: handler}
        idx = _make_idx(
            symbol_refs=(
                SymbolRef(
                    name="views",
                    fqn="myapp.views",
                    resolution=ResolutionStatus.RESOLVED,
                    location=SourceSpan(
                        file="urls.py", line=1, column=0, end_line=1, end_column=20
                    ),
                    provenance=_PROV,
                ),
            ),
            functions=(handler,),
        )
        fact = _imperative_source_fact(
            'path("", views.index)', entry_fqn="django.urls.path", file="urls.py"
        )
        match = _make_match(
            descriptor=self._DESCRIPTOR,
            source_fact=fact,
            provider_id="django",
        )

        route, _gaps = convert_route_match(match, fn_by_fqn, idx=idx)
        assert route is not None
        assert route.handler.fqn == "myapp.views.index"
        assert route.url_rule == ""

    def test_dotted_handler_with_multiple_functions(self) -> None:
        """Multiple dotted handlers in the same urls.py all resolve."""
        fn_index = _function("myapp.views.index", file="views.py")
        fn_create = _function("myapp.views.user_create", file="views.py", line=20)
        fn_by_fqn = {fn_index.fqn: fn_index, fn_create.fqn: fn_create}
        idx = _make_idx(
            symbol_refs=(
                SymbolRef(
                    name="views",
                    fqn="myapp.views",
                    resolution=ResolutionStatus.RESOLVED,
                    location=SourceSpan(
                        file="urls.py", line=1, column=0, end_line=1, end_column=20
                    ),
                    provenance=_PROV,
                ),
            ),
            functions=(fn_index, fn_create),
        )
        fact = _imperative_source_fact(
            'path("/create", views.user_create)',
            entry_fqn="django.urls.path",
            file="urls.py",
        )
        match = _make_match(
            descriptor=self._DESCRIPTOR,
            source_fact=fact,
            provider_id="django",
        )

        route, _gaps = convert_route_match(match, fn_by_fqn, idx=idx)
        assert route is not None
        assert route.handler.fqn == "myapp.views.user_create"
        assert route.url_rule == "/create"

    def test_dotted_handler_unresolved_head_produces_gap(self) -> None:
        """views.index with no symbol resolution for 'views' → gap."""
        handler = _function("myapp.views.index", file="views.py")
        fn_by_fqn = {handler.fqn: handler}
        idx = _make_idx(functions=(handler,))  # No symbol refs
        fact = _imperative_source_fact(
            'path("", views.index)', entry_fqn="django.urls.path", file="urls.py"
        )
        match = _make_match(
            descriptor=self._DESCRIPTOR,
            source_fact=fact,
            provider_id="django",
        )

        route, gaps = convert_route_match(match, fn_by_fqn, idx=idx)
        assert route is None
        assert len(gaps) >= 1
        assert any(g.kind == GapKind.SYMBOL_UNRESOLVED for g in gaps)

    def test_as_view_call_is_deferred_without_gap(self) -> None:
        """path("account/", ProtectedAPIView.as_view()) is deferred to ClassViewPattern."""
        fn_by_fqn: dict[str, FunctionRecord] = {}
        idx = _make_idx()
        fact = _imperative_source_fact(
            'path("account/", ProtectedAPIView.as_view())',
            entry_fqn="django.urls.path",
            file="urls.py",
        )
        match = _make_match(
            descriptor=self._DESCRIPTOR,
            source_fact=fact,
            provider_id="django",
        )

        route, gaps = convert_route_match(match, fn_by_fqn, idx=idx)
        assert route is None
        assert gaps == ()

    def test_dotted_as_view_call_is_deferred_without_gap(self) -> None:
        """path("list/", views.ArticleListView.as_view()) is a class-view factory."""
        fn_by_fqn: dict[str, FunctionRecord] = {}
        idx = _make_idx(
            symbol_refs=(
                SymbolRef(
                    name="views",
                    fqn="myapp.views",
                    resolution=ResolutionStatus.RESOLVED,
                    location=SourceSpan(
                        file="urls.py", line=1, column=0, end_line=1, end_column=20
                    ),
                    provenance=_PROV,
                ),
            ),
        )
        fact = _imperative_source_fact(
            'path("list/", views.ArticleListView.as_view())',
            entry_fqn="django.urls.path",
            file="urls.py",
        )
        match = _make_match(
            descriptor=self._DESCRIPTOR,
            source_fact=fact,
            provider_id="django",
        )

        route, gaps = convert_route_match(match, fn_by_fqn, idx=idx)
        assert route is None
        assert gaps == ()

    def test_dotted_handler_without_idx_falls_back_to_gap(self) -> None:
        """Without idx, dotted handlers still produce gaps (backward compatibility)."""
        handler = _function("myapp.views.index", file="views.py")
        fn_by_fqn = {handler.fqn: handler}
        fact = _imperative_source_fact(
            'path("", views.index)', entry_fqn="django.urls.path", file="urls.py"
        )
        match = _make_match(
            descriptor=self._DESCRIPTOR,
            source_fact=fact,
            provider_id="django",
        )

        # No idx passed — backward compatible
        route, gaps = convert_route_match(match, fn_by_fqn)
        assert route is None
        assert len(gaps) >= 1
        assert any(g.kind == GapKind.SYMBOL_UNRESOLVED for g in gaps)


# =====================================================================
# WebApp.from_index integration — engine runs and routes appear
# =====================================================================


class TestWebAppRouteWiring:
    """WebApp.from_index runs the provider engine and exposes routes."""

    class SimpleRouteProvider(Provider):
        meta = ProviderMeta(
            id="simple-route",
            name="Simple Route",
            library="simple_route",
            library_fqn="simple_route",
        )
        fqn_aliases: ClassVar[dict[str, str]] = {}
        routes = (RouteDecorator(fqn="simple_route.app.route"),)

    def test_from_index_produces_routes_from_engine(self) -> None:
        """WebApp.from_index() runs the engine and yields Route objects."""
        from flawed._semantic import WebApp
        from flawed._semantic._provider_engine import ProviderEngine

        handler_fn = _function("app.index")
        idx = CodeIndex(
            repo_root=_ROOT,
            functions=(handler_fn,),
            classes=(),
            decorators=(
                _decorator(
                    "simple_route.app.route",
                    target_fqn="app.index",
                    args=('"/home"',),
                ),
            ),
            imports=(
                ImportFact(
                    module="simple_route",
                    names=(),
                    aliases=(),
                    is_from_import=False,
                    location=_SPAN,
                    provenance=_PROV,
                ),
            ),
            attributes=(),
            call_edges=(),
            cfgs={},
            value_flow_edges=(),
            symbol_refs=(),
            errors=(),
            provenance=_PROV,
        )

        engine = ProviderEngine(providers=(self.SimpleRouteProvider,))
        webapp = WebApp.from_index(idx, provider_engine=engine)
        rv = webapp.repo_view()

        assert len(rv.routes) == 1
        route = next(iter(rv.routes))
        assert route.url_rule == "/home"
        assert route.handler.fqn == "app.index"

    def test_no_providers_imported_gives_empty_routes(self) -> None:
        """No provider imports → empty route collection, no errors."""
        from flawed._semantic import WebApp

        idx = CodeIndex(
            repo_root=_ROOT,
            functions=(),
            classes=(),
            decorators=(),
            imports=(),
            attributes=(),
            call_edges=(),
            cfgs={},
            value_flow_edges=(),
            symbol_refs=(),
            errors=(),
            provenance=_PROV,
        )

        webapp = WebApp.from_index(idx)
        rv = webapp.repo_view()

        assert len(rv.routes) == 0


# =====================================================================
# Route deduplication
# =====================================================================


class TestRouteDeduplication:
    """Post-conversion route merging removes true duplicate registrations."""

    def test_merges_same_semantic_route_across_registered_methods(self) -> None:
        """Duplicate MethodView registrations should not yield duplicate route scans."""
        duplicate_get = _make_route(
            endpoint="search",
            url_rule="/search",
            methods=frozenset({HttpMethod.GET}),
            handler_fqn="app.views.Search.get",
            line=20,
            gap_message="first registration",
        )
        duplicate_post = _make_route(
            endpoint="search",
            url_rule="/search",
            methods=frozenset({HttpMethod.POST}),
            handler_fqn="app.views.Search.get",
            line=10,
            gap_message="second registration",
        )
        distinct_handler = _make_route(
            endpoint="search",
            url_rule="/search",
            methods=frozenset({HttpMethod.POST}),
            handler_fqn="app.views.Search.post",
            line=30,
        )

        merged = _merge_routes((duplicate_get, duplicate_post, distinct_handler))

        assert len(merged) == 2
        same_handler = next(r for r in merged if r.handler.fqn == "app.views.Search.get")
        assert same_handler.methods == frozenset({HttpMethod.GET, HttpMethod.POST})
        assert same_handler.url_rule == "/search"
        assert same_handler.location.line == 10
        assert [gap.message for gap in same_handler.gaps] == [
            "second registration",
            "first registration",
        ]
        assert any(r.handler.fqn == "app.views.Search.post" for r in merged)

    def test_preserves_same_endpoint_handler_when_route_context_differs(self) -> None:
        """A reused handler can back distinct URLs/groups/security contexts."""
        public = _make_route(
            endpoint="search",
            url_rule="/search",
            methods=frozenset({HttpMethod.GET}),
            handler_fqn="app.views.Search.get",
            group="public",
            provider_id="flask",
            router_group_variable_fqn="app.public_bp",
            line=20,
        )
        admin = _make_route(
            endpoint="search",
            url_rule="/admin/search",
            methods=frozenset({HttpMethod.GET}),
            handler_fqn="app.views.Search.get",
            group="admin",
            provider_id="flask",
            router_group_variable_fqn="app.admin_bp",
            line=10,
        )

        merged = _merge_routes((public, admin))

        assert len(merged) == 2
        assert [(route.url_rule, route.group) for route in merged] == [
            ("/admin/search", "admin"),
            ("/search", "public"),
        ]
        assert {
            object.__getattribute__(route, "_router_group_variable_fqn") for route in merged
        } == {
            "app.admin_bp",
            "app.public_bp",
        }


# =====================================================================
# ConcreteRouteCollection filter methods
# =====================================================================


class TestConcreteRouteCollectionFilters:
    """Route collection filter methods work on populated data."""

    def test_in_file_filters_by_route_location(self) -> None:
        from flawed._semantic._collections import ConcreteRouteCollection
        from flawed._semantic._enriched import EnrichedRoute

        route1 = EnrichedRoute(
            endpoint="index",
            url_rule="/",
            methods=frozenset({HttpMethod.GET}),
            handler=_make_stub_function("app.index"),
            group=None,
            location=_make_location("app.py", 10),
            provenance=_make_provenance(),
        )
        _set_route_gaps(route1, ())
        route2 = EnrichedRoute(
            endpoint="admin",
            url_rule="/admin",
            methods=frozenset({HttpMethod.GET}),
            handler=_make_stub_function("admin.index"),
            group=None,
            location=_make_location("admin.py", 5),
            provenance=_make_provenance(),
        )
        _set_route_gaps(route2, ())
        coll = ConcreteRouteCollection((route1, route2))

        assert len(coll.in_file("app.py")) == 1
        assert len(coll.in_file("admin.py")) == 1
        assert len(coll.in_file("missing.py")) == 0

    def test_accepting_filters_by_http_method(self) -> None:
        from flawed._semantic._collections import ConcreteRouteCollection
        from flawed._semantic._enriched import EnrichedRoute

        get_route = EnrichedRoute(
            endpoint="get_only",
            url_rule="/get",
            methods=frozenset({HttpMethod.GET}),
            handler=_make_stub_function("app.get_only"),
            group=None,
            location=_make_location("app.py", 10),
            provenance=_make_provenance(),
        )
        _set_route_gaps(get_route, ())
        post_route = EnrichedRoute(
            endpoint="post_only",
            url_rule="/post",
            methods=frozenset({HttpMethod.POST}),
            handler=_make_stub_function("app.post_only"),
            group=None,
            location=_make_location("app.py", 20),
            provenance=_make_provenance(),
        )
        _set_route_gaps(post_route, ())
        coll = ConcreteRouteCollection((get_route, post_route))

        from flawed.route import accepting

        assert len(coll.where(accepting(HttpMethod.GET))) == 1
        assert len(coll.where(accepting(HttpMethod.POST))) == 1
        assert len(coll.where(accepting(HttpMethod.DELETE))) == 0

    def test_in_group_filters_by_group_name(self) -> None:
        from flawed._semantic._collections import ConcreteRouteCollection
        from flawed._semantic._enriched import EnrichedRoute

        route_api = EnrichedRoute(
            endpoint="api.users",
            url_rule="/api/users",
            methods=frozenset({HttpMethod.GET}),
            handler=_make_stub_function("api.users"),
            group="api",
            location=_make_location("api.py", 10),
            provenance=_make_provenance(),
        )
        _set_route_gaps(route_api, ())
        route_web = EnrichedRoute(
            endpoint="index",
            url_rule="/",
            methods=frozenset({HttpMethod.GET}),
            handler=_make_stub_function("web.index"),
            group=None,
            location=_make_location("web.py", 5),
            provenance=_make_provenance(),
        )
        _set_route_gaps(route_web, ())
        coll = ConcreteRouteCollection((route_api, route_web))

        assert len(coll.in_group("api")) == 1
        assert len(coll.in_group("web")) == 0


# =====================================================================
# ClassViewPattern URL-from-list extraction
# =====================================================================


class TestIsUrlList:
    """_is_url_list distinguishes URL-path lists from HTTP method lists."""

    def test_single_url_path_is_url_list(self) -> None:
        assert _is_url_list(["/profile"]) is True

    def test_single_url_with_params_is_url_list(self) -> None:
        assert _is_url_list(["/users/<int:id>"]) is True

    def test_empty_list_is_not_url(self) -> None:
        assert _is_url_list([]) is False

    def test_multi_element_list_is_not_url(self) -> None:
        assert _is_url_list(["/a", "/b"]) is False

    def test_http_methods_are_not_url(self) -> None:
        assert _is_url_list(["GET"]) is False
        assert _is_url_list(["GET", "POST"]) is False

    def test_non_path_string_is_not_url(self) -> None:
        assert _is_url_list(["plain"]) is False


class TestClassViewRegistrationUrlFromList:
    """_parse_class_view_registration_args extracts URLs from list args."""

    def test_url_in_list_arg_is_extracted(self) -> None:
        """register_view(bp, routes=["/path"], view_func=Cls.as_view("ep"))."""
        args = ["bp", '["/path"]', 'Cls.as_view("ep")']
        reg = _parse_class_view_registration_args(args, 10, frozenset({"as_view"}))
        assert reg is not None
        assert reg.url_rule == "/path"
        assert reg.class_name == "Cls"
        assert reg.endpoint == "ep"

    def test_bare_string_url_takes_precedence(self) -> None:
        """add_url_rule("/path", view_func=Cls.as_view("ep")) — bare string wins."""
        args = ['"/path"', 'Cls.as_view("ep")']
        reg = _parse_class_view_registration_args(args, 10, frozenset({"as_view"}))
        assert reg is not None
        assert reg.url_rule == "/path"

    def test_methods_list_is_not_url(self) -> None:
        """methods=["GET", "POST"] is correctly identified as methods, not URL."""
        args = ['"/path"', 'Cls.as_view("ep")', '["GET", "POST"]']
        reg = _parse_class_view_registration_args(args, 10, frozenset({"as_view"}))
        assert reg is not None
        assert reg.url_rule == "/path"
        assert reg.methods_expr == '["GET", "POST"]'

    def test_no_url_and_no_class_returns_none(self) -> None:
        """Missing both URL and class → None (not silent success)."""
        args = ["bp", "some_var"]
        reg = _parse_class_view_registration_args(args, 10, frozenset({"as_view"}))
        assert reg is None


# =====================================================================
# Helpers
# =====================================================================


def _make_route(
    *,
    endpoint: str,
    url_rule: str,
    methods: frozenset[HttpMethod],
    handler_fqn: str,
    line: int,
    gap_message: str | None = None,
    group: str | None = None,
    provider_id: str | None = None,
    router_group_variable_fqn: str | None = None,
) -> Route:
    from flawed._semantic._enriched import EnrichedRoute

    route = EnrichedRoute(
        endpoint=endpoint,
        url_rule=url_rule,
        methods=methods,
        handler=_make_stub_function(handler_fqn),
        group=group,
        location=_make_location("app.py", line),
        provenance=_make_provenance(),
    )
    gaps: tuple[AnalysisGap, ...] = ()
    if gap_message is not None:
        gaps = (
            AnalysisGap(
                kind=GapKind.INFERENCE_FAILURE,
                message=gap_message,
                affected_file="app.py",
            ),
        )
    _set_route_gaps(route, gaps)
    if provider_id is not None:
        object.__setattr__(route, "_provider_id", provider_id)
    if router_group_variable_fqn is not None:
        object.__setattr__(
            route,
            "_router_group_variable_fqn",
            router_group_variable_fqn,
        )
    return route


def _make_stub_function(fqn: str) -> Function:
    """Create an EnrichedFunction for use in Route construction."""
    from flawed._semantic._collections import (
        ConcreteDecoratorCollection,
        ConcreteFunctionCollection,
    )
    from flawed._semantic._enriched import EnrichedFunction
    from flawed.core import Location, Provenance
    from flawed.function import FunctionKind

    fn = EnrichedFunction(
        fqn=fqn,
        name=fqn.rsplit(".", 1)[-1],
        params=(),
        kind=FunctionKind.TOP_LEVEL,
        parent_class=None,
        parent_function=None,
        location=Location(file="app.py", line=1, column=0, end_line=5, end_column=0),
        provenance=Provenance(
            source_layer="L2",
            interpreter="test",
            confidence=1.0,
        ),
    )
    object.__setattr__(fn, "_decorators", ConcreteDecoratorCollection(()))
    object.__setattr__(fn, "_gaps", ())
    object.__setattr__(fn, "_calls", ConcreteFunctionCollection(()))
    object.__setattr__(fn, "_called_by", ConcreteFunctionCollection(()))
    return fn


def _make_location(file: str, line: int) -> Location:
    return Location(file=file, line=line, column=0)


def _make_provenance() -> Provenance:
    return Provenance(source_layer="L2", interpreter="test", confidence=1.0)


def _set_route_gaps(route: object, gaps: tuple[object, ...]) -> None:
    object.__setattr__(route, "_gaps", gaps)
