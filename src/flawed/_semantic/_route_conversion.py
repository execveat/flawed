"""Provider route match → Route domain object conversion.

Converts ``ProviderMatch`` records from the ROUTES phase into
``Route`` (actually ``EnrichedRoute``) domain objects or explicit
``AnalysisGap`` records when required arguments are missing or dynamic.

This module handles ``RouteDecorator``, plain-function
``RouteCallPattern``, ``ImperativeRoutePattern``, and
``ClassViewPattern`` descriptors.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from flawed._index._types import CallEdge, DecoratorFact, FlowKind, SymbolRef
from flawed._semantic._conversion_utils import simple_name as _simple_name
from flawed._semantic._enriched import EnrichedRoute
from flawed._semantic._expr_cache import parse_expression as _parse_expression
from flawed._semantic._matching import _module_fqns_by_file
from flawed._semantic.providers import (
    ClassViewPattern,
    ImperativeRoutePattern,
    RouteCallPattern,
    RouteDecorator,
)
from flawed.core import AnalysisGap, GapKind, Location, Provenance
from flawed.route import HttpMethod

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flawed._index import CodeIndex
    from flawed._index._types import CallArgument, ClassRecord, FunctionRecord
    from flawed._semantic._provider_engine import ProviderMatch, RouterGroupInfo

_ROUTE_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="route_conversion",
    confidence=1.0,
    supporting_facts=("converted from provider route match",),
)

_HTTP_METHOD_MAP: dict[str, HttpMethod] = {
    "GET": HttpMethod.GET,
    "POST": HttpMethod.POST,
    "PUT": HttpMethod.PUT,
    "PATCH": HttpMethod.PATCH,
    "DELETE": HttpMethod.DELETE,
    "OPTIONS": HttpMethod.OPTIONS,
    "HEAD": HttpMethod.HEAD,
}


def convert_route_match(
    match: ProviderMatch,
    fn_by_fqn: dict[str, FunctionRecord],
    router_group_info_by_var: dict[str, RouterGroupInfo] | None = None,
    *,
    idx: CodeIndex | None = None,
) -> tuple[EnrichedRoute | None, tuple[AnalysisGap, ...]]:
    """Convert a route-phase ProviderMatch into a Route domain object.

    Returns ``(route, gaps)`` where ``route`` is ``None`` if required
    arguments are missing or dynamic.  Gaps are always returned even
    when the route is successfully created (e.g. imprecise methods).
    """
    if isinstance(match.descriptor, RouteDecorator):
        return _convert_decorator_route(match, fn_by_fqn, router_group_info_by_var)
    if isinstance(match.descriptor, RouteCallPattern):
        return _convert_call_route(match, fn_by_fqn, router_group_info_by_var)
    if isinstance(match.descriptor, ImperativeRoutePattern):
        return _convert_imperative_route(match, fn_by_fqn, router_group_info_by_var, idx=idx)
    return None, (_unsupported_descriptor_gap(match),)


def _convert_decorator_route(
    match: ProviderMatch,
    fn_by_fqn: dict[str, FunctionRecord],
    router_group_info_by_var: dict[str, RouterGroupInfo] | None = None,
) -> tuple[EnrichedRoute | None, tuple[AnalysisGap, ...]]:
    descriptor = match.descriptor
    assert isinstance(descriptor, RouteDecorator)
    fact = match.source_fact
    assert isinstance(fact, DecoratorFact)

    gaps: list[AnalysisGap] = []

    # Extract URL rule from positional args.
    url_rule = _extract_literal_arg(fact.args, descriptor.rule_arg)
    if url_rule is None:
        return None, (_url_rule_gap(match),)

    # Resolve handler function.
    handler_fn = fn_by_fqn.get(fact.target_fqn)
    if handler_fn is None:
        return None, (_handler_gap(match, fact.target_fqn),)

    # Determine HTTP methods.
    if descriptor.implied_method is not None:
        methods = _parse_methods((descriptor.implied_method,))
    else:
        methods_expr = _find_kwarg(fact.kwargs, descriptor.methods_kwarg)
        if methods_expr is not None:
            parsed = _parse_methods_expr(methods_expr)
            if parsed is not None:
                methods = parsed
            else:
                methods = _parse_methods(descriptor.default_methods)
                gaps.append(_dynamic_methods_gap(match))
        else:
            methods = _parse_methods(descriptor.default_methods)

    # Derive endpoint from handler name.
    endpoint = handler_fn.name

    # Resolve router-group and URL prefix.
    group, url_rule, router_group_variable_fqn = _apply_router_group_metadata(
        match.observed_fqn, url_rule, router_group_info_by_var, gaps
    )

    return _build_route(
        match=match,
        url_rule=url_rule,
        methods=methods,
        handler_fn=handler_fn,
        endpoint=endpoint,
        group=group,
        router_group_variable_fqn=router_group_variable_fqn,
        route_gaps=tuple(gaps),
    ), tuple(gaps)


def _convert_call_route(
    match: ProviderMatch,
    fn_by_fqn: dict[str, FunctionRecord],
    router_group_info_by_var: dict[str, RouterGroupInfo] | None = None,
) -> tuple[EnrichedRoute | None, tuple[AnalysisGap, ...]]:
    descriptor = match.descriptor
    assert isinstance(descriptor, RouteCallPattern)
    fact = match.source_fact
    assert isinstance(fact, CallEdge)

    gaps: list[AnalysisGap] = []

    # Extract URL rule.
    url_rule = _extract_call_arg_literal(fact, position=descriptor.rule_arg, keyword="rule")
    if url_rule is None:
        return None, (_url_rule_gap(match),)

    # Resolve handler via view_func kwarg or positional fallback slot.
    view_func_expr = _find_call_kwarg(fact, descriptor.view_func_kwarg)
    if view_func_expr is None:
        view_func_expr = _find_call_arg_expr(fact, position=2)
    handler_fn = _resolve_handler_function(view_func_expr, fact, fn_by_fqn)
    if handler_fn is None:
        if _is_class_view_factory_call(view_func_expr):
            return None, ()
        target = view_func_expr or "<unknown>"
        return None, (_handler_gap(match, target),)

    endpoint, endpoint_gaps = _resolve_call_endpoint(fact, handler_fn.name)
    gaps.extend(endpoint_gaps)

    methods_expr = _find_call_kwarg(fact, descriptor.methods_kwarg)
    if methods_expr is not None:
        parsed = _parse_methods_expr(methods_expr)
        if parsed is not None:
            methods = parsed
        else:
            methods = _parse_methods(("GET",))
            gaps.append(_dynamic_methods_gap(match))
    else:
        methods = _parse_methods(("GET",))

    # Resolve router-group (blueprint) and URL prefix from the call receiver
    # (e.g. ``bp.add_url_rule(...)`` -> receiver ``...bp``).  Previously this
    # path hard-coded ``group=None``, so every plain-function call route on a
    # blueprint went unattributed (FLAW-166).
    group, url_rule, router_group_variable_fqn = _apply_router_group_metadata(
        match.observed_fqn, url_rule, router_group_info_by_var, gaps
    )

    return _build_route(
        match=match,
        url_rule=url_rule,
        methods=methods,
        handler_fn=handler_fn,
        endpoint=endpoint,
        group=group,
        router_group_variable_fqn=router_group_variable_fqn,
        route_gaps=tuple(gaps),
    ), tuple(gaps)


def _convert_imperative_route(
    match: ProviderMatch,
    fn_by_fqn: dict[str, FunctionRecord],
    router_group_info_by_var: dict[str, RouterGroupInfo] | None = None,
    *,
    idx: CodeIndex | None = None,
) -> tuple[EnrichedRoute | None, tuple[AnalysisGap, ...]]:
    """Convert an ImperativeRoutePattern match into a Route domain object.

    The source fact is a SymbolRef whose ``name`` carries the AST-unparsed
    constructor call expression (e.g. ``Route('/users', list_users)``).
    If the match FQN corresponds to the descriptor's ``nested_fqn``, a gap
    is produced indicating deferred nested route resolution.
    """
    descriptor = match.descriptor
    assert isinstance(descriptor, ImperativeRoutePattern)
    fact = match.source_fact
    assert isinstance(fact, SymbolRef)

    # Check for nested route constructors (e.g. Mount(...)).
    nested_fqns = frozenset(
        _as_tuple_str(descriptor.nested_fqn) if descriptor.nested_fqn is not None else ()
    )
    if match.canonical_fqn in nested_fqns:
        return None, (_nested_route_gap(match),)

    # Parse the constructor call expression stored in the source fact.
    call_node = _parse_call_node(fact.name)
    if call_node is None:
        return None, (_url_rule_gap(match),)

    gaps: list[AnalysisGap] = []

    # Extract URL rule from positional arg.
    url_rule = _extract_ast_arg_literal(call_node, descriptor.rule_arg)
    if url_rule is None:
        return None, (_url_rule_gap(match),)

    # Extract handler from positional arg or keyword arg.
    handler_expr = _extract_ast_arg_expr(call_node, descriptor.view_arg)
    if handler_expr is None:
        handler_expr = _extract_ast_kwarg_expr(call_node, descriptor.view_kwarg)
    handler_fn_rec = _resolve_handler_function_imperative(handler_expr, match, fn_by_fqn, idx=idx)
    if handler_fn_rec is None:
        if _is_class_view_factory_call(handler_expr):
            return None, ()
        target = handler_expr or "<unknown>"
        return None, (_handler_gap(match, target),)

    # Extract methods.
    methods_expr: str | None = None
    if descriptor.methods_kwarg is not None:
        methods_expr = _extract_ast_kwarg_expr(call_node, descriptor.methods_kwarg)
    if methods_expr is not None:
        parsed = _parse_methods_expr(methods_expr)
        if parsed is not None:
            methods = parsed
        else:
            methods = _parse_methods(("GET",))
            gaps.append(_dynamic_methods_gap(match))
    else:
        methods = _parse_methods(("GET",))

    endpoint = handler_fn_rec.name

    group, url_rule, router_group_variable_fqn = _apply_router_group_metadata(
        match.observed_fqn, url_rule, router_group_info_by_var, gaps
    )

    return _build_route(
        match=match,
        url_rule=url_rule,
        methods=methods,
        handler_fn=handler_fn_rec,
        endpoint=endpoint,
        group=group,
        router_group_variable_fqn=router_group_variable_fqn,
        route_gaps=tuple(gaps),
    ), tuple(gaps)


def _parse_call_node(expression: str) -> ast.Call | None:
    """Parse a source expression and return its Call AST node, or None."""
    tree = _parse_expression(expression)
    if tree is None:
        return None
    node = tree.body
    if isinstance(node, ast.Call):
        return node
    return None


def _is_class_view_factory_call(expression: str | None) -> bool:
    """Return True for ``ClassName.as_view(...)`` handler factories.

    These calls produce callable route handlers at runtime, but the callable is
    not an indexed function.  ``ClassViewPattern`` conversion correlates the
    factory call with the matching class and emits method-scoped routes, so the
    plain function-route converter should not report a duplicate handler gap.
    """
    if expression is None:
        return False
    node = _parse_call_node(expression)
    if node is None:
        return False
    return isinstance(node.func, ast.Attribute) and node.func.attr == "as_view"


def _extract_ast_arg_literal(call_node: ast.Call, position: int) -> str | None:
    """Extract a literal string from a positional argument of an AST Call."""
    if position >= len(call_node.args):
        return None
    return _try_ast_literal_string(call_node.args[position])


def _extract_ast_arg_expr(call_node: ast.Call, position: int) -> str | None:
    """Extract the unparsed expression of a positional arg from an AST Call."""
    if position >= len(call_node.args):
        return None
    return ast.unparse(call_node.args[position])


def _extract_ast_kwarg_expr(call_node: ast.Call, keyword: str) -> str | None:
    """Extract the unparsed expression of a keyword arg from an AST Call."""
    for kw in call_node.keywords:
        if kw.arg == keyword:
            return ast.unparse(kw.value)
    return None


def _resolve_handler_function_imperative(
    expression: str | None,
    match: ProviderMatch,
    fn_by_fqn: dict[str, FunctionRecord],
    *,
    idx: CodeIndex | None = None,
) -> FunctionRecord | None:
    """Resolve an imperative-route handler expression to an indexed function.

    Resolution strategies, in order:
    1. Direct FQN lookup in the function map.
    2. Same-file bare-name matching for simple identifiers.
    3. Dotted-name resolution via the L1 symbol table (e.g.
       ``views.index`` → resolve ``views`` to its module FQN, then
       look up ``{module}.index`` in the function map).

    Call expressions (e.g. ``ClassName.as_view()``) are skipped — those
    are handled by ``ClassViewPattern`` conversion.
    """
    if expression is None:
        return None

    direct = fn_by_fqn.get(expression)
    if direct is not None:
        return direct

    simple = _simple_name(expression)
    if simple is not None:
        same_file_matches = tuple(
            fn
            for fn in fn_by_fqn.values()
            if fn.file == match.location.file and fn.name == simple and not fn.is_method
        )
        if len(same_file_matches) == 1:
            return same_file_matches[0]

    if idx is not None and "." in expression:
        return _resolve_dotted_handler(expression, match.location.file, fn_by_fqn, idx)

    return None


def _resolve_dotted_handler(
    expression: str,
    file: str,
    fn_by_fqn: dict[str, FunctionRecord],
    idx: CodeIndex,
) -> FunctionRecord | None:
    """Resolve a dotted handler expression like ``views.index`` via the symbol table.

    Parses the expression as AST, rejects call expressions (class-view
    factories like ``Views.as_view()``), then resolves the leading name
    through L1 symbol references and looks up the reconstructed FQN.
    """
    tree = _parse_expression(expression)
    if tree is None:
        return None
    node = tree.body

    # Class-view factory calls are handled by ClassViewPattern.
    if isinstance(node, ast.Call):
        return None

    if not isinstance(node, ast.Attribute):
        return None

    # Collect name parts: views.submod.func → ["views", "submod", "func"]
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    parts.reverse()

    resolved_head = idx.symbols.resolve(parts[0], file)
    if resolved_head is None:
        return None

    resolved_fqn = ".".join([resolved_head, *parts[1:]])
    return fn_by_fqn.get(resolved_fqn)


def _as_tuple_str(value: str | tuple[str, ...]) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    return value


def _nested_route_gap(match: ProviderMatch) -> AnalysisGap:
    loc = match.location
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=(
            f"Nested/mounted route group at {loc.file}:{loc.line} "
            f"requires recursive resolution (deferred)"
        ),
        affected_file=loc.file,
        source_error="route_conversion: nested route pattern not yet resolved",
        origin_phase="route_conversion",
        origin_provider=match.provider_id,
    )


def _build_route(
    *,
    match: ProviderMatch,
    url_rule: str,
    methods: frozenset[HttpMethod],
    handler_fn: FunctionRecord,
    endpoint: str,
    group: str | None,
    router_group_variable_fqn: str | None,
    route_gaps: tuple[AnalysisGap, ...],
) -> EnrichedRoute:
    """Construct an EnrichedRoute from conversion results."""
    from flawed._semantic._conversion import convert_function

    handler = convert_function(handler_fn)
    loc = match.location
    route = EnrichedRoute(
        endpoint=endpoint,
        url_rule=url_rule,
        methods=methods,
        handler=handler,
        group=group,
        location=Location(
            file=loc.file,
            line=loc.line,
            column=loc.column,
            end_line=loc.end_line,
            end_column=loc.end_column,
        ),
        provenance=_ROUTE_PROVENANCE,
    )
    object.__setattr__(route, "_gaps", (*match.predicate_gaps, *route_gaps))
    object.__setattr__(route, "_provider_id", match.provider_id)
    object.__setattr__(route, "_router_group_variable_fqn", router_group_variable_fqn)
    return route


# =====================================================================
# ClassViewPattern conversion (class-based views with verb dispatch)
# =====================================================================


def convert_class_view_matches(
    matches: tuple[ProviderMatch, ...],
    idx: CodeIndex,
    fn_by_fqn: dict[str, FunctionRecord],
    router_group_info_by_var: Mapping[str, RouterGroupInfo] | None = None,
) -> tuple[tuple[EnrichedRoute, ...], tuple[AnalysisGap, ...]]:
    """Convert ClassViewPattern matches into routes via route-call correlation.

    Each ClassViewPattern match represents a class-based view subclass.
    We find ``RouteCallPattern`` registrations whose view-func argument
    contains ``ClassName.<as_view_method>("endpoint")``, then create one
    route per effective HTTP method with scopes constrained to the matching
    class method body.  This keeps POST/PUT/DELETE analysis from inheriting
    the GET handler body on frameworks that dispatch class views by verb.
    """
    routes: list[EnrichedRoute] = []
    gaps: list[AnalysisGap] = []
    class_by_fqn = {class_.fqn: class_ for class_ in idx.classes}

    # Collect the as_view_method name from each descriptor to support
    # frameworks that use different factory method names.
    view_method_names: set[str] = set()
    for match in matches:
        if isinstance(match.descriptor, ClassViewPattern):
            view_method_names.add(match.descriptor.as_view_method)

    registrations = _find_class_view_registrations(
        idx, frozenset(view_method_names), router_group_info_by_var
    )

    for match in matches:
        if not isinstance(match.descriptor, ClassViewPattern):
            continue
        match_routes, match_gaps = _convert_class_view_match(
            match,
            match.descriptor,
            registrations,
            fn_by_fqn,
            class_by_fqn,
        )
        routes.extend(match_routes)
        gaps.extend(match_gaps)

    return tuple(routes), tuple(gaps)


def _convert_class_view_match(
    match: ProviderMatch,
    descriptor: ClassViewPattern,
    registrations: tuple[_ClassViewRegistration, ...],
    fn_by_fqn: dict[str, FunctionRecord],
    class_by_fqn: dict[str, ClassRecord],
) -> tuple[tuple[EnrichedRoute, ...], tuple[AnalysisGap, ...]]:
    """Convert one class-view descriptor match to method-specific routes."""
    class_fqn = match.observed_fqn
    class_name = class_fqn.rsplit(".", 1)[-1]
    handlers_by_method = _class_http_method_handlers(
        class_fqn,
        fn_by_fqn,
        descriptor.method_map,
        class_by_fqn,
    )
    class_methods = frozenset(handlers_by_method)
    exact_registrations = tuple(reg for reg in registrations if reg.class_fqn == class_fqn)
    unresolved_registrations = tuple(
        reg for reg in registrations if reg.class_fqn is None and reg.class_name == class_name
    )
    class_registrations = exact_registrations
    if not class_registrations and unresolved_registrations:
        same_name_classes = tuple(
            sorted(class_.fqn for class_ in class_by_fqn.values() if class_.name == class_name)
        )
        if len(same_name_classes) > 1:
            return (), (
                _ambiguous_class_view_registration_gap(match, class_name, same_name_classes),
            )
        class_registrations = unresolved_registrations
    if not class_registrations:
        return (), (_no_registration_gap(match),)

    routes: list[EnrichedRoute] = []
    gaps: list[AnalysisGap] = []
    for reg in class_registrations:
        reg_routes, reg_gaps = _convert_class_view_registration(
            match,
            descriptor,
            reg,
            class_fqn=class_fqn,
            class_name=class_name,
            class_methods=class_methods,
            handlers_by_method=handlers_by_method,
        )
        routes.extend(reg_routes)
        gaps.extend(reg_gaps)
    return tuple(routes), tuple(gaps)


def _convert_class_view_registration(
    match: ProviderMatch,
    descriptor: ClassViewPattern,
    reg: _ClassViewRegistration,
    *,
    class_fqn: str,
    class_name: str,
    class_methods: frozenset[HttpMethod],
    handlers_by_method: dict[HttpMethod, FunctionRecord],
) -> tuple[tuple[EnrichedRoute, ...], tuple[AnalysisGap, ...]]:
    """Convert one class-view registration to per-method route objects."""
    gaps: list[AnalysisGap] = []
    reg_methods = None
    if reg.methods_expr is not None:
        reg_methods = _parse_methods_expr(reg.methods_expr)
        if reg_methods is None:
            gaps.append(_dynamic_methods_gap(match))
    requested_methods = reg_methods if reg_methods is not None else class_methods

    missing_methods = requested_methods - class_methods
    if missing_methods:
        gaps.append(_missing_method_handler_gap(match, class_fqn, missing_methods))

    effective_methods = requested_methods & class_methods
    if not effective_methods:
        return (), (*gaps, _handler_gap(match, class_fqn))

    # Attribute the route to its blueprint group and apply the group's URL
    # prefix (FLAW-166).  ``reg.group_info`` is resolved at registration-parse
    # time from the call receiver or a blueprint argument.
    group_gaps: list[AnalysisGap] = []
    if reg.group_info is not None:
        url_rule = _apply_group_prefix(reg.url_rule, reg.group_info, group_gaps)
        group = reg.group_info.group
        router_group_variable_fqn: str | None = reg.group_info.variable_fqn
    else:
        url_rule = reg.url_rule
        group = None
        router_group_variable_fqn = None

    routes = tuple(
        _build_route(
            match=match,
            url_rule=url_rule,
            methods=frozenset({method}),
            handler_fn=handlers_by_method[method],
            endpoint=reg.endpoint or class_name.lower(),
            group=group,
            router_group_variable_fqn=router_group_variable_fqn,
            route_gaps=tuple(group_gaps),
        )
        for method in _ordered_methods(descriptor.method_map)
        if method in effective_methods
    )
    return routes, tuple(gaps)


class _ClassViewRegistration:
    """Parsed imperative route-call site for a class-based view."""

    __slots__ = (
        "class_fqn",
        "class_name",
        "endpoint",
        "group_info",
        "line",
        "methods_expr",
        "url_rule",
    )

    def __init__(
        self,
        *,
        url_rule: str,
        class_name: str,
        class_fqn: str | None = None,
        endpoint: str | None,
        methods_expr: str | None,
        line: int,
        group_info: RouterGroupInfo | None = None,
    ) -> None:
        self.url_rule = url_rule
        self.class_name = class_name
        self.class_fqn = class_fqn
        self.endpoint = endpoint
        self.methods_expr = methods_expr
        self.line = line
        # Router-group (blueprint) the registration call attributes the route
        # to — resolved from the call receiver or a blueprint argument at the
        # registration call site (FLAW-166).
        self.group_info = group_info


def _find_class_view_registrations(
    idx: CodeIndex,
    view_method_names: frozenset[str],
    router_group_info_by_var: Mapping[str, RouterGroupInfo] | None = None,
) -> tuple[_ClassViewRegistration, ...]:
    """Find route-call registrations that wire class-based views.

    Scans both module-level value-flow ARGUMENT edges and call graph
    edges for calls whose arguments contain a
    ``ClassName.<view_method>("endpoint")`` expression.

    Each call site also records the enclosing function (``caller_fqn``) and
    the call receiver (``receiver_fqn``) so the route can be attributed to its
    router group (blueprint): the receiver of a direct ``bp.add_url_rule(...)``
    or a blueprint passed as an argument to a registration wrapper such as
    ``register_view(bp, routes=[...], view_func=...)`` (FLAW-166).
    """
    # RouteCallPattern registrations appear as value-flow ARGUMENT edges
    # or call graph edges.  We collect all call-site arguments grouped
    # by (file, line) without hardcoding any particular method suffix.
    call_site_args: dict[tuple[str, int], list[str]] = {}
    # Per call site: enclosing function FQN and call receiver FQN (for group
    # attribution).  Call-graph edges (in-function calls) supply both; module
    # level value-flow edges leave them None.
    call_site_caller: dict[tuple[str, int], str | None] = {}
    call_site_receiver: dict[tuple[str, int], str | None] = {}

    for edge in idx.value_flow.edges:
        if edge.kind is not FlowKind.ARGUMENT or edge.containing_function_fqn is not None:
            continue
        # Check if any argument in this call site references a view factory.
        key = (edge.target_location.file, edge.target_location.line)
        call_site_args.setdefault(key, []).append(edge.source_expr)
        call_site_caller.setdefault(key, None)
        call_site_receiver.setdefault(key, None)

    # Also check call graph edges (for in-function route-call registrations).
    for call_edge in idx.call_graph.edges:
        if call_edge.callee_fqn is None:
            continue
        key = (call_edge.location.file, call_edge.location.line)
        args_list = call_site_args.setdefault(key, [])
        for a in call_edge.arguments:
            args_list.append(a.expression)
        # Prefer the call-graph edge's structural info (overwrite module-level
        # None placeholders): the caller is the enclosing function and the
        # receiver is the callee FQN minus its method segment.
        call_site_caller[key] = call_edge.caller_fqn
        call_site_receiver[key] = _call_receiver_fqn(call_edge.callee_fqn)

    module_by_file = _module_fqns_by_file(idx)
    registrations: list[_ClassViewRegistration] = []
    for (file, line), args in sorted(call_site_args.items()):
        reg = _parse_class_view_registration_args(
            args,
            line,
            view_method_names,
            file=file,
            idx=idx,
            caller_fqn=call_site_caller.get((file, line)),
            receiver_fqn=call_site_receiver.get((file, line)),
            module_fqn=module_by_file.get(file),
            router_group_info_by_var=router_group_info_by_var,
        )
        if reg is not None:
            registrations.append(reg)

    return tuple(registrations)


def _call_receiver_fqn(callee_fqn: str | None) -> str | None:
    """Return the receiver FQN of a method-call callee (``a.b.m`` -> ``a.b``)."""
    if callee_fqn is None or "." not in callee_fqn:
        return None
    return callee_fqn.rsplit(".", maxsplit=1)[0]


def _resolve_registration_group(
    group_var_names: list[str],
    *,
    caller_fqn: str | None,
    receiver_fqn: str | None,
    module_fqn: str | None,
    router_group_info_by_var: Mapping[str, RouterGroupInfo] | None,
) -> RouterGroupInfo | None:
    """Resolve a class-view registration to its router group (blueprint).

    Candidate variable FQNs, in priority order:
    1. the call receiver (``bp.add_url_rule(...)`` -> ``...bp``);
    2. for each bare-name registration argument ``n`` (e.g. the ``bp`` passed to
       ``register_view(bp, ...)``): the enclosing-function local
       ``{caller_fqn}.<locals>.{n}`` and the module-level ``{module_fqn}.{n}``.

    Falls back to a unique same-leaf match (see ``_router_group_for_receiver``).
    """
    if not router_group_info_by_var:
        return None

    info = _router_group_for_receiver(receiver_fqn, router_group_info_by_var)
    if info is not None:
        return info

    for name in group_var_names:
        candidates = []
        if caller_fqn is not None:
            candidates.append(f"{caller_fqn}.<locals>.{name}")
        if module_fqn is not None:
            candidates.append(f"{module_fqn}.{name}")
        for candidate in candidates:
            found = router_group_info_by_var.get(candidate)
            if found is not None:
                return found
        leaf_match = _router_group_for_receiver(name, router_group_info_by_var)
        if leaf_match is not None:
            return leaf_match

    return None


def _parse_class_view_registration_args(
    args: list[str],
    line: int,
    view_method_names: frozenset[str],
    *,
    file: str | None = None,
    idx: CodeIndex | None = None,
    caller_fqn: str | None = None,
    receiver_fqn: str | None = None,
    module_fqn: str | None = None,
    router_group_info_by_var: Mapping[str, RouterGroupInfo] | None = None,
) -> _ClassViewRegistration | None:
    """Parse route-call arguments into a class-view registration record.

    Looks for: a literal URL string (or a single-element list containing
    one, e.g. ``routes=["/path"]``), a ``ClassName.<view_method>("endpoint")``
    expression, and an optional methods list.
    """
    url_rule: str | None = None
    class_name: str | None = None
    class_fqn: str | None = None
    endpoint: str | None = None
    methods_expr: str | None = None

    for a in args:
        view_class, view_class_fqn, view_endpoint = _parse_view_factory_expr(
            a,
            view_method_names,
            file=file,
            idx=idx,
        )
        if view_class is not None:
            class_name = view_class
            class_fqn = view_class_fqn
            endpoint = view_endpoint
            continue

        literal = _try_literal_string(a)
        if literal is not None and url_rule is None:
            url_rule = literal
            continue

        list_val = _try_literal_list(a)
        if list_val is not None:
            # Distinguish URL-path lists (routes=["/path"]) from HTTP
            # method lists (methods=["GET", "POST"]).  URL paths start
            # with "/" — HTTP methods never do.
            if url_rule is None and _is_url_list(list_val):
                url_rule = list_val[0]
            else:
                methods_expr = a
            continue

    if url_rule is None or class_name is None:
        return None

    # Attribute the route to its router group (blueprint): the call receiver
    # (``bp.add_url_rule``) or a bare-name blueprint argument passed to a
    # registration wrapper (``register_view(bp, ...)``) (FLAW-166).
    group_var_names = [name for a in args if (name := _simple_name(a)) is not None]
    group_info = _resolve_registration_group(
        group_var_names,
        caller_fqn=caller_fqn,
        receiver_fqn=receiver_fqn,
        module_fqn=module_fqn,
        router_group_info_by_var=router_group_info_by_var,
    )

    return _ClassViewRegistration(
        url_rule=url_rule,
        class_name=class_name,
        class_fqn=class_fqn,
        endpoint=endpoint,
        methods_expr=methods_expr,
        line=line,
        group_info=group_info,
    )


def _is_url_list(values: list[str]) -> bool:
    """Return True when *values* is a single-element list containing a URL path."""
    return len(values) == 1 and values[0].startswith("/")


def _parse_view_factory_expr(
    expression: str,
    view_method_names: frozenset[str],
    *,
    file: str | None = None,
    idx: CodeIndex | None = None,
) -> tuple[str | None, str | None, str | None]:
    """Parse ClassName.<view_method>("endpoint").

    Returns ``(short_class_name, resolved_class_fqn, endpoint)``.  The FQN is
    resolved through the L1 symbol table when available so registrations for
    classes sharing a short name do not cross-associate.
    """
    tree = _parse_expression(expression)
    if tree is None:
        return None, None, None
    node = tree.body
    if not isinstance(node, ast.Call):
        return None, None, None
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr not in view_method_names:
        return None, None, None
    class_parts = _attribute_name_parts(func.value)
    if class_parts is None:
        return None, None, None

    class_name = class_parts[-1]
    class_fqn = _resolve_class_view_factory_fqn(class_parts, file=file, idx=idx)
    endpoint: str | None = None
    if node.args:
        endpoint = _try_ast_literal_string(node.args[0])

    return class_name, class_fqn, endpoint


def _attribute_name_parts(node: ast.expr) -> tuple[str, ...] | None:
    """Return dotted-name parts for a Name/Attribute expression."""
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    parts.reverse()
    return tuple(parts)


def _resolve_class_view_factory_fqn(
    class_parts: tuple[str, ...],
    *,
    file: str | None,
    idx: CodeIndex | None,
) -> str | None:
    """Resolve the class portion of ``ClassName.as_view()`` to an FQN."""
    if idx is None or file is None:
        return None

    written_name = ".".join(class_parts)
    resolved = idx.symbols.resolve(written_name, file)
    if resolved is not None:
        return resolved

    resolved_head = idx.symbols.resolve(class_parts[0], file)
    if resolved_head is not None:
        return ".".join((resolved_head, *class_parts[1:]))

    if len(class_parts) != 1:
        return None

    local_classes = tuple(class_.fqn for class_ in idx.classes if class_.file == file)
    matching_local = tuple(
        fqn for fqn in local_classes if fqn.rsplit(".", maxsplit=1)[-1] == class_parts[0]
    )
    if len(matching_local) == 1:
        return matching_local[0]
    return None


def _try_ast_literal_string(node: ast.expr) -> str | None:
    """Extract a literal string from an AST expression node."""
    try:
        value = ast.literal_eval(node)
    except (SyntaxError, ValueError):
        return None
    return value if isinstance(value, str) else None


def _try_literal_list(expression: str) -> list[str] | None:
    """Parse an expression as a literal list of strings."""
    try:
        value = ast.literal_eval(expression)
    except (SyntaxError, ValueError):
        return None
    if isinstance(value, list | tuple | set):
        return [str(v) for v in value]
    return None


def _class_http_method_handlers(
    class_fqn: str,
    fn_by_fqn: dict[str, FunctionRecord],
    method_map: dict[str, str],
    class_by_fqn: dict[str, ClassRecord],
) -> dict[HttpMethod, FunctionRecord]:
    """Return implemented HTTP methods and their class-view handler functions."""
    handlers: dict[HttpMethod, FunctionRecord] = {}
    class_record = class_by_fqn.get(class_fqn)
    for method_name, http_verb in method_map.items():
        method = _HTTP_METHOD_MAP.get(http_verb.upper())
        if method is None:
            continue

        fn = fn_by_fqn.get(f"{class_fqn}.{method_name}")
        if fn is None and class_record is not None:
            fn = _inherited_method_handler(class_record, method_name, fn_by_fqn)
        if fn is not None:
            handlers[method] = fn
    return handlers


def _inherited_method_handler(
    class_record: ClassRecord,
    method_name: str,
    fn_by_fqn: dict[str, FunctionRecord],
) -> FunctionRecord | None:
    """Return the inherited handler implementation for *method_name*, if known."""
    for inherited in class_record.inherited_methods:
        if inherited.name != method_name:
            continue
        return fn_by_fqn.get(f"{inherited.defining_class_fqn}.{method_name}")
    return None


def _ordered_methods(method_map: dict[str, str]) -> tuple[HttpMethod, ...]:
    """Return provider-declared HTTP methods in deterministic dispatch order."""
    methods: list[HttpMethod] = []
    for http_verb in method_map.values():
        method = _HTTP_METHOD_MAP.get(http_verb.upper())
        if method is not None and method not in methods:
            methods.append(method)
    return tuple(methods)


def _no_registration_gap(match: ProviderMatch) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.SYMBOL_UNRESOLVED,
        message=(f"Class-based view {match.observed_fqn} has no route-call registration"),
        affected_file=match.location.file,
        source_error="class_view_conversion: no route-call registration found",
        origin_phase="route_conversion",
        origin_provider=match.provider_id,
    )


def _ambiguous_class_view_registration_gap(
    match: ProviderMatch,
    class_name: str,
    candidates: tuple[str, ...],
) -> AnalysisGap:
    candidate_names = ", ".join(candidates)
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=(
            f"Class-based view registration for {class_name} is ambiguous; "
            f"resolve via L1 symbol table before associating candidates: {candidate_names}"
        ),
        affected_file=match.location.file,
        source_error="class_view_conversion: ambiguous short-name registration",
        origin_phase="route_conversion",
        origin_provider=match.provider_id,
    )


def _missing_method_handler_gap(
    match: ProviderMatch,
    class_fqn: str,
    methods: frozenset[HttpMethod],
) -> AnalysisGap:
    method_names = ", ".join(sorted(method.value for method in methods))
    return AnalysisGap(
        kind=GapKind.SYMBOL_UNRESOLVED,
        message=f"Class-based view {class_fqn} has no handler for method(s): {method_names}",
        affected_file=match.location.file,
        source_error="class_view_conversion: registered method has no handler",
        origin_phase="route_conversion",
        origin_provider=match.provider_id,
    )


# =====================================================================
# Router group metadata helpers
# =====================================================================


def _apply_router_group_metadata(
    observed_fqn: str,
    url_rule: str,
    router_group_info_by_var: dict[str, RouterGroupInfo] | None,
    gaps: list[AnalysisGap],
) -> tuple[str | None, str, str | None]:
    """Resolve router-group and prepend URL prefix.

    The ``observed_fqn`` for a decorator like ``@bp.route("/path")``
    looks like ``mymodule.bp.route``.  The group variable FQN is
    the prefix before the method name: ``mymodule.bp``.

    Returns ``(group, url_rule, router_group_variable_fqn)`` with prefix
    prepended if applicable.
    """
    if not router_group_info_by_var:
        return None, url_rule, None

    # The observed FQN is e.g. "mymodule.bp.route" — strip the method.
    receiver_fqn = observed_fqn.rsplit(".", maxsplit=1)[0] if "." in observed_fqn else None
    info = _router_group_for_receiver(receiver_fqn, router_group_info_by_var)
    if info is None:
        return None, url_rule, None

    return info.group, _apply_group_prefix(url_rule, info, gaps), info.variable_fqn


def _router_group_for_receiver(
    receiver_fqn: str | None,
    router_group_info_by_var: Mapping[str, RouterGroupInfo] | None,
) -> RouterGroupInfo | None:
    """Resolve a receiver/variable FQN to its router-group info.

    Tries an exact ``variable_fqn`` match first, then falls back to a unique
    same-leaf match (mirrors the lifecycle-hook resolver) so a receiver that L1
    resolved structurally but not back to the original assignment FQN — e.g. an
    imported package-level ``bp`` — still attributes when the leaf name is
    unambiguous.
    """
    if not receiver_fqn or not router_group_info_by_var:
        return None
    info = router_group_info_by_var.get(receiver_fqn)
    if info is not None:
        return info
    leaf = receiver_fqn.rsplit(".", maxsplit=1)[-1]
    same_leaf = [
        candidate
        for variable_fqn, candidate in router_group_info_by_var.items()
        if variable_fqn.rsplit(".", maxsplit=1)[-1] == leaf
    ]
    return same_leaf[0] if len(same_leaf) == 1 else None


def _apply_group_prefix(
    url_rule: str,
    info: RouterGroupInfo,
    gaps: list[AnalysisGap],
) -> str:
    """Record router-group gaps and prepend the group's URL prefix, if any."""
    gaps.extend(info.group_gaps)
    gaps.extend(info.prefix_gaps)
    if info.url_prefix is not None:
        prefix = info.url_prefix.rstrip("/")
        if prefix:
            return f"{prefix}{url_rule}"
    return url_rule


# =====================================================================
# Argument extraction helpers
# =====================================================================


def _extract_literal_arg(args: tuple[str, ...], position: int) -> str | None:
    """Extract a literal string value from decorator positional args."""
    if position >= len(args):
        return None
    return _try_literal_string(args[position])


def _extract_call_arg_literal(
    edge: CallEdge,
    *,
    position: int,
    keyword: str | None = None,
) -> str | None:
    """Extract a literal string from a call edge positional or keyword argument."""
    arg = _find_call_arg(edge, position=position, keyword=keyword)
    if arg is None:
        return None
    return _try_literal_string(arg.expression)


def _find_kwarg(
    kwargs: tuple[tuple[str, str], ...],
    name: str,
) -> str | None:
    """Find a keyword argument value expression by name."""
    for kw_name, kw_value in kwargs:
        if kw_name == name:
            return kw_value
    return None


def _find_call_kwarg(edge: CallEdge, name: str) -> str | None:
    """Find a keyword argument expression from a call edge."""
    for arg in edge.arguments:
        if arg.keyword == name:
            return arg.expression
    return None


def _find_call_arg_expr(edge: CallEdge, *, position: int) -> str | None:
    """Find a positional argument expression from a call edge."""
    arg = _find_call_arg(edge, position=position, keyword=None)
    return arg.expression if arg is not None else None


def _find_call_arg(
    edge: CallEdge,
    *,
    position: int,
    keyword: str | None,
) -> CallArgument | None:
    """Find a call argument by positional index, falling back to keyword."""
    for arg in edge.arguments:
        if arg.position == position:
            return arg
    if keyword is None:
        return None
    for arg in edge.arguments:
        if arg.keyword == keyword:
            return arg
    return None


def _resolve_handler_function(
    expression: str | None,
    edge: CallEdge,
    fn_by_fqn: dict[str, FunctionRecord],
) -> FunctionRecord | None:
    """Resolve a call-route handler expression to an indexed function."""
    if expression is None:
        return None

    direct = fn_by_fqn.get(expression)
    if direct is not None:
        return direct

    simple_name = _simple_name(expression)
    if simple_name is None:
        return None

    same_file_matches = tuple(
        fn
        for fn in fn_by_fqn.values()
        if fn.file == edge.location.file and fn.name == simple_name and not fn.is_method
    )
    if len(same_file_matches) == 1:
        return same_file_matches[0]
    return None


def _resolve_call_endpoint(
    edge: CallEdge,
    default_endpoint: str,
) -> tuple[str, tuple[AnalysisGap, ...]]:
    """Resolve route-call endpoint from keyword or positional arg."""
    endpoint_expr = _find_call_kwarg(edge, "endpoint")
    if endpoint_expr is None:
        endpoint_expr = _find_call_arg_expr(edge, position=1)
    if endpoint_expr is None:
        return default_endpoint, ()

    literal = _try_literal_string(endpoint_expr)
    if literal is not None:
        return literal, ()

    if _is_none_literal(endpoint_expr):
        return default_endpoint, ()

    return default_endpoint, (_dynamic_endpoint_gap(edge, endpoint_expr),)


def _try_literal_string(expression: str) -> str | None:
    """Parse a source expression as a literal string, or None."""
    # Handle trailing comma from decorator arg extraction.
    expr = expression.rstrip(",").strip()
    try:
        value = ast.literal_eval(expr)
    except (SyntaxError, ValueError):
        return None
    return value if isinstance(value, str) else None


def _is_none_literal(expression: str) -> bool:
    """Return True when expression is the literal None."""
    try:
        value = ast.literal_eval(expression.strip())
    except (SyntaxError, ValueError):
        return False
    return value is None


def _parse_methods_expr(expression: str) -> frozenset[HttpMethod] | None:
    """Parse a methods= expression like '["GET", "POST"]'."""
    try:
        value = ast.literal_eval(expression)
    except (SyntaxError, ValueError):
        return None
    if isinstance(value, list | tuple | set):
        return _parse_methods(tuple(value))
    return None


def _parse_methods(names: tuple[str, ...]) -> frozenset[HttpMethod]:
    """Convert method name strings to HttpMethod frozenset."""
    methods: set[HttpMethod] = set()
    for name in names:
        method = _HTTP_METHOD_MAP.get(name.upper())
        if method is not None:
            methods.add(method)
    return frozenset(methods) if methods else frozenset({HttpMethod.GET})


# =====================================================================
# Gap constructors
# =====================================================================


def _url_rule_gap(match: ProviderMatch) -> AnalysisGap:
    loc = match.location
    return AnalysisGap(
        kind=GapKind.INTERPRETER_ERROR,
        message=f"Could not extract URL rule from route at {loc.file}:{loc.line}",
        affected_file=loc.file,
        source_error="route_conversion: missing or dynamic URL rule argument",
        origin_phase="route_conversion",
        origin_provider=match.provider_id,
    )


def _handler_gap(match: ProviderMatch, target_fqn: str) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.SYMBOL_UNRESOLVED,
        message=f"Route handler function not found: {target_fqn}",
        affected_file=match.location.file,
        source_error="route_conversion: handler function not in index",
        origin_phase="route_conversion",
        origin_provider=match.provider_id,
    )


def _dynamic_methods_gap(match: ProviderMatch) -> AnalysisGap:
    loc = match.location
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=f"Dynamic methods= at {loc.file}:{loc.line}; using defaults",
        affected_file=loc.file,
        source_error="route_conversion: non-literal methods kwarg",
        origin_phase="route_conversion",
        origin_provider=match.provider_id,
    )


def _dynamic_endpoint_gap(edge: CallEdge, expression: str) -> AnalysisGap:
    loc = edge.location
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=f"Dynamic endpoint= at {loc.file}:{loc.line}; using handler name",
        affected_file=loc.file,
        source_error=f"route_conversion: non-literal endpoint argument {expression!r}",
        origin_phase="route_conversion",
    )


def _unsupported_descriptor_gap(match: ProviderMatch) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INTERPRETER_ERROR,
        message=f"Unsupported route descriptor type: {type(match.descriptor).__name__}",
        affected_file=match.location.file,
        source_error="route_conversion: descriptor not yet implemented",
        origin_phase="route_conversion",
        origin_provider=match.provider_id,
    )


__all__ = ["convert_route_match"]
