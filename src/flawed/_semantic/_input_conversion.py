"""Convert provider input matches into public InputRead observations."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from flawed._index._types import (
    AccessKind,
    AttributeAccess,
    CallArgument,
    CallEdge,
    FlowKind,
    ParameterKind,
)
from flawed._semantic._conversion_utils import (
    call_expression as _call_expression,
)
from flawed._semantic._conversion_utils import (
    call_target_expression as _call_target_expression,
)
from flawed._semantic._conversion_utils import (
    conversion_gap as _conversion_gap,
)
from flawed._semantic._conversion_utils import (
    fact_function as _fact_function,
)
from flawed._semantic._conversion_utils import (
    literal_string as _literal_string,
)
from flawed._semantic._conversion_utils import (
    location as _location,
)
from flawed._semantic._conversion_utils import (
    simple_name as _simple_name,
)
from flawed._semantic._conversion_utils import (
    span_starts_not_after as _span_starts_not_after,
)
from flawed._semantic._expr_cache import parse_expression as _parse_expression
from flawed._semantic._provider_engine import ParameterFact
from flawed._semantic.providers import (
    ClaimContainerPattern,
    InputAttributePattern,
    InputContainerPattern,
    InputFieldAccessPattern,
    InputMethodPattern,
    InputParameterPattern,
)
from flawed.core import AnalysisGap, GapKind, JsonPath, Key, Provenance
from flawed.inputs import (
    AccessPattern,
    Cardinality,
    Cookie,
    FileUpload,
    Form,
    FrameworkGlobal,
    Header,
    InputRead,
    InputSource,
    InputValueType,
    Json,
    PathParam,
    ProviderClaim,
    Query,
    RawBody,
    SessionValue,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from flawed._index import CodeIndex
    from flawed._index._types import FunctionRecord, SourceSpan
    from flawed._semantic._provider_engine import ProviderMatch
    from flawed.function import Function
    from flawed.route import Route


_L2_INPUT_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="provider_inputs",
    confidence=0.95,
    supporting_facts=("provider input descriptor matched L1 structural fact",),
)
_PATH_PARAM_RE = re.compile(
    r"<(?:(?P<converter>[^:<>]+):)?(?P<angle>[A-Za-z_][A-Za-z0-9_]*)>"
    r"|\{(?P<brace>[A-Za-z_][A-Za-z0-9_]*)\}"
)
_ROUTE_CONVERTER_VALUE_TYPES = {
    "any": InputValueType.STRING,
    "float": InputValueType.FLOAT,
    "int": InputValueType.INTEGER,
    "path": InputValueType.STRING,
    "string": InputValueType.STRING,
    "uuid": InputValueType.UUID,
}


@dataclass(frozen=True)
class InputConversionResult:
    """Converted input reads and non-fatal conversion gaps."""

    reads: tuple[InputRead, ...]
    gaps: tuple[AnalysisGap, ...] = ()


@dataclass(frozen=True)
class _ContainerExpression:
    expression: str
    available_from: SourceSpan


@dataclass(frozen=True)
class _CardinalityResult:
    cardinality: Cardinality
    gaps: tuple[AnalysisGap, ...] = ()


@dataclass(frozen=True)
class _PathParamSpec:
    name: str
    converter: str | None
    uses_angle_syntax: bool


def convert_input_match(  # noqa: PLR0911  — one return per input descriptor type
    match: ProviderMatch,
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> InputConversionResult:
    """Convert one INPUTS-phase provider match into InputRead observations."""
    descriptor = match.descriptor
    if isinstance(descriptor, InputAttributePattern):
        return _convert_attribute_match(match, descriptor, idx, functions_by_fqn)
    if isinstance(descriptor, InputContainerPattern):
        return _convert_container_input_match(match, descriptor, idx, functions_by_fqn)
    if isinstance(descriptor, InputMethodPattern):
        return _convert_method_match(match, descriptor, idx, functions_by_fqn)
    if isinstance(descriptor, InputFieldAccessPattern):
        return _convert_field_access_match(match, descriptor, functions_by_fqn)
    if isinstance(descriptor, InputParameterPattern):
        return _convert_parameter_match(match, descriptor, functions_by_fqn)
    if isinstance(descriptor, ClaimContainerPattern):
        return _convert_claim_container_match(match, descriptor, idx, functions_by_fqn)
    return InputConversionResult(
        reads=(),
        gaps=(
            AnalysisGap(
                kind=GapKind.INTERPRETER_ERROR,
                message=f"Unsupported input descriptor: {type(descriptor).__name__}",
                affected_file=match.location.file,
                affected_function=_fact_function(match),
                source_error="input_conversion: unsupported descriptor",
                origin_phase="input_conversion",
                origin_provider=match.provider_id,
            ),
        ),
    )


def path_param_reads_for_route(
    route: Route,
    l1_fn_by_fqn: dict[str, FunctionRecord],
) -> InputConversionResult:
    """Create path-parameter reads from a route URL rule and handler signature."""
    l1_handler = l1_fn_by_fqn.get(route.handler.fqn)
    if l1_handler is None:
        return InputConversionResult(reads=(), gaps=(_missing_route_handler_gap(route),))

    params_by_name = {param.name: param for param in l1_handler.params}
    reads: list[InputRead] = []
    gaps: list[AnalysisGap] = []
    for spec in _path_param_specs(route.url_rule):
        value_type = _path_param_value_type(spec)
        if spec.converter is not None and value_type is None:
            gaps.append(_unknown_route_converter_gap(route, spec.converter))
        param = params_by_name.get(spec.name)
        if param is None:
            continue
        reads.append(
            InputRead(
                source=PathParam(name=Key(spec.name)),
                access_pattern=AccessPattern.UNKNOWN,
                cardinality=Cardinality.SINGLE,
                function=route.handler,
                location=_location(param.location),
                expression=spec.name,
                provenance=_L2_INPUT_PROVENANCE,
                value_type=value_type,
            )
        )
    return InputConversionResult(reads=tuple(reads), gaps=tuple(gaps))


def _convert_attribute_match(
    match: ProviderMatch,
    descriptor: InputAttributePattern,
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> InputConversionResult:
    fact = match.source_fact
    assert isinstance(fact, AttributeAccess), (
        "InputAttributePattern matches are constructed from AttributeAccess facts"
    )
    if fact.containing_function_fqn is None:
        return InputConversionResult(
            reads=(),
            gaps=(_missing_containing_function_gap(match, "input attribute"),),
        )

    function = functions_by_fqn.get(fact.containing_function_fqn)
    if function is None:
        return InputConversionResult(
            reads=(),
            gaps=(_missing_function_gap(match, fact.containing_function_fqn),),
        )

    container_expr = f"{fact.target_expr}.{fact.attr_name}"
    containers = _container_expressions(fact, container_expr, idx)
    sibling = _find_precise_container_access(fact, containers, idx)
    if sibling is not None:
        sibling_fact, sibling_container_expr = sibling
        return _convert_subscript_access(
            match,
            descriptor,
            function,
            sibling_fact,
            sibling_container_expr,
            idx,
            functions_by_fqn,
        )

    call = _find_container_method_call(fact, containers, idx)
    if call is not None:
        return _convert_container_method_call(
            match, descriptor, function, call, idx, functions_by_fqn
        )

    source = _make_source(descriptor.source_type, None)
    if source is None:
        return _unknown_source_type_gap(match, descriptor.source_type)
    cardinality = _cardinality(match, descriptor.cardinality)
    return InputConversionResult(
        reads=(
            InputRead(
                source=source,
                access_pattern=AccessPattern.ATTRIBUTE,
                cardinality=cardinality.cardinality,
                function=function,
                location=_location(fact.location),
                expression=container_expr,
                provenance=_L2_INPUT_PROVENANCE,
            ),
        ),
        gaps=cardinality.gaps,
    )


def _convert_subscript_access(
    match: ProviderMatch,
    descriptor: InputAttributePattern,
    function: Function,
    sibling: AttributeAccess,
    container_expr: str,
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> InputConversionResult:
    return _keyed_input_reads(
        match=match,
        source_type=descriptor.source_type,
        key_expr=sibling.attr_name,
        function=function,
        idx=idx,
        functions_by_fqn=functions_by_fqn,
        access_pattern=AccessPattern.SUBSCRIPT,
        cardinality=Cardinality.SINGLE,
        location=sibling.location,
        expression=f"{container_expr}[{sibling.attr_name}]",
    )


def _convert_container_method_call(
    match: ProviderMatch,
    descriptor: InputAttributePattern,
    function: Function,
    call: CallEdge,
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> InputConversionResult:
    method_name = _called_method_name(call)
    key_arg = _positional_arg(call.arguments, 0)
    access_pattern = AccessPattern.GETLIST if method_name == "getlist" else AccessPattern.GET
    cardinality = (
        Cardinality.MULTI if access_pattern is AccessPattern.GETLIST else Cardinality.SINGLE
    )
    return _keyed_input_reads(
        match=match,
        source_type=descriptor.source_type,
        key_expr=key_arg.expression if key_arg is not None else "",
        function=function,
        idx=idx,
        functions_by_fqn=functions_by_fqn,
        access_pattern=access_pattern,
        cardinality=cardinality,
        location=call.location,
        expression=_call_expression(call),
    )


def _convert_container_input_match(  # noqa: PLR0911  — one return per access shape / gap
    match: ProviderMatch,
    descriptor: InputContainerPattern,
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> InputConversionResult:
    """Convert an InputContainerPattern match (``session``/``g`` keyed access).

    Subscript ``session["k"]`` and method ``session.get("k")`` resolve the key
    through :func:`_keyed_input_reads` (handling indirected keys + honest gaps);
    an attribute ``g.k`` is keyed directly by the attribute name -- the name *is*
    the key, unlike a request-container attribute (``request.json``) which has no
    key.
    """
    fact = match.source_fact
    card = _cardinality(match, descriptor.cardinality)
    if isinstance(fact, AttributeAccess):
        if fact.containing_function_fqn is None:
            return InputConversionResult(
                reads=(),
                gaps=(_missing_containing_function_gap(match, "input container"),),
            )
        function = functions_by_fqn.get(fact.containing_function_fqn)
        if function is None:
            return InputConversionResult(
                reads=(),
                gaps=(_missing_function_gap(match, fact.containing_function_fqn),),
            )
        if fact.access_kind is AccessKind.SUBSCRIPT:
            result = _keyed_input_reads(
                match=match,
                source_type=descriptor.source_type,
                key_expr=fact.attr_name,
                function=function,
                idx=idx,
                functions_by_fqn=functions_by_fqn,
                access_pattern=AccessPattern.SUBSCRIPT,
                cardinality=card.cardinality,
                location=fact.location,
                expression=f"{fact.target_expr}[{fact.attr_name}]",
            )
            return InputConversionResult(reads=result.reads, gaps=(*result.gaps, *card.gaps))
        # ATTR: the attribute name *is* the key (``g.cart_id`` -> ``"cart_id"``).
        source = _make_source(descriptor.source_type, fact.attr_name)
        if source is None:
            return _unknown_source_type_gap(match, descriptor.source_type)
        return InputConversionResult(
            reads=(
                InputRead(
                    source=source,
                    access_pattern=AccessPattern.ATTRIBUTE,
                    cardinality=card.cardinality,
                    function=function,
                    location=_location(fact.location),
                    expression=f"{fact.target_expr}.{fact.attr_name}",
                    provenance=_L2_INPUT_PROVENANCE,
                ),
            ),
            gaps=card.gaps,
        )
    assert isinstance(fact, CallEdge), (
        "InputContainerPattern matches are built from AttributeAccess or CallEdge facts"
    )
    function = functions_by_fqn.get(fact.caller_fqn)
    if function is None:
        return InputConversionResult(
            reads=(), gaps=(_missing_function_gap(match, fact.caller_fqn),)
        )
    key_arg = _positional_arg(fact.arguments, 0)
    result = _keyed_input_reads(
        match=match,
        source_type=descriptor.source_type,
        key_expr=key_arg.expression if key_arg is not None else "",
        function=function,
        idx=idx,
        functions_by_fqn=functions_by_fqn,
        access_pattern=AccessPattern.GET,
        cardinality=card.cardinality,
        location=fact.location,
        expression=_call_expression(fact),
    )
    return InputConversionResult(reads=result.reads, gaps=(*result.gaps, *card.gaps))


def _convert_method_match(
    match: ProviderMatch,
    descriptor: InputMethodPattern,
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> InputConversionResult:
    fact = match.source_fact
    assert isinstance(fact, CallEdge), (
        "InputMethodPattern matches are constructed from CallEdge facts"
    )

    function = functions_by_fqn.get(fact.caller_fqn)
    if function is None:
        return InputConversionResult(
            reads=(),
            gaps=(_missing_function_gap(match, fact.caller_fqn),),
        )

    cardinality = _cardinality(match, descriptor.cardinality)
    key_expr = _descriptor_key_expr(fact.arguments, descriptor)
    result = _keyed_input_reads(
        match=match,
        source_type=descriptor.source_type,
        key_expr=key_expr if key_expr is not None else "",
        function=function,
        idx=idx,
        functions_by_fqn=functions_by_fqn,
        access_pattern=AccessPattern.ATTRIBUTE,
        cardinality=cardinality.cardinality,
        location=fact.location,
        expression=_call_expression(fact),
    )
    return InputConversionResult(reads=result.reads, gaps=(*result.gaps, *cardinality.gaps))


def _convert_claim_container_match(
    match: ProviderMatch,
    descriptor: ClaimContainerPattern,
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> InputConversionResult:
    """Convert a ClaimContainerPattern match into ProviderClaim InputReads.

    The match's source fact is the *claims-producing call* (e.g.
    ``authorize_access_token()``).  Its return value is a claims container; we
    walk value flow forward from that return to the variables that hold the
    container and any value navigated out of it
    (``token`` -> ``token["userinfo"]`` -> ``userinfo``), then emit a
    :class:`~flawed.inputs.ProviderClaim` read for every keyed access
    (subscript ``["k"]`` or ``.get("k")`` / ``.getlist("k")``) on those
    containers, keyed by the access key.

    Recognition is **interprocedural** (FLAW-203): when a claims container (or a
    sub-container navigated out of it) is passed as a call argument, the callee's
    bound parameter becomes a claims source too, so a callee that does
    ``userinfo.get("email")`` on a parameter it received surfaces the claim. This
    mirrors the real federated-identity idiom where the token exchange and the
    claim reads live in different functions (a callback delegating to a
    ``create_or_update_sso_user(userinfo)`` helper). Propagation follows call
    arguments transitively, guarded by a ``(function, container)`` visited set so
    recursion and shared helpers terminate.
    """
    fact = match.source_fact
    assert isinstance(fact, CallEdge), (
        "ClaimContainerPattern matches are constructed from CallEdge facts"
    )
    call_expr = _call_expression(fact)
    fn_records = {record.fqn: record for record in idx.functions}

    by_identity: dict[tuple[str, str], InputRead] = {}
    gaps: list[AnalysisGap] = []
    visited: set[tuple[str, str]] = set()
    # Worklist of (function_fqn, seed_container_vars). The caller is seeded from
    # the variables the claims-call return is assigned to; callees are seeded
    # from the parameter that receives a claims container at the call site.
    queue: list[tuple[str, frozenset[str]]] = [
        (fact.caller_fqn, _vars_assigned_from(fact.caller_fqn, call_expr, idx))
    ]
    while queue:
        fn_fqn, seeds = queue.pop()
        unseen = frozenset(name for name in seeds if (fn_fqn, name) not in visited)
        if not unseen:
            # Either the container is consumed inline (no binding) or this
            # (function, container) was already recognized. Not an error.
            continue
        container_vars = _expand_container_vars(fn_fqn, unseen, idx)
        visited.update((fn_fqn, name) for name in container_vars)
        function = functions_by_fqn.get(fn_fqn)
        if function is None:
            gaps.append(_missing_function_gap(match, fn_fqn))
            continue
        propagations = _claim_container_args_to_callees(fn_fqn, container_vars, fn_records, idx)
        # A keyed access whose value is passed as a container argument to a callee
        # (``helper(token["userinfo"])``) is a navigation, not a leaf claim — the
        # leaf reads are emitted in the callee. Suppress it here so it does not
        # become a spurious parent claim that falsely correlates its descendants.
        navigation_exprs = frozenset(arg_expr for _, _, arg_expr in propagations)
        for read in _claim_reads_for_containers(
            container_vars, descriptor, function, fn_fqn, idx, navigation_exprs
        ):
            by_identity.setdefault((read.expression, repr(read.location)), read)
        for callee_fqn, param_name, _ in propagations:
            if (callee_fqn, param_name) not in visited:
                queue.append((callee_fqn, frozenset({param_name})))
    return InputConversionResult(reads=tuple(by_identity.values()), gaps=tuple(gaps))


def _vars_assigned_from(fn_fqn: str, expr: str, idx: CodeIndex) -> frozenset[str]:
    """Simple-name variables directly assigned or aliased from ``expr`` in ``fn_fqn``."""
    from flawed._semantic._matching import _value_flow_for_function

    names: set[str] = set()
    for edge in _value_flow_for_function(idx, fn_fqn):
        if edge.kind in {FlowKind.ASSIGN, FlowKind.ALIAS} and edge.source_expr == expr:
            name = _simple_name(edge.target_expr)
            if name is not None:
                names.add(name)
    return frozenset(names)


def _expand_container_vars(fn_fqn: str, seeds: frozenset[str], idx: CodeIndex) -> frozenset[str]:
    """Expand ``seeds`` through aliases and keyed navigations within ``fn_fqn``.

    From each container name, follow ``alias = container`` and
    ``x = container["k"]`` / ``container.get("k")`` edges, so a claim read on a
    descended sub-container (``userinfo = token["userinfo"]``) is still
    attributed to the claim source.
    """
    from flawed._semantic._matching import _value_flow_for_function

    edges = [
        edge
        for edge in _value_flow_for_function(idx, fn_fqn)
        if edge.kind in {FlowKind.ASSIGN, FlowKind.ALIAS}
    ]
    seen: set[str] = set(seeds)
    frontier: list[str] = list(seeds)
    cursor = 0
    while cursor < len(frontier):
        container = frontier[cursor]
        cursor += 1
        for edge in edges:
            if edge.source_expr == container or _is_navigation_off(edge.source_expr, container):
                name = _simple_name(edge.target_expr)
                if name is not None and name not in seen:
                    seen.add(name)
                    frontier.append(name)
    return frozenset(seen)


def _claim_container_args_to_callees(
    fn_fqn: str,
    container_vars: frozenset[str],
    fn_records: Mapping[str, FunctionRecord],
    idx: CodeIndex,
) -> tuple[tuple[str, str, str], ...]:
    """Find ``(callee_fqn, param_name, arg_expression)`` triples passing a container.

    A call argument carries a claims container when its expression is one of
    ``container_vars`` (``helper(userinfo)``) or a keyed navigation off one
    (``helper(token["userinfo"])``). The receiving parameter is then itself a
    claims source in the callee. Only project-local callees with a resolved FQN
    are followed; the parameter is resolved by keyword name or positional index
    (adjusting for a method's leading ``self``/``cls``), so an unmappable
    argument (``*args``/``**kwargs``) is conservatively skipped. The argument
    expression is returned so the caller can suppress it as a navigation.
    """
    from flawed._semantic._matching import _call_edges_for_caller

    results: list[tuple[str, str, str]] = []
    for edge in _call_edges_for_caller(idx, fn_fqn):
        callee_fqn = edge.callee_fqn
        if callee_fqn is None:
            continue
        callee = fn_records.get(callee_fqn)
        if callee is None:
            continue
        for arg in edge.arguments:
            if not _arg_carries_container(arg.expression, container_vars):
                continue
            param_name = _callee_param_for_arg(callee, arg)
            if param_name is not None:
                results.append((callee_fqn, param_name, arg.expression))
    return tuple(results)


def _arg_carries_container(expression: str, container_vars: frozenset[str]) -> bool:
    """Whether a call-argument expression denotes a claims container."""
    if expression in container_vars:
        return True
    return any(_is_navigation_off(expression, container) for container in container_vars)


def _callee_param_for_arg(callee: FunctionRecord, arg: CallArgument) -> str | None:
    """Resolve the callee parameter name that ``arg`` binds, or ``None``.

    Keyword arguments bind by name. Positional arguments bind by index into the
    callee's positional parameters, skipping a leading ``self``/``cls`` for
    methods. Star-args/kwargs and out-of-range positions yield ``None`` (no
    propagation) rather than a guessed binding.
    """
    if arg.keyword is not None:
        for param in callee.params:
            if param.name == arg.keyword:
                return param.name
        return None
    if arg.position is not None:
        positional = [
            param
            for param in callee.params
            if param.kind in {ParameterKind.POSITIONAL_ONLY, ParameterKind.POSITIONAL_OR_KEYWORD}
        ]
        if callee.is_method and positional:
            positional = positional[1:]
        if 0 <= arg.position < len(positional):
            return positional[arg.position].name
    return None


def _is_navigation_off(source_expr: str, container: str) -> bool:
    """Whether ``source_expr`` keys a value out of ``container`` (subscript/get)."""
    return source_expr.startswith((f"{container}[", f"{container}.get(", f"{container}.getlist("))


def _claim_reads_for_containers(
    container_vars: frozenset[str],
    descriptor: ClaimContainerPattern,
    function: Function,
    caller_fqn: str,
    idx: CodeIndex,
    navigation_exprs: frozenset[str] = frozenset(),
) -> tuple[InputRead, ...]:
    """Emit a ProviderClaim read for every *leaf* keyed access on a claim container.

    A keyed access whose result is itself descended as a deeper container (e.g.
    ``userinfo = token["userinfo"]``) is a structural navigation, not a leaf
    claim: emitting it as a keyed read would make every leaf claim share that
    common ancestor and falsely correlate (``email`` would ``shares_origin`` with
    ``sub``).  Such navigation accesses are therefore suppressed; only leaf claim
    reads (``userinfo.get("email")``) are emitted.

    ``navigation_exprs`` extends that suppression to keyed accesses whose value is
    passed as a container argument into a callee (``helper(token["userinfo"])``):
    the leaf reads are emitted in the callee, so the access here is a navigation.
    """
    from flawed._semantic._matching import _call_edges_for_caller, _value_flow_for_function

    # Variables that are the base of at least one keyed access — i.e. containers
    # that get descended into. A keyed access whose result is one of these is a
    # navigation, not a leaf claim.
    descended_bases = _claim_descended_bases(caller_fqn, idx)
    # Map each keyed-access expression to the variable its result is bound to.
    result_var_by_expr: dict[str, str] = {}
    for vf_edge in _value_flow_for_function(idx, caller_fqn):
        if vf_edge.kind in {FlowKind.ASSIGN, FlowKind.ALIAS}:
            name = _simple_name(vf_edge.target_expr)
            if name is not None:
                result_var_by_expr.setdefault(vf_edge.source_expr, name)

    by_identity: dict[tuple[str, str], InputRead] = {}

    def _record(
        key: str | None, access: AccessPattern, location: SourceSpan, expression: str
    ) -> None:
        if expression in navigation_exprs:
            return  # value flows into a callee as a container — leaf reads emitted there
        if result_var_by_expr.get(expression) in descended_bases:
            return  # navigation into a deeper container, not a leaf claim
        source = _make_source(descriptor.source_type, key)
        if source is None:
            return
        cardinality = Cardinality.MULTI if access is AccessPattern.GETLIST else Cardinality.SINGLE
        read = InputRead(
            source=source,
            access_pattern=access,
            cardinality=cardinality,
            function=function,
            location=_location(location),
            expression=expression,
            provenance=_L2_INPUT_PROVENANCE,
        )
        by_identity.setdefault((expression, repr(read.location)), read)

    # Subscript keyed accesses: container["key"].
    for attr in idx.attributes:
        if (
            attr.containing_function_fqn == caller_fqn
            and attr.access_kind is AccessKind.SUBSCRIPT
            and not attr.is_write
            and attr.target_expr in container_vars
        ):
            _record(
                _literal_string(attr.attr_name),
                AccessPattern.SUBSCRIPT,
                attr.location,
                f"{attr.target_expr}[{attr.attr_name}]",
            )

    # Method keyed accesses: container.get("key") / container.getlist("key").
    # The L1 call graph records ``userinfo.get("email")`` as two edges — one
    # carrying the call_expression and one carrying the parsed arguments — so we
    # key off whichever edge yields the literal claim key and skip keyless edges
    # (a non-literal key cannot give the read a correlatable identity).
    for edge in _call_edges_for_caller(idx, caller_fqn):
        method = _called_method_name(edge)
        if method not in {"get", "getlist"}:
            continue
        receiver = _method_receiver_name(edge)
        if receiver is None or receiver not in container_vars:
            continue
        key = _literal_arg(edge.arguments, position=0, keyword=None)
        if key is None:
            continue
        access = AccessPattern.GETLIST if method == "getlist" else AccessPattern.GET
        _record(key, access, edge.location, f"{receiver}.{method}({edge.arguments[0].expression})")

    return tuple(by_identity.values())


def _claim_descended_bases(caller_fqn: str, idx: CodeIndex) -> frozenset[str]:
    """Simple-name variables that are the base/receiver of a keyed access.

    These are containers that get descended into; a keyed access producing one
    of them is a navigation rather than a leaf claim read.
    """
    from flawed._semantic._matching import _call_edges_for_caller

    bases: set[str] = set()
    for attr in idx.attributes:
        if (
            attr.containing_function_fqn == caller_fqn
            and attr.access_kind is AccessKind.SUBSCRIPT
            and not attr.is_write
            and (name := _simple_name(attr.target_expr)) is not None
        ):
            bases.add(name)
    for edge in _call_edges_for_caller(idx, caller_fqn):
        if _called_method_name(edge) in {"get", "getlist"}:
            receiver = _method_receiver_name(edge)
            if receiver is not None:
                bases.add(receiver)
    return frozenset(bases)


def _method_receiver_name(edge: CallEdge) -> str | None:
    """The receiver variable of a ``recv.method(...)`` call edge, if simple."""
    expression = edge.call_expression or edge.callee_fqn
    if expression is None:
        return None
    target = _call_target_expression(expression) or expression
    return target.rsplit(".", maxsplit=1)[0] if "." in target else None


def _convert_field_access_match(
    match: ProviderMatch,
    descriptor: InputFieldAccessPattern,
    functions_by_fqn: Mapping[str, Function],
) -> InputConversionResult:
    """Convert an InputFieldAccessPattern match into an InputRead.

    The source fact is an ``AttributeAccess`` with ``target_expr`` like
    ``form.username`` and ``attr_name`` like ``data``.  The field name (key)
    is the last component of ``target_expr``.
    """
    fact = match.source_fact
    assert isinstance(fact, AttributeAccess), (
        "InputFieldAccessPattern matches are constructed from AttributeAccess facts"
    )
    if fact.containing_function_fqn is None:
        return InputConversionResult(
            reads=(),
            gaps=(_missing_containing_function_gap(match, "input field access"),),
        )

    function = functions_by_fqn.get(fact.containing_function_fqn)
    if function is None:
        return InputConversionResult(
            reads=(),
            gaps=(_missing_function_gap(match, fact.containing_function_fqn),),
        )

    field_name = _dotted_last(fact.target_expr)
    source = _make_source(descriptor.source_type, field_name)
    if source is None:
        return _unknown_source_type_gap(match, descriptor.source_type)

    expression = f"{fact.target_expr}.{fact.attr_name}"
    cardinality = _cardinality(match, descriptor.cardinality)
    return InputConversionResult(
        reads=(
            InputRead(
                source=source,
                access_pattern=AccessPattern.ATTRIBUTE,
                cardinality=cardinality.cardinality,
                function=function,
                location=_location(fact.location),
                expression=expression,
                provenance=_L2_INPUT_PROVENANCE,
            ),
        ),
        gaps=cardinality.gaps,
    )


def _dotted_last(expression: str) -> str | None:
    """Extract the last component from a dotted expression like ``form.username``."""
    parts = expression.rsplit(".", maxsplit=1)
    if len(parts) == 2:
        return parts[1]
    return None


def _convert_parameter_match(
    match: ProviderMatch,
    descriptor: InputParameterPattern,
    functions_by_fqn: Mapping[str, Function],
) -> InputConversionResult:
    """Convert an InputParameterPattern match into an InputRead.

    The source fact is a ``ParameterFact`` carrying the L1 ``Parameter``
    and its containing function FQN.
    """
    fact = match.source_fact
    assert isinstance(fact, ParameterFact), (
        "InputParameterPattern matches are constructed from ParameterFact facts"
    )

    function = functions_by_fqn.get(fact.function_fqn)
    if function is None:
        return InputConversionResult(
            reads=(),
            gaps=(_missing_function_gap(match, fact.function_fqn),),
        )

    key, key_gaps = _parameter_key(fact, descriptor, match)
    source = _make_source(descriptor.source_type, key)
    if source is None:
        source_result = _unknown_source_type_gap(match, descriptor.source_type)
        return InputConversionResult(reads=(), gaps=(*key_gaps, *source_result.gaps))
    default_text = fact.param.default or ""
    cardinality = _cardinality(match, descriptor.cardinality)
    return InputConversionResult(
        reads=(
            InputRead(
                source=source,
                access_pattern=AccessPattern.ATTRIBUTE,
                cardinality=cardinality.cardinality,
                function=function,
                location=_location(fact.location),
                expression=default_text,
                provenance=_L2_INPUT_PROVENANCE,
            ),
        ),
        gaps=(*key_gaps, *cardinality.gaps),
    )


def _parameter_key(
    fact: ParameterFact,
    descriptor: InputParameterPattern,
    match: ProviderMatch,
) -> tuple[str | None, tuple[AnalysisGap, ...]]:
    """Derive the input key from a parameter default based on ``key_from``."""
    if descriptor.key_from == "param_name":
        return fact.param.name, ()
    if descriptor.key_from == "alias":
        return _parameter_literal_key(
            _parse_default_kwarg(fact.param.default, "alias"),
            fact,
            match,
            key_source="alias",
        )
    if descriptor.key_from == "first_arg":
        return _parameter_literal_key(
            _parse_default_first_arg(fact.param.default),
            fact,
            match,
            key_source="first_arg",
        )
    return fact.param.name, (
        AnalysisGap(
            kind=GapKind.INTERPRETER_ERROR,
            message=(f"Unsupported input parameter key strategy: {descriptor.key_from}"),
            affected_file=match.location.file,
            affected_function=fact.function_fqn,
            source_error="input_conversion: unsupported parameter key strategy",
            origin_phase="input_conversion",
            origin_provider=match.provider_id,
        ),
    )


def _parameter_literal_key(
    key: str | None,
    fact: ParameterFact,
    match: ProviderMatch,
    *,
    key_source: str,
) -> tuple[str | None, tuple[AnalysisGap, ...]]:
    if key is not None:
        return key, ()
    return None, (
        AnalysisGap(
            kind=GapKind.INFERENCE_FAILURE,
            message=(
                f"Could not derive input key from {key_source} for parameter "
                f"{fact.function_fqn}.{fact.param.name}"
            ),
            affected_file=match.location.file,
            affected_function=fact.function_fqn,
            source_error="input_conversion: non-literal parameter key",
            origin_phase="input_conversion",
            origin_provider=match.provider_id,
        ),
    )


def _parse_default_kwarg(default: str | None, kwarg_name: str) -> str | None:
    """Extract a keyword argument value from a default call expression."""
    if default is None:
        return None
    tree = _parse_expression(default)
    if tree is None:
        return None
    node = tree.body
    if not isinstance(node, ast.Call):
        return None
    for kw in node.keywords:
        if kw.arg == kwarg_name:
            return _literal_string(ast.unparse(kw.value))
    return None


def _parse_default_first_arg(default: str | None) -> str | None:
    """Extract the first positional arg as a literal string from a default."""
    if default is None:
        return None
    tree = _parse_expression(default)
    if tree is None:
        return None
    node = tree.body
    if not isinstance(node, ast.Call) or not node.args:
        return None
    return _literal_string(ast.unparse(node.args[0]))


def _find_precise_container_access(
    fact: AttributeAccess,
    containers: tuple[_ContainerExpression, ...],
    idx: CodeIndex,
) -> tuple[AttributeAccess, str] | None:
    for candidate in idx.attributes:
        for container in containers:
            if (
                candidate.containing_function_fqn == fact.containing_function_fqn
                and candidate.location.file == fact.location.file
                and _span_starts_not_after(container.available_from, candidate.location)
                and candidate.target_expr == container.expression
                and candidate.access_kind is AccessKind.SUBSCRIPT
                and not candidate.is_write
            ):
                return candidate, container.expression
    return None


def _find_container_method_call(
    fact: AttributeAccess,
    containers: tuple[_ContainerExpression, ...],
    idx: CodeIndex,
) -> CallEdge | None:
    from flawed._semantic._matching import _call_edges_for_caller

    if fact.containing_function_fqn is None:
        return None
    for edge in _call_edges_for_caller(idx, fact.containing_function_fqn):
        for container in containers:
            method_prefix = f"{container.expression}."
            if (
                edge.location.file == fact.location.file
                and _span_starts_not_after(container.available_from, edge.location)
                and edge.call_expression is not None
                and edge.call_expression.startswith(method_prefix)
                and _called_method_name(edge) in {"get", "getlist"}
            ):
                return edge
    return None


def _container_expressions(
    fact: AttributeAccess,
    container_expr: str,
    idx: CodeIndex,
) -> tuple[_ContainerExpression, ...]:
    containers = [_ContainerExpression(container_expr, fact.location)]
    if fact.containing_function_fqn is None:
        return tuple(containers)

    from flawed._semantic._matching import _value_flow_for_function

    seen = {container_expr}
    for edge in _value_flow_for_function(idx, fact.containing_function_fqn):
        if (
            edge.kind not in {FlowKind.ASSIGN, FlowKind.ALIAS}
            or edge.source_expr != container_expr
            or not _span_starts_not_after(fact.location, edge.source_location)
        ):
            continue
        alias_name = _simple_name(edge.target_expr)
        if alias_name is None or alias_name in seen:
            continue
        seen.add(alias_name)
        containers.append(_ContainerExpression(alias_name, edge.target_location))
    return tuple(containers)


def _called_method_name(edge: CallEdge) -> str | None:
    expression = edge.call_expression or edge.callee_fqn
    if expression is None:
        return None
    target = _call_target_expression(expression) or expression
    return target.rsplit(".", maxsplit=1)[-1]


def _literal_arg(
    args: tuple[CallArgument, ...],
    *,
    position: int | None,
    keyword: str | None,
) -> str | None:
    for arg in args:
        if arg.position == position and arg.keyword == keyword:
            return _literal_string(arg.expression)
    return None


_MAX_KEY_PROPAGATION_HOPS = 4

#: Private attribute carrying the accessor parameter expression of a wildcard
#: read awaiting per-route key re-resolution (FLAW-243).  Set off the public
#: ``InputRead`` field list so it never leaks into the Rule API surface.
_UNRESOLVED_KEY_PARAM_ATTR = "_unresolved_key_param"


@dataclass(frozen=True)
class _PropagatedKeys:
    """Literal request keys resolved for an indirected accessor parameter."""

    keys: tuple[str, ...]
    had_unresolved: bool


def _positional_arg(args: tuple[CallArgument, ...], position: int) -> CallArgument | None:
    """The positional call argument at ``position`` (ignores keyword args)."""
    for arg in args:
        if arg.position == position and arg.keyword is None:
            return arg
    return None


def _arg_for_param(
    args: tuple[CallArgument, ...], *, position: int | None, keyword: str
) -> CallArgument | None:
    """Call argument bound to a parameter, matched positionally or by keyword."""
    for arg in args:
        if (position is not None and arg.position == position and arg.keyword is None) or (
            arg.keyword == keyword
        ):
            return arg
    return None


def _callsite_position_for_param(function: Function, param_name: str) -> int | None:
    """0-based call-site positional index for ``param_name``.

    Accounts for an implicit ``self``/``cls`` receiver on methods (it is not
    passed positionally at the call site).
    """
    names = [param.name for param in function.params]
    if param_name not in names:
        return None
    decl_index = names.index(param_name)
    implicit_receiver = (
        function.parent_class is not None and bool(names) and names[0] in ("self", "cls")
    )
    position = decl_index - 1 if implicit_receiver else decl_index
    return position if position >= 0 else None


def _resolve_param_key_via_callsites(
    function: Function,
    key_expr: str,
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
    *,
    allowed_callers: frozenset[str] | None = None,
    _depth: int = 0,
    _seen: frozenset[tuple[str, str]] = frozenset(),
) -> _PropagatedKeys | None:
    """Resolve a request key passed through pass-through accessor helper hops.

    When ``key_expr`` names a parameter of ``function`` (e.g. the ``name`` in
    ``request.args.get(name)`` inside ``def get_param(name): ...``), walk
    ``function``'s call sites and collect the literal keys passed for that
    parameter.  A call site that forwards *another* parameter -- the
    ``get_int_param(name) -> get_param(name)`` chain in real code -- is followed
    one hop further, bounded by ``_MAX_KEY_PROPAGATION_HOPS`` and a cycle guard.

    ``allowed_callers`` restricts the walk to call sites whose *caller* is in the
    given FQN set, at every hop.  This is how per-route (route-path) resolution
    works: passing the route's reachable closure confines the literals to the
    ones that reach the accessor *along this route's own call paths*, so a
    globally multi-key generic accessor resolves to a single key per route
    without leaking another route's key (FLAW-243).  ``None`` (the default)
    considers every call site globally (the route-agnostic FLAW-229 behaviour).

    Returns ``None`` when ``key_expr`` is not a bare parameter reference (the
    caller keeps the existing direct-access behaviour).  Otherwise returns the
    distinct literal keys discovered and whether any reachable call site supplied
    a non-literal (an unresolved hop -> the caller emits an ``AnalysisGap``).
    """
    ident = _simple_name(key_expr)
    if ident is None:
        return None
    if ident not in {param.name for param in function.params}:
        return None
    position = _callsite_position_for_param(function, ident)

    marker = (function.fqn, ident)
    if marker in _seen or _depth >= _MAX_KEY_PROPAGATION_HOPS:
        return _PropagatedKeys((), had_unresolved=True)
    seen = _seen | {marker}

    keys: set[str] = set()
    had_unresolved = False
    for edge in idx.call_graph.edges_to(function.fqn):
        if allowed_callers is not None and edge.caller_fqn not in allowed_callers:
            # Call site outside this scope's reachable closure: irrelevant to the
            # scope being resolved, so skip it without marking it unresolved.
            continue
        arg = _arg_for_param(edge.arguments, position=position, keyword=ident)
        if arg is None:
            had_unresolved = True
            continue
        literal = _literal_string(arg.expression)
        if literal is not None:
            keys.add(literal)
            continue
        forwarded = _simple_name(arg.expression)
        caller = functions_by_fqn.get(edge.caller_fqn)
        if forwarded is not None and caller is not None:
            deeper = _resolve_param_key_via_callsites(
                caller,
                forwarded,
                idx,
                functions_by_fqn,
                allowed_callers=allowed_callers,
                _depth=_depth + 1,
                _seen=seen,
            )
            if deeper is not None and deeper.keys:
                keys.update(deeper.keys)
                had_unresolved = had_unresolved or deeper.had_unresolved
                continue
        had_unresolved = True
    return _PropagatedKeys(tuple(sorted(keys)), had_unresolved=had_unresolved)


def _indirected_key_gap(
    match: ProviderMatch, function: Function, key_expr: str, detail: str
) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=(
            f"Could not resolve input key '{key_expr}' through pass-through "
            f"accessor {function.fqn} ({detail})"
        ),
        affected_file=match.location.file,
        affected_function=function.fqn,
        source_error="input_conversion: unresolved indirected input key",
        origin_phase="input_conversion",
        origin_provider=match.provider_id,
    )


def _resolve_input_key(
    match: ProviderMatch,
    key_expr: str,
    function: Function,
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> tuple[str | None, tuple[AnalysisGap, ...], str | None]:
    """Resolve the literal key for an input access (see :func:`_keyed_input_reads`).

    Returns ``(key, gaps, rekey_param)``: a literal key with no gap, or ``None``
    with an explanatory ``AnalysisGap`` when an indirected key cannot be resolved
    unambiguously (``None`` with no gap when the key is an ordinary dynamic
    expression rather than a pass-through accessor parameter).

    ``rekey_param`` is the accessor parameter expression (e.g. ``"name"``) when
    the key is an *unresolved pass-through accessor parameter* -- a generic
    multi-key accessor whose route-agnostic key is ambiguous.  It is ``None``
    otherwise.  Scope construction uses it to re-resolve the key per route via
    :func:`rekey_read_for_scope` (FLAW-243): the read keeps the conservative
    wildcard + gap globally, but each route that reaches the accessor along a
    single-key path recovers its own literal key.
    """
    local_key = _literal_string(key_expr)
    if local_key is not None:
        return local_key, (), None
    propagated = _resolve_param_key_via_callsites(function, key_expr, idx, functions_by_fqn)
    if propagated is None:
        return None, (), None
    if len(propagated.keys) == 1 and not propagated.had_unresolved:
        # Unambiguous single-key pass-through accessor: every call site agrees.
        return propagated.keys[0], (), None
    if len(propagated.keys) > 1:
        detail = (
            "call sites supply multiple distinct keys "
            f"({', '.join(propagated.keys)}); resolved per-route where possible"
        )
    elif propagated.had_unresolved:
        detail = "some call sites pass a non-literal key"
    else:
        detail = "no call site supplies a literal key"
    # A pass-through accessor parameter that did not resolve to a single global
    # key: keep the wildcard + gap, but mark it for per-route re-resolution.
    return None, (_indirected_key_gap(match, function, key_expr, detail),), key_expr


def _keyed_input_reads(
    *,
    match: ProviderMatch,
    source_type: str,
    key_expr: str,
    function: Function,
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
    access_pattern: AccessPattern,
    cardinality: Cardinality,
    location: SourceSpan,
    expression: str,
) -> InputConversionResult:
    """Build the keyed ``InputRead`` for an input access, resolving an indirected key.

    A literal key is used directly (unchanged behaviour).  A non-literal key that
    names a *pass-through accessor* parameter is resolved from the helper's call
    sites, but only when every call site agrees on a **single** literal -- then
    that one key is safe to attach (the read is route-agnostic, anchored at the
    helper, so a unanimous key cannot mis-key any reaching route).  When call
    sites disagree (a generic ``get_param(name)`` read with many keys) or a hop
    stays dynamic, the read keeps the conservative ``key=None`` wildcard *and*
    carries an ``AnalysisGap`` -- honest about the unresolved key rather than
    failing open, and free of cross-route contamination.  Per-route resolution of
    a multi-key generic accessor needs call-site (route-path) attribution; see the
    FLAW-229 follow-up.  A non-literal that is not such a parameter keeps the prior
    wildcard behaviour with no gap.
    """

    def _read(source: InputSource) -> InputRead:
        return InputRead(
            source=source,
            access_pattern=access_pattern,
            cardinality=cardinality,
            function=function,
            location=_location(location),
            expression=expression,
            provenance=_L2_INPUT_PROVENANCE,
        )

    key, gaps, rekey_param = _resolve_input_key(match, key_expr, function, idx, functions_by_fqn)
    source = _make_source(source_type, key)
    if source is None:
        return _unknown_source_type_gap(match, source_type)
    read = _read(source)
    if rekey_param is not None:
        # Mark the wildcard read for per-route key re-resolution (FLAW-243).
        object.__setattr__(read, _UNRESOLVED_KEY_PARAM_ATTR, rekey_param)
    return InputConversionResult(reads=(read,), gaps=gaps)


def rekey_read_for_scope(
    read: InputRead,
    *,
    allowed_caller_fqns: frozenset[str],
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> InputRead | None:
    """Re-resolve a wildcard accessor read's key for one scope's call paths.

    A generic multi-key accessor (``get_param(name)`` called with different
    literals on different routes) yields a route-agnostic wildcard read marked
    by :data:`_UNRESOLVED_KEY_PARAM_ATTR` (see :func:`_keyed_input_reads`).  When
    that read is materialised into a *specific* scope -- a route's reachable or
    full-stack closure -- this re-resolves the accessor key using only the call
    sites whose caller is in ``allowed_caller_fqns`` (that scope's reachable
    closure plus its root).  If, *along this scope's own paths*, exactly one
    literal key reaches the accessor with no unresolved hop, a copy of the read
    keyed to that literal is returned; otherwise ``None`` (keep the conservative
    wildcard + gap).  Confining the walk to the scope's callers is what prevents
    cross-route contamination -- another route's key is never in scope (FLAW-243).

    Returns ``None`` for any read not carrying the marker (the common case), so
    callers fall back to the read unchanged.
    """
    key_expr = getattr(read, _UNRESOLVED_KEY_PARAM_ATTR, None)
    if key_expr is None:
        return None
    propagated = _resolve_param_key_via_callsites(
        read.function,
        key_expr,
        idx,
        functions_by_fqn,
        allowed_callers=allowed_caller_fqns,
    )
    if propagated is None or propagated.had_unresolved or len(propagated.keys) != 1:
        return None
    source = _make_source(type(read.source).__name__, propagated.keys[0])
    if source is None:
        return None
    # ``replace`` copies only dataclass fields, so the per-route copy does not
    # carry the marker -- it is a resolved read, not a wildcard awaiting re-keying.
    return replace(read, source=source)


def _descriptor_key_expr(
    args: tuple[CallArgument, ...], descriptor: InputMethodPattern
) -> str | None:
    """Raw source expression of an ``InputMethodPattern`` key argument."""
    if descriptor.key_arg is not None:
        arg = _positional_arg(args, descriptor.key_arg)
        if arg is not None:
            return arg.expression
    if descriptor.key_kwarg is not None:
        arg = next((a for a in args if a.keyword == descriptor.key_kwarg), None)
        if arg is not None:
            return arg.expression
    return None


def _make_source(source_type: str, key: str | None) -> InputSource | None:
    typed_key = Key(key) if key is not None else None
    source_factories: dict[str, Callable[[], InputSource]] = {
        "Query": lambda: Query(key=typed_key),
        "Form": lambda: Form(key=typed_key),
        "Json": lambda: Json(path=JsonPath(f"$.{key}") if key is not None else None),
        "Header": lambda: Header(name=typed_key),
        "Cookie": lambda: Cookie(name=typed_key),
        "PathParam": lambda: PathParam(name=typed_key),
        "FileUpload": lambda: FileUpload(field=typed_key),
        "RawBody": RawBody,
        "ProviderClaim": lambda: ProviderClaim(key=typed_key),
        "SessionValue": lambda: SessionValue(key=typed_key),
        "FrameworkGlobal": lambda: FrameworkGlobal(name=typed_key),
    }
    factory = source_factories.get(source_type)
    return factory() if factory is not None else None


def _cardinality(match: ProviderMatch, value: str) -> _CardinalityResult:
    if value == "SINGLE":
        return _CardinalityResult(Cardinality.SINGLE)
    if value == "MULTI":
        return _CardinalityResult(Cardinality.MULTI)
    if value == "UNKNOWN":
        return _CardinalityResult(Cardinality.UNKNOWN)
    return _CardinalityResult(
        Cardinality.SINGLE,
        (
            AnalysisGap(
                kind=GapKind.INTERPRETER_ERROR,
                message=f"Unknown input cardinality: {value}",
                affected_file=match.location.file,
                affected_function=_fact_function(match),
                source_error="input_conversion: unknown cardinality",
                origin_phase="input_conversion",
                origin_provider=match.provider_id,
            ),
        ),
    )


def _path_param_specs(url_rule: str) -> tuple[_PathParamSpec, ...]:
    return tuple(
        _PathParamSpec(
            name=name,
            converter=_converter_name(match.group("converter")),
            uses_angle_syntax=match.group("angle") is not None,
        )
        for match in _PATH_PARAM_RE.finditer(url_rule)
        if (name := (match.group("angle") or match.group("brace"))) is not None
    )


def _converter_name(converter: str | None) -> str | None:
    if converter is None:
        return None
    return converter.split("(", 1)[0].strip()


def _path_param_value_type(spec: _PathParamSpec) -> InputValueType | None:
    if spec.converter is None:
        return InputValueType.STRING if spec.uses_angle_syntax else None
    return _ROUTE_CONVERTER_VALUE_TYPES.get(spec.converter)


def _unknown_route_converter_gap(route: Route, converter: str) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=(
            f"Unknown route parameter converter '{converter}' in {route.url_rule}; "
            "path parameter type constraint not modeled"
        ),
        affected_file=route.location.file,
        affected_function=route.handler.fqn,
        source_error="input_conversion: unknown route parameter converter",
        origin_phase="input_conversion",
        origin_provider=_route_provider_id(route),
    )


def _missing_route_handler_gap(route: Route) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INTERPRETER_ERROR,
        message=(
            f"No L1 handler record found for route {route.url_rule} handler {route.handler.fqn}"
        ),
        affected_file=route.location.file,
        affected_function=route.handler.fqn,
        source_error="input_conversion: missing route handler record",
        origin_phase="input_conversion",
        origin_provider=_route_provider_id(route),
    )


def _route_provider_id(route: Route) -> str | None:
    try:
        value: object = object.__getattribute__(route, "_provider_id")
    except AttributeError:
        return None
    return value if isinstance(value, str) else None


def _missing_containing_function_gap(match: ProviderMatch, source_kind: str) -> AnalysisGap:
    return _conversion_gap(
        match,
        f"Matched {source_kind} is not inside a function",
        origin_phase="input_conversion",
        source_error="input_conversion: missing containing function",
    )


def _missing_function_gap(match: ProviderMatch, function_fqn: str) -> AnalysisGap:
    return _conversion_gap(
        match,
        f"No converted Function found for {function_fqn}",
        origin_phase="input_conversion",
        source_error="input_conversion: missing function",
    )


def _unknown_source_type_gap(match: ProviderMatch, source_type: str) -> InputConversionResult:
    return InputConversionResult(
        reads=(),
        gaps=(
            AnalysisGap(
                kind=GapKind.INTERPRETER_ERROR,
                message=f"Unknown input source type: {source_type}",
                affected_file=match.location.file,
                affected_function=_fact_function(match),
                source_error="input_conversion: unknown source type",
                origin_phase="input_conversion",
                origin_provider=match.provider_id,
            ),
        ),
    )
