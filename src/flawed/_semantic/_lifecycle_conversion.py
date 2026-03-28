"""Convert provider lifecycle matches into route full-stack inputs.

Lifecycle declarations do not have a public Rule API collection yet. For now
the useful observable behavior is scope enrichment: route ``full_stack`` must
include the user-code functions registered as lifecycle hooks.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import TYPE_CHECKING

from flawed._index._types import CallEdge, DecoratorFact, SymbolRef
from flawed._semantic._conversion_utils import call_expression, location, simple_name
from flawed._semantic._expr_cache import parse_expression as _parse_expression
from flawed._semantic.providers import (
    CheckRegistrationPattern,
    ControlPlaneExemptionPattern,
    HookType,
    LifecycleDecoratorPattern,
    LifecycleRegistrationPattern,
    MiddlewareClassPattern,
)
from flawed.core import AnalysisGap, GapKind, Location, Provenance
from flawed.effects import Effect, EffectCategory, StateScope

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flawed._index import CodeIndex
    from flawed._semantic._provider_engine import ProviderMatch, RouterGroupInfo
    from flawed.function import Function
    from flawed.route import Route


_L2_LIFECYCLE_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="provider_lifecycle",
    confidence=0.95,
    supporting_facts=("provider lifecycle descriptor matched L1 structural fact",),
)


@dataclass(frozen=True)
class LifecycleHook:
    """A user-code lifecycle handler declared by a provider match."""

    handler: Function
    hook_type: HookType
    scope: str
    group: str | None
    location: Location
    provenance: Provenance
    router_group_variable_fqn: str | None = None


@dataclass(frozen=True)
class ImplicitCheck:
    """A provider-owned security check installed by a lifecycle registration.

    Unlike ``LifecycleHook`` this has no user-code handler -- the check is
    internal to the framework extension (e.g. ``CSRFProtect.protect``).
    Scope attachment uses ``hook_type`` to decide applicability (global
    ``BEFORE_HANDLER`` applies to all routes).
    """

    category: str
    hook_type: HookType
    expression: str
    location: Location
    provenance: Provenance
    provider_id: str | None = None
    scope: str = "global"
    group: str | None = None
    router_group_variable_fqn: str | None = None
    gaps: tuple[AnalysisGap, ...] = ()


@dataclass(frozen=True)
class ControlPlaneExemption:
    """A call-form control-plane exemption targeting a view or blueprint.

    Produced from a :class:`ControlPlaneExemptionPattern` match (e.g.
    ``csrf.exempt(view)`` at module scope).  Carries the resolved target name
    so the per-route scope assembly can attribute a control-plane-write effect
    onto the matching route(s)' ``full_stack`` -- the call form has no enclosing
    function, so the ordinary effect-conversion path drops it.

    ``target_name`` is the simple identifier named as the exempted target
    (the view function or blueprint variable).  ``target_module`` is the module
    FQN of the exempting call's receiver when known, enabling an exact
    ``{module}.{name}`` match before falling back to suffix matching (mirrors
    the router-group resolver).
    """

    category: EffectCategory
    scope: StateScope | None
    expression: str
    location: Location
    provenance: Provenance
    target_name: str
    target_module: str | None = None
    provider_id: str | None = None
    gaps: tuple[AnalysisGap, ...] = ()


@dataclass(frozen=True)
class LifecycleConversionResult:
    """Converted lifecycle hooks and non-fatal conversion gaps."""

    hooks: tuple[LifecycleHook, ...]
    implicit_checks: tuple[ImplicitCheck, ...] = ()
    exemptions: tuple[ControlPlaneExemption, ...] = ()
    gaps: tuple[AnalysisGap, ...] = ()


def convert_lifecycle_match(
    match: ProviderMatch,
    functions_by_fqn: Mapping[str, Function],
    router_group_info_by_var: Mapping[str, RouterGroupInfo],
) -> LifecycleConversionResult:
    """Convert one lifecycle-phase provider match into a hook observation."""
    descriptor = match.descriptor
    if isinstance(descriptor, LifecycleDecoratorPattern):
        return _convert_decorator_match(
            match,
            descriptor,
            functions_by_fqn,
            router_group_info_by_var,
        )
    if isinstance(descriptor, MiddlewareClassPattern):
        return _convert_middleware_class_match(match, descriptor, functions_by_fqn)
    if isinstance(descriptor, LifecycleRegistrationPattern):
        implicit_checks: tuple[ImplicitCheck, ...] = ()
        if descriptor.check_category is not None:
            implicit_checks = (
                ImplicitCheck(
                    category=descriptor.check_category,
                    hook_type=descriptor.hook_type,
                    expression=match.canonical_fqn,
                    location=location(match.location),
                    provenance=_L2_LIFECYCLE_PROVENANCE,
                    provider_id=match.provider_id,
                ),
            )
        return LifecycleConversionResult(
            hooks=(),
            implicit_checks=implicit_checks,
            gaps=(*match.predicate_gaps, _implicit_registration_gap(match)),
        )
    if isinstance(descriptor, CheckRegistrationPattern):
        return _convert_check_registration_match(match, descriptor, router_group_info_by_var)
    if isinstance(descriptor, ControlPlaneExemptionPattern):
        return _convert_control_plane_exemption_match(match, descriptor, functions_by_fqn)
    return LifecycleConversionResult(
        hooks=(),
        gaps=(
            AnalysisGap(
                kind=GapKind.INTERPRETER_ERROR,
                message=f"Unsupported lifecycle descriptor type: {type(descriptor).__name__}",
                affected_file=match.location.file,
                source_error="lifecycle_conversion: descriptor not yet implemented",
                origin_phase="lifecycle_conversion",
                origin_provider=match.provider_id,
            ),
        ),
    )


def lifecycle_function_fqns_for_route(
    route: Route,
    hooks: tuple[LifecycleHook, ...],
    group_ancestry: Mapping[str, frozenset[str]] | None = None,
) -> tuple[str, ...]:
    """Return lifecycle handler FQNs that apply to *route*.

    *group_ancestry* maps a route group's variable FQN to the set of its
    ancestor group variable FQNs (parents/grandparents into which it was
    mounted).  It lets a hook declared on a *parent* router group reach
    routes registered on a *nested child* group -- the
    ``bp.register_blueprint(child.bp)`` shape (FLAW-114).  When omitted,
    attribution falls back to exact group matching only.
    """
    return tuple(
        hook.handler.fqn
        for hook in hooks
        if _hook_applies_to_route(hook, route, group_ancestry or {})
    )


def build_group_nesting(
    idx: CodeIndex,
    router_group_info_by_var: Mapping[str, RouterGroupInfo],
) -> dict[str, frozenset[str]]:
    """Build child-group → ancestor-groups variable-FQN nesting from L1 mounts.

    A router group mounted into another router group (e.g. a
    ``parent.register_blueprint(child.bp)`` / ``parent.include_router(child)``
    style mount, depending on the provider) creates a parent→child
    relationship: the parent's lifecycle hooks run for every route under the
    child.  This is detected *structurally* -- a call whose receiver is a
    known router-group variable and whose argument resolves to another known
    router-group variable -- so it stays framework-agnostic (no mount-method
    name is hardcoded here; the receiver/argument both being router groups is
    the signal).

    Returns a mapping from each group variable FQN to the transitive set of
    its ancestor group variable FQNs.
    """
    group_vars = frozenset(router_group_info_by_var)
    if not group_vars:
        return {}

    # Direct parent edges: child_var_fqn -> parent_var_fqn.
    parents: dict[str, set[str]] = {}
    for edge in idx.call_graph.edges:
        if edge.callee_fqn is None:
            continue
        receiver, separator, _method = edge.callee_fqn.rpartition(".")
        if not separator:
            continue
        # The receiver of a mount call is the parent group; the callee FQN
        # already resolves it structurally, so an exact lookup is enough.
        if receiver not in group_vars:
            continue
        for argument in edge.arguments:
            child_var = _resolve_group_var(
                argument.expression, argument.location.file, idx, group_vars
            )
            if child_var is not None and child_var != receiver:
                parents.setdefault(child_var, set()).add(receiver)

    # Transitively close: each child inherits its ancestors' ancestors.
    ancestry: dict[str, frozenset[str]] = {}
    for child in parents:
        seen: set[str] = set()
        frontier = set(parents.get(child, ()))
        while frontier:
            ancestor = frontier.pop()
            if ancestor in seen:
                continue
            seen.add(ancestor)
            frontier.update(parents.get(ancestor, ()))
        ancestry[child] = frozenset(seen)
    return ancestry


def _resolve_group_var(
    expression: str,
    file: str,
    idx: CodeIndex,
    group_vars: frozenset[str],
) -> str | None:
    """Resolve a mount-argument *expression* to a known group variable FQN.

    Tries, in order: (1) exact match, (2) L1 symbol resolution scoped to the
    call-site *file* (handles aliased cross-module imports such as
    ``alpha.bp`` -> ``pkg.children.alpha.bp``), (3) a unique dotted-suffix
    match -- matching the alias-resolution philosophy of
    ``_unique_router_group_with_same_leaf`` without binding ambiguous leaves.
    """
    if expression in group_vars:
        return expression
    # Accept a bare name (``bp``) or a dotted attribute path (``alpha.bp``);
    # reject calls/subscripts/other complex expressions.
    if not _is_dotted_name(expression):
        return None
    resolved = idx.symbols.resolve(expression, file)
    if resolved is not None and resolved in group_vars:
        return resolved
    # Suffix fallback: unique group var whose FQN ends with this dotted path
    # (``alpha.bp`` -> ``pkg.children.alpha.bp``).  Stays generic by binding
    # only when exactly one group var matches.
    candidates = [var for var in group_vars if var == expression or var.endswith(f".{expression}")]
    if len(candidates) == 1:
        return candidates[0]
    return None


def _is_dotted_name(expression: str) -> bool:
    """Return whether *expression* is a bare name or dotted attribute path."""
    tree = _parse_expression(expression)
    if tree is None:
        return False
    node = tree.body
    while isinstance(node, ast.Attribute):
        node = node.value
    return isinstance(node, ast.Name)


def implicit_check_applies_to_route(check: ImplicitCheck, route: Route) -> bool:
    """Return whether a provider-owned implicit check applies to *route*."""
    if check.scope == "global":
        return True
    if check.scope == "group":
        route_group_var = getattr(route, "_router_group_variable_fqn", None)
        if check.router_group_variable_fqn is not None:
            return route_group_var == check.router_group_variable_fqn
        return check.group is not None and check.group == route.group
    return True


def _convert_decorator_match(
    match: ProviderMatch,
    descriptor: LifecycleDecoratorPattern,
    functions_by_fqn: Mapping[str, Function],
    router_group_info_by_var: Mapping[str, RouterGroupInfo],
) -> LifecycleConversionResult:
    fact = match.source_fact
    if not isinstance(fact, DecoratorFact):
        return LifecycleConversionResult(hooks=())

    handler = functions_by_fqn.get(fact.target_fqn)
    if handler is None:
        return LifecycleConversionResult(hooks=(), gaps=(_handler_gap(match, fact.target_fqn),))

    group_info = _group_info_for_match(
        match.observed_fqn, descriptor.scope, router_group_info_by_var
    )
    group = group_info.group if group_info is not None else None
    hook = LifecycleHook(
        handler=handler,
        hook_type=descriptor.hook_type,
        scope=descriptor.scope,
        group=group,
        location=location(match.location),
        provenance=_L2_LIFECYCLE_PROVENANCE,
        router_group_variable_fqn=group_info.variable_fqn if group_info is not None else None,
    )
    return LifecycleConversionResult(hooks=(hook,), gaps=match.predicate_gaps)


def _convert_middleware_class_match(
    match: ProviderMatch,
    descriptor: MiddlewareClassPattern,
    functions_by_fqn: Mapping[str, Function],
) -> LifecycleConversionResult:
    fact = match.source_fact
    if not isinstance(fact, SymbolRef) or fact.fqn is None:
        return LifecycleConversionResult(hooks=(), gaps=(_source_fact_gap(match),))

    hooks: list[LifecycleHook] = []
    for method_name, hook_type in descriptor.method_hooks.items():
        handler = functions_by_fqn.get(f"{fact.fqn}.{method_name}")
        if handler is None:
            continue
        hooks.append(
            LifecycleHook(
                handler=handler,
                hook_type=hook_type,
                scope="global",
                group=None,
                location=handler.location,
                provenance=_L2_LIFECYCLE_PROVENANCE,
            )
        )

    if not hooks:
        return LifecycleConversionResult(
            hooks=(),
            gaps=(*match.predicate_gaps, _middleware_hooks_gap(match, fact.fqn)),
        )
    return LifecycleConversionResult(hooks=tuple(hooks), gaps=match.predicate_gaps)


def _convert_check_registration_match(
    match: ProviderMatch,
    descriptor: CheckRegistrationPattern,
    router_group_info_by_var: Mapping[str, RouterGroupInfo],
) -> LifecycleConversionResult:
    fact = match.source_fact
    if not isinstance(fact, CallEdge):
        return LifecycleConversionResult(hooks=(), gaps=(_source_fact_gap(match),))

    # Application-scope checks don't need a target expression — they apply
    # globally.  Check this BEFORE target resolution so that target_arg=None
    # (used when L1 can't capture the real target) doesn't short-circuit.
    if descriptor.target_kind == "application":
        return LifecycleConversionResult(
            hooks=(),
            implicit_checks=(
                _implicit_check_for_registration(
                    match,
                    descriptor,
                    fact,
                    scope="global",
                ),
            ),
            gaps=match.predicate_gaps,
        )
    # For non-application scopes, resolve the target expression.
    target_expr = _target_expression(fact, descriptor)
    if target_expr is None:
        return LifecycleConversionResult(
            hooks=(), gaps=(*match.predicate_gaps, _missing_target_gap(match))
        )

    if descriptor.target_kind != "router_group":
        return LifecycleConversionResult(
            hooks=(),
            gaps=(*match.predicate_gaps, _unsupported_target_kind_gap(match, descriptor)),
        )

    group_info, group_gaps = _resolve_router_group_target(
        match,
        target_expr,
        router_group_info_by_var,
    )
    if group_info is None:
        return LifecycleConversionResult(hooks=(), gaps=(*match.predicate_gaps, *group_gaps))

    check = _implicit_check_for_registration(
        match,
        descriptor,
        fact,
        scope="group",
        group=group_info.group,
        router_group_variable_fqn=group_info.variable_fqn,
        gaps=group_info.group_gaps,
    )
    return LifecycleConversionResult(
        hooks=(),
        implicit_checks=(check,),
        gaps=(*match.predicate_gaps, *group_gaps),
    )


def _target_expression(
    edge: CallEdge,
    descriptor: CheckRegistrationPattern | ControlPlaneExemptionPattern,
) -> str | None:
    if descriptor.target_kwarg is not None:
        for argument in edge.arguments:
            if argument.keyword == descriptor.target_kwarg:
                return argument.expression
    if descriptor.target_arg is None:
        return None
    for argument in edge.arguments:
        if argument.keyword is None and argument.position == descriptor.target_arg:
            return argument.expression
    return None


def _convert_control_plane_exemption_match(
    match: ProviderMatch,
    descriptor: ControlPlaneExemptionPattern,
    functions_by_fqn: Mapping[str, Function],
) -> LifecycleConversionResult:
    """Resolve a module-scope ``csrf.exempt(target)`` call to a route-attributable marker.

    This pattern exists ONLY to recover the *module-scope* call form, whose
    effect the ordinary effect-conversion path drops (its caller is the module,
    absent from ``functions_by_fqn`` -- ``_effect_conversion._convert_call_match``).
    When the call sits *inside a handler*, that effect-conversion path already
    produces a body ``Config.write()`` effect, so re-attributing here would
    duplicate it; such in-handler calls are skipped (no marker).

    For a genuine module-scope call we resolve the named target (view or
    blueprint) and emit a :class:`ControlPlaneExemption` carrying the target
    identity; the per-route scope assembly attributes the exemption effect onto
    matching routes' ``full_stack`` (fail-closed: an unresolvable target or
    unknown category/scope yields a gap and no marker, never a silent effect).
    """
    fact = match.source_fact
    if not isinstance(fact, CallEdge):
        return LifecycleConversionResult(hooks=(), gaps=(_source_fact_gap(match),))

    # In-handler calls are owned by the effect-conversion body path; only the
    # orphaned module-scope form (caller not a function) needs re-attribution.
    if fact.caller_fqn in functions_by_fqn:
        return LifecycleConversionResult(hooks=(), gaps=match.predicate_gaps)

    target_expr = _target_expression(fact, descriptor)
    if target_expr is None:
        return LifecycleConversionResult(
            hooks=(), gaps=(*match.predicate_gaps, _missing_target_gap(match))
        )
    target_name = simple_name(target_expr)
    if target_name is None:
        # A dynamic / non-name target (subscript, call result) cannot be
        # statically attributed to a route -- surface a gap, attribute nothing.
        return LifecycleConversionResult(
            hooks=(),
            gaps=(*match.predicate_gaps, _dynamic_router_group_target_gap(match, target_expr)),
        )

    kind = _exemption_effect_kind(match, descriptor)
    if isinstance(kind, AnalysisGap):
        return LifecycleConversionResult(hooks=(), gaps=(*match.predicate_gaps, kind))
    category, scope = kind

    exemption = ControlPlaneExemption(
        category=category,
        scope=scope,
        expression=call_expression(fact),
        location=location(match.location),
        provenance=_L2_LIFECYCLE_PROVENANCE,
        target_name=target_name,
        target_module=_module_fqn_from_instance_method(match.observed_fqn),
        provider_id=match.provider_id,
        gaps=match.predicate_gaps,
    )
    return LifecycleConversionResult(hooks=(), exemptions=(exemption,), gaps=match.predicate_gaps)


def control_plane_exemption_applies_to_route(
    exemption: ControlPlaneExemption, route: Route
) -> bool:
    """Whether *exemption* targets *route* (by view handler or blueprint group).

    A ``csrf.exempt(view)`` names a single handler; a ``csrf.exempt(blueprint)``
    names a routing group covering many routes.  The two are syntactically
    indistinguishable at the call site, so this matches *either*:

    - the route's handler FQN is ``{target_module}.{target_name}`` (exact) or
      ends with ``.{target_name}`` (view form), or
    - the route's router-group variable FQN ends with ``.{target_name}``
      (blueprint form).
    """
    suffix = f".{exemption.target_name}"
    handler_fqn = route.handler.fqn
    if exemption.target_module is not None and handler_fqn == (
        f"{exemption.target_module}.{exemption.target_name}"
    ):
        return True
    if handler_fqn == exemption.target_name or handler_fqn.endswith(suffix):
        return True
    group_var = getattr(route, "_router_group_variable_fqn", None)
    return bool(group_var is not None and group_var.endswith(suffix))


def build_exemption_effect(exemption: ControlPlaneExemption, handler: Function) -> Effect:
    """Construct the route-attributed control-plane exemption effect."""
    return Effect(
        category=exemption.category,
        function=handler,
        location=exemption.location,
        expression=exemption.expression,
        provenance=exemption.provenance,
        scope=exemption.scope,
    )


def _exemption_effect_kind(
    match: ProviderMatch,
    descriptor: ControlPlaneExemptionPattern,
) -> tuple[EffectCategory, StateScope | None] | AnalysisGap:
    """Resolve the declared category/scope strings to enums (fail-closed)."""
    try:
        category = EffectCategory[descriptor.category]
    except KeyError:
        return _exemption_enum_gap(match, "category", descriptor.category)
    if descriptor.scope is None:
        return category, None
    try:
        return category, StateScope[descriptor.scope]
    except KeyError:
        return _exemption_enum_gap(match, "scope", descriptor.scope)


def _exemption_enum_gap(match: ProviderMatch, field: str, raw: str) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INTERPRETER_ERROR,
        message=f"ControlPlaneExemptionPattern declares unknown {field} '{raw}'",
        affected_file=match.location.file,
        source_error=f"lifecycle_conversion: unknown exemption {field}",
        origin_phase="lifecycle_conversion",
        origin_provider=match.provider_id,
    )


def _resolve_router_group_target(
    match: ProviderMatch,
    target_expr: str,
    router_group_info_by_var: Mapping[str, RouterGroupInfo],
) -> tuple[RouterGroupInfo | None, tuple[AnalysisGap, ...]]:
    target_name = simple_name(target_expr)
    if target_name is None:
        return None, (_dynamic_router_group_target_gap(match, target_expr),)

    exact_module = _module_fqn_from_instance_method(match.observed_fqn)
    if exact_module is not None:
        exact = router_group_info_by_var.get(f"{exact_module}.{target_name}")
        if exact is not None:
            return exact, ()

    candidates = tuple(
        info
        for variable_fqn, info in router_group_info_by_var.items()
        if variable_fqn.endswith(f".{target_name}")
    )
    if len(candidates) == 1:
        return candidates[0], ()
    if len(candidates) > 1:
        return None, (_ambiguous_router_group_target_gap(match, target_expr, candidates),)
    return None, (_unknown_router_group_target_gap(match, target_expr),)


def _module_fqn_from_instance_method(observed_fqn: str) -> str | None:
    receiver_fqn, separator, _method_name = observed_fqn.rpartition(".")
    if not separator:
        return None
    module_fqn, receiver_separator, _receiver_name = receiver_fqn.rpartition(".")
    return module_fqn if receiver_separator else None


def _implicit_check_for_registration(
    match: ProviderMatch,
    descriptor: CheckRegistrationPattern,
    fact: CallEdge,
    *,
    scope: str,
    group: str | None = None,
    router_group_variable_fqn: str | None = None,
    gaps: tuple[AnalysisGap, ...] = (),
) -> ImplicitCheck:
    return ImplicitCheck(
        category=descriptor.check_category,
        hook_type=descriptor.hook_type,
        expression=call_expression(fact),
        location=location(match.location),
        provenance=_L2_LIFECYCLE_PROVENANCE,
        provider_id=match.provider_id,
        scope=scope,
        group=group,
        router_group_variable_fqn=router_group_variable_fqn,
        gaps=gaps,
    )


def _hook_applies_to_route(
    hook: LifecycleHook,
    route: Route,
    group_ancestry: Mapping[str, frozenset[str]],
) -> bool:
    if hook.scope == "global":
        return True
    if hook.scope == "group":
        route_group_var = getattr(route, "_router_group_variable_fqn", None)
        if hook.router_group_variable_fqn is not None:
            if route_group_var == hook.router_group_variable_fqn:
                return True
            # A hook on a *parent* group reaches routes on a nested child
            # group (``parent_bp.register_blueprint(child.bp)`` -- FLAW-114).
            if route_group_var is not None:
                ancestors = group_ancestry.get(route_group_var, frozenset())
                return hook.router_group_variable_fqn in ancestors
            return False
        return hook.group is not None and hook.group == route.group
    return True


def _group_for_match(
    observed_fqn: str,
    scope: str,
    router_group_info_by_var: Mapping[str, RouterGroupInfo],
) -> str | None:
    info = _group_info_for_match(observed_fqn, scope, router_group_info_by_var)
    return info.group if info is not None else None


def _group_info_for_match(
    observed_fqn: str,
    scope: str,
    router_group_info_by_var: Mapping[str, RouterGroupInfo],
) -> RouterGroupInfo | None:
    if scope != "group":
        return None
    receiver_fqn = observed_fqn.rsplit(".", maxsplit=1)[0] if "." in observed_fqn else None
    if receiver_fqn is None:
        return None
    info = router_group_info_by_var.get(receiver_fqn)
    if info is None:
        info = _unique_router_group_with_same_leaf(receiver_fqn, router_group_info_by_var)
    if info is None:
        return None
    return info


def _unique_router_group_with_same_leaf(
    receiver_fqn: str,
    router_group_info_by_var: Mapping[str, RouterGroupInfo],
) -> RouterGroupInfo | None:
    """Resolve imported router-group aliases by variable leaf name.

    Blueprint hooks are often registered from sibling modules that import a
    package-level ``bp``/``router`` object (for example
    ``pkg.auth.middleware.bp.before_request`` for ``pkg.bp``).  L1 has already
    resolved the decorator receiver structurally, but not always back to the
    original assignment FQN.  Falling back only when the leaf variable name is
    unique keeps this generic and avoids binding unrelated blueprints.
    """

    leaf = receiver_fqn.rsplit(".", maxsplit=1)[-1]
    matches = [
        info
        for variable_fqn, info in router_group_info_by_var.items()
        if variable_fqn.rsplit(".", maxsplit=1)[-1] == leaf
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def _handler_gap(match: ProviderMatch, target_fqn: str) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=f"Lifecycle hook handler not found: {target_fqn}",
        affected_file=match.location.file,
        affected_function=target_fqn,
        source_error="lifecycle_conversion: missing handler function",
        origin_phase="lifecycle_conversion",
        origin_provider=match.provider_id,
    )


def _source_fact_gap(match: ProviderMatch) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INTERPRETER_ERROR,
        message="Middleware lifecycle match does not carry a class symbol fact",
        affected_file=match.location.file,
        source_error="lifecycle_conversion: invalid middleware class match",
        origin_phase="lifecycle_conversion",
        origin_provider=match.provider_id,
    )


def _missing_target_gap(match: ProviderMatch) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=f"Check registration target not found: {match.canonical_fqn}",
        affected_file=match.location.file,
        source_error="lifecycle_conversion: missing check registration target",
        origin_phase="lifecycle_conversion",
        origin_provider=match.provider_id,
    )


def _unsupported_target_kind_gap(
    match: ProviderMatch,
    descriptor: CheckRegistrationPattern,
) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INTERPRETER_ERROR,
        message=f"Unsupported check registration target kind: {descriptor.target_kind}",
        affected_file=match.location.file,
        source_error="lifecycle_conversion: unsupported check registration target kind",
        origin_phase="lifecycle_conversion",
        origin_provider=match.provider_id,
    )


def _dynamic_router_group_target_gap(match: ProviderMatch, target_expr: str) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=f"Dynamic router-group check target: {target_expr}",
        affected_file=match.location.file,
        source_error="lifecycle_conversion: dynamic router-group check target",
        origin_phase="lifecycle_conversion",
        origin_provider=match.provider_id,
    )


def _unknown_router_group_target_gap(match: ProviderMatch, target_expr: str) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.SYMBOL_UNRESOLVED,
        message=f"Router-group check target not found: {target_expr}",
        affected_file=match.location.file,
        source_error="lifecycle_conversion: unknown router-group check target",
        origin_phase="lifecycle_conversion",
        origin_provider=match.provider_id,
    )


def _ambiguous_router_group_target_gap(
    match: ProviderMatch,
    target_expr: str,
    candidates: tuple[RouterGroupInfo, ...],
) -> AnalysisGap:
    candidate_names = ", ".join(sorted(info.variable_fqn for info in candidates))
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=f"Ambiguous router-group check target {target_expr}: {candidate_names}",
        affected_file=match.location.file,
        source_error="lifecycle_conversion: ambiguous router-group check target",
        origin_phase="lifecycle_conversion",
        origin_provider=match.provider_id,
    )


def _middleware_hooks_gap(match: ProviderMatch, class_fqn: str) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=f"Middleware class has no modeled hook methods: {class_fqn}",
        affected_file=match.location.file,
        affected_function=class_fqn,
        source_error="lifecycle_conversion: missing middleware hook methods",
        origin_phase="lifecycle_conversion",
        origin_provider=match.provider_id,
    )


def _implicit_registration_gap(match: ProviderMatch) -> AnalysisGap:
    fact = match.source_fact
    caller_fqn = fact.caller_fqn if isinstance(fact, CallEdge) else None
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=(
            "Implicit lifecycle registration has no modeled user-code handler: "
            f"{match.canonical_fqn}"
        ),
        affected_file=match.location.file,
        affected_function=caller_fqn,
        source_error="lifecycle_conversion: implicit registration has no handler",
        origin_phase="lifecycle_conversion",
        origin_provider=match.provider_id,
    )
