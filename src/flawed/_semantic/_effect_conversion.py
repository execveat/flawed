"""Convert provider effect matches into public Effect observations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from flawed._index._types import (
    AccessKind,
    AttributeAccess,
    CallEdge,
    FlowKind,
    SourceSpan,
    SymbolRef,
    ValueFlowEdge,
)

# FLAW-310: reuse the single canonical principal-proxy definition rather than
# re-spelling the identity-proxy names here (which would both risk drift and put
# framework-suggestive identifiers into a second L2-core module).  The names live
# in _auth_inference because that is where principal recognition originated; a
# future refactor could promote _PRINCIPAL_BASE_RE to a shared _semantic constant.
from flawed._semantic._auth_inference import _PRINCIPAL_BASE_RE
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
from flawed._semantic.providers import (
    EffectAttributePattern,
    EffectCallPattern,
    EffectSubscriptPattern,
    StateProxyPattern,
)
from flawed.core import AnalysisGap, Provenance
from flawed.effects import Effect, EffectCategory, StateScope

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flawed._index import CodeIndex
    from flawed._semantic._provider_engine import ProviderMatch
    from flawed.function import Function


_L2_EFFECT_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="provider_effects",
    confidence=0.95,
    supporting_facts=("provider effect descriptor matched L1 structural fact",),
)
_SERVER_STATE_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="server_state_effects",
    confidence=0.9,
    supporting_facts=("function mutates a module-level state container",),
)
_SUPPORTED_STATE_CATEGORIES = frozenset({EffectCategory.STATE_READ, EffectCategory.STATE_WRITE})
_ALIAS_FLOW_KINDS = frozenset({FlowKind.ASSIGN, FlowKind.ALIAS, FlowKind.CHAIN})

# FLAW-281a: inferred custom-mutation provenance. Lower confidence than a
# provider-declared effect (_L2_EFFECT_PROVENANCE = 0.95) so downstream rules
# can distinguish a verb-heuristic guess from a modeled write, and so the write
# is not over-trusted by flow reasoning.
_INFERRED_STATE_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="inferred_state_writes",
    confidence=0.5,
    supporting_facts=("call to a verb-named mutating method with no provider-declared effect",),
)
# Generic, framework-agnostic mutating verbs (no framework names -- must pass the
# framework-name grep gate). Exact names plus underscore-bounded prefixes so we
# match ``delete`` / ``delete_result`` but not ``settings`` / ``updated_at`` /
# ``additional``. Tuned to emit a write when in doubt (FN-priority): the cost of
# a spurious match is a coverage FP, never a missed mutation.
_EXACT_MUTATING_VERBS = frozenset(
    {
        "delete",
        "remove",
        "destroy",
        "save",
        "update",
        "create",
        "insert",
        "add",
        "write",
        "store",
        "put",
        "commit",
        "flush",
        "persist",
    }
)
_MUTATING_VERB_PREFIXES = (
    "delete_",
    "remove_",
    "destroy_",
    "save_",
    "update_",
    "create_",
    "insert_",
    "add_",
    "write_",
    "store_",
    "put_",
    "set_",
)
# Receivers whose verb-named methods are conventionally non-persistent (e.g.
# ``logger.add`` / ``log.write`` from loguru/logging). Kept deliberately tiny so
# it never suppresses a real write -- only the most unambiguous benign cases.
_NON_PERSISTENT_RECEIVERS = frozenset({"logger", "log", "logging"})

# FLAW-333: request-scoped infrastructure objects whose verb-named methods are NOT
# module-global "server-wide" state, even though their base symbol (``db`` / ``cache``)
# is module-level. A request-scoped ``session`` (an ORM / web session) is per-request by
# construction, and cache invalidation (``cache.delete_memoized(...)`` and friends) is
# housekeeping -- neither is the "affects all users" server state that the
# high-confidence server-wide-state-write rules require. Scoping them REQUEST stops
# those high-confidence rules over-firing (the
# dominant wild FP: ~140 ``cache.delete_memoized`` calls on one real-world corpus)
# while still emitting the STATE_WRITE, so the scope-agnostic coverage rules continue
# to see the call. FN-safe:
# only these specific, unambiguous idioms are downgraded; an unauth'd mutation still
# reaches the coverage rules via REQUEST. (This is generic library-convention knowledge,
# like ``_NON_PERSISTENT_RECEIVERS`` and the mutating-verb sets -- not provider logic.)
_REQUEST_SCOPED_RECEIVER_NAMES = frozenset({"session", "db_session"})
_CACHE_RECEIVER_NAMES = frozenset({"cache"})
# ``delete_memoized`` / ``delete_memoized_verhash`` are distinctive cache-invalidation
# method names -- recognising the method alone is FN-safe (no application-state object
# carries them). The generic verbs are gated on a cache-named receiver.
_CACHE_INVALIDATION_METHODS = frozenset({"delete_memoized", "delete_memoized_verhash"})
_CACHE_HOUSEKEEPING_METHODS = frozenset(
    {"delete", "delete_many", "clear", "uncache", "delete_memoized", "delete_memoized_verhash"}
)


@dataclass(frozen=True)
class EffectConversionResult:
    """Converted effects and non-fatal conversion gaps."""

    effects: tuple[Effect, ...]
    gaps: tuple[AnalysisGap, ...] = ()


def convert_effect_match(
    match: ProviderMatch,
    functions_by_fqn: Mapping[str, Function],
) -> EffectConversionResult:
    """Convert one provider effect/proxy match into public effects."""
    descriptor = match.descriptor
    if isinstance(descriptor, StateProxyPattern):
        return _convert_proxy_match(match, descriptor, functions_by_fqn)
    if isinstance(descriptor, EffectAttributePattern):
        return _convert_attribute_match(match, descriptor, functions_by_fqn)
    if isinstance(descriptor, EffectSubscriptPattern):
        return _convert_subscript_match(match, descriptor, functions_by_fqn)
    if isinstance(descriptor, EffectCallPattern):
        return _convert_call_match(match, descriptor, functions_by_fqn)
    return EffectConversionResult(
        effects=(),
        gaps=(
            _conversion_gap(
                match,
                f"Unsupported effect descriptor type: {type(descriptor).__name__}",
                origin_phase="effect_conversion",
                source_error="effect_conversion: descriptor not yet implemented",
            ),
        ),
    )


def convert_server_state_writes(
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> EffectConversionResult:
    """Convert writes to module-level containers into SERVER state effects."""
    module_targets = _module_state_targets_by_file(idx)
    effects: list[Effect] = []
    for fact in idx.attributes:
        if not fact.is_write or fact.containing_function_fqn is None:
            continue
        if fact.access_kind is AccessKind.ATTR and _attribute_name_is_private(fact.attr_name):
            continue
        state_target = _server_state_target(fact, module_targets, idx)
        if state_target is None:
            continue
        function = functions_by_fqn.get(fact.containing_function_fqn)
        if function is None:
            continue
        effects.append(
            Effect(
                category=EffectCategory.STATE_WRITE,
                function=function,
                location=_location(fact.location),
                expression=_attribute_expression(fact),
                provenance=_SERVER_STATE_PROVENANCE,
                scope=StateScope.SERVER,
                key=_server_state_key(fact),
            )
        )
    return EffectConversionResult(effects=tuple(effects))


def convert_inferred_state_writes(
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
    modeled_locations: frozenset[tuple[str, int, int]],
) -> EffectConversionResult:
    """Infer SERVER state writes for verb-named mutating calls no provider models.

    A custom storage wrapper such as ``store.delete_result(...)`` emits *no*
    provider effect, so a real persistent write is invisible to coverage
    reasoning -- the FLAW-281 ``delete_report`` false negative, where the only
    modeled effect on a genuinely-destructive route is its response write.

    This conservative, framework-agnostic pass emits a low-confidence
    ``STATE_WRITE`` for a method call whose name matches a generic mutating verb
    and whose source location is not already covered by a provider effect
    (``modeled_locations``).  Only method-shaped calls (``recv.method(...)``)
    qualify; a bare function call is too ambiguous to treat as a write.

    FN-direction by construction: over-emitting a state write can only make
    coverage rules fire *more* (an FP risk), never fewer -- so it cannot create
    a false negative.  The low-confidence provenance keeps the inference honest
    and distinguishable from a provider-declared write.

    Scope is resolved by receiver binding (FLAW-291): ``SERVER`` only when the
    receiver provably binds to a module-level / class target -- the precondition
    the high-confidence "affects all users" rules require --
    else ``REQUEST``.  Without this, every verb-named method call (an ORM
    ``s.commit()``, a local accumulator ``out.append()``) was stamped ``SERVER``
    and flooded those rules with request-local false positives.  Coverage rules
    are unaffected: they select by category via ``Mutation.persistent()``
    (scope-agnostic), so the inferred ``STATE_WRITE`` category is unchanged and
    the FLAW-281 ``delete_report`` coverage fix is preserved.
    """
    module_targets = _module_state_targets_by_file(idx)
    effects: list[Effect] = []
    emitted: set[tuple[str, int, int]] = set()
    for edge in idx.call_graph.edges:
        # Require a real method-call source shape (``recv.method(...)``).  A bare
        # function call (``create_user(...)``) is too ambiguous to treat as a
        # persistent write -- and its resolved FQN is dotted like any module
        # member, so the callee FQN cannot distinguish the two.
        receiver = edge.receiver_expression
        if receiver is None:
            continue
        method = _called_method_name(edge)
        if method is None or not _is_mutating_verb(method):
            continue
        if _immediate_receiver_name(receiver) in _NON_PERSISTENT_RECEIVERS:
            continue
        loc = edge.location
        loc_key = (loc.file, loc.line, loc.column)
        if loc_key in modeled_locations or loc_key in emitted:
            continue
        function = functions_by_fqn.get(edge.caller_fqn)
        if function is None:
            continue
        emitted.add(loc_key)
        effects.append(
            Effect(
                category=EffectCategory.STATE_WRITE,
                function=function,
                location=_location(loc),
                expression=_call_expression(edge),
                provenance=_INFERRED_STATE_PROVENANCE,
                scope=_inferred_write_scope(
                    receiver, method, edge.caller_fqn, loc, module_targets, idx
                ),
                key=None,
            )
        )
    return EffectConversionResult(effects=tuple(effects))


# FLAW-310: a write onto the request principal proxy (current_user/g.user/...) is
# real, security-relevant state the existing converters never surface --
# convert_server_state_writes fires only for module-level targets, and the
# principal is request-scoped. High confidence: a direct L1 write fact whose
# receiver matches the canonical principal set.
_PRINCIPAL_ATTR_WRITE_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="principal_attr_writes",
    confidence=0.9,
    supporting_facts=("attribute write whose receiver is a request-principal proxy",),
)
# Attribute-shaped writes onto the principal. SUBSCRIPT (``session["k"] = ...``) is
# excluded: session writes are already modeled as STATE_WRITE/SESSION by providers,
# and the principal subscripts that matter are session keys. DEL / CALL_MUTATOR are
# not value-carrying assignments, so they cannot receive attacker input.
_PRINCIPAL_WRITE_KINDS = frozenset({AccessKind.ATTR, AccessKind.AUGMENTED})


def convert_principal_attr_writes(
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> EffectConversionResult:
    """Emit a ``PRINCIPAL_ATTR_WRITE`` for an attribute write onto the principal.

    ``current_user.is_admin = request.form["is_admin"]`` writes attacker input
    onto the authenticated principal's own role/identity -- a privilege-escalation
    false negative (FLAW-310).  L1 records the ``AttributeAccess`` (``is_write``),
    but no other converter emits an effect for it: ``convert_server_state_writes``
    requires a module-level/server-state receiver, and the principal proxy is
    request-scoped.  A principal-tampering rule consumes this category, gated on
    request taint reaching the write, to flag the escalation.

    FN-direction safe by construction: emitting an extra write can only make a
    consuming rule fire *more*, never fewer, so it cannot create a false negative.
    Precision is supplied downstream by the taint gate (a non-tainted principal
    write such as ``current_user.last_login = datetime.now()`` reaches no rule).
    """
    effects: list[Effect] = []
    for fact in idx.attributes:
        if not fact.is_write or fact.containing_function_fqn is None:
            continue
        if fact.access_kind not in _PRINCIPAL_WRITE_KINDS:
            continue
        if _attribute_name_is_private(fact.attr_name):
            continue
        if _PRINCIPAL_BASE_RE.search(fact.target_expr) is None:
            continue
        function = functions_by_fqn.get(fact.containing_function_fqn)
        if function is None:
            continue
        effects.append(
            Effect(
                category=EffectCategory.PRINCIPAL_ATTR_WRITE,
                function=function,
                location=_location(fact.location),
                expression=_attribute_expression(fact),
                provenance=_PRINCIPAL_ATTR_WRITE_PROVENANCE,
                scope=None,
                key=fact.attr_name,
            )
        )
    return EffectConversionResult(effects=tuple(effects))


def _called_method_name(edge: CallEdge) -> str | None:
    """Return the called method's bare name for a method-call edge, else ``None``.

    Prefers the source spelling (``edge.call_expression``) so it reflects what was
    actually written; falls back to the resolved ``callee_fqn``.  Only invoked for
    edges that already carry a ``receiver_expression`` (a real method call).
    """
    if edge.call_expression is not None:
        target = _call_target_expression(edge.call_expression)
        if target is not None:
            name = target.rpartition(".")[2]
            if name:
                return name
    if edge.callee_fqn is not None:
        return edge.callee_fqn.rpartition(".")[2] or None
    return None


def _is_mutating_verb(method: str) -> bool:
    if method in _EXACT_MUTATING_VERBS:
        return True
    return any(method.startswith(prefix) for prefix in _MUTATING_VERB_PREFIXES)


def _immediate_receiver_name(receiver: str) -> str:
    """The bare name of the immediate receiver (``logger`` in ``app.logger``)."""
    tail = receiver.rpartition(".")[2] or receiver
    return tail.strip().lower()


def _convert_attribute_match(
    match: ProviderMatch,
    descriptor: EffectAttributePattern,
    functions_by_fqn: Mapping[str, Function],
) -> EffectConversionResult:
    fact = match.source_fact
    assert isinstance(fact, AttributeAccess), (
        "EffectAttributePattern matches are constructed from AttributeAccess facts"
    )

    category_result = _effect_category(match, descriptor.category)
    if category_result.gaps:
        return EffectConversionResult(effects=(), gaps=category_result.gaps)
    category = category_result.category

    scope_result = _effect_scope(match, category, descriptor.scope)
    if scope_result.gaps:
        return EffectConversionResult(effects=(), gaps=scope_result.gaps)
    function = _function_for_attribute(match, fact, functions_by_fqn)
    if isinstance(function, AnalysisGap):
        return EffectConversionResult(effects=(), gaps=(function,))

    return EffectConversionResult(
        effects=(
            Effect(
                category=category,
                function=function,
                location=_location(fact.location),
                expression=_attribute_expression(fact),
                provenance=_L2_EFFECT_PROVENANCE,
                scope=scope_result.scope,
                key=fact.attr_name,
            ),
        )
    )


def _convert_subscript_match(
    match: ProviderMatch,
    descriptor: EffectSubscriptPattern,
    functions_by_fqn: Mapping[str, Function],
) -> EffectConversionResult:
    fact = match.source_fact
    assert isinstance(fact, AttributeAccess), (
        "EffectSubscriptPattern matches are constructed from AttributeAccess facts"
    )

    category_result = _effect_category(match, descriptor.category)
    if category_result.gaps:
        return EffectConversionResult(effects=(), gaps=category_result.gaps)
    category = category_result.category

    scope_result = _effect_scope(match, category, descriptor.scope)
    if scope_result.gaps:
        return EffectConversionResult(effects=(), gaps=scope_result.gaps)
    function = _function_for_attribute(match, fact, functions_by_fqn)
    if isinstance(function, AnalysisGap):
        return EffectConversionResult(effects=(), gaps=(function,))

    return EffectConversionResult(
        effects=(
            Effect(
                category=category,
                function=function,
                location=_location(fact.location),
                expression=_attribute_expression(fact),
                provenance=_L2_EFFECT_PROVENANCE,
                scope=scope_result.scope,
                key=_literal_string(fact.attr_name),
            ),
        )
    )


def _convert_proxy_match(
    match: ProviderMatch,
    descriptor: StateProxyPattern,
    functions_by_fqn: Mapping[str, Function],
) -> EffectConversionResult:
    fact = match.source_fact
    if isinstance(fact, SymbolRef):
        return _convert_proxy_symbol_match()
    assert isinstance(fact, AttributeAccess), (
        "StateProxyPattern matches are constructed from SymbolRef or AttributeAccess facts"
    )

    scope_result = _effect_scope(match, EffectCategory.STATE_READ, descriptor.scope)
    if scope_result.gaps:
        return EffectConversionResult(effects=(), gaps=scope_result.gaps)
    function = _function_for_attribute(match, fact, functions_by_fqn)
    if isinstance(function, AnalysisGap):
        return EffectConversionResult(effects=(), gaps=(function,))

    return EffectConversionResult(
        effects=(
            Effect(
                category=EffectCategory.STATE_READ,
                function=function,
                location=_location(fact.location),
                expression=_attribute_expression(fact),
                provenance=_L2_EFFECT_PROVENANCE,
                scope=scope_result.scope,
                key=_proxy_key(descriptor.resolves_to),
            ),
        )
    )


def _convert_call_match(
    match: ProviderMatch,
    descriptor: EffectCallPattern,
    functions_by_fqn: Mapping[str, Function],
) -> EffectConversionResult:
    fact = match.source_fact
    assert isinstance(fact, CallEdge), (
        "EffectCallPattern matches are constructed from CallEdge facts"
    )

    category_result = _effect_category(match, descriptor.category)
    if category_result.gaps:
        return EffectConversionResult(effects=(), gaps=category_result.gaps)
    category = category_result.category

    scope_result = _effect_scope(match, category, descriptor.scope)
    if scope_result.gaps:
        return EffectConversionResult(effects=(), gaps=scope_result.gaps)
    function = functions_by_fqn.get(fact.caller_fqn)
    if function is None:
        return EffectConversionResult(
            effects=(),
            gaps=(_missing_function_gap(match, fact.caller_fqn),),
        )

    keys: tuple[str | None, ...] = descriptor.keys or (None,)
    return EffectConversionResult(
        effects=tuple(
            Effect(
                category=category,
                function=function,
                location=_location(fact.location),
                expression=_call_expression(fact),
                provenance=_L2_EFFECT_PROVENANCE,
                scope=scope_result.scope,
                key=key,
            )
            for key in keys
        )
    )


@dataclass(frozen=True)
class _CategoryResult:
    category: EffectCategory
    gaps: tuple[AnalysisGap, ...] = ()


@dataclass(frozen=True)
class _ScopeResult:
    scope: StateScope | None
    gaps: tuple[AnalysisGap, ...] = ()


def _effect_category(match: ProviderMatch, raw: str) -> _CategoryResult:
    try:
        return _CategoryResult(EffectCategory[raw])
    except KeyError:
        return _CategoryResult(
            EffectCategory.STATE_READ,
            (
                _conversion_gap(
                    match,
                    f"Unknown effect category: {raw}",
                    origin_phase="effect_conversion",
                    source_error="effect_conversion: unknown category",
                ),
            ),
        )


def _effect_scope(match: ProviderMatch, category: EffectCategory, raw: str | None) -> _ScopeResult:
    if raw is None:
        if category not in _SUPPORTED_STATE_CATEGORIES:
            return _ScopeResult(None)
        return _ScopeResult(
            None,
            (
                _conversion_gap(
                    match,
                    "State effect descriptor is missing a scope",
                    origin_phase="effect_conversion",
                    source_error="effect_conversion: missing state scope",
                ),
            ),
        )
    try:
        return _ScopeResult(StateScope[raw])
    except KeyError:
        return _ScopeResult(
            None,
            (
                _conversion_gap(
                    match,
                    f"Unknown state scope: {raw}",
                    origin_phase="effect_conversion",
                    source_error="effect_conversion: unknown state scope",
                ),
            ),
        )


def _convert_proxy_symbol_match() -> EffectConversionResult:
    """A bare proxy SymbolRef is a resolution hint, not a function-scoped effect.

    ``StateProxyPattern`` matching deliberately emits SymbolRef matches so an
    import/local name like ``current_user`` can help receiver resolution for
    attribute matches such as ``current_user.id``.  SymbolRef facts do not carry
    containing-function metadata, so emitting a function-scoped state read here
    would be guesswork; the AttributeAccess match is the actionable effect.
    """
    return EffectConversionResult(effects=())


def _function_for_attribute(
    match: ProviderMatch,
    fact: AttributeAccess,
    functions_by_fqn: Mapping[str, Function],
) -> Function | AnalysisGap:
    if fact.containing_function_fqn is None:
        return _conversion_gap(
            match,
            "Effect match is not inside a function",
            origin_phase="effect_conversion",
            source_error="effect_conversion: missing containing function",
        )
    function = functions_by_fqn.get(fact.containing_function_fqn)
    if function is None:
        return _missing_function_gap(match, fact.containing_function_fqn)
    return function


def _missing_function_gap(match: ProviderMatch, function_fqn: str) -> AnalysisGap:
    return _conversion_gap(
        match,
        f"No converted Function found for {function_fqn}",
        origin_phase="effect_conversion",
        source_error="effect_conversion: missing function",
    )


def _attribute_expression(fact: AttributeAccess) -> str:
    if fact.access_kind is AccessKind.SUBSCRIPT:
        return f"{fact.target_expr}[{fact.attr_name}]"
    return f"{fact.target_expr}.{fact.attr_name}"


def _proxy_key(resolves_to: str | tuple[str, ...]) -> str | None:
    values = (resolves_to,) if isinstance(resolves_to, str) else resolves_to
    keys = {value.rpartition(".")[2] for value in values if value.rpartition(".")[1]}
    if len(keys) != 1:
        return None
    return keys.pop()


def _module_state_targets_by_file(idx: CodeIndex) -> dict[str, frozenset[str]]:
    from flawed._semantic._matching import _module_level_vf_for_file_all

    targets: dict[str, set[str]] = {}
    for class_ in idx.classes:
        targets.setdefault(class_.file, set()).add(class_.name)
    for file, edges in _module_level_vf_for_file_all(idx).items():
        for edge in edges:
            if edge.kind not in _ALIAS_FLOW_KINDS:
                continue
            name = _simple_name(edge.target_expr)
            if name is None:
                continue
            targets.setdefault(file, set()).add(name)
    return {file: frozenset(names) for file, names in targets.items()}


def _resolve_module_state_name(
    target_expr: str,
    file: str,
    containing_function_fqn: str | None,
    location: SourceSpan,
    module_targets: Mapping[str, frozenset[str]],
    idx: CodeIndex,
) -> str | None:
    """Resolve ``target_expr`` to a module-level / class target name in ``file``.

    Returns the resolved module-target name (the bare receiver name, possibly
    reached through a chain of local aliases), or ``None`` when the expression is
    not provably module-level / class state.  Shared by the attribute-write path
    (``_server_state_target``) and the inferred-write scope decision
    (``_inferred_write_scope``) so both judge "is this server-wide state?"
    identically.
    """
    file_targets = module_targets.get(file, frozenset())
    name = _simple_name(target_expr)
    if name is None or not file_targets:
        return None
    if name in file_targets:
        return name
    if containing_function_fqn is None:
        return None
    return _resolve_local_server_state_alias(
        name,
        containing_function_fqn,
        location,
        file_targets,
        idx,
        seen=frozenset({name}),
    )


def _server_state_target(
    fact: AttributeAccess,
    module_targets: Mapping[str, frozenset[str]],
    idx: CodeIndex,
) -> str | None:
    return _resolve_module_state_name(
        fact.target_expr,
        fact.location.file,
        fact.containing_function_fqn,
        fact.location,
        module_targets,
        idx,
    )


def _is_request_scoped_infra_call(receiver: str, method: str) -> bool:
    """Whether a verb-named method call is request-scoped infrastructure housekeeping.

    True for a request-scoped ``session`` mutation (an ORM / web session is per-request
    by construction) and cache invalidation (``cache.delete_memoized(...)`` and friends).
    Neither is module-global server state, even though ``db`` / ``cache`` are module
    symbols -- so they must not satisfy the "affects all users" precondition of
    the high-confidence server-wide-state-write rules. FN-safe: narrowly the named
    idioms; the inferred STATE_WRITE is still emitted (REQUEST), so the
    scope-agnostic coverage rules still see the call.
    """
    immediate = _immediate_receiver_name(receiver)
    if immediate in _REQUEST_SCOPED_RECEIVER_NAMES:
        return True
    if method in _CACHE_INVALIDATION_METHODS:
        return True
    return immediate in _CACHE_RECEIVER_NAMES and method in _CACHE_HOUSEKEEPING_METHODS


def _inferred_write_scope(
    receiver: str,
    method: str,
    caller_fqn: str,
    location: SourceSpan,
    module_targets: Mapping[str, frozenset[str]],
    idx: CodeIndex,
) -> StateScope:
    """``SERVER`` iff the call receiver provably binds to module/class state.

    An inferred write is a verb-name heuristic over a method call with no
    provider-declared effect.  Only when its receiver resolves to module-level or
    class state -- the *same* resolution ``convert_server_state_writes`` applies
    to attribute writes -- is the mutation provably server-wide, the precondition
    the high-confidence "affects all users" rules require.
    An unresolved or request-local receiver (an ORM session ``s.commit()``, a
    local accumulator ``out.append()``) is *not* provable server state, so
    ``REQUEST`` keeps those rules from over-firing.  Erring toward ``REQUEST`` is
    FN-safe: the SERVER rules are deliberately high-confidence (FP < 5%) and
    should fire only on provable server state; the request-scoped consumers
    (keyless-write-sensitive rules) skip keyless writes, and inferred writes carry ``key=None``.

    Request-scoped infrastructure housekeeping (a request-scoped ``session`` op, a
    ``cache.delete_memoized(...)`` invalidation) is ``REQUEST`` regardless of its
    module-level base symbol -- see ``_is_request_scoped_infra_call`` (FLAW-333).
    """
    if _is_request_scoped_infra_call(receiver, method):
        return StateScope.REQUEST
    resolved = _resolve_module_state_name(
        receiver, location.file, caller_fqn, location, module_targets, idx
    )
    return StateScope.SERVER if resolved is not None else StateScope.REQUEST


def _resolve_local_server_state_alias(
    name: str,
    function_fqn: str,
    before: SourceSpan,
    module_targets: frozenset[str],
    idx: CodeIndex,
    *,
    seen: frozenset[str],
) -> str | None:
    edge = _latest_alias_edge(name, function_fqn, before, idx)
    if edge is None:
        return None
    source_name = _simple_name(edge.source_expr)
    if source_name is None:
        return None
    if source_name in module_targets:
        return source_name
    if source_name in seen:
        return None
    return _resolve_local_server_state_alias(
        source_name,
        function_fqn,
        edge.source_location,
        module_targets,
        idx,
        seen=seen | {source_name},
    )


def _latest_alias_edge(
    name: str,
    function_fqn: str,
    before: SourceSpan,
    idx: CodeIndex,
) -> ValueFlowEdge | None:
    from flawed._semantic._matching import _value_flow_for_function

    candidates = [
        edge
        for edge in _value_flow_for_function(idx, function_fqn)
        if edge.target_expr == name
        and edge.kind in _ALIAS_FLOW_KINDS
        and _span_starts_not_after(edge.target_location, before)
    ]
    if not candidates:
        return None
    return max(
        candidates, key=lambda edge: (edge.target_location.line, edge.target_location.column)
    )


def _server_state_key(fact: AttributeAccess) -> str | None:
    if fact.access_kind is AccessKind.CALL_MUTATOR:
        return None
    if fact.access_kind is AccessKind.SUBSCRIPT:
        return _literal_string(fact.attr_name)
    return fact.attr_name


def _attribute_name_is_private(name: str) -> bool:
    return name.startswith("__") and name.endswith("__")
