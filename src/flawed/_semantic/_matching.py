"""Pattern matching and shared utilities for the provider engine.

This module contains the declarative descriptor matching logic that maps
Layer 1 structural facts to provider descriptors, plus shared utility
functions used by alias resolution and router-group extraction.  It is the
foundation that the other provider-engine sub-modules import from.

Provider predicate evaluation (``when`` predicates) lives in
``_predicate_eval.py`` — extracted by P11 (DISC-042).
"""

from __future__ import annotations

import ast
from collections import OrderedDict
from collections.abc import Hashable, Iterator
from typing import TYPE_CHECKING, Any, cast

from flawed._index._parsing import parse_analyzed_module
from flawed._index._types import (
    AccessKind,
    AttributeAccess,
    CallEdge,
    ClassRecord,
    DecoratorFact,
    EdgeSource,
    ExtractionProvenance,
    FlowKind,
    ResolutionStatus,
    SourceSpan,
    SymbolRef,
    ValueFlowEdge,
)
from flawed._semantic._budget import budgeted
from flawed._semantic._conversion_utils import simple_name as _simple_name
from flawed._semantic._conversion_utils import span_starts_not_after as _span_starts_not_after
from flawed._semantic._expr_cache import parse_expression as _parse_expression
from flawed._semantic._predicate_eval import (
    _concrete_facts_disagree,
    _descriptor_when,
    _evaluate_when_predicate,
    _type_matches,
)
from flawed._semantic._provider_engine import (
    _PHASE_DESCRIPTOR_ATTRS,
    _PHASE_ORDER,
    ParameterFact,
    PredicateStatus,
    ProviderDescriptor,
    ProviderMatch,
    ProviderPhase,
    ProviderSourceFact,
    canonicalize_fqn,
)
from flawed._semantic.providers import (
    CheckKind,
    CheckRegistrationPattern,
    ClaimContainerPattern,
    ClassAttributeGuardPattern,
    ClassViewPattern,
    ControlPlaneExemptionPattern,
    DependencyPattern,
    DispatchPattern,
    EffectAttributePattern,
    EffectCallPattern,
    EffectSubscriptPattern,
    FlowPropagatorPattern,
    ImperativeRoutePattern,
    InputAttributePattern,
    InputContainerPattern,
    InputFieldAccessPattern,
    InputMethodPattern,
    InputParameterPattern,
    LifecycleDecoratorPattern,
    LifecycleRegistrationPattern,
    MiddlewareClassPattern,
    Provider,
    RouteCallPattern,
    RouteDecorator,
    SafeGeneratedURLPattern,
    SecurityCheckPattern,
    StateProxyPattern,
    TaintSinkPattern,
    ValidatedValueGuardPattern,
)

if TYPE_CHECKING:
    from flawed._index import CodeIndex
    from flawed.core import AnalysisGap


def _provider_descriptor_methods(provider: Provider) -> dict[str, frozenset[str]]:
    methods_by_class: dict[str, set[str]] = {}
    for phase in _PHASE_ORDER:
        for descriptor in _phase_descriptors(provider, phase):
            for fqn in _matchable_descriptor_fqns(descriptor):
                receiver_fqn, method_name = _split_receiver_method_fqn(fqn)
                if receiver_fqn is None:
                    continue
                methods_by_class.setdefault(receiver_fqn, set()).add(method_name)
    return {
        receiver_fqn: frozenset(method_names)
        for receiver_fqn, method_names in methods_by_class.items()
    }


def _matchable_descriptor_fqns(descriptor: ProviderDescriptor) -> tuple[str, ...]:
    if isinstance(
        descriptor,
        RouteDecorator
        | RouteCallPattern
        | InputMethodPattern
        | EffectCallPattern
        | SecurityCheckPattern
        | LifecycleDecoratorPattern
        | LifecycleRegistrationPattern
        | CheckRegistrationPattern
        | ControlPlaneExemptionPattern
        | DependencyPattern
        | DispatchPattern
        | FlowPropagatorPattern
        | SafeGeneratedURLPattern
        | ValidatedValueGuardPattern
        | TaintSinkPattern,
    ):
        return _descriptor_fqns(descriptor)
    if isinstance(descriptor, EffectSubscriptPattern):
        return _as_tuple(descriptor.receiver_fqn)
    return ()


def _split_receiver_method_fqn(fqn: str) -> tuple[str | None, str]:
    receiver_fqn, separator, method_name = fqn.rpartition(".")
    if not separator or not receiver_fqn:
        return None, method_name
    return receiver_fqn, method_name


# ── Matching cache ────────────────────────────────────────────────────
#
# Several matching helpers recompute the same derived data structures
# on every call — ``_module_fqns_by_file`` iterates all functions and
# classes, ``_resolve_module_level_name`` linear-scans all value-flow
# edges, etc.  Because matchers run once per (provider, phase,
# descriptor, fact) tuple, these O(n) scans are invoked hundreds or
# thousands of times per engine run.
#
# The cache below is keyed by ``id(idx)`` — safe because a CodeIndex
# is long-lived (one per scan) and immutable during matching.


class _MatchingCache:
    """Lazy, per-CodeIndex cache for derived lookup structures."""

    __slots__ = (
        "_call_edges_by_caller",
        "_class_by_fqn",
        "_function_params",
        "_idx",
        "_module_fqns",
        "_module_level_assignments",
        "_module_level_vf_by_file",
        "_symbol_refs_by_file_line",
        "_value_flow_by_function",
    )

    def __init__(self, idx: CodeIndex) -> None:
        self._idx = idx
        self._module_fqns: dict[str, str] | None = None
        self._module_level_assignments: dict[tuple[str, str], str] | None = None
        self._value_flow_by_function: dict[str | None, list[ValueFlowEdge]] | None = None
        self._function_params: dict[str, frozenset[str]] | None = None
        self._module_level_vf_by_file: dict[str, list[ValueFlowEdge]] | None = None
        self._call_edges_by_caller: dict[str, list[CallEdge]] | None = None
        self._symbol_refs_by_file_line: dict[tuple[str, int], tuple[SymbolRef, ...]] | None = None
        self._class_by_fqn: dict[str, ClassRecord] | None = None

    @property
    def module_fqns_by_file(self) -> dict[str, str]:
        if self._module_fqns is None:
            self._module_fqns = _compute_module_fqns_by_file(self._idx)
        return self._module_fqns

    @property
    def module_level_assignments(self) -> dict[tuple[str, str], str]:
        """Map ``(file, target_name)`` → module-qualified FQN for module-level assignments."""
        if self._module_level_assignments is None:
            idx = self._idx
            result: dict[tuple[str, str], str] = {}
            mods = self.module_fqns_by_file
            for edge in idx.value_flow.edges:
                if edge.containing_function_fqn is not None:
                    continue
                if edge.kind is not FlowKind.ASSIGN:
                    continue
                name = _simple_name(edge.target_expr)
                if name is None:
                    continue
                file = edge.target_location.file
                module_fqn = mods.get(file)
                if module_fqn is not None:
                    result.setdefault((file, name), f"{module_fqn}.{name}")
            self._module_level_assignments = result
        return self._module_level_assignments

    @property
    def value_flow_by_function(self) -> dict[str | None, list[ValueFlowEdge]]:
        """Value-flow edges grouped by containing function FQN (None = module level)."""
        if self._value_flow_by_function is None:
            grouped: dict[str | None, list[ValueFlowEdge]] = {}
            for edge in self._idx.value_flow.edges:
                grouped.setdefault(edge.containing_function_fqn, []).append(edge)
            self._value_flow_by_function = grouped
        return self._value_flow_by_function

    @property
    def function_params(self) -> dict[str, frozenset[str]]:
        """Map function FQN → frozenset of parameter names."""
        if self._function_params is None:
            self._function_params = {
                fn.fqn: frozenset(p.name for p in fn.params) for fn in self._idx.functions
            }
        return self._function_params

    @property
    def module_level_vf_by_file(self) -> dict[str, list[ValueFlowEdge]]:
        """Module-level value-flow edges grouped by file path."""
        if self._module_level_vf_by_file is None:
            grouped: dict[str, list[ValueFlowEdge]] = {}
            for edge in self.value_flow_by_function.get(None, ()):
                grouped.setdefault(edge.target_location.file, []).append(edge)
            self._module_level_vf_by_file = grouped
        return self._module_level_vf_by_file

    @property
    def call_edges_by_caller(self) -> dict[str, list[CallEdge]]:
        """Call-graph edges grouped by caller FQN."""
        if self._call_edges_by_caller is None:
            grouped: dict[str, list[CallEdge]] = {}
            for edge in self._idx.call_graph.edges:
                if edge.caller_fqn is not None:
                    grouped.setdefault(edge.caller_fqn, []).append(edge)
            self._call_edges_by_caller = grouped
        return self._call_edges_by_caller

    @property
    def symbol_refs_by_file_line(self) -> dict[tuple[str, int], tuple[SymbolRef, ...]]:
        """Symbol references grouped by source file and line."""
        if self._symbol_refs_by_file_line is None:
            grouped: dict[tuple[str, int], list[SymbolRef]] = {}
            for ref in self._idx.symbols.refs:
                grouped.setdefault((ref.location.file, ref.location.line), []).append(ref)
            self._symbol_refs_by_file_line = {
                location: tuple(refs) for location, refs in grouped.items()
            }
        return self._symbol_refs_by_file_line

    @property
    def class_by_fqn(self) -> dict[str, ClassRecord]:
        """Project class records keyed by fully qualified name."""
        if self._class_by_fqn is None:
            self._class_by_fqn = {klass.fqn: klass for klass in self._idx.classes}
        return self._class_by_fqn


_MAX_MATCHING_CACHES = 8
_cache_store: OrderedDict[int, _MatchingCache] = OrderedDict()


def _get_cache(idx: CodeIndex) -> _MatchingCache:
    key = id(idx)
    cache = _cache_store.get(key)
    if cache is None:
        cache = _MatchingCache(idx)
        _cache_store[key] = cache
        if len(_cache_store) > _MAX_MATCHING_CACHES:
            _cache_store.popitem(last=False)
    else:
        _cache_store.move_to_end(key)
    return cache


def clear_matching_cache() -> None:
    """Drop per-index matching caches after a provider run or focused test."""
    _cache_store.clear()


def _module_fqns_by_file(idx: CodeIndex) -> dict[str, str]:
    return _get_cache(idx).module_fqns_by_file


def _value_flow_for_function(idx: CodeIndex, fn_fqn: str | None) -> list[ValueFlowEdge]:
    """Return value-flow edges for *fn_fqn* via the per-CodeIndex cache."""
    return _get_cache(idx).value_flow_by_function.get(fn_fqn, [])


def _module_level_vf_for_file(idx: CodeIndex, file: str) -> list[ValueFlowEdge]:
    """Return module-level value-flow edges for *file* via the per-CodeIndex cache."""
    return _get_cache(idx).module_level_vf_by_file.get(file, [])


def _module_level_vf_for_file_all(idx: CodeIndex) -> dict[str, list[ValueFlowEdge]]:
    """Return all module-level value-flow edges grouped by file."""
    return _get_cache(idx).module_level_vf_by_file


def _call_edges_for_caller(idx: CodeIndex, caller_fqn: str) -> list[CallEdge]:
    """Return call-graph edges where *caller_fqn* is the caller."""
    return _get_cache(idx).call_edges_by_caller.get(caller_fqn, [])


def _symbol_refs_for_file_line(idx: CodeIndex, file: str, line: int) -> tuple[SymbolRef, ...]:
    """Return symbol references at one source line via the per-CodeIndex cache."""
    return _get_cache(idx).symbol_refs_by_file_line.get((file, line), ())


def _compute_module_fqns_by_file(idx: CodeIndex) -> dict[str, str]:
    module_by_file: dict[str, str] = {}
    for function in idx.functions:
        if function.is_nested:
            continue
        if function.is_method and function.parent_class is not None:
            module_fqn = function.parent_class.rsplit(".", maxsplit=1)[0]
        else:
            module_fqn = function.fqn.rsplit(".", maxsplit=1)[0]
        module_by_file.setdefault(function.file, module_fqn)
    for klass in idx.classes:
        module_by_file.setdefault(klass.file, klass.fqn.rsplit(".", maxsplit=1)[0])
    for file in _indexed_files(idx):
        module_by_file.setdefault(file, idx.module_fqn_for_file(file))
    return module_by_file


def _indexed_files(idx: CodeIndex) -> frozenset[str]:
    files: set[str] = set()
    files.update(function.file for function in idx.functions)
    files.update(klass.file for klass in idx.classes)
    files.update(decorator.location.file for decorator in idx.decorators)
    files.update(import_fact.location.file for import_fact in idx.imports)
    files.update(attribute.location.file for attribute in idx.attributes)
    files.update(ref.location.file for ref in idx.symbols.refs)
    files.update(edge.location.file for edge in idx.call_graph.edges)
    for edge in idx.value_flow.edges:
        files.add(edge.source_location.file)
        files.add(edge.target_location.file)
    return frozenset(files)


def _dotted_name_parts(expression: str) -> tuple[str, ...] | None:
    tree = _parse_expression(expression)
    if tree is None:
        return None
    node = tree.body

    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return tuple(reversed(parts))


def _call_callee_expr(expression: str) -> str | None:
    tree = _parse_expression(expression)
    if tree is None:
        return None
    node = tree.body
    if not isinstance(node, ast.Call):
        return None
    return ast.unparse(node.func)


def _unresolved_call_simple_name(call_expression: str | None) -> str | None:
    if call_expression is None:
        return None
    callee = _call_callee_expr(call_expression) or call_expression
    parts = _dotted_name_parts(callee)
    if not parts:
        return None
    return parts[-1]


def _decorator_observed_fqns(fact: DecoratorFact, idx: CodeIndex) -> tuple[str, ...]:
    candidates: list[str] = [fact.fqn] if fact.fqn is not None else []
    module_fqn = _module_fqns_by_file(idx).get(fact.location.file)
    if (
        module_fqn is not None
        and fact.fqn is not None
        and not fact.fqn.startswith(f"{module_fqn}.")
    ):
        candidates.append(f"{module_fqn}.{fact.fqn}")
    for ref in _symbol_refs_for_file_line(idx, fact.location.file, fact.location.line):
        if ref.fqn is None:
            continue
        candidates.append(ref.fqn)
    candidates.extend(_decorator_receiver_typed_fqns(fact, idx))
    return tuple(candidates)


def _decorator_receiver_typed_fqns(fact: DecoratorFact, idx: CodeIndex) -> tuple[str, ...]:
    """Resolve an instance-attribute decorator (``@recv.attr``) to ``<Class>.attr`` FQNs.

    A decorator written as an attribute call on a locally-constructed instance —
    e.g. ``@ns.route(...)`` where ``ns = Namespace(...)`` — has an L1-resolved
    ``fqn`` of the *module-local* binding (``<module>.ns.route``), never the
    library FQN (``flask_restx.Namespace.route``).  The decorator path therefore
    never matched provider descriptors keyed on the library FQN — the corpus-wide
    flask-restx false negative (a large ``api/v1`` surface was invisible).

    The call path already resolves a receiver variable's class from its local
    constructor (``_resolve_variable_class`` over value-flow ASSIGN edges).  This
    shares that machinery into the decorator path: split ``recv.attr``, resolve
    ``recv``'s class in the scope enclosing the decorated entity (module scope for
    a module-level class, the factory function for a nested one), and emit
    ``<ClassFqn>.attr`` as an *additional* observed-FQN candidate that the caller
    canonicalises against the provider alias map.  Purely additive — it can only
    make an unmatched decorator match, never suppress an existing match (strictly
    FN-reducing).  When the receiver cannot be typed, behaviour is unchanged (the
    decorator stays unresolved, honestly).
    """
    receiver, sep, attr = fact.name.partition(".")
    if not sep or "." in attr or not receiver.isidentifier() or not attr.isidentifier():
        return ()
    # The receiver variable lives in the scope that encloses the decorated entity:
    # the module (value-flow key ``None``) for a module-level def/class, or the
    # factory function for a nested one.  ``function_params`` is keyed by function
    # FQN, so its keys are exactly the set of known function scopes.
    parent_scope = fact.target_fqn.rpartition(".")[0]
    containing_fqn = parent_scope if parent_scope in _get_cache(idx).function_params else None
    class_fqn = _resolve_variable_class(
        receiver, containing_fqn, fact.location, fact.location.file, idx
    )
    if class_fqn is None:
        return ()
    return (f"{class_fqn}.{attr}",)


def _match_phase(
    provider: Provider,
    phase: ProviderPhase,
    idx: CodeIndex,
    aliases: dict[str, str],
) -> tuple[ProviderMatch, ...]:
    matches: list[ProviderMatch] = []
    for descriptor in _phase_descriptors(provider, phase):
        matches.extend(_match_descriptor(provider, phase, descriptor, idx, aliases))
    return _prefer_precise_call_matches(tuple(matches))


def _prefer_precise_call_matches(matches: tuple[ProviderMatch, ...]) -> tuple[ProviderMatch, ...]:
    """Drop lossy call matches when an AST match covers the same site.

    A non-AST edge (e.g. a hierarchy-resolved one) may not carry call arguments
    or caller FQNs in the same shape as LibCST AST edges. When both sources
    matched the same provider descriptor at the same call site, the AST edge is
    the stable conversion input because it preserves arguments and source-relative
    caller identity.
    """
    if len(matches) < 2:
        return matches

    precise_keys: set[_CallSiteKey] = set()
    precise_by_locus: dict[_CallSiteLocus, list[ProviderMatch]] = {}
    for match in matches:
        if not _is_precise_call_match(match):
            continue
        core = _call_site_core(match)
        precise_keys.add(_call_site_key(match, core))
        precise_by_locus.setdefault(_call_site_locus(match), []).append(match)
    if not precise_keys:
        return matches

    kept: list[ProviderMatch] = []
    for match in matches:
        if _is_lossy_call_match(match) and _has_precise_call_site(
            match,
            precise_keys,
            precise_by_locus,
        ):
            continue
        kept.append(match)
    return tuple(kept)


_CallSiteCore = tuple[str, Hashable, int, int]
_CallSiteKey = tuple[_CallSiteCore, str, str]
_CallSiteLocus = tuple[Hashable, int]


def _has_precise_call_site(
    match: ProviderMatch,
    precise_keys: set[_CallSiteKey],
    precise_by_locus: dict[_CallSiteLocus, list[ProviderMatch]],
) -> bool:
    core = _call_site_core(match)
    if _call_site_key(match, core) in precise_keys:
        return True

    # The exact fast path missed: the AST and non-AST (hierarchy-resolved) edges
    # for one logical call routinely diverge on column and on which declared alias each
    # resolved to.  Fall back to the relaxed equivalence, but only against precise
    # matches that already share this match's descriptor and line (the locus
    # bucket), keeping the comparison O(matches-at-this-line).
    return any(
        _same_provider_call_site(match, precise)
        for precise in precise_by_locus.get(_call_site_locus(match), ())
    )


def _call_site_locus(match: ProviderMatch) -> _CallSiteLocus:
    return (_descriptor_identity(match.descriptor), match.location.line)


def _call_site_core(match: ProviderMatch) -> _CallSiteCore:
    return (
        match.canonical_fqn,
        _descriptor_identity(match.descriptor),
        match.location.line,
        match.location.column,
    )


def _call_site_key(match: ProviderMatch, core: _CallSiteCore) -> _CallSiteKey:
    fact = match.source_fact
    caller_fqn = fact.caller_fqn if isinstance(fact, CallEdge) else ""
    return (core, _normalized_file(match.location.file), caller_fqn)


def _descriptor_identity(descriptor: ProviderDescriptor) -> Hashable:
    try:
        hash(descriptor)
    except TypeError:
        return (type(descriptor), id(descriptor))
    return (type(descriptor), cast("Any", descriptor))


def _normalized_file(file: str) -> str:
    return "" if file == "<unknown>" else file.replace("\\", "/")


def _is_precise_call_match(match: ProviderMatch) -> bool:
    fact = match.source_fact
    return isinstance(fact, CallEdge) and fact.source is EdgeSource.AST


def _is_lossy_call_match(match: ProviderMatch) -> bool:
    fact = match.source_fact
    return isinstance(fact, CallEdge) and fact.source is not EdgeSource.AST and not fact.arguments


def _same_provider_call_site(left: ProviderMatch, right: ProviderMatch) -> bool:
    left_fact = left.source_fact
    right_fact = right.source_fact
    if not isinstance(left_fact, CallEdge) or not isinstance(right_fact, CallEdge):
        return False
    if left.descriptor != right.descriptor:
        return False
    # Same descriptor + same line are already guaranteed by the caller's locus
    # bucket.  One logical call's AST and non-AST edges may resolve to different
    # *declared aliases* of that descriptor and report different columns, so
    # equate any two FQNs the descriptor itself declares as aliases and ignore
    # column entirely (the precise sibling is strictly more informative).
    if not _alias_equivalent_fqn(left, right):
        return False
    if _same_or_nested_file(left.location.file, right.location.file):
        return True
    return _same_or_nested_fqn(left_fact.caller_fqn, right_fact.caller_fqn)


def _alias_equivalent_fqn(left: ProviderMatch, right: ProviderMatch) -> bool:
    """True when two FQNs name the same call via the descriptor's declared aliases.

    A provider may declare re-export aliases as one tuple on a single descriptor
    (e.g. ``("requests.get", "requests.api.get")``); the AST edge resolves to one
    and a non-AST edge to another for the *same* physical call.  Only FQNs the
    descriptor itself declares are ever equated, so two semantically different
    endpoints can never be merged.
    """
    if left.canonical_fqn == right.canonical_fqn:
        return True
    declared = frozenset(_matchable_descriptor_fqns(left.descriptor))
    if left.canonical_fqn in declared and right.canonical_fqn in declared:
        return True
    return _same_or_nested_fqn(left.canonical_fqn, right.canonical_fqn)


def _same_or_nested_file(left: str, right: str) -> bool:
    if left == "<unknown>" or right == "<unknown>":
        return False
    left_norm = left.replace("\\", "/")
    right_norm = right.replace("\\", "/")
    return (
        left_norm == right_norm
        or left_norm.endswith(f"/{right_norm}")
        or right_norm.endswith(f"/{left_norm}")
    )


def _same_or_nested_fqn(left: str, right: str) -> bool:
    return left == right or left.endswith(f".{right}") or right.endswith(f".{left}")


def _phase_descriptors(provider: Provider, phase: ProviderPhase) -> tuple[ProviderDescriptor, ...]:
    return cast(
        "tuple[ProviderDescriptor, ...]",
        getattr(provider, _PHASE_DESCRIPTOR_ATTRS[phase]),
    )


def _match_descriptor(  # noqa: PLR0911, PLR0912  — one return per descriptor type
    provider: Provider,
    phase: ProviderPhase,
    descriptor: ProviderDescriptor,
    idx: CodeIndex,
    aliases: dict[str, str],
) -> tuple[ProviderMatch, ...]:
    if isinstance(descriptor, RouteDecorator | LifecycleDecoratorPattern) or (
        isinstance(descriptor, SecurityCheckPattern) and descriptor.kind is CheckKind.DECORATOR
    ):
        return _match_decorator_descriptor(provider, phase, descriptor, idx, aliases)
    if isinstance(
        descriptor,
        InputAttributePattern | EffectAttributePattern | EffectSubscriptPattern,
    ):
        return _match_attribute_descriptor(provider, phase, descriptor, idx, aliases)
    if isinstance(descriptor, InputContainerPattern):
        return _match_container_descriptor(provider, phase, descriptor, idx, aliases)
    if isinstance(descriptor, StateProxyPattern):
        return _match_symbol_descriptor(provider, phase, descriptor, idx, aliases)
    if isinstance(descriptor, ClassViewPattern):
        return _match_class_view_descriptor(provider, phase, descriptor, idx, aliases)
    if isinstance(descriptor, MiddlewareClassPattern):
        return _match_middleware_class_descriptor(provider, phase, descriptor, idx, aliases)
    if isinstance(descriptor, ImperativeRoutePattern):
        return _match_imperative_route_descriptor(provider, phase, descriptor, idx, aliases)
    if isinstance(descriptor, DispatchPattern):
        return _match_dispatch_descriptor(provider, phase, descriptor, idx, aliases)
    if isinstance(
        descriptor,
        RouteCallPattern
        | InputMethodPattern
        | ClaimContainerPattern
        | EffectCallPattern
        | LifecycleRegistrationPattern
        | CheckRegistrationPattern
        | ControlPlaneExemptionPattern
        | DependencyPattern
        | FlowPropagatorPattern
        | SafeGeneratedURLPattern
        | ValidatedValueGuardPattern
        | TaintSinkPattern,
    ):
        return _match_call_descriptor(provider, phase, descriptor, idx, aliases)
    if isinstance(descriptor, SecurityCheckPattern):
        return _match_security_check_descriptor(provider, phase, descriptor, idx, aliases)
    if isinstance(descriptor, ClassAttributeGuardPattern):
        return _match_class_attribute_guard(provider, phase, descriptor, idx, aliases)
    if isinstance(descriptor, InputParameterPattern):
        return _match_parameter_descriptor(provider, phase, descriptor, idx, aliases)
    if isinstance(descriptor, InputFieldAccessPattern):
        return _match_field_access_descriptor(provider, phase, descriptor, idx, aliases)
    return ()


def _match_security_check_descriptor(
    provider: Provider,
    phase: ProviderPhase,
    descriptor: SecurityCheckPattern,
    idx: CodeIndex,
    aliases: dict[str, str],
) -> tuple[ProviderMatch, ...]:
    if descriptor.kind is CheckKind.DECORATOR:
        return _match_decorator_descriptor(provider, phase, descriptor, idx, aliases)
    if descriptor.kind is CheckKind.METHOD_CALL:
        return _match_security_method_call_descriptor(provider, phase, descriptor, idx, aliases)
    return _match_call_descriptor(provider, phase, descriptor, idx, aliases)


def _match_security_method_call_descriptor(
    provider: Provider,
    phase: ProviderPhase,
    descriptor: SecurityCheckPattern,
    idx: CodeIndex,
    aliases: dict[str, str],
) -> tuple[ProviderMatch, ...]:
    descriptor_fqns = frozenset(_descriptor_fqns(descriptor))
    descriptor_methods = tuple(
        parts for fqn in descriptor_fqns if (parts := _method_descriptor_parts(fqn)) is not None
    )
    if not descriptor_methods:
        return ()

    matches: list[ProviderMatch] = []
    for edge in budgeted(idx.call_graph.edges):
        if edge.callee_fqn is None:
            continue
        canonical_fqn = canonicalize_fqn(edge.callee_fqn, aliases)
        if canonical_fqn in descriptor_fqns:
            matches.append(
                _make_match(provider, phase, descriptor, edge, edge.callee_fqn, canonical_fqn)
            )
            continue
        edge_owner, edge_method = _split_method_fqn(canonical_fqn)
        if edge_owner is None or edge_method is None:
            continue
        for descriptor_owner, descriptor_method in descriptor_methods:
            if edge_method != descriptor_method:
                continue
            if not _method_owner_extends_descriptor(
                edge_owner,
                descriptor_owner,
                edge,
                idx,
                aliases,
            ):
                continue
            matches.append(
                _make_match(
                    provider,
                    phase,
                    descriptor,
                    edge,
                    edge.callee_fqn,
                    f"{descriptor_owner}.{descriptor_method}",
                )
            )
            break
    return _prefer_precise_call_matches(tuple(matches))


def _method_owner_extends_descriptor(
    edge_owner: str,
    descriptor_owner: str,
    edge: CallEdge,
    idx: CodeIndex,
    aliases: dict[str, str],
) -> bool:
    target_fqns = frozenset({descriptor_owner})
    if _fqn_extends_any(edge_owner, target_fqns, idx, aliases):
        return True

    receiver_name = _method_call_receiver(edge)
    if receiver_name is None:
        return False
    class_fqn = _resolve_variable_class(
        receiver_name,
        edge.caller_fqn,
        edge.location,
        edge.location.file,
        idx,
    )
    return class_fqn is not None and _fqn_extends_any(class_fqn, target_fqns, idx, aliases)


def _method_call_receiver(edge: CallEdge) -> str | None:
    if edge.call_expression is not None:
        target_expr = edge.call_expression
    elif edge.callee_fqn is not None:
        target_expr = edge.callee_fqn
    else:
        return None
    parts = _dotted_name_parts(target_expr)
    if parts is None or len(parts) < 2:
        return None
    return parts[-2] if edge.call_expression is None else parts[0]


def _method_descriptor_parts(fqn: str) -> tuple[str, str] | None:
    owner, method = _split_method_fqn(fqn)
    if owner is None or method is None:
        return None
    return owner, method


def _split_method_fqn(fqn: str) -> tuple[str | None, str | None]:
    owner, sep, method = fqn.rpartition(".")
    if not sep or not owner or not method:
        return None, None
    return owner, method


def _match_decorator_descriptor(
    provider: Provider,
    phase: ProviderPhase,
    descriptor: RouteDecorator | LifecycleDecoratorPattern | SecurityCheckPattern,
    idx: CodeIndex,
    aliases: dict[str, str],
) -> tuple[ProviderMatch, ...]:
    descriptor_fqns = frozenset(_descriptor_fqns(descriptor))
    matches: list[ProviderMatch] = []
    for fact in idx.decorators:
        seen_candidates: set[str] = set()
        for observed_fqn in _decorator_observed_fqns(fact, idx):
            if observed_fqn in seen_candidates:
                continue
            seen_candidates.add(observed_fqn)
            match_observed_fqn = observed_fqn
            canonical_fqn = canonicalize_fqn(match_observed_fqn, aliases)
            if canonical_fqn not in descriptor_fqns:
                alias_key = _unique_alias_key_with_suffix(match_observed_fqn, aliases)
                if alias_key is not None:
                    canonical_fqn = canonicalize_fqn(alias_key, aliases)
                    match_observed_fqn = alias_key
            if canonical_fqn in descriptor_fqns:
                matches.append(
                    _make_match(
                        provider,
                        phase,
                        descriptor,
                        fact,
                        match_observed_fqn,
                        canonical_fqn,
                    )
                )
                break
    return tuple(matches)


def _unique_alias_key_with_suffix(
    observed_fqn: str,
    aliases: dict[str, str],
) -> str | None:
    """Recover provider aliases for package-relative decorator FQNs.

    L1 can emit decorators imported from sibling packages as relative or
    package-root-less FQNs (for example ``..bp.before_request`` from
    ``pkg/auth/middleware.py`` while the router-group alias is
    ``pkg.bp.before_request``).  If exactly one known alias ends with the same
    receiver/method suffix, use it; ambiguity intentionally stays unresolved.
    """

    suffix = observed_fqn.lstrip(".")
    if not suffix:
        return None
    matches = [alias for alias in aliases if alias.endswith(f".{suffix}") or alias == suffix]
    if len(matches) != 1:
        return None
    return matches[0]


def _call_receiver_name(edge: CallEdge) -> str | None:
    """Extract the receiver variable name from a method call edge.

    For ``db.add(user)`` with ``call_expression="db.add(user)"``, extracts
    the callee ``db.add`` then returns the root ``db``.  Falls back to
    ``_method_call_receiver`` for edges without a call expression.
    """
    if edge.call_expression is not None:
        callee = _call_callee_expr(edge.call_expression)
        if callee is not None:
            parts = _dotted_name_parts(callee)
            if parts is not None and len(parts) >= 2:
                return parts[0]
    return _method_call_receiver(edge)


def _resolve_call_receiver_type(
    edge: CallEdge,
    idx: CodeIndex,
) -> str | None:
    """Resolve the receiver variable's declared type via type enrichment.

    For a call like ``db.add(user)`` where L1 resolves the callee as
    ``create_user.<locals>.db.add``, type enrichment can reveal that ``db``
    has type ``sqlalchemy.orm.session.Session``.  This allows the matching
    engine to reconstruct the canonical FQN ``Session.add`` and match it
    against provider descriptors.
    """
    receiver_name = _call_receiver_name(edge)
    if receiver_name is None:
        return None
    if idx.type_enrichment is None:
        # No enrichment oracle — still resolve from source-level facts so a
        # local constructor binding works in index-only / no-oracle runs.
        return _resolve_receiver_type_from_source(receiver_name, edge, idx)
    facts = idx.type_enrichment.types_for_expression(
        receiver_name,
        edge.location.file,
        containing_function_fqn=edge.caller_fqn,
    )
    concrete = tuple(f for f in facts if f.is_concrete)
    if not concrete:
        return _resolve_receiver_type_from_source(receiver_name, edge, idx)
    if _concrete_facts_disagree(concrete):
        return None
    return concrete[0].declared_type


def _resolve_receiver_type_from_source(
    receiver_name: str,
    edge: CallEdge,
    idx: CodeIndex,
) -> str | None:
    """Resolve a receiver variable's type from source-level facts.

    Used when type enrichment is absent or returns no *concrete* type (e.g.
    ``Unknown`` for a function-local variable the oracle didn't model).  Tries
    an explicit local annotation (``name: Type``) first, then the constructor
    class of a local assignment (``name = Type(...)`` via a value-flow ASSIGN
    edge).  This makes receiver typing independent of *binding location*: a
    blueprint, session, or any object constructed inside a factory function
    resolves to the same canonical type as a module-level binding would (the
    module-level path already resolves via alias canonicalisation).
    """
    annotated = _resolve_variable_annotation(
        receiver_name,
        edge.caller_fqn,
        edge.location,
        edge.location.file,
        idx,
    )
    if annotated is not None:
        return annotated
    return _resolve_variable_class(
        receiver_name,
        edge.caller_fqn,
        edge.location,
        edge.location.file,
        idx,
    )


def _match_call_descriptor(
    provider: Provider,
    phase: ProviderPhase,
    descriptor: (
        RouteCallPattern
        | InputMethodPattern
        | ClaimContainerPattern
        | EffectCallPattern
        | SecurityCheckPattern
        | LifecycleRegistrationPattern
        | CheckRegistrationPattern
        | ControlPlaneExemptionPattern
        | DependencyPattern
        | DispatchPattern
        | FlowPropagatorPattern
        | SafeGeneratedURLPattern
        | ValidatedValueGuardPattern
        | TaintSinkPattern
    ),
    idx: CodeIndex,
    aliases: dict[str, str],
) -> tuple[ProviderMatch, ...]:
    if isinstance(descriptor, SecurityCheckPattern) and descriptor.kind is CheckKind.DECORATOR:
        return ()

    descriptor_fqns = frozenset(_descriptor_fqns(descriptor))
    descriptor_names = _descriptor_names(descriptor)

    # Precompute method → owner mappings for receiver-type fallback.
    # E.g. maps ``"add"`` → ``{"owner.Class"}`` for a descriptor ``owner.Class.add``.
    descriptor_method_owners: dict[str, set[str]] = {}
    for fqn in descriptor_fqns:
        owner, method = _split_receiver_method_fqn(fqn)
        if owner is not None:
            descriptor_method_owners.setdefault(method, set()).add(owner)

    matches: list[ProviderMatch] = []
    for edge in budgeted(idx.call_graph.edges):
        if edge.callee_fqn is None:
            if (
                descriptor_names
                and (unresolved_name := _unresolved_call_simple_name(edge.call_expression))
                in descriptor_names
            ):
                predicate_eval = _evaluate_when_predicate(
                    _descriptor_when(descriptor), edge, idx.type_enrichment
                )
                if predicate_eval.status is PredicateStatus.FAILED:
                    continue
                matches.append(
                    _make_match(
                        provider,
                        phase,
                        descriptor,
                        edge,
                        unresolved_name,
                        unresolved_name,
                        predicate_status=predicate_eval.status,
                        predicate_gaps=predicate_eval.gaps,
                    )
                )
            continue
        if (
            isinstance(descriptor, CheckRegistrationPattern)
            and descriptor.require_call_result_invocation
            and not _is_call_result_invocation(edge.call_expression)
        ):
            continue
        canonical_fqn = canonicalize_fqn(edge.callee_fqn, aliases)

        # ── Exact FQN match (primary path) ──────────────────────────
        if canonical_fqn in descriptor_fqns or _fqn_simple_name(canonical_fqn) in descriptor_names:
            predicate_eval = _evaluate_when_predicate(
                _descriptor_when(descriptor), edge, idx.type_enrichment
            )
            if predicate_eval.status is PredicateStatus.FAILED:
                continue
            matches.append(
                _make_match(
                    provider,
                    phase,
                    descriptor,
                    edge,
                    edge.callee_fqn,
                    canonical_fqn,
                    predicate_status=predicate_eval.status,
                    predicate_gaps=predicate_eval.gaps,
                )
            )
            continue

        # ── Receiver-type resolution fallback ───────────────────────
        resolved = _match_via_receiver_type(
            edge,
            canonical_fqn,
            descriptor_method_owners,
            descriptor,
            idx,
            provider,
            phase,
            aliases,
        )
        if resolved is not None:
            matches.append(resolved)

    return tuple(matches)


def _is_call_result_invocation(call_expression: str | None) -> bool:
    """Return true for two-stage call-result invocations like ``f(...)(x)``."""
    if call_expression is None:
        return False
    tree = _parse_expression(call_expression)
    return (
        isinstance(tree, ast.Expression)
        and isinstance(tree.body, ast.Call)
        and isinstance(tree.body.func, ast.Call)
    )


def _match_via_receiver_type(
    edge: CallEdge,
    canonical_fqn: str,
    descriptor_method_owners: dict[str, set[str]],
    descriptor: (
        RouteCallPattern
        | InputMethodPattern
        | ClaimContainerPattern
        | EffectCallPattern
        | SecurityCheckPattern
        | LifecycleRegistrationPattern
        | CheckRegistrationPattern
        | ControlPlaneExemptionPattern
        | DependencyPattern
        | DispatchPattern
        | FlowPropagatorPattern
        | SafeGeneratedURLPattern
        | ValidatedValueGuardPattern
        | TaintSinkPattern
    ),
    idx: CodeIndex,
    provider: Provider,
    phase: ProviderPhase,
    aliases: dict[str, str],
) -> ProviderMatch | None:
    """Try to match a call edge by resolving the receiver's declared type.

    When L1 resolves ``db.add(user)`` as ``create_user.<locals>.db.add``,
    type enrichment may reveal that ``db`` has type ``Session``.  This
    function reconstructs the canonical FQN ``Session.add`` and checks
    it against the descriptor's owner+method pairs.

    The resolved receiver type is an *observed* FQN, so it is canonicalized
    through the provider aliases before comparison — mirroring every other
    matching path (e.g. ``_fqn_extends_any``). Without this, a receiver whose
    type resolves to a re-export/internal form (``argon2._password_hasher``)
    would never match a descriptor declared with the canonical public FQN.
    """
    if not descriptor_method_owners or edge.callee_fqn is None:
        return None
    _, edge_method = _split_receiver_method_fqn(canonical_fqn)
    owners_for_method = descriptor_method_owners.get(edge_method)
    if owners_for_method is None:
        return None

    receiver_type = _resolve_call_receiver_type(edge, idx)
    if receiver_type is None:
        return None
    canonical_receiver = canonicalize_fqn(receiver_type, aliases)

    for owner_fqn in owners_for_method:
        if not _type_matches(canonical_receiver, {owner_fqn}):
            continue
        resolved_fqn = f"{owner_fqn}.{edge_method}"
        predicate_eval = _evaluate_when_predicate(
            _descriptor_when(descriptor), edge, idx.type_enrichment
        )
        if predicate_eval.status is PredicateStatus.FAILED:
            return None
        return _make_match(
            provider,
            phase,
            descriptor,
            edge,
            edge.callee_fqn,
            resolved_fqn,
            predicate_status=predicate_eval.status,
            predicate_gaps=predicate_eval.gaps,
        )
    return None


def _match_attribute_descriptor(
    provider: Provider,
    phase: ProviderPhase,
    descriptor: InputAttributePattern | EffectAttributePattern | EffectSubscriptPattern,
    idx: CodeIndex,
    aliases: dict[str, str],
) -> tuple[ProviderMatch, ...]:
    matches: list[ProviderMatch] = []
    for fact in idx.attributes:
        observed_receiver = _resolve_attribute_receiver(fact, idx)
        canonical_receiver = canonicalize_fqn(observed_receiver, aliases)
        if isinstance(descriptor, InputAttributePattern):
            if (
                fact.is_write
                or fact.access_kind is not AccessKind.ATTR
                or fact.attr_name != descriptor.attribute
                or canonical_receiver not in _as_tuple(descriptor.receiver_fqn)
            ):
                continue
            canonical_fqn = f"{canonical_receiver}.{fact.attr_name}"
        elif isinstance(descriptor, EffectAttributePattern):
            if (
                fact.access_kind is not AccessKind.ATTR
                or not _effect_access_matches(descriptor.category, fact.is_write)
                or canonical_receiver not in _as_tuple(descriptor.receiver_fqn)
            ):
                continue
            canonical_fqn = f"{canonical_receiver}.{fact.attr_name}"
        else:
            if (
                fact.access_kind is not AccessKind.SUBSCRIPT
                or not _effect_access_matches(descriptor.category, fact.is_write)
                or canonical_receiver not in _as_tuple(descriptor.receiver_fqn)
            ):
                continue
            canonical_fqn = f"{canonical_receiver}[{fact.attr_name}]"
        matches.append(
            _make_match(
                provider,
                phase,
                descriptor,
                fact,
                observed_receiver,
                canonical_fqn,
            )
        )
    return tuple(matches)


def _match_container_descriptor(
    provider: Provider,
    phase: ProviderPhase,
    descriptor: InputContainerPattern,
    idx: CodeIndex,
    aliases: dict[str, str],
) -> tuple[ProviderMatch, ...]:
    """Match keyed access on a provider-declared module-global container.

    Subscript ``container["k"]`` and attribute ``container.k`` reads come from
    the attribute-access facts; the ``.get()`` / ``.pop()`` method forms come
    from call edges.  Only *reads* match -- a write (``container[k] = v``) is a
    state effect, not an input.  An ``.get``/``.pop`` attribute fact (the bound
    method
    of a method-call) is skipped here and recovered via the call edge so its key
    is the call argument, not the literal method name.
    """
    receivers = frozenset(_as_tuple(descriptor.receiver_fqn))
    match_subscript = "subscript" in descriptor.access
    match_attribute = "attribute" in descriptor.access
    matches: list[ProviderMatch] = []
    for fact in idx.attributes:
        if fact.is_write:
            continue
        canonical_receiver = canonicalize_fqn(_resolve_attribute_receiver(fact, idx), aliases)
        if canonical_receiver not in receivers:
            continue
        if fact.access_kind is AccessKind.SUBSCRIPT and match_subscript:
            canonical_fqn = f"{canonical_receiver}[{fact.attr_name}]"
        elif (
            fact.access_kind is AccessKind.ATTR
            and match_attribute
            and fact.attr_name not in descriptor.key_methods
        ):
            canonical_fqn = f"{canonical_receiver}.{fact.attr_name}"
        else:
            continue
        matches.append(
            _make_match(provider, phase, descriptor, fact, canonical_receiver, canonical_fqn)
        )
    if "method" in descriptor.access and descriptor.key_methods:
        method_fqns = frozenset(
            f"{receiver}.{method}" for receiver in receivers for method in descriptor.key_methods
        )
        for edge in budgeted(idx.call_graph.edges):
            if edge.callee_fqn is None:
                continue
            canonical_fqn = canonicalize_fqn(edge.callee_fqn, aliases)
            if canonical_fqn in method_fqns:
                matches.append(
                    _make_match(provider, phase, descriptor, edge, edge.callee_fqn, canonical_fqn)
                )
    return tuple(matches)


def _match_parameter_descriptor(
    provider: Provider,
    phase: ProviderPhase,
    descriptor: InputParameterPattern,
    idx: CodeIndex,
    aliases: dict[str, str],
) -> tuple[ProviderMatch, ...]:
    """Match function parameter defaults against InputParameterPattern.

    Scans all functions in the index for parameters whose default value
    is a constructor call matching ``descriptor.default_type_fqn``.
    """
    target_fqns = frozenset(_as_tuple(descriptor.default_type_fqn))
    matches: list[ProviderMatch] = []
    for function in idx.functions:
        for param in function.params:
            if param.default is None:
                continue
            call_name = _parse_default_call_name(param.default)
            if call_name is None:
                continue
            resolved = idx.symbols.resolve(call_name, function.file) or call_name
            canonical = canonicalize_fqn(resolved, aliases)
            if canonical not in target_fqns:
                continue
            fact = ParameterFact(
                param=param,
                function_fqn=function.fqn,
                location=param.location,
            )
            matches.append(
                _make_match(
                    provider,
                    phase,
                    descriptor,
                    fact,
                    call_name,
                    canonical,
                )
            )
    return tuple(matches)


def _parse_default_call_name(default: str) -> str | None:
    """Extract the callable name from a parameter default expression.

    Returns the function/class name if the default is a call expression
    (e.g. ``"Query(None)"`` → ``"Query"``), or ``None`` otherwise.
    """
    tree = _parse_expression(default)
    if tree is None:
        return None
    node = tree.body
    if not isinstance(node, ast.Call):
        return None
    return ast.unparse(node.func)


def _match_field_access_descriptor(
    provider: Provider,
    phase: ProviderPhase,
    descriptor: InputFieldAccessPattern,
    idx: CodeIndex,
    aliases: dict[str, str],
) -> tuple[ProviderMatch, ...]:
    """Match an InputFieldAccessPattern against L1 attribute accesses.

    Matches ``form.<field>.data`` patterns where ``form`` is an instance of a
    class that extends ``descriptor.base_class_fqn``.  Resolution:

    1. Filter attributes where ``attr_name == descriptor.field_attribute`` and
       the access is a read.
    2. Extract the root variable from ``target_expr`` (e.g. ``form`` from
       ``form.username``).
    3. Look up value-flow ASSIGN edges to find the constructor call assigned to
       that variable.
    4. Resolve the constructor class via symbol index and check whether any of
       its bases (via ``idx.classes``) match ``descriptor.base_class_fqn``.
    """
    base_fqns = frozenset(_as_tuple(descriptor.base_class_fqn))
    matches: list[ProviderMatch] = []
    for fact in idx.attributes:
        if fact.is_write or fact.attr_name != descriptor.field_attribute:
            continue
        root_var = _dotted_root(fact.target_expr)
        if root_var is None:
            continue
        class_fqn = _resolve_variable_class(
            root_var, fact.containing_function_fqn, fact.location, fact.location.file, idx
        )
        if class_fqn is None:
            continue
        field_name = _field_access_name(fact.target_expr)
        if field_name is None:
            continue
        if not _field_access_matches_descriptor(class_fqn, field_name, base_fqns, idx, aliases):
            continue
        canonical_fqn = f"{class_fqn}.{fact.attr_name}"
        matches.append(_make_match(provider, phase, descriptor, fact, class_fqn, canonical_fqn))
    return tuple(matches)


def _field_access_matches_descriptor(
    owner_class_fqn: str,
    field_name: str,
    target_fqns: frozenset[str],
    idx: CodeIndex,
    aliases: dict[str, str],
) -> bool:
    """Return true when either the owner class or field class matches a descriptor."""
    if _fqn_extends_any(owner_class_fqn, target_fqns, idx, aliases):
        return True

    field_class_fqn = _resolve_class_field_type(owner_class_fqn, field_name, idx)
    return field_class_fqn is not None and _fqn_extends_any(
        field_class_fqn,
        target_fqns,
        idx,
        aliases,
    )


def _field_access_name(expression: str) -> str | None:
    """Extract the field component from a dotted access chain."""
    parts = _dotted_name_parts(expression)
    if parts is None or len(parts) < 2:
        return None
    return parts[1]


def _dotted_root(expression: str) -> str | None:
    """Extract the root name from a dotted expression like ``form.username``."""
    parts = _dotted_name_parts(expression)
    if parts is not None and len(parts) >= 2:
        return parts[0]
    return _simple_name(expression)


def _resolve_variable_class(
    variable_name: str,
    containing_function_fqn: str | None,
    before: SourceSpan,
    file: str,
    idx: CodeIndex,
) -> str | None:
    """Resolve a local variable to the FQN of its constructor class.

    Looks for value-flow ASSIGN edges ``ClassName(...) → variable_name`` in the
    given scope (``containing_function_fqn``; ``None`` = module scope, where a
    binding like ``ns = Namespace(...)`` lives).  Extracts the class name from the
    constructor call expression and resolves it via the symbol index.

    Also resolves the ``name = self.<attr>()`` factory indirection (FLAW-274): a
    class-based view that declares its form class as a class attribute and
    instantiates it through ``self.<attr>()`` (the ``form = self.form()``
    class-based-view idiom).  See ``_resolve_self_attribute_class``.
    """
    edge = _latest_assignment_to_name(variable_name, containing_function_fqn, before, idx)
    if edge is None:
        return None
    class_name = _extract_constructor_class_name(edge.source_expr)
    if class_name is None:
        return None
    self_attribute = _self_attribute_name(class_name)
    if self_attribute is not None:
        return _resolve_self_attribute_class(self_attribute, containing_function_fqn, idx)
    resolved = idx.symbols.resolve(class_name, file)
    return resolved or class_name


def _self_attribute_name(call_name: str) -> str | None:
    """Return ``attr`` for a ``self.attr`` callee name, else ``None``.

    ``_extract_constructor_class_name("self.form()")`` yields ``"self.form"``; this
    recognises that shape so the receiver is resolved through the enclosing class's
    attribute binding rather than the (absent) symbol ``self.form``.
    """
    parts = call_name.split(".")
    if len(parts) == 2 and parts[0] == "self" and parts[1].isidentifier():
        return parts[1]
    return None


def _resolve_self_attribute_class(
    attribute: str,
    containing_function_fqn: str | None,
    idx: CodeIndex,
) -> str | None:
    """Resolve ``self.<attribute>`` (called as a factory) to its bound class FQN.

    Handles a common class-based-view idiom (a ``Login.post``-style MethodView):
    a MethodView subclass declares ``form = LoginForm`` (the form *class*) and
    constructs an instance via
    ``form = self.form()``.  Resolving the self-attribute to ``LoginForm`` lets the
    normal subclass check credit ``form.validate_on_submit()`` as
    CSRF/FORM_VALIDATION (FLAW-274).

    Resolve-or-gap (FN-safe): returns ``None`` whenever the enclosing class or the
    attribute's class binding can't be proven, so an unrecognised receiver leaves
    the missing-validation finding firing rather than silently crediting it.
    """
    if containing_function_fqn is None:
        return None
    class_fqn = _enclosing_class_fqn(containing_function_fqn, idx)
    if class_fqn is None:
        return None
    klass = _class_record_for_fqn(class_fqn, idx)
    if klass is None:
        return None
    edge = _class_attribute_assignment(klass, attribute, idx)
    if edge is None:
        return None
    bound_class = _class_reference_name(edge.source_expr)
    if bound_class is None:
        return None
    return idx.symbols.resolve(bound_class, klass.file) or bound_class


def _enclosing_class_fqn(function_fqn: str, idx: CodeIndex) -> str | None:
    """Return the FQN of the class enclosing ``function_fqn`` when it names a method
    of a known class (``module.Class.method`` -> ``module.Class``)."""
    owner, separator, _method = function_fqn.rpartition(".")
    if not separator or not owner:
        return None
    return owner if _class_record_for_fqn(owner, idx) is not None else None


def _class_reference_name(expression: str) -> str | None:
    """Extract a class name from a class-attribute binding source expression --
    either a bare class reference (``LoginForm``) or a constructor call
    (``LoginForm()``)."""
    constructor = _extract_constructor_class_name(expression)
    if constructor is not None:
        return constructor
    tree = _parse_expression(expression)
    if tree is not None and isinstance(tree.body, ast.Name):
        return tree.body.id
    return None


def _resolve_variable_annotation(
    variable_name: str,
    containing_function_fqn: str | None,
    before: SourceSpan,
    file: str,
    idx: CodeIndex,
) -> str | None:
    """Resolve ``name: Type = ...`` annotations for receiver-type matching."""
    if containing_function_fqn is None:
        return None
    source_path = idx.repo_root / file
    try:
        module = parse_analyzed_module(source_path.read_text(), filename=str(source_path))
    except (OSError, SyntaxError, UnicodeDecodeError):
        return None

    function_name = containing_function_fqn.rsplit(".", maxsplit=1)[-1]
    best = max(
        _annotated_assignment_candidates(module, function_name, variable_name, before),
        default=None,
    )

    if best is None:
        return None
    annotation = _annotation_name(best[2])
    if annotation is None:
        return None
    resolved = idx.symbols.resolve(annotation, file)
    return resolved or annotation


def _annotated_assignment_candidates(
    module: ast.Module,
    function_name: str,
    variable_name: str,
    before: SourceSpan,
) -> Iterator[tuple[int, int, ast.expr]]:
    for node in ast.walk(module):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if node.name != function_name or not _ast_node_contains_line(node, before.line):
            continue
        yield from _function_annotation_candidates(node, variable_name, before)


def _function_annotation_candidates(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    variable_name: str,
    before: SourceSpan,
) -> Iterator[tuple[int, int, ast.expr]]:
    for assignment in ast.walk(node):
        if not isinstance(assignment, ast.AnnAssign):
            continue
        if not isinstance(assignment.target, ast.Name) or assignment.target.id != variable_name:
            continue
        location = (assignment.lineno, assignment.col_offset)
        if location < (before.line, before.column):
            yield (*location, assignment.annotation)


def _ast_node_contains_line(node: ast.AST, line: int) -> bool:
    start = getattr(node, "lineno", None)
    end = getattr(node, "end_lineno", None)
    return isinstance(start, int) and isinstance(end, int) and start <= line <= end


def _annotation_name(annotation: ast.expr) -> str | None:
    if isinstance(annotation, ast.Name):
        return annotation.id
    if isinstance(annotation, ast.Attribute):
        return ast.unparse(annotation)
    if isinstance(annotation, ast.Subscript):
        return _annotation_name(annotation.value)
    return None


def _extract_constructor_class_name(expression: str) -> str | None:
    """Extract the class name from a constructor call like ``RegistrationForm()``."""
    return _parse_default_call_name(expression)


def _resolve_class_field_type(
    class_fqn: str,
    field_name: str,
    idx: CodeIndex,
) -> str | None:
    """Resolve a class-level field assignment to its constructor FQN."""
    klass = _class_record_for_fqn(class_fqn, idx)
    if klass is None:
        return None

    target_suffix = f".{field_name}"
    candidate_targets = {f"{class_fqn}{target_suffix}", f"{klass.name}{target_suffix}"}
    candidates = [
        edge
        for edge in idx.value_flow.edges
        if edge.kind is FlowKind.ASSIGN
        and edge.containing_function_fqn is None
        and (
            edge.target_expr in candidate_targets
            or edge.target_expr.endswith(f".{klass.name}{target_suffix}")
        )
    ]
    if not candidates:
        return None

    edge = max(
        candidates,
        key=lambda item: (item.target_location.line, item.target_location.column),
    )
    class_name = _extract_constructor_class_name(edge.source_expr)
    if class_name is None:
        return None
    return idx.symbols.resolve(class_name, klass.file) or class_name


def _class_record_for_fqn(class_fqn: str, idx: CodeIndex) -> ClassRecord | None:
    return _get_cache(idx).class_by_fqn.get(class_fqn)


def _fqn_extends_any(
    class_fqn: str,
    target_fqns: frozenset[str],
    idx: CodeIndex,
    aliases: dict[str, str],
) -> bool:
    """Return True if the class identified by ``class_fqn`` extends any target FQN.

    Checks the class's own FQN and its bases/MRO chain against the target FQNs,
    applying provider aliases for canonicalization.
    """
    canonical = canonicalize_fqn(class_fqn, aliases)
    if canonical in target_fqns:
        return True
    klass = _class_record_for_fqn(class_fqn, idx)
    return klass is not None and _class_extends_any(klass, target_fqns, idx, aliases)


def _resolve_attribute_receiver(fact: AttributeAccess, idx: CodeIndex) -> str:
    """Resolve an attribute receiver expression without crossing local shadowing.

    The symbol index can resolve imported module-level names. Before using that
    file-level fact, first honor local value aliases and then guard against the
    simple local shadowing forms that would make such a resolution unsafe in a
    function body.
    """
    local_alias = _resolve_local_receiver_alias(fact, idx)
    if local_alias is not None:
        return local_alias
    if _is_local_shadowed_name(fact, idx):
        return fact.target_expr
    resolved = idx.symbols.resolve(fact.target_expr, fact.location.file)
    if resolved is not None:
        return resolved
    return _resolve_dotted_receiver(fact, idx) or fact.target_expr


def _resolve_dotted_receiver(fact: AttributeAccess, idx: CodeIndex) -> str | None:
    parts = _dotted_name_parts(fact.target_expr)
    if parts is None or len(parts) < 2:
        return None

    head, *tail = parts
    resolved_head: str | None = None
    if fact.containing_function_fqn is not None:
        resolved_head = _resolve_local_alias_assignment(
            head,
            fact.containing_function_fqn,
            fact.location,
            fact.location.file,
            idx,
            seen=frozenset({head}),
        )
        if resolved_head is None and _is_local_shadowed_name_before(
            head,
            fact.containing_function_fqn,
            fact.location,
            idx,
        ):
            return None

    if resolved_head is None:
        resolved_head = idx.symbols.resolve(head, fact.location.file)
    if resolved_head is None:
        resolved_head = _resolve_module_level_name(head, fact.location.file, idx)
    if resolved_head is None:
        return None
    return ".".join((resolved_head, *tail))


def _resolve_local_receiver_alias(fact: AttributeAccess, idx: CodeIndex) -> str | None:
    if fact.containing_function_fqn is None:
        return None
    name = _simple_name(fact.target_expr)
    if name is None:
        return None
    return _resolve_local_alias_assignment(
        name,
        fact.containing_function_fqn,
        fact.location,
        fact.location.file,
        idx,
        seen=frozenset({name}),
    )


def _resolve_local_alias_assignment(
    name: str,
    function_fqn: str,
    before: SourceSpan,
    file: str,
    idx: CodeIndex,
    *,
    seen: frozenset[str],
) -> str | None:
    edge = _latest_assignment_to_name(name, function_fqn, before, idx)
    if edge is None:
        return None
    return _resolve_alias_source_expr(
        edge.source_expr,
        function_fqn,
        edge.source_location,
        file,
        idx,
        seen=seen,
    )


def _latest_assignment_to_name(
    name: str,
    function_fqn: str | None,
    before: SourceSpan,
    idx: CodeIndex,
) -> ValueFlowEdge | None:
    # ``function_fqn is None`` selects module-scope value flow (e.g. a top-level
    # ``ns = Namespace(...)`` binding), which the cache keys under ``None``.
    edges = _get_cache(idx).value_flow_by_function.get(function_fqn, ())
    candidates = [
        edge
        for edge in edges
        if edge.target_expr == name
        and edge.kind in {FlowKind.ASSIGN, FlowKind.ALIAS}
        and _span_starts_not_after(edge.target_location, before)
    ]
    if not candidates:
        return None
    return max(
        candidates, key=lambda edge: (edge.target_location.line, edge.target_location.column)
    )


def _resolve_alias_source_expr(
    source_expr: str,
    function_fqn: str,
    before: SourceSpan,
    file: str,
    idx: CodeIndex,
    *,
    seen: frozenset[str],
) -> str | None:
    resolved = idx.symbols.resolve(source_expr, file)
    if resolved is not None:
        return resolved

    source_name = _simple_name(source_expr)
    if source_name is not None:
        return _resolve_simple_source_expr(
            source_name,
            source_expr,
            function_fqn,
            before,
            file,
            idx,
            seen=seen,
        )

    dotted = _dotted_name_parts(source_expr)
    if dotted is None:
        return None
    head, *tail = dotted
    resolved_head = idx.symbols.resolve(head, file)
    if resolved_head is None and head not in seen:
        resolved_head = _resolve_local_alias_assignment(
            head,
            function_fqn,
            before,
            file,
            idx,
            seen=seen | {head},
        )
    if resolved_head is None:
        return source_expr
    return ".".join((resolved_head, *tail))


def _resolve_simple_source_expr(
    source_name: str,
    source_expr: str,
    function_fqn: str,
    before: SourceSpan,
    file: str,
    idx: CodeIndex,
    *,
    seen: frozenset[str],
) -> str | None:
    if source_name in seen:
        return None
    nested = _resolve_local_alias_assignment(
        source_name,
        function_fqn,
        before,
        file,
        idx,
        seen=seen | {source_name},
    )
    if nested is not None:
        return nested
    if _is_local_shadowed_name_before(source_name, function_fqn, before, idx):
        return source_expr
    return _resolve_module_level_name(source_name, file, idx) or source_expr


def _resolve_module_level_name(name: str, file: str, idx: CodeIndex) -> str | None:
    return _get_cache(idx).module_level_assignments.get((file, name))


def _is_local_shadowed_name(fact: AttributeAccess, idx: CodeIndex) -> bool:
    if fact.containing_function_fqn is None:
        return False
    name = _simple_name(fact.target_expr)
    if name is None:
        return False
    return _is_local_shadowed_name_before(name, fact.containing_function_fqn, fact.location, idx)


def _is_local_shadowed_name_before(
    name: str,
    function_fqn: str,
    before: SourceSpan,
    idx: CodeIndex,
) -> bool:
    cache = _get_cache(idx)
    if name in cache.function_params.get(function_fqn, frozenset()):
        return True

    for edge in cache.value_flow_by_function.get(function_fqn, ()):
        if edge.target_expr == name and _span_starts_not_after(
            edge.target_location,
            before,
        ):
            return True
    return False


def _effect_access_matches(category: str, is_write: bool) -> bool:
    if category.endswith("_READ"):
        return not is_write
    return is_write


def _match_symbol_descriptor(
    provider: Provider,
    phase: ProviderPhase,
    descriptor: StateProxyPattern,
    idx: CodeIndex,
    aliases: dict[str, str],
) -> tuple[ProviderMatch, ...]:
    descriptor_fqns = frozenset(_as_tuple(descriptor.fqn))
    matches: list[ProviderMatch] = []
    for fact in idx.symbols.refs:
        if fact.fqn is None:
            continue
        canonical_fqn = canonicalize_fqn(fact.fqn, aliases)
        if canonical_fqn in descriptor_fqns:
            matches.append(_make_match(provider, phase, descriptor, fact, fact.fqn, canonical_fqn))
    for attr_fact in idx.attributes:
        if attr_fact.is_write:
            continue
        observed_fqn = _resolve_attribute_receiver(attr_fact, idx)
        canonical_fqn = canonicalize_fqn(observed_fqn, aliases)
        if canonical_fqn in descriptor_fqns:
            matches.append(
                _make_match(provider, phase, descriptor, attr_fact, observed_fqn, canonical_fqn)
            )
    return tuple(matches)


def _match_dispatch_descriptor(
    provider: Provider,
    phase: ProviderPhase,
    descriptor: DispatchPattern,
    idx: CodeIndex,
    aliases: dict[str, str],
) -> tuple[ProviderMatch, ...]:
    """Match dispatch descriptors against decorator and call-site facts."""
    descriptor_fqns = frozenset(_dispatch_descriptor_fqns(descriptor))
    matches: list[ProviderMatch] = []

    for fact in idx.decorators:
        seen_candidates: set[str] = set()
        for observed_fqn in _decorator_observed_fqns(fact, idx):
            if observed_fqn in seen_candidates:
                continue
            seen_candidates.add(observed_fqn)
            canonical_fqn = canonicalize_fqn(observed_fqn, aliases)
            if canonical_fqn not in descriptor_fqns:
                continue
            matches.append(
                _make_match(
                    provider,
                    phase,
                    descriptor,
                    fact,
                    observed_fqn,
                    canonical_fqn,
                )
            )
            break

    for edge in budgeted(idx.call_graph.edges):
        if edge.callee_fqn is None:
            continue
        canonical_fqn = canonicalize_fqn(edge.callee_fqn, aliases)
        if canonical_fqn not in descriptor_fqns:
            continue
        matches.append(
            _make_match(provider, phase, descriptor, edge, edge.callee_fqn, canonical_fqn)
        )

    return tuple(matches)


def _match_class_view_descriptor(
    provider: Provider,
    phase: ProviderPhase,
    descriptor: ClassViewPattern,
    idx: CodeIndex,
    aliases: dict[str, str],
) -> tuple[ProviderMatch, ...]:
    """Match a ClassViewPattern against L1 classes by base class FQN.

    For each class whose bases resolve to the declared base_class_fqn,
    produce a ProviderMatch with the class FQN as the observed FQN and
    a SymbolRef as the source fact.
    """
    base_fqns = frozenset(_as_tuple(descriptor.base_class_fqn))
    matches: list[ProviderMatch] = []
    for klass in idx.classes:
        if _class_extends_any(klass, base_fqns, idx, aliases):
            source_fact = SymbolRef(
                name=klass.name,
                fqn=klass.fqn,
                resolution=ResolutionStatus.RESOLVED,
                location=klass.location,
                provenance=ExtractionProvenance(
                    producer="class_view_match",
                    producer_version="0.0.0",
                    artifact="",
                ),
            )
            matches.append(
                _make_match(
                    provider,
                    phase,
                    descriptor,
                    source_fact,
                    klass.fqn,
                    klass.fqn,
                )
            )
    return tuple(matches)


def _match_middleware_class_descriptor(
    provider: Provider,
    phase: ProviderPhase,
    descriptor: MiddlewareClassPattern,
    idx: CodeIndex,
    aliases: dict[str, str],
) -> tuple[ProviderMatch, ...]:
    """Match MiddlewareClassPattern against project classes by base FQN."""
    base_fqns = frozenset(_as_tuple(descriptor.base_class_fqn))
    matches: list[ProviderMatch] = []
    for klass in idx.classes:
        if not _class_extends_any(klass, base_fqns, idx, aliases):
            continue
        source_fact = SymbolRef(
            name=klass.name,
            fqn=klass.fqn,
            resolution=ResolutionStatus.RESOLVED,
            location=klass.location,
            provenance=ExtractionProvenance(
                producer="middleware_class_match",
                producer_version="0.0.0",
                artifact="",
            ),
        )
        matches.append(
            _make_match(
                provider,
                phase,
                descriptor,
                source_fact,
                klass.fqn,
                klass.fqn,
            )
        )
    return tuple(matches)


def _match_class_attribute_guard(
    provider: Provider,
    phase: ProviderPhase,
    descriptor: ClassAttributeGuardPattern,
    idx: CodeIndex,
    aliases: dict[str, str],
) -> tuple[ProviderMatch, ...]:
    """Match class-level guard lists on subclasses of a declared view base."""
    view_base_fqns = frozenset(_as_tuple(descriptor.view_base_fqn))
    guard_base_fqns = frozenset(_as_tuple(descriptor.guard_base_fqn))
    matches: list[ProviderMatch] = []
    for klass in idx.classes:
        if not _class_extends_any(klass, view_base_fqns, idx, aliases):
            continue
        edge = _class_attribute_assignment(klass, descriptor.attribute_name, idx)
        if edge is None:
            continue
        for guard_expr in _guard_attribute_entries(edge.source_expr):
            guard_fqn = idx.symbols.resolve(guard_expr, klass.file) or guard_expr
            canonical_guard_fqn = canonicalize_fqn(guard_fqn, aliases)
            if not _guard_entry_matches(canonical_guard_fqn, guard_base_fqns, idx, aliases):
                continue
            source_fact = SymbolRef(
                name=f"{klass.name}.{descriptor.attribute_name}",
                fqn=klass.fqn,
                resolution=ResolutionStatus.RESOLVED,
                location=edge.target_location,
                provenance=ExtractionProvenance(
                    producer="class_attribute_guard_match",
                    producer_version="0.0.0",
                    artifact="",
                ),
            )
            matches.append(
                _make_match(
                    provider,
                    phase,
                    descriptor,
                    source_fact,
                    guard_fqn,
                    canonical_guard_fqn,
                )
            )
    return tuple(matches)


def _class_attribute_assignment(
    klass: ClassRecord,
    attribute_name: str,
    idx: CodeIndex,
) -> ValueFlowEdge | None:
    if attribute_name not in klass.class_var_names:
        return None
    candidates = [
        edge
        for edge in idx.value_flow.edges
        if edge.kind is FlowKind.ASSIGN
        and edge.containing_function_fqn is None
        and edge.target_expr in {attribute_name, f"{klass.name}.{attribute_name}"}
        and _span_inside_class(edge.target_location, klass)
    ]
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda edge: (edge.target_location.line, edge.target_location.column),
    )


def _span_inside_class(span: SourceSpan, klass: ClassRecord) -> bool:
    if span.file != klass.file:
        return False
    return (
        (klass.location.line, klass.location.column)
        <= (span.line, span.column)
        <= (klass.location.end_line, klass.location.end_column)
    )


def _guard_attribute_entries(expression: str) -> tuple[str, ...]:
    tree = _parse_expression(expression)
    if tree is None:
        return ()
    node = tree.body
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return tuple(ast.unparse(item) for item in node.elts)
    if isinstance(node, ast.Name | ast.Attribute | ast.Call):
        return (ast.unparse(node.func) if isinstance(node, ast.Call) else ast.unparse(node),)
    return ()


def _guard_entry_matches(
    guard_fqn: str,
    guard_base_fqns: frozenset[str],
    idx: CodeIndex,
    aliases: dict[str, str],
) -> bool:
    if _fqn_extends_any(guard_fqn, guard_base_fqns, idx, aliases):
        return True
    # External guard classes often have no project-local ClassRecord/MRO. Once
    # the view class and declared guard attribute match, keep the resolved entry
    # rather than silently dropping a real framework guard.
    return _class_record_for_fqn(guard_fqn, idx) is None


def _class_extends_any(
    klass: ClassRecord,
    target_fqns: frozenset[str],
    idx: CodeIndex,
    aliases: dict[str, str],
) -> bool:
    """Return True if any of the class's bases resolves to a target FQN."""
    return _class_extends_any_seen(klass, target_fqns, idx, aliases, seen=frozenset())


def _class_extends_any_seen(
    klass: ClassRecord,
    target_fqns: frozenset[str],
    idx: CodeIndex,
    aliases: dict[str, str],
    *,
    seen: frozenset[str],
) -> bool:
    for ancestor_fqn in klass.mro_chain:
        canonical = canonicalize_fqn(ancestor_fqn, aliases)
        if canonical in target_fqns:
            return True

    for base in klass.bases:
        resolved = idx.symbols.resolve(base, klass.file)
        canonical = canonicalize_fqn(resolved or base, aliases)
        if canonical in target_fqns:
            return True
        if canonical in seen:
            continue
        base_record = _class_record_for_fqn(canonical, idx)
        if base_record is not None and _class_extends_any_seen(
            base_record,
            target_fqns,
            idx,
            aliases,
            seen=seen | {canonical},
        ):
            return True
    return False


def _match_imperative_route_descriptor(
    provider: Provider,
    phase: ProviderPhase,
    descriptor: ImperativeRoutePattern,
    idx: CodeIndex,
    aliases: dict[str, str],
) -> tuple[ProviderMatch, ...]:
    """Match an ImperativeRoutePattern against module-level list/constructor assignments.

    Scans value-flow ASSIGN edges for module-level assignments whose source
    expression contains constructor calls matching ``descriptor.entry_fqn``
    (or ``descriptor.nested_fqn``).  List literals are parsed to extract
    individual constructor calls; bare constructor assignments are also matched.
    """
    entry_fqns = frozenset(_as_tuple(descriptor.entry_fqn))
    nested_fqns: frozenset[str] = frozenset()
    if descriptor.nested_fqn is not None:
        nested_fqns = frozenset(_as_tuple(descriptor.nested_fqn))
    all_fqns = entry_fqns | nested_fqns

    matches: list[ProviderMatch] = []

    for edge in idx.value_flow.edges:
        if edge.kind is not FlowKind.ASSIGN or edge.containing_function_fqn is not None:
            continue

        call_nodes = _extract_constructor_calls(edge.source_expr)
        for call_node in call_nodes:
            callee_expr = ast.unparse(call_node.func)
            resolved_fqn = idx.symbols.resolve(callee_expr, edge.source_location.file)
            if resolved_fqn is None:
                resolved_fqn = callee_expr
            canonical_fqn = canonicalize_fqn(resolved_fqn, aliases)

            if canonical_fqn not in all_fqns:
                continue

            call_text = ast.unparse(call_node)
            source_fact = SymbolRef(
                name=call_text,
                fqn=canonical_fqn,
                resolution=ResolutionStatus.RESOLVED,
                location=edge.source_location,
                provenance=ExtractionProvenance(
                    producer="imperative_route_match",
                    producer_version="0.0.0",
                    artifact="",
                ),
            )
            matches.append(
                _make_match(provider, phase, descriptor, source_fact, canonical_fqn, canonical_fqn)
            )

    return tuple(matches)


def _extract_constructor_calls(expression: str) -> list[ast.Call]:
    """Extract all top-level Call nodes from an expression.

    Handles both bare constructor calls (``Route(...)``) and list/tuple
    literals containing constructor calls (``[Route(...), Mount(...)]``).
    """
    tree = _parse_expression(expression)
    if tree is None:
        return []
    node = tree.body

    if isinstance(node, ast.Call):
        return [node]

    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return [elt for elt in node.elts if isinstance(elt, ast.Call)]

    return []


def _make_match(
    provider: Provider,
    phase: ProviderPhase,
    descriptor: ProviderDescriptor,
    source_fact: ProviderSourceFact,
    observed_fqn: str,
    canonical_fqn: str,
    *,
    predicate_status: PredicateStatus = PredicateStatus.PASSED,
    predicate_gaps: tuple[AnalysisGap, ...] = (),
) -> ProviderMatch:
    return ProviderMatch(
        provider_id=provider.meta.id,
        phase=phase,
        descriptor=descriptor,
        source_fact=source_fact,
        observed_fqn=observed_fqn,
        canonical_fqn=canonical_fqn,
        location=source_fact.location,
        predicate_status=predicate_status,
        predicate_gaps=predicate_gaps,
    )


def _descriptor_fqns(
    descriptor: (
        RouteDecorator
        | RouteCallPattern
        | InputMethodPattern
        | ClaimContainerPattern
        | EffectCallPattern
        | SecurityCheckPattern
        | LifecycleDecoratorPattern
        | LifecycleRegistrationPattern
        | CheckRegistrationPattern
        | ControlPlaneExemptionPattern
        | DependencyPattern
        | DispatchPattern
        | FlowPropagatorPattern
        | SafeGeneratedURLPattern
        | ValidatedValueGuardPattern
        | TaintSinkPattern
    ),
) -> tuple[str, ...]:
    if isinstance(
        descriptor,
        LifecycleRegistrationPattern | CheckRegistrationPattern | ControlPlaneExemptionPattern,
    ):
        return _as_tuple(descriptor.registration_fqn)
    if isinstance(descriptor, DependencyPattern):
        return _as_tuple(descriptor.inject_fqn)
    if isinstance(descriptor, DispatchPattern):
        return _dispatch_descriptor_fqns(descriptor)
    if isinstance(descriptor, ValidatedValueGuardPattern | ClaimContainerPattern):
        return () if descriptor.fqn is None else _as_tuple(descriptor.fqn)
    return _as_tuple(descriptor.fqn)


def _descriptor_names(descriptor: ProviderDescriptor) -> frozenset[str]:
    if isinstance(
        descriptor,
        ValidatedValueGuardPattern
        | ClaimContainerPattern
        | EffectCallPattern
        | FlowPropagatorPattern,
    ):
        return frozenset(descriptor.names)
    return frozenset()


def _fqn_simple_name(fqn: str) -> str:
    return fqn.rsplit(".", maxsplit=1)[-1]


def _as_tuple(value: str | tuple[str, ...]) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    return value


def _dispatch_descriptor_fqns(descriptor: DispatchPattern) -> tuple[str, ...]:
    """Return exact and target-method call FQNs a dispatch descriptor can match."""
    fqns: list[str] = []
    for source_fqn in _as_tuple(descriptor.source_fqn):
        _append_unique(fqns, source_fqn)
        for method_name in descriptor.target_method_names:
            if not source_fqn.endswith(f".{method_name}"):
                _append_unique(fqns, f"{source_fqn}.{method_name}")
    return tuple(fqns)


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)
