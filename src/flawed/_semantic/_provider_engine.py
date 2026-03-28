"""Provider discovery, activation, and declarative pattern matching.

This module is the orchestrator for Layer 2 provider processing.  It owns
the public types, engine class, and provider lifecycle, delegating alias
resolution to ``_alias_resolution``, router-group extraction to
``_router_groups``, and pattern matching to ``_matching``.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol, cast

from flawed._index._types import (
    AttributeAccess,
    CallEdge,
    DecoratorFact,
    Parameter,
    SourceSpan,
    SymbolRef,
)
from flawed._semantic.providers import (
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
from flawed.core import AnalysisGap, GapKind

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from flawed._index import CodeIndex


class ProviderPhase(Enum):
    """Declarative provider processing phases, in execution order."""

    ROUTES = "routes"
    INPUTS = "inputs"
    EFFECTS = "effects"
    CHECKS = "checks"
    VALIDATION_GUARDS = "validation_guards"
    LIFECYCLE = "lifecycle"
    DEPENDENCIES = "dependencies"
    DISPATCHES = "dispatches"
    PROPAGATORS = "propagators"
    SAFE_GENERATED_URLS = "safe_generated_urls"
    SINKS = "sinks"
    PROXIES = "proxies"


class PredicateStatus(Enum):
    """Result of evaluating a descriptor ``when=`` predicate."""

    PASSED = "passed"
    FAILED = "failed"
    UNKNOWN = "unknown"


ProviderDescriptor = (
    RouteDecorator
    | RouteCallPattern
    | ClassViewPattern
    | ImperativeRoutePattern
    | InputAttributePattern
    | InputContainerPattern
    | InputMethodPattern
    | InputFieldAccessPattern
    | InputParameterPattern
    | ClaimContainerPattern
    | EffectCallPattern
    | EffectAttributePattern
    | EffectSubscriptPattern
    | SecurityCheckPattern
    | ClassAttributeGuardPattern
    | LifecycleDecoratorPattern
    | LifecycleRegistrationPattern
    | CheckRegistrationPattern
    | ControlPlaneExemptionPattern
    | MiddlewareClassPattern
    | DependencyPattern
    | DispatchPattern
    | FlowPropagatorPattern
    | SafeGeneratedURLPattern
    | ValidatedValueGuardPattern
    | TaintSinkPattern
    | StateProxyPattern
)


@dataclass(frozen=True)
class ParameterFact:
    """A function parameter paired with its containing function context.

    ``Parameter`` alone lacks a ``containing_function_fqn`` field, so the
    engine wraps it with the function context at match time so conversion
    can look up the domain ``Function``.
    """

    param: Parameter
    function_fqn: str
    location: SourceSpan


ProviderSourceFact = DecoratorFact | CallEdge | AttributeAccess | SymbolRef | ParameterFact


@dataclass(frozen=True)
class ProviderMatch:
    """A provider descriptor matched against a Layer 1 structural fact."""

    provider_id: str
    phase: ProviderPhase
    descriptor: ProviderDescriptor
    source_fact: ProviderSourceFact
    observed_fqn: str
    canonical_fqn: str
    location: SourceSpan
    predicate_status: PredicateStatus = PredicateStatus.PASSED
    predicate_gaps: tuple[AnalysisGap, ...] = ()


@dataclass(frozen=True)
class RouterGroupInfo:
    """Metadata extracted from a router-group constructor assignment.

    Maps a variable FQN (e.g. ``mymodule.admin_bp``) to the constructor
    class FQN, the group name (first constructor arg), and the effective
    URL prefix (from constructor kwarg or mount call override).
    """

    variable_fqn: str
    """Project-level FQN of the router-group variable."""

    constructor_fqn: str
    """Canonical class FQN of the constructor."""

    group: str | None
    """Group name (first constructor arg), or ``None`` if dynamic."""

    url_prefix: str | None
    """Effective URL prefix, or ``None`` if absent or dynamic."""

    group_gaps: tuple[AnalysisGap, ...] = ()
    """Gaps from dynamic/unresolvable group name."""

    prefix_gaps: tuple[AnalysisGap, ...] = ()
    """Gaps from dynamic/unresolvable URL prefix."""


@dataclass(frozen=True)
class MembershipContainerSpec:
    """A provider container that recognizes ``key in container`` membership reads.

    Derived from an :class:`InputContainerPattern` whose ``access`` includes
    ``"membership"`` (an identity container keyed by ``key in container``). Carried on
    the engine result so the L2 membership-read inference stays framework-agnostic --
    the receiver FQNs and source type come from the provider, never hard-coded in L2 core.
    """

    receiver_fqns: tuple[str, ...]
    source_type: str


@dataclass(frozen=True)
class ProviderEngineResult:
    """Result of one provider-engine run."""

    active_provider_ids: tuple[str, ...]
    matches: tuple[ProviderMatch, ...]
    gaps: tuple[AnalysisGap, ...]
    router_group_info: tuple[RouterGroupInfo, ...] = ()
    membership_container_specs: tuple[MembershipContainerSpec, ...] = ()
    aliases: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class _PredicateEval:
    status: PredicateStatus
    gaps: tuple[AnalysisGap, ...] = ()


class _ProviderHook(Protocol):
    def __call__(self, idx: CodeIndex) -> Sequence[object]: ...


_PHASE_ORDER: tuple[ProviderPhase, ...] = (
    ProviderPhase.ROUTES,
    ProviderPhase.INPUTS,
    ProviderPhase.EFFECTS,
    ProviderPhase.CHECKS,
    ProviderPhase.VALIDATION_GUARDS,
    ProviderPhase.LIFECYCLE,
    ProviderPhase.DEPENDENCIES,
    ProviderPhase.DISPATCHES,
    ProviderPhase.PROPAGATORS,
    ProviderPhase.SAFE_GENERATED_URLS,
    ProviderPhase.SINKS,
    ProviderPhase.PROXIES,
)

_PHASE_HOOKS: dict[ProviderPhase, str] = {
    ProviderPhase.ROUTES: "extract_routes",
    ProviderPhase.INPUTS: "extract_inputs",
    ProviderPhase.EFFECTS: "extract_effects",
    ProviderPhase.CHECKS: "extract_checks",
    ProviderPhase.VALIDATION_GUARDS: "extract_validation_guards",
    ProviderPhase.LIFECYCLE: "extract_lifecycle",
    ProviderPhase.DEPENDENCIES: "extract_dependencies",
    ProviderPhase.DISPATCHES: "extract_dispatches",
    ProviderPhase.PROPAGATORS: "extract_propagators",
    ProviderPhase.SAFE_GENERATED_URLS: "extract_safe_generated_urls",
    ProviderPhase.SINKS: "extract_sinks",
    ProviderPhase.PROXIES: "extract_proxies",
}

_PHASE_DESCRIPTOR_ATTRS: dict[ProviderPhase, str] = {
    ProviderPhase.ROUTES: "routes",
    ProviderPhase.INPUTS: "inputs",
    ProviderPhase.EFFECTS: "effects",
    ProviderPhase.CHECKS: "checks",
    ProviderPhase.VALIDATION_GUARDS: "validation_guards",
    ProviderPhase.LIFECYCLE: "lifecycle",
    ProviderPhase.DEPENDENCIES: "dependencies",
    ProviderPhase.DISPATCHES: "dispatches",
    ProviderPhase.PROPAGATORS: "propagators",
    ProviderPhase.SAFE_GENERATED_URLS: "safe_generated_urls",
    ProviderPhase.SINKS: "sinks",
    ProviderPhase.PROXIES: "proxies",
}


# Cache for sorted alias tuples keyed by (id, len) of the aliases dict.
# Using len() alongside id() detects in-place mutations during alias building.
_MAX_CANONICALIZE_CACHE = 8192
_MAX_SORTED_ALIASES_CACHE = 128
_SORTED_ALIASES_CACHE: OrderedDict[tuple[int, int], tuple[tuple[str, str], ...]] = OrderedDict()

# Cache for canonicalized FQN results: (fqn, id, len) -> result.
_CANONICALIZE_CACHE: OrderedDict[tuple[str, int, int], str] = OrderedDict()
_ALWAYS_ACTIVE_LIBRARY_FQNS = frozenset({"builtins"})


def canonicalize_fqn(fqn: str, aliases: dict[str, str]) -> str:
    """Apply provider FQN aliases using the longest matching prefix."""
    aliases_key = (id(aliases), len(aliases))
    cache_key = (fqn, *aliases_key)
    try:
        result = _CANONICALIZE_CACHE[cache_key]
    except KeyError:
        pass
    else:
        _CANONICALIZE_CACHE.move_to_end(cache_key)
        return result

    try:
        sorted_pairs = _SORTED_ALIASES_CACHE[aliases_key]
    except KeyError:
        sorted_pairs = tuple(
            sorted(
                aliases.items(),
                key=lambda item: (-len(item[0]), item[0]),
            )
        )
        _SORTED_ALIASES_CACHE[aliases_key] = sorted_pairs
        _trim_ordered_cache(_SORTED_ALIASES_CACHE, _MAX_SORTED_ALIASES_CACHE)
    else:
        _SORTED_ALIASES_CACHE.move_to_end(aliases_key)

    for observed_prefix, canonical_prefix in sorted_pairs:
        if fqn == observed_prefix or fqn.startswith(f"{observed_prefix}."):
            result = f"{canonical_prefix}{fqn[len(observed_prefix) :]}"
            _CANONICALIZE_CACHE[cache_key] = result
            _trim_ordered_cache(_CANONICALIZE_CACHE, _MAX_CANONICALIZE_CACHE)
            return result

    _CANONICALIZE_CACHE[cache_key] = fqn
    _trim_ordered_cache(_CANONICALIZE_CACHE, _MAX_CANONICALIZE_CACHE)
    return fqn


def _trim_ordered_cache(cache: OrderedDict[Any, Any], max_size: int) -> None:
    while len(cache) > max_size:
        cache.popitem(last=False)


def clear_canonicalize_cache() -> None:
    """Drop cached sorted-alias tuples and FQN results (for test isolation)."""
    _SORTED_ALIASES_CACHE.clear()
    _CANONICALIZE_CACHE.clear()


# -- Delegated imports from sub-modules ------------------------------------
from flawed._semantic._alias_resolution import _provider_fqn_aliases  # noqa: E402
from flawed._semantic._matching import _match_phase  # noqa: E402
from flawed._semantic._router_groups import _extract_router_group_info  # noqa: E402


class ProviderEngine:
    """Runs Layer 2 provider activation and declarative matching."""

    __slots__ = ("_providers", "_providers_by_id")

    def __init__(self, providers: Iterable[type[Provider]] | None = None) -> None:
        provider_classes = (
            tuple(providers) if providers is not None else discover_builtin_provider_classes()
        )
        self._providers = _dedupe_provider_classes(provider_classes)
        self._providers_by_id = {provider.meta.id: provider for provider in self._providers}

    def run(
        self,
        idx: CodeIndex,
        *,
        provider_ids: Sequence[str] | None = None,
    ) -> ProviderEngineResult:
        """Activate providers and match their declarative descriptors."""
        from flawed._semantic._matching import _phase_descriptors, clear_matching_cache

        try:
            active_provider_classes, activation_gaps = self._activate_providers(idx, provider_ids)
            active_providers = tuple(provider_cls() for provider_cls in active_provider_classes)
            provider_aliases = {
                provider.meta.id: _provider_fqn_aliases(provider, idx)
                for provider in active_providers
            }

            # Merge all provider aliases and collect router-group declarations.
            merged_aliases: dict[str, str] = {}
            for aliases in provider_aliases.values():
                merged_aliases.update(aliases)
            all_router_group_info = list(
                _extract_router_group_info(idx, merged_aliases, active_providers)
            )
            # Membership-capable input containers (e.g. ``session``/``g`` declaring
            # "membership" access), carried on the result so the L2 membership-read
            # inference (FLAW-336) stays framework-agnostic.
            membership_container_specs = tuple(
                MembershipContainerSpec(
                    receiver_fqns=(
                        (descriptor.receiver_fqn,)
                        if isinstance(descriptor.receiver_fqn, str)
                        else tuple(descriptor.receiver_fqn)
                    ),
                    source_type=descriptor.source_type,
                )
                for provider in active_providers
                for descriptor in _phase_descriptors(provider, ProviderPhase.INPUTS)
                if isinstance(descriptor, InputContainerPattern)
                and "membership" in descriptor.access
            )

            matches: list[ProviderMatch] = []
            gaps = list(activation_gaps)
            for phase in _PHASE_ORDER:
                for provider in active_providers:
                    matches.extend(
                        _match_phase(provider, phase, idx, provider_aliases[provider.meta.id])
                    )
                    gaps.extend(_run_provider_hook(provider, phase, idx))

            for match in matches:
                gaps.extend(match.predicate_gaps)

            return ProviderEngineResult(
                active_provider_ids=tuple(provider.meta.id for provider in active_providers),
                matches=tuple(matches),
                gaps=tuple(gaps),
                router_group_info=tuple(all_router_group_info),
                membership_container_specs=membership_container_specs,
                aliases=merged_aliases,
            )
        finally:
            clear_matching_cache()
            clear_canonicalize_cache()

    def _activate_providers(
        self,
        idx: CodeIndex,
        provider_ids: Sequence[str] | None,
    ) -> tuple[tuple[type[Provider], ...], tuple[AnalysisGap, ...]]:
        if provider_ids is not None:
            selected: list[type[Provider]] = []
            gaps: list[AnalysisGap] = []
            for provider_id in provider_ids:
                provider_cls = self._providers_by_id.get(provider_id)
                if provider_cls is None:
                    gaps.append(_unknown_provider_gap(provider_id))
                    continue
                selected.append(provider_cls)
            return tuple(selected), tuple(gaps)

        imported_modules = tuple(import_fact.module for import_fact in idx.imports)
        return (
            tuple(
                provider_cls
                for provider_cls in self._providers
                if _provider_is_imported(provider_cls, imported_modules)
            ),
            (),
        )


def discover_builtin_provider_classes() -> tuple[type[Provider], ...]:
    """Discover built-in provider classes with deterministic ID ordering."""
    from flawed._semantic import providers as provider_package

    package_paths = cast("Sequence[str]", provider_package.__path__)
    discovered: list[type[Provider]] = []
    for module_info in pkgutil.iter_modules(package_paths):
        if module_info.ispkg or module_info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{provider_package.__name__}.{module_info.name}")
        members: list[tuple[str, object]] = inspect.getmembers(module, inspect.isclass)
        for _, member in members:
            if (
                isinstance(member, type)
                and member is not Provider
                and issubclass(member, Provider)
                and member.__module__ == module.__name__
            ):
                discovered.append(member)
    return tuple(
        sorted(_dedupe_provider_classes(discovered), key=lambda provider: provider.meta.id)
    )


def _dedupe_provider_classes(providers: Iterable[type[Provider]]) -> tuple[type[Provider], ...]:
    provider_order: list[str] = []
    providers_by_id: dict[str, type[Provider]] = {}
    for provider in providers:
        provider_id = provider.meta.id
        if provider_id not in providers_by_id:
            provider_order.append(provider_id)
        providers_by_id[provider_id] = provider
    return tuple(providers_by_id[provider_id] for provider_id in provider_order)


def _provider_is_imported(provider_cls: type[Provider], imported_modules: tuple[str, ...]) -> bool:
    library_fqn = provider_cls.meta.library_fqn
    if not library_fqn:
        return False
    if library_fqn in _ALWAYS_ACTIVE_LIBRARY_FQNS:
        return True

    # Collect all FQN prefixes that should trigger activation:
    # the canonical library_fqn PLUS any alias source prefixes that
    # map into it (e.g. flask_allows2 → flask_allows) PLUS any
    # wrapper/re-export libraries declared via activation_imports
    # (e.g. flask_sqlalchemy re-exposes the SQLAlchemy ORM).
    activation_prefixes = [library_fqn]
    aliases: dict[str, str] = getattr(provider_cls, "fqn_aliases", {})
    for alias_from, alias_to in aliases.items():
        if alias_to == library_fqn or alias_to.startswith(f"{library_fqn}."):
            activation_prefixes.append(alias_from)
    activation_prefixes.extend(provider_cls.meta.activation_imports)

    return any(
        module == prefix or module.startswith(f"{prefix}.")
        for module in imported_modules
        for prefix in activation_prefixes
    )


def _unknown_provider_gap(provider_id: str) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INTERPRETER_ERROR,
        message=f"Unknown semantic provider id: {provider_id}",
        source_error="provider activation",
        origin_phase="provider_activation",
        origin_provider=provider_id,
    )


def _run_provider_hook(
    provider: Provider,
    phase: ProviderPhase,
    idx: CodeIndex,
) -> tuple[AnalysisGap, ...]:
    hook_name = _PHASE_HOOKS[phase]
    hook_obj = getattr(provider, hook_name, None)
    if hook_obj is None or not callable(hook_obj):
        return ()
    hook = cast("_ProviderHook", hook_obj)
    try:
        hook(idx)
    except Exception as exc:
        return (
            AnalysisGap(
                kind=GapKind.INTERPRETER_ERROR,
                message=f"Provider {provider.meta.id} {hook_name} failed: {exc}",
                source_error=type(exc).__name__,
                origin_phase="provider_hook",
                origin_provider=provider.meta.id,
            ),
        )
    return ()


__all__ = [
    "PredicateStatus",
    "ProviderEngine",
    "ProviderEngineResult",
    "ProviderMatch",
    "ProviderPhase",
    "RouterGroupInfo",
    "canonicalize_fqn",
    "clear_canonicalize_cache",
    "discover_builtin_provider_classes",
]
