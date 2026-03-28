"""Convert provider dispatch matches into synthetic reachability edges.

Dispatch patterns describe framework calls that the static L1 call graph cannot
see directly. Conversion is intentionally conservative: concrete scheduling
sites such as background-task registration become synthetic caller → callback
edges immediately, while decoupled signal registration only becomes an edge when
the same repository also contains a matching signal emission site.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from flawed._index._types import CallEdge, DecoratorFact
from flawed._semantic._conversion_utils import (
    location,
)
from flawed._semantic._conversion_utils import (
    simple_name as _simple_name,
)
from flawed._semantic._expr_cache import parse_expression as _parse_expression
from flawed._semantic._lifecycle_conversion import LifecycleHook
from flawed._semantic.providers import DispatchPattern
from flawed.core import AnalysisGap, GapKind, Location, Provenance

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from flawed._index import CodeIndex
    from flawed._index._types import CallArgument
    from flawed._semantic._provider_engine import ProviderMatch
    from flawed.function import Function


_L2_DISPATCH_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="provider_dispatch",
    confidence=0.85,
    supporting_facts=("provider dispatch descriptor matched L1 structural fact",),
)
_GENERIC_CALLBACK_KEYWORDS = frozenset({"callback", "func", "fn", "receiver"})
_SIGNAL_ARGUMENT_KEYWORDS = frozenset({"signal"})
_SIGNAL_DECORATOR_FACTORY_METHODS = frozenset({"connect_via"})
_SIGNAL_EMIT_METHODS = frozenset({"send", "send_robust"})
_REGISTRATION_CALLER_SCOPE = "registration_caller"
_MATCHING_EMISSION_SCOPE = "matching_emission"
_EMISSION_CALLER_SCOPE = "emission_caller"
_FRAMEWORK_LIFECYCLE_SCOPE = "framework_lifecycle"


@dataclass(frozen=True)
class DispatchEdge:
    """A provider-declared dynamic dispatch from one function to another."""

    caller_fqn: str
    target: Function
    dispatch_type: str
    location: Location
    provenance: Provenance


@dataclass(frozen=True)
class DispatchConversionResult:
    """Converted dispatch edges and non-fatal conversion gaps."""

    edges: tuple[DispatchEdge, ...]
    hooks: tuple[LifecycleHook, ...] = ()
    gaps: tuple[AnalysisGap, ...] = ()


@dataclass(frozen=True)
class _SignalRegistration:
    signal_fqn: str
    target: Function


@dataclass(frozen=True)
class _SignalEmission:
    signal_fqn: str
    caller_fqn: str
    dispatch_type: str
    location: Location


@dataclass(frozen=True)
class _CallbackRegistration:
    invocation_key: str
    target: Function


@dataclass(frozen=True)
class _CallbackEmission:
    invocation_key: str
    caller_fqn: str
    dispatch_type: str
    location: Location


@dataclass(frozen=True)
class _SignalConversionResult:
    registrations: tuple[_SignalRegistration, ...] = ()
    emissions: tuple[_SignalEmission, ...] = ()
    gaps: tuple[AnalysisGap, ...] = ()


@dataclass(frozen=True)
class _CallbackConversionResult:
    registrations: tuple[_CallbackRegistration, ...] = ()
    emissions: tuple[_CallbackEmission, ...] = ()
    hooks: tuple[LifecycleHook, ...] = ()
    gaps: tuple[AnalysisGap, ...] = ()


@dataclass(frozen=True)
class _CallbackTargetResult:
    target: Function | None = None
    gaps: tuple[AnalysisGap, ...] = ()


@dataclass(frozen=True)
class _SignalKeyResult:
    signal_fqns: tuple[str, ...] = ()
    gaps: tuple[AnalysisGap, ...] = ()


def convert_dispatch_match(
    match: ProviderMatch,
    functions_by_fqn: Mapping[str, Function],
    *,
    idx: CodeIndex | None = None,
) -> DispatchConversionResult:
    """Convert one dispatch-phase provider match into synthetic reachability."""
    return convert_dispatch_matches((match,), functions_by_fqn, idx=idx)


def convert_dispatch_matches(
    matches: Iterable[ProviderMatch],
    functions_by_fqn: Mapping[str, Function],
    *,
    idx: CodeIndex | None = None,
) -> DispatchConversionResult:
    """Convert dispatch-phase provider matches into synthetic reachability.

    Signal routing needs all registration and emission matches together: a
    receiver registration alone has no runtime caller, and an emission alone has
    no project-local target. Non-signal dispatches are converted independently.
    """
    dispatch_matches = tuple(matches)
    decorator_fact_keys = _decorator_fact_keys(dispatch_matches)
    registrations_by_signal: dict[str, list[_SignalRegistration]] = defaultdict(list)
    registrations_by_key: dict[str, list[_CallbackRegistration]] = defaultdict(list)
    emissions: list[_SignalEmission] = []
    callback_emissions: list[_CallbackEmission] = []
    edges: list[DispatchEdge] = []
    hooks: list[LifecycleHook] = []
    gaps: list[AnalysisGap] = []

    for match in dispatch_matches:
        descriptor = match.descriptor
        if not isinstance(descriptor, DispatchPattern):
            continue

        if descriptor.dispatch_type == "signal":
            signal_result = _convert_signal_match(
                match,
                descriptor,
                functions_by_fqn,
                idx,
                decorator_fact_keys,
            )
            gaps.extend(signal_result.gaps)
            for signal_registration in signal_result.registrations:
                registrations_by_signal[signal_registration.signal_fqn].append(signal_registration)
            emissions.extend(signal_result.emissions)
            continue

        if descriptor.invocation_scope in {
            _MATCHING_EMISSION_SCOPE,
            _EMISSION_CALLER_SCOPE,
            _FRAMEWORK_LIFECYCLE_SCOPE,
        }:
            callback_result = _convert_callback_match(
                match,
                descriptor,
                functions_by_fqn,
                idx,
                decorator_fact_keys,
            )
            gaps.extend(callback_result.gaps)
            hooks.extend(callback_result.hooks)
            for callback_registration in callback_result.registrations:
                registrations_by_key[callback_registration.invocation_key].append(
                    callback_registration
                )
            callback_emissions.extend(callback_result.emissions)
            continue

        result = _convert_direct_callback_match(match, descriptor, functions_by_fqn, idx)
        edges.extend(result.edges)
        hooks.extend(result.hooks)
        gaps.extend(result.gaps)

    for signal_emission in emissions:
        edges.extend(
            (
                DispatchEdge(
                    caller_fqn=signal_emission.caller_fqn,
                    target=signal_registration.target,
                    dispatch_type=signal_emission.dispatch_type,
                    location=signal_emission.location,
                    provenance=_L2_DISPATCH_PROVENANCE,
                )
            )
            for signal_registration in registrations_by_signal.get(signal_emission.signal_fqn, ())
        )

    for callback_emission in callback_emissions:
        edges.extend(
            (
                DispatchEdge(
                    caller_fqn=callback_emission.caller_fqn,
                    target=callback_registration.target,
                    dispatch_type=callback_emission.dispatch_type,
                    location=callback_emission.location,
                    provenance=_L2_DISPATCH_PROVENANCE,
                )
            )
            for callback_registration in registrations_by_key.get(
                callback_emission.invocation_key, ()
            )
        )

    return DispatchConversionResult(edges=tuple(edges), hooks=tuple(hooks), gaps=tuple(gaps))


def _convert_callback_match(
    match: ProviderMatch,
    descriptor: DispatchPattern,
    functions_by_fqn: Mapping[str, Function],
    idx: CodeIndex | None,
    decorator_fact_keys: frozenset[tuple[str, int, str]],
) -> _CallbackConversionResult:
    if descriptor.invocation_scope == _EMISSION_CALLER_SCOPE:
        return _callback_emission_from_match(match, descriptor, decorator_fact_keys)

    target_result = _callback_target(match, descriptor, functions_by_fqn, idx)
    if target_result.gaps:
        return _CallbackConversionResult(gaps=target_result.gaps)
    if target_result.target is None:
        return _CallbackConversionResult(gaps=(_source_fact_gap(match),))

    if descriptor.invocation_scope == _FRAMEWORK_LIFECYCLE_SCOPE:
        return _lifecycle_hook_from_callback(match, descriptor, target_result.target)

    return _CallbackConversionResult(
        registrations=(
            _CallbackRegistration(
                invocation_key=_callback_invocation_key(descriptor),
                target=target_result.target,
            ),
        ),
        gaps=match.predicate_gaps,
    )


def _callback_emission_from_match(
    match: ProviderMatch,
    descriptor: DispatchPattern,
    decorator_fact_keys: frozenset[tuple[str, int, str]],
) -> _CallbackConversionResult:
    fact = match.source_fact
    if not isinstance(fact, CallEdge):
        return _CallbackConversionResult(gaps=(_source_fact_gap(match),))
    if _is_decorator_factory_call(match, fact, decorator_fact_keys):
        return _CallbackConversionResult()
    if not fact.caller_fqn:
        return _CallbackConversionResult(gaps=(_caller_gap(match),))
    return _CallbackConversionResult(
        emissions=(
            _CallbackEmission(
                invocation_key=_callback_invocation_key(descriptor),
                caller_fqn=fact.caller_fqn,
                dispatch_type=descriptor.dispatch_type,
                location=location(match.location),
            ),
        ),
        gaps=match.predicate_gaps,
    )


def _lifecycle_hook_from_callback(
    match: ProviderMatch,
    descriptor: DispatchPattern,
    target: Function,
) -> _CallbackConversionResult:
    if descriptor.hook_type is None:
        return _CallbackConversionResult(gaps=(_hook_type_gap(match),))
    return _CallbackConversionResult(
        hooks=(
            LifecycleHook(
                handler=target,
                hook_type=descriptor.hook_type,
                scope="global",
                group=None,
                location=location(match.location),
                provenance=_L2_DISPATCH_PROVENANCE,
            ),
        ),
        gaps=match.predicate_gaps,
    )


def _convert_signal_match(
    match: ProviderMatch,
    descriptor: DispatchPattern,
    functions_by_fqn: Mapping[str, Function],
    idx: CodeIndex | None,
    decorator_fact_keys: frozenset[tuple[str, int, str]],
) -> _SignalConversionResult:
    fact = match.source_fact
    if isinstance(fact, DecoratorFact):
        return _signal_registration_from_decorator(match, descriptor, fact, functions_by_fqn, idx)
    if isinstance(fact, CallEdge):
        if _is_decorator_factory_call(match, fact, decorator_fact_keys):
            return _SignalConversionResult()
        method_name = _dispatch_method_name(match.canonical_fqn, descriptor)
        if _is_signal_emit_method(method_name):
            return _signal_emission_from_call(match, descriptor, fact)
        return _signal_registration_from_call(match, descriptor, fact, functions_by_fqn, idx)
    return _SignalConversionResult(gaps=(_source_fact_gap(match),))


def _signal_registration_from_decorator(
    match: ProviderMatch,
    descriptor: DispatchPattern,
    fact: DecoratorFact,
    functions_by_fqn: Mapping[str, Function],
    idx: CodeIndex | None,
) -> _SignalConversionResult:
    target = _resolve_function(fact.target_fqn, match, functions_by_fqn, idx)
    if target is None:
        return _SignalConversionResult(gaps=(_target_resolution_gap(match, fact.target_fqn),))

    signal_result = _signal_keys_for_decorator(match, descriptor, fact, idx)
    if signal_result.gaps:
        return _SignalConversionResult(gaps=signal_result.gaps)

    return _SignalConversionResult(
        registrations=tuple(
            _SignalRegistration(signal_fqn=signal_fqn, target=target)
            for signal_fqn in signal_result.signal_fqns
        ),
        gaps=match.predicate_gaps,
    )


def _signal_registration_from_call(
    match: ProviderMatch,
    descriptor: DispatchPattern,
    fact: CallEdge,
    functions_by_fqn: Mapping[str, Function],
    idx: CodeIndex | None,
) -> _SignalConversionResult:
    method_name = _dispatch_method_name(match.canonical_fqn, descriptor)
    if method_name in _SIGNAL_DECORATOR_FACTORY_METHODS:
        return _SignalConversionResult()

    target_arg = _target_argument(fact, descriptor)
    if target_arg is None:
        return _SignalConversionResult(gaps=(_target_argument_gap(match),))

    target = _resolve_function(target_arg.expression, match, functions_by_fqn, idx)
    if target is None:
        return _SignalConversionResult(
            gaps=(_target_resolution_gap(match, target_arg.expression),)
        )

    return _SignalConversionResult(
        registrations=(
            _SignalRegistration(
                signal_fqn=_signal_base_fqn(match.canonical_fqn, descriptor),
                target=target,
            ),
        ),
        gaps=match.predicate_gaps,
    )


def _signal_emission_from_call(
    match: ProviderMatch,
    descriptor: DispatchPattern,
    fact: CallEdge,
) -> _SignalConversionResult:
    if not fact.caller_fqn:
        return _SignalConversionResult(gaps=(_caller_gap(match),))
    return _SignalConversionResult(
        emissions=(
            _SignalEmission(
                signal_fqn=_signal_base_fqn(match.canonical_fqn, descriptor),
                caller_fqn=fact.caller_fqn,
                dispatch_type=descriptor.dispatch_type,
                location=location(match.location),
            ),
        ),
        gaps=match.predicate_gaps,
    )


def _callback_target(
    match: ProviderMatch,
    descriptor: DispatchPattern,
    functions_by_fqn: Mapping[str, Function],
    idx: CodeIndex | None,
) -> _CallbackTargetResult:
    fact = match.source_fact
    if isinstance(fact, DecoratorFact):
        target_expression = fact.target_fqn
    elif isinstance(fact, CallEdge):
        target_arg = _target_argument(fact, descriptor)
        if target_arg is None:
            return _CallbackTargetResult(gaps=(_target_argument_gap(match),))
        target_expression = target_arg.expression
    else:
        return _CallbackTargetResult(gaps=(_source_fact_gap(match),))

    target = _resolve_function(target_expression, match, functions_by_fqn, idx)
    if target is None:
        return _CallbackTargetResult(gaps=(_target_resolution_gap(match, target_expression),))
    return _CallbackTargetResult(target=target)


def _signal_keys_for_decorator(
    match: ProviderMatch,
    descriptor: DispatchPattern,
    fact: DecoratorFact,
    idx: CodeIndex | None,
) -> _SignalKeyResult:
    method_name = _dispatch_method_name(match.canonical_fqn, descriptor)
    if method_name is not None:
        return _SignalKeyResult(signal_fqns=(_signal_base_fqn(match.canonical_fqn, descriptor),))

    signal_expressions = [
        *fact.args,
        *(value for name, value in fact.kwargs if name in _SIGNAL_ARGUMENT_KEYWORDS),
    ]
    if not signal_expressions:
        return _SignalKeyResult(gaps=(_signal_key_gap(match),))

    signal_fqns: list[str] = []
    gaps: list[AnalysisGap] = []
    for expression in signal_expressions:
        for signal_expression in _signal_expression_items(expression):
            signal_fqn = _resolve_signal_expression(signal_expression, match, idx)
            if signal_fqn is None:
                gaps.append(_signal_resolution_gap(match, signal_expression))
                continue
            _append_unique(signal_fqns, signal_fqn)
    return _SignalKeyResult(signal_fqns=tuple(signal_fqns), gaps=tuple(gaps))


def _convert_direct_callback_match(
    match: ProviderMatch,
    descriptor: DispatchPattern,
    functions_by_fqn: Mapping[str, Function],
    idx: CodeIndex | None,
) -> DispatchConversionResult:
    fact = match.source_fact
    if isinstance(fact, DecoratorFact):
        return _edge_for_target(match, descriptor, fact.target_fqn, None, functions_by_fqn, idx)
    if isinstance(fact, CallEdge):
        target_arg = _target_argument(fact, descriptor)
        if target_arg is None:
            return DispatchConversionResult(edges=(), gaps=(_target_argument_gap(match),))
        return _edge_for_target(
            match,
            descriptor,
            target_arg.expression,
            fact.caller_fqn,
            functions_by_fqn,
            idx,
        )
    return DispatchConversionResult(edges=(), gaps=(_source_fact_gap(match),))


def _edge_for_target(
    match: ProviderMatch,
    descriptor: DispatchPattern,
    target_expression: str,
    caller_fqn: str | None,
    functions_by_fqn: Mapping[str, Function],
    idx: CodeIndex | None,
) -> DispatchConversionResult:
    if caller_fqn is None:
        return DispatchConversionResult(edges=(), gaps=(_caller_gap(match),))

    target = _resolve_function(target_expression, match, functions_by_fqn, idx)
    if target is None:
        return DispatchConversionResult(
            edges=(),
            gaps=(_target_resolution_gap(match, target_expression),),
        )
    return DispatchConversionResult(
        edges=(
            DispatchEdge(
                caller_fqn=caller_fqn,
                target=target,
                dispatch_type=descriptor.dispatch_type,
                location=location(match.location),
                provenance=_L2_DISPATCH_PROVENANCE,
            ),
        ),
        gaps=match.predicate_gaps,
    )


def _target_argument(edge: CallEdge, descriptor: DispatchPattern) -> CallArgument | None:
    explicit = _explicit_callback_argument(edge, descriptor)
    if explicit is not _ARGUMENT_NOT_DECLARED:
        return cast("CallArgument | None", explicit)

    named = _argument_by_any_keyword(edge, descriptor.target_method_names)
    if named is not None:
        return named

    positional = _argument_by_position(edge, 0)
    if positional is not None:
        return positional

    return _argument_by_any_keyword(edge, _GENERIC_CALLBACK_KEYWORDS)


_ARGUMENT_NOT_DECLARED = object()


def _explicit_callback_argument(
    edge: CallEdge,
    descriptor: DispatchPattern,
) -> CallArgument | None | object:
    if descriptor.callback_kwarg is not None:
        arg = _argument_by_keyword(edge, descriptor.callback_kwarg)
        if arg is not None:
            return arg
        if descriptor.callback_arg is None:
            return None

    if descriptor.callback_arg is not None:
        arg = _argument_by_position(edge, descriptor.callback_arg)
        if arg is not None:
            return arg
        if descriptor.callback_kwarg is not None:
            return None
    return _ARGUMENT_NOT_DECLARED


def _argument_by_any_keyword(
    edge: CallEdge,
    keywords: tuple[str, ...] | frozenset[str],
) -> CallArgument | None:
    for keyword in keywords:
        if (arg := _argument_by_keyword(edge, keyword)) is not None:
            return arg
    return None


def _argument_by_keyword(edge: CallEdge, keyword: str) -> CallArgument | None:
    for arg in edge.arguments:
        if arg.keyword == keyword:
            return arg
    return None


def _argument_by_position(edge: CallEdge, position: int) -> CallArgument | None:
    for arg in edge.arguments:
        if arg.position == position:
            return arg
    return None


def _resolve_function(
    expression: str,
    match: ProviderMatch,
    functions_by_fqn: Mapping[str, Function],
    idx: CodeIndex | None,
) -> Function | None:
    direct = functions_by_fqn.get(expression)
    if direct is not None:
        return direct

    if idx is not None:
        resolved = idx.symbols.resolve(expression, match.location.file)
        if resolved is not None:
            resolved_direct = functions_by_fqn.get(resolved)
            if resolved_direct is not None:
                return resolved_direct

    simple_name = _simple_name(expression)
    if simple_name is None:
        return None

    same_file_matches = tuple(
        function
        for function in functions_by_fqn.values()
        if function.location.file == match.location.file
        and function.name == simple_name
        and function.parent_class is None
    )
    if len(same_file_matches) == 1:
        return same_file_matches[0]
    return None


def _decorator_fact_keys(matches: tuple[ProviderMatch, ...]) -> frozenset[tuple[str, int, str]]:
    return frozenset(
        (match.location.file, match.location.line, match.canonical_fqn)
        for match in matches
        if isinstance(match.source_fact, DecoratorFact)
    )


def _is_decorator_factory_call(
    match: ProviderMatch,
    fact: CallEdge,
    decorator_fact_keys: frozenset[tuple[str, int, str]],
) -> bool:
    return (
        fact.callee_fqn is not None
        and (match.location.file, match.location.line, match.canonical_fqn) in decorator_fact_keys
    )


def _is_signal_emit_method(method_name: str | None) -> bool:
    return method_name in _SIGNAL_EMIT_METHODS


def _dispatch_method_name(canonical_fqn: str, descriptor: DispatchPattern) -> str | None:
    for method_name in descriptor.target_method_names:
        if canonical_fqn.endswith(f".{method_name}"):
            return method_name
    terminal = canonical_fqn.rsplit(".", maxsplit=1)[-1]
    if terminal in _SIGNAL_EMIT_METHODS:
        return terminal
    return None


def _signal_base_fqn(canonical_fqn: str, descriptor: DispatchPattern) -> str:
    method_name = _dispatch_method_name(canonical_fqn, descriptor)
    if method_name is None:
        return canonical_fqn
    return canonical_fqn.removesuffix(f".{method_name}")


def _callback_invocation_key(descriptor: DispatchPattern) -> str:
    if descriptor.invocation_key is not None:
        return descriptor.invocation_key
    source_fqn = (
        descriptor.source_fqn[0]
        if isinstance(descriptor.source_fqn, tuple)
        else descriptor.source_fqn
    )
    return f"{descriptor.dispatch_type}:{source_fqn}"


def _signal_expression_items(expression: str) -> tuple[str, ...]:
    tree = _parse_expression(expression)
    if tree is None:
        return (expression,)
    node = tree.body
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return tuple(ast.unparse(item) for item in node.elts)
    return (expression,)


def _resolve_signal_expression(
    expression: str,
    match: ProviderMatch,
    idx: CodeIndex | None,
) -> str | None:
    tree = _parse_expression(expression)
    if tree is None:
        return None
    node = tree.body
    if not isinstance(node, ast.Name | ast.Attribute):
        return None
    if idx is not None:
        resolved = idx.symbols.resolve(expression, match.location.file)
        if resolved is not None:
            return resolved
    return expression


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _target_argument_gap(match: ProviderMatch) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=f"Dispatch target callable not found for {match.observed_fqn}",
        affected_file=match.location.file,
        source_error="dispatch_conversion: missing target callable argument",
        origin_phase="dispatch_conversion",
        origin_provider=match.provider_id,
    )


def _target_resolution_gap(match: ProviderMatch, target_expression: str) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=f"Dispatch target callable could not be resolved: {target_expression}",
        affected_file=match.location.file,
        affected_function=target_expression,
        source_error="dispatch_conversion: unresolved target callable",
        origin_phase="dispatch_conversion",
        origin_provider=match.provider_id,
    )


def _caller_gap(match: ProviderMatch) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=f"Dispatch caller could not be resolved for {match.observed_fqn}",
        affected_file=match.location.file,
        source_error="dispatch_conversion: missing dispatch caller",
        origin_phase="dispatch_conversion",
        origin_provider=match.provider_id,
    )


def _hook_type_gap(match: ProviderMatch) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=f"Framework lifecycle dispatch hook type not declared for {match.observed_fqn}",
        affected_file=match.location.file,
        source_error="dispatch_conversion: missing lifecycle hook type",
        origin_phase="dispatch_conversion",
        origin_provider=match.provider_id,
    )


def _signal_key_gap(match: ProviderMatch) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=f"Signal registration target signal not found for {match.observed_fqn}",
        affected_file=match.location.file,
        source_error="dispatch_conversion: missing signal registration target",
        origin_phase="dispatch_conversion",
        origin_provider=match.provider_id,
    )


def _signal_resolution_gap(match: ProviderMatch, signal_expression: str) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=f"Signal registration target could not be resolved: {signal_expression}",
        affected_file=match.location.file,
        source_error="dispatch_conversion: unresolved signal registration target",
        origin_phase="dispatch_conversion",
        origin_provider=match.provider_id,
    )


def _source_fact_gap(match: ProviderMatch) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INTERPRETER_ERROR,
        message="Dispatch match does not carry a decorator or call fact",
        affected_file=match.location.file,
        source_error="dispatch_conversion: invalid dispatch match",
        origin_phase="dispatch_conversion",
        origin_provider=match.provider_id,
    )
