"""Transparent flow edges for provider-declared state proxies."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from flawed._index._types import AccessKind, AttributeAccess, SymbolRef
from flawed._semantic._conversion_utils import conversion_gap as _conversion_gap
from flawed._semantic._flow_propagation import FlowPropagationEdge
from flawed._semantic._provider_engine import ProviderMatch, ProviderPhase
from flawed._semantic.providers import StateProxyPattern
from flawed.core import AnalysisGap, GapKind

if TYPE_CHECKING:
    from collections.abc import Iterable

    from flawed._index import CodeIndex
    from flawed._index._types import FunctionRecord, SourceSpan


@dataclass(frozen=True)
class ProxyFlowResult:
    """Provider proxy-resolution edges plus conversion gaps."""

    propagators: tuple[FlowPropagationEdge, ...]
    gaps: tuple[AnalysisGap, ...] = ()


def convert_proxy_flow_matches(
    matches: tuple[ProviderMatch, ...],
    *,
    idx: CodeIndex | None = None,
) -> ProxyFlowResult:
    """Convert state-proxy matches into transparent value-flow edges.

    ``StateProxyPattern`` already tells L2 that one public symbol is a view over
    another request/session/server-scoped object.  These edges make that
    relationship visible to taint tracing instead of only to state-read effect
    conversion.
    """
    propagators: list[FlowPropagationEdge] = []
    gaps: list[AnalysisGap] = []
    seen: set[tuple[str, str, str, int]] = set()
    handled_accesses: set[tuple[str, str, int]] = set()
    symbol_matches_requiring_index: list[ProviderMatch] = []
    for match in matches:
        if match.phase is not ProviderPhase.PROXIES:
            continue
        if not isinstance(match.descriptor, StateProxyPattern):
            continue
        if isinstance(match.source_fact, AttributeAccess):
            converted = _attribute_proxy_edges(match, seen)
            handled_accesses.add(_match_location_key(match))
        elif isinstance(match.source_fact, SymbolRef):
            if idx is None:
                symbol_matches_requiring_index.append(match)
                continue
            converted = _symbol_proxy_edges(match, idx, seen)
        else:
            gaps.append(_gap(match, "proxy match does not carry a symbol or attribute access"))
            continue
        propagators.extend(converted.propagators)
        gaps.extend(converted.gaps)
    gaps.extend(
        _gap(
            match,
            "state-proxy symbol access requires index context to identify a containing function",
        )
        for match in symbol_matches_requiring_index
        if _match_location_key(match) not in handled_accesses
    )
    return ProxyFlowResult(tuple(propagators), tuple(gaps))


def _attribute_proxy_edges(
    match: ProviderMatch,
    seen: set[tuple[str, str, str, int]],
) -> ProxyFlowResult:
    fact = match.source_fact
    assert isinstance(fact, AttributeAccess)
    descriptor = match.descriptor
    assert isinstance(descriptor, StateProxyPattern)

    if fact.containing_function_fqn is None:
        return ProxyFlowResult(
            (),
            (
                _gap(
                    match,
                    "state-proxy attribute access is missing containing function context",
                ),
            ),
        )

    target_expression = _attribute_expression(fact)
    edges: list[FlowPropagationEdge] = []
    for source_expression in _source_expressions(descriptor.resolves_to, fact.attr_name):
        key = (
            fact.containing_function_fqn,
            source_expression,
            target_expression,
            fact.location.line,
        )
        if key in seen:
            continue
        seen.add(key)
        edges.append(
            FlowPropagationEdge(
                provider_id=match.provider_id,
                observed_fqn=match.observed_fqn,
                canonical_fqn=match.canonical_fqn,
                source_expression=source_expression,
                source_location=fact.location,
                target_expression=target_expression,
                target_location=fact.location,
                containing_function_fqn=fact.containing_function_fqn,
                description=_description(descriptor),
            )
        )
    return ProxyFlowResult(tuple(edges))


def _symbol_proxy_edges(
    match: ProviderMatch,
    idx: CodeIndex,
    seen: set[tuple[str, str, str, int]],
) -> ProxyFlowResult:
    fact = match.source_fact
    assert isinstance(fact, SymbolRef)
    descriptor = match.descriptor
    assert isinstance(descriptor, StateProxyPattern)

    function_fqn = _function_fqn_for_span(idx.functions, fact.location)
    if function_fqn is None:
        return ProxyFlowResult(
            (),
            (
                _gap(
                    match,
                    "state-proxy symbol access is outside any known containing function",
                ),
            ),
        )

    edges: list[FlowPropagationEdge] = []
    for source_expression in _target_expression_variants_from_value(descriptor.resolves_to):
        key = (function_fqn, source_expression, fact.name, fact.location.line)
        if key in seen:
            continue
        seen.add(key)
        edges.append(
            FlowPropagationEdge(
                provider_id=match.provider_id,
                observed_fqn=match.observed_fqn,
                canonical_fqn=match.canonical_fqn,
                source_expression=source_expression,
                source_location=fact.location,
                target_expression=fact.name,
                target_location=fact.location,
                containing_function_fqn=function_fqn,
                description=_description(descriptor),
            )
        )
    return ProxyFlowResult(tuple(edges))


def _gap(match: ProviderMatch, message: str) -> AnalysisGap:
    return _conversion_gap(
        match,
        message,
        origin_phase="proxy_flow_conversion",
        kind=GapKind.VALUE_FLOW_INCOMPLETE,
    )


def _match_location_key(match: ProviderMatch) -> tuple[str, str, int]:
    return (match.canonical_fqn, match.location.file, match.location.line)


def _source_expressions(resolves_to: str | tuple[str, ...], attr_name: str) -> tuple[str, ...]:
    expressions: list[str] = []
    for target in _target_expression_variants_from_value(resolves_to):
        expressions.append(target)
        expressions.append(f"{target}.{attr_name}")
    return _dedupe(expressions)


def _target_expression_variants_from_value(value: str | tuple[str, ...]) -> tuple[str, ...]:
    expressions: list[str] = []
    for target in _as_tuple(value):
        expressions.extend(_target_expression_variants(target))
    return _dedupe(expressions)


def _target_expression_variants(target: str) -> tuple[str, ...]:
    parts = target.split(".")
    variants = [target]
    if len(parts) >= 2:
        variants.append(".".join(parts[-2:]))
    if len(parts) >= 3:
        variants.append(".".join(parts[-3:]))
    return _dedupe(variants)


def _attribute_expression(fact: AttributeAccess) -> str:
    if fact.access_kind is AccessKind.SUBSCRIPT:
        return f"{fact.target_expr}[{fact.attr_name}]"
    return f"{fact.target_expr}.{fact.attr_name}"


def _description(descriptor: StateProxyPattern) -> str:
    if descriptor.description:
        return f"Transparent state-proxy flow: {descriptor.description}"
    return "Transparent state-proxy flow"


def _function_fqn_for_span(
    functions: Iterable[FunctionRecord],
    span: SourceSpan,
) -> str | None:
    matches = tuple(
        function
        for function in functions
        if function.file == span.file
        and function.line <= span.line
        and (function.location.end_line is None or span.line <= function.location.end_line)
    )
    if not matches:
        return None
    return max(matches, key=lambda function: function.line).fqn


def _as_tuple(value: str | tuple[str, ...]) -> tuple[str, ...]:
    return (value,) if isinstance(value, str) else value


def _dedupe(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))
