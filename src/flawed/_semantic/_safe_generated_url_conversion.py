"""Convert provider-generated safe URL matches into public value facts."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import TYPE_CHECKING

from flawed._index._types import CallEdge
from flawed._semantic._conversion_utils import (
    call_expression as _call_expression,
)
from flawed._semantic._conversion_utils import (
    conversion_gap as _conversion_gap,
)
from flawed._semantic._conversion_utils import (
    location as _location,
)
from flawed._semantic.providers import SafeGeneratedURLPattern
from flawed.core import AnalysisGap, GapKind, Provenance
from flawed.generated import SafeGeneratedURL

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flawed._semantic._provider_engine import ProviderMatch
    from flawed.function import Function


_L2_SAFE_URL_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="provider_safe_generated_urls",
    confidence=0.95,
    supporting_facts=("provider safe-generated-URL descriptor matched L1 call graph fact",),
)


@dataclass(frozen=True)
class SafeGeneratedURLConversionResult:
    """Converted safe generated URLs and non-fatal conversion gaps."""

    safe_generated_urls: tuple[SafeGeneratedURL, ...]
    gaps: tuple[AnalysisGap, ...] = ()


def convert_safe_generated_url_matches(
    matches: tuple[ProviderMatch, ...],
    functions_by_fqn: Mapping[str, Function],
) -> SafeGeneratedURLConversionResult:
    """Convert SAFE_GENERATED_URLS provider matches into value facts."""
    safe_urls: list[SafeGeneratedURL] = []
    gaps: list[AnalysisGap] = []
    for match in matches:
        descriptor = match.descriptor
        fact = match.source_fact
        if not isinstance(descriptor, SafeGeneratedURLPattern):
            continue
        if not isinstance(fact, CallEdge):
            gaps.append(
                _conversion_gap(
                    match,
                    "safe generated URL match does not carry a call edge",
                    origin_phase="safe_generated_url_conversion",
                )
            )
            continue
        if descriptor.output != "return":
            gaps.append(
                _conversion_gap(
                    match,
                    f"unsupported output {descriptor.output!r}",
                    origin_phase="safe_generated_url_conversion",
                )
            )
            continue

        function = functions_by_fqn.get(fact.caller_fqn)
        if function is None:
            gaps.append(
                _conversion_gap(
                    match,
                    "safe generated URL call has no converted caller",
                    origin_phase="safe_generated_url_conversion",
                )
            )
            continue

        external_state = _external_state(descriptor, fact)
        if external_state == _ExternalState.UNSAFE:
            continue
        if external_state == _ExternalState.DYNAMIC:
            gaps.append(_dynamic_external_gap(match, descriptor))
            continue

        safe_urls.append(
            SafeGeneratedURL(
                function=function,
                location=_location(fact.location),
                expression=_call_expression(fact),
                safe_for_sink_kinds=tuple(dict.fromkeys(descriptor.safe_for_sink_kinds)),
                provenance=_L2_SAFE_URL_PROVENANCE,
                description=descriptor.description,
            )
        )
    return SafeGeneratedURLConversionResult(tuple(safe_urls), tuple(gaps))


class _ExternalState:
    SAFE = "safe"
    UNSAFE = "unsafe"
    DYNAMIC = "dynamic"


def _external_state(
    descriptor: SafeGeneratedURLPattern,
    edge: CallEdge,
) -> str:
    if descriptor.external_kwarg is None:
        return _ExternalState.SAFE

    external_arg = next(
        (arg for arg in edge.arguments if arg.keyword == descriptor.external_kwarg),
        None,
    )
    if external_arg is None:
        return _ExternalState.SAFE

    literal = _literal_bool(external_arg.expression)
    if literal is None:
        return _ExternalState.SAFE if descriptor.external_safe else _ExternalState.DYNAMIC
    if literal is False:
        return _ExternalState.SAFE
    return _ExternalState.SAFE if descriptor.external_safe else _ExternalState.UNSAFE


def _literal_bool(expression: str) -> bool | None:
    try:
        value = ast.literal_eval(expression)
    except (SyntaxError, ValueError):
        return None
    return value if isinstance(value, bool) else None


def _dynamic_external_gap(
    match: ProviderMatch,
    descriptor: SafeGeneratedURLPattern,
) -> AnalysisGap:
    kwarg = descriptor.external_kwarg or "<external>"
    return _conversion_gap(
        match,
        f"dynamic {kwarg} prevents safe generated URL classification",
        origin_phase="safe_generated_url_conversion",
        kind=GapKind.INFERENCE_FAILURE,
    )
