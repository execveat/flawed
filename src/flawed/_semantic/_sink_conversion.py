"""Convert provider taint-sink matches into public sink observations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from flawed._index._types import CallEdge
from flawed._semantic._conversion_utils import (
    argument_target_description as _argument_target,
)
from flawed._semantic._conversion_utils import (
    call_expression as _call_expression,
)
from flawed._semantic._conversion_utils import (
    conversion_gap as _conversion_gap,
)
from flawed._semantic._conversion_utils import (
    find_argument as _argument,
)
from flawed._semantic._conversion_utils import (
    location as _location,
)
from flawed._semantic._value_definition import definition_location_for_expression
from flawed._semantic.providers import TaintSinkPattern
from flawed.core import Provenance
from flawed.sinks import TaintSink

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flawed._index import CodeIndex
    from flawed._semantic._provider_engine import ProviderMatch
    from flawed.core import AnalysisGap
    from flawed.function import Function


_L2_SINK_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="provider_sinks",
    confidence=0.95,
    supporting_facts=("provider taint-sink descriptor matched L1 call graph fact",),
)


@dataclass(frozen=True)
class SinkConversionResult:
    """Converted taint sinks and non-fatal conversion gaps."""

    sinks: tuple[TaintSink, ...]
    gaps: tuple[AnalysisGap, ...] = ()


def convert_sink_match(
    match: ProviderMatch,
    functions_by_fqn: Mapping[str, Function],
    *,
    idx: CodeIndex | None = None,
) -> SinkConversionResult:
    """Convert one SINKS-phase provider match into a public sink observation."""
    descriptor = match.descriptor
    fact = match.source_fact
    if not isinstance(descriptor, TaintSinkPattern):
        return SinkConversionResult(())
    if not isinstance(fact, CallEdge):
        return SinkConversionResult(
            (),
            (
                _conversion_gap(
                    match,
                    "sink match does not carry a call edge",
                    origin_phase="sink_conversion",
                ),
            ),
        )

    function = functions_by_fqn.get(fact.caller_fqn)
    if function is None:
        return SinkConversionResult(
            (),
            (
                _conversion_gap(
                    match,
                    "sink call has no converted caller",
                    origin_phase="sink_conversion",
                ),
            ),
        )

    argument = _argument(fact, position=descriptor.arg, keyword=descriptor.keyword)
    if argument is None:
        target = _argument_target(descriptor.arg, descriptor.keyword)
        return SinkConversionResult(
            (),
            (
                _conversion_gap(
                    match,
                    f"sink argument {target} is missing",
                    origin_phase="sink_conversion",
                ),
            ),
        )

    sink = TaintSink(
        kind=descriptor.sink_kind,
        function=function,
        location=_location(fact.location),
        expression=_call_expression(fact),
        argument_location=_location(argument.location),
        argument_expression=argument.expression,
        provenance=_L2_SINK_PROVENANCE,
        description=descriptor.description,
    )
    # When the provider declared a when-predicate and it passed, the sink
    # argument has been validated (e.g. confirmed non-literal).  This allows
    # the collection to use scope-coincidence instead of requiring L1 flow
    # proof for patterns the value-flow graph cannot trace (f-strings, concat).
    if descriptor.when is not None:
        object.__setattr__(sink, "_predicate_validated", True)
    if idx is not None:
        object.__setattr__(
            sink,
            "_argument_definition_location",
            definition_location_for_expression(
                idx,
                function_fqn=function.fqn,
                expression=argument.expression,
                before=argument.location,
            ),
        )
    return SinkConversionResult((sink,))
