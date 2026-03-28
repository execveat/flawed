"""Convert provider validation-guard matches into validated value facts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from flawed._index._types import CallEdge
from flawed._semantic._check_conversion import ConcreteCondition
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
from flawed._semantic.providers import ValidatedValueGuardPattern
from flawed.conditions import CodeScope, ConditionKind, DenialKind, GuardClassification
from flawed.core import Provenance
from flawed.validation import ValidatedValue

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flawed._index import CodeIndex
    from flawed._index._types import CallArgument
    from flawed._semantic._provider_engine import ProviderMatch
    from flawed.core import AnalysisGap
    from flawed.function import Function


_L2_VALIDATED_VALUE_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="provider_validation_guards",
    confidence=0.9,
    supporting_facts=("provider validation-guard descriptor matched L1 call graph fact",),
)


@dataclass(frozen=True)
class ValidationGuardConversionResult:
    """Converted validated values, exposed checks, and non-fatal gaps."""

    validated_values_by_function: dict[str, list[ValidatedValue]]
    conditions_by_function: dict[str, list[ConcreteCondition]]
    gaps: tuple[AnalysisGap, ...] = ()


def convert_validation_guard_matches(
    matches: tuple[ProviderMatch, ...],
    functions_by_fqn: Mapping[str, Function],
    *,
    idx: CodeIndex | None = None,
) -> ValidationGuardConversionResult:
    """Convert validation guard provider matches into function-scoped facts."""
    values_by_function: dict[str, list[ValidatedValue]] = {}
    conditions_by_function: dict[str, list[ConcreteCondition]] = {}
    gaps: list[AnalysisGap] = []
    for match in matches:
        descriptor = match.descriptor
        fact = match.source_fact
        if not isinstance(descriptor, ValidatedValueGuardPattern):
            continue
        if not isinstance(fact, CallEdge):
            gaps.append(
                _conversion_gap(
                    match,
                    "validation guard match does not carry a call edge",
                    origin_phase="validation_guard_conversion",
                )
            )
            continue

        function = functions_by_fqn.get(fact.caller_fqn)
        if function is None:
            gaps.append(
                _conversion_gap(
                    match,
                    "validation guard call has no converted caller",
                    origin_phase="validation_guard_conversion",
                )
            )
            continue

        argument = _argument(fact, position=descriptor.arg, keyword=descriptor.keyword)
        if argument is None:
            target = _argument_target(descriptor.arg, descriptor.keyword)
            gaps.append(
                _conversion_gap(
                    match,
                    f"validated argument {target} is missing",
                    origin_phase="validation_guard_conversion",
                )
            )
            continue

        call_expr = _call_expression(fact)
        value = build_validated_value_from_call(
            fact,
            function,
            argument=argument,
            safe_for_sink_kinds=descriptor.safe_for_sink_kinds,
            validated_when=descriptor.validated_when,
            description=descriptor.description,
            provenance=_L2_VALIDATED_VALUE_PROVENANCE,
            idx=idx,
        )
        values_by_function.setdefault(function.fqn, []).append(value)
        conditions_by_function.setdefault(function.fqn, []).append(
            _condition_for_guard(match, descriptor, function, call_expr),
        )
    return ValidationGuardConversionResult(
        validated_values_by_function=values_by_function,
        conditions_by_function=conditions_by_function,
        gaps=tuple(gaps),
    )


def build_validated_value_from_call(
    fact: CallEdge,
    function: Function,
    *,
    argument: CallArgument,
    safe_for_sink_kinds: tuple[str, ...],
    validated_when: bool,
    description: str,
    provenance: Provenance,
    idx: CodeIndex | None,
) -> ValidatedValue:
    """Build a :class:`ValidatedValue` from a resolved guard call edge.

    Shared by the name/FQN-declared guard path (this module) and the
    shape-based structural recognizer (``_structural_url_guard``) so both
    emit byte-identical facts and the downstream sink-suppression logic
    (``_collections._sink_target_is_validated``) treats them uniformly.
    """
    return ValidatedValue(
        function=function,
        location=_location(fact.location),
        expression=_call_expression(fact),
        validated_location=_location(argument.location),
        validated_expression=argument.expression,
        definition_location=(
            definition_location_for_expression(
                idx,
                function_fqn=function.fqn,
                expression=argument.expression,
                before=argument.location,
            )
            if idx is not None
            else None
        ),
        safe_for_sink_kinds=tuple(dict.fromkeys(safe_for_sink_kinds)),
        validated_when=validated_when,
        provenance=provenance,
        description=description,
    )


def _condition_for_guard(
    match: ProviderMatch,
    descriptor: ValidatedValueGuardPattern,
    function: Function,
    call_expr: str,
) -> ConcreteCondition:
    branch = _empty_scope()
    return ConcreteCondition(
        expression=call_expr,
        location=_location(match.location),
        function=function,
        kind=ConditionKind.CALL_RESULT,
        provenance=_L2_VALIDATED_VALUE_PROVENANCE,
        category=descriptor.category,
        provider_id=match.provider_id,
        _true_branch=branch,
        _false_branch=branch,
        _guard=GuardClassification(
            guarded_branch=branch,
            denied_branch=branch,
            denial_kind=DenialKind.UNKNOWN,
            confidence=0.8,
        ),
    )


def _empty_scope() -> CodeScope:
    from flawed._semantic._scope import ConcreteCodeScope

    return ConcreteCodeScope()
