"""Convert provider security-check matches into public Condition objects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from flawed._index._types import CallEdge, DecoratorFact, SourceSpan, SymbolRef
from flawed._semantic._conversion_utils import call_expression, location
from flawed._semantic.providers import CheckKind, ClassAttributeGuardPattern, SecurityCheckPattern
from flawed.conditions import Check, CodeScope, ConditionKind, DenialKind, GuardClassification
from flawed.core import AnalysisGap, GapKind, Provenance

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flawed._index import CodeIndex
    from flawed._semantic._provider_engine import ProviderMatch
    from flawed.flow import ValueHandle
    from flawed.function import Function


_L2_CHECK_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="provider_checks",
    confidence=0.95,
    supporting_facts=("provider security-check descriptor matched L1 structural fact",),
)


@dataclass(frozen=True)
class ConcreteCondition(Check):
    """Concrete :class:`~flawed.conditions.Check` backed by a provider-declared
    (or L2-inferred) security check.

    ``category`` and ``provider_id`` are inherited from :class:`Check`: this is
    the runtime object every ``.checks()`` query yields, so the typed surface
    rules see (``check.provider_id``, a ``str`` ``category``) is truthful by
    construction.
    """

    _operator: str | None = None
    _true_branch: CodeScope | None = None
    _false_branch: CodeScope | None = None
    _left: ValueHandle | None = None
    _right: ValueHandle | None = None
    _guard: GuardClassification | None = None

    @property
    def operator(self) -> str | None:
        return self._operator

    @property
    def true_branch(self) -> CodeScope:
        if self._true_branch is None:
            return _empty_scope()
        return self._true_branch

    @property
    def false_branch(self) -> CodeScope:
        if self._false_branch is None:
            return _empty_scope()
        return self._false_branch

    @property
    def left(self) -> ValueHandle | None:
        return self._left

    @property
    def right(self) -> ValueHandle | None:
        return self._right

    @property
    def guard(self) -> GuardClassification | None:
        return self._guard


@dataclass(frozen=True)
class CheckConversionResult:
    """Converted check conditions grouped by containing function FQN."""

    conditions_by_function: dict[str, list[ConcreteCondition]]
    gaps: tuple[AnalysisGap, ...] = ()


def convert_check_matches(
    matches: tuple[ProviderMatch, ...],
    functions_by_fqn: Mapping[str, Function],
    *,
    idx: CodeIndex | None = None,
) -> CheckConversionResult:
    """Convert provider CHECKS-phase matches to function-scoped conditions."""
    conditions_by_function: dict[str, list[ConcreteCondition]] = {}
    gaps: list[AnalysisGap] = []
    for match in matches:
        gaps.extend(match.predicate_gaps)
        descriptor = match.descriptor
        if not isinstance(descriptor, SecurityCheckPattern | ClassAttributeGuardPattern):
            gaps.append(_unsupported_descriptor_gap(match))
            continue
        functions = _functions_for_match(match, functions_by_fqn)
        if not functions:
            if _is_module_security_source(match, idx):
                continue
            gaps.append(_owner_gap(match))
            continue
        for function in functions:
            condition = _condition_for_match(match, descriptor.category, function)
            conditions_by_function.setdefault(function.fqn, []).append(condition)
    return CheckConversionResult(conditions_by_function=conditions_by_function, gaps=tuple(gaps))


def _functions_for_match(
    match: ProviderMatch,
    functions_by_fqn: Mapping[str, Function],
) -> tuple[Function, ...]:
    fact = match.source_fact
    if isinstance(fact, DecoratorFact):
        direct = functions_by_fqn.get(fact.target_fqn)
        if direct is not None:
            return (direct,)
        return _methods_for_class(fact.target_fqn, functions_by_fqn)
    if isinstance(fact, CallEdge):
        function = functions_by_fqn.get(fact.caller_fqn)
        return (function,) if function is not None else ()
    if isinstance(fact, SymbolRef) and fact.fqn is not None:
        return _methods_for_class(fact.fqn, functions_by_fqn)
    return ()


def _methods_for_class(
    class_fqn: str,
    functions_by_fqn: Mapping[str, Function],
) -> tuple[Function, ...]:
    return tuple(
        function for function in functions_by_fqn.values() if function.parent_class == class_fqn
    )


def _is_module_security_source(match: ProviderMatch, idx: CodeIndex | None) -> bool:
    """Return true for module-scope security scheme values consumed by DI.

    Security scheme constructors are commonly declared once at module scope
    and later passed to dependency-injection markers.  The constructor call is
    a security source, but it is not itself a function-scoped guard; dependency
    conversion attaches the guard when a DI chain consumes the assigned value.
    """
    descriptor = match.descriptor
    fact = match.source_fact
    return (
        isinstance(descriptor, SecurityCheckPattern)
        and descriptor.kind is CheckKind.CALL
        and isinstance(fact, CallEdge)
        and fact.caller_fqn == "<module>"
        and idx is not None
        and bool(_assigned_variable_fqns(match.location, idx))
    )


def _assigned_variable_fqns(span: SourceSpan, idx: CodeIndex) -> tuple[str, ...]:
    from flawed._semantic._dependency_conversion import (
        _assigned_variable_fqns as _dependency_assigned_variable_fqns,
    )

    return _dependency_assigned_variable_fqns(span, idx)


def _condition_for_match(
    match: ProviderMatch,
    category: str,
    function: Function,
) -> ConcreteCondition:
    expression = _condition_expression(match)
    branch = _empty_scope()
    return ConcreteCondition(
        expression=expression,
        location=location(match.location),
        function=function,
        kind=ConditionKind.CALL_RESULT,
        provenance=_L2_CHECK_PROVENANCE,
        category=category,
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


def _condition_expression(match: ProviderMatch) -> str:
    fact = match.source_fact
    if isinstance(fact, DecoratorFact):
        return f"@{fact.name}"
    if isinstance(fact, CallEdge):
        return call_expression(fact)
    if isinstance(fact, SymbolRef):
        return f"{fact.name} -> {match.canonical_fqn}"
    return match.observed_fqn


def _empty_scope() -> CodeScope:
    from flawed._semantic._scope import ConcreteCodeScope

    return ConcreteCodeScope()


def _unsupported_descriptor_gap(match: ProviderMatch) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INTERPRETER_ERROR,
        message=f"Unsupported check descriptor type: {type(match.descriptor).__name__}",
        affected_file=match.location.file,
        affected_function=_owner_fqn(match),
        source_error="check_conversion: descriptor not implemented",
        origin_phase="check_conversion",
        origin_provider=match.provider_id,
    )


def _owner_gap(match: ProviderMatch) -> AnalysisGap:
    owner = _owner_fqn(match)
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=f"Security check could not be attached to a function: {match.observed_fqn}",
        affected_file=match.location.file,
        affected_function=owner,
        source_error="check_conversion: missing containing function",
        origin_phase="check_conversion",
        origin_provider=match.provider_id,
    )


def _owner_fqn(match: ProviderMatch) -> str | None:
    fact = match.source_fact
    if isinstance(fact, DecoratorFact):
        return fact.target_fqn
    if isinstance(fact, CallEdge):
        return fact.caller_fqn
    return None
