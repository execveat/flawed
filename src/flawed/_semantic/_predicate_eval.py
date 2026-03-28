"""Provider predicate evaluation for the provider engine.

This module evaluates ``when`` predicates attached to provider descriptors.
Predicate types include literal-string checks, type-check predicates
(resolved against type-enrichment facts), and boolean combinators
(``And``, ``Or``, ``Not``).  The result is a ``_PredicateEval`` with
a ``PredicateStatus`` and any ``AnalysisGap`` records produced during
resolution.

Extracted from ``_matching.py`` to localise predicate logic for
independent evolution (P11, DISC-042).
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from flawed._semantic._provider_engine import PredicateStatus, _PredicateEval
from flawed._semantic.providers import (
    EffectCallPattern,
    LifecycleRegistrationPattern,
    TaintSinkPattern,
)
from flawed._semantic.providers._base import (
    AndPredicate,
    LiteralStringPredicate,
    NotPredicate,
    OrPredicate,
    TypeCheckPredicate,
    WhenPredicate,
)
from flawed.core import AnalysisGap, GapKind

if TYPE_CHECKING:
    from collections.abc import Callable

    from flawed._index._type_enrichment import TypeEnrichmentIndex, TypeFact
    from flawed._index._types import CallArgument, CallEdge
    from flawed._semantic.providers import (
        CheckRegistrationPattern,
        ClaimContainerPattern,
        ControlPlaneExemptionPattern,
        DependencyPattern,
        DispatchPattern,
        FlowPropagatorPattern,
        InputMethodPattern,
        RouteCallPattern,
        SafeGeneratedURLPattern,
        SecurityCheckPattern,
        ValidatedValueGuardPattern,
    )


def _descriptor_when(
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
) -> WhenPredicate | None:
    if isinstance(descriptor, EffectCallPattern | TaintSinkPattern | LifecycleRegistrationPattern):
        return descriptor.when
    return None


def _evaluate_when_predicate(
    predicate: WhenPredicate | None,
    edge: CallEdge,
    type_enrichment: TypeEnrichmentIndex | None = None,
) -> _PredicateEval:
    if predicate is None:
        result = _PredicateEval(PredicateStatus.PASSED)
    elif isinstance(predicate, LiteralStringPredicate):
        arg = _find_argument(edge.arguments, position=predicate.arg_pos, keyword=predicate.arg_kw)
        if arg is None:
            result = _PredicateEval(PredicateStatus.FAILED)
        else:
            result = _PredicateEval(
                PredicateStatus.PASSED
                if _is_literal_string_expression(arg.expression)
                else PredicateStatus.FAILED
            )
    elif isinstance(predicate, TypeCheckPredicate):
        result = _evaluate_type_check(predicate, edge, type_enrichment)
    elif isinstance(predicate, NotPredicate):
        inner = _evaluate_when_predicate(predicate.inner, edge, type_enrichment)
        if inner.status is PredicateStatus.PASSED:
            result = _PredicateEval(PredicateStatus.FAILED, inner.gaps)
        elif inner.status is PredicateStatus.FAILED:
            result = _PredicateEval(PredicateStatus.PASSED, inner.gaps)
        else:
            result = inner
    elif isinstance(predicate, AndPredicate):
        result = _combine_predicates(
            _evaluate_when_predicate(predicate.left, edge, type_enrichment),
            _evaluate_when_predicate(predicate.right, edge, type_enrichment),
            failed_when=lambda left, right: (
                left.status is PredicateStatus.FAILED or right.status is PredicateStatus.FAILED
            ),
            passed_when=lambda left, right: (
                left.status is PredicateStatus.PASSED and right.status is PredicateStatus.PASSED
            ),
        )
    elif isinstance(predicate, OrPredicate):
        result = _combine_predicates(
            _evaluate_when_predicate(predicate.left, edge, type_enrichment),
            _evaluate_when_predicate(predicate.right, edge, type_enrichment),
            failed_when=lambda left, right: (
                left.status is PredicateStatus.FAILED and right.status is PredicateStatus.FAILED
            ),
            passed_when=lambda left, right: (
                left.status is PredicateStatus.PASSED or right.status is PredicateStatus.PASSED
            ),
        )
    else:
        result = _PredicateEval(PredicateStatus.UNKNOWN)
    return result


def _combine_predicates(
    left: _PredicateEval,
    right: _PredicateEval,
    *,
    failed_when: Callable[[_PredicateEval, _PredicateEval], bool],
    passed_when: Callable[[_PredicateEval, _PredicateEval], bool],
) -> _PredicateEval:
    gaps = (*left.gaps, *right.gaps)
    if failed_when(left, right):
        return _PredicateEval(PredicateStatus.FAILED, gaps)
    if passed_when(left, right):
        return _PredicateEval(PredicateStatus.PASSED, gaps)
    return _PredicateEval(PredicateStatus.UNKNOWN, gaps)


def _find_argument(
    arguments: tuple[CallArgument, ...],
    *,
    position: int | None,
    keyword: str | None,
) -> CallArgument | None:
    for argument in arguments:
        if keyword is not None and argument.keyword == keyword:
            return argument
        if keyword is None and position is not None and argument.position == position:
            return argument
    return None


def _evaluate_type_check(
    predicate: TypeCheckPredicate,
    edge: CallEdge,
    type_enrichment: TypeEnrichmentIndex | None,
) -> _PredicateEval:
    """Dispatch a TypeCheckPredicate: find the argument, then resolve."""
    arg = _find_argument(edge.arguments, position=predicate.arg_pos, keyword=predicate.arg_kw)
    if arg is None:
        return _PredicateEval(PredicateStatus.FAILED)
    if type_enrichment is None:
        return _PredicateEval(
            PredicateStatus.UNKNOWN,
            (
                AnalysisGap(
                    kind=GapKind.INFERENCE_FAILURE,
                    message="Type-based provider predicate requires type enrichment",
                    affected_file=edge.location.file,
                    affected_function=edge.caller_fqn,
                    source_error=(
                        "unsupported predicate: "
                        f"arg({predicate.arg_pos}).type_is({predicate.type_fqn})"
                    ),
                    origin_phase="provider_matching",
                ),
            ),
        )
    return _resolve_type_predicate(predicate, arg, edge, type_enrichment)


def _resolve_type_predicate(
    predicate: TypeCheckPredicate,
    arg: CallArgument,
    edge: CallEdge,
    type_enrichment: TypeEnrichmentIndex,
) -> _PredicateEval:
    """Resolve a type-check predicate against type-enrichment facts."""
    matching_facts = type_enrichment.types_for_expression(
        arg.expression,
        arg.location.file,
        containing_function_fqn=edge.caller_fqn,
    )
    if not matching_facts:
        return _PredicateEval(
            PredicateStatus.UNKNOWN,
            (
                _type_predicate_gap(
                    edge,
                    message=f"No type fact for argument '{arg.expression}'",
                    source_error=f"no type enrichment for: {arg.expression}",
                ),
            ),
        )
    concrete_facts = tuple(fact for fact in matching_facts if fact.is_concrete)
    if not concrete_facts:
        return _PredicateEval(
            PredicateStatus.UNKNOWN,
            (
                _type_predicate_gap(
                    edge,
                    message=(
                        f"No concrete type fact for argument '{arg.expression}'; "
                        "all type facts are imprecise"
                    ),
                    source_error=f"imprecise type facts: {_format_type_facts(matching_facts)}",
                ),
            ),
        )
    if _concrete_facts_disagree(concrete_facts):
        return _PredicateEval(
            PredicateStatus.UNKNOWN,
            (
                _type_predicate_gap(
                    edge,
                    message=f"Conflicting concrete type facts for argument '{arg.expression}'",
                    source_error=(
                        f"conflicting concrete type facts: {_format_type_facts(concrete_facts)}"
                    ),
                ),
            ),
        )
    fact = concrete_facts[0]
    allowed_fqns = {predicate.type_fqn, *predicate.alt_fqns}
    if _type_matches(fact.declared_type, allowed_fqns):
        return _PredicateEval(PredicateStatus.PASSED)
    return _PredicateEval(PredicateStatus.FAILED)


def _type_predicate_gap(
    edge: CallEdge,
    *,
    message: str,
    source_error: str,
) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=message,
        affected_file=edge.location.file,
        affected_function=edge.caller_fqn,
        source_error=source_error,
        origin_phase="provider_matching",
    )


def _concrete_facts_disagree(facts: tuple[TypeFact, ...]) -> bool:
    representatives: list[str] = []
    for fact in facts:
        if not any(_type_strings_agree(fact.declared_type, seen) for seen in representatives):
            representatives.append(fact.declared_type)
    return len(representatives) > 1


def _type_strings_agree(left: str, right: str) -> bool:
    return left == right or left.endswith(f".{right}") or right.endswith(f".{left}")


def _format_type_facts(facts: tuple[TypeFact, ...]) -> str:
    return ", ".join(f"{fact.source_tool}={fact.declared_type}" for fact in facts)


def _type_matches(declared_type: str, allowed_fqns: set[str]) -> bool:
    """Check if a declared type matches any of the allowed FQNs."""
    for fqn in allowed_fqns:
        if declared_type == fqn:
            return True
        if declared_type.endswith(f".{fqn}") or fqn.endswith(f".{declared_type}"):
            return True
    return False


def _is_literal_string_expression(expression: str) -> bool:
    try:
        value = ast.literal_eval(expression)
    except (SyntaxError, ValueError):
        return False
    return _is_literal_string_value(value)


def _is_literal_string_value(value: object) -> bool:
    if isinstance(value, str):
        return True
    if isinstance(value, tuple | list | set | frozenset):
        return all(_is_literal_string_value(item) for item in value)
    if isinstance(value, dict):
        return all(
            _is_literal_string_value(key) and _is_literal_string_value(item)
            for key, item in value.items()
        )
    return False
