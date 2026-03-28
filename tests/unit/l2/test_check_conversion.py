"""Tests for provider security-check conversion."""

from __future__ import annotations

from flawed._index._types import (
    CallEdge,
    DecoratorFact,
    EdgeSource,
    ExtractionProvenance,
    FunctionRecord,
    ResolutionStatus,
    SourceSpan,
)
from flawed._index._types import FunctionKind as L1FunctionKind
from flawed._semantic._check_conversion import convert_check_matches
from flawed._semantic._conversion import convert_function
from flawed._semantic._provider_engine import ProviderMatch, ProviderPhase
from flawed._semantic.providers import CheckKind, SecurityCheckPattern
from flawed.core import AnalysisGap, GapKind

_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="")


def test_security_check_condition_carries_provider_id() -> None:
    """Rule API checks retain the provider that declared the check."""
    record = _function("app.handler")
    function = convert_function(record)
    match = _check_match(
        _call("app.handler", "flask_login.login_required"),
        provider_id="flask-login",
        category="AUTHENTICATION",
    )

    result = convert_check_matches((match,), {function.fqn: function})

    assert result.gaps == ()
    condition = result.conditions_by_function["app.handler"][0]
    assert condition.category == "AUTHENTICATION"
    assert condition.provider_id == "flask-login"


def test_security_check_with_missing_caller_produces_gap() -> None:
    """Unattached provider checks are gaps, not silent false negatives."""
    match = _check_match(_call("app.missing", "flask_login.login_required"))

    result = convert_check_matches((match,), {})

    assert result.conditions_by_function == {}
    assert len(result.gaps) == 1
    assert result.gaps[0].kind is GapKind.INFERENCE_FAILURE
    assert result.gaps[0].affected_function == "app.missing"


def test_security_check_conversion_propagates_predicate_gaps() -> None:
    """Provider predicate uncertainty remains visible after check conversion."""
    record = _function("app.handler")
    function = convert_function(record)
    predicate_gap = AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message="Type-based provider predicate requires type enrichment",
        affected_file="app.py",
        affected_function="app.handler",
        source_error="provider predicate",
    )
    match = _check_match(
        _call("app.handler", "flask_login.login_required"),
        predicate_gaps=(predicate_gap,),
    )

    result = convert_check_matches((match,), {function.fqn: function})

    assert result.conditions_by_function["app.handler"]
    assert result.gaps == (predicate_gap,)


def test_class_target_decorator_check_applies_to_methods() -> None:
    """Class-target decorator facts are converted onto all class methods."""
    get_record = _function("app.AdminView.get", parent_class="app.AdminView")
    post_record = _function("app.AdminView.post", parent_class="app.AdminView")
    helper_record = _function("app.helper")
    functions = {
        record.fqn: convert_function(record) for record in (get_record, post_record, helper_record)
    }
    match = _decorator_check_match(
        _decorator("flask_login.login_required", target_fqn="app.AdminView"),
    )

    result = convert_check_matches((match,), functions)

    assert result.gaps == ()
    assert set(result.conditions_by_function) == {
        "app.AdminView.get",
        "app.AdminView.post",
    }
    assert "app.helper" not in result.conditions_by_function


def _check_match(
    edge: CallEdge,
    *,
    provider_id: str = "test",
    category: str = "AUTHENTICATION",
    predicate_gaps: tuple[AnalysisGap, ...] = (),
) -> ProviderMatch:
    return ProviderMatch(
        provider_id=provider_id,
        phase=ProviderPhase.CHECKS,
        descriptor=SecurityCheckPattern(
            fqn=edge.callee_fqn or "",
            kind=CheckKind.CALL,
            category=category,
        ),
        source_fact=edge,
        observed_fqn=edge.callee_fqn or "",
        canonical_fqn=edge.callee_fqn or "",
        location=edge.location,
        predicate_gaps=predicate_gaps,
    )


def _decorator_check_match(
    fact: DecoratorFact,
    *,
    provider_id: str = "test",
    category: str = "AUTHENTICATION",
) -> ProviderMatch:
    return ProviderMatch(
        provider_id=provider_id,
        phase=ProviderPhase.CHECKS,
        descriptor=SecurityCheckPattern(
            fqn=fact.fqn or fact.name,
            kind=CheckKind.DECORATOR,
            category=category,
        ),
        source_fact=fact,
        observed_fqn=fact.fqn or fact.name,
        canonical_fqn=fact.fqn or fact.name,
        location=fact.location,
        predicate_gaps=(),
    )


def _call(caller_fqn: str, callee_fqn: str, *, line: int = 10) -> CallEdge:
    return CallEdge(
        caller_fqn=caller_fqn,
        callee_fqn=callee_fqn,
        arguments=(),
        resolution=ResolutionStatus.RESOLVED,
        source=EdgeSource.AST,
        unresolved_reason=None,
        location=_span(line),
        provenance=_PROV,
        call_expression=f"{callee_fqn}()",
    )


def _decorator(fqn: str, *, target_fqn: str = "app.handler") -> DecoratorFact:
    return DecoratorFact(
        name=fqn.rsplit(".", maxsplit=1)[-1],
        fqn=fqn,
        args=(),
        kwargs=(),
        target_fqn=target_fqn,
        application_order=0,
        location=_span(10),
        provenance=_PROV,
    )


def _function(
    fqn: str,
    *,
    line: int = 1,
    parent_class: str | None = None,
) -> FunctionRecord:
    name = fqn.rsplit(".", maxsplit=1)[-1]
    return FunctionRecord(
        fqn=fqn,
        name=name,
        file="app.py",
        line=line,
        params=(),
        decorator_names=(),
        decorator_fqns=(),
        kind=L1FunctionKind.METHOD if parent_class is not None else L1FunctionKind.TOP_LEVEL,
        is_method=parent_class is not None,
        is_nested=False,
        is_async=False,
        parent_class=parent_class,
        location=_span(line),
        provenance=_PROV,
        parent_function=None,
    )


def _span(line: int, column: int = 0) -> SourceSpan:
    return SourceSpan(
        file="app.py",
        line=line,
        column=column,
        end_line=line,
        end_column=column + 1,
    )
