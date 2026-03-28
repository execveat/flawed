"""Tests for provider-declared validated value guards."""

from __future__ import annotations

from flawed._semantic import WebApp
from flawed._semantic._provider_engine import ProviderEngine, ProviderPhase
from flawed._semantic._validation_guard_conversion import convert_validation_guard_matches
from flawed._semantic.providers import (
    Provider,
    ProviderMeta,
    RouteDecorator,
    ValidatedValueGuardPattern,
)
from flawed._semantic.providers.flask_core import FlaskProvider
from flawed.core import GapKind
from tests.factories import (
    make_call_arg,
    make_call_edge,
    make_decorator,
    make_enriched_function,
    make_function_record,
    make_import,
    make_index,
    make_provider_match,
    make_span,
)

_ARG0 = make_span(line=10, column=19, end_column=25)


class GenericValidationProvider(Provider):
    meta = ProviderMeta(
        id="generic-validation",
        name="Generic Validation",
        version="0.1.0",
        library="Generic",
        library_fqn="generic_validation",
    )

    validation_guards = (
        ValidatedValueGuardPattern(
            names=("accepts_target",),
            arg=0,
            safe_for_sink_kinds=("GENERIC_SINK",),
            category="GENERIC_VALIDATION",
            description="Generic guard validates argument 0",
        ),
    )


class RoutedValidationProvider(Provider):
    meta = ProviderMeta(
        id="routed-validation",
        name="Routed Validation",
        version="0.1.0",
        library="Routed Validation",
        library_fqn="routed_validation",
    )

    routes = (RouteDecorator(fqn="routed_validation.App.route"),)
    validation_guards = (
        ValidatedValueGuardPattern(
            fqn="routed_validation.accepts_target",
            arg=0,
            safe_for_sink_kinds=("GENERIC_SINK",),
            category="GENERIC_VALIDATION",
        ),
    )


def test_provider_engine_matches_validation_guard_by_simple_name() -> None:
    idx = make_index(
        imports=(make_import("generic_validation", is_from_import=False),),
        call_edges=(
            make_call_edge(
                "project.validators.accepts_target",
                make_call_arg(0, "target", _ARG0),
                call_expression="accepts_target",
            ),
        ),
    )

    engine_result = ProviderEngine(providers=(GenericValidationProvider,)).run(idx)
    result = convert_validation_guard_matches(
        engine_result.matches,
        {"app.handler": make_enriched_function("app.handler")},
    )

    assert engine_result.active_provider_ids == ("generic-validation",)
    assert len(result.validated_values_by_function["app.handler"]) == 1
    value = result.validated_values_by_function["app.handler"][0]
    assert value.expression == "accepts_target(target)"
    assert value.validated_expression == "target"
    assert value.safe_for_sink_kinds == ("GENERIC_SINK",)
    assert value.validated_when is True
    assert len(result.conditions_by_function["app.handler"]) == 1
    assert result.conditions_by_function["app.handler"][0].category == "GENERIC_VALIDATION"
    assert result.gaps == ()


def test_flask_provider_declares_project_local_url_validation_names() -> None:
    idx = make_index(
        imports=(make_import("flask", is_from_import=False),),
        call_edges=(
            make_call_edge(
                "myapp.security.is_safe_url",
                make_call_arg(0, "next_url", _ARG0),
                call_expression="is_safe_url",
            ),
        ),
    )

    engine_result = ProviderEngine(providers=(FlaskProvider,)).run(idx)
    result = convert_validation_guard_matches(
        engine_result.matches,
        {"app.handler": make_enriched_function("app.handler")},
    )

    value = result.validated_values_by_function["app.handler"][0]
    assert value.validated_expression == "next_url"
    assert value.safe_for_sink_kinds == ("OPEN_REDIRECT",)
    assert result.conditions_by_function["app.handler"][0].category == "URL_VALIDATION"


def test_missing_validated_argument_records_gap() -> None:
    pattern = ValidatedValueGuardPattern(fqn="generic_validation.accepts_target", arg=0)
    edge = make_call_edge("generic_validation.accepts_target", call_expression="accepts_target")
    match = make_provider_match(
        pattern,
        edge,
        provider_id="generic-validation",
        phase=ProviderPhase.VALIDATION_GUARDS,
    )

    result = convert_validation_guard_matches(
        (match,), {"app.handler": make_enriched_function("app.handler")}
    )

    assert result.validated_values_by_function == {}
    assert result.conditions_by_function == {}
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == GapKind.INTERPRETER_ERROR
    assert "validated argument 0 is missing" in result.gaps[0].message


def test_validation_guard_gap_reaches_route_scopes_and_findings() -> None:
    idx = make_index(
        functions=(make_function_record("app.handler"),),
        decorators=(
            make_decorator(
                "routed_validation.App.route",
                '"/guarded"',
                target_fqn="app.handler",
            ),
        ),
        imports=(make_import("routed_validation", is_from_import=False),),
        call_edges=(
            make_call_edge(
                "routed_validation.accepts_target",
                caller_fqn="app.handler",
                call_expression="accepts_target()",
            ),
        ),
    )

    repo = WebApp.from_index(
        idx,
        provider_engine=ProviderEngine(providers=(RoutedValidationProvider,)),
    ).repo_view()

    route = repo.routes.one()
    gap = next(gap for gap in repo.gaps if "validated argument 0 is missing" in gap.message)

    assert gap in route.body.gaps
    assert gap in route.full_stack.gaps
    assert gap in route.gaps
    assert gap in route.finding("guard gap propagated").gaps
