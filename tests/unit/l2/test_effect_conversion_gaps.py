"""No-fail-open coverage for provider effect conversion gaps."""

from __future__ import annotations

from typing import Any, ClassVar, cast

from flawed._semantic import WebApp
from flawed._semantic._conversion import convert_function
from flawed._semantic._effect_conversion import convert_effect_match
from flawed._semantic._provider_engine import ProviderEngine, ProviderPhase
from flawed._semantic.providers import (
    EffectCallPattern,
    Provider,
    ProviderMeta,
    RouteDecorator,
    StateProxyPattern,
)
from flawed.core import AnalysisGap, GapKind
from tests.factories import (
    make_call_edge,
    make_decorator,
    make_function_record,
    make_import,
    make_index,
    make_provider_match,
    make_symbol,
)


class _InvalidEffectProvider(Provider):
    meta = ProviderMeta(
        id="effect-gap",
        name="Effect Gap",
        version="0.1.0",
        library="effect_gap",
        library_fqn="effect_gap",
    )

    fqn_aliases: ClassVar[dict[str, str]] = {"effect_gap.local": "effect_gap"}
    routes = (RouteDecorator(fqn="effect_gap.App.route"),)
    effects = (
        EffectCallPattern(
            fqn="effect_gap.mutate",
            category="NOT_A_CATEGORY",
            scope="SESSION",
        ),
    )


def _effect_match(descriptor: Any) -> Any:
    edge = make_call_edge("effect_gap.mutate")
    return make_provider_match(
        descriptor,
        edge,
        provider_id="effect-gap",
        phase=ProviderPhase.EFFECTS,
        canonical_fqn="effect_gap.mutate",
    )


def _assert_gap(
    gaps: tuple[AnalysisGap, ...],
    *,
    source_error: str,
    message: str,
) -> AnalysisGap:
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap.kind is GapKind.INTERPRETER_ERROR
    assert gap.affected_file == "app.py"
    assert gap.affected_function == "app.handler"
    assert gap.source_error == source_error
    assert gap.origin_phase == "effect_conversion"
    assert gap.origin_provider == "effect-gap"
    assert message in gap.message
    return gap


def test_unknown_effect_category_records_actionable_gap() -> None:
    result = convert_effect_match(
        _effect_match(
            EffectCallPattern(
                fqn="effect_gap.mutate",
                category="NOT_A_CATEGORY",
                scope="SESSION",
            )
        ),
        {"app.handler": convert_function(make_function_record("app.handler"))},
    )

    assert result.effects == ()
    _assert_gap(
        result.gaps,
        source_error="effect_conversion: unknown category",
        message="Unknown effect category: NOT_A_CATEGORY",
    )


def test_missing_state_effect_scope_records_actionable_gap() -> None:
    result = convert_effect_match(
        _effect_match(EffectCallPattern(fqn="effect_gap.mutate", category="STATE_WRITE")),
        {"app.handler": convert_function(make_function_record("app.handler"))},
    )

    assert result.effects == ()
    _assert_gap(
        result.gaps,
        source_error="effect_conversion: missing state scope",
        message="State effect descriptor is missing a scope",
    )


def test_unknown_state_effect_scope_records_actionable_gap() -> None:
    result = convert_effect_match(
        _effect_match(
            EffectCallPattern(
                fqn="effect_gap.mutate",
                category="STATE_READ",
                scope="THREAD",
            )
        ),
        {"app.handler": convert_function(make_function_record("app.handler"))},
    )

    assert result.effects == ()
    _assert_gap(
        result.gaps,
        source_error="effect_conversion: unknown state scope",
        message="Unknown state scope: THREAD",
    )


def test_unsupported_effect_descriptor_records_actionable_gap() -> None:
    class UnsupportedDescriptor:
        pass

    result = convert_effect_match(
        _effect_match(cast("Any", UnsupportedDescriptor())),
        {"app.handler": convert_function(make_function_record("app.handler"))},
    )

    assert result.effects == ()
    _assert_gap(
        result.gaps,
        source_error="effect_conversion: descriptor not yet implemented",
        message="Unsupported effect descriptor type: UnsupportedDescriptor",
    )


def test_missing_effect_function_records_actionable_gap() -> None:
    result = convert_effect_match(
        _effect_match(EffectCallPattern(fqn="effect_gap.mutate", category="DB_WRITE")),
        {},
    )

    assert result.effects == ()
    _assert_gap(
        result.gaps,
        source_error="effect_conversion: missing function",
        message="No converted Function found for app.handler",
    )


def test_state_proxy_symbol_match_is_resolution_hint_not_silent_precondition_miss() -> None:
    symbol = make_symbol("current_actor", "effect_gap.current_actor", line=21)
    result = convert_effect_match(
        make_provider_match(
            StateProxyPattern(
                fqn="effect_gap.current_actor",
                resolves_to="effect_gap.g.actor",
                scope="REQUEST",
            ),
            symbol,
            provider_id="effect-gap",
            phase=ProviderPhase.PROXIES,
            observed_fqn="effect_gap.current_actor",
            canonical_fqn="effect_gap.current_actor",
        ),
        {"app.handler": convert_function(make_function_record("app.handler"))},
    )

    assert result.effects == ()
    assert result.gaps == ()


def test_effect_conversion_gap_reaches_repo_route_and_function_scopes() -> None:
    idx = make_index(
        functions=(make_function_record("app.handler"),),
        decorators=(make_decorator("effect_gap.App.route", '"/effect"', name="route"),),
        imports=(make_import("effect_gap", names=("App", "mutate")),),
        call_edges=(make_call_edge("effect_gap.mutate"),),
    )
    repo = WebApp.from_index(
        idx,
        provider_engine=ProviderEngine(providers=(_InvalidEffectProvider,)),
    ).repo_view()

    route = repo.routes.one()
    handler = repo.functions.named("handler").one()
    gap = _assert_gap(
        repo.gaps,
        source_error="effect_conversion: unknown category",
        message="Unknown effect category: NOT_A_CATEGORY",
    )

    assert gap in route.body.gaps
    assert gap in route.full_stack.gaps
    assert gap in route.gaps
    assert gap in handler.reachable.gaps
    assert tuple(route.body.effects()) == ()
