"""Tests for provider-declared safe generated URL conversion."""

from __future__ import annotations

from typing import ClassVar

from flawed._semantic._provider_engine import ProviderEngine, ProviderPhase
from flawed._semantic._safe_generated_url_conversion import convert_safe_generated_url_matches
from flawed._semantic.providers import Provider, ProviderMeta, SafeGeneratedURLPattern
from flawed._semantic.providers.flask_core import FlaskProvider
from flawed.core import GapKind, Location
from tests.factories import (
    make_call_arg,
    make_enriched_function,
    make_import,
    make_index,
    make_kwarg,
    make_provider_match,
    make_span,
)

_ARG0 = make_span(line=10, column=16, end_column=23)
_ARG1 = make_span(line=10, column=25, end_column=42)


class GenericSafeURLProvider(Provider):
    meta = ProviderMeta(
        id="generic",
        name="Generic",
        version="0.1.0",
        library="Generic",
        library_fqn="generic",
    )

    fqn_aliases: ClassVar[dict[str, str]] = {
        "generic.public_url_for": "generic.url_for",
    }
    safe_generated_urls = (SafeGeneratedURLPattern(fqn="generic.url_for"),)


def _call(*args, fqn: str, call_expression: str):
    from tests.factories import make_call_edge

    return make_call_edge(fqn, *args, call_expression=call_expression)


def test_provider_engine_matches_safe_generated_url_descriptor() -> None:
    idx = make_index(
        imports=(make_import("generic", is_from_import=False),),
        call_edges=(
            _call(
                make_call_arg(0, '"dashboard"', _ARG0),
                fqn="generic.public_url_for",
                call_expression='url_for("dashboard")',
            ),
        ),
    )

    engine_result = ProviderEngine(providers=(GenericSafeURLProvider,)).run(idx)
    result = convert_safe_generated_url_matches(
        engine_result.matches,
        {"app.handler": make_enriched_function("app.handler")},
    )

    assert engine_result.active_provider_ids == ("generic",)
    assert len(result.safe_generated_urls) == 1
    assert result.safe_generated_urls[0].expression == 'url_for("dashboard")'
    assert result.safe_generated_urls[0].safe_for_sink_kinds == ("OPEN_REDIRECT",)
    assert result.gaps == ()


def test_flask_url_for_converts_to_open_redirect_safe_generated_url() -> None:
    idx = make_index(
        imports=(make_import("flask", is_from_import=False),),
        call_edges=(
            _call(
                make_call_arg(0, '"dashboard"', _ARG0),
                fqn="flask.url_for",
                call_expression='url_for("dashboard")',
            ),
        ),
    )

    engine_result = ProviderEngine(providers=(FlaskProvider,)).run(idx)
    result = convert_safe_generated_url_matches(
        engine_result.matches,
        {"app.handler": make_enriched_function("app.handler")},
    )

    assert result.gaps == ()
    assert len(result.safe_generated_urls) == 1
    safe_url = result.safe_generated_urls[0]
    assert safe_url.function.fqn == "app.handler"
    assert safe_url.location == Location(
        file="app.py",
        line=21,
        column=0,
        end_line=21,
        end_column=10,
    )
    assert safe_url.expression == 'url_for("dashboard")'
    assert safe_url.safe_for_sink_kinds == ("OPEN_REDIRECT",)


def test_flask_url_for_external_true_is_not_classified_local_safe() -> None:
    idx = make_index(
        imports=(make_import("flask", is_from_import=False),),
        call_edges=(
            _call(
                make_call_arg(0, '"dashboard"', _ARG0),
                make_kwarg("_external", "True", _ARG1),
                fqn="flask.url_for",
                call_expression='url_for("dashboard", _external=True)',
            ),
        ),
    )

    engine_result = ProviderEngine(providers=(FlaskProvider,)).run(idx)
    result = convert_safe_generated_url_matches(
        engine_result.matches,
        {"app.handler": make_enriched_function("app.handler")},
    )

    assert result.safe_generated_urls == ()
    assert result.gaps == ()


def test_flask_url_for_dynamic_external_records_gap_instead_of_safe_fact() -> None:
    idx = make_index(
        imports=(make_import("flask", is_from_import=False),),
        call_edges=(
            _call(
                make_call_arg(0, '"dashboard"', _ARG0),
                make_kwarg("_external", "external", _ARG1),
                fqn="flask.url_for",
                call_expression='url_for("dashboard", _external=external)',
            ),
        ),
    )

    engine_result = ProviderEngine(providers=(FlaskProvider,)).run(idx)
    result = convert_safe_generated_url_matches(
        engine_result.matches,
        {"app.handler": make_enriched_function("app.handler")},
    )

    assert result.safe_generated_urls == ()
    assert len(result.gaps) == 1
    gap = result.gaps[0]
    assert gap.kind == GapKind.INFERENCE_FAILURE
    assert gap.affected_function == "app.handler"
    assert gap.origin_phase == "safe_generated_url_conversion"
    assert gap.origin_provider == "flask"
    assert "dynamic _external" in gap.message


def test_unsupported_output_records_conversion_gap() -> None:
    pattern = SafeGeneratedURLPattern(fqn="generic.url_for", output="argument")
    edge = _call(
        make_call_arg(0, '"dashboard"', _ARG0),
        fqn="generic.url_for",
        call_expression='url_for("dashboard")',
    )
    match = make_provider_match(
        pattern,
        edge,
        provider_id="generic",
        phase=ProviderPhase.SAFE_GENERATED_URLS,
        canonical_fqn="generic.url_for",
    )

    result = convert_safe_generated_url_matches(
        (match,),
        {"app.handler": make_enriched_function("app.handler")},
    )

    assert result.safe_generated_urls == ()
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == GapKind.INTERPRETER_ERROR
    assert "unsupported output" in result.gaps[0].message
