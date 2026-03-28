"""Tests for provider-driven taint sink conversion."""

from __future__ import annotations

from flawed._semantic._provider_engine import ProviderMatch, ProviderPhase
from flawed._semantic._sink_conversion import convert_sink_match
from flawed._semantic.providers import TaintSinkPattern
from flawed._semantic.providers.flask_core import FlaskProvider
from flawed.core import GapKind
from tests.factories import (
    make_attribute,
    make_call_arg,
    make_call_edge,
    make_enriched_function,
    make_kwarg,
    make_provider_match,
    make_span,
)

_ARG0 = make_span(line=10, column=16, end_column=23)


def _sink_match(pattern: TaintSinkPattern, edge) -> ProviderMatch:
    return make_provider_match(
        pattern,
        edge,
        provider_id="generic",
        phase=ProviderPhase.SINKS,
        canonical_fqn="generic.execute",
    )


def test_taint_sink_match_converts_sink_argument_observation() -> None:
    pattern = TaintSinkPattern(
        fqn="generic.execute",
        arg=0,
        sink_kind="SQL_INJECTION",
        description="raw SQL execution",
    )
    match = _sink_match(
        pattern, make_call_edge("generic.execute", make_call_arg(0, "query", _ARG0))
    )

    result = convert_sink_match(match, {"app.handler": make_enriched_function("app.handler")})

    assert result.gaps == ()
    assert len(result.sinks) == 1
    sink = result.sinks[0]
    assert sink.kind == "SQL_INJECTION"
    assert sink.function.fqn == "app.handler"
    assert sink.expression == "generic.execute(query)"
    assert sink.argument_expression == "query"
    assert sink.argument_location.line == 10
    assert sink.description == "raw SQL execution"


def test_taint_sink_match_selects_keyword_argument() -> None:
    pattern = TaintSinkPattern(
        fqn="mail.Message",
        arg=0,
        keyword="subject",
        sink_kind="EMAIL_HEADER_INJECTION",
    )
    match = _sink_match(
        pattern,
        make_call_edge("mail.Message", make_kwarg("subject", "subject", _ARG0)),
    )

    result = convert_sink_match(match, {"app.handler": make_enriched_function("app.handler")})

    assert result.gaps == ()
    assert len(result.sinks) == 1
    assert result.sinks[0].argument_expression == "subject"


def test_taint_sink_match_keyword_falls_back_to_positional_argument() -> None:
    pattern = TaintSinkPattern(
        fqn="flask.helpers.redirect",
        arg=0,
        keyword="location",
        sink_kind="OPEN_REDIRECT",
    )
    match = _sink_match(
        pattern, make_call_edge("flask.helpers.redirect", make_call_arg(0, "target", _ARG0))
    )

    result = convert_sink_match(match, {"app.handler": make_enriched_function("app.handler")})

    assert result.gaps == ()
    assert len(result.sinks) == 1
    assert result.sinks[0].argument_expression == "target"


def test_flask_redirect_keyword_location_attaches_to_caller_sink() -> None:
    pattern = next(
        descriptor
        for descriptor in FlaskProvider.sinks
        if "flask.helpers.redirect" in descriptor.fqn
    )
    match = _sink_match(
        pattern,
        make_call_edge("flask.helpers.redirect", make_kwarg("location", "target", _ARG0)),
    )

    result = convert_sink_match(match, {"app.handler": make_enriched_function("app.handler")})

    assert result.gaps == ()
    assert len(result.sinks) == 1
    assert result.sinks[0].kind == "OPEN_REDIRECT"
    assert result.sinks[0].function.fqn == "app.handler"
    assert result.sinks[0].argument_expression == "target"


def test_missing_sink_argument_records_analysis_gap() -> None:
    pattern = TaintSinkPattern(fqn="generic.execute", arg=1, sink_kind="SQL_INJECTION")
    match = _sink_match(
        pattern, make_call_edge("generic.execute", make_call_arg(0, "query", _ARG0))
    )

    result = convert_sink_match(match, {"app.handler": make_enriched_function("app.handler")})

    assert result.sinks == ()
    assert len(result.gaps) == 1
    gap = result.gaps[0]
    assert gap.kind == GapKind.INTERPRETER_ERROR
    assert gap.affected_file == "app.py"
    assert gap.affected_function == "app.handler"
    assert "sink argument 1 is missing" in gap.message


def test_missing_converted_caller_records_analysis_gap() -> None:
    pattern = TaintSinkPattern(fqn="generic.execute", arg=0, sink_kind="SQL_INJECTION")
    match = _sink_match(
        pattern, make_call_edge("generic.execute", make_call_arg(0, "query", _ARG0))
    )

    result = convert_sink_match(match, {})

    assert result.sinks == ()
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == GapKind.INTERPRETER_ERROR
    assert result.gaps[0].affected_function == "app.handler"
    assert "no converted caller" in result.gaps[0].message


def test_non_call_sink_match_records_analysis_gap() -> None:
    pattern = TaintSinkPattern(fqn="generic.execute", arg=0, sink_kind="SQL_INJECTION")
    attr = make_attribute("generic", "execute")
    match = ProviderMatch(
        provider_id="generic",
        phase=ProviderPhase.SINKS,
        descriptor=pattern,
        source_fact=attr,
        observed_fqn="generic.execute",
        canonical_fqn="generic.execute",
        location=attr.location,
    )

    result = convert_sink_match(match, {"app.handler": make_enriched_function("app.handler")})

    assert result.sinks == ()
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == GapKind.INTERPRETER_ERROR
    assert result.gaps[0].affected_function == "app.handler"
    assert "does not carry a call edge" in result.gaps[0].message
