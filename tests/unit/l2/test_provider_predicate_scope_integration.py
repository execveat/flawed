"""End-to-end provider predicate gap propagation into Rule API scopes."""

from __future__ import annotations

from flawed._semantic import WebApp
from flawed._semantic._provider_engine import ProviderEngine
from flawed._semantic.providers import (
    Provider,
    ProviderMeta,
    RouteDecorator,
    TaintSinkPattern,
    arg,
)
from tests.factories import (
    make_call_arg,
    make_call_edge,
    make_decorator,
    make_function_record,
    make_import,
    make_index,
    make_param,
)


class PredicateScopeProvider(Provider):
    meta = ProviderMeta(
        id="predicate-scope",
        name="Predicate Scope",
        version="0.1.0",
        library="Predicate Scope",
        library_fqn="predicate_scope",
    )

    routes = (RouteDecorator(fqn="predicate_scope.App.route"),)
    sinks = (
        TaintSinkPattern(
            fqn="predicate_scope.emit",
            arg=0,
            sink_kind="PREDICATE_SCOPE",
            when=arg(0).type_is("predicate_scope.DynamicPayload"),
        ),
    )


def _predicate_rule(repo):
    for route in repo.routes:
        for sink in route.body.sinks(kind="PREDICATE_SCOPE"):
            yield route.finding("predicate sink reached").evidence(
                sink,
                "provider-predicate sink consumed by rule",
            )


def test_provider_predicate_gap_reaches_scope_attachment_and_rule_findings() -> None:
    idx = make_index(
        functions=(
            make_function_record(
                "app.handler",
                params=(make_param("payload"),),
            ),
        ),
        decorators=(
            make_decorator(
                "predicate_scope.App.route",
                '"/items/<payload>"',
                target_fqn="app.handler",
            ),
        ),
        imports=(make_import("predicate_scope", is_from_import=False),),
        call_edges=(
            make_call_edge(
                "predicate_scope.emit",
                make_call_arg(0, "payload"),
                caller_fqn="app.handler",
                call_expression="emit(payload)",
            ),
        ),
    )

    repo = WebApp.from_index(
        idx,
        provider_engine=ProviderEngine(providers=(PredicateScopeProvider,)),
    ).repo_view()

    route = repo.routes.one()
    sink = route.body.sinks(kind="PREDICATE_SCOPE").one()
    gap = next(gap for gap in repo.gaps if gap.source_error == "no type enrichment for: payload")

    assert sink.argument_expression == "payload"
    assert gap in route.body.gaps
    assert gap in route.full_stack.gaps
    assert gap in route.gaps

    finding = next(iter(_predicate_rule(repo)))
    assert gap in finding.gaps
