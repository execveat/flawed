"""End-to-end L1 extraction gap propagation into L3 scopes."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest

import flawed._index._pipeline as pipeline
from flawed._index._type_enrichment import TypeEnrichmentIndex
from flawed._semantic import WebApp
from flawed._semantic._provider_engine import ProviderEngine
from flawed._semantic.providers import (
    EffectCallPattern,
    Provider,
    ProviderMeta,
    RouteDecorator,
    arg,
)
from flawed.core import GapKind
from tests.factories import (
    make_call_arg,
    make_call_edge,
    make_decorator,
    make_function_record,
    make_import,
    make_index,
    make_param,
)

if TYPE_CHECKING:
    from pathlib import Path

    from flawed.core import AnalysisGap
    from flawed.repo import RepoView

pytestmark = pytest.mark.slow


def _empty_type_enrichment(*_args: object, **_kwargs: object) -> TypeEnrichmentIndex:
    return TypeEnrichmentIndex.empty()


class PredicateGapProvider(Provider):
    meta = ProviderMeta(
        id="predicate-gap",
        name="Predicate Gap",
        version="0.1.0",
        library="Predicate Gap",
        library_fqn="predicate_gap",
    )

    routes = (RouteDecorator(fqn="predicate_gap.App.route"),)
    effects = (
        EffectCallPattern(
            fqn="predicate_gap.emit",
            category="DB_WRITE",
            when=arg(0).type_is("predicate_gap.Payload"),
        ),
    )


def _rule_observed_scope_gaps(repo: RepoView) -> tuple[AnalysisGap, ...]:
    route = repo.routes.one()
    return route.body.gaps


def test_predicate_evaluation_gap_reaches_rule_api_code_scope() -> None:
    idx = make_index(
        functions=(
            make_function_record(
                "app.handler",
                params=(make_param("payload"),),
            ),
        ),
        decorators=(
            make_decorator(
                "predicate_gap.App.route",
                '"/items/<payload>"',
                target_fqn="app.handler",
            ),
        ),
        imports=(make_import("predicate_gap", is_from_import=False),),
        call_edges=(
            make_call_edge(
                "predicate_gap.emit",
                make_call_arg(0, "payload"),
                caller_fqn="app.handler",
                call_expression="emit(payload)",
            ),
        ),
    )

    repo = WebApp.from_index(
        idx,
        provider_engine=ProviderEngine(providers=(PredicateGapProvider,)),
    ).repo_view()

    route = repo.routes.one()
    effect = route.body.effects().one()
    gap = next(gap for gap in repo.gaps if gap.source_error == "no type enrichment for: payload")

    assert effect.expression == "emit(payload)"
    assert gap.kind is GapKind.INFERENCE_FAILURE
    assert gap.message == "No type fact for argument 'payload'"
    assert gap.affected_function == "app.handler"
    assert gap in _rule_observed_scope_gaps(cast("RepoView", repo))


def test_l1_gap_from_reachable_callee_reaches_l3_scopes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.py").write_text(
        """\
from flask import Flask
from helpers import helper

app = Flask(__name__)


@app.route("/")
def index():
    helper()
    return "ok"
""",
        encoding="utf-8",
    )
    (repo / "helpers.py").write_text(
        """\
def helper():
    try:
        risky()
    except* ValueError:
        handle()
    return "ok"
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(pipeline, "build_type_enrichment_index", _empty_type_enrichment)

    idx = pipeline.build_index(
        repo,
    )
    repo_view = WebApp.from_index(idx).repo_view()

    route = repo_view.routes.one()
    handler = repo_view.functions.named("index").one()
    helper_gap = next(
        gap for gap in route.body.gaps if gap.message == "Deferred construct: except*"
    )

    assert helper_gap.kind is GapKind.CFG_UNAVAILABLE
    assert helper_gap.affected_file == "helpers.py"
    assert helper_gap in route.full_stack.gaps
    assert helper_gap in route.gaps
    assert helper_gap in handler.reachable.gaps
