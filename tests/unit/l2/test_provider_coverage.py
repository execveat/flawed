from __future__ import annotations

from click.testing import CliRunner

import flawed._cli.app as cli_app
import flawed._semantic._provider_engine as provider_engine
from flawed._cli.app import cli
from flawed._cli.provider_coverage import (
    build_provider_coverage_report,
    format_provider_coverage_report,
)
from flawed._semantic._provider_engine import ProviderEngineResult, ProviderPhase
from flawed._semantic.providers import InputMethodPattern, Provider, ProviderMeta, RouteDecorator
from flawed.core import AnalysisGap, GapKind
from tests.factories import make_decorator, make_import, make_index, make_provider_match


class ExampleProvider(Provider):
    meta = ProviderMeta(
        id="example",
        name="Example",
        library="example-lib",
        library_fqn="examplelib",
    )
    routes = (
        RouteDecorator(fqn="examplelib.App.route"),
        RouteDecorator(fqn="examplelib.App.post"),
    )
    inputs = (InputMethodPattern(fqn="examplelib.request.get", source_type="Query"),)


def test_provider_coverage_reports_activation_matches_unmatched_and_gaps() -> None:
    index = make_index(imports=(make_import("examplelib", is_from_import=False),))
    match = make_provider_match(
        ExampleProvider.routes[0],
        make_decorator("examplelib.App.route"),
        provider_id="example",
        phase=ProviderPhase.ROUTES,
        observed_fqn="examplelib.App.route",
    )
    gap = AnalysisGap(
        kind=GapKind.INTERPRETER_ERROR,
        message="predicate could not be evaluated",
        affected_file="app.py",
        origin_phase="routes",
        origin_provider="example",
    )
    result = ProviderEngineResult(
        active_provider_ids=("example",),
        matches=(match,),
        gaps=(gap,),
    )

    report = build_provider_coverage_report(
        index=index,
        result=result,
        provider_classes=(ExampleProvider,),
    )

    provider = report.providers[0]
    assert provider.active is True
    assert provider.activation_evidence == ("app.py:1 import examplelib",)
    assert provider.declared_count == 3
    assert provider.matched_declaration_count == 1
    assert provider.unmatched_count == 2
    assert provider.gaps == ("routes app.py: predicate could not be evaluated",)
    rendered = format_provider_coverage_report(report)
    assert "Activated providers: example" in rendered
    assert "RouteDecorator examplelib.App.post" in rendered
    assert "app.py:10 examplelib.App.route" in rendered


def test_providers_coverage_cli_uses_provider_engine_result(monkeypatch, tmp_path) -> None:
    index = make_index(imports=(make_import("examplelib", is_from_import=False),), root=tmp_path)
    result = ProviderEngineResult(active_provider_ids=("example",), matches=(), gaps=())

    monkeypatch.setattr(cli_app, "run_index", lambda **kwargs: index)
    monkeypatch.setattr(cli_app, "run_provider_engine", lambda *args, **kwargs: result)
    monkeypatch.setattr(
        provider_engine,
        "discover_builtin_provider_classes",
        lambda: (ExampleProvider,),
    )

    cli_result = CliRunner().invoke(cli, ["providers", "coverage", str(tmp_path)])

    assert cli_result.exit_code == 0
    assert "Provider coverage dashboard" in cli_result.output
    assert "Activated providers: example" in cli_result.output
    assert "InputMethodPattern examplelib.request.get" in cli_result.output
