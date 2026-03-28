"""Tests for EnrichedRoute: reachable, full_stack, source(), and finding() via MRO."""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

from flawed._semantic._enriched import EnrichedRoute

if TYPE_CHECKING:
    from pathlib import Path
from flawed._semantic._scope import ConcreteCodeScope
from flawed.core import AnalysisGap, GapKind, Location, Provenance
from flawed.effects import Effect, EffectCategory
from flawed.evidence import Finding
from flawed.function import Function, FunctionKind
from flawed.inputs import AccessPattern, Cardinality, InputRead, Query
from flawed.route import HttpMethod


def _make_handler(
    fqn: str = "myapp.app.index",
    name: str = "index",
    file: str = "app.py",
    line: int = 10,
) -> Function:
    return Function(
        fqn=fqn,
        name=name,
        params=(),
        kind=FunctionKind.TOP_LEVEL,
        parent_class=None,
        parent_function=None,
        location=Location(file=file, line=line, column=0),
        provenance=Provenance(source_layer="L2", interpreter="test", confidence=1.0),
    )


def _make_enriched_route(
    *,
    handler: Function | None = None,
    endpoint: str = "index",
    url_rule: str = "/",
    file: str = "app.py",
    line: int = 10,
) -> EnrichedRoute:
    h = handler or _make_handler(file=file, line=line)
    return EnrichedRoute(
        endpoint=endpoint,
        url_rule=url_rule,
        methods=frozenset({HttpMethod.GET}),
        handler=h,
        group=None,
        location=Location(file=file, line=line, column=0),
        provenance=Provenance(source_layer="L2", interpreter="test", confidence=1.0),
    )


def _make_input_read(handler: Function) -> InputRead:
    return InputRead(
        source=Query(),
        access_pattern=AccessPattern.GET,
        cardinality=Cardinality.SINGLE,
        function=handler,
        location=handler.location,
        expression='request.args.get("id")',
        provenance=Provenance(source_layer="L2", interpreter="test", confidence=1.0),
    )


def _make_effect(handler: Function) -> Effect:
    return Effect(
        category=EffectCategory.STATE_WRITE,
        function=handler,
        location=handler.location,
        expression='session["user"] = value',
        provenance=Provenance(source_layer="L2", interpreter="test", confidence=1.0),
    )


class TestReachableProperty:
    """EnrichedRoute.reachable returns the reachable scope."""

    def test_reachable_returns_concrete_scope(self) -> None:
        route = _make_enriched_route()
        scope = ConcreteCodeScope()
        object.__setattr__(route, "_body_scope", scope)
        object.__setattr__(route, "_reachable_scope", scope)
        object.__setattr__(route, "_full_stack_scope", scope)
        object.__setattr__(route, "_gaps", ())
        object.__setattr__(route, "_repo_path", "/tmp")

        result = route.reachable

        assert isinstance(result, ConcreteCodeScope)
        assert result is scope

    def test_reachable_reads_and_effects_callable(self) -> None:
        handler = _make_handler()
        route = _make_enriched_route(handler=handler)
        read = _make_input_read(handler)
        effect = _make_effect(handler)
        scope = ConcreteCodeScope(
            input_reads=(read,),
            effects=(effect,),
        )
        object.__setattr__(route, "_body_scope", scope)
        object.__setattr__(route, "_reachable_scope", scope)
        object.__setattr__(route, "_full_stack_scope", scope)
        object.__setattr__(route, "_gaps", ())
        object.__setattr__(route, "_repo_path", "/tmp")

        reads = route.reachable.reads(Query())
        assert len(tuple(reads)) == 1

        from flawed.effects import State

        effects = route.reachable.effects(State.write())
        assert len(tuple(effects)) == 1


class TestFullStackProperty:
    """EnrichedRoute.full_stack returns reachable scope plus lifecycle gap."""

    def test_full_stack_returns_concrete_scope(self) -> None:
        route = _make_enriched_route()
        scope = ConcreteCodeScope()
        lifecycle_gap = AnalysisGap(
            kind=GapKind.INFERENCE_FAILURE,
            message="Lifecycle hooks not yet analyzed for this route",
        )
        full_stack = ConcreteCodeScope(gaps=(lifecycle_gap,))
        object.__setattr__(route, "_body_scope", scope)
        object.__setattr__(route, "_reachable_scope", scope)
        object.__setattr__(route, "_full_stack_scope", full_stack)
        object.__setattr__(route, "_gaps", ())
        object.__setattr__(route, "_repo_path", "/tmp")

        result = route.full_stack

        assert isinstance(result, ConcreteCodeScope)

    def test_full_stack_includes_lifecycle_gap(self) -> None:
        route = _make_enriched_route()
        scope = ConcreteCodeScope()
        lifecycle_gap = AnalysisGap(
            kind=GapKind.INFERENCE_FAILURE,
            message="Lifecycle hooks not yet analyzed for this route",
        )
        full_stack = ConcreteCodeScope(gaps=(lifecycle_gap,))
        object.__setattr__(route, "_body_scope", scope)
        object.__setattr__(route, "_reachable_scope", scope)
        object.__setattr__(route, "_full_stack_scope", full_stack)
        object.__setattr__(route, "_gaps", ())
        object.__setattr__(route, "_repo_path", "/tmp")

        result = route.full_stack
        assert len(result.gaps) >= 1
        lifecycle_gaps = [
            g
            for g in result.gaps
            if g.kind is GapKind.INFERENCE_FAILURE and "lifecycle" in g.message.lower()
        ]
        assert len(lifecycle_gaps) == 1


class TestSourceMethod:
    """EnrichedRoute.source() reads handler text from the filesystem."""

    def test_source_reads_handler_text(self, tmp_path: Path) -> None:
        source_code = textwrap.dedent("""\
            from flask import Flask
            app = Flask(__name__)

            @app.route('/')
            def index():
                return 'Hello'

            @app.route('/other')
            def other():
                return 'Other'
        """)
        app_file = tmp_path / "app.py"
        app_file.write_text(source_code)

        handler = _make_handler(file="app.py", line=5)
        route = _make_enriched_route(handler=handler, file="app.py", line=5)
        scope = ConcreteCodeScope()
        object.__setattr__(route, "_body_scope", scope)
        object.__setattr__(route, "_reachable_scope", scope)
        object.__setattr__(route, "_full_stack_scope", scope)
        object.__setattr__(route, "_gaps", ())
        object.__setattr__(route, "_repo_path", str(tmp_path))

        result = route.source()

        assert "def index():" in result
        assert "return 'Hello'" in result

    def test_source_with_context_zero(self, tmp_path: Path) -> None:
        lines = ["line1", "line2", "line3", "line4", "line5"]
        app_file = tmp_path / "app.py"
        app_file.write_text("\n".join(lines))

        handler = _make_handler(file="app.py", line=3)
        route = _make_enriched_route(handler=handler, file="app.py", line=3)
        scope = ConcreteCodeScope()
        object.__setattr__(route, "_body_scope", scope)
        object.__setattr__(route, "_reachable_scope", scope)
        object.__setattr__(route, "_full_stack_scope", scope)
        object.__setattr__(route, "_gaps", ())
        object.__setattr__(route, "_repo_path", str(tmp_path))

        result = route.source(context=0)
        assert result == "line3"

    def test_source_with_missing_file_returns_placeholder(self) -> None:
        route = _make_enriched_route(file="nonexistent.py", line=5)
        scope = ConcreteCodeScope()
        object.__setattr__(route, "_body_scope", scope)
        object.__setattr__(route, "_reachable_scope", scope)
        object.__setattr__(route, "_full_stack_scope", scope)
        object.__setattr__(route, "_gaps", ())
        object.__setattr__(route, "_repo_path", "/nonexistent/path")

        result = route.source()

        assert "source unavailable" in result
        assert "nonexistent.py" in result


class TestFindingViaMRO:
    """Route.finding() works on EnrichedRoute via MRO delegation to self.gaps."""

    def test_finding_produces_valid_finding(self) -> None:
        route = _make_enriched_route(endpoint="api.create_user")
        gap = AnalysisGap(
            kind=GapKind.CALL_GRAPH_INCOMPLETE,
            message="Call graph may be incomplete",
        )
        scope = ConcreteCodeScope()
        object.__setattr__(route, "_body_scope", scope)
        object.__setattr__(route, "_reachable_scope", scope)
        object.__setattr__(route, "_full_stack_scope", scope)
        object.__setattr__(route, "_gaps", (gap,))
        object.__setattr__(route, "_repo_path", "/tmp")

        finding = route.finding("Missing auth guard")

        assert isinstance(finding, Finding)
        assert finding.route_endpoint == "api.create_user"
        assert finding.summary == "Missing auth guard"
        assert finding.location == route.location
        assert gap in finding.gaps

    def test_finding_with_no_gaps(self) -> None:
        route = _make_enriched_route(endpoint="public.home")
        scope = ConcreteCodeScope()
        object.__setattr__(route, "_body_scope", scope)
        object.__setattr__(route, "_reachable_scope", scope)
        object.__setattr__(route, "_full_stack_scope", scope)
        object.__setattr__(route, "_gaps", ())
        object.__setattr__(route, "_repo_path", "/tmp")

        finding = route.finding("Info disclosure")

        assert isinstance(finding, Finding)
        assert finding.gaps == ()

    def test_finding_evidence_accepts_input_read_subject(self) -> None:
        handler = _make_handler()
        route = _make_enriched_route(handler=handler)
        read = _make_input_read(handler)
        scope = ConcreteCodeScope(input_reads=(read,))
        object.__setattr__(route, "_body_scope", scope)
        object.__setattr__(route, "_reachable_scope", scope)
        object.__setattr__(route, "_full_stack_scope", scope)
        object.__setattr__(route, "_gaps", ())
        object.__setattr__(route, "_repo_path", "/tmp")

        finding = route.finding("Unguarded query read").evidence(
            read,
            "Query parameter controls branch",
        )

        assert len(finding.evidence_items) == 1
        assert finding.evidence_items[0].fact is read
        assert finding.evidence_items[0].location == read.location

    def test_finding_evidence_accepts_effect_subject(self) -> None:
        handler = _make_handler()
        route = _make_enriched_route(handler=handler)
        effect = _make_effect(handler)
        scope = ConcreteCodeScope(effects=(effect,))
        object.__setattr__(route, "_body_scope", scope)
        object.__setattr__(route, "_reachable_scope", scope)
        object.__setattr__(route, "_full_stack_scope", scope)
        object.__setattr__(route, "_gaps", ())
        object.__setattr__(route, "_repo_path", "/tmp")

        finding = route.finding("Session write").evidence(
            effect,
            "Handler mutates session state",
        )

        assert len(finding.evidence_items) == 1
        assert finding.evidence_items[0].fact is effect
        assert finding.evidence_items[0].location == effect.location

    def test_finding_chain_keeps_route_gaps_with_input_and_effect_evidence(self) -> None:
        handler = _make_handler()
        route = _make_enriched_route(handler=handler)
        read = _make_input_read(handler)
        effect = _make_effect(handler)
        gap = AnalysisGap(
            kind=GapKind.CALL_GRAPH_INCOMPLETE,
            message="Reachable scope may miss indirect callees",
        )
        scope = ConcreteCodeScope(input_reads=(read,), effects=(effect,))
        object.__setattr__(route, "_body_scope", scope)
        object.__setattr__(route, "_reachable_scope", scope)
        object.__setattr__(route, "_full_stack_scope", scope)
        object.__setattr__(route, "_gaps", (gap,))
        object.__setattr__(route, "_repo_path", "/tmp")

        base_finding = route.finding("Input reaches state write")
        finding = base_finding.evidence(
            read,
            "Reads attacker-controlled query parameter",
        ).evidence(
            effect,
            "Writes request-derived value to state",
        )

        assert base_finding.evidence_items == ()
        assert finding.gaps == (gap,)
        assert [item.fact for item in finding.evidence_items] == [read, effect]
