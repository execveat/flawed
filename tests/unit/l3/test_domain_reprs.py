"""Concise ``__repr__`` for Layer 3 domain objects (FLAW-129 repr slice).

Domain objects embed heavy nested structures (a ``Route`` holds a ``Function``
holding ``Parameter`` tuples; an ``Effect`` holds a ``Function`` and
``Provenance`` with supporting facts).  The dataclass auto-generated repr
recurses through all of it, so echoing one object in a REPL dumped ~1 KB and a
collection tens of KB.  Each domain type now defines a one-line ``__repr__``
that leads with identity plus a couple of facts and never recurses into nested
domain objects.

These tests pin three properties for every domain repr:

1. **Concise** -- bounded length, single line.
2. **Identifying** -- the key facts (name, location, category) are present.
3. **Non-recursive** -- the repr does not embed a nested object's full dump
   (the property that made the old reprs explode).
"""

from __future__ import annotations

from flawed.core import (
    AnalysisGap,
    GapKind,
    Key,
    Location,
    Provenance,
    _short_expr,
    _short_loc,
)
from flawed.effects import Effect, EffectCategory, StateScope
from flawed.flow import FlowStep, FlowTrace, ValueHandle
from flawed.function import Decorator, Function, FunctionKind, Parameter
from flawed.inputs import AccessPattern, Cardinality, InputRead, Query
from flawed.route import HttpMethod, Route

_LOC = Location(file="app/auth.py", line=42, column=4)
_PROV = Provenance(
    source_layer="L2",
    interpreter="flask_routes",
    confidence=0.95,
    supporting_facts=("decorator @app.route found", "handler reads request.json"),
)


def _handler() -> Function:
    params = tuple(
        Parameter(name=f"p{i}", annotation=None, default=None, kind="positional_or_keyword")
        for i in range(4)
    )
    return Function(
        fqn="myapp.auth.login",
        name="login",
        params=params,
        kind=FunctionKind.TOP_LEVEL,
        parent_class=None,
        parent_function=None,
        location=_LOC,
        provenance=_PROV,
    )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def test_short_loc_renders_file_line() -> None:
    assert _short_loc(_LOC) == "app/auth.py:42"


def test_short_loc_none_is_explicit_marker() -> None:
    # No fail-open: an unknown location renders a marker, never a crash.
    assert _short_loc(None) == "?"


def test_short_expr_collapses_whitespace_and_truncates() -> None:
    multiline = "db.session.query(User)\n    .filter_by(id=user_id)\n    .first()"
    out = _short_expr(multiline, limit=20)
    assert "\n" not in out
    assert len(out) <= 20
    assert out.endswith("…")


def test_short_expr_keeps_short_input_intact() -> None:
    assert _short_expr("request.args") == "request.args"


# ---------------------------------------------------------------------------
# core types
# ---------------------------------------------------------------------------


def test_location_repr() -> None:
    assert repr(_LOC) == "Location(app/auth.py:42:4)"


def test_provenance_repr_omits_supporting_facts() -> None:
    text = repr(_PROV)
    assert text == "Provenance(L2/flask_routes, conf=0.95)"
    # The (potentially long) supporting-facts tuple must not be inlined.
    assert "decorator @app.route found" not in text


def test_analysis_gap_repr_uses_most_specific_locus() -> None:
    gap = AnalysisGap(
        kind=GapKind.CALL_GRAPH_INCOMPLETE,
        message="call graph edges may be missing",
        affected_file="app.py",
        affected_function="myapp.auth.login",
    )
    assert repr(gap) == "AnalysisGap(CALL_GRAPH_INCOMPLETE, myapp.auth.login)"
    assert repr(AnalysisGap(GapKind.PARSE_FAILURE, "x")) == "AnalysisGap(PARSE_FAILURE, global)"


# ---------------------------------------------------------------------------
# function types
# ---------------------------------------------------------------------------


def test_parameter_repr_renders_signature_fragment() -> None:
    assert (
        repr(Parameter("user_id", "int", "0", "positional_or_keyword"))
        == "Parameter(user_id: int = 0)"
    )
    assert repr(Parameter("data", None, None, "positional_or_keyword")) == "Parameter(data)"


def test_decorator_repr() -> None:
    dec = Decorator(
        name="app.route",
        fqn="flask.Flask.route",
        arguments=("/users", "methods=['POST']"),
        location=_LOC,
    )
    assert repr(dec) == "Decorator(@app.route(/users, methods=['POST']), app/auth.py:42)"


def test_function_repr_is_concise_and_non_recursive() -> None:
    fn = _handler()
    text = repr(fn)
    assert text == "Function(login(p0, p1, p2, p3), top_level, app/auth.py:42)"
    # Must not recurse into the full Parameter repr nor Provenance facts.
    assert "Parameter(" not in text
    assert "Provenance(" not in text


# ---------------------------------------------------------------------------
# route / effect / input / flow
# ---------------------------------------------------------------------------


def test_route_repr_leads_with_methods_path_handler() -> None:
    route = Route(
        endpoint="auth.login",
        url_rule="/login",
        methods=frozenset({HttpMethod.GET, HttpMethod.POST}),
        handler=_handler(),
        group="auth",
        location=_LOC,
        provenance=_PROV,
    )
    text = repr(route)
    # Methods are sorted for a stable repr regardless of frozenset ordering.
    assert text == "Route(GET|POST /login → login, app/auth.py:42)"
    assert "Function(" not in text  # handler is summarised by name, not embedded


def test_effect_repr_is_concise_vs_recursive_default() -> None:
    effect = Effect(
        category=EffectCategory.STATE_WRITE,
        function=_handler(),
        location=_LOC,
        expression='session["user_id"] = user.id',
        provenance=_PROV,
        scope=StateScope.SESSION,
        key="user_id",
    )
    text = repr(effect)
    assert text.startswith("Effect(STATE_WRITE, session,")
    assert _short_loc(_LOC) in text
    # The bug this fixes: the default repr inlined the whole Function + Provenance
    # (~1 KB).  Guard the regression with a hard length bound.
    assert len(text) < 200
    assert "Parameter(" not in text


def test_input_read_repr() -> None:
    read = InputRead(
        source=Query(key=Key("id")),
        access_pattern=AccessPattern.GET,
        cardinality=Cardinality.SINGLE,
        function=_handler(),
        location=_LOC,
        expression='request.args.get("id")',
        provenance=_PROV,
    )
    text = repr(read)
    assert text == "InputRead(Query(key='id'), request.args.get(\"id\"), app/auth.py:42)"
    assert "Function(" not in text


def test_value_handle_repr() -> None:
    handle = ValueHandle(location=_LOC, expression='request.args.get("id")')
    assert repr(handle) == 'ValueHandle(request.args.get("id"), app/auth.py:42)'


def test_flow_step_repr() -> None:
    step = FlowStep(location=_LOC, expression="x = src", description="assignment", kind="ASSIGN")
    assert repr(step) == "FlowStep(ASSIGN, x = src, app/auth.py:42)"
    # kind=None falls back to a generic label.
    assert repr(FlowStep(_LOC, "y", "d")).startswith("FlowStep(step,")


def test_flow_trace_repr_summarises_endpoints_and_step_count() -> None:
    src = ValueHandle(_LOC, 'request.args.get("id")')
    sink = ValueHandle(_LOC, 'session["user_id"]')
    trace = FlowTrace(
        source=src, sink=sink, steps=(FlowStep(_LOC, "x", "d"),), reachable=True, gaps=()
    )
    text = repr(trace)
    assert "→" in text
    assert "1 steps" in text
    assert "reachable=True" in text
    # Unreachable traces use a distinct arrow.
    broken = FlowTrace(source=src, sink=sink, steps=(), reachable=False, gaps=())
    assert "↛" in repr(broken)


def test_collection_of_routes_repr_stays_small() -> None:
    # The headline regression: list(repo.routes) dumped 71 KB.  With concise
    # per-item reprs, a list of many routes stays tiny.
    route = Route(
        endpoint="auth.login",
        url_rule="/login",
        methods=frozenset({HttpMethod.GET}),
        handler=_handler(),
        group="auth",
        location=_LOC,
        provenance=_PROV,
    )
    assert len(repr([route] * 75)) < 5000
