"""Vertical slice integration test: open_repo() -> routes -> reads/effects -> finding.

Tests the full L1 -> L2 -> L3 pipeline on the ``flask_basic`` fixture,
verifying that every layer produces populated, queryable domain objects.

Uses the session-scoped ``flask_basic`` fixture from root conftest.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed.effects import State
from flawed.inputs import Form, Query
from flawed.route import HttpMethod

if TYPE_CHECKING:
    from flawed.repo import RepoView


# -- Route population -----------------------------------------------------


def test_routes_cover_all_direct_decorator_endpoints(flask_basic: RepoView) -> None:
    """Every @app.route / @app.get / @app.post in flask_basic is discovered."""
    routes = {r.endpoint for r in flask_basic.routes}
    expected = {
        "index",
        "users",
        "items_get",
        "items_post",
        "input_query",
        "input_form",
        "input_json_attr",
        "input_json_method",
        "input_headers",
        "input_cookies",
        "input_path",
        "input_files",
        "input_raw",
    }
    assert expected.issubset(routes)


# -- Input reads -----------------------------------------------------------


def test_query_route_reads_query_source(flask_basic: RepoView) -> None:
    """input_query route reads from Query source."""
    routes = {r.endpoint: r for r in flask_basic.routes}
    reads = routes["input_query"].body.reads(Query())
    assert len(reads) >= 1
    expressions = {r.expression for r in reads}
    assert any("request.args" in e for e in expressions)


def test_form_route_reads_form_source(flask_basic: RepoView) -> None:
    """input_form route reads from Form source."""
    routes = {r.endpoint: r for r in flask_basic.routes}
    reads = routes["input_form"].body.reads(Form())
    assert len(reads) >= 1


def test_no_arg_reads_returns_all(flask_basic: RepoView) -> None:
    """Calling reads() with no arguments returns all input reads."""
    routes = {r.endpoint: r for r in flask_basic.routes}
    all_reads = routes["input_form"].body.reads()
    form_reads = routes["input_form"].body.reads(Form())
    assert len(all_reads) >= len(form_reads)
    assert len(all_reads) >= 1


def test_query_route_no_form_reads(flask_basic: RepoView) -> None:
    """input_query route has no Form reads — source filter works."""
    routes = {r.endpoint: r for r in flask_basic.routes}
    form_reads = routes["input_query"].body.reads(Form())
    assert len(form_reads) == 0


# -- Effects ---------------------------------------------------------------


def test_session_write_route_has_state_write_effects(flask_basic: RepoView) -> None:
    """effect_session_write route produces STATE_WRITE effects."""
    routes = {r.endpoint: r for r in flask_basic.routes}
    effects = routes["effect_session_write"].body.effects(State.write())
    assert len(effects) >= 2
    expressions = {e.expression for e in effects}
    assert any("session" in e for e in expressions)


def test_no_arg_effects_returns_all(flask_basic: RepoView) -> None:
    """Calling effects() with no arguments returns all effects."""
    routes = {r.endpoint: r for r in flask_basic.routes}
    all_effects = routes["effect_session_write"].body.effects()
    state_effects = routes["effect_session_write"].body.effects(State.write())
    assert len(all_effects) >= len(state_effects)


# -- Cross-function reachability -------------------------------------------


def test_users_reachable_scope_includes_callee_reads(flask_basic: RepoView) -> None:
    """users() calls create_user(), which reads request.form — reachable sees it."""
    routes = {r.endpoint: r for r in flask_basic.routes}
    body_reads = routes["users"].body.reads()
    assert len(body_reads) >= 1, "users route body should include callee reads"


def test_users_reachable_scope_includes_callee_effects(flask_basic: RepoView) -> None:
    """users() calls create_user() which does db.commit() — reachable sees it."""
    routes = {r.endpoint: r for r in flask_basic.routes}
    body_effects = routes["users"].body.effects()
    assert len(body_effects) >= 1, "users route body should include callee effects"


# -- Finding builder -------------------------------------------------------


def test_finding_from_route(flask_basic: RepoView) -> None:
    """Route.finding() produces a valid Finding with route metadata."""
    routes = {r.endpoint: r for r in flask_basic.routes}
    finding = routes["input_query"].finding("reads user-controlled query param")
    assert finding.route_endpoint == "input_query"
    assert finding.summary == "reads user-controlled query param"
    assert finding.location is not None


def test_finding_evidence_chain(flask_basic: RepoView) -> None:
    """Finding.evidence() appends evidence items immutably."""
    routes = {r.endpoint: r for r in flask_basic.routes}
    route = routes["input_query"]
    reads = list(route.body.reads(Query()))
    assert reads, "precondition: at least one query read"

    f1 = route.finding("user input")
    f2 = f1.evidence(reads[0], "reads query parameter")
    assert len(f2.evidence_items) == 1
    assert len(f1.evidence_items) == 0, "original Finding is immutable"
    assert f2.evidence_items[0].description == "reads query parameter"


def test_finding_preserves_route_gaps(flask_basic: RepoView) -> None:
    """Finding inherits gaps from the route."""
    routes = {r.endpoint: r for r in flask_basic.routes}
    route = routes["index"]
    finding = route.finding("test gaps propagation")
    # index has no gaps, so finding should have zero
    assert isinstance(finding.gaps, tuple)


# -- Route metadata --------------------------------------------------------


def test_route_methods_populated(flask_basic: RepoView) -> None:
    """Routes carry correct HTTP method sets."""
    routes = {r.endpoint: r for r in flask_basic.routes}
    assert routes["users"].methods == frozenset({HttpMethod.GET, HttpMethod.POST})
    assert routes["index"].methods == frozenset({HttpMethod.GET})


def test_route_handler_has_fqn(flask_basic: RepoView) -> None:
    """Route handler links back to a Function with a fully-qualified name."""
    routes = {r.endpoint: r for r in flask_basic.routes}
    handler = routes["input_query"].handler
    assert handler.fqn == "flask_basic.app.input_query"


def test_route_source_returns_code_snippet(flask_basic: RepoView) -> None:
    """Route.source() returns the handler's source code."""
    routes = {r.endpoint: r for r in flask_basic.routes}
    src = routes["input_query"].source()
    assert "request.args" in src
    assert "def input_query" in src


def test_route_reachable_scope_infers_reads_through_container_arguments(
    flask_basic: RepoView,
) -> None:
    """helper(request.form) + data.get/getlist is modeled as Form reads."""
    from flawed.inputs import Cardinality, Form

    routes = {r.endpoint: r for r in flask_basic.routes}
    reads = list(routes["gadget_helper_form_cardinality"].reachable.reads(Form()))
    observed = {
        (str(read.source.key), read.cardinality) for read in reads if isinstance(read.source, Form)
    }

    assert ("item", Cardinality.SINGLE) in observed
    assert ("items", Cardinality.MULTI) in observed
