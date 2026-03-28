"""EP-8: Flow propagation and end-to-end taint tracking tests.

Tests that the Semantic API correctly follows data flow through
library calls that are opaque to structural analysis.

Pattern types under test:
  - FlowPropagatorPattern (data flows through library calls)
  - End-to-end input→sink flow chains
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flawed import Fn
from flawed.core import Key
from flawed.effects import Db, Response
from flawed.inputs import Form, Query

if TYPE_CHECKING:
    from flawed.repo import RepoView

pytestmark = pytest.mark.slow


# =====================================================================
# FlowPropagatorPattern
# =====================================================================


class TestFlowPropagatorPattern:
    """Test that taint propagates through declared library calls.

    Provider declaration:
        FlowPropagatorPattern(
            fqn="sqlalchemy.orm.Session.add",
            input_arg=0,
            output="receiver",
        )

    The engine's flow tracer uses these during BFS to cross opaque
    library call boundaries.
    """

    def test_l0_taint_through_session_add(self, flask_basic: RepoView) -> None:
        """Object taint propagates to session via session.add(obj).

        EXPECT: if obj carries user input, session is now tainted
        """

    def test_l0_taint_through_query_filter(self, flask_basic: RepoView) -> None:
        """Taint propagates through Query.filter() → to result set.

        EXPECT: filter criteria taint flows to query result
        """


# =====================================================================
# End-to-end: input source → taint sink
# =====================================================================


class TestEndToEndFlow:
    """Test complete data-flow chains from input source to taint sink.

    These are the most critical tests: they verify that the engine
    can trace user input from HTTP request containers through arbitrary
    code to injection sinks.
    """

    # -- L0: Direct flow (same function) ---------------------------------

    def test_l0_direct_input_to_sink(self, flask_basic: RepoView) -> None:
        """request.form["query"] → text(query) in same function."""
        route = flask_basic.routes.where(lambda r: r.endpoint == "sink_sql_injection").one()
        read = route.body.reads(Form()).one()
        effect = route.body.effects(Db.write()).one()

        assert effect.target is not None
        assert read.value.flows_to(effect.target)

        trace = flask_basic.trace_flow(read.location, effect.location)
        assert trace.reachable
        assert trace.source.expression == read.expression
        assert trace.steps

    def test_assignment_chain_flows_to_sql_call_argument(self, flask_basic: RepoView) -> None:
        """request.form["query"] → query → text(query) call argument."""
        route = flask_basic.routes.where(lambda r: r.endpoint == "sink_sql_injection").one()
        read = route.body.reads(Form()).one()
        call = route.reachable.calls(Fn.fqn("sqlalchemy.text")).one()
        sql_arg = call.arguments[0]

        assert sql_arg.value is not None
        assert read.value.flows_to(sql_arg.value)

    def test_l0_direct_ssti(self, flask_basic: RepoView) -> None:
        """request.form["template"] → render_template_string(template).

        Fixture: flask_basic/app.py::sink_ssti()
        EXPECT: flow trace from Form read to SSTI sink
        """

    def test_l0_direct_xss(self, flask_basic: RepoView) -> None:
        """request.args.get("name") → Markup(name).

        Fixture: flask_basic/app.py::sink_xss()
        EXPECT: flow trace from Query read to XSS sink
        """

    def test_l0_direct_open_redirect(self, flask_basic: RepoView) -> None:
        """request.args.get("next") → redirect(url)."""
        route = flask_basic.routes.where(lambda r: r.endpoint == "sink_open_redirect").one()
        read = route.body.reads(Query()).one()
        effect = route.body.effects(Response.write()).one()

        assert effect.target is not None
        assert read.value.flows_to(effect.target)
        assert effect.target.flows_from(read.value)

    def test_localproxy_next_query_flows_to_redirect(
        self,
        flask_real_world_gaps: RepoView,
    ) -> None:
        """A request.args LocalProxy flow reaches redirect()."""
        route = flask_real_world_gaps.routes.where(
            lambda r: r.endpoint == "login_redirect" and r.group == "auth"
        ).one()
        read = route.reachable.reads(Query(key=Key("next"))).one()
        effect = (
            route.reachable.effects(Response.write())
            .where(lambda e: e.expression.startswith("redirect("))
            .one()
        )

        assert read.expression == 'request.args.get("next")'
        assert effect.target is not None
        assert read.value.flows_to(effect.target)
        assert effect.target.flows_from(read.value)

        trace = flask_real_world_gaps.trace_flow(read.location, effect.location)
        assert trace.reachable
        assert trace.gaps == ()

    # -- L0: Safe pattern (no flow to sink) ------------------------------

    def test_l0_literal_string_not_flagged(self, flask_basic: RepoView) -> None:
        """text("SELECT 1") → NOT flagged (literal string).

        Fixture: flask_basic/app.py::sink_sql_safe()
        EXPECT: no SQL_INJECTION finding — when= predicate excludes
                literal strings
        """

    # -- L3: Cross-function flow -----------------------------------------

    def test_l3_input_through_helper_to_sink(self, flask_indirect: RepoView) -> None:
        """request.form["query"] → _run_query(query) → text(query_str).

        Fixture: flask_indirect/app.py::l3_cross_function_sink()
        EXPECT: flow crosses function boundary via call-graph
        """

    # -- L4: Cross-file flow ---------------------------------------------

    def test_l4_input_through_imported_helper(self, flask_indirect: RepoView) -> None:
        """request.form["query"] → helpers.execute_raw(query) → text().

        Fixture: flask_indirect/app.py::l4_cross_file_sink()
        EXPECT: flow crosses file boundary
        """

    # -- L6: Multi-hop flow ----------------------------------------------

    def test_l6_multi_hop_flow(self, flask_indirect: RepoView) -> None:
        """request.form["query"] → utils.run_user_query() → helpers.execute_raw() → text().

        Fixture: flask_indirect/app.py::l6_multi_hop_sink()
        EXPECT: flow crosses two file boundaries
        """


# =====================================================================
# Flow direction and API: flows_to / flows_from
# =====================================================================


class TestFlowAPI:
    """Test the ValueHandle flow-tracing API.

    Rule authors use read.value.flows_to(effect.target) to check
    whether user input reaches a sensitive operation.
    """

    def test_flows_to_positive(self, flask_basic: RepoView) -> None:
        """input_read.value.flows_to(sink_arg) → True when input reaches the sink."""
        route = flask_basic.routes.where(lambda r: r.endpoint == "sink_sql_injection").one()
        read = route.body.reads(Form()).one()
        effect = route.body.effects(Db.write()).one()

        assert effect.target is not None
        assert read.value.flows_to(effect.target)
        assert read.value.same_origin(read.value)
        assert read.value.derived_from(Form())

    def test_flows_to_negative(self, flask_basic: RepoView) -> None:
        """input_read.value.flows_to(sink_arg) → False for safe code."""
        source_route = flask_basic.routes.where(lambda r: r.endpoint == "sink_sql_injection").one()
        safe_route = flask_basic.routes.where(lambda r: r.endpoint == "sink_sql_safe").one()
        read = source_route.body.reads(Form()).one()
        effect = safe_route.body.effects(Db.write()).one()

        assert effect.target is not None
        assert not read.value.flows_to(effect.target)
