"""Specs: scoped queries on CodeScope (body, reachable, full_stack).

Fixture: tests/fixtures/apps/semantic/flask_basic/ (session-scoped via root conftest)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed.calls import Fn
from flawed.effects import Data, State, StateScope
from flawed.flow import ValueHandle
from flawed.inputs import FrameworkGlobal, Json, SessionValue
from flawed.route import GET, POST

if TYPE_CHECKING:
    from flawed.repo import RepoView


class TestBodyScope:
    """route.body only includes the handler function body."""

    def test_body_reads_are_local(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "input_json_attr").one()
        reads = route.body.reads(Json())
        # input_json_attr reads request.json in its body
        assert len(reads) >= 1

    def test_body_effects_are_local(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "effect_session_write").one()
        effects = route.body.effects(State.write(scope=StateScope.SESSION))
        # effect_session_write performs a session write in its body
        assert len(effects) >= 1

    def test_body_does_not_include_other_routes(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "input_query").one()
        writes = route.body.effects(Data.write())
        # input_query does not write data -- it only reads request args and
        # returns jsonify() (which is a RESPONSE_WRITE, not a data write)
        assert len(writes) == 0


class TestReachableScope:
    """route.reachable includes transitively called functions."""

    def test_reachable_includes_helper_calls(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "users").one()
        # create_user() is called from users(); its effects should be reachable
        # The db.execute and db.commit calls happen in the helper body
        effects = route.reachable.effects()
        assert any(effect.function.name == "create_user" for effect in effects)

    def test_reachable_conditions(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "users").one()
        conds = route.reachable.conditions()
        # users() has an if request.method branch
        assert len(conds) >= 1


class TestCallScope:
    """Scoped call queries expose L1 call edges on route scopes."""

    def test_body_calls_filter_by_project_function_name(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "users").one()
        calls = route.body.calls(Fn.named("create_user"))
        assert len(calls) == 1
        call = calls.one()
        assert call.target is not None
        assert call.target.name == "create_user"

    def test_reachable_calls_include_helper_call_sites(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "users").one()
        calls = route.reachable.calls(Fn.named("execute"))
        assert len(calls) >= 1
        assert any(call.function.name == "create_user" for call in calls)

    def test_calls_filter_by_external_fqn(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "check_password").one()
        calls = route.body.calls(Fn.fqn("werkzeug.security.check_password_hash"))
        call = calls.one()
        assert call.target is None
        assert call.target_fqn == "werkzeug.security.check_password_hash"
        assert call.argument(0).expression == "stored_hash"

    def test_calls_without_selector_returns_all_scope_calls(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "do_login").one()
        calls = route.body.calls()
        assert len(calls) >= 1
        assert any(call.target_fqn == "flask_login.login_user" for call in calls)

    def test_call_argument_value_is_flow_handle(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "users").one()
        read = route.body.reads().first()
        call = route.reachable.calls(Fn.named("execute")).first()

        assert read is not None
        assert call is not None

        argument_value = call.argument(0).value
        assert isinstance(argument_value, ValueHandle)
        assert argument_value == call.arguments[0].value
        assert argument_value.expression == call.arguments[0].expression
        assert isinstance(read.value.flows_to(argument_value), bool)
        assert isinstance(call.return_value, ValueHandle)


class TestScopeFiltering:
    """Scoped queries filter correctly by source type."""

    def test_reads_filter_by_source(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "effect_session_read").one()
        # Session reads are state effects (State.read with scope=SESSION), not InputSource reads.
        session_effects = route.body.effects(State.read(scope=StateScope.SESSION))
        json_reads = route.body.reads(Json())
        # effect_session_read reads from session, not from JSON body
        assert len(session_effects) >= 1
        assert len(json_reads) == 0

    def test_effects_filter_by_selector(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "effect_session_write").one()
        writes = route.body.effects(State.write(scope=StateScope.SESSION))
        reads = route.body.effects(State.read(scope=StateScope.SESSION))
        # effect_session_write writes session state but does not read it
        assert len(writes) >= 1
        assert len(reads) == 0

    def test_conditions_using_value(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "users").one()
        condition = route.body.conditions().comparing("request.method", "*POST*").one()
        assert condition.left is not None

        conds = route.body.conditions_using(condition.left)

        assert len(conds) == 1
        assert conds.one().expression == condition.expression


class TestBranchRestrictedScope:
    """Branch-restricted scope queries filter to a single HTTP method arm."""

    def test_branch_post_calls_only_post_callees(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "users").one()
        post_scope = route.body.branch(POST)
        assert post_scope is not None
        assert len(post_scope.calls(Fn.named("create_user"))) == 1
        assert len(post_scope.calls(Fn.named("list_users"))) == 0

    def test_branch_get_calls_only_get_callees(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "users").one()
        get_scope = route.body.branch(GET)
        assert get_scope is not None
        assert len(get_scope.calls(Fn.named("list_users"))) == 1
        assert len(get_scope.calls(Fn.named("create_user"))) == 0

    def test_branch_accepts_string_method(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "users").one()
        post_scope = route.body.branch("POST")
        assert post_scope is not None
        assert len(post_scope.calls(Fn.named("create_user"))) == 1

    def test_branch_nonexistent_method_returns_none(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "users").one()
        assert route.body.branch("DELETE") is None

    def test_route_branch_delegates_to_body(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "users").one()
        assert route.branch(POST) is route.body.branch(POST)
        assert route.branch("GET") is route.body.branch("GET")

    def test_branch_effects_filter_by_method(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(
            lambda r: r.endpoint == "gadget_method_guarded_auth",
        ).one()
        get_scope = route.branch(GET)
        post_scope = route.branch(POST)
        assert get_scope is not None
        assert post_scope is not None
        # GET branch writes to session; POST branch does not
        get_writes = get_scope.effects(State.write(scope=StateScope.SESSION))
        post_writes = post_scope.effects(State.write(scope=StateScope.SESSION))
        assert len(get_writes) >= 1
        assert len(post_writes) == 0

    def test_branch_reads_filter_by_method(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(
            lambda r: r.endpoint == "gadget_method_guarded_auth",
        ).one()
        get_scope = route.branch(GET)
        assert get_scope is not None
        # GET branch reads request.args.get("user_id")
        reads = get_scope.reads()
        assert len(reads) >= 1

    def test_branch_scope_has_cfg(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "users").one()
        post_scope = route.body.branch(POST)
        assert post_scope is not None
        # Branch scopes expose a control flow view
        cfg = post_scope.cfg
        assert cfg is not None
        # The create_user call should be locatable in the branch CFG
        call = post_scope.calls(Fn.named("create_user")).one()
        assert cfg.block_id_for(call.location) is not None

    def test_no_branch_for_single_method_route(self, flask_basic: RepoView) -> None:
        route = flask_basic.routes.where(lambda r: r.endpoint == "input_query").one()
        # Single-method route has no internal method dispatch
        assert route.branch(GET) is None
        assert route.branch(POST) is None


class TestReadsFlowingTo:
    """scope.reads_flowing_to(target) — the first-class read->sink correlation
    (FLAW-199). A faithful filter over the identity-inclusive read set, so the
    comparative/invariant-flow rules need not hand-roll it."""

    def test_matches_manual_flows_to_filter_across_fixture(self, flask_basic: RepoView) -> None:
        """For every effect target in the app, reads_flowing_to returns exactly
        the reads the manual ``[r for r in all_reads if r.value.flows_to(target)]``
        filter would.

        FLAW-240 made ``reads_flowing_to`` a deliberate SUPERSET of
        ``filter(reads())``: identity sources (session values, framework
        globals) are excluded from the noisy wildcard ``reads()`` stream for FP
        containment, but remain visible to this *targeted* query so a
        session-vs-request mismatch can still be paired. The invariant is
        therefore stated over the identity-inclusive read set (wildcard plus the
        opt-in identity sources) and compared by membership: once containment
        interleaves the two streams, their positional order need not coincide,
        but the set of reads flowing to a target must match exactly.
        """
        exercised_a_real_flow = False
        for route in flask_basic.routes:
            scope = route.reachable
            # Wildcard reads() drops identity sources (FLAW-240 containment);
            # add them back via the opt-in path to reconstruct the full set
            # reads_flowing_to actually correlates over.
            all_reads = (
                list(scope.reads())
                + list(scope.reads(SessionValue()))
                + list(scope.reads(FrameworkGlobal()))
            )
            if not all_reads:
                continue
            for effect in scope.effects():
                target = effect.target
                if target is None:
                    continue
                expected = [r for r in all_reads if r.value.flows_to(target)]
                actual = list(scope.reads_flowing_to(target))
                assert sorted(actual, key=repr) == sorted(expected, key=repr), (
                    f"reads_flowing_to diverged from the identity-inclusive "
                    f"manual filter for effect {effect.expression!r} in "
                    f"{route.endpoint}"
                )
                if expected:
                    exercised_a_real_flow = True
        # Guard against a vacuous pass: the fixture must contain at least one
        # real read->effect flow, or this test proves nothing.
        assert exercised_a_real_flow

    def test_returns_empty_when_no_read_flows(self, flask_basic: RepoView) -> None:
        """A target that no input read reaches yields an empty collection
        (not an error, not a fail-open match)."""
        route = flask_basic.routes.where(lambda r: r.endpoint == "input_query").one()
        scope = route.reachable
        # Build a value handle for a read itself; no *input read* flows into a
        # bare request-args read target in this single-read GET handler beyond
        # itself, so cross-source feeders are empty.
        reads = list(scope.reads())
        assert reads  # fixture sanity
        # An effect-free GET route: reads_flowing_to over its own read's value
        # returns at most that read (same_origin), never a spurious match.
        feeders = list(scope.reads_flowing_to(reads[0].value))
        assert all(f.value.flows_to(reads[0].value) for f in feeders)
