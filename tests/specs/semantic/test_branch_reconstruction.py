"""Specs: CFG-backed branch reconstruction for method and condition scopes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed.calls import Fn
from flawed.effects import State, StateScope
from flawed.inputs import AnyOf, Header, Query
from flawed.route import GET, POST

if TYPE_CHECKING:
    from flawed.repo import RepoView


def _route(repo: RepoView, endpoint: str):
    return repo.routes.where(lambda route: route.endpoint == endpoint).one()


class TestMethodBranchReconstruction:
    """Route and CodeScope branch queries use CFG method predicates."""

    def test_route_body_branch_restricts_post_callees(self, flask_basic: RepoView) -> None:
        route = _route(flask_basic, "users")

        post_branch = route.body.branch("POST")
        get_branch = route.body.branch(GET)

        assert post_branch is not None
        assert get_branch is not None
        create_user_call = post_branch.calls(Fn.named("create_user")).one()
        assert create_user_call.target is not None
        assert create_user_call.target.name == "create_user"
        assert len(post_branch.calls(Fn.named("list_users"))) == 0
        list_users_call = get_branch.calls(Fn.named("list_users")).one()
        assert list_users_call.target is not None
        assert list_users_call.target.name == "list_users"
        assert len(get_branch.calls(Fn.named("create_user"))) == 0
        full_list_users_call = route.body.calls(Fn.named("list_users")).one()
        assert post_branch.cfg.block_id_for(create_user_call.location) is not None
        assert post_branch.cfg.block_id_for(full_list_users_call.location) is None

    def test_route_branch_delegates_to_body_branch(self, flask_basic: RepoView) -> None:
        route = _route(flask_basic, "users")

        assert route.branch(POST) is route.body.branch(POST)
        assert route.branch("POST") is route.body.branch("POST")

    def test_method_branches_filter_direct_handler_effects(
        self,
        flask_basic: RepoView,
    ) -> None:
        route = _route(flask_basic, "gadget_method_guarded_auth")

        post_branch = route.branch(POST)
        get_branch = route.branch(GET)

        assert post_branch is not None
        assert get_branch is not None
        assert len(post_branch.calls(Fn.named("abort"))) == 1
        assert len(post_branch.effects(State.write(scope=StateScope.SESSION))) == 0
        assert len(get_branch.calls(Fn.named("abort"))) == 0
        assert len(get_branch.effects(State.write(scope=StateScope.SESSION))) == 1


class TestConditionBranchReconstruction:
    """Condition true/false branches expose CFG arm scopes."""

    def test_condition_branches_reconstruct_true_and_false_arms(
        self,
        flask_basic: RepoView,
    ) -> None:
        route = _route(flask_basic, "users")
        condition = route.body.conditions().comparing("request.method", "*POST*").one()

        create_user_call = condition.true_branch.calls(Fn.named("create_user")).one()
        assert create_user_call.target is not None
        assert create_user_call.target.name == "create_user"
        assert len(condition.true_branch.calls(Fn.named("list_users"))) == 0
        list_users_call = condition.false_branch.calls(Fn.named("list_users")).one()
        assert list_users_call.target is not None
        assert list_users_call.target.name == "list_users"
        assert len(condition.false_branch.calls(Fn.named("create_user"))) == 0


class TestInterproceduralConditionOperands:
    """FLAW-117: branch-condition operands trace ``derived_from`` across calls.

    Mirrors the ``predicates()`` interprocedural wiring landed by FLAW-113: a
    bare-name operand of an ``if`` test whose value is produced by a *callee*
    resolves ``derived_from(InputSource)`` back to the originating request read.
    Before FLAW-117 the ``conditions()`` lifter built eager, flow-context-free
    operand handles anchored at the *use* site, so this returned ``False`` — a
    silent false negative on the FLAW-104 r02c/g012 ``conditions()`` arm for the
    interprocedural branch shape.
    """

    def test_branch_condition_operand_traces_request_through_callee(
        self,
        detection_credential_derivation_divergence: RepoView,
    ) -> None:
        repo = detection_credential_derivation_divergence
        # ``load_principal`` does ``token = extract_credential()`` then ``if not
        # token:`` — the operand ``token`` is defined via a callee whose return
        # reads ``request.headers`` / ``request.args``.
        load_principal = repo.functions.named("load_principal").one()

        token_conditions = [
            condition
            for condition in load_principal.body.conditions()
            if condition.left is not None and condition.left.expression == "token"
        ]
        assert token_conditions, "expected a branch condition over `token`"
        condition = token_conditions[0]

        assert condition.left is not None
        assert condition.left.derived_from(AnyOf(sources=(Header(), Query()))) is True
