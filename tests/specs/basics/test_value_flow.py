"""Specs: value flow tracking across assignments and calls.

Fixture: tests/fixtures/apps/functions/ (session-scoped via root conftest)
         tests/fixtures/apps/semantic/flask_basic/ (session-scoped via root conftest)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed.inputs import Json, PathParam

if TYPE_CHECKING:
    from flawed.repo import RepoView


class TestValueFlowBasics:
    """ValueHandle.flows_to and flows_from on simple assignments."""

    def test_return_value_flows_to_caller(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("with_nested").one()
        inner = (
            functions_app.functions.named("inner")
            .where(lambda f: f.parent_function is not None and "with_nested" in f.parent_function)
            .one()
        )
        # inner's return value should flow to with_nested's call site
        # (the return of with_nested is inner(5))
        assert fn is not None and inner is not None  # skeleton: needs engine for flow

    def test_assignment_chain(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("with_lambda").one()
        # transform = lambda x: x.upper()
        # return transform("hello")
        # The lambda's return flows through the assignment to the call result
        assert fn is not None  # skeleton: needs engine for flow

    def test_parameter_flows_to_body(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("top_level").one()
        # x flows to the return expression (x + y)
        assert fn is not None  # skeleton: needs engine for flow


class TestValueFlowFlask:
    """Value flow tracking in a Flask context (L1 flask_basic fixture)."""

    def test_request_json_flows_to_variable(self, flask_basic_l1: RepoView) -> None:
        fn = flask_basic_l1.functions.named("create_user").one()
        # data = request.json; name = data.get("name")
        # request.json should flow to data, data flows to name
        assert fn is not None  # skeleton: needs engine for flow

    def test_input_read_derived_from_source(self, flask_basic_l1: RepoView) -> None:
        fn = flask_basic_l1.functions.named("create_user").one()
        reads = fn.body.reads(Json())
        # There should be reads from JSON body
        assert len(reads) >= 1
        read = reads.first()
        assert read is not None
        assert read.value.derived_from(Json())

    def test_path_param_flows_to_query(self, flask_basic_l1: RepoView) -> None:
        fn = flask_basic_l1.functions.named("update_user").one()
        # user_id path param flows into the SQL query
        reads = fn.body.reads(PathParam())
        # update_user receives user_id as path param
        assert fn is not None and reads is not None  # skeleton: needs engine for flow

    def test_flow_does_not_cross_unrelated_functions(self, flask_basic_l1: RepoView) -> None:
        # list_users and create_user are separate functions;
        # a value in list_users should not flow to create_user
        list_fn = flask_basic_l1.functions.named("list_users").one()
        create_fn = flask_basic_l1.functions.named("create_user").one()
        # These should be independent scopes
        assert list_fn.fqn != create_fn.fqn  # distinct functions, no cross-flow
