"""Exploration specs for interactive Rule API workflows.

These tests intentionally use session-scoped fixture analyses from the root
``tests/conftest.py``. That keeps the specs representative of ``open_repo()``
usage while preserving the suite-wide timing guard against inline analysis.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import FrozenInstanceError
from typing import TYPE_CHECKING, cast

import pytest

from flawed import RepoView
from flawed._semantic._provider_engine import discover_builtin_provider_classes
from flawed._semantic.providers import RouteDecorator
from flawed.calls import Fn
from flawed.core import GapKind, Key
from flawed.effects import EffectCategory, State, StateScope
from flawed.evidence import Finding
from flawed.inputs import AccessPattern, Cardinality, Form, Json, Query
from flawed.route import GET, POST

if TYPE_CHECKING:
    from flawed._semantic._provider_engine import ProviderEngineResult
    from flawed.repo import RepoView as RepoViewProto


def test_open_repo_result_supports_interactive_route_navigation(
    flask_basic: RepoViewProto,
) -> None:
    """An ``open_repo()`` result is queryable from routes back to handlers."""
    assert isinstance(flask_basic, RepoView)
    assert flask_basic.path.endswith("tests/fixtures/apps/semantic/flask_basic")

    route = flask_basic.routes.with_path("/items").accepting(POST).one()

    assert route.endpoint == "items_post"
    assert route.methods == frozenset({POST})
    assert route.handler is flask_basic.functions.with_fqn("flask_basic.app.items_post").one()
    assert flask_basic.routes.with_path("/items").accepting(GET).one().endpoint == "items_get"


def test_open_repo_workflow_queries_route_inputs(flask_basic: RepoViewProto) -> None:
    """Interactive route scopes expose typed input reads."""
    route = flask_basic.routes.with_path("/inputs/form").one()

    reads = tuple(route.body.reads(Form()))

    assert {cast("Form", read.source).key for read in reads} == {Key("name"), Key("email")}
    assert {read.access_pattern for read in reads} == {
        AccessPattern.SUBSCRIPT,
        AccessPattern.GET,
    }
    assert all(read.cardinality is Cardinality.SINGLE for read in reads)
    assert tuple(route.body.reads(Query())) == ()


def test_open_repo_workflow_queries_json_inputs(flask_basic: RepoViewProto) -> None:
    """Selectors can narrow a scope to one input family."""
    route = flask_basic.routes.with_path("/inputs/json").one()

    read = route.body.reads(Json()).one()

    assert read.source == Json()
    assert read.access_pattern is AccessPattern.ATTRIBUTE
    assert read.expression == "request.json"
    assert read.function.fqn == "flask_basic.app.input_json_attr"


def test_open_repo_workflow_queries_route_effects(flask_basic: RepoViewProto) -> None:
    """Interactive route scopes expose effect selectors and metadata."""
    route = flask_basic.routes.with_path("/effects/session_write").one()

    writes = tuple(route.body.effects(State.write(scope=StateScope.SESSION)))

    assert {effect.key for effect in writes} == {"role", "user_id"}
    assert {effect.category for effect in writes} == {EffectCategory.STATE_WRITE}
    assert all(effect.scope is StateScope.SESSION for effect in writes)
    assert tuple(route.body.effects(State.read(scope=StateScope.SESSION))) == ()


def test_composed_fn_selector_matches_local_and_external_calls(
    flask_basic: RepoViewProto,
) -> None:
    """``Fn.named(...) | Fn.fqn(...)`` composes across local and library calls."""
    selector = Fn.named("create_user") | Fn.fqn("werkzeug.security.check_password_hash")
    users = flask_basic.routes.with_path("/users").one()
    password = flask_basic.routes.with_path("/checks/password").one()

    local_call = users.body.calls(selector).one()
    external_call = password.body.calls(selector).one()

    assert local_call.target is not None
    assert local_call.target.name == "create_user"
    assert external_call.target is None
    assert external_call.target_fqn == "werkzeug.security.check_password_hash"


def test_composed_fn_selector_reuses_collection_filters(
    flask_basic: RepoViewProto,
) -> None:
    """Composable selectors work both at query time and as collection filters."""
    selector = Fn.named("login_user") | Fn.fqn("flask.redirect")
    route = flask_basic.routes.with_path("/login").one()

    calls = route.body.calls().to(selector)

    assert {call.target_fqn for call in calls} == {"flask.redirect", "flask_login.login_user"}
    assert calls.to(Fn.fqn("flask.redirect")).one().argument(0).expression == 'url_for("index")'


def test_open_repo_workflow_queries_safe_generated_urls(
    flask_basic: RepoViewProto,
) -> None:
    """Interactive route scopes expose safe provider-generated URL facts."""
    route = flask_basic.routes.with_path("/login").one()

    generated_url = route.body.generated_urls().safe_for("OPEN_REDIRECT").one()

    assert generated_url.expression == 'url_for("index")'
    assert generated_url.function.fqn == "flask_basic.app.do_login"
    assert "OPEN_REDIRECT" in generated_url.safe_for_sink_kinds
    assert tuple(route.reachable.generated_urls()) == (generated_url,)


def test_open_repo_workflow_queries_validated_values(
    flask_basic: RepoViewProto,
) -> None:
    """Interactive route scopes expose validator-proven value facts."""
    route = flask_basic.routes.with_path("/sinks/redirect_validated").one()

    validated = route.body.validated_values().safe_for("OPEN_REDIRECT").one()

    assert validated.expression == "is_safe_url(url)"
    assert validated.validated_expression == "url"
    assert validated.function.fqn == "flask_basic.app.sink_open_redirect_validated"
    assert "OPEN_REDIRECT" in validated.safe_for_sink_kinds
    assert route.body.validated_values().named("is_safe_url").one() == validated
    assert tuple(route.reachable.validated_values()) == (validated,)


def test_validated_values_are_inherited_by_method_branch_scopes(
    flask_basic: RepoViewProto,
) -> None:
    """Child method scopes inherit validation facts from dominating parent code."""
    route = flask_basic.routes.with_path("/sinks/redirect_validated_branch").one()

    parent_validated = route.body.validated_values().safe_for("OPEN_REDIRECT").one()
    post_scope = route.branch(POST)
    assert post_scope is not None
    post_validated = post_scope.validated_values().safe_for("OPEN_REDIRECT").one()

    assert post_validated == parent_validated
    assert post_validated.validated_expression == "url"


def test_finding_builder_records_evidence_immutably(flask_basic: RepoViewProto) -> None:
    """Route findings are immutable builders over evidence items."""
    route = flask_basic.routes.with_path("/inputs/query").one()
    read = route.body.reads(Query()).one()

    base = route.finding("query input reaches response")
    finding = base.evidence(read, "reads query parameter")

    assert isinstance(finding, Finding)
    assert finding.route_endpoint == "input_query"
    assert finding.summary == "query input reaches response"
    assert base.evidence_items == ()
    assert len(finding.evidence_items) == 1
    assert finding.evidence_items[0].fact is read
    assert finding.evidence_items[0].location == read.location


def test_finding_builder_preserves_gap_context(flask_basic: RepoViewProto) -> None:
    """Findings carry the route gap context used to interpret confidence."""
    route = flask_basic.routes.with_path("/inputs/query").one()

    finding = route.finding("inspect gap context")

    assert finding.gaps == route.gaps
    assert any(gap.kind is GapKind.INFERENCE_FAILURE for gap in finding.gaps)


def test_provider_inspection_lists_builtin_provider_patterns() -> None:
    """Provider authors can inspect built-in provider metadata and descriptors."""
    providers = {provider.meta.id: provider for provider in discover_builtin_provider_classes()}

    flask = providers["flask"]
    route_fqns = {
        fqn
        for pattern in flask.routes
        if isinstance(pattern, RouteDecorator)
        for fqn in _as_tuple(pattern.fqn)
    }

    assert flask.meta.library_fqn == "flask"
    assert "flask.Flask.route" in route_fqns
    assert "flask.Blueprint.route" in route_fqns
    assert len(flask.inputs) >= 20
    assert len(flask.effects) >= 20


def test_provider_inspection_identifies_active_fixture_providers(
    flask_basic_provider_result: ProviderEngineResult,
) -> None:
    """Provider matching reports which providers were active for a fixture app."""
    active = set(flask_basic_provider_result.active_provider_ids)
    matches_by_provider = Counter(
        match.provider_id for match in flask_basic_provider_result.matches
    )

    assert {"flask", "flask-login", "flask-wtf", "sqlalchemy"} <= active
    assert "django" not in active
    assert matches_by_provider["flask"] > 0
    assert matches_by_provider["sqlalchemy"] > 0


def test_provider_authoring_patterns_are_frozen() -> None:
    """Provider descriptors are immutable authoring records."""
    providers = {provider.meta.id: provider for provider in discover_builtin_provider_classes()}
    pattern = providers["flask"].routes[0]

    with pytest.raises(FrozenInstanceError):
        # The route-pattern union has no `description` field; the assignment is
        # expected to raise FrozenInstanceError at runtime regardless.
        pattern.description = "mutated"  # type: ignore[union-attr]


def test_gap_inspection_filters_repository_gaps_by_kind_and_file(
    django_basic: RepoViewProto,
) -> None:
    """Repository gaps can be grouped by kind and affected file."""
    unresolved = [gap for gap in django_basic.gaps if gap.kind is GapKind.SYMBOL_UNRESOLVED]
    urls_gaps = [gap for gap in unresolved if gap.affected_file == "urls.py"]

    assert len(urls_gaps) >= 2
    assert all(gap.origin_provider == "django" for gap in urls_gaps)
    assert any("Route handler function not found" in gap.message for gap in urls_gaps)


def test_gap_inspection_filters_context_by_function(flask_basic: RepoViewProto) -> None:
    """Function navigation scopes gap inspection to one handler context."""
    function = flask_basic.functions.with_fqn("flask_basic.app.input_query").one()
    app_py_gaps = [gap for gap in function.gaps if gap.affected_file == "app.py"]

    assert app_py_gaps
    assert all(gap.kind is GapKind.INFERENCE_FAILURE for gap in app_py_gaps)


def _as_tuple(value: str | tuple[str, ...]) -> tuple[str, ...]:
    return value if isinstance(value, tuple) else (value,)
