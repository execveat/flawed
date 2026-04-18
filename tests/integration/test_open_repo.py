"""End-to-end tests for the public ``open_repo`` entry point.

Uses session-scoped ``flask_basic`` fixture from root conftest.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed import RepoView
from flawed.route import HttpMethod

if TYPE_CHECKING:
    from flawed.repo import RepoView as RepoViewProto


def test_open_repo_returns_runtime_repo_view_protocol(flask_basic: RepoViewProto) -> None:
    assert isinstance(flask_basic, RepoView)


def test_open_repo_populates_route_function_and_class_collections(
    flask_basic: RepoViewProto,
) -> None:
    assert len(flask_basic.routes) > 0
    assert len(flask_basic.functions) > 0
    assert len(flask_basic.classes) > 0


def test_open_repo_routes_are_semantically_resolved(flask_basic: RepoViewProto) -> None:
    routes = {route.endpoint: route for route in flask_basic.routes}

    assert routes["index"].url_rule == "/"
    assert routes["index"].methods == frozenset({HttpMethod.GET})
    assert routes["index"].handler.fqn == "flask_basic.app.index"
    assert routes["users"].methods == frozenset({HttpMethod.GET, HttpMethod.POST})


def test_open_repo_route_exposes_name_identity(flask_basic: RepoViewProto) -> None:
    """Route answers to ``.name`` like every other navigable domain object.

    Regression for FLAW-170: ``getattr(route, "name", "?")`` read ``"?"`` during
    exploration because ``Route`` exposed its identity only as ``endpoint`` while
    ``Function``/``Blueprint``/``Parameter``/``Decorator`` all expose ``.name``.
    ``Route.name`` is the endpoint and is always a real, non-empty value.
    """
    assert len(flask_basic.routes) > 0
    for route in flask_basic.routes:
        assert route.name == route.endpoint
        assert route.name not in ("", "?")
    by_name = {route.name: route for route in flask_basic.routes}
    assert by_name["index"].url_rule == "/"


def test_open_repo_collections_support_query_api(flask_basic: RepoViewProto) -> None:
    assert flask_basic.functions.named("index").one().fqn == "flask_basic.app.index"
    assert flask_basic.classes.named("FlaskBasicModel").one().fqn == (
        "flask_basic.models.FlaskBasicModel"
    )
