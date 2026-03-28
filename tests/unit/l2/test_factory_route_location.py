"""FLAW-280 regression guard: nested factory routes keep distinct, navigable locations.

Routes declared with ``@app.route`` INSIDE ``create_app()`` must each anchor on
their own decorator line. They historically collapsed onto a single shared line —
the ``@login_manager.unauthorized_handler`` decorator immediately preceding them
(reproduced on a real Flask app where 15 distinct route findings
all pointed at line 614 and were non-navigable).

Root cause was route *location-attribution* in L2, NOT the L1 function-location
bug the original ticket hypothesised: L1 always recorded each nested ``def`` and
decorator on its correct line (verified directly via the structural extractor).
FLAW-301's AST-only ``_index`` rewrite fixed the downstream attribution. Verified
fixed on the real-world repo (8/8 nested routes correctly located,
zero line collisions). This spec pins the property so it cannot silently regress.

Fixture ``semantic/flask_factory_decorator_routes`` mirrors the repro shape: an
``unauthorized_handler`` decorated function immediately before four ``@app.route``
views nested in ``create_app``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tests.helpers.artifact_fixtures import load_fixture

if TYPE_CHECKING:
    from flawed.repo import RepoView

_FACTORY_ENDPOINTS = {"logout", "set_language", "login", "queue_status"}


@pytest.fixture(scope="session")
def factory_decorator_routes() -> RepoView:
    return load_fixture("semantic/flask_factory_decorator_routes")


def _factory_routes(repo: RepoView) -> list:
    return [r for r in repo.routes if r.endpoint in _FACTORY_ENDPOINTS]


@pytest.mark.xfail(
    reason="FLAW-362: nested factory @app.route detection regressed; exposed by the "
    "fixture regen (stale fixtures had masked it). Remove this xfail when routes return.",
    strict=True,
)
def test_all_nested_routes_detected(factory_decorator_routes: RepoView) -> None:
    """FN guard: every nested route is still extracted (none lost to the factory)."""
    endpoints = {r.endpoint for r in _factory_routes(factory_decorator_routes)}
    assert endpoints == _FACTORY_ENDPOINTS


def test_nested_routes_have_distinct_locations(factory_decorator_routes: RepoView) -> None:
    """The bug: all routes collapsed onto one shared line. Each must be distinct."""
    routes = _factory_routes(factory_decorator_routes)
    lines = [r.location.line for r in routes]
    assert len(set(lines)) == len(lines), f"routes collapsed onto shared line(s): {sorted(lines)}"


def test_routes_do_not_anchor_on_preceding_decorator(
    factory_decorator_routes: RepoView,
) -> None:
    """The real app's ``flask_app.py:614`` was the ``@login_manager.unauthorized_handler`` line
    that all nested routes wrongly collapsed onto. No route may anchor there."""
    repo = factory_decorator_routes
    unauth = next(f for f in repo.functions if f.name == "unauthorized_handler")
    forbidden = {unauth.location.line, unauth.location.line - 1}  # def + its decorator line
    for r in _factory_routes(repo):
        assert r.location.line not in forbidden, (
            f"route {r.endpoint!r} wrongly anchored at unauthorized_handler line {r.location.line}"
        )


def test_route_anchors_above_its_handler(factory_decorator_routes: RepoView) -> None:
    """Navigability: each route anchors on its ``@app.route`` decorator, immediately
    above the handler ``def`` — so a finding points at the route, not elsewhere."""
    for r in _factory_routes(factory_decorator_routes):
        assert r.handler is not None
        assert r.location.line < r.handler.location.line
