"""Flask-RESTX route detection via the package-root import idiom.

Apps that do ``from flask_restx import Namespace, Resource`` (the dominant
real-world idiom — a whole ``api/v1`` surface) produced ZERO routes.
Two independent causes were pinned:

1. The provider declared only the *submodule* FQNs
   (``flask_restx.resource.Resource``, ``flask_restx.namespace.Namespace.route``),
   not the package-root spellings the engine resolves root imports to
   (``flask_restx.Resource`` etc.). FIXED here by declaring both as FQN-alias
   tuples (mirroring ``flask_core``'s ``flask.Flask.route`` /
   ``flask.Blueprint.route``). The Resource *base class* now resolves and matches.

2. The route *registration* (``@ns.route`` / ``ns.add_resource``) is an attribute
   call on a ``Namespace`` **instance**. Without receiver-type inference for that
   instance, the engine resolves the call to the module-local name
   (``<module>.ns.route``), not ``flask_restx.Namespace.route``, so no FQN can
   match. This requires receiver-type inference of a library-class instance
   (FLAW-266) and is independent of the provider FQNs. The end-to-end route
   assertions below are therefore ``xfail`` in the (uninstalled) local
   environment; they should pass once instance receiver-typing lands, and are
   validated meanwhile by an installed-env sandbox re-scan of a real app.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flawed.route import HttpMethod

if TYPE_CHECKING:
    from flawed.repo import RepoView
    from flawed.route import Route


def _routes_for_handler_suffix(repo: RepoView, suffix: str) -> list[Route]:
    return [r for r in repo.routes if r.handler.fqn.endswith(suffix)]


@pytest.mark.xfail(
    reason=(
        "flask-restx route registration is an attribute call on a Namespace "
        "instance (@ns.route / ns.add_resource); resolving it to "
        "flask_restx.Namespace.route needs receiver-type inference of the "
        "library-class instance (FLAW-266). The provider FQN aliases fixed by "
        "this change handle the Resource base-class match but cannot match the "
        "module-local registration call. Validate end-to-end on an installed "
        "sandbox (real-app re-scan)."
    ),
    strict=False,
)
class TestFlaskRestxRootReexportRoutes:
    """`@ns.route` / `ns.add_resource` on a `Resource` imported from the root."""

    def test_resource_get_route_detected(self, flask_restx_api: RepoView) -> None:
        """The Resource's get() surfaces as a GET route (was invisible: 0 routes)."""
        matches = _routes_for_handler_suffix(flask_restx_api, "UserResource.get")
        seen = [
            (r.url_rule, sorted(m.value for m in r.methods), r.handler.fqn)
            for r in flask_restx_api.routes
        ]
        assert matches, f"flask-restx Resource.get route not detected. Routes seen: {seen}"
        get_route = next(r for r in matches if HttpMethod.GET in r.methods)
        assert get_route.url_rule == "/users/<int:user_id>"
        assert get_route.methods == frozenset({HttpMethod.GET})

    def test_resource_delete_route_scoped_to_delete(self, flask_restx_api: RepoView) -> None:
        """DELETE is dispatched to delete(), not get() (class-view method split)."""
        matches = _routes_for_handler_suffix(flask_restx_api, "UserResource.delete")
        assert matches, "flask-restx Resource.delete route not detected"
        delete_route = next(r for r in matches if HttpMethod.DELETE in r.methods)
        assert delete_route.url_rule == "/users/<int:user_id>"
        assert delete_route.methods == frozenset({HttpMethod.DELETE})


def _all_fqns(value: str | tuple[str, ...]) -> frozenset[str]:
    return frozenset((value,) if isinstance(value, str) else value)


class TestFlaskRestxRootReexportAliasesDeclared:
    """Regression guard: every public flask-restx name re-exported at the package
    root must be declared alongside its submodule FQN, or root-import apps go
    invisible. Pins the exact aliases this fix added."""

    def test_resource_base_and_route_aliases(self) -> None:
        from flawed._semantic.providers.flask_restx import FlaskRestxProvider

        route_fqns: set[str] = set()
        class_view_bases: set[str] = set()
        for pattern in FlaskRestxProvider.routes:
            if hasattr(pattern, "base_class_fqn"):
                class_view_bases |= _all_fqns(pattern.base_class_fqn)
            if hasattr(pattern, "fqn"):
                route_fqns |= _all_fqns(pattern.fqn)

        # Resource base class — root re-export AND submodule spelling.
        assert {"flask_restx.Resource", "flask_restx.resource.Resource"} <= class_view_bases
        # @ns.route / ns.add_resource — root spellings present.
        assert "flask_restx.Namespace.route" in route_fqns
        assert "flask_restx.Namespace.add_resource" in route_fqns
