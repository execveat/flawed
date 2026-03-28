"""Blueprint -- a route group (Flask blueprint, FastAPI router, Django app).

A :class:`Blueprint` is the framework's organizational unit for a set of
routes.  It is produced by the Semantic Layer from router-group constructor
assignments; rule authors never construct one directly.  Reach blueprints via
:attr:`~flawed.repo.RepoView.blueprints` or :attr:`~flawed.route.Route.blueprint`.

Example::

    for bp in kb.blueprints:
        print(bp.name, bp.url_prefix, len(bp.routes))

    route = kb.routes.first()
    if route.blueprint is not None:
        print(route.blueprint.name)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flawed.collections import RouteCollection


@dataclass(frozen=True)
class Blueprint:
    """A route group identified by the Semantic Layer.

    The blueprint's identity is its :attr:`name` (the declared group name,
    e.g. ``"admin"``).  Routes registered on the group are reachable via
    :attr:`routes`, and each :class:`~flawed.route.Route` links back through
    :attr:`~flawed.route.Route.blueprint`.

    Not directly constructable by rule authors.
    """

    name: str
    """Group name -- the blueprint/router variable's declared name."""

    url_prefix: str | None
    """Effective URL prefix (constructor kwarg or mount-call override), or
    ``None`` when absent or not statically resolvable."""

    @property
    def routes(self) -> RouteCollection:
        """Routes registered on this group.

        Returns a :class:`~flawed.collections.RouteCollection` that can be
        filtered with ``.where()``, ``.accepting()``, etc.
        """
        locals()
        raise RuntimeError("Blueprint.routes requires Semantic Layer context")

    def __repr__(self) -> str:
        prefix = f", {self.url_prefix}" if self.url_prefix else ""
        try:
            count = len(self.routes)
        except RuntimeError:
            return f"Blueprint({self.name}{prefix})"
        noun = "route" if count == 1 else "routes"
        return f"Blueprint({self.name}{prefix}, {count} {noun})"
