"""Route domain type, HttpMethod enum, and HTTP method helpers.

Routes are HTTP endpoints identified by Layer 2 (Semantic Layer)
interpreters.  They are **not directly constructable** by rule
authors -- they are produced by analyzing framework-specific patterns
(e.g. ``@app.route``) and made available through
:attr:`~flawed.repo.RepoView.routes`.

Each route provides three scoping levels for queries:

- :attr:`Route.body` -- only the handler function body
- :attr:`Route.reachable` -- transitively reachable code from the handler
- :attr:`Route.full_stack` -- including lifecycle hooks and middleware

Example::

    from flawed import open_repo
    from flawed.route import POST, accepting

    kb = open_repo("path/to/store")
    for route in kb.routes.where(accepting(POST)):
        print(route.endpoint, route.url_rule, route.methods)
        for read in route.reachable.reads(Json()):
            print(f"  reads {read.source}")
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from flawed.core import _short_loc
from flawed.evidence import Finding

if TYPE_CHECKING:
    from collections.abc import Callable

    from flawed.blueprint import Blueprint
    from flawed.core import AnalysisGap, Location, Provenance
    from flawed.function import Function
    from flawed.scopes import CodeScope


class HttpMethod(Enum):
    """Standard HTTP methods.

    Used in :attr:`Route.methods` as a ``frozenset[HttpMethod]`` and
    with the :func:`accepting` predicate factory for route filtering.
    Module-level aliases (``GET``, ``POST``, etc.) are provided for
    convenience.
    """

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


# Module-level aliases for convenience, importable directly:
#     from flawed.route import POST, GET
GET = HttpMethod.GET
"""Alias for ``HttpMethod.GET``."""

POST = HttpMethod.POST
"""Alias for ``HttpMethod.POST``."""

PUT = HttpMethod.PUT
"""Alias for ``HttpMethod.PUT``."""

PATCH = HttpMethod.PATCH
"""Alias for ``HttpMethod.PATCH``."""

DELETE = HttpMethod.DELETE
"""Alias for ``HttpMethod.DELETE``."""

OPTIONS = HttpMethod.OPTIONS
"""Alias for ``HttpMethod.OPTIONS``."""

HEAD = HttpMethod.HEAD
"""Alias for ``HttpMethod.HEAD``."""


@dataclass(frozen=True)
class Route:
    """An HTTP endpoint identified by the Semantic Layer.

    Created by Layer 2 interpreters by analyzing decorator patterns,
    URL rules, and handler function signatures.  Not directly
    constructable by rule authors.

    A route is the primary iteration target for per-route detectors::

        @detector("my-rule")
        def detect(kb: "RepoView") -> Iterator[Finding]:
            for route in kb.routes.where(accepting(POST)):
                # query route.body, route.reachable, or route.full_stack
                ...
    """

    endpoint: str
    """Framework endpoint name (e.g. ``"api.create_user"``, ``"profile"``)."""

    url_rule: str
    """URL rule pattern (e.g. ``"/users/<int:id>"``, ``"/profile"``)."""

    methods: frozenset[HttpMethod]
    """HTTP methods this endpoint accepts."""

    handler: Function
    """The handler function that processes requests to this endpoint."""

    group: str | None
    """Route group name (Flask blueprint, Django app, FastAPI router, etc.),
    or ``None`` if registered at the top level."""

    location: Location
    """Source location of the route registration (decorator, URL conf entry, etc.)."""

    provenance: Provenance
    """Semantic Layer provenance with supporting facts."""

    def __repr__(self) -> str:
        methods = "|".join(method.name for method in sorted(self.methods, key=lambda m: m.name))
        return (
            f"Route({methods} {self.url_rule} → {self.handler.name}, {_short_loc(self.location)})"
        )

    @property
    def name(self) -> str:
        """Endpoint name identifying this route (e.g. ``"profile"``, ``"api.create_user"``).

        Alias of :attr:`endpoint`, exposed so that every navigable domain object
        answers to ``.name`` uniformly during exploration -- the same identity
        accessor carried by :class:`~flawed.function.Function`,
        :class:`~flawed.blueprint.Blueprint`, ``Parameter``, and ``Decorator``.
        Always a real, non-empty value: the Semantic Layer derives every endpoint
        from a handler/registration name, never an unknown placeholder.
        """
        return self.endpoint

    @property
    def body(self) -> CodeScope:
        """Direct handler body as a queryable scope.

        Covers only statements inside the handler function itself.
        Does not include transitively called functions.
        """
        locals()
        raise RuntimeError("Route.body requires Semantic Layer context")

    @property
    def reachable(self) -> CodeScope:
        """Transitively reachable code from the handler.

        Includes the handler body plus all functions called directly
        or indirectly.  This is the most common scope for detection
        rules.
        """
        locals()
        raise RuntimeError("Route.reachable requires Semantic Layer context")

    @property
    def full_stack(self) -> CodeScope:
        """Reachable code including lifecycle hooks and middleware.

        Extends :attr:`reachable` to cover before-request hooks,
        after-request hooks, error handlers, and middleware that
        execute as part of the request lifecycle for this route.
        """
        locals()
        raise RuntimeError("Route.full_stack requires Semantic Layer context")

    def branch(self, method: HttpMethod | str) -> CodeScope | None:
        """Code scope for a single HTTP method branch, if present.

        Some handlers dispatch on the HTTP method internally
        (``if request.method == "POST": ...``).  Returns the
        :class:`~flawed.scopes.CodeScope` for the branch handling
        the given method, or ``None`` if no such branch is detected.
        """
        locals()
        raise RuntimeError("Route.branch requires Semantic Layer context")

    @property
    def gaps(self) -> tuple[AnalysisGap, ...]:
        """Analysis gaps affecting this route's handler and reachable code.

        Union of gaps from the handler function and all transitively
        reachable functions.  Automatically propagated into findings
        via :meth:`finding`.
        """
        locals()
        raise RuntimeError("Route.gaps requires Semantic Layer context")

    @property
    def lifecycle_hooks(self) -> tuple[Function, ...]:
        """Lifecycle hook handlers (before/after request, teardown) for this route.

        The framework-invoked handler functions that run around this route's
        handler -- app-scoped hooks plus hooks declared on its blueprint/router
        group (and any parent group it is nested under), owner-first then in
        deterministic order.  Returns an empty tuple when the route has no
        lifecycle hooks.  Each element is a navigable :class:`~flawed.function.Function`.

        Example::

            for hook in route.lifecycle_hooks:
                if hook.body.checks(category="AUTHENTICATION"):
                    ...
        """
        locals()
        raise RuntimeError("Route.lifecycle_hooks requires Semantic Layer context")

    @property
    def blueprint(self) -> Blueprint | None:
        """The route group (Flask blueprint, FastAPI router, ...) owning this route.

        Returns the :class:`~flawed.blueprint.Blueprint` this route is
        registered on, or ``None`` when the route is declared at the top
        level.  The blueprint carries the group's ``url_prefix`` and the full
        set of sibling routes::

            if route.blueprint is not None:
                siblings = route.blueprint.routes
        """
        locals()
        raise RuntimeError("Route.blueprint requires Semantic Layer context")

    def source(self, context: int = 3) -> str:
        """Return handler source text with surrounding context lines.

        Args:
            context: Number of lines before and after to include.
        """
        return self.handler.source(context=context)

    def finding(self, summary: str) -> Finding:
        """Start building a detection finding for this route.

        Returns a :class:`~flawed.evidence.Finding` pre-populated
        with this route's endpoint and location.  Chain ``.evidence()``
        calls to build the evidence trail::

            yield route.finding("Missing auth guard").evidence(read, "Unguarded input")
        """
        return Finding(
            route_endpoint=self.endpoint,
            summary=summary,
            location=self.location,
            gaps=self.gaps,
        )


def accepting(*methods: HttpMethod) -> Callable[[Route], bool]:
    """Predicate factory for filtering routes by accepted HTTP methods.

    Returns a callable that returns ``True`` for routes whose
    :attr:`Route.methods` intersect with the given methods.

    Example::

        from flawed.route import POST, PUT, accepting

        write_routes = kb.routes.where(accepting(POST, PUT))
    """
    method_set = frozenset(methods)

    def predicate(route: Route) -> bool:
        return bool(route.methods & method_set)

    return predicate
