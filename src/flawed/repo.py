"""RepoView -- the top-level entry point for exploring an analyzed repository.

:class:`RepoView` is returned by :func:`~flawed.open_repo` and is the
single entry point for all navigation and detection.  It provides
access to the three main collections (routes, functions, classes) and
on-demand data-flow tracing.

Example::

    from flawed import open_repo

    kb = open_repo("/path/to/analysis-store/repos/slug/snapshot")
    kb.routes  # RouteCollection -- all identified HTTP endpoints
    kb.functions  # FunctionCollection -- every function in the repo
    kb.classes  # ClassCollection -- every class in the repo
    kb.trace_flow(source_loc, sink_loc)  # on-demand data-flow tracing
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from flawed.collections import (
        BlueprintCollection,
        ClassCollection,
        FunctionCollection,
        RouteCollection,
    )
    from flawed.core import AnalysisGap, Location
    from flawed.disagreement import TypeDisagreement
    from flawed.flow import FlowTrace


@runtime_checkable
class RepoView(Protocol):
    """Top-level navigation object returned by ``open_repo``.

    The single entry point for all Rule API queries.  Rule authors
    receive a ``RepoView`` as the argument to their detector function
    and use it to navigate routes, functions, and classes.

    Example::

        @detector("my-rule")
        def detect(kb: "RepoView") -> Iterator[Finding]:
            for route in kb.routes.where(accepting(POST)):
                ...
    """

    path: str
    """Path to the analyzed repository (or analysis store snapshot)."""

    snapshot: str | None
    """Git commit hash of the analyzed snapshot, or ``None`` if unknown."""

    @property
    def routes(self) -> RouteCollection:
        """All HTTP routes identified in the repository.

        Returns a :class:`~flawed.collections.RouteCollection`
        that can be filtered with ``.where()``, ``.accepting()``,
        ``.in_group()``, etc.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @property
    def functions(self) -> FunctionCollection:
        """All functions discovered in the repository.

        Returns a :class:`~flawed.collections.FunctionCollection`
        that can be filtered with ``.named()``, ``.with_fqn()``,
        ``.in_file()``, ``.decorated_with()``, etc.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @property
    def classes(self) -> ClassCollection:
        """All classes discovered in the repository."""
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @property
    def blueprints(self) -> BlueprintCollection:
        """All route groups (Flask blueprints, FastAPI routers, ...) in the repo.

        Returns a :class:`~flawed.collections.BlueprintCollection`.  Each
        :class:`~flawed.blueprint.Blueprint` carries its ``url_prefix`` and the
        routes registered on it; individual routes link back via
        :attr:`~flawed.route.Route.blueprint`.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @property
    def gaps(self) -> tuple[AnalysisGap, ...]:
        """Repository-level analysis gaps produced during semantic conversion."""
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @property
    def type_disagreements(self) -> tuple[TypeDisagreement, ...]:
        """Concrete type-checker disagreement signals in the repository."""
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def trace_flow(self, source: Location, sink: Location) -> FlowTrace:
        """Trace data flow between two specific source locations.

        Returns a :class:`~flawed.flow.FlowTrace` with the full
        path of :class:`~flawed.flow.FlowStep` objects and a
        ``reachable`` flag.

        Args:
            source: The origin location.
            sink: The destination location.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")
