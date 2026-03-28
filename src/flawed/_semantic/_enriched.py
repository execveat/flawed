"""Enriched domain objects with live navigation properties.

Layer 3 domain types (``Function``, ``Class``) are frozen dataclasses
whose navigation properties (``decorators``, ``gaps``, ``calls``, etc.)
require Semantic Layer context.  This module provides subclasses that
override those properties with concrete implementations backed by lookup maps
built during L2 construction.

The enriched types ARE the L3 types (via inheritance) so they satisfy
``isinstance`` checks and type annotations throughout the Rule API.

Private attributes are set via ``object.__setattr__`` after frozen
``__init__`` completes — this is the standard pattern for adding
non-field state to frozen dataclasses.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

from flawed.blueprint import Blueprint
from flawed.calls import CallSite
from flawed.class_ import Class
from flawed.flow import ValueHandle, _get_private, attach_flow_context
from flawed.function import Function, Parameter
from flawed.inputs import InputRead
from flawed.route import HttpMethod, Route

if TYPE_CHECKING:
    from flawed._semantic._collections import (
        ConcreteDecoratorCollection,
        ConcreteFunctionCollection,
        ConcreteRouteCollection,
    )
    from flawed._semantic._scope import ConcreteCodeScope
    from flawed.calls import Argument
    from flawed.core import AnalysisGap
    from flawed.inputs import InputSource


class EnrichedFunction(Function):
    """Function with live navigation backed by L2 lookup maps."""

    @property
    def decorators(self) -> ConcreteDecoratorCollection:  # type: ignore[override]
        """Decorators applied to this function."""
        return cast("ConcreteDecoratorCollection", object.__getattribute__(self, "_decorators"))

    @property
    def gaps(self) -> tuple[AnalysisGap, ...]:
        """Analysis gaps affecting this function."""
        return cast("tuple[AnalysisGap, ...]", object.__getattribute__(self, "_gaps"))

    @property
    def body(self) -> ConcreteCodeScope:  # type: ignore[override]
        """Direct function body as a queryable scope."""
        return cast("ConcreteCodeScope", object.__getattribute__(self, "_body"))

    @property
    def reachable(self) -> ConcreteCodeScope:  # type: ignore[override]
        """Transitively reachable code from this function."""
        return cast("ConcreteCodeScope", object.__getattribute__(self, "_reachable"))

    @property
    def calls(self) -> ConcreteFunctionCollection:
        """Functions called by this function (callees)."""
        return cast("ConcreteFunctionCollection", object.__getattribute__(self, "_calls"))

    @property
    def called_by(self) -> ConcreteFunctionCollection:
        """Functions that call this function (callers)."""
        return cast("ConcreteFunctionCollection", object.__getattribute__(self, "_called_by"))

    def parameter_named(self, name: str) -> Parameter:
        """Look up a parameter by name.

        Raises ``KeyError`` if no parameter with the given name exists.
        """
        for p in self.params:
            if p.name == name:
                return p
        raise KeyError(name)

    @classmethod
    def from_base(
        cls,
        fn: Function,
        *,
        decorators: ConcreteDecoratorCollection,
        gaps: tuple[AnalysisGap, ...],
        calls: ConcreteFunctionCollection,
        called_by: ConcreteFunctionCollection,
    ) -> EnrichedFunction:
        """Wrap a base Function with live navigation context."""
        obj = cls(
            fqn=fn.fqn,
            name=fn.name,
            params=fn.params,
            kind=fn.kind,
            parent_class=fn.parent_class,
            parent_function=fn.parent_function,
            location=fn.location,
            provenance=fn.provenance,
            overloads=fn.overloads,
        )
        object.__setattr__(obj, "_decorators", decorators)
        object.__setattr__(obj, "_gaps", gaps)
        object.__setattr__(obj, "_calls", calls)
        object.__setattr__(obj, "_called_by", called_by)
        return obj


class EnrichedRoute(Route):
    """Route with live navigation backed by L2 lookup maps.

    Overrides properties that require Semantic Layer context on the base
    ``Route`` with concrete implementations.  The semantic builder attaches
    body, reachable, and full-stack scopes after converting routes and
    lifecycle observations.
    """

    @property
    def body(self) -> ConcreteCodeScope:  # type: ignore[override]
        """Direct handler body as a queryable scope."""
        return cast("ConcreteCodeScope", object.__getattribute__(self, "_body_scope"))

    @property
    def reachable(self) -> ConcreteCodeScope:  # type: ignore[override]
        """Transitively reachable code from the handler."""
        return cast("ConcreteCodeScope", object.__getattribute__(self, "_reachable_scope"))

    @property
    def full_stack(self) -> ConcreteCodeScope:  # type: ignore[override]
        """Reachable code including lifecycle hooks and middleware."""
        return cast("ConcreteCodeScope", object.__getattribute__(self, "_full_stack_scope"))

    @property
    def gaps(self) -> tuple[AnalysisGap, ...]:
        """Analysis gaps affecting this route."""
        return cast("tuple[AnalysisGap, ...]", object.__getattribute__(self, "_gaps"))

    @property
    def lifecycle_hooks(self) -> tuple[Function, ...]:
        """Lifecycle hook handlers that run for this route.

        The before/after-request (and teardown) handlers attributed to this
        route -- app-scoped hooks plus hooks declared on its blueprint/router
        group (including parent groups it is nested under).  Empty when the
        route has no lifecycle hooks.  Surfacing the handler functions directly
        means a rule author can navigate each (``.body``, ``.name``, ...)
        instead of inferring hook presence from callee FQNs (FLAW-129).
        """
        return cast("tuple[Function, ...]", object.__getattribute__(self, "_lifecycle_hooks"))

    @property
    def blueprint(self) -> Blueprint | None:
        """The route group owning this route, or ``None`` if top-level."""
        return cast("Blueprint | None", object.__getattribute__(self, "_blueprint"))

    def branch(self, method: HttpMethod | str) -> ConcreteCodeScope | None:  # type: ignore[override]
        """Code scope for a single HTTP method branch when one is modeled."""
        return self.body.branch(method)

    def source(self, context: int = 3) -> str:
        """Return handler source text with surrounding context lines."""
        repo_path: str = object.__getattribute__(self, "_repo_path")
        loc = self.location
        file_path = Path(repo_path) / loc.file
        try:
            lines = file_path.read_text().splitlines()
        except (OSError, UnicodeDecodeError):
            return f"<source unavailable: {loc.file}:{loc.line}>"
        start = max(0, loc.line - 1 - context)
        end_line = loc.end_line if loc.end_line is not None else loc.line
        end = min(len(lines), end_line + context)
        return "\n".join(lines[start:end])


class EnrichedBlueprint(Blueprint):
    """Blueprint with its routes attached by the semantic builder."""

    @property
    def routes(self) -> ConcreteRouteCollection:
        """Routes registered on this group."""
        return cast("ConcreteRouteCollection", object.__getattribute__(self, "_routes"))


class EnrichedCallSite(CallSite):
    """CallSite with working argument lookup."""

    def argument(self, index: int) -> Argument:
        """Look up an argument by 0-based positional index."""
        if index < 0 or index >= len(self.arguments):
            raise IndexError(index)
        return self.arguments[index]

    def keyword_argument(self, name: str) -> Argument | None:
        """Look up an argument by keyword name."""
        for arg in self.arguments:
            if arg.name == name:
                return arg
        return None


class EnrichedValueHandle(ValueHandle):
    """ValueHandle that knows its originating input source."""

    def derived_from(self, source: InputSource) -> bool:
        """Check if this value is derived from the given input source."""
        return super().derived_from(source)

    def flows_to(self, target: ValueHandle) -> bool:
        """Return True if this value reaches *target*."""
        return super().flows_to(target)

    def flows_from(self, source: ValueHandle) -> bool:
        """Return True if this value comes from *source*."""
        return super().flows_from(source)


class EnrichedInputRead(InputRead):
    """InputRead with a working value handle that knows its source."""

    @property
    def value(self) -> EnrichedValueHandle:
        """Handle carrying the input source for derived_from queries."""
        handle = cast("EnrichedValueHandle", object.__getattribute__(self, "_value_handle"))
        trace_flow = _get_private(self, "_trace_flow") or _get_private(
            self.function, "_trace_flow"
        )
        derived_from = _get_private(self, "_derived_from") or _get_private(
            self.function, "_derived_from"
        )
        attach_flow_context(
            handle,
            trace_flow=trace_flow,
            derived_from=derived_from,
            function_fqn=self.function.fqn,
            input_source=self.source,
        )
        return handle

    @classmethod
    def from_base(cls, read: InputRead) -> EnrichedInputRead:
        """Wrap a plain InputRead with an enriched value handle."""
        obj = cls(
            source=read.source,
            access_pattern=read.access_pattern,
            cardinality=read.cardinality,
            function=read.function,
            location=read.location,
            expression=read.expression,
            provenance=read.provenance,
            value_type=read.value_type,
        )
        handle = EnrichedValueHandle(
            location=read.location,
            expression=read.expression,
        )
        object.__setattr__(handle, "_input_source", read.source)
        object.__setattr__(obj, "_value_handle", handle)
        return obj


class EnrichedClass(Class):
    """Class with live navigation backed by L2 lookup maps."""

    @property
    def decorators(self) -> ConcreteDecoratorCollection:  # type: ignore[override]
        """Decorators applied to this class."""
        return cast("ConcreteDecoratorCollection", object.__getattribute__(self, "_decorators"))

    @property
    def methods(self) -> ConcreteFunctionCollection:
        """Methods defined directly on this class as Function objects."""
        return cast("ConcreteFunctionCollection", object.__getattribute__(self, "_methods"))

    @property
    def is_abstract(self) -> bool:
        """Whether this class was marked abstract by L1."""
        return cast("bool", object.__getattribute__(self, "_is_abstract"))

    @property
    def gaps(self) -> tuple[AnalysisGap, ...]:
        """Analysis gaps affecting this class."""
        return cast("tuple[AnalysisGap, ...]", object.__getattribute__(self, "_gaps"))

    @classmethod
    def from_base(
        cls,
        klass: Class,
        *,
        decorators: ConcreteDecoratorCollection | None = None,
        methods: ConcreteFunctionCollection,
        is_abstract: bool,
        gaps: tuple[AnalysisGap, ...],
    ) -> EnrichedClass:
        """Wrap a base Class with live navigation context."""
        obj = cls(
            fqn=klass.fqn,
            name=klass.name,
            bases=klass.bases,
            mro=klass.mro,
            method_names=klass.method_names,
            inherited_methods=klass.inherited_methods,
            location=klass.location,
            provenance=klass.provenance,
        )
        if decorators is None:
            from flawed._semantic._collections import ConcreteDecoratorCollection

            decorators = ConcreteDecoratorCollection(())
        object.__setattr__(obj, "_decorators", decorators)
        object.__setattr__(obj, "_methods", methods)
        object.__setattr__(obj, "_is_abstract", is_abstract)
        object.__setattr__(obj, "_gaps", gaps)
        return obj
