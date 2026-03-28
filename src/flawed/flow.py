"""Value flow tracking handles and trace results.

A :class:`ValueHandle` is **not** a plain value -- it is an opaque
handle that carries an engine reference for tracking how a value
propagates through the program.  Handles are available on:

- :attr:`~flawed.inputs.InputRead.value`
- :attr:`~flawed.effects.Effect.target` and ``.value``
- :attr:`~flawed.calls.CallSite.return_value`
- :attr:`~flawed.calls.Argument.value`
- :attr:`~flawed.conditions.Condition.left` and ``.right``

Flow queries have two scopes:

1. **Intra-function** (pre-computed) -- flows within a single function
   body are resolved statically during analysis and are always
   available.
2. **Interprocedural** (structural) -- flows across function boundaries
   use the call graph and are available when the engine has computed
   interprocedural data flow.

Example::

    read = route.reachable.reads(Json()).first()
    effect = route.reachable.effects(Mutation.write()).first()

    read.value.flows_to(effect.target)  # does the read reach the effect?
    effect.target.derived_from(PathParam())  # traced back to URL path?

:class:`FlowTrace` and :class:`FlowStep` provide detailed path
information when tracing flow between two specific points via
:meth:`~flawed.repo.RepoView.trace_flow`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from flawed.core import _short_expr, _short_loc

if TYPE_CHECKING:
    from collections.abc import Iterable

    from flawed.core import AnalysisGap, Location
    from flawed.correlation import InputEquivalence
    from flawed.inputs import InputRead, InputSource


_TraceFlow = Callable[["ValueHandle", "ValueHandle"], "FlowTrace"]
_PreservesWholeValue = Callable[["ValueHandle", "ValueHandle"], "ValuePreservationResult"]
_DerivedFrom = Callable[["ValueHandle", "InputSource"], bool]
_TraceDerivedFrom = Callable[["ValueHandle", "InputSource"], "FlowTrace"]


@dataclass(frozen=True)
class ValueHandle:
    """Opaque handle for tracking value flow through the program.

    Not a plain value -- carries an engine reference that enables
    flow queries.  Obtained from domain objects, never constructed
    directly by rule authors.

    The three flow query methods answer different questions:

    - :meth:`flows_to` -- forward: does this value reach the target?
    - :meth:`flows_from` -- backward: does this value come from the source?
    - :meth:`derived_from` -- provenance: is this value derived from a
      specific input source type?

    The boolean ``flows_to`` / ``flows_from`` facades each have a
    gap-carrying sibling -- :meth:`trace_flow_to` / :meth:`trace_flow_from`
    -- that returns the underlying :class:`FlowTrace` (path *and* analysis
    gaps) instead of collapsing it to ``bool``.  A rule that must tell
    "proven no flow" apart from "could not analyze this path" uses those.
    """

    location: Location
    """Source location where this value was observed."""

    expression: str
    """Source text of the expression producing this value."""

    def __repr__(self) -> str:
        return f"ValueHandle({_short_expr(self.expression)}, {_short_loc(self.location)})"

    @property
    def source(self) -> InputSource | None:
        """The typed input source this value was read from, or ``None``.

        A handle obtained from :attr:`~flawed.inputs.InputRead.value` carries
        the originating :class:`~flawed.inputs.InputSource`; this exposes it as
        a typed member so a rule can ask *what kind of input* a value is
        (``handle.source``, ``handle.source.identifier``) instead of reaching
        for private state.  Returns ``None`` for handles built without an input
        source (intermediate flow values, test/helper handles).

        Note this is the *origin input container* of the value, distinct from
        the ``source`` parameter of :meth:`flows_from`/:meth:`flows_to`, which
        name another :class:`ValueHandle`.
        """
        return cast("InputSource | None", _get_private(self, "_input_source"))

    def flows_to(self, target: ValueHandle) -> bool:
        """Return True if this value flows to the target.

        Checks whether there is a data-flow path from this handle to
        the target handle, combining intra-function and interprocedural
        analysis.

        This is the boolean projection of :meth:`trace_flow_to`: it
        collapses the underlying :class:`FlowTrace` to its
        :attr:`~FlowTrace.reachable` flag, discarding any analysis gaps.
        A rule that must distinguish "proven no flow" from "could not
        analyze this path" should call :meth:`trace_flow_to` instead and
        inspect :attr:`~FlowTrace.gaps` (the project's false-negative-first
        priority).

        Example::

            if read.value.flows_to(effect.target):
                print("User input reaches the write target")
        """
        return self.trace_flow_to(target).reachable

    def flows_from(self, source: ValueHandle) -> bool:
        """Return True if this value flows from the source.

        The reverse of :meth:`flows_to`: ``a.flows_from(b)`` is
        equivalent to ``b.flows_to(a)``.
        """
        return source.flows_to(self)

    def trace_flow_to(self, target: ValueHandle) -> FlowTrace:
        """Gap-carrying counterpart of :meth:`flows_to`.

        Returns the full :class:`FlowTrace` -- the resolved path *and* any
        :class:`~flawed.core.AnalysisGap` objects the engine hit while
        attempting the trace -- instead of collapsing it to a ``bool``.
        This lets a rule tell three states apart, which :meth:`flows_to`
        cannot:

        - ``reachable`` is True -- a data-flow path was proven.
        - ``reachable`` is False and ``gaps`` is empty -- the engine proved
          there is no path.
        - ``reachable`` is False and ``gaps`` is non-empty -- the engine
          could **not** analyze the path (e.g. an unresolved callee).  Per
          flawed's false-negative-first priority, a rule should treat this
          as an honest :class:`~flawed.core.AnalysisGap`, never as a
          confident "no flow".

        Handles built without Semantic-Layer flow context (in tests or rule
        helpers) carry no analysis that could be incomplete, so they yield a
        gap-free unreachable trace -- mirroring
        :meth:`preserves_whole_value_to`.

        Example::

            trace = read.value.trace_flow_to(effect.target)
            if trace.reachable:
                yield route.finding("user input reaches the write target")
            elif trace.gaps:
                # Could not analyze this path -- surface as a gap, never a
                # silent negative.
                ...
        """
        if self.same_origin(target):
            return FlowTrace(source=self, sink=target, steps=(), reachable=True)

        trace_flow = _trace_flow_for(self, target)
        if trace_flow is None:
            return FlowTrace(source=self, sink=target, steps=(), reachable=False)
        return trace_flow(self, target)

    def trace_flow_from(self, source: ValueHandle) -> FlowTrace:
        """Gap-carrying counterpart of :meth:`flows_from`.

        The reverse of :meth:`trace_flow_to`: ``a.trace_flow_from(b)`` is
        equivalent to ``b.trace_flow_to(a)`` and returns that same
        :class:`FlowTrace` (source ``b``, sink ``a``).
        """
        return source.trace_flow_to(self)

    def derived_from(self, source: InputSource) -> bool:
        """Return True if this value is derived from the given input source.

        Traces backwards from this handle to determine whether any
        input read matching the given source type contributes to this
        value.

        This is the boolean projection of :meth:`trace_derived_from`: it
        collapses the result to its :attr:`~FlowTrace.reachable` flag,
        discarding any analysis gaps.  A rule that must distinguish "no
        matching provenance" from "could not analyze the provenance" should
        call :meth:`trace_derived_from` instead and inspect
        :attr:`~FlowTrace.gaps` (the project's false-negative-first priority).

        Example::

            if effect.target.derived_from(PathParam()):
                print("Write target comes from URL path parameter")
        """
        return self.trace_derived_from(source).reachable

    def trace_derived_from(self, source: InputSource) -> FlowTrace:
        """Gap-carrying counterpart of :meth:`derived_from`.

        Returns a :class:`FlowTrace` describing the provenance query instead
        of collapsing it to a ``bool``, letting a rule tell three states apart
        (mirroring :meth:`trace_flow_to`):

        - ``reachable`` is True -- a matching input read was proven to reach
          this value; the trace's :attr:`~FlowTrace.source` is that input's
          value handle and its :attr:`~FlowTrace.steps` are the proven path.
        - ``reachable`` is False and ``gaps`` is empty -- no matching input
          read reaches this value.
        - ``reachable`` is False and ``gaps`` is non-empty -- the engine could
          **not** analyze the provenance of some matching read (e.g. an
          unresolved callee on the path).  Per flawed's false-negative-first
          priority a rule should treat this as an honest
          :class:`~flawed.core.AnalysisGap`, never as a confident "no
          provenance".

        Handles built without Semantic-Layer flow context yield a gap-free
        unreachable trace, mirroring :meth:`trace_flow_to`.

        Example::

            trace = effect.target.trace_derived_from(PathParam())
            if trace.reachable:
                yield route.finding("write target comes from URL path parameter")
            elif trace.gaps:
                # Could not analyze provenance -- surface as a gap, never a
                # silent negative.
                ...
        """
        from flawed.inputs import InputSource

        input_source = _get_private(self, "_input_source")
        if isinstance(input_source, InputSource) and input_source.matches(source):
            return FlowTrace(source=self, sink=self, steps=(), reachable=True)

        trace_derived = cast("_TraceDerivedFrom | None", _get_private(self, "_trace_derived_from"))
        if trace_derived is not None:
            return trace_derived(self, source)

        # No gap-carrying callback attached: fall back to the boolean provenance
        # callback so ``derived_from`` never silently regresses to ``False``
        # when only the legacy callback is present.  The bool callback cannot
        # report gaps, so the projected trace is gap-free -- conservative, but
        # it never fails open.
        derived_from = cast("_DerivedFrom | None", _get_private(self, "_derived_from"))
        if derived_from is None:
            return FlowTrace(source=self, sink=self, steps=(), reachable=False)
        return FlowTrace(source=self, sink=self, steps=(), reachable=derived_from(self, source))

    def same_origin(self, other: ValueHandle) -> bool:
        """Return True when two handles refer to the same observed value."""
        return self.location == other.location and self.expression == other.expression

    def shares_origin(
        self,
        other: ValueHandle,
        *,
        among: Iterable[InputRead],
        equivalence: InputEquivalence | None = None,
    ) -> bool:
        """Return True when this value and *other* derive from the same logical input.

        The same-logical-entity correlation primitive (FLAW-126): a detection
        rule uses this to assert that two derivations operate on the *same*
        request value, instead of hand-rolling key intersection.

        Origins are resolved by tracing each handle's
        :meth:`derived_from` provenance against the candidate input reads in
        *among* (typically ``route.reachable.reads()``) -- a value's origin is
        not self-describing, so the universe of reads to consider must be
        supplied. *equivalence* selects how strict "same input" is and defaults
        to :attr:`~flawed.correlation.InputEquivalence.EXACT` (same source type
        and key). See :mod:`flawed.correlation`.

        Example::

            reads = list(route.reachable.reads())
            if lowered.shares_origin(stripped, among=reads):
                yield route.finding("same value normalized two ways")
        """
        from flawed.correlation import InputEquivalence, value_inputs

        if equivalence is None:
            equivalence = InputEquivalence.EXACT
        candidates = list(among)
        mine = value_inputs(self, candidates, equivalence)
        if not mine:
            return False
        return bool(mine & value_inputs(other, candidates, equivalence))

    def preserves_whole_value_to(self, target: ValueHandle) -> ValuePreservationResult:
        """Return whether this exact whole value reaches *target* unchanged.

        Unlike :meth:`flows_to`, this is a preservation query: it does not treat
        embedded or same-line expressions as equivalent to the source value, and
        Layer 2 rejects paths that pass through transformation edges.
        """
        if self.same_origin(target):
            return ValuePreservationResult(preserved=True)

        preserves = _preserves_whole_value_for(self, target)
        if preserves is None:
            return ValuePreservationResult(preserved=False)
        return preserves(self, target)


def attach_flow_context(
    handle: ValueHandle,
    *,
    trace_flow: object | None = None,
    preserves_whole_value: object | None = None,
    derived_from: object | None = None,
    trace_derived_from: object | None = None,
    function_fqn: str | None = None,
    input_source: InputSource | None = None,
    broad_sink: bool = False,
) -> ValueHandle:
    """Attach Semantic Layer flow callbacks to a handle.

    The public handle remains a frozen dataclass; Layer 2 attaches opaque
    private callbacks when it creates handles for analyzed code. Handles
    constructed directly by tests or rule helpers simply return conservative
    ``False`` answers for flow queries.
    """
    if trace_flow is not None:
        object.__setattr__(handle, "_trace_flow", trace_flow)
    if preserves_whole_value is not None:
        object.__setattr__(handle, "_preserves_whole_value", preserves_whole_value)
    if derived_from is not None:
        object.__setattr__(handle, "_derived_from", derived_from)
    if trace_derived_from is not None:
        object.__setattr__(handle, "_trace_derived_from", trace_derived_from)
    if function_fqn is not None:
        object.__setattr__(handle, "_function_fqn", function_fqn)
    if input_source is not None:
        object.__setattr__(handle, "_input_source", input_source)
    if broad_sink:
        object.__setattr__(handle, "_broad_sink", True)
    return handle


def _trace_flow_for(source: ValueHandle, target: ValueHandle) -> _TraceFlow | None:
    trace_flow = _get_private(source, "_trace_flow")
    if trace_flow is None:
        trace_flow = _get_private(target, "_trace_flow")
    return cast("_TraceFlow | None", trace_flow)


def _preserves_whole_value_for(
    source: ValueHandle, target: ValueHandle
) -> _PreservesWholeValue | None:
    preserves = _get_private(source, "_preserves_whole_value")
    if preserves is None:
        preserves = _get_private(target, "_preserves_whole_value")
    return cast("_PreservesWholeValue | None", preserves)


def _get_private(obj: object | None, name: str) -> object | None:
    """Read a private attribute set via ``object.__setattr__`` on a frozen dataclass.

    Returns ``None`` when *obj* is ``None`` or when the attribute does not exist.
    This is the single canonical helper for accessing opaque private state
    attached to frozen domain objects — do not duplicate it elsewhere.
    """
    if obj is None:
        return None
    try:
        value: object = object.__getattribute__(obj, name)
    except AttributeError:
        return None
    else:
        return value


def make_value_handle(
    *,
    owner: object,
    function: object | None,
    location: Location,
    expression: str,
    input_source: InputSource | None = None,
    broad_sink: bool = False,
) -> ValueHandle:
    """Create a :class:`ValueHandle` with flow context from a domain object.

    This is the canonical factory for the value-handle-construction pattern
    shared by every L3 domain type.  It resolves ``_trace_flow`` and
    ``_derived_from`` from *owner* with *function* as fallback, creates the
    handle, and attaches flow context in one call.

    Args:
        owner: The domain object whose ``.value`` / ``.target`` property is
            being computed (e.g. an ``InputRead`` or ``TaintSink``).
        function: The ``Function`` that contains the observation.  Used as
            fallback for ``_trace_flow`` / ``_derived_from`` when *owner*
            does not carry them directly.
        location: Source location for the handle.
        expression: Source text for the handle.
        input_source: Optional input source for ``derived_from`` queries.
        broad_sink: Whether the handle is a broad sink target.
    """
    trace_flow = _get_private(owner, "_trace_flow") or _get_private(function, "_trace_flow")
    preserves_whole_value = _get_private(owner, "_preserves_whole_value") or _get_private(
        function, "_preserves_whole_value"
    )
    derived_from = _get_private(owner, "_derived_from") or _get_private(function, "_derived_from")
    trace_derived_from = _get_private(owner, "_trace_derived_from") or _get_private(
        function, "_trace_derived_from"
    )
    function_fqn = getattr(function, "fqn", None)
    handle = ValueHandle(location=location, expression=expression)
    return attach_flow_context(
        handle,
        trace_flow=trace_flow,
        preserves_whole_value=preserves_whole_value,
        derived_from=derived_from,
        trace_derived_from=trace_derived_from,
        function_fqn=function_fqn,
        input_source=input_source,
        broad_sink=broad_sink,
    )


@dataclass(frozen=True)
class FlowStep:
    """A single step in a traced flow path.

    Represents one node in the chain of assignments, calls, and
    transformations that connect a source to a sink.
    """

    location: Location
    """Source location of this step."""

    expression: str
    """Source text at this step."""

    description: str
    """Human-readable description of what happens at this step."""

    kind: str | None = None
    """Value-flow edge kind for this step, if it came from an edge."""

    def __repr__(self) -> str:
        return (
            f"FlowStep({self.kind or 'step'}, {_short_expr(self.expression)}, "
            f"{_short_loc(self.location)})"
        )


@dataclass(frozen=True)
class ValuePreservationResult:
    """Result of a whole-value preservation query."""

    preserved: bool
    """Whether the source whole value reaches the target unchanged."""

    gaps: tuple[AnalysisGap, ...] = ()
    """Analysis gaps encountered while trying to prove preservation."""


@dataclass(frozen=True)
class FlowTrace:
    """The result of tracing data flow between two specific points.

    Returned by :meth:`~flawed.repo.RepoView.trace_flow`.
    Contains the full path of :class:`FlowStep` objects and a
    :attr:`reachable` flag indicating whether the flow is connected.

    Example::

        trace = kb.trace_flow(source_loc, sink_loc)
        if trace.reachable:
            for step in trace.steps:
                print(f"  {step.location.line}: {step.expression} -- {step.description}")
    """

    source: ValueHandle
    """The source (origin) of the traced flow."""

    sink: ValueHandle
    """The sink (destination) of the traced flow."""

    steps: tuple[FlowStep, ...]
    """Ordered sequence of flow steps from source to sink."""

    reachable: bool
    """Whether a data-flow path exists from source to sink."""

    gaps: tuple[AnalysisGap, ...] = ()
    """Analysis gaps encountered while attempting to trace this flow."""

    def __repr__(self) -> str:
        arrow = "→" if self.reachable else "↛"
        return (
            f"FlowTrace({_short_expr(self.source.expression, 24)} {arrow} "
            f"{_short_expr(self.sink.expression, 24)}, {len(self.steps)} steps, "
            f"reachable={self.reachable})"
        )
