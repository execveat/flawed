"""CodeScope and ControlFlowView for querying regions of code.

:class:`CodeScope` is the central query interface for the Rule API.
Every query about what happens in code -- reads, effects, conditions,
calls, decorators, validated values, generated URLs -- goes through a
``CodeScope``.  Scopes are
obtained from routes and functions at three granularity levels:

- ``.body`` -- direct function body only
- ``.reachable`` -- transitively reachable code (body + all callees)
- ``.full_stack`` -- reachable code plus lifecycle hooks and middleware

:class:`ControlFlowView` answers ordering and dominance questions
over source locations within a scope.

Example::

    scope = route.reachable
    reads = scope.reads(Json())
    effects = scope.effects(Mutation.write())
    cfg = scope.cfg

    for read in reads:
        for effect in effects:
            if read.value.flows_to(effect.target):
                if cfg.dominates(guard.location, effect.location):
                    print("Guard protects the write")
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from flawed.calls import FnSelector
    from flawed.collections import (
        CallSiteCollection,
        CheckCollection,
        ConditionCollection,
        DecoratorCollection,
        EffectCollection,
        FunctionCollection,
        InputReadCollection,
        PredicateCollection,
        SafeGeneratedURLCollection,
        TaintSinkCollection,
        ValidatedValueCollection,
    )
    from flawed.conditions import ExceptionGuard, SwallowedRejection
    from flawed.core import AnalysisGap, Location
    from flawed.disagreement import TypeDisagreement
    from flawed.effects import EffectSelector
    from flawed.flow import ValueHandle
    from flawed.inputs import InputSource
    from flawed.route import HttpMethod


class CodeScope:
    """A queryable region of code (function body, reachable closure, etc.).

    The central query interface for the Rule API.  All domain queries
    (reads, effects, conditions, calls, decorators, validated values,
    generated URLs) are scoped to a ``CodeScope``, which determines what
    code is included in the search.

    Obtained from:

    - :attr:`Route.body <flawed.route.Route.body>` /
      :attr:`~flawed.route.Route.reachable` /
      :attr:`~flawed.route.Route.full_stack`
    - :attr:`Function.body <flawed.function.Function.body>` /
      :attr:`~flawed.function.Function.reachable`
    - :attr:`Condition.true_branch <flawed.conditions.Condition.true_branch>` /
      :attr:`~flawed.conditions.Condition.false_branch`

    Example::

        scope = route.reachable
        for read in scope.reads(Json()):
            for effect in scope.effects(Mutation.write()):
                if read.value.flows_to(effect.target):
                    yield route.finding("Input flows to write")
    """

    def conditions(self) -> ConditionCollection:
        """All conditional expressions in this scope.

        Returns every ``if`` / ``elif`` / ternary observed in the
        scoped code region.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def conditions_using(self, value: ValueHandle) -> ConditionCollection:
        """Conditions that reference the given value.

        Filters to conditions where the given
        :class:`~flawed.flow.ValueHandle` appears as an operand.

        Example::

            guards = route.body.conditions_using(read.value)
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def predicates(self) -> PredicateCollection:
        """Predicate expressions produced as values in this scope.

        Sibling to :meth:`conditions`.  Returns comparison / membership /
        identity / truthiness expressions produced as a *value* — a
        ``return`` value (``return token is not None``), an assignment RHS
        (``is_admin = role == "admin"``), or a ternary operand — rather
        than as a control-flow branch test.

        Unlike :class:`~flawed.conditions.Condition`, a
        :class:`~flawed.conditions.Predicate` carries no ``true_branch`` /
        ``false_branch``: it does not steer control flow.  Its
        :attr:`~flawed.conditions.Predicate.left` /
        :attr:`~flawed.conditions.Predicate.right` operands support
        interprocedural :meth:`~flawed.flow.ValueHandle.derived_from`, so a
        rule can trace an operand back across call boundaries to its
        originating request read.

        Example::

            for predicate in route.full_stack.predicates():
                if predicate.left is not None and predicate.left.derived_from(Header()):
                    ...
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def checks(self, category: str | None = None) -> CheckCollection:
        """Provider-declared security checks in this scope.

        Returns :class:`~flawed.conditions.Check` objects — a :class:`Condition`
        narrowed to a recognised security check, so ``category`` is always a
        ``str`` and ``provider_id`` is exposed as a typed ``str | None``.
        Conditions produced from provider ``SecurityCheckPattern`` declarations;
        structural conditions without a provider security category are excluded.
        When *category* is provided, only checks with that exact provider
        category are returned.

        Example::

            auth = scope.checks(category="AUTHENTICATION")
            providers = {c.provider_id for c in auth if c.provider_id is not None}
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def reads(self, source: InputSource | None = None) -> InputReadCollection:
        """Input reads in this scope, optionally filtered by source.

        When called with no arguments, returns all input reads in the
        scope.  When called with a source, returns only reads matching
        that source type.

        Example::

            all_reads = scope.reads()
            json_reads = scope.reads(Json())
            specific = scope.reads(Json(path=JsonPath("$.user_id")))
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def reads_flowing_to(self, target: ValueHandle) -> InputReadCollection:
        """Reads in this scope whose value flows to *target*.

        The first-class form of the read-to-sink correlation that
        comparative and invariant-flow rules otherwise hand-roll as
        ``[r for r in scope.reads() if r.value.flows_to(target)]``.
        Centralising it gives the engine one definition of "which inputs
        feed this value" and one place to optimise the underlying flow
        queries.

        *target* is any :class:`~flawed.flow.ValueHandle` — typically an
        :attr:`Effect.target <flawed.effects.Effect.target>` (a write sink) or
        a call-argument value. Semantically identical to filtering
        :meth:`reads` by :meth:`~flawed.flow.ValueHandle.flows_to`; reads are
        returned in scope order so a rule's evidence selection is stable.

        Example::

            for effect in scope.effects(Db.write()):
                feeders = scope.reads_flowing_to(effect.target)
                if len({type(r.source) for r in feeders}) >= 2:
                    yield route.finding("Multiple input sources reach one write")
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def effects(self, selector: EffectSelector | None = None) -> EffectCollection:
        """Effects in this scope, optionally filtered by selector.

        When called with no arguments, returns all effects in the
        scope.  When called with a selector, returns only effects
        matching that selector's categories and filters.

        Example::

            all_effects = scope.effects()
            writes = scope.effects(Mutation.write())
            any_mutation = scope.effects(Mutation.any() | State.write())
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def calls(self, selector: FnSelector | None = None) -> CallSiteCollection:
        """Call sites in this scope, optionally filtered by function selector.

        When *selector* is provided, returns call sites where the called
        function matches it.  Use :class:`~flawed.calls.Fn` to construct
        selectors.  With no selector, returns all call sites in the scope.

        Example::

            db_calls = scope.calls(Fn.named("execute") | Fn.named("add"))
            all_calls = scope.calls()
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def reachable_functions(self) -> FunctionCollection:
        """Functions whose bodies make up this scope.

        For a ``reachable`` or ``full_stack`` scope this is the transitive
        call-graph closure -- the handler/owner plus every directly or
        indirectly called function (and lifecycle hooks, for ``full_stack``);
        for a ``body`` scope it is the single owning function.  The owner is
        listed first.  This is the direct primitive for "what code does this
        route actually run", replacing a hand-rolled ``.calls()`` walk.

        Example::

            for fn in route.reachable.reachable_functions():
                print(fn.fqn)
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def sinks(self, kind: str | None = None) -> TaintSinkCollection:
        """Taint sinks reached by input flow in this scope.

        When *kind* is provided, returns only sinks with that provider-declared
        taxonomy value (for example ``"SQL_INJECTION"``).  Sinks are
        flow-sensitive: a declared sink call is returned only when at least one
        input read in the same scope reaches the sink argument.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def validated_values(self) -> ValidatedValueCollection:
        """Values proven safe for specific sink kinds by validation guards.

        Returns :class:`~flawed.validation.ValidatedValue` facts produced from
        provider-declared validation guard semantics, such as a project-local
        ``is_safe_url(target)`` check that makes ``target`` safe for
        ``"OPEN_REDIRECT"`` after the guard succeeds.

        Example::

            for value in scope.validated_values():
                if "OPEN_REDIRECT" in value.safe_for_sink_kinds:
                    print(f"{value.validated_expression} was URL-validated")
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def generated_urls(self) -> SafeGeneratedURLCollection:
        """Provider-generated URL values safe for specific sink kinds.

        Returns :class:`~flawed.generated.SafeGeneratedURL` facts produced from
        framework URL builders, such as ``url_for("index")``.  These facts are
        intentionally narrow: they mean the provider controls the destination
        boundary for the listed sink kinds, not that the value is generally
        untainted.

        Example::

            safe_redirect_targets = [
                url for url in scope.generated_urls() if "OPEN_REDIRECT" in url.safe_for_sink_kinds
            ]
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def decorators(self) -> DecoratorCollection:
        """Decorators applied to functions in this scope."""
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def type_disagreements(
        self,
        *,
        security_relevant: bool | None = None,
    ) -> tuple[TypeDisagreement, ...]:
        """Type-checker disagreement signals in this scope.

        When ``security_relevant`` is true, returns only disagreements that
        match a named inconsistency pattern.  When false, returns only currently
        unclassified disagreements.  The default returns all disagreements.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def exception_guards(self) -> tuple[ExceptionGuard, ...]:
        """Exception-based guards (try/except blocks acting as security checks).

        Returns :class:`~flawed.conditions.ExceptionGuard` objects for
        ``try``/``except`` blocks where the except handler denies access
        (aborts, raises, redirects).

        Example::

            for guard in route.body.exception_guards():
                if scope.cfg.precedes(guard.location, effect.location):
                    print("Exception guard protects the effect")
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def swallowed_rejections(self) -> tuple[SwallowedRejection, ...]:
        """Rejection ``raise``s swallowed by their ``except`` handler.

        Returns :class:`~flawed.conditions.SwallowedRejection` objects for
        ``try``/``except`` blocks whose try body raises to reject input but whose handler
        neither re-raises nor denies -- a function (typically a validator) that *looks*
        like it rejects but never does (FLAW-319).

        Example::

            for sr in fn.body.swallowed_rejections():
                print(sr.raise_location)  # the rejection that goes nowhere
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def branch(self, method: HttpMethod | str) -> CodeScope | None:
        """Code scope for a reconstructed HTTP method branch, if present.

        Some multi-method handlers dispatch internally with conditions such as
        ``request.method == "POST"``.  When Semantic Layer CFG reconstruction
        recognizes that pattern, this returns the method-restricted scope.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @property
    def gaps(self) -> tuple[AnalysisGap, ...]:
        """Analysis gaps affecting functions in this scope.

        Union of all gaps from all functions included in this scope.
        Automatically populated by Layer 2.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @property
    def cfg(self) -> ControlFlowView:
        """Control flow graph scoped to this code region.

        Returns a :class:`ControlFlowView` for answering ordering
        and dominance questions.

        - ``route.body.cfg`` is intra-procedural (single function).
        - ``route.reachable.cfg`` is interprocedural (when available).
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")


class CFGBlock(Protocol):
    """Structural view of a single basic block in the control-flow graph.

    Kept local as a :class:`~typing.Protocol` rather than re-exporting the
    Layer-1 ``flawed._index._types.CFGBlock`` dataclass, because import-linter
    forbids the Rule API (Layer 3) from importing the index layer directly.
    The runtime objects yielded by :attr:`ControlFlowView.blocks` are those L1
    dataclasses, which satisfy this Protocol structurally.

    Declares the block surface rules may rely on.  The L1 ``statements`` field
    (``tuple[SourceSpan, ...]``) is deliberately **not** surfaced here: its
    element type is a Layer-1 location shape with no Layer-3 (:class:`Location`)
    equivalent, so exposing it honestly would leak the index layer.  Rules that
    need per-statement spans call
    :meth:`ControlFlowView.statement_locations` with this block's :attr:`id`,
    which projects them into public :class:`Location` objects.
    """

    @property
    def id(self) -> int:
        """Unique block identifier within the function's CFG."""

    @property
    def successors(self) -> tuple[int, ...]:
        """Block IDs of successor blocks."""

    @property
    def predecessors(self) -> tuple[int, ...]:
        """Block IDs of predecessor blocks."""

    @property
    def condition_expr(self) -> str | None:
        """Branch condition source text if this block ends with a branch."""


class ControlFlowView:
    """Answers ordering and dominance questions over source locations.

    This is a **query surface**, not a data carrier.  It holds a
    reference to the underlying CFG engine and is *not* a frozen
    dataclass — unlike domain data objects such as :class:`~flawed.route.Route`
    or :class:`~flawed.function.Function`.

    Obtained via :attr:`CodeScope.cfg`.  All methods accept
    :class:`~flawed.core.Location` objects and return booleans.

    Example::

        cfg = route.body.cfg

        cfg.dominates(a, b)  # every path to b passes through a
        cfg.precedes(a, b)  # a executes before b on all paths
        cfg.ordered(a, b, c)  # a, b, c in order on all paths
        cfg.reachable_between(a, b)  # any execution path from a to b
    """

    def dominates(self, a: Location, b: Location) -> bool:
        """Return True if location ``a`` dominates location ``b`` in the CFG.

        Dominance means every execution path reaching ``b`` must first
        pass through ``a``.  Dominance is reflexive: a location
        dominates itself.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def precedes(self, a: Location, b: Location) -> bool:
        """Return True if ``a`` precedes ``b`` on all execution paths.

        Stronger than dominance: ``a`` must execute *before* ``b`` on
        every path (not just be reachable before ``b``).
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def ordered(self, *locations: Location) -> bool:
        """Return True if locations appear in this order on all paths.

        Generalizes :meth:`precedes` to an arbitrary sequence of
        locations.

        Example::

            cfg.ordered(auth_check.location, guard.location, write.location)
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def reachable_between(self, a: Location, b: Location) -> bool:
        """Return True if there is any execution path from ``a`` to ``b``.

        Weaker than :meth:`precedes` -- only requires that *some* path
        exists, not that *all* paths go through both.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @property
    def blocks(self) -> tuple[CFGBlock, ...]:
        """Basic blocks of the backing CFG, or empty when unavailable.

        When this view is scoped to a subset of the CFG (e.g. a single branch
        arm), only the blocks within that subset are returned.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def block_id_for(self, location: Location) -> int | None:
        """Return the CFG block ID containing ``location``, or ``None``.

        Returns ``None`` when no block contains the location, or when the
        location falls outside this view's scope.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def statement_locations(self, block_id: int) -> tuple[Location, ...]:
        """Source :class:`~flawed.core.Location` of each statement in ``block_id``.

        Bridges the L1/L3 shape gap noted on :class:`CFGBlock`: per-statement
        spans are a Layer-1 type with no place on the public block protocol,
        so this projection exposes them as public locations.  Pass a block ID
        obtained from :attr:`blocks` (``block.id``).

        Returns an empty tuple when no such block is visible in this view --
        an unknown ID, a block outside a restricted scope, or a view with no
        backing CFG.  It never fabricates spans.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")
