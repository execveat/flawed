"""Condition domain type for conditional expressions in code.

A :class:`Condition` represents a conditional expression (``if``,
``elif``, ternary) observed in analyzed code.  Each condition has a
structural :class:`ConditionKind` classification and exposes its
:attr:`true_branch` and :attr:`false_branch` as queryable
:class:`~flawed.scopes.CodeScope` objects.

Guard semantics are handled by the optional :attr:`guard` property,
which carries a :class:`GuardClassification` when Layer 2 determines
that a condition acts as a security guard.  This replaces the previous
``error_branch`` / ``pass_branch`` model with a richer, more reliable
classification:

- **true_branch / false_branch** -- universal, always present
- **guard** -- optional L2 enrichment identifying which branch is
  the guarded continuation and which is the denial path

Exception-based guards (``try: verify() except: abort()``) are modeled
separately as :class:`ExceptionGuard` and accessed via
:meth:`~flawed.scopes.CodeScope.exception_guards`.

Example::

    for cond in route.reachable.conditions():
        print(cond.expression, cond.kind)
        if cond.guard is not None:
            # This condition acts as a security guard
            writes_after = cond.guard.guarded_branch.effects(Mutation.write())
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Iterable

    from flawed.calls import CallSite, FnSelector
    from flawed.core import AnalysisGap, Location, Provenance
    from flawed.effects import Effect, EffectSelector
    from flawed.flow import ValueHandle
    from flawed.function import Function


class CodeScope(Protocol):
    """Structural stand-in for the scope API used by condition branches.

    Kept local to avoid a domain-model import cycle through ``flawed.scopes``
    (``scopes`` -> ``collections`` -> ``conditions``).  Declares the query
    surface branch scopes expose to rules: ``calls``, ``effects``, and
    ``gaps``, with the same signatures as the concrete Rule API
    :class:`flawed.scopes.CodeScope` (which documents the full semantics).

    Returns are typed as plain iterables, not the rich L3 ``*Collection``
    types, deliberately: the runtime branch object is a Layer-2
    ``ConcreteCodeScope`` whose ``_CollectionOps``-based results are parallel to
    (not subtypes of) the Layer-3 ``DomainCollection`` surface (import-linter
    forbids L2 from importing L3).  Both hierarchies are iterable, and rules
    only iterate branch results, so ``Iterable`` is the honest common type that
    every concrete branch scope satisfies.
    """

    def effects(self, selector: EffectSelector | None = None) -> Iterable[Effect]:
        """Effects in this branch, optionally filtered by selector."""
        ...

    def calls(self, selector: FnSelector | None = None) -> Iterable[CallSite]:
        """Call sites in this branch, optionally filtered by function selector."""
        ...

    @property
    def gaps(self) -> tuple[AnalysisGap, ...]:
        """Analysis gaps affecting functions reachable in this branch."""
        ...


class ConditionKind(Enum):
    """Structural classification of a condition from AST analysis.

    Assigned by Layer 1 based on the AST structure of the conditional
    expression.  Lets rule authors filter conditions by structural
    type without manually inspecting operators.

    Values:

    - ``COMPARISON`` -- ``x == y``, ``x != y``, ``x < y``, etc.
    - ``MEMBERSHIP`` -- ``x in y``, ``x not in y``
    - ``IDENTITY`` -- ``x is y``, ``x is not y``
    - ``TRUTHINESS`` -- ``if x:``, ``if not x:``
    - ``CALL_RESULT`` -- ``if check_func():``, ``if not verify():``
    - ``COMPOUND`` -- ``if a and b:``, ``if a or b:``
    - ``UNKNOWN`` -- could not be classified structurally
    """

    COMPARISON = "comparison"
    MEMBERSHIP = "membership"
    IDENTITY = "identity"
    TRUTHINESS = "truthiness"
    CALL_RESULT = "call_result"
    COMPOUND = "compound"
    UNKNOWN = "unknown"


class DenialKind(Enum):
    """How a failed guard denies access.

    Classified by Layer 2 when it recognizes a condition as a
    security guard.  The denial kind describes what happens in the
    branch that rejects the request.

    Values:

    - ``ABORT`` -- ``abort(4xx)`` or ``raise HTTPException``
    - ``RETURN_ERROR`` -- ``return jsonify({{"error": ...}}), 4xx``
    - ``RAISE`` -- ``raise SomeException``
    - ``REDIRECT`` -- ``redirect(url_for("login"))``
    - ``EARLY_RETURN`` -- bare ``return`` or non-response return
    - ``UNKNOWN`` -- denial pattern not recognized
    """

    ABORT = "abort"
    RETURN_ERROR = "return_error"
    RAISE = "raise_"
    REDIRECT = "redirect"
    EARLY_RETURN = "early_return"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class GuardClassification:
    """Layer 2's assessment of a condition as a security guard.

    When a condition is classified as a guard, this object identifies
    which branch is the normal continuation (guarded) and which is the
    denial path, along with the kind of denial and a confidence score.

    Example::

        if cond.guard is not None:
            print(cond.guard.denial_kind)  # e.g. DenialKind.ABORT
            writes = cond.guard.guarded_branch.effects(Mutation.write())
    """

    guarded_branch: CodeScope
    """The branch protected by the guard (normal execution continues here)."""

    denied_branch: CodeScope
    """The branch taken on guard failure (error/abort/redirect)."""

    denial_kind: DenialKind
    """How the denial manifests."""

    confidence: float
    """Layer 2's confidence in this classification ``[0.0, 1.0]``."""


@dataclass(frozen=True)
class ExceptionGuard:
    """A try/except block that acts as a security guard.

    Models exception-based guard patterns like::

        try:
            verify_token(token)
        except InvalidTokenError:
            abort(403)

    These are NOT modeled as :class:`Condition` (they are not ``if``
    expressions).  Access them via
    :meth:`~flawed.scopes.CodeScope.exception_guards`.

    Example::

        for guard in route.body.exception_guards():
            print(guard.denial_kind, guard.guarded_call)
    """

    try_body: CodeScope
    """Code scope covering the try block."""

    except_body: CodeScope
    """Code scope covering the except block."""

    guarded_call: CallSite
    """The call in the try block that might raise."""

    denial_kind: DenialKind
    """How the except block denies access."""

    location: Location
    """Source location of the ``try`` keyword."""

    function: Function
    """The function containing this guard."""

    provenance: Provenance
    """Semantic Layer provenance for this observation."""


@dataclass(frozen=True)
class SwallowedRejection:
    """A rejection ``raise`` in a ``try`` body that its ``except`` handler swallows.

    The function *appears* to reject invalid input -- it ``raise``s inside a ``try`` --
    but the handler neither re-raises nor otherwise denies (``except: pass``, or
    log-and-continue), so the rejection never takes effect.  A validator with this shape
    silently accepts everything: an inconsistency between "looks validated" and "is validated"
    (the root cause of real-world bypasses — e.g. an SSRF guard whose ``raise`` is swallowed).

    These are NOT modeled as :class:`Condition`.  Access them via
    :meth:`~flawed.scopes.CodeScope.swallowed_rejections`.

    Example::

        for sr in fn.body.swallowed_rejections():
            print(sr.raise_location)  # the rejection that goes nowhere
    """

    try_body: CodeScope
    """Code scope covering the ``try`` block (which raises)."""

    except_body: CodeScope
    """Code scope covering the swallowing ``except`` block."""

    guarded_call: CallSite
    """A representative call in the ``try`` body (the construct being guarded)."""

    raise_location: Location
    """Source location of the rejection ``raise`` that is swallowed."""

    location: Location
    """Source location of the ``try`` keyword."""

    function: Function
    """The function containing this swallowed rejection."""

    provenance: Provenance
    """Semantic Layer provenance for this observation."""


@dataclass(frozen=True)
class Condition:
    """A conditional expression observed in code.

    Produced by Layer 2 when it identifies ``if`` / ``elif`` / ternary
    expressions.  Not directly constructable by rule authors -- obtained
    from :meth:`~flawed.scopes.CodeScope.conditions` or
    :meth:`~flawed.scopes.CodeScope.conditions_using`.

    Universal properties (:attr:`true_branch`, :attr:`false_branch`)
    are always present.  The optional :attr:`guard` property is set
    when Layer 2 classifies the condition as a security guard.

    Example::

        for cond in route.body.conditions():
            if cond.kind == ConditionKind.COMPARISON:
                # Structural filtering by condition type
                writes_in_true = cond.true_branch.effects(Mutation.write())
            if cond.guard is not None:
                # L2 classified this as a security guard
                writes_after_guard = cond.guard.guarded_branch.effects(Mutation.write())
    """

    expression: str
    """Source text of the entire conditional expression."""

    location: Location
    """Source location of the ``if`` / ``elif`` keyword."""

    function: Function
    """The function containing this condition."""

    kind: ConditionKind
    """Structural classification of the condition (from AST)."""

    provenance: Provenance
    """Semantic Layer provenance for this observation."""

    category: str | None = None
    """Security-check category, or ``None``.

    Set only when Layer 2 recognizes this condition as a provider-declared
    security check (see :meth:`~flawed.scopes.CodeScope.checks`), naming the
    check family (e.g. ``"csrf"``, ``"auth"``).  ``None`` for ordinary
    structural conditions.  Concrete check conditions narrow this to ``str``.
    """

    @property
    def operator(self) -> str | None:
        """Comparison / membership / identity operator, or ``None``.

        Returns the operator string (``==``, ``!=``, ``in``, ``is``,
        etc.) for conditions that have one.  Returns ``None`` for
        truthiness, call-result, and compound conditions.
        """
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @property
    def true_branch(self) -> CodeScope:
        """Code reachable when the condition evaluates to true.

        Returns a :class:`~flawed.scopes.CodeScope` covering the
        ``if`` / ``elif`` body.  Always present.
        """
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @property
    def false_branch(self) -> CodeScope:
        """Code reachable when the condition evaluates to false.

        Returns a :class:`~flawed.scopes.CodeScope` covering the
        ``else`` body (or the continuation after the ``if`` block
        when there is no explicit ``else``).  Always present.
        """
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @property
    def left(self) -> ValueHandle | None:
        """Left operand as a trackable value handle.

        The sole operand for truthiness conditions (``if x:``).
        ``None`` for compound conditions (``if a and b:``).
        """
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @property
    def right(self) -> ValueHandle | None:
        """Right operand as a trackable value handle.

        ``None`` for truthiness, call-result, and compound conditions.
        """
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @property
    def guard(self) -> GuardClassification | None:
        """Layer 2's assessment of this condition as a security guard.

        Returns a :class:`GuardClassification` when Layer 2 determines
        that this condition acts as an access control check, or ``None``
        if L2 cannot classify it as a guard or it is not a guard pattern.
        """
        raise RuntimeError("Rule API surface requires Semantic Layer context")


@dataclass(frozen=True)
class Check(Condition):
    """A security check recognised by Layer 2 — the element type of
    :meth:`~flawed.scopes.CodeScope.checks`.

    A :class:`Check` is a :class:`Condition` that Layer 2 matched to a provider
    security-check declaration (or inferred), so it makes two guarantees the
    generic ``Condition`` cannot — and exposes them *as types*, so the checker
    enforces them during rule development rather than at scan time:

    - :attr:`category` is always a ``str`` (the check family, e.g.
      ``"AUTHENTICATION"``), never ``None``.
    - :attr:`provider_id` exists as a typed attribute — the id of the provider
      that declared the check, or ``None`` for a check Layer 2 *inferred*.

    Because ``provider_id`` is typed ``str | None`` here, the type checker sees
    its nullability: a rule that sorts or groups checks by ``provider_id``
    without handling ``None`` is a mypy error at edit time, not a ``TypeError``
    at scan time.  Access these fields directly (``check.provider_id``) — never
    via ``getattr``, which erases the type to ``Any`` and reopens that gap.

    Obtained from :meth:`~flawed.scopes.CodeScope.checks`; not directly
    constructable by rule authors.
    """

    category: str
    """Security-check family (e.g. ``"AUTHENTICATION"``, ``"SCHEMA_VALIDATION"``).

    Narrows :attr:`Condition.category` (``str | None``) — a recognised check
    always carries one.
    """

    provider_id: str | None = None
    """Id of the provider that declared this check.

    ``None`` when Layer 2 *inferred* the check (e.g. an in-body auth pattern)
    rather than matching a provider declaration.  An unattributed check is not
    an identified provider, so rules grouping or ordering by provider must
    handle the ``None`` — which the typed ``str | None`` forces them to.
    """


@dataclass(frozen=True)
class Predicate:
    """A predicate expression produced as a VALUE, not a branch test.

    Sibling to :class:`Condition`.  Where a ``Condition`` models an
    ``if`` / ``elif`` / ``while`` / ternary *test* that steers control
    flow (and therefore carries :attr:`~Condition.true_branch` /
    :attr:`~Condition.false_branch`), a ``Predicate`` models a
    comparison / membership / identity / truthiness expression that is
    produced as a *value* — a ``return`` value (``return token is not
    None``), an assignment RHS (``is_admin = role == "admin"``), or a
    ternary operand.

    The engine deliberately stays neutral: it exposes "a predicate
    produced as a value" without judging what the predicate *means*.
    The security interpretation ("this is presence-only credential
    auth") belongs to the rule layer.  This is why a ``Predicate`` has
    **no** ``true_branch`` / ``false_branch`` / ``guard`` — it does not
    steer control flow, so those concepts do not apply.

    Obtained from :meth:`~flawed.scopes.CodeScope.predicates`.  Not
    directly constructable by rule authors.

    Example::

        for predicate in fn.body.predicates():
            if predicate.kind is ConditionKind.IDENTITY:
                # ``token is not None`` — does an operand derive from input?
                if predicate.left is not None and predicate.left.derived_from(Header()):
                    yield fn.finding("Presence-only credential check")
    """

    expression: str
    """Source text of the predicate expression."""

    location: Location
    """Source location of the predicate expression."""

    function: Function
    """The function containing this predicate."""

    kind: ConditionKind
    """Structural classification of the predicate (from AST)."""

    provenance: Provenance
    """Semantic Layer provenance for this observation."""

    @property
    def operator(self) -> str | None:
        """Comparison / membership / identity operator, or ``None``.

        Returns the operator string (``==``, ``!=``, ``in``, ``is``,
        etc.) for predicates that have one.  Returns ``None`` for
        truthiness and compound predicates.
        """
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @property
    def left(self) -> ValueHandle | None:
        """Left operand as a trackable value handle.

        The sole operand for truthiness predicates (``return bool(x)``).
        ``None`` for compound predicates (``return a and b``).  Supports
        interprocedural :meth:`~flawed.flow.ValueHandle.derived_from` so a
        rule can trace the operand back across call boundaries to its
        originating request read.
        """
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @property
    def right(self) -> ValueHandle | None:
        """Right operand as a trackable value handle.

        ``None`` for truthiness and compound predicates.  Supports
        interprocedural :meth:`~flawed.flow.ValueHandle.derived_from`.
        """
        raise RuntimeError("Rule API surface requires Semantic Layer context")
