"""Call site, argument, and function selector types.

A :class:`CallSite` represents a specific location where a function is
called with specific arguments.  This is distinct from
:class:`~flawed.function.Function` -- a ``Function`` is the
*definition*, while a ``CallSite`` is a particular *invocation* with
its actual arguments and return value handle.

The :class:`FnSelector` type and its :class:`Fn` sugar namespace
provide composable selectors for matching functions by name, FQN, or
pattern.  Selectors compose with ``|``::

    from flawed.calls import Fn

    selector = Fn.named("execute") | Fn.fqn("sqlalchemy.Session.add")
    calls = route.reachable.calls(selector)

    for call in calls:
        print(call.target, call.arguments)
        if call.return_value.flows_to(some_effect.target):
            print("Return value reaches the effect")
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flawed.core import Location
    from flawed.flow import ValueHandle
    from flawed.function import Decorator, Function


@dataclass(frozen=True)
class Argument:
    """A specific argument at a call site.

    Represents one positional or keyword argument passed at a
    particular call site.  The :attr:`value` property provides a
    :class:`~flawed.flow.ValueHandle` for tracking the argument
    value through the program.

    Example::

        call = route.reachable.calls(Fn.named("execute")).first()
        for arg in call.arguments:
            print(arg.index, arg.name, arg.expression)
            if arg.value.derived_from(Json()):
                print("Argument comes from JSON input!")
    """

    index: int
    """0-based positional index of the argument."""

    name: str | None
    """Keyword name if passed as a keyword argument, or ``None``."""

    expression: str
    """Source text of the argument expression."""

    location: Location
    """Source location of the argument expression."""

    @property
    def value(self) -> ValueHandle:
        """Handle for tracking this argument's value through the program."""
        from flawed.flow import _get_private, make_value_handle

        function = _get_private(self, "_function")
        return make_value_handle(
            owner=self,
            function=function,
            location=self.location,
            expression=self.expression,
        )


@dataclass(frozen=True)
class CallSite:
    """A specific invocation of a function with specific arguments.

    Distinct from :class:`~flawed.function.Function` -- a function
    may be called from many sites, and each site carries its own
    arguments and return value.

    The :attr:`target` is ``None`` when the called function cannot be
    resolved (e.g. a call through a variable whose value is unknown).

    Example::

        for call in route.reachable.calls(Fn.named("execute")):
            print(call.target_expression)
            arg0 = call.argument(0)
            if arg0.value.derived_from(Json()):
                yield route.finding("SQL from JSON").evidence(call, "db call")
    """

    target: Function | None
    """The called function, or ``None`` if the target is unresolved."""

    target_expression: str
    """Source text of the call target (e.g. ``"db.execute"``)."""

    arguments: tuple[Argument, ...]
    """All arguments in call-site order."""

    location: Location
    """Source location of the call expression."""

    function: Function
    """The function containing this call site."""

    target_fqn: str | None = None
    """Resolved callee FQN, including external/library callees when known."""

    receiver_expression: str | None = None
    """Source text of the method-call receiver (``x`` in ``x.lower()``), or ``None``.

    ``None`` for plain function calls and calls whose receiver could not be
    captured.  See :attr:`receiver`.
    """

    receiver_location: Location | None = None
    """Source location of the receiver expression, or ``None``."""

    @property
    def expression(self) -> str:
        """Source text for the called target.

        ``target_expression`` is the canonical field name.  ``expression``
        keeps call sites aligned with other evidence facts and existing
        example rules.
        """
        return self.target_expression

    def argument(self, index: int) -> Argument:
        """Look up an argument by 0-based positional index.

        Raises ``IndexError`` if the index is out of range.
        """
        if index < 0 or index >= len(self.arguments):
            raise IndexError(index)
        return self.arguments[index]

    def keyword_argument(self, name: str) -> Argument | None:
        """Look up an argument by keyword name.

        Returns ``None`` if no keyword argument with the given name
        exists at this call site.
        """
        for arg in self.arguments:
            if arg.name == name:
                return arg
        return None

    @property
    def return_value(self) -> ValueHandle:
        """Handle for tracking the call's return value.

        Use to check whether the return value flows to a particular
        effect or is used in a condition.
        """
        from flawed.flow import make_value_handle

        return make_value_handle(
            owner=self,
            function=self.function,
            location=self.location,
            expression=self.target_expression,
        )

    @property
    def receiver(self) -> ValueHandle | None:
        """Handle for the method-call receiver, or ``None`` for non-method calls.

        For a method-style transform (``email.lower()``) this is a
        :class:`~flawed.flow.ValueHandle` for the subject the method is invoked
        on (``email``).  Plain function calls (``normalize(email)``) and calls
        whose receiver was not captured return ``None`` -- use the argument
        handles (:attr:`Argument.value`) for the function-call subject instead.

        The handle participates in provenance queries exactly like
        :attr:`return_value` and :attr:`Argument.value`, so a rule can ask
        whether two transforms share an origin::

            first.receiver.shares_origin(second.receiver, among=route.reachable.reads())
        """
        if self.receiver_expression is None or self.receiver_location is None:
            return None
        from flawed.flow import make_value_handle

        return make_value_handle(
            owner=self,
            function=self.function,
            location=self.receiver_location,
            expression=self.receiver_expression,
        )


@dataclass(frozen=True)
class FnSelector:
    """Composable selector for filtering functions by name, FQN, or pattern.

    Single selectors match by one criterion (name, FQN, or regex).
    Composed selectors (via ``|``) match if *any* alternative matches.

    Construct via the :class:`Fn` sugar namespace rather than directly::

        selector = Fn.named("execute") | Fn.fqn("db.Session.add")
    """

    name_filter: str | None = None
    """Match functions with this exact short name."""

    fqn_filter: str | None = None
    """Match functions with this exact fully qualified name."""

    pattern_filter: tuple[str, ...] = ()
    """Match functions whose name or FQN matches any regex/glob pattern."""

    _alternatives: tuple[FnSelector, ...] = ()
    """Internal: composed alternatives from ``|`` operations."""

    def __or__(self, other: FnSelector) -> FnSelector:
        """Compose selectors: the result matches if either matches.

        Example::

            combined = Fn.named("execute") | Fn.named("run_query")
        """
        my = self._alternatives or (self,)
        theirs = other._alternatives or (other,)
        return FnSelector(_alternatives=(*my, *theirs))

    def matches(self, fn: Function | Decorator | None) -> bool:
        """Return True if *fn* satisfies this selector.

        Accepts any named symbol carrying ``name``/``fqn`` — a project
        :class:`~flawed.function.Function` or a
        :class:`~flawed.function.Decorator` (rules match auth-decorator
        selectors against a handler's decorators).
        """
        fqn = fn.fqn if fn is not None else None
        name = fn.name if fn is not None else None
        return self.matches_values(name=name, fqn=fqn)

    def matches_call(self, call: CallSite) -> bool:
        """Return True if *call* satisfies this selector.

        Call sites may target external functions that are not represented as
        project ``Function`` objects.  In that case, match against the L1
        resolved callee FQN and source expression carried by the call site.
        """
        fqn = call.target.fqn if call.target is not None else call.target_fqn
        name = call.target.name if call.target is not None else _short_name(fqn)
        return self.matches_values(name=name, fqn=fqn, expression=call.target_expression)

    def matches_values(
        self,
        *,
        name: str | None,
        fqn: str | None,
        expression: str | None = None,
    ) -> bool:
        """Return True if the given callee identity satisfies this selector."""
        if self._alternatives:
            return any(
                alt.matches_values(name=name, fqn=fqn, expression=expression)
                for alt in self._alternatives
            )
        if self.name_filter is not None:
            return name == self.name_filter
        if self.fqn_filter is not None:
            return fqn == self.fqn_filter
        if self.pattern_filter:
            candidates = tuple(c for c in (name, fqn, expression) if c)
            return any(
                _pattern_matches(pattern, candidate)
                for pattern in self.pattern_filter
                for candidate in candidates
            )
        return False


class Fn:
    """Sugar namespace for constructing function selectors.

    Example::

        Fn.named("execute")  # match by short name
        Fn.fqn("sqlalchemy.Session.add")  # match by FQN
        Fn.matching(r"^(get|fetch)_")  # match by regex
    """

    @staticmethod
    def named(name: str) -> FnSelector:
        """Select functions with the given short name.

        Args:
            name: Exact function name to match (e.g. ``"execute"``).
        """
        return FnSelector(name_filter=name)

    @staticmethod
    def fqn(fqn: str) -> FnSelector:
        """Select functions with the given fully qualified name.

        Args:
            fqn: Exact FQN to match (e.g. ``"hmac.compare_digest"``).
        """
        return FnSelector(fqn_filter=fqn)

    @staticmethod
    def matching(pattern: str, *additional: str) -> FnSelector:
        """Select functions matching one or more regex/glob patterns.

        Args:
            pattern: Regular expression matched against the function name/FQN.
            additional: Optional additional patterns composed as alternatives.
        """
        return FnSelector(pattern_filter=(pattern, *additional))


def _short_name(fqn: str | None) -> str | None:
    if fqn is None:
        return None
    return fqn.rsplit(".", maxsplit=1)[-1]


def _pattern_matches(pattern: str, candidate: str) -> bool:
    try:
        return bool(re.search(pattern, candidate))
    except re.error:
        return fnmatch.fnmatchcase(candidate, pattern)
