"""Validated value facts exposed by provider guard semantics."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flawed.core import Location, Provenance
    from flawed.flow import ValueHandle
    from flawed.function import Function


@dataclass(frozen=True)
class ValidatedValue:
    """A value proven safe for specific sink kinds by a successful guard call.

    The fact is deliberately sink-specific: a URL validator can make a value safe
    for ``OPEN_REDIRECT`` without claiming it is generally untainted or safe for
    SQL, template, filesystem, or command sinks.
    """

    function: Function
    """Function containing the guard call."""

    location: Location
    """Source location of the guard call expression."""

    expression: str
    """Source text of the guard call expression."""

    validated_location: Location
    """Source location of the argument being validated."""

    validated_expression: str
    """Source text of the argument being validated."""

    definition_location: Location | None
    """Where the validated value was originally defined, or ``None``."""

    safe_for_sink_kinds: tuple[str, ...]
    """Sink taxonomy values this guard makes the value safe for."""

    validated_when: bool
    """Whether the guard validates on truthy (``True``) or falsy (``False``)."""

    provenance: Provenance
    """Semantic Layer provenance for this observation."""

    description: str = ""
    """Provider-supplied explanation of the guard semantics."""

    @property
    def value(self) -> ValueHandle:
        """Handle for the whole value accepted by the guard."""
        from flawed.flow import make_value_handle

        return make_value_handle(
            owner=self,
            function=self.function,
            location=self.validated_location,
            expression=self.validated_expression,
        )
