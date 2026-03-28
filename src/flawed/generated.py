"""Provider-generated value facts exposed to the Rule API domain model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flawed.core import Location, Provenance
    from flawed.flow import ValueHandle
    from flawed.function import Function


@dataclass(frozen=True)
class SafeGeneratedURL:
    """A provider-generated URL value that is safe for specific sink kinds.

    This fact does not claim the URL is untainted.  It records a narrower
    guarantee: the provider constructs the destination boundary, so the whole
    generated value is safe where the listed sink kinds care about that
    boundary, such as ``OPEN_REDIRECT``.
    """

    function: Function
    """Function containing the URL-generation call."""

    location: Location
    """Source location of the URL-generation expression."""

    expression: str
    """Source text of the URL-generation expression."""

    safe_for_sink_kinds: tuple[str, ...]
    """Sink taxonomy values the generated URL is inherently safe for."""

    provenance: Provenance
    """Semantic Layer provenance for this observation."""

    description: str = ""
    """Provider-supplied explanation of the safety guarantee."""

    @property
    def value(self) -> ValueHandle:
        """Handle for the whole generated URL value."""
        from flawed.flow import make_value_handle

        return make_value_handle(
            owner=self,
            function=self.function,
            location=self.location,
            expression=self.expression,
        )
