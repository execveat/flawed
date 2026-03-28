"""Taint sink observations produced by provider declarations.

A :class:`TaintSink` is a provider-declared injection point whose sink
argument is reached by externally controlled input within the queried scope.
Rule authors query sinks from :class:`~flawed.scopes.CodeScope` with
``scope.sinks(kind="SQL_INJECTION")`` and inspect the sink argument through
:attr:`TaintSink.target`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flawed.core import Location, Provenance
    from flawed.flow import ValueHandle
    from flawed.function import Function


@dataclass(frozen=True)
class TaintSink:
    """A provider-declared injection sink reached by scoped input flow."""

    kind: str
    """Sink taxonomy value, e.g. ``SQL_INJECTION`` or ``OPEN_REDIRECT``."""

    function: Function
    """Function containing the sink call."""

    location: Location
    """Location of the sink call expression."""

    expression: str
    """Source text of the sink call expression."""

    argument_location: Location
    """Location of the specific argument declared as the sink."""

    argument_expression: str
    """Source text of the specific argument declared as the sink."""

    provenance: Provenance
    """Semantic Layer provenance for this observation."""

    description: str = ""
    """Provider-supplied explanation of the sink semantics."""

    @property
    def target(self) -> ValueHandle:
        """Handle for the argument value that must be externally controlled."""
        from flawed.flow import make_value_handle

        handle = make_value_handle(
            owner=self,
            function=self.function,
            location=self.argument_location,
            expression=self.argument_expression,
            broad_sink=True,
        )
        try:
            definition_location = object.__getattribute__(self, "_argument_definition_location")
        except AttributeError:
            definition_location = None
        if definition_location is not None:
            object.__setattr__(handle, "_definition_location", definition_location)
        return handle
