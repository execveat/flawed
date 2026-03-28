"""Type/shape disagreement domain signals.

This module exposes analysis signals that are not tied to one web framework
or sink category.  Type-checker disagreement is one such signal: when two
independent type engines infer materially different concrete types for the
same expression, the expression deserves security review even before a
traditional source-to-sink pattern fires.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flawed.core import Location, Provenance


class TypeDisagreementKind(Enum):
    """Security-oriented taxonomy for type-checker disagreement patterns."""

    OPTIONALITY = "optionality"
    """One checker sees a nullable value while another sees a non-null value."""

    CONTAINER_SHAPE = "container_shape"
    """Checkers disagree about mapping, sequence, tuple, or set shape."""

    SCALAR_KIND = "scalar_kind"
    """Checkers disagree across security-sensitive scalar families."""

    CALLABLE_SHAPE = "callable_shape"
    """A value is callable according to one checker but not another."""

    OBJECT_IDENTITY = "object_identity"
    """Checkers disagree about identity/principal/account-like object types."""

    UNKNOWN = "unknown"
    """Concrete disagreement exists, but it does not match a named pattern yet."""


@dataclass(frozen=True)
class TypeCheckerObservation:
    """One type checker's concrete observation for an expression."""

    source_tool: str
    """Tool that produced the observation, for example ``"mypy"``."""

    declared_type: str
    """Tool display type for the expression."""


@dataclass(frozen=True)
class TypeDisagreement:
    """A first-class type-checker disagreement signal.

    Rule authors can use these signals directly from
    :meth:`flawed.scopes.CodeScope.type_disagreements` or
    :attr:`flawed.repo.RepoView.type_disagreements`.  A disagreement is emitted
    only when at least two concrete type facts at the same source expression do
    not collapse to the same fully-qualified/simple type spelling.
    """

    expression: str
    """Source expression where the disagreement occurred."""

    location: Location
    """Source location of the expression."""

    observations: tuple[TypeCheckerObservation, ...]
    """Concrete observations that disagree."""

    kind: TypeDisagreementKind
    """Security-oriented classification of the disagreement shape."""

    security_relevance: str
    """Why this disagreement can matter for review."""

    containing_function_fqn: str | None
    """Function containing the expression, if known."""

    provenance: Provenance
    """Provenance for the derived disagreement signal."""

    @property
    def is_security_relevant(self) -> bool:
        """Return true when the disagreement matched a named security pattern."""
        return self.kind is not TypeDisagreementKind.UNKNOWN

    @property
    def source_tools(self) -> tuple[str, ...]:
        """Type-checker names contributing concrete observations."""
        return tuple(observation.source_tool for observation in self.observations)
