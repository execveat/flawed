"""Class domain type.

Represents a Python class discovered by Layer 1 (Code Index) and
enriched by Layer 2 (Semantic Layer).  Every class in the analyzed
repository is represented as a :class:`Class` with its hierarchy,
methods, and structural metadata.

Example::

    from flawed import open_repo

    kb = open_repo("path/to/store")
    cls = kb.classes.named("User").one()
    print(cls.fqn)  # "myapp.models.User"
    print(cls.bases)  # ("myapp.models.Timestamped", "myapp.models.Base")
    print(cls.method_names)  # ("__init__", "greet", "save")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flawed.collections import DecoratorCollection, FunctionCollection
    from flawed.core import AnalysisGap, Location, Provenance


@dataclass(frozen=True)
class InheritedMethod:
    """A method inherited from an ancestor class via the MRO.

    Pairs the method name with the FQN of the class that defines it,
    in MRO order.  Used to determine where a method originates when
    it is not defined directly on the class.

    Example::

        for m in cls.inherited_methods:
            print(f"{m.name} defined in {m.defining_class}")
    """

    name: str
    """Method name."""

    defining_class: str
    """FQN of the class that defines this method."""


@dataclass(frozen=True)
class Class:
    """A Python class in the analyzed repository.

    Created by Layer 1 (Code Index) during AST traversal.  Not
    directly constructable by rule authors -- obtained from
    :attr:`~flawed.repo.RepoView.classes`.

    The ``bases`` field lists the direct base classes (FQNs when
    resolved, short names otherwise).  The ``mro`` field gives the
    full method resolution order as computed by astroid.

    Example::

        cls = kb.classes.named("User").one()
        print(cls.fqn)  # "myapp.models.User"
        print(cls.mro)  # ("myapp.models.User", "myapp.models.Base", ...)
        for m in cls.inherited_methods:
            print(m.name, m.defining_class)
    """

    fqn: str
    """Fully qualified name (e.g. ``"myapp.models.User"``)."""

    name: str
    """Short name (e.g. ``"User"``)."""

    bases: tuple[str, ...]
    """FQNs of direct base classes (resolved when possible)."""

    mro: tuple[str, ...] = field()
    """Method resolution order as FQNs (computed by astroid).

    Uses ``field()`` to prevent shadowing Python's built-in
    ``type.mro()`` method which would otherwise act as a default.
    """

    method_names: tuple[str, ...] = field()
    """Names of methods defined directly on this class."""

    inherited_methods: tuple[InheritedMethod, ...] = field()
    """Methods inherited from ancestor classes, in MRO order."""

    location: Location = field()
    """Source location of the ``class`` keyword."""

    provenance: Provenance = field()
    """Provenance of this class observation.

    Produced by Layer 2 when converting Layer 1's ``ClassRecord``
    into a domain object.  See :class:`~flawed.core.Provenance`.
    """

    @property
    def decorators(self) -> DecoratorCollection:
        """Decorators applied to this class."""
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @property
    def methods(self) -> FunctionCollection:
        """Methods defined directly on this class as Function objects."""
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @property
    def superclasses(self) -> tuple[str, ...]:
        """FQNs of all ancestor classes (from MRO, excluding self).

        Convenience property that slices ``mro`` to exclude the class
        itself.  Returns an empty tuple if the MRO contains only self.
        """
        return self.mro[1:] if len(self.mro) > 1 else ()

    @property
    def is_abstract(self) -> bool:
        """Whether this class has abstract methods.

        Determined by Layer 1 from the presence of
        ``@abc.abstractmethod``-decorated methods.
        """
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @property
    def gaps(self) -> tuple[AnalysisGap, ...]:
        """Analysis gaps affecting this class (e.g. MRO resolution failure)."""
        raise RuntimeError("Rule API surface requires Semantic Layer context")
