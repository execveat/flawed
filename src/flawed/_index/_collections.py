"""Typed Layer 1 collections — filterable, composable query objects.

Every filter method returns a new instance of the same collection type
(immutable query chaining).  Collections wrap a ``tuple`` of frozen
records and never mutate their contents.

All collections share a uniform API surface:
    ``__iter__``, ``__len__``, ``__bool__``, ``__getitem__``,
    ``all()``, ``first()``, ``one()``, ``exists()``, ``where()``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Generic, TypeVar, overload

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

from flawed._index._types import (
    AccessKind,
    AttributeAccess,
    ClassRecord,
    DecoratorFact,
    ExtractionError,
    FunctionRecord,
    ImportFact,
    SymbolRef,
    ValueFlowEdge,
)

_T = TypeVar("_T")


def _decorator_matches(name_or_fqn: str, decorator_name: str, decorator_fqn: str | None) -> bool:
    return name_or_fqn in (decorator_name, decorator_fqn)


# =====================================================================
# Base collection
# =====================================================================


class _BaseCollection(Generic[_T]):
    """Generic read-only collection with filtering primitives."""

    __slots__ = ("_items",)

    def __init__(self, items: tuple[_T, ...]) -> None:
        self._items: tuple[_T, ...] = items

    # -- core protocol ------------------------------------------------

    def all(self) -> tuple[_T, ...]:
        """All items in the collection."""
        return self._items

    def first(self) -> _T | None:
        """First item, or ``None`` if empty."""
        return self._items[0] if self._items else None

    def one(self) -> _T:
        """Exactly one item, or raise ``ValueError``."""
        if len(self._items) != 1:
            msg = f"expected exactly 1 item, got {len(self._items)}"
            raise ValueError(msg)
        return self._items[0]

    def exists(self) -> bool:
        """``True`` if the collection is non-empty."""
        return len(self._items) > 0

    # -- iteration / sizing -------------------------------------------

    def __iter__(self) -> Iterator[_T]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return len(self._items) > 0

    @overload
    def __getitem__(self, index: int) -> _T: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[_T, ...]: ...

    def __getitem__(self, index: int | slice) -> _T | tuple[_T, ...]:
        return self._items[index]

    def __repr__(self) -> str:
        cls = type(self).__name__
        return f"{cls}({len(self._items)} items)"


# =====================================================================
# FunctionCollection
# =====================================================================


class FunctionCollection(_BaseCollection[FunctionRecord]):
    """Filterable set of ``FunctionRecord`` facts."""

    __slots__ = ()

    def where(self, predicate: Callable[[FunctionRecord], bool]) -> FunctionCollection:
        """Keep only records matching *predicate*."""
        return FunctionCollection(tuple(r for r in self._items if predicate(r)))

    def named(self, name: str) -> FunctionCollection:
        """Filter by short function name."""
        return FunctionCollection(tuple(r for r in self._items if r.name == name))

    def with_fqn(self, fqn: str) -> FunctionCollection:
        """Filter by exact fully-qualified name."""
        return FunctionCollection(tuple(r for r in self._items if r.fqn == fqn))

    def by_fqn(self, fqn: str) -> FunctionRecord | None:
        """Look up a single function by FQN."""
        for r in self._items:
            if r.fqn == fqn:
                return r
        return None

    def in_file(self, path: str) -> FunctionCollection:
        """Keep only functions defined in *path* (relative to repo root)."""
        return FunctionCollection(tuple(r for r in self._items if r.file == path))

    def in_dir(self, prefix: str) -> FunctionCollection:
        """Keep only functions whose file starts with *prefix*."""
        return FunctionCollection(tuple(r for r in self._items if r.file.startswith(prefix)))

    def in_class(self, class_fqn: str) -> FunctionCollection:
        """Keep only methods of the given class."""
        return FunctionCollection(tuple(r for r in self._items if r.parent_class == class_fqn))

    def methods(self) -> FunctionCollection:
        """Keep only class methods."""
        return FunctionCollection(tuple(r for r in self._items if r.is_method))

    def top_level(self) -> FunctionCollection:
        """Keep only module-level functions."""
        from flawed._index._types import FunctionKind

        return FunctionCollection(
            tuple(r for r in self._items if r.kind == FunctionKind.TOP_LEVEL)
        )

    def nested(self) -> FunctionCollection:
        """Keep only functions nested inside another function."""
        return FunctionCollection(tuple(r for r in self._items if r.is_nested))

    def decorated_with(self, name: str) -> FunctionCollection:
        """Keep functions decorated with *name*.

        Matches against both syntactic decorator names and resolved FQNs.
        """
        return FunctionCollection(
            tuple(
                r
                for r in self._items
                if any(
                    _decorator_matches(name, decorator_name, decorator_fqn)
                    for decorator_name, decorator_fqn in zip(
                        r.decorator_names,
                        r.decorator_fqns,
                        strict=True,
                    )
                )
            )
        )


# =====================================================================
# ClassCollection
# =====================================================================


class ClassCollection(_BaseCollection[ClassRecord]):
    """Filterable set of ``ClassRecord`` facts."""

    __slots__ = ("_decorators",)

    def __init__(
        self,
        items: tuple[ClassRecord, ...],
        decorators: tuple[DecoratorFact, ...] = (),
    ) -> None:
        super().__init__(items)
        self._decorators = decorators

    def _with_items(self, items: tuple[ClassRecord, ...]) -> ClassCollection:
        return ClassCollection(items, self._decorators)

    def where(self, predicate: Callable[[ClassRecord], bool]) -> ClassCollection:
        """Keep only records matching *predicate*."""
        return self._with_items(tuple(r for r in self._items if predicate(r)))

    def named(self, name: str) -> ClassCollection:
        """Filter by short class name."""
        return self._with_items(tuple(r for r in self._items if r.name == name))

    def with_fqn(self, fqn: str) -> ClassCollection:
        """Filter by exact fully-qualified name."""
        return self._with_items(tuple(r for r in self._items if r.fqn == fqn))

    def by_fqn(self, fqn: str) -> ClassRecord | None:
        """Look up a single class by FQN."""
        for r in self._items:
            if r.fqn == fqn:
                return r
        return None

    def in_file(self, path: str) -> ClassCollection:
        """Keep only classes defined in *path*."""
        return self._with_items(tuple(r for r in self._items if r.file == path))

    def in_dir(self, prefix: str) -> ClassCollection:
        """Keep only classes whose file starts with *prefix*."""
        return self._with_items(tuple(r for r in self._items if r.file.startswith(prefix)))

    def decorated_with(self, name: str) -> ClassCollection:
        """Keep classes decorated with *name*.

        Matches against both syntactic decorator names and resolved FQNs from
        L1 ``DecoratorFact`` records.
        """
        target_fqns = frozenset(
            decorator.target_fqn
            for decorator in self._decorators
            if _decorator_matches(name, decorator.name, decorator.fqn)
        )
        return self._with_items(tuple(r for r in self._items if r.fqn in target_fqns))

    def subclasses_of(self, base_fqn: str) -> ClassCollection:
        """Transitive: all descendants via ``all_subclasses``."""
        for r in self._items:
            if r.fqn == base_fqn:
                sub_fqns = frozenset(r.all_subclasses)
                return self._with_items(tuple(c for c in self._items if c.fqn in sub_fqns))
        return self._with_items(())

    def direct_subclasses_of(self, base_fqn: str) -> ClassCollection:
        """Direct only: single level via ``subclasses``."""
        for r in self._items:
            if r.fqn == base_fqn:
                sub_fqns = frozenset(r.subclasses)
                return self._with_items(tuple(c for c in self._items if c.fqn in sub_fqns))
        return self._with_items(())


# =====================================================================
# DecoratorCollection
# =====================================================================


class DecoratorCollection(_BaseCollection[DecoratorFact]):
    """Filterable set of ``DecoratorFact`` records."""

    __slots__ = ()

    def where(self, predicate: Callable[[DecoratorFact], bool]) -> DecoratorCollection:
        """Keep only records matching *predicate*."""
        return DecoratorCollection(tuple(r for r in self._items if predicate(r)))

    def named(self, name: str) -> DecoratorCollection:
        """Filter by short decorator name."""
        return DecoratorCollection(tuple(r for r in self._items if r.name == name))

    def with_fqn(self, fqn: str) -> DecoratorCollection:
        """Filter by resolved FQN."""
        return DecoratorCollection(tuple(r for r in self._items if r.fqn == fqn))

    def on_function(self, target_fqn: str) -> DecoratorCollection:
        """Keep decorators applied to a specific function or class FQN."""
        return DecoratorCollection(tuple(r for r in self._items if r.target_fqn == target_fqn))

    def on_function_named(self, name: str) -> DecoratorCollection:
        """Keep decorators whose target function short name matches."""
        return DecoratorCollection(
            tuple(r for r in self._items if r.target_fqn.rsplit(".", 1)[-1] == name)
        )

    def in_file(self, path: str) -> DecoratorCollection:
        """Keep decorators in the given file."""
        return DecoratorCollection(tuple(r for r in self._items if r.location.file == path))


# =====================================================================
# ImportCollection
# =====================================================================


class ImportCollection(_BaseCollection[ImportFact]):
    """Filterable set of ``ImportFact`` records."""

    __slots__ = ()

    def where(self, predicate: Callable[[ImportFact], bool]) -> ImportCollection:
        """Keep only records matching *predicate*."""
        return ImportCollection(tuple(r for r in self._items if predicate(r)))

    def in_file(self, path: str) -> ImportCollection:
        """Keep imports in the given file."""
        return ImportCollection(tuple(r for r in self._items if r.location.file == path))

    def importing(self, module: str) -> ImportCollection:
        """Keep imports of the given module name."""
        return ImportCollection(tuple(r for r in self._items if r.module == module))

    def importing_name(self, name: str) -> ImportCollection:
        """Keep imports that import a specific name (``from m import name``)."""
        return ImportCollection(tuple(r for r in self._items if name in r.names))


# =====================================================================
# AttributeAccessCollection
# =====================================================================


class AttributeAccessCollection(_BaseCollection[AttributeAccess]):
    """Filterable set of ``AttributeAccess`` facts."""

    __slots__ = ()

    def where(self, predicate: Callable[[AttributeAccess], bool]) -> AttributeAccessCollection:
        """Keep only records matching *predicate*."""
        return AttributeAccessCollection(tuple(r for r in self._items if predicate(r)))

    def reads_on(self, target_expr: str) -> AttributeAccessCollection:
        """Reads on a specific target expression."""
        return AttributeAccessCollection(
            tuple(r for r in self._items if not r.is_write and r.target_expr == target_expr)
        )

    def writes_on(self, target_expr: str) -> AttributeAccessCollection:
        """Writes on a specific target expression."""
        return AttributeAccessCollection(
            tuple(r for r in self._items if r.is_write and r.target_expr == target_expr)
        )

    def named(self, attr_name: str) -> AttributeAccessCollection:
        """All accesses of a named attribute."""
        return AttributeAccessCollection(tuple(r for r in self._items if r.attr_name == attr_name))

    def in_function(self, fqn: str) -> AttributeAccessCollection:
        """All accesses within a specific function."""
        return AttributeAccessCollection(
            tuple(r for r in self._items if r.containing_function_fqn == fqn)
        )

    def in_file(self, path: str) -> AttributeAccessCollection:
        """All accesses in a specific file."""
        return AttributeAccessCollection(tuple(r for r in self._items if r.location.file == path))

    def reads(self) -> AttributeAccessCollection:
        """All reads (non-writes)."""
        return AttributeAccessCollection(tuple(r for r in self._items if not r.is_write))

    def writes(self) -> AttributeAccessCollection:
        """All writes."""
        return AttributeAccessCollection(tuple(r for r in self._items if r.is_write))

    def of_kind(self, kind: AccessKind) -> AttributeAccessCollection:
        """All accesses of a specific kind."""
        return AttributeAccessCollection(tuple(r for r in self._items if r.access_kind == kind))


# =====================================================================
# ValueFlowEdgeCollection
# =====================================================================


class ValueFlowEdgeCollection(_BaseCollection[ValueFlowEdge]):
    """Filterable set of ``ValueFlowEdge`` facts."""

    __slots__ = ()

    def where(self, predicate: Callable[[ValueFlowEdge], bool]) -> ValueFlowEdgeCollection:
        """Keep only edges matching *predicate*."""
        return ValueFlowEdgeCollection(tuple(r for r in self._items if predicate(r)))

    def in_function(self, fqn: str) -> ValueFlowEdgeCollection:
        """Edges within a specific function."""
        return ValueFlowEdgeCollection(
            tuple(r for r in self._items if r.containing_function_fqn == fqn)
        )


# =====================================================================
# SymbolRefCollection
# =====================================================================


class SymbolRefCollection(_BaseCollection[SymbolRef]):
    """Filterable set of ``SymbolRef`` facts."""

    __slots__ = ()

    def where(self, predicate: Callable[[SymbolRef], bool]) -> SymbolRefCollection:
        """Keep only refs matching *predicate*."""
        return SymbolRefCollection(tuple(r for r in self._items if predicate(r)))

    def in_file(self, path: str) -> SymbolRefCollection:
        """Refs in a specific file."""
        return SymbolRefCollection(tuple(r for r in self._items if r.location.file == path))


# =====================================================================
# ExtractionErrorCollection
# =====================================================================


class ExtractionErrorCollection(_BaseCollection[ExtractionError]):
    """Filterable set of ``ExtractionError`` records."""

    __slots__ = ()

    def where(self, predicate: Callable[[ExtractionError], bool]) -> ExtractionErrorCollection:
        """Keep only errors matching *predicate*."""
        return ExtractionErrorCollection(tuple(r for r in self._items if predicate(r)))

    def in_file(self, path: str) -> ExtractionErrorCollection:
        """Errors in a specific file."""
        return ExtractionErrorCollection(tuple(r for r in self._items if r.file == path))

    def for_pass(self, pass_name: str) -> ExtractionErrorCollection:
        """Errors from a specific extraction pass."""
        return ExtractionErrorCollection(tuple(r for r in self._items if r.pass_name == pass_name))

    def fatal(self) -> ExtractionErrorCollection:
        """Only fatal errors."""
        return ExtractionErrorCollection(tuple(r for r in self._items if r.is_fatal))
