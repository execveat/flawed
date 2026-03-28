"""Concrete Rule API collection implementations.

Layer 2 provides concrete collection classes that implement the same
interface as the abstract classes in ``flawed.collections`` WITHOUT
subclassing them — direct import of ``flawed.collections`` is forbidden
by import-linter contracts.

These wrap tuples of converted L3 domain objects with typed query methods.
All collections are immutable: every filter returns a new instance.

All L3 type references use TYPE_CHECKING-only imports to avoid triggering
transitive forbidden-module chains through import-linter.  Runtime access
works because ``from __future__ import annotations`` makes all annotations
string-only and the actual objects are passed in at construction time.
"""

from __future__ import annotations

import ast
import fnmatch
from collections import Counter
from itertools import chain
from typing import TYPE_CHECKING, Generic, Self, TypeVar, cast, overload

from flawed._index._parsing import parse_analyzed_module
from flawed.inputs import InputValueType

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator

    from flawed._semantic._cfgview import ControlFlowView
    from flawed.blueprint import Blueprint
    from flawed.calls import CallSite, FnSelector
    from flawed.class_ import Class
    from flawed.effects import Effect, EffectSelector
    from flawed.flow import ValueHandle
    from flawed.function import Decorator, Function
    from flawed.generated import SafeGeneratedURL
    from flawed.inputs import InputRead, InputSource
    from flawed.route import Route
    from flawed.sinks import TaintSink
    from flawed.validation import ValidatedValue


_T = TypeVar("_T")


def _as_keyfn(key: str | Callable[[object], object]) -> Callable[[object], object]:
    """Normalize a group/count key spec to a callable.

    A string is treated as an attribute name; a callable is used as-is.
    """
    if callable(key):
        return key
    attr = key
    return lambda item: getattr(item, attr)


class _CollectionOps(Generic[_T]):
    """Generic sequence / grouping / repr behaviour shared by every concrete
    Rule API collection.

    This mixin lives in Layer 2 on purpose.  ``import-linter`` forbids
    ``flawed._semantic`` from importing the Layer 3 ``flawed.collections``
    surface, so the concrete collections *cannot* inherit the abstract
    ``DomainCollection`` — they would have to import across a layer boundary.
    Centralizing the shared behaviour here keeps it DRY across the dozen
    concrete classes without crossing layers; the Layer 3 ``DomainCollection``
    advertises the same method signatures for type checkers and rule authors.

    Subclasses provide ``__iter__``/``__len__`` (and, for non-trivial
    constructors, override :meth:`_rebuild`).
    """

    __slots__ = ()

    _PREVIEW = 3
    """Number of items shown inline by ``__repr__`` before eliding the rest."""

    if TYPE_CHECKING:
        # Provided by every concrete collection; declared here so the mixin's
        # generic operations type-check without redefining them at runtime.
        def __iter__(self) -> Iterator[_T]: ...
        def __len__(self) -> int: ...

    def _rebuild(self, items: tuple[_T, ...]) -> Self:
        """Construct a new same-type collection from *items*.

        Defaults to the ``type(self)(items)`` constructor shape shared by
        almost every concrete collection.  Collections that carry extra
        construction context (e.g. taint sinks) override this.
        """
        return type(self)(items)  # type: ignore[call-arg]

    @overload
    def __getitem__(self, index: int) -> _T: ...
    @overload
    def __getitem__(self, index: slice) -> Self: ...
    def __getitem__(self, index: int | slice) -> _T | Self:
        """Index (``coll[0]``) or slice (``coll[:5]`` → a new collection).

        Returning a single item avoids the ``list(coll)[0]`` idiom that
        materialized and rendered the entire collection.
        """
        items = tuple(self)
        if isinstance(index, slice):
            return self._rebuild(items[index])
        return items[index]

    def __or__(self, other: Self) -> Self:
        """Union with another collection of the same type, deduplicated.

        Order is preserved (this collection first); duplicates are dropped by
        value equality (frozen domain objects compare by field), falling back
        to identity for any unhashable item.
        """
        if type(other) is not type(self):
            msg = f"cannot union {type(self).__name__} with {type(other).__name__}"
            raise TypeError(msg)
        seen_hashable: set[object] = set()
        seen_unhashable: list[_T] = []
        merged: list[_T] = []
        for item in chain(self, cast("Iterable[_T]", other)):
            try:
                if item in seen_hashable:
                    continue
                seen_hashable.add(item)
            except TypeError:
                if any(item is prior or item == prior for prior in seen_unhashable):
                    continue
                seen_unhashable.append(item)
            merged.append(item)
        return self._rebuild(tuple(merged))

    def group_by(self, key: str | Callable[[_T], object]) -> dict[object, Self]:
        """Partition into ``{key_value: sub-collection}`` preserving order.

        *key* is an attribute name or a callable applied to each item.
        """
        keyfn = _as_keyfn(cast("str | Callable[[object], object]", key))
        buckets: dict[object, list[_T]] = {}
        for item in self:
            buckets.setdefault(keyfn(item), []).append(item)
        return {value: self._rebuild(tuple(items)) for value, items in buckets.items()}

    def count_by(self, key: str | Callable[[_T], object]) -> Counter[object]:
        """Count items by *key* (attribute name or callable) as a ``Counter``."""
        keyfn = _as_keyfn(cast("str | Callable[[object], object]", key))
        return Counter(keyfn(item) for item in self)

    def tabulate(self, *columns: str | Callable[[_T], object]) -> None:
        """Print the collection as aligned columns to stdout.

        Each column is an attribute name (also used as the header) or a
        callable.  With no columns, prints one item ``repr`` per line.
        """
        items = tuple(self)
        if not columns:
            for item in items:
                print(repr(item))
            return
        headers = [col if isinstance(col, str) else f"col{i}" for i, col in enumerate(columns)]
        keyfns = [_as_keyfn(cast("str | Callable[[object], object]", col)) for col in columns]
        rows = [[str(keyfn(item)) for keyfn in keyfns] for item in items]
        widths = [
            max([len(headers[i]), *(len(row[i]) for row in rows)]) for i in range(len(columns))
        ]

        def _fmt(cells: list[str]) -> str:
            return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells))

        print(_fmt(headers))
        print("  ".join("-" * width for width in widths))
        for row in rows:
            print(_fmt(row))

    def __repr__(self) -> str:
        name = type(self).__name__.removeprefix("Concrete")
        items = tuple(self)
        count = len(items)
        if count == 0:
            return f"{name}(0) []"
        shown = ", ".join(repr(item) for item in items[: self._PREVIEW])
        more = f", +{count - self._PREVIEW} more" if count > self._PREVIEW else ""
        return f"{name}({count}) [{shown}{more}]"


# =====================================================================
# ConcreteConditionCollection
# =====================================================================


class ConcreteConditionCollection(_CollectionOps[object]):
    """Concrete filterable collection of ``Condition`` domain objects."""

    __slots__ = ("_items",)

    def __init__(self, items: tuple[object, ...]) -> None:
        self._items = items

    def __iter__(self) -> Iterator[object]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return len(self._items) > 0

    def where(self, predicate: Callable[[object], bool]) -> Self:
        """Keep only conditions matching *predicate*."""
        return type(self)(tuple(condition for condition in self._items if predicate(condition)))

    def first(self) -> object | None:
        """First item, or ``None`` if empty."""
        return self._items[0] if self._items else None

    def one(self) -> object:
        """Exactly one item, or raise ``ValueError``."""
        if len(self._items) != 1:
            msg = f"expected exactly 1 item, got {len(self._items)}"
            raise ValueError(msg)
        return self._items[0]

    def using(self, value: ValueHandle) -> Self:
        """Keep conditions whose expression or operands reference *value*."""
        value_expr = getattr(value, "expression", None)
        if value_expr is None:
            return type(self)(())
        return type(self)(
            tuple(condition for condition in self._items if _condition_uses(condition, value_expr))
        )

    def comparing(self, left_pattern: str, right_pattern: str) -> Self:
        """Keep comparisons whose left/right operands match the given patterns."""
        return type(self)(
            tuple(
                condition
                for condition in self._items
                if _matches_operand(getattr(condition, "left", None), left_pattern)
                and _matches_operand(getattr(condition, "right", None), right_pattern)
            )
        )


class ConcretePredicateCollection(_CollectionOps[object]):
    """Concrete filterable collection of ``Predicate`` domain objects.

    Sibling to :class:`ConcreteConditionCollection` for predicates
    produced as values (``return token is not None``) rather than branch
    tests.
    """

    __slots__ = ("_items",)

    def __init__(self, items: tuple[object, ...]) -> None:
        self._items = items

    def __iter__(self) -> Iterator[object]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return len(self._items) > 0

    def where(self, predicate: Callable[[object], bool]) -> Self:
        """Keep only predicates matching *predicate*."""
        return type(self)(tuple(item for item in self._items if predicate(item)))

    def first(self) -> object | None:
        """First item, or ``None`` if empty."""
        return self._items[0] if self._items else None

    def one(self) -> object:
        """Exactly one item, or raise ``ValueError``."""
        if len(self._items) != 1:
            msg = f"expected exactly 1 item, got {len(self._items)}"
            raise ValueError(msg)
        return self._items[0]

    def comparing(self, left_pattern: str, right_pattern: str) -> Self:
        """Keep predicates whose left/right operands match the given patterns."""
        return type(self)(
            tuple(
                item
                for item in self._items
                if _matches_operand(getattr(item, "left", None), left_pattern)
                and _matches_operand(getattr(item, "right", None), right_pattern)
            )
        )


def _condition_uses(condition: object, expression: str) -> bool:
    operands = (getattr(condition, "left", None), getattr(condition, "right", None))
    if any(getattr(operand, "expression", None) == expression for operand in operands):
        return True
    condition_expression = getattr(condition, "expression", None)
    return isinstance(condition_expression, str) and expression in condition_expression


def _matches_operand(value: ValueHandle | None, pattern: str) -> bool:
    expression = getattr(value, "expression", None)
    return isinstance(expression, str) and fnmatch.fnmatch(expression, pattern)


# =====================================================================
# ConcreteDecoratorCollection
# =====================================================================


class ConcreteDecoratorCollection(_CollectionOps["Decorator"]):
    """Concrete filterable collection of ``Decorator`` domain objects.

    Implements the same interface as ``flawed.collections.DecoratorCollection``
    without subclassing it (to satisfy layer contracts).
    """

    __slots__ = ("_items",)

    def __init__(self, items: tuple[Decorator, ...]) -> None:
        self._items = items

    def __iter__(self) -> Iterator[Decorator]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return len(self._items) > 0

    def first(self) -> Decorator | None:
        """First item, or ``None`` if empty."""
        return self._items[0] if self._items else None

    def one(self) -> Decorator:
        """Exactly one item, or raise ``ValueError``."""
        if len(self._items) != 1:
            msg = f"expected exactly 1 item, got {len(self._items)}"
            raise ValueError(msg)
        return self._items[0]

    def named(self, name: str) -> Self:
        """Filter by decorator short name."""
        return type(self)(tuple(d for d in self._items if d.name == name))

    def with_fqn(self, fqn: str) -> Self:
        """Filter by decorator FQN."""
        return type(self)(tuple(d for d in self._items if d.fqn == fqn))


# =====================================================================
# ConcreteInputReadCollection
# =====================================================================


class ConcreteInputReadCollection(_CollectionOps["InputRead"]):
    """Concrete filterable collection of ``InputRead`` domain objects."""

    __slots__ = ("_items",)

    def __init__(self, items: tuple[InputRead, ...]) -> None:
        self._items = items

    def __iter__(self) -> Iterator[InputRead]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return len(self._items) > 0

    def where(self, predicate: Callable[[InputRead], bool]) -> Self:
        """Keep only input reads matching *predicate*."""
        return type(self)(tuple(read for read in self._items if predicate(read)))

    def first(self) -> InputRead | None:
        """First item, or ``None`` if empty."""
        return self._items[0] if self._items else None

    def one(self) -> InputRead:
        """Exactly one item, or raise ``ValueError``."""
        if len(self._items) != 1:
            msg = f"expected exactly 1 item, got {len(self._items)}"
            raise ValueError(msg)
        return self._items[0]

    def in_file(self, path: str) -> Self:
        """Keep only reads in the given file."""
        return type(self)(tuple(read for read in self._items if read.location.file.endswith(path)))

    def in_dir(self, path: str) -> Self:
        """Keep only reads in the given directory."""
        return type(self)(tuple(read for read in self._items if path in read.location.file))

    def from_source(self, source: InputSource) -> Self:
        """Filter to reads whose source matches *source*."""
        return type(self)(
            tuple(read for read in self._items if _source_matches(read.source, source))
        )


def _source_matches(actual: InputSource, expected: InputSource) -> bool:
    """Whether the read's *actual* source satisfies the *expected* pattern.

    Thin delegate to :meth:`flawed.inputs.InputSource.matches` (FLAW-271).  Kept
    as a module-level helper because ``_flow_engine`` imports it by name; the
    matcher logic itself lives exactly once, on the domain type, so the L2 and
    L3 copies that previously drifted (review H1/M1) can no longer diverge.
    """
    return actual.matches(expected)


# =====================================================================
# ConcreteEffectCollection
# =====================================================================


class ConcreteEffectCollection(_CollectionOps["Effect"]):
    """Concrete filterable collection of ``Effect`` domain objects."""

    __slots__ = ("_items",)

    def __init__(self, items: tuple[Effect, ...]) -> None:
        self._items = items

    def __iter__(self) -> Iterator[Effect]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return len(self._items) > 0

    def where(self, predicate: Callable[[Effect], bool]) -> Self:
        """Keep only effects matching *predicate*."""
        return type(self)(tuple(effect for effect in self._items if predicate(effect)))

    def first(self) -> Effect | None:
        """First item, or ``None`` if empty."""
        return self._items[0] if self._items else None

    def one(self) -> Effect:
        """Exactly one item, or raise ``ValueError``."""
        if len(self._items) != 1:
            msg = f"expected exactly 1 item, got {len(self._items)}"
            raise ValueError(msg)
        return self._items[0]

    def in_file(self, path: str) -> Self:
        """Keep only effects in the given file."""
        return type(self)(
            tuple(effect for effect in self._items if effect.location.file.endswith(path))
        )

    def in_dir(self, path: str) -> Self:
        """Keep only effects in the given directory."""
        return type(self)(tuple(effect for effect in self._items if path in effect.location.file))

    def matching(self, selector: EffectSelector) -> Self:
        """Filter to effects matching *selector*."""
        return type(self)(
            tuple(effect for effect in self._items if _effect_matches(effect, selector))
        )


def _effect_matches(effect: Effect, selector: EffectSelector) -> bool:
    if effect.category not in selector.categories:
        return False
    if selector.key_filter is not None and effect.key not in selector.key_filter:
        return False
    if selector.scope_filter is not None:
        if effect.scope is None:
            return False
        return bool(effect.scope & selector.scope_filter)
    return True


# =====================================================================
# ConcreteCallSiteCollection
# =====================================================================


class ConcreteCallSiteCollection(_CollectionOps["CallSite"]):
    """Concrete filterable collection of ``CallSite`` domain objects."""

    __slots__ = ("_items",)

    def __init__(self, items: tuple[CallSite, ...]) -> None:
        self._items = items

    def __iter__(self) -> Iterator[CallSite]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return len(self._items) > 0

    def where(self, predicate: Callable[[CallSite], bool]) -> Self:
        """Keep only call sites matching *predicate*."""
        return type(self)(tuple(call for call in self._items if predicate(call)))

    def first(self) -> CallSite | None:
        """First item, or ``None`` if empty."""
        return self._items[0] if self._items else None

    def one(self) -> CallSite:
        """Exactly one item, or raise ``ValueError``."""
        if len(self._items) != 1:
            msg = f"expected exactly 1 item, got {len(self._items)}"
            raise ValueError(msg)
        return self._items[0]

    def in_file(self, path: str) -> Self:
        """Keep only call sites in the given file."""
        return type(self)(tuple(call for call in self._items if call.location.file.endswith(path)))

    def in_dir(self, path: str) -> Self:
        """Keep only call sites in the given directory."""
        return type(self)(tuple(call for call in self._items if path in call.location.file))

    def to(self, selector: FnSelector) -> Self:
        """Filter to call sites targeting functions matching *selector*."""
        return type(self)(tuple(call for call in self._items if selector.matches_call(call)))

    def with_argument_from(self, value: ValueHandle) -> Self:
        """Filter to call sites with an argument matching *value*.

        Full interprocedural value-flow is implemented in a later phase.  This
        concrete collection still supports the common exact-expression case so
        call-site rules can compose while broader flow precision lands.
        """
        value_expr = getattr(value, "expression", None)
        return type(self)(
            tuple(
                call
                for call in self._items
                if any(arg.expression == value_expr for arg in call.arguments)
            )
        )


# =====================================================================
# ConcreteValidatedValueCollection
# =====================================================================


class ConcreteValidatedValueCollection(_CollectionOps["ValidatedValue"]):
    """Concrete filterable collection of ``ValidatedValue`` domain objects."""

    __slots__ = ("_items",)

    def __init__(self, items: tuple[ValidatedValue, ...]) -> None:
        self._items = items

    def __iter__(self) -> Iterator[ValidatedValue]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return len(self._items) > 0

    def where(self, predicate: Callable[[ValidatedValue], bool]) -> Self:
        """Keep only validated values matching *predicate*."""
        return type(self)(tuple(value for value in self._items if predicate(value)))

    def first(self) -> ValidatedValue | None:
        """First item, or ``None`` if empty."""
        return self._items[0] if self._items else None

    def one(self) -> ValidatedValue:
        """Exactly one item, or raise ``ValueError``."""
        if len(self._items) != 1:
            msg = f"expected exactly 1 item, got {len(self._items)}"
            raise ValueError(msg)
        return self._items[0]

    def named(self, name: str) -> Self:
        """Filter by validator function name."""
        return type(self)(tuple(v for v in self._items if _call_name(v.expression) == name))

    def in_file(self, path: str) -> Self:
        """Keep only validated values in the given file."""
        return type(self)(
            tuple(value for value in self._items if value.location.file.endswith(path))
        )

    def in_dir(self, path: str) -> Self:
        """Keep only validated values in the given directory."""
        return type(self)(tuple(value for value in self._items if path in value.location.file))

    def safe_for(self, kind: str) -> Self:
        """Keep only values validated for the given sink taxonomy value."""
        return type(self)(
            tuple(value for value in self._items if kind in value.safe_for_sink_kinds)
        )


def _call_name(expression: str) -> str:
    target = expression.split("(", 1)[0].strip()
    return target.rsplit(".", 1)[-1]


# =====================================================================
# ConcreteSafeGeneratedURLCollection
# =====================================================================


class ConcreteSafeGeneratedURLCollection(_CollectionOps["SafeGeneratedURL"]):
    """Concrete filterable collection of ``SafeGeneratedURL`` domain objects."""

    __slots__ = ("_items",)

    def __init__(self, items: tuple[SafeGeneratedURL, ...]) -> None:
        self._items = items

    def __iter__(self) -> Iterator[SafeGeneratedURL]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return len(self._items) > 0

    def where(self, predicate: Callable[[SafeGeneratedURL], bool]) -> Self:
        """Keep only generated URLs matching *predicate*."""
        return type(self)(tuple(url for url in self._items if predicate(url)))

    def first(self) -> SafeGeneratedURL | None:
        """First item, or ``None`` if empty."""
        return self._items[0] if self._items else None

    def one(self) -> SafeGeneratedURL:
        """Exactly one item, or raise ``ValueError``."""
        if len(self._items) != 1:
            msg = f"expected exactly 1 item, got {len(self._items)}"
            raise ValueError(msg)
        return self._items[0]

    def in_file(self, path: str) -> Self:
        """Keep only generated URLs in the given file."""
        return type(self)(tuple(url for url in self._items if url.location.file.endswith(path)))

    def in_dir(self, path: str) -> Self:
        """Keep only generated URLs in the given directory."""
        return type(self)(tuple(url for url in self._items if path in url.location.file))

    def safe_for(self, kind: str) -> Self:
        """Keep only generated URLs safe for the given sink taxonomy value."""
        return type(self)(tuple(url for url in self._items if kind in url.safe_for_sink_kinds))


# =====================================================================
# ConcreteTaintSinkCollection
# =====================================================================


class ConcreteTaintSinkCollection(_CollectionOps["TaintSink"]):
    """Concrete filterable collection of flow-reached ``TaintSink`` objects."""

    __slots__ = (
        "_cfg",
        "_flow_reached_cache",
        "_input_reads",
        "_items",
        "_safe_generated_urls",
        "_validated_values",
    )

    def __init__(
        self,
        items: tuple[TaintSink, ...],
        *,
        input_reads: tuple[InputRead, ...] = (),
        safe_generated_urls: tuple[SafeGeneratedURL, ...] = (),
        validated_values: tuple[ValidatedValue, ...] = (),
        cfg: ControlFlowView | None = None,
    ) -> None:
        self._items = items
        self._input_reads = input_reads
        self._safe_generated_urls = safe_generated_urls
        self._validated_values = validated_values
        self._cfg = cfg
        self._flow_reached_cache: tuple[TaintSink, ...] | None = None

    def __iter__(self) -> Iterator[TaintSink]:
        return iter(self._flow_reached_items())

    def __len__(self) -> int:
        return len(self._flow_reached_items())

    def __bool__(self) -> bool:
        return len(self) > 0

    def _rebuild(self, items: tuple[TaintSink, ...]) -> Self:
        """Rebuild preserving flow-reaching context (input reads, cfg, ...).

        Overrides the default ``type(self)(items)`` because this collection's
        constructor carries the context needed to recompute flow-reachability.
        """
        return type(self)(
            items,
            input_reads=self._input_reads,
            safe_generated_urls=self._safe_generated_urls,
            validated_values=self._validated_values,
            cfg=self._cfg,
        )

    def where(self, predicate: Callable[[TaintSink], bool]) -> Self:
        """Keep only sinks matching *predicate*."""
        return type(self)(
            tuple(sink for sink in self._items if predicate(sink)),
            input_reads=self._input_reads,
            safe_generated_urls=self._safe_generated_urls,
            validated_values=self._validated_values,
            cfg=self._cfg,
        )

    def first(self) -> TaintSink | None:
        """First item, or ``None`` if empty."""
        items = self._flow_reached_items()
        return items[0] if items else None

    def one(self) -> TaintSink:
        """Exactly one item, or raise ``ValueError``."""
        items = self._flow_reached_items()
        if len(items) != 1:
            msg = f"expected exactly 1 item, got {len(items)}"
            raise ValueError(msg)
        return items[0]

    def in_file(self, path: str) -> Self:
        """Keep only sinks in the given file."""
        return self.where(lambda sink: sink.location.file.endswith(path))

    def in_dir(self, path: str) -> Self:
        """Keep only sinks in the given directory."""
        return self.where(lambda sink: path in sink.location.file)

    def of_kind(self, kind: str) -> Self:
        """Keep only sinks with the given taxonomy value."""
        return self.where(lambda sink: sink.kind == kind)

    def _flow_reached_items(self) -> tuple[TaintSink, ...]:
        cached = self._flow_reached_cache
        if cached is not None:
            return cached
        if not self._input_reads:
            self._flow_reached_cache = ()
            return ()
        result = tuple(
            sink
            for sink in self._items
            if _sink_is_reachable(
                sink,
                self._input_reads,
                self._safe_generated_urls,
                self._validated_values,
                self._cfg,
            )
        )
        self._flow_reached_cache = result
        return result


def _sink_is_reachable(
    sink: TaintSink,
    input_reads: tuple[InputRead, ...],
    safe_generated_urls: tuple[SafeGeneratedURL, ...],
    validated_values: tuple[ValidatedValue, ...],
    cfg: ControlFlowView | None,
) -> bool:
    """Check whether a sink is reached by any input read in scope.

    Sinks whose provider ``when=`` predicate passed (``_predicate_validated``)
    use scope-coincidence over string-compatible reads.  This handles f-string,
    concatenation, and ``.format()`` patterns where the L1 value-flow graph
    cannot prove the connection, without treating constrained integer route
    parameters as satisfying string-only sink predicates.

    Sinks without a validated predicate require proven flow from at least one
    input read via the value-flow graph.
    """
    if _sink_target_is_safe_generated_url(sink, safe_generated_urls):
        return False
    if _sink_target_is_validated(sink, input_reads, validated_values, cfg):
        return False
    if _sink_target_is_validated_helper_return(sink, validated_values):
        return False

    # Predicate-validated sinks: scope-coincidence is sufficient.
    try:
        validated = object.__getattribute__(sink, "_predicate_validated")
    except AttributeError:
        validated = False
    if validated:
        return any(_input_read_can_satisfy_string_sink(read) for read in input_reads)
    # No predicate validation: require proven flow.
    return any(read.value.flows_to(sink.target) for read in input_reads)


def _input_read_can_satisfy_string_sink(read: InputRead) -> bool:
    value_type = read.value_type
    return value_type is None or value_type is InputValueType.STRING


def _sink_target_is_validated_helper_return(
    sink: TaintSink,
    validated_values: tuple[ValidatedValue, ...],
) -> bool:
    """Return true when a sink receives a helper call that returns only validated data.

    This is a narrow path-sensitive summary for helpers shaped like::

        if validator(candidate):
            return candidate

    It suppresses flows through the helper's return value only when the same
    helper contains a provider-declared validation guard for the returned
    expression and the sink argument calls that helper.
    """
    for value in validated_values:
        if sink.kind not in value.safe_for_sink_kinds:
            continue
        helper_name = value.function.name
        if f"{helper_name}(" not in sink.argument_expression:
            continue
        if _function_returns_validated_expression(value):
            return True
    return False


def _function_returns_validated_expression(value: ValidatedValue) -> bool:
    source = value.function.source(context=0)
    try:
        tree = parse_analyzed_module(source)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        if value.expression not in ast.unparse(node.test):
            continue
        if _branch_returns_expression(node.body, value.validated_expression):
            return True
    return False


def _branch_returns_expression(statements: list[ast.stmt], expression: str) -> bool:
    for statement in statements:
        if (
            isinstance(statement, ast.Return)
            and statement.value is not None
            and ast.unparse(statement.value) == expression
        ):
            return True
        for child in ast.iter_child_nodes(statement):
            if isinstance(child, ast.If) and _branch_returns_expression(child.body, expression):
                return True
    return False


def _sink_target_is_safe_generated_url(
    sink: TaintSink,
    safe_generated_urls: tuple[SafeGeneratedURL, ...],
) -> bool:
    for safe_url in safe_generated_urls:
        if sink.kind not in safe_url.safe_for_sink_kinds:
            continue
        if _same_whole_value(sink, safe_url):
            return True
    return False


def _same_whole_value(sink: TaintSink, safe_url: SafeGeneratedURL) -> bool:
    """Return true only when the same generated whole value reaches the sink."""
    result = safe_url.value.preserves_whole_value_to(sink.target)
    if result.gaps:
        object.__setattr__(sink, "_safe_generated_url_preservation_gaps", result.gaps)
    return result.preserved


def _sink_target_is_validated(
    sink: TaintSink,
    input_reads: tuple[InputRead, ...],
    validated_values: tuple[ValidatedValue, ...],
    cfg: ControlFlowView | None,
) -> bool:
    validations = tuple(
        value
        for value in validated_values
        if sink.kind in value.safe_for_sink_kinds
        and _same_validated_value(sink, value)
        and (
            _sink_in_guarded_branch(sink, value, cfg)
            or _sink_after_negative_guard_exit(sink, value)
        )
    )
    if not validations:
        return False

    flowing_reads = tuple(read for read in input_reads if read.value.flows_to(sink.target))
    return bool(flowing_reads)


def _same_validated_value(sink: TaintSink, value: ValidatedValue) -> bool:
    """Return true when the sink argument is the same whole expression validated."""
    if sink.argument_expression != value.validated_expression:
        return False
    sink_definition = _sink_argument_definition_location(sink)
    if value.definition_location is not None and sink_definition is not None:
        return value.definition_location == sink_definition
    return True


def _sink_argument_definition_location(sink: TaintSink) -> object | None:
    try:
        value: object = object.__getattribute__(sink, "_argument_definition_location")
    except AttributeError:
        return None
    return value


def _sink_in_guarded_branch(
    sink: TaintSink,
    value: ValidatedValue,
    cfg: ControlFlowView | None,
) -> bool:
    if cfg is None:
        return False
    sink_block_id = cfg.block_id_for(sink.location)
    if sink_block_id is None:
        return False
    guarded_blocks = cfg.branch_path_block_ids(value.location, direction=value.validated_when)
    return sink_block_id in guarded_blocks


def _sink_after_negative_guard_exit(sink: TaintSink, value: ValidatedValue) -> bool:
    """Handle guard clauses like ``if not is_safe_url(x): return`` before sink use."""
    if not value.validated_when or sink.function.fqn != value.function.fqn:
        return False

    source = value.function.source(context=0)
    try:
        tree = parse_analyzed_module(source)
    except SyntaxError:
        return False

    base_line = value.function.location.line - 1
    sink_line = sink.location.line - base_line
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        if sink_line <= (node.end_lineno or node.lineno):
            continue
        if not _is_negated_guard_expression(node.test, value.expression):
            continue
        if _all_paths_exit(node.body):
            return True
    return False


def _is_negated_guard_expression(test: ast.expr, guard_expression: str) -> bool:
    return (
        isinstance(test, ast.UnaryOp)
        and isinstance(test.op, ast.Not)
        and ast.unparse(test.operand) == guard_expression
    )


def _all_paths_exit(statements: list[ast.stmt]) -> bool:
    if not statements:
        return False
    for statement in statements:
        if isinstance(statement, (ast.Return, ast.Raise)):
            return True
        if (
            isinstance(statement, ast.If)
            and _all_paths_exit(statement.body)
            and _all_paths_exit(statement.orelse)
        ):
            return True
    return False


# =====================================================================
# ConcreteFunctionCollection
# =====================================================================


class ConcreteFunctionCollection(_CollectionOps["Function"]):
    """Concrete filterable collection of ``Function`` domain objects.

    Implements the same interface as ``flawed.collections.FunctionCollection``
    without subclassing it (to satisfy layer contracts).
    """

    __slots__ = ("_items",)

    def __init__(self, items: tuple[Function, ...]) -> None:
        self._items = items

    def __iter__(self) -> Iterator[Function]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return len(self._items) > 0

    def where(self, predicate: Callable[[Function], bool]) -> Self:
        """Keep only functions matching *predicate*."""
        return type(self)(tuple(f for f in self._items if predicate(f)))

    def first(self) -> Function | None:
        """First item, or ``None`` if empty."""
        return self._items[0] if self._items else None

    def one(self) -> Function:
        """Exactly one item, or raise ``ValueError``."""
        if len(self._items) != 1:
            msg = f"expected exactly 1 item, got {len(self._items)}"
            raise ValueError(msg)
        return self._items[0]

    def in_file(self, path: str) -> Self:
        """Keep only functions in the given file."""
        return type(self)(tuple(f for f in self._items if f.location.file.endswith(path)))

    def in_dir(self, path: str) -> Self:
        """Keep only functions in the given directory."""
        return type(self)(tuple(f for f in self._items if path in f.location.file))

    def named(self, name: str) -> Self:
        """Filter by short function name."""
        return type(self)(tuple(f for f in self._items if f.name == name))

    def with_fqn(self, fqn: str) -> Self:
        """Filter by exact fully-qualified name."""
        return type(self)(tuple(f for f in self._items if f.fqn == fqn))

    def decorated_with(self, name_or_fqn: str) -> Self:
        """Filter to functions decorated with the given decorator.

        Matches against both short names and FQNs of decorators.
        Every function in this collection should be enriched with decorator
        context by ``WebApp.from_index``.
        """
        result: list[Function] = []
        for f in self._items:
            for d in f.decorators:
                if name_or_fqn in (d.name, d.fqn):
                    result.append(f)
                    break
        return type(self)(tuple(result))


# =====================================================================
# ConcreteClassCollection
# =====================================================================


class ConcreteClassCollection(_CollectionOps["Class"]):
    """Concrete filterable collection of ``Class`` domain objects.

    Implements the same interface as ``flawed.collections.ClassCollection``
    without subclassing it (to satisfy layer contracts).
    """

    __slots__ = ("_items",)

    def __init__(self, items: tuple[Class, ...]) -> None:
        self._items = items

    def __iter__(self) -> Iterator[Class]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return len(self._items) > 0

    def where(self, predicate: Callable[[Class], bool]) -> Self:
        """Keep only classes matching *predicate*."""
        return type(self)(tuple(c for c in self._items if predicate(c)))

    def first(self) -> Class | None:
        """First item, or ``None`` if empty."""
        return self._items[0] if self._items else None

    def one(self) -> Class:
        """Exactly one item, or raise ``ValueError``."""
        if len(self._items) != 1:
            msg = f"expected exactly 1 item, got {len(self._items)}"
            raise ValueError(msg)
        return self._items[0]

    def in_file(self, path: str) -> Self:
        """Keep only classes in the given file."""
        return type(self)(tuple(c for c in self._items if c.location.file.endswith(path)))

    def in_dir(self, path: str) -> Self:
        """Keep only classes in the given directory."""
        return type(self)(tuple(c for c in self._items if path in c.location.file))

    def named(self, name: str) -> Self:
        """Filter by short class name."""
        return type(self)(tuple(c for c in self._items if c.name == name))

    def with_fqn(self, fqn: str) -> Self:
        """Filter by exact fully-qualified name."""
        return type(self)(tuple(c for c in self._items if c.fqn == fqn))

    def subclasses_of(self, base: str) -> Self:
        """Transitive subclasses: classes whose MRO includes *base*."""
        return type(self)(
            tuple(
                c
                for c in self._items
                if c.fqn != base and any(base == m or base == m.rsplit(".", 1)[-1] for m in c.mro)
            )
        )

    def direct_subclasses_of(self, base: str) -> Self:
        """Direct subclasses only (single level)."""
        return type(self)(
            tuple(
                c
                for c in self._items
                if any(base == b or base == b.rsplit(".", 1)[-1] for b in c.bases)
            )
        )

    def decorated_with(self, name_or_fqn: str) -> Self:
        """Filter to classes decorated with the given decorator.

        Matches against both syntactic decorator names and resolved FQNs.
        """
        result: list[Class] = []
        for klass in self._items:
            for decorator in klass.decorators:
                if name_or_fqn in (decorator.name, decorator.fqn):
                    result.append(klass)
                    break
        return type(self)(tuple(result))


# =====================================================================
# ConcreteRouteCollection
# =====================================================================


class ConcreteRouteCollection(_CollectionOps["Route"]):
    """Concrete filterable collection of ``Route`` domain objects.

    Implements the same interface as ``flawed.collections.RouteCollection``
    without subclassing it (to satisfy layer contracts).

    Empty until the provider engine (L2-003+) produces routes.
    """

    __slots__ = ("_items",)

    def __init__(self, items: tuple[Route, ...] = ()) -> None:
        self._items: tuple[Route, ...] = items

    def __iter__(self) -> Iterator[Route]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return len(self._items) > 0

    def where(self, predicate: Callable[[Route], bool]) -> Self:
        """Keep only routes matching *predicate*."""
        return type(self)(tuple(r for r in self._items if predicate(r)))

    def first(self) -> Route | None:
        """First item, or ``None`` if empty."""
        return self._items[0] if self._items else None

    def one(self) -> Route:
        """Exactly one item, or raise ``ValueError``."""
        if len(self._items) != 1:
            msg = f"expected exactly 1 item, got {len(self._items)}"
            raise ValueError(msg)
        return self._items[0]

    def in_file(self, path: str) -> Self:
        """Keep only routes whose location is in the given file."""
        return type(self)(tuple(r for r in self._items if r.location.file.endswith(path)))

    def in_dir(self, path: str) -> Self:
        """Keep only routes whose location is in the given directory."""
        return type(self)(tuple(r for r in self._items if path in r.location.file))

    def accepting(self, *methods: object) -> Self:
        """Keep only routes accepting any of the given HTTP methods."""
        method_set = frozenset(methods)
        return type(self)(tuple(r for r in self._items if r.methods & method_set))

    def with_path(self, path: str) -> Self:
        """Keep only routes whose URL rule matches *path* exactly."""
        return type(self)(tuple(r for r in self._items if r.url_rule == path))

    def in_group(self, name: str) -> Self:
        """Keep only routes in the given group (router group, app)."""
        return type(self)(tuple(r for r in self._items if r.group == name))


# =====================================================================
# ConcreteBlueprintCollection
# =====================================================================


class ConcreteBlueprintCollection(_CollectionOps["Blueprint"]):
    """Concrete filterable collection of ``Blueprint`` domain objects.

    Implements the same interface as ``flawed.collections.BlueprintCollection``
    without subclassing it (to satisfy layer contracts).
    """

    __slots__ = ("_items",)

    def __init__(self, items: tuple[Blueprint, ...] = ()) -> None:
        self._items: tuple[Blueprint, ...] = items

    def __iter__(self) -> Iterator[Blueprint]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return len(self._items) > 0

    def where(self, predicate: Callable[[Blueprint], bool]) -> Self:
        """Keep only blueprints matching *predicate*."""
        return type(self)(tuple(b for b in self._items if predicate(b)))

    def named(self, name: str) -> Self:
        """Keep only blueprints whose group name equals *name*."""
        return type(self)(tuple(b for b in self._items if b.name == name))

    def first(self) -> Blueprint | None:
        """First item, or ``None`` if empty."""
        return self._items[0] if self._items else None

    def one(self) -> Blueprint:
        """Exactly one item, or raise ``ValueError``."""
        if len(self._items) != 1:
            msg = f"expected exactly 1 item, got {len(self._items)}"
            raise ValueError(msg)
        return self._items[0]
