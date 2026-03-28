"""Collection ergonomics + fail-soft tests.

Covers FLAW-156 (``__getitem__``/``__or__``), FLAW-157 (``group_by``/
``count_by``/``tabulate``), the FLAW-129 collection ``__repr__`` and the
``AnyContainer`` wildcard, and FLAW-143 (``open_repo`` no-fail-open warning).

The concrete collections wrap a plain tuple, so lightweight ``SimpleNamespace``
stand-ins exercise the generic operations without building heavy domain objects.
"""

from __future__ import annotations

from operator import attrgetter
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

from flawed import _routeless_warning
from flawed._semantic._collections import (
    ConcreteFunctionCollection,
    ConcreteInputReadCollection,
    ConcreteRouteCollection,
    _CollectionOps,
    _source_matches,
)
from flawed.core import Key
from flawed.inputs import AnyContainer, AnyOf, DependencyInput, Header, Query

if TYPE_CHECKING:
    from flawed.function import Function
    from flawed.inputs import InputRead
    from flawed.route import Route


def _route(**attrs: object) -> Route:
    """A SimpleNamespace stand-in for Route: the collection only reads attrs."""
    return cast("Route", SimpleNamespace(**attrs))


def _func(**attrs: object) -> Function:
    """A SimpleNamespace stand-in for Function (unhashable equality-fallback path)."""
    return cast("Function", SimpleNamespace(**attrs))


class _IntColl(_CollectionOps[int]):
    """Minimal collection over hashable items (exercises the fast dedup path)."""

    __slots__ = ("_items",)

    def __init__(self, items: tuple[int, ...]) -> None:
        self._items = tuple(items)

    def __iter__(self):
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)


def _routes(count: int, **constant: object) -> ConcreteRouteCollection:
    return ConcreteRouteCollection(
        tuple(_route(endpoint=f"e{i}", **constant) for i in range(count))
    )


def test_getitem_int_returns_element() -> None:
    coll = _routes(5)
    assert coll[0].endpoint == "e0"
    assert coll[-1].endpoint == "e4"


def test_getitem_slice_returns_same_type_collection() -> None:
    coll = _routes(5)
    sub = coll[:2]
    assert isinstance(sub, ConcreteRouteCollection)
    assert [r.endpoint for r in sub] == ["e0", "e1"]


def test_or_union_dedups_hashable() -> None:
    union = _IntColl((1, 2, 3)) | _IntColl((3, 4))
    assert isinstance(union, _IntColl)
    assert tuple(union) == (1, 2, 3, 4)


def test_or_union_dedups_unhashable() -> None:
    # SimpleNamespace is unhashable -> exercises the equality fallback path.
    a = ConcreteFunctionCollection((_func(name="x"), _func(name="y")))
    b = ConcreteFunctionCollection((_func(name="y"), _func(name="z")))
    names = [f.name for f in (a | b)]
    assert names == ["x", "y", "z"]


def test_or_rejects_mismatched_types() -> None:
    import pytest

    with pytest.raises(TypeError):
        # Mismatched collection types is a deliberate type error: we assert the
        # runtime guard raises, so the static |-operator complaint is expected.
        _ = _routes(1) | ConcreteFunctionCollection((_func(name="x"),))  # type: ignore[operator]


def test_group_by_attr_and_callable() -> None:
    coll = ConcreteRouteCollection(
        tuple(_route(endpoint=f"e{i}", method="GET" if i < 3 else "POST") for i in range(5))
    )
    groups = coll.group_by("method")
    assert set(groups) == {"GET", "POST"}
    assert isinstance(groups["GET"], ConcreteRouteCollection)
    assert len(groups["GET"]) == 3
    assert len(coll.group_by(attrgetter("method"))["POST"]) == 2


def test_count_by() -> None:
    coll = ConcreteRouteCollection(
        tuple(_route(endpoint=f"e{i}", method="GET" if i < 3 else "POST") for i in range(5))
    )
    counts = coll.count_by("method")
    assert counts["GET"] == 3
    assert counts["POST"] == 2


def test_tabulate_prints_aligned(capsys) -> None:
    coll = ConcreteRouteCollection(
        (
            _route(endpoint="login", method="POST"),
            _route(endpoint="x", method="GET"),
        )
    )
    coll.tabulate("endpoint", "method")
    out = capsys.readouterr().out
    assert "endpoint" in out and "login" in out and "POST" in out
    # "x" is padded to the width of "login" (column alignment).
    assert "x    " in out


def test_repr_is_concise_and_elides() -> None:
    coll = _routes(75)
    rendered = repr(coll)
    assert rendered.startswith("RouteCollection(75)")
    assert "+72 more" in rendered
    assert len(rendered) < 2000  # never dumps all 75
    assert repr(ConcreteRouteCollection(())) == "RouteCollection(0) []"


def test_anycontainer_wildcard_matches_any_key() -> None:
    read_source = Query(key=Key("id"))
    assert _source_matches(read_source, AnyContainer())  # wildcard (key=None)
    assert _source_matches(read_source, AnyContainer(key=Key("id")))
    assert not _source_matches(read_source, AnyContainer(key=Key("other")))


def test_from_source_matches_dependency_parameter_key() -> None:
    """FLAW-257 fast-follow (review H1/M1): the production L2 source-filter path
    must see ``parameter``-keyed sources.

    ``DependencyInput``'s identifying field is ``parameter``; the old hand-rolled
    ``_source_key`` looped only ``key``/``name``/``field``/``path``, so it returned
    ``None`` for a dependency-injected source and ``AnyContainer(key=...)`` could
    never match it on the path rules actually hit (``reads.from_source(...)``) —
    a false negative. Now ``_source_key`` delegates to ``InputSource.identifier``.
    """
    dep = DependencyInput(parameter=Key("db"))
    # Direct matcher: ``parameter`` is now a first-class identifier.
    assert _source_matches(dep, AnyContainer(key=Key("db")))
    assert not _source_matches(dep, AnyContainer(key=Key("other")))
    assert _source_matches(dep, AnyContainer())  # wildcard still matches

    # Through the production ``ConcreteInputReadCollection.from_source`` filter.
    reads = ConcreteInputReadCollection((cast("InputRead", SimpleNamespace(source=dep)),))
    assert len(reads.from_source(AnyContainer(key=Key("db")))) == 1
    assert len(reads.from_source(AnyContainer(key=Key("other")))) == 0


def test_inputsource_matches_is_the_single_matcher() -> None:
    """FLAW-271: the matcher logic lives once, on ``InputSource.matches`` -- the
    module-level ``_source_matches`` helpers (here and in ``flow.py``) are thin
    delegates so the two copies can never drift again.
    """
    q = Query(key=Key("id"))
    # AnyContainer wildcard + keyed, type-aware concrete match, AnyOf union.
    assert q.matches(AnyContainer())
    assert q.matches(AnyContainer(key=Key("id")))
    assert not q.matches(AnyContainer(key=Key("other")))
    assert q.matches(Query())  # wildcard same-type
    assert q.matches(Query(key=Key("id")))
    assert not q.matches(Query(key=Key("other")))
    assert not q.matches(Header(name=Key("id")))  # type mismatch
    assert q.matches(AnyOf(sources=(Header(name=Key("x")), Query())))
    assert not q.matches(AnyOf(sources=(Header(), Query(key=Key("zz")))))
    # ``parameter``-keyed source matches via the unified identifier.
    assert DependencyInput(parameter=Key("db")).matches(AnyContainer(key=Key("db")))
    # The module-level delegate routes to the method.
    assert _source_matches(q, AnyContainer(key=Key("id")))


def test_routeless_warning_policy() -> None:
    assert _routeless_warning(1134, 0, "/p") is not None  # substantial repo, no routes
    assert "/p" in _routeless_warning(1134, 0, "/p")  # type: ignore[operator]
    assert _routeless_warning(0, 0, "/p") is None  # genuinely empty repo: no false alarm
    assert _routeless_warning(100, 5, "/p") is None  # routes present: fine
    assert _routeless_warning(14, 0, "/p") is None  # small non-web module: stay quiet
