"""Generic and typed collection classes for domain objects.

Every query method on :class:`~flawed.scopes.CodeScope` returns a
typed collection.  Collections support:

- **Iteration** -- ``for item in collection``
- **Length** -- ``len(collection)``
- **Boolean** -- ``if collection`` (true when non-empty)
- **Chaining** -- ``collection.where(...).in_file(...).named(...)``
  Each filter returns a new collection; the original is unchanged.
- **Extraction** -- ``.first()`` returns the first item or ``None``;
  ``.one()`` returns the single item or raises if not exactly one.

The base :class:`DomainCollection` provides generic operations.
Typed subclasses add domain-specific filters (e.g.
:meth:`FunctionCollection.named`, :meth:`RouteCollection.accepting`).

Example::

    fns = kb.functions.in_file("app.py").named("create_user")
    fn = fns.one()  # exactly one match, or raises

    for route in kb.routes.where(accepting(POST)):
        reads = route.reachable.reads(Json())
        if reads:
            print(f"{route.endpoint}: {len(reads)} JSON reads")
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, Self, TypeVar, overload, runtime_checkable

from flawed.blueprint import Blueprint
from flawed.calls import CallSite
from flawed.conditions import Check, Condition, Predicate
from flawed.effects import Effect
from flawed.function import Decorator, Function
from flawed.generated import SafeGeneratedURL
from flawed.inputs import InputRead
from flawed.route import Route
from flawed.sinks import TaintSink
from flawed.validation import ValidatedValue

if TYPE_CHECKING:
    from collections import Counter
    from collections.abc import Callable, Iterator

    from flawed.calls import FnSelector
    from flawed.class_ import Class  # noqa: F401
    from flawed.effects import EffectSelector
    from flawed.flow import ValueHandle
    from flawed.inputs import InputSource
    from flawed.route import HttpMethod

T_co = TypeVar("T_co", covariant=True)


@runtime_checkable
class DomainCollection(Protocol[T_co]):
    """Base collection with filtering, iteration, and aggregation.

    All typed collections inherit from this class.  Filtering methods
    return new collections (immutable chaining) -- the original
    collection is never modified.

    Collections of *located* domain objects (everything except
    :class:`BlueprintCollection`) additionally inherit
    :class:`LocatedCollection`, which adds the ``in_file`` / ``in_dir``
    location filters.  A :class:`~flawed.blueprint.Blueprint` is a route
    *group* with no single source location, so it intentionally does not
    expose those filters.

    This is a structural :class:`~typing.Protocol`: the concrete
    implementations live in Layer 2 (``flawed._semantic._collections``)
    and cannot nominally inherit this surface, because ``import-linter``
    forbids Layer 2 from importing ``flawed.collections``.  Declaring the
    public collection types as Protocols lets the Layer 2 ``Concrete*``
    collections satisfy them *structurally* (matching method signatures),
    so e.g. ``ConcreteRepoView`` conforms to :class:`~flawed.repo.RepoView`
    without a cast.  These classes are never instantiated directly.
    """

    def __iter__(self) -> Iterator[T_co]:
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def __len__(self) -> int:
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def __bool__(self) -> bool:
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def where(self, predicate: Callable[[T_co], bool]) -> Self:
        """Filter items by an arbitrary predicate.

        Returns a new collection containing only items for which
        ``predicate(item)`` returns ``True``.

        Example::

            large_fns = kb.functions.where(lambda f: len(f.params) > 3)
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def first(self) -> T_co | None:
        """Return the first item, or ``None`` if the collection is empty."""
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def one(self) -> T_co:
        """Return the single item; raise if not exactly one.

        Raises ``ValueError`` if the collection is empty or contains
        more than one item.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    @overload
    def __getitem__(self, index: int) -> T_co: ...
    @overload
    def __getitem__(self, index: slice) -> Self: ...
    def __getitem__(self, index: int | slice) -> T_co | Self:
        """Index a single item (``coll[0]``) or slice a sub-collection (``coll[:5]``).

        Integer indexing returns the element; slicing returns a new collection
        of the same type.  Prefer this over ``list(coll)[0]``, which renders
        the whole collection.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def __or__(self, other: Self) -> Self:
        """Union with another collection of the same type, deduplicated.

        Order-preserving (this collection first); duplicate items are dropped.

        Example::

            body_reads = form_reads | json_reads
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def group_by(self, key: str | Callable[[T_co], object]) -> dict[object, Self]:
        """Partition into ``{key_value: sub-collection}``, preserving order.

        *key* is an attribute name or a callable applied to each item.

        Example::

            by_file = kb.routes.group_by("file")
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def count_by(self, key: str | Callable[[T_co], object]) -> Counter[object]:
        """Count items by *key* (attribute name or callable) as a ``Counter``.

        Example::

            kb.routes.count_by(lambda r: r.methods)
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def tabulate(self, *columns: str | Callable[[T_co], object]) -> None:
        """Print the collection as aligned columns to stdout.

        Each column is an attribute name (used as the header) or a callable.
        With no columns, prints one item ``repr`` per line.

        Example::

            kb.routes.tabulate("endpoint", "url_rule", lambda r: sorted(r.methods))
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")


@runtime_checkable
class LocatedCollection(DomainCollection[T_co], Protocol):
    """A :class:`DomainCollection` whose items have a source location.

    Adds the ``in_file`` / ``in_dir`` filters shared by every collection of
    located domain objects (routes, functions, classes, calls, conditions,
    effects, reads, ...).  :class:`BlueprintCollection` deliberately does NOT
    inherit this: a route *group* has no single source file.
    """

    def in_file(self, path: str) -> Self:
        """Filter to items located in the given file.

        Matches items whose source file path ends with the given
        string (suffix match).

        Example::

            helpers = kb.functions.in_file("helpers.py")
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def in_dir(self, path: str) -> Self:
        """Filter to items located in the given directory.

        Matches items whose source file path contains the given
        directory path.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")


class RouteCollection(LocatedCollection[Route], Protocol):
    """Collection of Route domain objects with route-specific filters.

    Obtained from :attr:`~flawed.repo.RepoView.routes`.

    Example::

        post_routes = kb.routes.where(accepting(POST))
        api_routes = kb.routes.in_group("api")
    """

    def with_path(self, path: str) -> Self:
        """Filter to routes whose URL rule matches *path* exactly.

        Example::

            login = kb.routes.with_path("/login").one()
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def accepting(self, method: HttpMethod) -> Self:
        """Filter to routes that accept the given HTTP method.

        Example::

            post_routes = kb.routes.accepting(POST)
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def in_group(self, name: str) -> Self:
        """Filter to routes in the named group.

        The group corresponds to the framework's organizational unit:
        Flask blueprints, Django apps, FastAPI routers, Sanic blueprints, etc.

        Example::

            api_routes = kb.routes.in_group("api")
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")


class BlueprintCollection(DomainCollection[Blueprint], Protocol):
    """Collection of Blueprint (route group) domain objects.

    Obtained from :attr:`~flawed.repo.RepoView.blueprints`.

    Example::

        admin = kb.blueprints.named("admin").one()
        for route in admin.routes:
            ...
    """

    def named(self, name: str) -> Self:
        """Filter to blueprints whose group name equals *name*.

        Example::

            api = kb.blueprints.named("api").one()
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")


class FunctionCollection(LocatedCollection[Function], Protocol):
    """Collection of Function domain objects with function-specific filters.

    Obtained from :attr:`~flawed.repo.RepoView.functions`,
    :attr:`~flawed.function.Function.calls`, or
    :attr:`~flawed.function.Function.called_by`.

    Example::

        fn = kb.functions.named("create_user").one()
        decorated = kb.functions.decorated_with("login_required")
    """

    def named(self, name: str) -> Self:
        """Filter to functions with the given short name.

        Example::

            fns = kb.functions.named("create_user")
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def with_fqn(self, fqn: str) -> Self:
        """Filter to functions with the given fully qualified name.

        Example::

            fns = kb.functions.with_fqn("myapp.views.create_user")
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def decorated_with(self, name_or_fqn: str) -> Self:
        """Filter to functions decorated with the given decorator.

        Matches by decorator short name or FQN.

        Example::

            protected = kb.functions.decorated_with("login_required")
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")


class InputReadCollection(LocatedCollection[InputRead], Protocol):
    """Collection of InputRead observations with source filters.

    Obtained from :meth:`~flawed.scopes.CodeScope.reads`.

    Example::

        all_reads = scope.reads(Json())
        form_reads = scope.reads(Form()).from_source(Form(key=Key("name")))
    """

    def from_source(self, source: InputSource) -> Self:
        """Filter to reads from the given input source.

        Narrows an existing collection to reads matching a more
        specific source.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")


class EffectCollection(LocatedCollection[Effect], Protocol):
    """Collection of Effect observations with selector filters.

    Obtained from :meth:`~flawed.scopes.CodeScope.effects`.

    Example::

        writes = scope.effects(Mutation.write())
        narrow = writes.matching(Mutation.write())  # further filter
    """

    def matching(self, selector: EffectSelector) -> Self:
        """Filter to effects matching the given selector.

        Applies an additional category filter to an existing
        collection.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")


class ConditionCollection(LocatedCollection[Condition], Protocol):
    """Collection of Condition domain objects with value-aware filters.

    Obtained from :meth:`~flawed.scopes.CodeScope.conditions` or
    :meth:`~flawed.scopes.CodeScope.conditions_using`.

    Example::

        all_conds = scope.conditions()
        guards = scope.conditions_using(read.value)
        eq_checks = all_conds.comparing("request.method", "POST")
    """

    def using(self, value: ValueHandle) -> Self:
        """Filter to conditions that reference the given value.

        Example::

            guards = scope.conditions().using(read.value)
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def comparing(self, left_pattern: str, right_pattern: str) -> Self:
        """Filter to conditions comparing expressions matching the patterns.

        Matches conditions where the left operand's expression matches
        ``left_pattern`` and the right operand matches ``right_pattern``.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")


class CheckCollection(LocatedCollection[Check], Protocol):
    """Collection of :class:`~flawed.conditions.Check` objects.

    The element type of :meth:`~flawed.scopes.CodeScope.checks`.  Same filtering
    surface as :class:`ConditionCollection`, but its elements are typed
    :class:`Check` — so ``check.provider_id`` and a non-optional
    ``check.category`` are available, type-checked, and shown in autocomplete.

    Example::

        auth = scope.checks(category="AUTHENTICATION")
        providers = {c.provider_id for c in auth if c.provider_id is not None}
    """

    def using(self, value: ValueHandle) -> Self:
        """Filter to checks that reference the given value."""
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def comparing(self, left_pattern: str, right_pattern: str) -> Self:
        """Filter to checks comparing expressions matching the patterns."""
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")


class PredicateCollection(LocatedCollection[Predicate], Protocol):
    """Collection of :class:`~flawed.conditions.Predicate` domain objects.

    Sibling to :class:`ConditionCollection` for predicates produced as
    values (``return token is not None``, ``is_admin = role == "admin"``)
    rather than branch tests.  Obtained from
    :meth:`~flawed.scopes.CodeScope.predicates`.

    Example::

        for predicate in scope.predicates():
            if predicate.kind is ConditionKind.IDENTITY:
                ...
    """

    def comparing(self, left_pattern: str, right_pattern: str) -> Self:
        """Filter to predicates comparing expressions matching the patterns.

        Matches predicates where the left operand's expression matches
        ``left_pattern`` and the right operand matches ``right_pattern``.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")


class CallSiteCollection(LocatedCollection[CallSite], Protocol):
    """Collection of CallSite domain objects with target and argument filters.

    Obtained from :meth:`~flawed.scopes.CodeScope.calls`.

    Example::

        db_calls = scope.calls(Fn.named("execute"))
        tainted = db_calls.with_argument_from(read.value)
    """

    def to(self, selector: FnSelector) -> Self:
        """Filter to call sites targeting functions matching the selector.

        Applies an additional target filter to an existing collection.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def with_argument_from(self, value: ValueHandle) -> Self:
        """Filter to call sites with an argument derived from the given value.

        Checks whether any argument at the call site has a data-flow
        path from the given :class:`~flawed.flow.ValueHandle`.

        Example::

            validators = scope.calls(VALIDATORS).with_argument_from(read.value)
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")


class TaintSinkCollection(LocatedCollection[TaintSink], Protocol):
    """Collection of flow-reached taint sink observations."""

    def of_kind(self, kind: str) -> Self:
        """Filter to sinks with the given taxonomy value."""
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")


class ValidatedValueCollection(LocatedCollection[ValidatedValue], Protocol):
    """Collection of values proven safe by validation guards.

    Obtained from :meth:`~flawed.scopes.CodeScope.validated_values`.

    Example::

        redirects = [
            value
            for value in scope.validated_values()
            if "OPEN_REDIRECT" in value.safe_for_sink_kinds
        ]
    """

    def named(self, name: str) -> Self:
        """Filter to values validated by the guard with the given name.

        Example::

            url_guards = scope.validated_values().named("is_safe_url")
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def safe_for(self, kind: str) -> Self:
        """Filter to values validated for the given sink taxonomy value."""
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")


class SafeGeneratedURLCollection(LocatedCollection[SafeGeneratedURL], Protocol):
    """Collection of provider-generated URL values.

    Obtained from :meth:`~flawed.scopes.CodeScope.generated_urls`.

    Example::

        url_for_targets = scope.generated_urls().safe_for("OPEN_REDIRECT")
    """

    def safe_for(self, kind: str) -> Self:
        """Filter to generated URLs safe for the given sink taxonomy value."""
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")


class ClassCollection(LocatedCollection["Class"], Protocol):
    """Collection of Class domain objects with hierarchy-aware filters.

    Obtained from :attr:`~flawed.repo.RepoView.classes`.

    Example::

        models = kb.classes.named("User")
        children = kb.classes.subclasses_of("Base")
    """

    def named(self, name: str) -> Self:
        """Filter to classes with the given short name.

        Example::

            user_classes = kb.classes.named("User")
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def with_fqn(self, fqn: str) -> Self:
        """Filter to classes with the given fully qualified name.

        Example::

            model = kb.classes.with_fqn("myapp.models.User")
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def subclasses_of(self, base: str) -> Self:
        """Filter to classes that are transitive subclasses of the named base.

        The ``base`` is matched by short name or FQN.

        Example::

            resources = kb.classes.subclasses_of("Resource")
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def direct_subclasses_of(self, base: str) -> Self:
        """Filter to classes that are direct (single-level) subclasses.

        Example::

            direct_children = kb.classes.direct_subclasses_of("Base")
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def decorated_with(self, name_or_fqn: str) -> Self:
        """Filter to classes decorated with the given decorator.

        Matches by decorator short name or FQN.
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")


class DecoratorCollection(LocatedCollection[Decorator], Protocol):
    """Collection of Decorator domain objects with name filters.

    Obtained from :attr:`~flawed.function.Function.decorators` or
    :meth:`~flawed.scopes.CodeScope.decorators`.

    Example::

        routes = fn.decorators.named("route")
        specific = fn.decorators.with_fqn("flask.Flask.route")  # or "fastapi.FastAPI.get" etc.
    """

    def named(self, name: str) -> Self:
        """Filter to decorators with the given short name.

        Example::

            route_decs = fn.decorators.named("route")
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")

    def with_fqn(self, fqn: str) -> Self:
        """Filter to decorators with the given fully qualified name.

        Example::

            matched = fn.decorators.with_fqn("flask.Flask.route")
        """
        locals()
        raise RuntimeError("Rule API surface requires Semantic Layer context")
