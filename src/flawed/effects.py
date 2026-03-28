"""Effect observations, categories, selectors, and sugar namespaces.

An **effect** is a security-relevant side effect observed in code: a
database write, session mutation, outbound HTTP request, file write, or
notification.  The :class:`EffectCategory` enum defines the taxonomy,
and the :class:`EffectSelector` type provides composable filtering.

Eight sugar namespaces make selectors readable:

- :class:`Mutation` -- any state-changing operation
- :class:`Data` -- data persistence (database + filesystem + cache)
- :class:`Db` -- database-specific operations
- :class:`State` -- scoped state access (request, session, server)
- :class:`Config` -- runtime configuration changes
- :class:`Response` -- response mutation (cookies, headers, redirects)
- :class:`Cache` -- cache operations (Redis, memcached, etc.)
- :class:`Outbound` -- outbound HTTP requests

Selectors compose with ``|``::

    from flawed.effects import Mutation, State, Outbound, Response, Cache

    Mutation.any()  # all modifications
    Db.write()  # DB_WRITE only
    Data.write()  # DB_WRITE | FILE_WRITE | CACHE_WRITE
    State.write()  # STATE_WRITE (any scope)
    State.write(scope=StateScope.SESSION)  # session-scoped only
    Response.write()  # RESPONSE_WRITE (cookies, headers, redirects)
    Cache.write()  # CACHE_WRITE
    Outbound.request()  # OUTBOUND_REQUEST

    # Compose with |
    effects = route.reachable.effects(Data.write() | State.write())

Categories:

=====================  ==================================================
Category               Meaning
=====================  ==================================================
``DB_WRITE``           Database insert or update
``DB_DELETE``          Database delete
``DB_READ``            Database read (query-then-act pattern)
``FILE_WRITE``         Filesystem write
``FILE_READ``          Filesystem read
``CACHE_WRITE``        Cache mutation (Redis, memcached, etc.)
``CACHE_READ``         Cache read
``STATE_WRITE``        Write to scoped state container
``STATE_READ``         Read from scoped state container
``CONFIG_WRITE``       Runtime configuration change (e.g. csrf.exempt)
``RESPONSE_WRITE``     Response mutation (cookies, headers, redirects)
``OUTBOUND_REQUEST``   HTTP call to an external service
``NOTIFICATION``       Email, SMS, or push notification
=====================  ==================================================
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, Flag, auto
from typing import TYPE_CHECKING

from flawed.core import _short_expr, _short_loc

if TYPE_CHECKING:
    from flawed.core import Location, Provenance
    from flawed.flow import ValueHandle
    from flawed.function import Function


class EffectCategory(Enum):
    """Taxonomy of security-relevant side effects.

    Each value represents a class of observable side effect that
    Layer 2 interpreters can identify.  Rule authors query for effects
    by category using :class:`EffectSelector` or the sugar namespaces.
    """

    DB_WRITE = "db_write"
    """Database insert or update (e.g. ``db.execute("INSERT ...")``))."""

    DB_DELETE = "db_delete"
    """Database delete (e.g. ``db.execute("DELETE ...")``))."""

    DB_READ = "db_read"
    """Database read in a query-then-act pattern."""

    FILE_WRITE = "file_write"
    """Filesystem write (e.g. ``open("f", "w").write(...)``)."""

    FILE_READ = "file_read"
    """Filesystem read (e.g. ``open("f").read()`` for data exfiltration)."""

    CACHE_WRITE = "cache_write"
    """Cache mutation (e.g. ``redis.set(key, value)``, ``cache.set()``)."""

    CACHE_READ = "cache_read"
    """Cache read (e.g. ``redis.get(key)``, ``cache.get()``)."""

    STATE_WRITE = "state_write"
    """Write to a scoped state container (session, request context, etc.).

    The specific scope is captured by :attr:`Effect.scope`.
    """

    STATE_READ = "state_read"
    """Read from a scoped state container.

    The specific scope is captured by :attr:`Effect.scope`.
    """

    PRINCIPAL_ATTR_WRITE = "principal_attr_write"
    """Attribute write onto the request *principal* proxy itself.

    ``current_user.is_admin = request.form["is_admin"]`` — writing a value onto
    the authenticated principal's own attributes (role/permission/identity).
    When the written value is externally controlled this is a state-integrity
    / identity-mutation false negative: the principal is request-scoped, so
    ``convert_server_state_writes`` (module-level state only) emits nothing for
    it, leaving the write invisible to every effect-consuming rule (FLAW-310).

    Deliberately kept OUT of the :class:`Mutation` / :class:`State` sugar
    selectors: it is a narrow, high-signal category consumed only by the rules
    that reason about principal tampering, so it does not perturb the
    coverage rules' mutation accounting.  :attr:`Effect.key` carries the written
    attribute name; the scope is ``None`` (the principal is neither module-level
    server state nor a session key).
    """

    CONFIG_WRITE = "config_write"
    """Runtime configuration change (e.g. ``csrf.exempt(view_func)``)."""

    RESPONSE_WRITE = "response_write"
    """Response mutation (e.g. ``set_cookie()``, ``redirect()``, headers)."""

    OUTBOUND_REQUEST = "outbound_request"
    """HTTP call to an external service whose target URL a caller can influence
    (e.g. ``requests.post(url)``).  A user-controllable target is the
    precondition for SSRF, so downstream taint-to-sink (SSRF) rules consume this category."""

    OUTBOUND_REQUEST_CONFIGURED = "outbound_request_configured"
    """HTTP call whose target is a *configured constant*, not a caller-supplied
    URL (e.g. an OAuth token exchange to a registered IdP endpoint, or an OIDC
    discovery/metadata fetch).  Still a real outbound request — timeout/coverage
    rules see it via :meth:`Outbound.request` — but it is **not** an SSRF sink,
    because no externally controllable value reaches its target.  Providers declare
    it for federation calls like ``authorize_access_token()`` so the SSRF rules
    do not false-positive on the token/claim that the same call produces."""

    NOTIFICATION = "notification"
    """Email, SMS, or push notification dispatch."""


class StateScope(Flag):
    """Lifetime/scope of a state access.

    Used on :attr:`Effect.scope` for ``STATE_WRITE`` / ``STATE_READ``
    effects to indicate how far the mutation persists.  Supports
    bitwise ``|`` for combining scopes in queries::

        State.write(scope=StateScope.SESSION | StateScope.SERVER)
    """

    REQUEST = auto()
    """Dies when the current request completes.

    Examples: Flask ``g``, Django ``request`` attributes, FastAPI
    dependency-injected values, Starlette ``request.state``.
    """

    SESSION = auto()
    """Persists across requests within a single user session.

    Examples: Flask/Django ``session["user_id"]``, JWT claims, signed cookies.
    """

    SERVER = auto()
    """Persists across requests and affects other users' sessions.

    Examples: module-level state, class variables modified at runtime,
    thread-local storage shared across requests, process-level caches.
    """


@dataclass(frozen=True)
class EffectSelector:
    """Composable selector for filtering effects by category.

    Construct via the sugar namespaces (:class:`Mutation`,
    :class:`Data`, :class:`Db`, :class:`State`, :class:`Config`,
    :class:`Outbound`) rather than directly.
    Combine selectors with ``|`` to match multiple categories::

        combined = Data.write() | State.write()
        effects = route.reachable.effects(combined)
    """

    categories: frozenset[EffectCategory]
    """Set of categories this selector matches."""

    key_filter: frozenset[str] | None = None
    """Optional key filter for key-scoped effects (e.g. session key).

    When set, only effects whose ``key`` is in this set are matched.
    ``None`` means match any key (wildcard).
    """

    scope_filter: StateScope | None = None
    """Optional scope filter for state effects.

    When set, only effects whose ``scope`` overlaps this value are
    matched.  ``None`` means match any scope (wildcard).
    """

    def __or__(self, other: EffectSelector) -> EffectSelector:
        """Compose two selectors into a union selector.

        The resulting selector matches effects in *either* set of
        categories.  Key filters are merged (union); scope filters
        are dropped on composition (different categories may have
        different scopes).
        """
        merged_keys: frozenset[str] | None
        if self.key_filter is not None and other.key_filter is not None:
            merged_keys = self.key_filter | other.key_filter
        else:
            # One or both sides are wildcard → union is wildcard
            merged_keys = None

        return EffectSelector(
            categories=self.categories | other.categories,
            key_filter=merged_keys,
            scope_filter=None,
        )


@dataclass(frozen=True)
class Effect:
    """A security-relevant side effect observed in code.

    Produced by Layer 2 interpreters.  Not directly constructable by
    rule authors -- obtained from
    :meth:`~flawed.scopes.CodeScope.effects`.

    The :attr:`target` and :attr:`value` properties return
    :class:`~flawed.flow.ValueHandle` objects for tracking what
    is being written to and what value is being written.

    Example::

        for effect in route.reachable.effects(Db.write()):
            print(effect.category, effect.expression)
            if effect.target and read.value.flows_to(effect.target):
                print("User input reaches the write target!")
    """

    category: EffectCategory
    """The effect's category from the taxonomy."""

    function: Function
    """The function containing this effect."""

    location: Location
    """Source location of the effect expression."""

    expression: str
    """Source text of the effect expression."""

    provenance: Provenance
    """Semantic Layer provenance for this observation."""

    scope: StateScope | None = None
    """Persistence scope for state and runtime-configuration effects.

    ``None`` for effects whose lifetime is not modeled (``DB_WRITE``,
    ``OUTBOUND_REQUEST``, etc.).  For state effects
    (``STATE_WRITE`` / ``STATE_READ``):

    - ``StateScope.REQUEST`` -- request-scoped (e.g. request context)
    - ``StateScope.SESSION`` -- session-scoped (e.g. user session)
    - ``StateScope.SERVER`` -- server-scoped (module-level state)

    ``CONFIG_WRITE`` effects use ``StateScope.SERVER`` when the write mutates
    process-wide runtime configuration such as CSRF, CORS, or middleware policy.
    """

    key: str | None = None
    """State key name when determinable (e.g. ``"user_id"``).

    Only populated for key-scoped effects like session access.
    """

    def __repr__(self) -> str:
        # StateScope is a Flag: a single member has a name, a combined value
        # (SESSION | SERVER) has name=None — render the latter via str().
        scope = "" if self.scope is None else f", {(self.scope.name or str(self.scope)).lower()}"
        return (
            f"Effect({self.category.name}{scope}, {_short_expr(self.expression)}, "
            f"{_short_loc(self.location)})"
        )

    @property
    def target(self) -> ValueHandle | None:
        """What is being written to (e.g. the table or session key).

        Returns ``None`` when the target cannot be determined.
        """
        from flawed.flow import make_value_handle

        return make_value_handle(
            owner=self,
            function=self.function,
            location=self.location,
            expression=self.expression,
            broad_sink=True,
        )

    @property
    def value(self) -> ValueHandle | None:
        """What value is being written.

        Returns ``None`` when the written value cannot be determined.
        """
        from flawed.flow import make_value_handle

        return make_value_handle(
            owner=self,
            function=self.function,
            location=self.location,
            expression=self.expression,
            broad_sink=True,
        )


# ---------------------------------------------------------------------------
# Sugar namespaces
# ---------------------------------------------------------------------------


class Mutation:
    """Sugar namespace for any state-changing effect selectors.

    Covers all modifications: database, filesystem, state, and config.

    Example::

        Mutation.any()  # all modifications
        Mutation.write()  # all writes (db, file, state, config)
        Mutation.delete()  # DB_DELETE only
    """

    @staticmethod
    def any() -> EffectSelector:
        """Select any state-changing effect."""
        return EffectSelector(
            categories=frozenset(
                {
                    EffectCategory.DB_WRITE,
                    EffectCategory.DB_DELETE,
                    EffectCategory.FILE_WRITE,
                    EffectCategory.CACHE_WRITE,
                    EffectCategory.STATE_WRITE,
                    EffectCategory.CONFIG_WRITE,
                    EffectCategory.RESPONSE_WRITE,
                }
            ),
        )

    @staticmethod
    def write() -> EffectSelector:
        """Select all write effects (database, file, cache, state, config, response)."""
        return EffectSelector(
            categories=frozenset(
                {
                    EffectCategory.DB_WRITE,
                    EffectCategory.FILE_WRITE,
                    EffectCategory.CACHE_WRITE,
                    EffectCategory.STATE_WRITE,
                    EffectCategory.CONFIG_WRITE,
                    EffectCategory.RESPONSE_WRITE,
                }
            ),
        )

    @staticmethod
    def persistent() -> EffectSelector:
        """Select state changes that PERSIST beyond the response.

        Identical to :meth:`any` but EXCLUDES ``RESPONSE_WRITE`` (returning a
        rendered template or ``jsonify`` payload), which mutates only the
        outgoing HTTP response, not durable server-side state.

        Auth / CSRF / coverage rules want this selector, not :meth:`any`:
        because *every* route writes a response, ``any()`` reports a mutation on
        100% of routes -- firing "missing authz/CSRF" on pure reads (the
        dominant false-positive engine, FLAW-281).  ``persistent()`` fires only
        on routes that change durable state, and -- because ``RESPONSE_WRITE``
        is absent from the result set -- the first selected effect is a real
        persistent mutation, so evidence cites the genuine write (e.g.
        ``store.delete_result()``) rather than the response write that happens
        to share the route.
        """
        return EffectSelector(
            categories=frozenset(
                {
                    EffectCategory.DB_WRITE,
                    EffectCategory.DB_DELETE,
                    EffectCategory.FILE_WRITE,
                    EffectCategory.CACHE_WRITE,
                    EffectCategory.STATE_WRITE,
                    EffectCategory.CONFIG_WRITE,
                }
            ),
        )

    @staticmethod
    def delete() -> EffectSelector:
        """Select data delete effects (``DB_DELETE``)."""
        return EffectSelector(
            categories=frozenset({EffectCategory.DB_DELETE}),
        )


class Data:
    """Sugar namespace for data persistence effect selectors.

    Convenience group over database, filesystem, and cache operations.

    Example::

        Data.write()  # DB_WRITE | FILE_WRITE | CACHE_WRITE
        Data.read()  # DB_READ | FILE_READ | CACHE_READ
        Data.any()  # all data operations
    """

    @staticmethod
    def write() -> EffectSelector:
        """Select data write effects (database + filesystem + cache)."""
        return EffectSelector(
            categories=frozenset(
                {
                    EffectCategory.DB_WRITE,
                    EffectCategory.FILE_WRITE,
                    EffectCategory.CACHE_WRITE,
                }
            ),
        )

    @staticmethod
    def read() -> EffectSelector:
        """Select data read effects (database + filesystem + cache)."""
        return EffectSelector(
            categories=frozenset(
                {
                    EffectCategory.DB_READ,
                    EffectCategory.FILE_READ,
                    EffectCategory.CACHE_READ,
                }
            ),
        )

    @staticmethod
    def any() -> EffectSelector:
        """Select any data persistence effect."""
        return EffectSelector(
            categories=frozenset(
                {
                    EffectCategory.DB_WRITE,
                    EffectCategory.DB_DELETE,
                    EffectCategory.DB_READ,
                    EffectCategory.FILE_WRITE,
                    EffectCategory.FILE_READ,
                    EffectCategory.CACHE_WRITE,
                    EffectCategory.CACHE_READ,
                }
            ),
        )


class Db:
    """Sugar namespace for database-specific effect selectors.

    Example::

        Db.write()  # DB_WRITE only
        Db.delete()  # DB_DELETE only
        Db.read()  # DB_READ only
        Db.any()  # any database operation
    """

    @staticmethod
    def write() -> EffectSelector:
        """Select database write effects (``DB_WRITE``)."""
        return EffectSelector(
            categories=frozenset({EffectCategory.DB_WRITE}),
        )

    @staticmethod
    def delete() -> EffectSelector:
        """Select database delete effects (``DB_DELETE``)."""
        return EffectSelector(
            categories=frozenset({EffectCategory.DB_DELETE}),
        )

    @staticmethod
    def read() -> EffectSelector:
        """Select database read effects (``DB_READ``)."""
        return EffectSelector(
            categories=frozenset({EffectCategory.DB_READ}),
        )

    @staticmethod
    def any() -> EffectSelector:
        """Select any database effect."""
        return EffectSelector(
            categories=frozenset(
                {
                    EffectCategory.DB_WRITE,
                    EffectCategory.DB_DELETE,
                    EffectCategory.DB_READ,
                }
            ),
        )


class State:
    """Sugar namespace for scoped state effect selectors.

    Example::

        State.write()  # any state write (any scope)
        State.write(scope=StateScope.SESSION)  # session-scoped only
        State.write(scope=StateScope.SESSION | StateScope.SERVER)
        State.read(key="user_id")  # state read for specific key
        State.any()  # STATE_WRITE | STATE_READ
    """

    @staticmethod
    def write(
        scope: StateScope | None = None,
        key: str | None = None,
    ) -> EffectSelector:
        """Select state write effects, optionally filtered by scope/key.

        Args:
            scope: Scope to filter on, or ``None`` for any scope.
                   Supports bitwise ``|`` for combining scopes.
            key: State key name to filter on, or ``None`` for any.
        """
        return EffectSelector(
            categories=frozenset({EffectCategory.STATE_WRITE}),
            key_filter=frozenset({key}) if key is not None else None,
            scope_filter=scope,
        )

    @staticmethod
    def read(
        scope: StateScope | None = None,
        key: str | None = None,
    ) -> EffectSelector:
        """Select state read effects, optionally filtered by scope/key.

        Args:
            scope: Scope to filter on, or ``None`` for any scope.
                   Supports bitwise ``|`` for combining scopes.
            key: State key name to filter on, or ``None`` for any.
        """
        return EffectSelector(
            categories=frozenset({EffectCategory.STATE_READ}),
            key_filter=frozenset({key}) if key is not None else None,
            scope_filter=scope,
        )

    @staticmethod
    def any(scope: StateScope | None = None) -> EffectSelector:
        """Select any state effect (read or write)."""
        return EffectSelector(
            categories=frozenset(
                {
                    EffectCategory.STATE_WRITE,
                    EffectCategory.STATE_READ,
                }
            ),
            scope_filter=scope,
        )


class Config:
    """Sugar namespace for runtime configuration effect selectors.

    Example::

        Config.write()  # CONFIG_WRITE (e.g. csrf.exempt)
    """

    @staticmethod
    def write() -> EffectSelector:
        """Select runtime configuration change effects."""
        return EffectSelector(
            categories=frozenset({EffectCategory.CONFIG_WRITE}),
        )


class Response:
    """Sugar namespace for response mutation effect selectors.

    Covers cookies, headers, redirects, and response body construction.

    Example::

        Response.write()  # any response mutation
        Response.write(key="cookie:session_id")  # specific cookie
    """

    @staticmethod
    def write(key: str | None = None) -> EffectSelector:
        """Select response mutation effects (``RESPONSE_WRITE``).

        Args:
            key: Optional key filter (e.g. ``"cookie:session_id"``,
                 ``"header:Location"``).  ``None`` matches any.
        """
        return EffectSelector(
            categories=frozenset({EffectCategory.RESPONSE_WRITE}),
            key_filter=frozenset({key}) if key is not None else None,
        )


class Cache:
    """Sugar namespace for cache operation effect selectors.

    Example::

        Cache.write()  # CACHE_WRITE
        Cache.read()  # CACHE_READ
        Cache.any()  # CACHE_WRITE | CACHE_READ
    """

    @staticmethod
    def write(key: str | None = None) -> EffectSelector:
        """Select cache write effects (``CACHE_WRITE``)."""
        return EffectSelector(
            categories=frozenset({EffectCategory.CACHE_WRITE}),
            key_filter=frozenset({key}) if key is not None else None,
        )

    @staticmethod
    def read(key: str | None = None) -> EffectSelector:
        """Select cache read effects (``CACHE_READ``)."""
        return EffectSelector(
            categories=frozenset({EffectCategory.CACHE_READ}),
            key_filter=frozenset({key}) if key is not None else None,
        )

    @staticmethod
    def any() -> EffectSelector:
        """Select any cache effect."""
        return EffectSelector(
            categories=frozenset(
                {
                    EffectCategory.CACHE_WRITE,
                    EffectCategory.CACHE_READ,
                }
            ),
        )


class Outbound:
    """Sugar namespace for outbound request effect selectors.

    Example::

        Outbound.request()  # any outbound HTTP request
    """

    @staticmethod
    def request(*, user_controllable_target: bool = False) -> EffectSelector:
        """Select outbound HTTP request effects.

        By default selects **all** outbound HTTP requests — both
        user-targetable (``OUTBOUND_REQUEST``) and configured-target
        (``OUTBOUND_REQUEST_CONFIGURED``, e.g. an OAuth token exchange to a
        registered IdP).  Timeout/coverage rules want this breadth.

        Pass ``user_controllable_target=True`` to select only outbounds whose
        target URL a caller can influence — the SSRF precondition — excluding
        configured-target calls.  Taint-to-sink (SSRF) rules use this so they do
        not false-positive on federation calls like ``authorize_access_token()``
        (the call's target is the configured IdP, and the token/claim it returns
        is response data, never an externally controlled request target).
        """
        if user_controllable_target:
            return EffectSelector(
                categories=frozenset({EffectCategory.OUTBOUND_REQUEST}),
            )
        return EffectSelector(
            categories=frozenset(
                {EffectCategory.OUTBOUND_REQUEST, EffectCategory.OUTBOUND_REQUEST_CONFIGURED}
            ),
        )
