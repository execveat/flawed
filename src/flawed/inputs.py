"""Input source hierarchy, InputRead observation, and access enums.

This module defines **where** HTTP request data comes from and **how**
code accesses it.  The :class:`InputSource` hierarchy models request
containers (query string, form body, JSON body, headers, cookies, etc.)
and the :class:`InputRead` type records an observation that code reads
from one of these containers.

When an :class:`InputSource` subclass is constructed **without** its
identifying field (no ``key``, ``name``, or ``path``), it matches *any*
read from that container type.  This is the wildcard form used for
broad queries::

    from flawed.inputs import Json, Form, PathParam

    all_json_reads = route.reachable.reads(Json())  # any JSON field
    specific_read = route.reachable.reads(Json(path="$.user_id"))  # one field

The :class:`AnyOf` combinator matches reads from any of several
sources::

    from flawed.inputs import AnyOf, Form, Json

    body_reads = route.reachable.reads(AnyOf(sources=(Form(), Json())))
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from typing import TYPE_CHECKING, ClassVar, cast

from flawed.core import _short_expr, _short_loc

if TYPE_CHECKING:
    from flawed.core import (
        JsonPath,
        Key,
        Location,
        Provenance,
    )
    from flawed.flow import ValueHandle
    from flawed.function import Function


class AccessPattern(Enum):
    """How an input source was accessed in code.

    Determined by the Semantic Layer from the syntactic form of the
    read expression.

    Values:

    - ``GET`` -- dict-style ``.get("key")`` access
    - ``SUBSCRIPT`` -- bracket ``["key"]`` access
    - ``GETLIST`` -- ``.getlist("key")`` for multi-value fields
    - ``ATTRIBUTE`` -- attribute access (e.g. ``request.json``)
    - ``ITERATION`` -- iteration over the container
    - ``MEMBERSHIP`` -- membership test (``"key" in container``)
    - ``UNKNOWN`` -- access pattern could not be determined
    """

    GET = "get"
    SUBSCRIPT = "subscript"
    GETLIST = "getlist"
    ATTRIBUTE = "attribute"
    ITERATION = "iteration"
    MEMBERSHIP = "membership"
    UNKNOWN = "unknown"


class Cardinality(Enum):
    """Whether an input read produces a single value or multiple.

    Values:

    - ``SINGLE`` -- one value (e.g. ``request.args.get("id")``)
    - ``MULTI`` -- multiple values (e.g. ``request.args.getlist("ids")``)
    - ``UNKNOWN`` -- cardinality could not be determined
    """

    SINGLE = "single"
    MULTI = "multi"
    UNKNOWN = "unknown"


class InputValueType(Enum):
    """Generic runtime value-type constraint for an input read.

    ``None`` on :class:`InputRead.value_type` means the semantic layer has
    no reliable type constraint and consumers must remain conservative.
    """

    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    UUID = "uuid"


# ---------------------------------------------------------------------------
# InputSource hierarchy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InputSource:
    """Base class for all HTTP request input sources.

    All subclasses are frozen dataclasses.  Construct without the
    identifying field to create a wildcard that matches any read from
    that container type.
    """

    _identifier_field: ClassVar[str | None] = None
    """Name of the subclass field that holds this source's identifier.

    Subclasses whose identity is a key/name/path/field/parameter set this to
    the field name; identifier-less sources (``RawBody``) and combinators
    (``AnyOf``) leave it ``None``.  It is the single declaration that powers
    :attr:`identifier`, so a new source type opts in with one line instead of
    re-implementing the accessor (the FLAW-257 typed-surface contract).
    """

    is_identity_source: ClassVar[bool] = False
    """Whether this is an identifier / auth-subject source rather than a general
    untrusted-input container.

    Identity sources (a server-managed session value, a request-scoped framework
    global) are *usually* trusted state — tainted only when populated from a
    request value. Surfacing them into the default wildcard
    :meth:`~flawed.scopes.CodeScope.reads` stream (alongside ``Query``/``Json``)
    would make every untrusted-input rule see them and produce a corpus-wide
    false-positive surge (FLAW-230 §"Deferred decision"). So identity sources are
    kept OUT of wildcard ``reads()`` and surfaced only via an explicit, opt-in
    ``reads(SessionValue())`` that subject/object and presence-vs-validity rules
    request by name. A new identity source opts in with one line.

    This is deliberately a per-type *category* flag, NOT a function of
    :attr:`identifier`: untrusted-input containers (``Query``/``Json``/``Form``)
    also carry an identifier (their key), so keying containment off ``identifier``
    would wrongly drop untrusted input from the wildcard stream — a false negative,
    the one thing this engine must never do.
    """

    @property
    def identifier(self) -> str | None:
        """The identifying key/name/path/field/parameter of this source.

        One typed accessor across the whole hierarchy: rules read
        ``source.identifier`` instead of probing divergently-named fields with
        ``getattr(source, "key"/"name"/"path"/...)`` (the type-erasure
        class this surface exists to retire).  Returns ``None`` for a wildcard
        (e.g. ``Query()``) or an identifier-less source (``RawBody``).
        """
        field_name = self._identifier_field
        if field_name is None:
            return None
        # The identifier field name varies by subclass (``key``/``name``/...),
        # so this is the one reflective boundary in the hierarchy; the value is
        # always typed ``Key | JsonPath | None`` (both str-NewTypes) at the
        # declaration site, so widening to ``str | None`` is sound.
        return cast("str | None", getattr(self, field_name))

    @property
    def leaf_identifier(self) -> str | None:
        """:attr:`identifier` reduced to the leaf segment used for cross-container
        correlation.

        Equal to :attr:`identifier` for flat sources.  Structured sources whose
        identity is a path (``Json``) override this to return the trailing
        segment, so a JSON field ``$.user.id`` correlates with the same-named
        ``id`` query/form field (FLAW-126/270).  Lives here, not in a consumer,
        so the reduction can never drift from the identifier it reduces.
        """
        return self.identifier

    def matches(self, expected: InputSource) -> bool:
        """Whether this (actual) source satisfies the *expected* source pattern.

        The single matcher for input-source patterns: ``actual.matches(expected)``
        is the one home for the ``AnyOf`` / ``AnyContainer``-wildcard / typed
        field-comparison logic that previously lived as drift-prone copies in
        ``flow.py`` and ``_semantic/_collections.py`` (FLAW-271).  Putting it on
        the domain type lets both the L3 rule API and the L2 collections call it
        without crossing a layer boundary (everyone may call *down* to
        ``inputs``).

        ``expected`` is the query pattern; ``self`` is the concrete source
        attached to an observed read.  ``AnyContainer`` matches any container
        type narrowed only by key; ``AnyOf`` matches if any member matches;
        otherwise the types must match and every set field on ``expected`` must
        equal ``self``'s (an unset field on ``expected`` is a wildcard).
        """
        if isinstance(expected, AnyOf):
            return any(self.matches(candidate) for candidate in expected.sources)
        if isinstance(expected, AnyContainer):
            # key=None is the wildcard: match any container regardless of key.
            return expected.key is None or self.identifier == expected.key
        if type(self) is not type(expected):
            return False
        if not is_dataclass(expected):
            return True
        for field in fields(expected):
            expected_value = getattr(expected, field.name)
            if expected_value is not None and getattr(self, field.name) != expected_value:
                return False
        return True


@dataclass(frozen=True)
class Query(InputSource):
    """Query string parameter source.

    Example::

        Query(key=Key("user_id"))  # specific parameter
        Query()  # any query parameter (wildcard)
    """

    _identifier_field: ClassVar[str | None] = "key"

    key: Key | None = None
    """Parameter name in the query string, or ``None`` for wildcard."""


@dataclass(frozen=True)
class Form(InputSource):
    """Form-encoded body field source.

    Example::

        Form(key=Key("amount"))  # specific field
        Form()  # any form field (wildcard)
    """

    _identifier_field: ClassVar[str | None] = "key"

    key: Key | None = None
    """Field name in the form-encoded body, or ``None`` for wildcard."""


@dataclass(frozen=True)
class Json(InputSource):
    """JSON body field source addressed by JSONPath.

    Example::

        Json(path=JsonPath("$.restaurant_id"))  # specific path
        Json()  # any JSON read (wildcard)
    """

    _identifier_field: ClassVar[str | None] = "path"

    path: JsonPath | None = None
    """JSONPath expression identifying the field, or ``None`` for wildcard."""

    @property
    def leaf_identifier(self) -> str | None:
        """The JSONPath reduced to its trailing segment (``$.user.id`` -> ``id``).

        A JSON field is addressed by a structured path, but for cross-container
        correlation only the leaf field name is comparable with a flat
        query/form/header field of the same name.
        """
        path = self.identifier
        return None if path is None else path.rsplit(".", maxsplit=1)[-1]


@dataclass(frozen=True)
class Header(InputSource):
    """HTTP header source.

    Example::

        Header(name=Key("X-Api-Key"))  # specific header
        Header()  # any header (wildcard)
    """

    _identifier_field: ClassVar[str | None] = "name"

    name: Key | None = None
    """Header name (case-insensitive by HTTP convention), or ``None`` for wildcard."""


@dataclass(frozen=True)
class Cookie(InputSource):
    """Cookie value source.

    Example::

        Cookie(name=Key("session"))  # specific cookie
        Cookie()  # any cookie (wildcard)
    """

    _identifier_field: ClassVar[str | None] = "name"

    name: Key | None = None
    """Cookie name, or ``None`` for wildcard."""


@dataclass(frozen=True)
class PathParam(InputSource):
    """URL path parameter source.

    Matches path parameters extracted from URL rules like
    ``/users/<int:id>``. Converter-derived value constraints live on
    :attr:`InputRead.value_type`, not on the source identity.

    Example::

        PathParam(name=Key("id"))  # specific parameter
        PathParam()  # any path parameter (wildcard)
    """

    _identifier_field: ClassVar[str | None] = "name"

    name: Key | None = None
    """Path parameter name as declared in the URL rule, or ``None`` for wildcard."""


@dataclass(frozen=True)
class FileUpload(InputSource):
    """Uploaded file source.

    Example::

        FileUpload(field=Key("avatar"))  # specific file field
        FileUpload()  # any file upload (wildcard)
    """

    _identifier_field: ClassVar[str | None] = "field"

    field: Key | None = None
    """Form field name for the uploaded file, or ``None`` for wildcard."""


@dataclass(frozen=True)
class RawBody(InputSource):
    """Raw request body source.

    Matches reads of the entire request body as bytes or text
    (e.g. ``request.data``, ``request.get_data()``).
    """


@dataclass(frozen=True)
class DependencyInput(InputSource):
    """Value injected into a handler parameter by framework dependency injection.

    Dependency-injection systems such as FastAPI ``Depends()`` and Litestar
    ``Provide()`` run provider callables before a route handler and bind their
    return values to handler parameters.  This source records the injected
    parameter and, when resolved, the provider callable or security scheme FQN.

    Example::

        DependencyInput(parameter=Key("db"), provider_fqn="app.deps.get_db")
        DependencyInput()  # any injected dependency value
    """

    _identifier_field: ClassVar[str | None] = "parameter"

    parameter: Key | None = None
    """Handler/dependency parameter receiving the injected value."""

    provider_fqn: str | None = None
    """Resolved provider callable or security scheme FQN, or ``None`` if unknown."""


@dataclass(frozen=True)
class ProviderClaim(InputSource):
    """OAuth/OIDC provider claim source (userinfo / ID-token claim).

    Models a value read **by key** from a provider claims container -- the
    ``userinfo`` mapping or decoded ID-token a federated-identity client returns
    from a token exchange (e.g. ``token = authorize_access_token()`` then
    ``token["userinfo"].get("email")``).  A provider email/``sub``/profile claim
    is externally influenced when the identity provider is untrusted, unverified,
    or misconfigured, so it is a first-class request input alongside the HTTP
    containers above -- not framework-specific, but federation-specific.

    The ``key`` is the claim name, which gives the source a
    :class:`~flawed.correlation.LogicalInput` identity so two derivations of the
    *same* claim (a normalized gate value vs. the raw identity value) correlate
    via :meth:`~flawed.flow.ValueHandle.shares_origin`.

    Example::

        ProviderClaim(key=Key("email"))  # the "email" claim
        ProviderClaim()  # any provider claim (wildcard)
    """

    _identifier_field: ClassVar[str | None] = "key"

    key: Key | None = None
    """Claim name (e.g. ``"email"``, ``"sub"``), or ``None`` for wildcard."""


@dataclass(frozen=True)
class SessionValue(InputSource):
    """Server-side session value source, addressed by key.

    Models a value read **by key** from a web framework's session container
    (the signed-cookie / server-side session the framework manages). Unlike the
    HTTP request containers above, a session value is *usually* server-managed
    and trusted -- so it is modeled as a distinct **identifier / auth-subject**
    source, NOT a general untrusted-input container. Its purpose is to let
    subject/object and presence-vs-validity rules recognise an inconsistency *axis*
    where a session-sourced identifier is paired against a request-sourced one
    (e.g. session ``cart_id`` vs path ``cart_id``).

    Whether a given session value is externally influenceable is a provider/rule
    judgement (a session populated from a request value is tainted); giving it
    its own source type keeps that decision explicit rather than collapsing it
    into the untrusted-input taxonomy. See ``docs/design`` and FLAW-230 for the
    emission decision (these reads are not yet surfaced into the wildcard
    :meth:`~flawed.scopes.CodeScope.reads` stream).

    Example::

        SessionValue(key=Key("cart_id"))  # the session "cart_id" value
        SessionValue()  # any session value (wildcard)
    """

    is_identity_source: ClassVar[bool] = True
    _identifier_field: ClassVar[str | None] = "key"

    key: Key | None = None
    """Session entry name, or ``None`` for wildcard."""


@dataclass(frozen=True)
class FrameworkGlobal(InputSource):
    """Request-scoped framework-global value source, addressed by name.

    Models a value read from a framework's per-request global namespace (e.g. a
    request-scoped attribute bag populated by middleware or a URL value
    preprocessor). Like :class:`SessionValue`, it is an **identifier /
    auth-subject** source rather than a general untrusted-input container: such a
    global is frequently populated *from* a request value (a path segment, a
    header) by a preprocessor, which is exactly the provenance ambiguity a
    subject/object rule must be able to see (session ``cart_id`` falling back to
    a path-populated request global). See FLAW-230 for the emission decision.

    Example::

        FrameworkGlobal(name=Key("cart_id"))  # request-global "cart_id"
        FrameworkGlobal()  # any request-global (wildcard)
    """

    is_identity_source: ClassVar[bool] = True
    _identifier_field: ClassVar[str | None] = "name"

    name: Key | None = None
    """Request-global attribute name, or ``None`` for wildcard."""


@dataclass(frozen=True)
class AnyContainer(InputSource):
    """Matches any request container, optionally narrowed to a key name.

    Use when the container type does not matter::

        AnyContainer(key=Key("id"))  # "id" from query, form, JSON, etc.
        AnyContainer()  # any read from any container (wildcard)
    """

    _identifier_field: ClassVar[str | None] = "key"

    key: Key | None = None
    """Key name to match across all container types, or ``None`` to match any key."""


@dataclass(frozen=True)
class AnyOf(InputSource):
    """Union of input sources -- matches reads from **any** of the given sources.

    Uses OR semantics: a read matches if it comes from *any* source in
    the ``sources`` tuple.  This is equivalent to combining individual
    ``reads()`` calls and merging the results.

    Example::

        body_reads = route.reachable.reads(AnyOf(sources=(Form(), Json())))
        # Equivalent to: form_reads | json_reads
    """

    sources: tuple[InputSource, ...]
    """Input sources to match (OR semantics -- any match counts)."""


# ---------------------------------------------------------------------------
# InputRead observation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InputRead:
    """Observation that code reads from an HTTP request container.

    Produced by Layer 2 (Semantic Layer) when it recognizes a pattern
    like ``request.args.get("id")``.  Not directly constructable by
    rule authors -- obtained from
    :meth:`~flawed.scopes.CodeScope.reads`.

    The :attr:`value` property returns a :class:`~flawed.flow.ValueHandle`
    for tracking how the read value propagates through the program.

    Example::

        for read in route.reachable.reads(Json()):
            print(read.source, read.access_pattern)
            if read.value.flows_to(effect.target):
                print("Input reaches the effect!")
    """

    source: InputSource
    """The typed input source (``Query``, ``Form``, ``Json``, etc.)."""

    access_pattern: AccessPattern
    """How the source was accessed (``GET``, ``SUBSCRIPT``, etc.)."""

    cardinality: Cardinality
    """Whether the read produces a single value or multiple."""

    function: Function
    """The function containing this read."""

    location: Location
    """Source location of the read expression."""

    expression: str
    """Source text of the read expression."""

    provenance: Provenance
    """Semantic Layer provenance for this observation."""

    value_type: InputValueType | None = None
    """Known generic runtime value type, or ``None`` if unconstrained/unknown."""

    def __repr__(self) -> str:
        return (
            f"InputRead({self.source!r}, {_short_expr(self.expression)}, "
            f"{_short_loc(self.location)})"
        )

    @property
    def value(self) -> ValueHandle:
        """Handle for tracking the read value through the program.

        Returns a :class:`~flawed.flow.ValueHandle` that can be
        used with ``flows_to``, ``flows_from``, and ``derived_from``
        to trace how the input data propagates.
        """
        from flawed.flow import make_value_handle

        return make_value_handle(
            owner=self,
            function=self.function,
            location=self.location,
            expression=self.expression,
            input_source=self.source,
        )
