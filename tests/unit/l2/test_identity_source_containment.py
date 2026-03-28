"""FP-containment for identifier / auth-subject input sources (FLAW-240/230).

Identity sources (``SessionValue``, ``FrameworkGlobal``) must stay OUT of the
default wildcard ``reads()`` stream — surfacing them there would make every
attacker-input rule see session/framework-global reads and produce a
corpus-wide false-positive surge. They are reachable only via an explicit,
opt-in ``reads(SessionValue())``. Attacker-input containers (``Query``/``Json``)
and provider claims (``ProviderClaim``) are unaffected and remain wildcard-visible.

This is the load-bearing core-contract half of FLAW-240; the provider *emission*
of session/g reads is a separate slice (it needs new ``_matching.py`` dispatch).
These tests construct synthetic reads so the containment is verified independent
of emission.
"""

from __future__ import annotations

from flawed._semantic._scope import ConcreteCodeScope
from flawed.core import Key, Location, Provenance
from flawed.function import Function, FunctionKind
from flawed.inputs import (
    AccessPattern,
    Cardinality,
    FrameworkGlobal,
    InputRead,
    InputSource,
    Json,
    ProviderClaim,
    Query,
    SessionValue,
)

_LOC = Location(file="app.py", line=1, column=0)
_PROV = Provenance(source_layer="L2", interpreter="test", confidence=1.0)
_FN = Function(
    fqn="app.handler",
    name="handler",
    params=(),
    kind=FunctionKind.TOP_LEVEL,
    parent_class=None,
    parent_function=None,
    location=_LOC,
    provenance=_PROV,
)


def _read(source: InputSource) -> InputRead:
    """Build a minimal InputRead for testing."""
    return InputRead(
        source=source,
        access_pattern=AccessPattern.ATTRIBUTE,
        cardinality=Cardinality.SINGLE,
        function=_FN,
        location=_LOC,
        expression="x",
        provenance=_PROV,
    )


class TestIdentitySourceFlag:
    """The category flag is set on identity sources and only on them."""

    def test_session_and_framework_global_are_identity_sources(self) -> None:
        assert SessionValue.is_identity_source is True
        assert FrameworkGlobal.is_identity_source is True

    def test_attacker_input_and_claims_are_not_identity_sources(self) -> None:
        # Attacker-controlled containers and provider claims must remain visible
        # in the wildcard stream — they are NOT identity sources.
        assert Query.is_identity_source is False
        assert Json.is_identity_source is False
        assert ProviderClaim.is_identity_source is False
        assert InputSource.is_identity_source is False


class TestWildcardContainment:
    """reads() with no source excludes identity sources; opt-in includes them."""

    def test_wildcard_reads_excludes_identity_sources(self) -> None:
        query = _read(Query(key=Key("user_id")))
        session = _read(SessionValue(key=Key("cart_id")))
        gvar = _read(FrameworkGlobal(name=Key("cart_id")))
        scope = ConcreteCodeScope(input_reads=(query, session, gvar))

        result = list(scope.reads())

        # Only the attacker-input read survives the wildcard stream.
        assert len(result) == 1
        assert result[0].source == Query(key=Key("user_id"))

    def test_provider_claim_stays_wildcard_visible(self) -> None:
        # ProviderClaim is intentionally NOT contained (it is attacker-influenced
        # federation input already surfaced by existing rules) — guard against a
        # regression that would silently drop it from the wildcard stream.
        claim = _read(ProviderClaim(key=Key("email")))
        query = _read(Query())
        scope = ConcreteCodeScope(input_reads=(claim, query))

        result = list(scope.reads())

        assert len(result) == 2

    def test_explicit_session_source_opt_in_sees_session_reads(self) -> None:
        query = _read(Query(key=Key("user_id")))
        session = _read(SessionValue(key=Key("cart_id")))
        scope = ConcreteCodeScope(input_reads=(query, session))

        # The opt-in path bypasses containment and returns the contained read.
        result = list(scope.reads(SessionValue()))

        assert len(result) == 1
        assert result[0].source == SessionValue(key=Key("cart_id"))

    def test_explicit_keyed_session_source_filters_by_key(self) -> None:
        cart = _read(SessionValue(key=Key("cart_id")))
        user = _read(SessionValue(key=Key("user_id")))
        scope = ConcreteCodeScope(input_reads=(cart, user))

        result = list(scope.reads(SessionValue(key=Key("cart_id"))))

        assert len(result) == 1
        assert result[0].source == SessionValue(key=Key("cart_id"))

    def test_framework_global_opt_in(self) -> None:
        gvar = _read(FrameworkGlobal(name=Key("cart_id")))
        scope = ConcreteCodeScope(input_reads=(gvar,))

        assert len(list(scope.reads())) == 0  # contained from wildcard
        assert len(list(scope.reads(FrameworkGlobal()))) == 1  # visible on opt-in

    def test_wildcard_with_only_attacker_input_unaffected(self) -> None:
        # Regression guard: a scope with no identity sources behaves exactly as
        # before (every read visible).
        reads = (_read(Query()), _read(Json()), _read(ProviderClaim(key=Key("sub"))))
        scope = ConcreteCodeScope(input_reads=reads)

        assert len(list(scope.reads())) == 3
