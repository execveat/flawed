"""Unit tests for the same-logical-entity correlation primitive (FLAW-126).

These exercise the equivalence semantics directly, without the Semantic Layer:
``ValueHandle`` flow context is faked so the tests pin the correlation policy
(which inputs count as "the same logical entity") rather than the flow engine.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

from flawed.core import Key, Location
from flawed.correlation import (
    InputEquivalence,
    LogicalInput,
    container_family,
    logical_input,
    read_inputs,
    same_logical_input,
    source_key,
    value_inputs,
)
from flawed.flow import ValueHandle, attach_flow_context
from flawed.inputs import (
    AnyContainer,
    Cookie,
    DependencyInput,
    Form,
    Header,
    Json,
    PathParam,
    Query,
)

if TYPE_CHECKING:
    from flawed.inputs import InputRead

EXACT = InputEquivalence.EXACT
SUBSTITUTABLE = InputEquivalence.SUBSTITUTABLE_CONTAINER
CREDENTIAL = InputEquivalence.SAME_CREDENTIAL


def _loc() -> Location:
    return Location(file="t.py", line=1, column=0)


def _read(source: object) -> InputRead:
    """A minimal read stand-in: correlation only reads ``.source``."""
    return cast("InputRead", SimpleNamespace(source=source))


def _value(*derives: tuple[type, str]) -> ValueHandle:
    """A ValueHandle whose ``derived_from`` answers for a fixed origin set.

    ``derives`` is the set of ``(source_type, key)`` the value flows from. The
    fake honours the container-blind ``AnyContainer(key=...)`` probe used by the
    credential equivalence.
    """
    origins = set(derives)
    handle = ValueHandle(location=_loc(), expression="v")

    def _derived_from(_handle: ValueHandle, source: object) -> bool:
        key = source_key(source)  # type: ignore[arg-type]
        if isinstance(source, AnyContainer):
            return any(k == key for _t, k in origins)
        return (type(source), key) in origins

    return attach_flow_context(handle, derived_from=_derived_from)


# -- source_key / container_family -------------------------------------------


def test_source_key_reads_each_identifying_field() -> None:
    assert source_key(Query(key=Key("user_id"))) == "user_id"
    assert source_key(Header(name=Key("Authorization"))) == "Authorization"
    assert source_key(PathParam(name=Key("id"))) == "id"
    assert source_key(Query()) is None  # wildcard


def test_source_key_includes_dependency_parameter() -> None:
    """FLAW-270: a ``DependencyInput`` correlates by its ``parameter`` name.

    The old hand-rolled loop looked only at ``key``/``name``/``field``/``path``,
    so a dependency-injected source returned ``None`` and never correlated with a
    same-named query/form field -- a latent false negative on the correlation path.
    """
    from flawed.core import JsonPath

    assert source_key(DependencyInput(parameter=Key("db"))) == "db"
    assert source_key(DependencyInput()) is None  # wildcard, no parameter
    # JSONPath trailing-segment reduction is preserved (a JSON field correlates
    # with the same-named flat field): ``$.user.id`` -> ``id``.
    assert source_key(Json(path=JsonPath("$.user.id"))) == "id"
    assert source_key(Json(path=JsonPath("$.restaurant_id"))) == "restaurant_id"


def test_container_family_isolates_path_params() -> None:
    assert container_family(PathParam) == "PATH"
    assert container_family(Query) == "FORGEABLE"
    assert container_family(Form) == "FORGEABLE"
    assert container_family(Header) == "FORGEABLE"


# -- logical_input equivalence semantics -------------------------------------


def test_exact_distinguishes_container_type() -> None:
    assert logical_input(Query(key=Key("x")), EXACT) == LogicalInput("Query", "x")
    assert logical_input(Form(key=Key("x")), EXACT) != logical_input(Query(key=Key("x")), EXACT)


def test_substitutable_collapses_forgeable_but_not_path() -> None:
    # The same key in two attacker-forgeable containers (form vs. JSON body) is
    # one logical input: a real container-split.
    assert same_logical_input(Form(key=Key("amount")), _json_field("amount"), SUBSTITUTABLE)
    # Different keys are different inputs even in the same family.
    assert (
        same_logical_input(Form(key=Key("amount")), Form(key=Key("other")), SUBSTITUTABLE) is False
    )
    # A query '?token=' and a URL '<token>' path segment share a NAME but are
    # NOT the same logical input -- a path segment cannot be forged into a query
    # field. This is the name-collision false positive the primitive fixes.
    assert (
        same_logical_input(Query(key=Key("token")), PathParam(name=Key("token")), SUBSTITUTABLE)
        is False
    )


def test_same_credential_collapses_credential_containers() -> None:
    # A bearer token presented via header, cookie, or query is one credential.
    assert same_logical_input(Header(name=Key("token")), Cookie(name=Key("token")), CREDENTIAL)
    assert same_logical_input(Header(name=Key("token")), Query(key=Key("token")), CREDENTIAL)
    # Different keys are different credentials.
    assert same_logical_input(Header(name=Key("a")), Header(name=Key("b")), CREDENTIAL) is False
    # A non-credential container has no credential identity.
    assert logical_input(Form(key=Key("token")), CREDENTIAL) is None


def _json_field(name: str) -> Json:
    from flawed.core import JsonPath

    return Json(path=JsonPath(f"$.{name}"))


# -- read_inputs / value_inputs ----------------------------------------------


def test_read_inputs_maps_and_drops_misses() -> None:
    reads = [
        _read(Header(name=Key("token"))),
        _read(Form(key=Key("token"))),  # not a credential -> dropped
        _read(Query()),  # wildcard -> dropped
    ]
    assert read_inputs(reads, CREDENTIAL) == frozenset({LogicalInput("CREDENTIAL", "token")})


def test_value_inputs_collects_only_derived_origins() -> None:
    reads = [
        _read(Query(key=Key("email"))),
        _read(Query(key=Key("name"))),
    ]
    value = _value((Query, "email"))
    assert value_inputs(value, reads, EXACT) == frozenset({LogicalInput("Query", "email")})


def test_value_inputs_credential_uses_container_blind_probe() -> None:
    # The value flows from a header credential; the candidate read is the same
    # key. Under the credential equivalence the probe is container-blind.
    reads = [_read(Header(name=Key("token")))]
    value = _value((Header, "token"))
    assert value_inputs(value, reads, CREDENTIAL) == frozenset(
        {LogicalInput("CREDENTIAL", "token")}
    )


# -- ValueHandle.shares_origin -----------------------------------------------


def test_shares_origin_same_value_two_transforms() -> None:
    reads = [_read(Query(key=Key("email")))]
    lowered = _value((Query, "email"))
    stripped = _value((Query, "email"))
    assert lowered.shares_origin(stripped, among=reads)


def test_shares_origin_different_inputs_do_not_correlate() -> None:
    reads = [_read(Query(key=Key("name"))), _read(Query(key=Key("city")))]
    name_t = _value((Query, "name"))
    city_t = _value((Query, "city"))
    assert not name_t.shares_origin(city_t, among=reads)


def test_shares_origin_empty_when_value_has_no_traced_origin() -> None:
    reads = [_read(Query(key=Key("name")))]
    untraced = _value()  # derives from nothing
    other = _value((Query, "name"))
    assert not untraced.shares_origin(other, among=reads)
