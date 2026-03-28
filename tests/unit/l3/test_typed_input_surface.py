"""Typed L3 rule-facing surface: uniform identifier + value-flow source (FLAW-257).

These pin the typed accessors that replace ``getattr(source, "key"/"name"/...)``
reaches in rules (the type-erasure class):

1. :attr:`flawed.inputs.InputSource.identifier` -- one typed accessor that
   returns the identifying key/name/path/field/parameter of any source,
   regardless of which divergently-named field each subclass uses, or ``None``
   for a wildcard / identifier-less source.
2. :attr:`flawed.flow.ValueHandle.source` -- the public typed input source a
   value was read from, replacing private ``_input_source`` reaches.
3. Top-level re-exports of the six rule-facing element types so authors can
   name them without spelunking submodules.
"""

from __future__ import annotations

from flawed.core import JsonPath, Key, Location
from flawed.flow import ValueHandle, attach_flow_context
from flawed.inputs import (
    AnyContainer,
    AnyOf,
    Cookie,
    DependencyInput,
    FileUpload,
    Form,
    FrameworkGlobal,
    Header,
    Json,
    PathParam,
    ProviderClaim,
    Query,
    RawBody,
    SessionValue,
)


def _loc(line: int = 1) -> Location:
    return Location(file="t.py", line=line, column=0)


class TestInputSourceIdentifier:
    def test_key_named_sources_expose_identifier(self) -> None:
        assert Query(key=Key("user_id")).identifier == "user_id"
        assert Form(key=Key("amount")).identifier == "amount"
        assert ProviderClaim(key=Key("email")).identifier == "email"
        assert SessionValue(key=Key("cart_id")).identifier == "cart_id"
        assert AnyContainer(key=Key("id")).identifier == "id"

    def test_name_named_sources_expose_identifier(self) -> None:
        assert Header(name=Key("X-Api-Key")).identifier == "X-Api-Key"
        assert Cookie(name=Key("session")).identifier == "session"
        assert PathParam(name=Key("id")).identifier == "id"
        assert FrameworkGlobal(name=Key("cart_id")).identifier == "cart_id"

    def test_divergently_named_identifier_fields(self) -> None:
        # path / field / parameter all surface through the SAME accessor.
        assert Json(path=JsonPath("$.user_id")).identifier == "$.user_id"
        assert FileUpload(field=Key("avatar")).identifier == "avatar"
        assert DependencyInput(parameter=Key("db")).identifier == "db"

    def test_wildcard_and_identifierless_sources_return_none(self) -> None:
        assert Query().identifier is None  # wildcard
        assert Json().identifier is None  # wildcard
        assert RawBody().identifier is None  # no identifier field at all
        assert AnyOf(sources=(Form(), Json())).identifier is None  # combinator


class TestValueHandleSource:
    def test_source_returns_attached_input_source(self) -> None:
        handle = attach_flow_context(
            ValueHandle(location=_loc(), expression="request.args['q']"),
            input_source=Query(key=Key("q")),
        )
        assert handle.source == Query(key=Key("q"))
        # and the uniform identifier accessor composes through it
        assert handle.source is not None
        assert handle.source.identifier == "q"

    def test_source_is_none_without_flow_context(self) -> None:
        bare = ValueHandle(location=_loc(), expression="x")
        assert bare.source is None


class TestTopLevelReExports:
    def test_six_element_types_are_importable_from_top_level(self) -> None:
        import flawed

        for name in ("InputRead", "InputSource", "CallSite", "Argument", "Effect", "Check"):
            assert name in flawed.__all__, f"{name} missing from flawed.__all__"
            assert hasattr(flawed, name), f"flawed.{name} not importable"
