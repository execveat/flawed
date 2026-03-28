"""Verify type hierarchy and subclass relationships."""

from __future__ import annotations


def test_input_source_hierarchy() -> None:
    from flawed.inputs import (
        AnyContainer,
        AnyOf,
        Cookie,
        FileUpload,
        Form,
        Header,
        InputSource,
        Json,
        PathParam,
        Query,
        RawBody,
    )

    subclasses = [
        Query,
        Form,
        Json,
        Header,
        Cookie,
        PathParam,
        FileUpload,
        RawBody,
        AnyContainer,
        AnyOf,
    ]
    for cls in subclasses:
        assert issubclass(cls, InputSource), f"{cls.__name__} should be InputSource subclass"


def test_collection_hierarchy() -> None:
    from flawed.collections import (
        CallSiteCollection,
        ClassCollection,
        ConditionCollection,
        DecoratorCollection,
        DomainCollection,
        EffectCollection,
        FunctionCollection,
        InputReadCollection,
        RouteCollection,
    )

    typed_collections = [
        RouteCollection,
        FunctionCollection,
        ClassCollection,
        InputReadCollection,
        EffectCollection,
        ConditionCollection,
        CallSiteCollection,
        DecoratorCollection,
    ]
    for cls in typed_collections:
        assert issubclass(cls, DomainCollection), (
            f"{cls.__name__} should be DomainCollection subclass"
        )


def test_analysis_gap_is_frozen() -> None:
    import pytest

    from flawed.core import AnalysisGap, GapKind

    gap = AnalysisGap(kind=GapKind.PARSE_FAILURE, message="err")
    with pytest.raises(AttributeError):
        gap.kind = GapKind.CFG_UNAVAILABLE  # type: ignore[misc]


def test_condition_new_types_exist() -> None:
    from flawed.conditions import (
        ConditionKind,
        DenialKind,
        ExceptionGuard,
        GuardClassification,
    )

    assert ConditionKind.COMPARISON.value == "comparison"
    assert DenialKind.ABORT.value == "abort"
    assert GuardClassification is not None
    assert ExceptionGuard is not None


def test_class_is_frozen() -> None:
    import pytest

    from flawed.class_ import Class
    from flawed.core import Location, Provenance

    cls = Class(
        fqn="app.models.User",
        name="User",
        bases=("app.models.Base",),
        mro=("app.models.User", "app.models.Base"),
        method_names=("__init__",),
        inherited_methods=(),
        location=Location(file="app/models.py", line=10, column=0),
        provenance=Provenance(
            source_layer="L2",
            interpreter="class_discovery",
            confidence=1.0,
        ),
    )
    with pytest.raises(AttributeError):
        cls.name = "Other"  # type: ignore[misc]


def test_inherited_method_is_frozen() -> None:
    import pytest

    from flawed.class_ import InheritedMethod

    m = InheritedMethod(name="save", defining_class="app.models.Base")
    with pytest.raises(AttributeError):
        m.name = "other"  # type: ignore[misc]


def test_input_source_instances_are_frozen() -> None:
    import pytest

    from flawed.core import Key
    from flawed.inputs import Query

    q = Query(key=Key("user_id"))
    with pytest.raises(AttributeError):
        q.key = Key("other")  # type: ignore[misc]


def test_input_source_instantiation() -> None:
    from flawed.core import JsonPath, Key
    from flawed.inputs import (
        AnyContainer,
        AnyOf,
        Cookie,
        FileUpload,
        Form,
        Header,
        Json,
        PathParam,
        Query,
        RawBody,
    )

    assert Query(key=Key("q")).key == Key("q")
    assert Form(key=Key("name")).key == Key("name")
    assert Json(path=JsonPath("$.data")).path == JsonPath("$.data")
    assert Header(name=Key("Authorization")).name == Key("Authorization")
    assert Cookie(name=Key("session")).name == Key("session")
    assert PathParam(name=Key("id")).name == Key("id")
    assert FileUpload(field=Key("avatar")).field == Key("avatar")
    assert RawBody() == RawBody()
    assert AnyContainer(key=Key("id")).key == Key("id")

    q = Query(key=Key("a"))
    f = Form(key=Key("b"))
    any_of = AnyOf(sources=(q, f))
    assert len(any_of.sources) == 2
    assert any_of.sources[0] is q
    assert any_of.sources[1] is f
