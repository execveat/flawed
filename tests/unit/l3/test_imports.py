"""Verify all public types import cleanly from the package."""

from __future__ import annotations


def test_top_level_imports() -> None:
    from flawed import (
        RepoView,
        detector,
        open_repo,
    )

    assert callable(open_repo)
    assert callable(detector)
    assert RepoView is not None


def test_core_imports() -> None:
    from flawed.core import (
        AnalysisGap,
        ExtractionProvenance,
        GapKind,
        JsonPath,
        Key,
        Location,
        Provenance,
    )

    assert Location is not None
    assert Provenance is not None
    assert ExtractionProvenance is not None
    assert Key is not None
    assert JsonPath is not None
    assert AnalysisGap is not None
    assert GapKind is not None


def test_route_imports() -> None:
    from flawed.route import (
        DELETE,
        GET,
        HEAD,
        OPTIONS,
        PATCH,
        POST,
        PUT,
        HttpMethod,
        Route,
        accepting,
    )

    assert Route is not None
    assert HttpMethod is not None
    assert callable(accepting)
    assert GET is HttpMethod.GET
    assert POST is HttpMethod.POST
    assert PUT is HttpMethod.PUT
    assert PATCH is HttpMethod.PATCH
    assert DELETE is HttpMethod.DELETE
    assert OPTIONS is HttpMethod.OPTIONS
    assert HEAD is HttpMethod.HEAD


def test_function_imports() -> None:
    from flawed.function import (
        Decorator,
        Function,
        FunctionKind,
        Parameter,
    )

    assert Function is not None
    assert Parameter is not None
    assert Decorator is not None
    assert FunctionKind is not None


def test_class_imports() -> None:
    from flawed.class_ import (
        Class,
        InheritedMethod,
    )

    assert Class is not None
    assert InheritedMethod is not None


def test_input_imports() -> None:
    from flawed.inputs import (
        AccessPattern,
        AnyContainer,
        AnyOf,
        Cardinality,
        Cookie,
        FileUpload,
        Form,
        Header,
        InputRead,
        InputSource,
        Json,
        PathParam,
        Query,
        RawBody,
    )

    assert InputSource is not None
    assert Query is not None
    assert Form is not None
    assert Json is not None
    assert Header is not None
    assert Cookie is not None
    assert PathParam is not None
    assert FileUpload is not None
    assert RawBody is not None
    assert AnyContainer is not None
    assert AnyOf is not None
    assert InputRead is not None
    assert AccessPattern is not None
    assert Cardinality is not None


def test_effect_imports() -> None:
    from flawed.effects import (
        Cache,
        Config,
        Data,
        Db,
        Effect,
        EffectCategory,
        EffectSelector,
        Mutation,
        Outbound,
        Response,
        State,
        StateScope,
    )

    assert Effect is not None
    assert EffectCategory is not None
    assert EffectSelector is not None
    assert StateScope is not None
    assert Mutation is not None
    assert Data is not None
    assert Db is not None
    assert State is not None
    assert Config is not None
    assert Response is not None
    assert Cache is not None
    assert Outbound is not None


def test_condition_imports() -> None:
    from flawed.conditions import (
        Condition,
        ConditionKind,
        DenialKind,
        ExceptionGuard,
        GuardClassification,
    )

    assert Condition is not None
    assert ConditionKind is not None
    assert DenialKind is not None
    assert GuardClassification is not None
    assert ExceptionGuard is not None


def test_call_imports() -> None:
    from flawed.calls import (
        Argument,
        CallSite,
        Fn,
        FnSelector,
    )

    assert CallSite is not None
    assert Argument is not None
    assert FnSelector is not None
    assert Fn is not None


def test_flow_imports() -> None:
    from flawed.flow import (
        FlowStep,
        FlowTrace,
        ValueHandle,
    )

    assert ValueHandle is not None
    assert FlowTrace is not None
    assert FlowStep is not None


def test_sink_imports() -> None:
    from flawed.sinks import TaintSink

    assert TaintSink is not None


def test_scope_imports() -> None:
    from flawed.scopes import (
        CodeScope,
        ControlFlowView,
    )

    assert CodeScope is not None
    assert ControlFlowView is not None


def test_collection_imports() -> None:
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
        TaintSinkCollection,
    )

    assert DomainCollection is not None
    assert RouteCollection is not None
    assert FunctionCollection is not None
    assert InputReadCollection is not None
    assert EffectCollection is not None
    assert ConditionCollection is not None
    assert CallSiteCollection is not None
    assert DecoratorCollection is not None
    assert ClassCollection is not None
    assert TaintSinkCollection is not None


def test_evidence_imports() -> None:
    from flawed.evidence import (
        Evidence,
        Finding,
    )

    assert Evidence is not None
    assert Finding is not None
