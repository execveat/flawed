"""Tests for provider dispatch conversion and synthetic reachability."""

from __future__ import annotations

from pathlib import Path

from flawed._index import CodeIndex
from flawed._index._types import (
    CallArgument,
    CallEdge,
    DecoratorFact,
    EdgeSource,
    ExtractionProvenance,
    FunctionRecord,
    ImportFact,
    Parameter,
    ParameterKind,
    ResolutionStatus,
    SourceSpan,
)
from flawed._index._types import FunctionKind as L1FunctionKind
from flawed._semantic import WebApp
from flawed._semantic._collections import ConcreteDecoratorCollection, ConcreteFunctionCollection
from flawed._semantic._dispatch_conversion import convert_dispatch_match, convert_dispatch_matches
from flawed._semantic._enriched import EnrichedFunction
from flawed._semantic._provider_engine import ProviderEngine, ProviderMatch, ProviderPhase
from flawed._semantic.providers import DispatchPattern, HookType, Provider, ProviderMeta
from flawed.core import GapKind, Location, Provenance
from flawed.function import FunctionKind

_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="")
_SPAN = SourceSpan(file="app.py", line=10, column=4, end_line=10, end_column=32)
_ARG = SourceSpan(file="app.py", line=10, column=20, end_line=10, end_column=28)
_ROOT = Path("/tmp/test-repo")


class GenericDispatchProvider(Provider):
    meta = ProviderMeta(
        id="generic-dispatch",
        name="Generic Dispatch",
        library="Generic Dispatch",
        library_fqn="genericdispatch",
    )

    dispatches = (
        DispatchPattern(
            source_fqn="genericdispatch.Background.add_task",
            target_method_names=("fn",),
            dispatch_type="background_task",
        ),
    )


class GenericSignalProvider(Provider):
    meta = ProviderMeta(
        id="generic-signal",
        name="Generic Signal",
        library="Generic Signal",
        library_fqn="genericsignal",
    )

    dispatches = (
        DispatchPattern(
            source_fqn="genericsignal.ready",
            target_method_names=("connect", "send"),
            dispatch_type="signal",
        ),
    )


class GenericCallbackProvider(Provider):
    meta = ProviderMeta(
        id="generic-callback",
        name="Generic Callback",
        library="Generic Callback",
        library_fqn="genericcallback",
    )

    dispatches = (
        DispatchPattern(
            source_fqn="genericcallback.Registry.on_event",
            target_method_names=(),
            dispatch_type="callback_registration",
            callback_arg=0,
            invocation_scope="matching_emission",
            invocation_key="generic-event",
        ),
        DispatchPattern(
            source_fqn="genericcallback.Registry.emit_event",
            target_method_names=(),
            dispatch_type="callback_registration",
            callback_arg=None,
            invocation_scope="emission_caller",
            invocation_key="generic-event",
        ),
    )


class GenericReceiverProvider(Provider):
    meta = ProviderMeta(
        id="generic-receiver",
        name="Generic Receiver",
        library="Generic Receiver",
        library_fqn="genericreceiver",
    )

    dispatches = (
        DispatchPattern(
            source_fqn="genericreceiver.receiver",
            target_method_names=(),
            dispatch_type="signal",
        ),
        DispatchPattern(
            source_fqn="genericsignal.ready",
            target_method_names=("send",),
            dispatch_type="signal",
        ),
    )


def test_dispatch_call_match_converts_first_argument_to_synthetic_edge() -> None:
    pattern = GenericDispatchProvider.dispatches[0]
    match = _call_match(pattern, _call("genericdispatch.Background.add_task", _arg(0, "task")))
    handler = _function("app.handler")
    task = _function("app.task")

    result = convert_dispatch_match(match, {handler.fqn: handler, task.fqn: task})

    assert result.gaps == ()
    assert len(result.edges) == 1
    assert result.edges[0].caller_fqn == "app.handler"
    assert result.edges[0].target.fqn == "app.task"
    assert result.edges[0].dispatch_type == "background_task"


def test_signal_decorator_registration_routes_matching_emission() -> None:
    pattern = DispatchPattern(
        source_fqn="genericdispatch.signals.ready",
        target_method_names=("connect", "send"),
        dispatch_type="signal",
    )
    registration = ProviderMatch(
        provider_id="generic",
        phase=ProviderPhase.DISPATCHES,
        descriptor=pattern,
        source_fact=_decorator("genericdispatch.signals.ready.connect", "app.on_ready"),
        observed_fqn="genericdispatch.signals.ready.connect",
        canonical_fqn="genericdispatch.signals.ready.connect",
        location=_SPAN,
    )
    emission = _call_match(
        pattern,
        _call(
            "genericdispatch.signals.ready.send",
            _arg(0, "sender"),
            call_expression="ready.send(sender)",
        ),
    )
    target = _function("app.on_ready")
    emitter = _function("app.handler")

    result = convert_dispatch_matches(
        (registration, emission),
        {target.fqn: target, emitter.fqn: emitter},
    )

    assert result.gaps == ()
    assert len(result.edges) == 1
    assert result.edges[0].caller_fqn == "app.handler"
    assert result.edges[0].target.fqn == "app.on_ready"


def test_signal_emit_without_project_receiver_does_not_treat_sender_as_callback() -> None:
    pattern = DispatchPattern(
        source_fqn="genericdispatch.signals.ready",
        target_method_names=("send",),
        dispatch_type="signal",
    )
    emission = _call_match(pattern, _call("genericdispatch.signals.ready.send", _arg(0, "sender")))

    result = convert_dispatch_match(emission, {})

    assert result.edges == ()
    assert result.gaps == ()


def test_callback_registration_routes_matching_emission_caller() -> None:
    registration_pattern, emission_pattern = GenericCallbackProvider.dispatches
    registration = _call_match(
        registration_pattern,
        _call("genericcallback.Registry.on_event", _arg(0, "registered_callback")),
    )
    emission = _call_match(
        emission_pattern,
        _call("genericcallback.Registry.emit_event", call_expression="registry.emit_event()"),
    )
    caller = _function("app.handler")
    callback = _function("app.registered_callback")

    result = convert_dispatch_matches(
        (registration, emission),
        {caller.fqn: caller, callback.fqn: callback},
    )

    assert result.gaps == ()
    assert result.hooks == ()
    assert [(edge.caller_fqn, edge.target.fqn) for edge in result.edges] == [
        ("app.handler", "app.registered_callback")
    ]


def test_callback_registration_without_emission_does_not_use_registration_caller() -> None:
    registration_pattern = GenericCallbackProvider.dispatches[0]
    registration = _call_match(
        registration_pattern,
        _call("genericcallback.Registry.on_event", _arg(0, "registered_callback")),
    )
    callback = _function("app.registered_callback")

    result = convert_dispatch_match(registration, {callback.fqn: callback})

    assert result.edges == ()
    assert result.hooks == ()
    assert result.gaps == ()


def test_framework_lifecycle_callback_registration_produces_hook() -> None:
    pattern = DispatchPattern(
        source_fqn="genericcallback.Registry.before_request",
        target_method_names=(),
        dispatch_type="callback_registration",
        callback_arg=0,
        invocation_scope="framework_lifecycle",
        hook_type=HookType.BEFORE_HANDLER,
    )
    match = _call_match(
        pattern,
        _call("genericcallback.Registry.before_request", _arg(0, "before_request")),
    )
    callback = _function("app.before_request")

    result = convert_dispatch_match(match, {callback.fqn: callback})

    assert result.edges == ()
    assert result.gaps == ()
    assert len(result.hooks) == 1
    assert result.hooks[0].handler.fqn == "app.before_request"
    assert result.hooks[0].hook_type is HookType.BEFORE_HANDLER


def test_callback_argument_can_be_declared_by_keyword() -> None:
    pattern = DispatchPattern(
        source_fqn="genericcallback.Registry.on_event",
        target_method_names=(),
        dispatch_type="callback_registration",
        callback_arg=None,
        callback_kwarg="handler",
    )
    match = _call_match(
        pattern,
        _call(
            "genericcallback.Registry.on_event",
            CallArgument(
                position=None,
                keyword="handler",
                expression="registered_callback",
                location=_ARG,
            ),
        ),
    )
    caller = _function("app.handler")
    callback = _function("app.registered_callback")

    result = convert_dispatch_match(match, {caller.fqn: caller, callback.fqn: callback})

    assert result.gaps == ()
    assert [(edge.caller_fqn, edge.target.fqn) for edge in result.edges] == [
        ("app.handler", "app.registered_callback")
    ]


def test_signal_receiver_decorator_routes_by_declared_signal_argument() -> None:
    registration_pattern = GenericReceiverProvider.dispatches[0]
    emission_pattern = GenericReceiverProvider.dispatches[1]
    registration = ProviderMatch(
        provider_id="generic",
        phase=ProviderPhase.DISPATCHES,
        descriptor=registration_pattern,
        source_fact=_decorator(
            "genericreceiver.receiver",
            "app.on_ready",
            args=("genericsignal.ready",),
        ),
        observed_fqn="genericreceiver.receiver",
        canonical_fqn="genericreceiver.receiver",
        location=_SPAN,
    )
    emission = _call_match(emission_pattern, _call("genericsignal.ready.send", _arg(0, "sender")))
    receiver = _function("app.on_ready")
    emitter = _function("app.handler")

    result = convert_dispatch_matches(
        (registration, emission),
        {receiver.fqn: receiver, emitter.fqn: emitter},
    )

    assert result.gaps == ()
    assert [(edge.caller_fqn, edge.target.fqn) for edge in result.edges] == [
        ("app.handler", "app.on_ready")
    ]


def test_signal_decorator_factory_call_edge_does_not_create_false_target_gap() -> None:
    registration_pattern = GenericReceiverProvider.dispatches[0]
    emission_pattern = GenericReceiverProvider.dispatches[1]
    registration = ProviderMatch(
        provider_id="generic",
        phase=ProviderPhase.DISPATCHES,
        descriptor=registration_pattern,
        source_fact=_decorator(
            "genericreceiver.receiver",
            "app.on_ready",
            args=("genericsignal.ready",),
        ),
        observed_fqn="genericreceiver.receiver",
        canonical_fqn="genericreceiver.receiver",
        location=_SPAN,
    )
    decorator_factory_call = _call_match(
        registration_pattern,
        _call("genericreceiver.receiver", _arg(0, "genericsignal.ready")),
    )
    emission = _call_match(emission_pattern, _call("genericsignal.ready.send", _arg(0, "sender")))
    receiver = _function("app.on_ready")
    emitter = _function("app.handler")

    result = convert_dispatch_matches(
        (registration, decorator_factory_call, emission),
        {receiver.fqn: receiver, emitter.fqn: emitter},
    )

    assert result.gaps == ()
    assert [(edge.caller_fqn, edge.target.fqn) for edge in result.edges] == [
        ("app.handler", "app.on_ready")
    ]


def test_signal_receiver_decorator_with_dynamic_signal_records_gap() -> None:
    pattern = GenericReceiverProvider.dispatches[0]
    registration = ProviderMatch(
        provider_id="generic",
        phase=ProviderPhase.DISPATCHES,
        descriptor=pattern,
        source_fact=_decorator(
            "genericreceiver.receiver",
            "app.on_ready",
            args=("choose_signal()",),
        ),
        observed_fqn="genericreceiver.receiver",
        canonical_fqn="genericreceiver.receiver",
        location=_SPAN,
    )
    receiver = _function("app.on_ready")

    result = convert_dispatch_match(registration, {receiver.fqn: receiver})

    assert result.edges == ()
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == GapKind.INFERENCE_FAILURE
    assert "could not be resolved" in result.gaps[0].message


def test_dispatch_call_with_unresolved_target_records_gap() -> None:
    pattern = GenericDispatchProvider.dispatches[0]
    match = _call_match(pattern, _call("genericdispatch.Background.add_task", _arg(0, "task")))

    result = convert_dispatch_match(match, {})

    assert result.edges == ()
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == GapKind.INFERENCE_FAILURE
    assert "could not be resolved" in result.gaps[0].message


def test_webapp_function_reachability_includes_synthetic_dispatch_target() -> None:
    idx = _index(
        imports=(_import("genericdispatch"),),
        functions=(_function_record("app.handler"), _function_record("app.task")),
        call_edges=(
            _call(
                "genericdispatch.Background.add_task",
                _arg(0, "task"),
                call_expression="background.add_task(task)",
            ),
        ),
    )

    repo = WebApp.from_index(
        idx,
        provider_engine=ProviderEngine(providers=(GenericDispatchProvider,)),
    ).repo_view()

    handler = next(function for function in repo.functions if function.fqn == "app.handler")
    task = next(function for function in repo.functions if function.fqn == "app.task")
    assert tuple(function.fqn for function in handler.calls) == ("app.task",)
    assert tuple(function.fqn for function in task.called_by) == ("app.handler",)


def test_webapp_signal_emit_reaches_registered_receiver() -> None:
    idx = _index(
        imports=(_import("genericsignal"),),
        functions=(_function_record("app.handler"), _function_record("app.on_ready")),
        decorators=(_decorator("genericsignal.ready.connect", "app.on_ready"),),
        call_edges=(
            _call(
                "genericsignal.ready.send",
                _arg(0, "sender"),
                call_expression="ready.send(sender)",
            ),
        ),
    )

    repo = WebApp.from_index(
        idx,
        provider_engine=ProviderEngine(providers=(GenericSignalProvider,)),
    ).repo_view()

    handler = next(function for function in repo.functions if function.fqn == "app.handler")
    receiver = next(function for function in repo.functions if function.fqn == "app.on_ready")
    assert tuple(function.fqn for function in handler.calls) == ("app.on_ready",)
    assert tuple(function.fqn for function in receiver.called_by) == ("app.handler",)


def _call_match(pattern: DispatchPattern, edge: CallEdge) -> ProviderMatch:
    return ProviderMatch(
        provider_id="generic",
        phase=ProviderPhase.DISPATCHES,
        descriptor=pattern,
        source_fact=edge,
        observed_fqn=edge.callee_fqn or "",
        canonical_fqn=edge.callee_fqn or "",
        location=edge.location,
    )


def _call(
    fqn: str,
    *args: CallArgument,
    call_expression: str | None = None,
) -> CallEdge:
    return CallEdge(
        caller_fqn="app.handler",
        callee_fqn=fqn,
        arguments=args,
        resolution=ResolutionStatus.RESOLVED,
        source=EdgeSource.AST,
        unresolved_reason=None,
        location=_SPAN,
        provenance=_PROV,
        call_expression=call_expression or f"{fqn}()",
    )


def _arg(position: int, expression: str) -> CallArgument:
    return CallArgument(position=position, keyword=None, expression=expression, location=_ARG)


def _decorator(
    fqn: str,
    target_fqn: str,
    *,
    args: tuple[str, ...] = (),
    kwargs: tuple[tuple[str, str], ...] = (),
) -> DecoratorFact:
    return DecoratorFact(
        name=fqn.rsplit(".", 1)[-1],
        fqn=fqn,
        args=args,
        kwargs=kwargs,
        target_fqn=target_fqn,
        application_order=0,
        location=_SPAN,
        provenance=_PROV,
    )


def _function(fqn: str) -> EnrichedFunction:
    fn = EnrichedFunction(
        fqn=fqn,
        name=fqn.rsplit(".", 1)[-1],
        params=(),
        kind=FunctionKind.TOP_LEVEL,
        parent_class=None,
        parent_function=None,
        location=Location(file="app.py", line=1, column=0, end_line=5, end_column=0),
        provenance=Provenance(source_layer="L2", interpreter="test", confidence=1.0),
    )
    object.__setattr__(fn, "_decorators", ConcreteDecoratorCollection(()))
    object.__setattr__(fn, "_gaps", ())
    object.__setattr__(fn, "_calls", ConcreteFunctionCollection(()))
    object.__setattr__(fn, "_called_by", ConcreteFunctionCollection(()))
    return fn


def _function_record(fqn: str) -> FunctionRecord:
    name = fqn.rsplit(".", 1)[-1]
    return FunctionRecord(
        fqn=fqn,
        name=name,
        file="app.py",
        line=1,
        params=(
            Parameter(
                name="request",
                annotation=None,
                default=None,
                kind=ParameterKind.POSITIONAL_OR_KEYWORD,
                position=0,
                location=SourceSpan(file="app.py", line=1, column=0, end_line=1, end_column=7),
            ),
        ),
        decorator_names=(),
        decorator_fqns=(),
        kind=L1FunctionKind.TOP_LEVEL,
        is_method=False,
        is_nested=False,
        is_async=False,
        parent_class=None,
        location=SourceSpan(file="app.py", line=1, column=0, end_line=5, end_column=0),
        provenance=_PROV,
    )


def _import(module: str) -> ImportFact:
    return ImportFact(
        module=module,
        names=(),
        aliases=(),
        is_from_import=False,
        location=_SPAN,
        provenance=_PROV,
    )


def _index(
    *,
    imports: tuple[ImportFact, ...],
    functions: tuple[FunctionRecord, ...],
    call_edges: tuple[CallEdge, ...],
    decorators: tuple[DecoratorFact, ...] = (),
) -> CodeIndex:
    return CodeIndex(
        repo_root=_ROOT,
        functions=functions,
        classes=(),
        decorators=decorators,
        imports=imports,
        attributes=(),
        call_edges=call_edges,
        cfgs={},
        value_flow_edges=(),
        symbol_refs=(),
        errors=(),
        provenance=_PROV,
    )
