"""Tests for the Layer 2 provider engine and declarative matcher."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from flawed._index import CodeIndex
from flawed._index._types import (
    AccessKind,
    AttributeAccess,
    CallArgument,
    CallEdge,
    ClassRecord,
    DecoratorFact,
    EdgeSource,
    ExtractionProvenance,
    FlowKind,
    FunctionRecord,
    ImportFact,
    ResolutionStatus,
    SourceSpan,
    SymbolRef,
    ValueFlowEdge,
)
from flawed._semantic._provider_engine import (
    PredicateStatus,
    ProviderEngine,
    ProviderPhase,
    _provider_is_imported,
    discover_builtin_provider_classes,
)
from flawed._semantic.providers import (
    CheckKind,
    CheckRegistrationPattern,
    ClassViewPattern,
    DependencyPattern,
    DispatchPattern,
    EffectCallPattern,
    EffectSubscriptPattern,
    FlowPropagatorPattern,
    HookType,
    ImperativeRoutePattern,
    InputAttributePattern,
    InputMethodPattern,
    LifecycleDecoratorPattern,
    LifecycleRegistrationPattern,
    MiddlewareClassPattern,
    Provider,
    ProviderMeta,
    RouteCallPattern,
    RouteDecorator,
    RouterGroupMountPattern,
    RouterGroupPattern,
    SecurityCheckPattern,
    StateProxyPattern,
    TaintSinkPattern,
    arg,
)
from flawed._semantic.providers.flask_limiter import FlaskLimiterProvider
from flawed._semantic.providers.python_stdlib import PythonStdlibProvider
from flawed.core import GapKind

_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="")
_SPAN = SourceSpan(file="app.py", line=1, column=0, end_line=1, end_column=10)
_ROOT = Path("/tmp/test-repo")


class FakeProvider(Provider):
    meta = ProviderMeta(
        id="fake",
        name="Fake",
        version="0.1.0",
        library="Fake",
        library_fqn="fakepkg",
    )

    fqn_aliases: ClassVar[dict[str, str]] = {
        "fake.alias": "fake.canonical",
    }

    routes = (
        RouteDecorator(fqn="fake.canonical.route"),
        RouteCallPattern(fqn="fake.canonical.add_route"),
    )
    inputs = (
        InputAttributePattern(
            receiver_fqn="fake.request",
            attribute="args",
            source_type="Query",
        ),
        InputMethodPattern(fqn="fake.Request.get_json", source_type="Json"),
    )
    effects = (
        EffectCallPattern(fqn="fake.db.write", category="DB_WRITE"),
        EffectSubscriptPattern(
            receiver_fqn="fake.session",
            category="STATE_WRITE",
            scope="SESSION",
        ),
    )
    checks = (
        SecurityCheckPattern(
            fqn="fake.login_required",
            kind=CheckKind.DECORATOR,
            category="AUTHENTICATION",
        ),
    )
    lifecycle = (
        LifecycleDecoratorPattern(
            fqn="fake.before_request",
            hook_type=HookType.BEFORE_HANDLER,
        ),
    )
    dependencies = (DependencyPattern(inject_fqn="fake.Depends"),)
    dispatches = (
        DispatchPattern(
            source_fqn="fake.signal",
            target_method_names=("handler",),
            dispatch_type="signal",
        ),
    )
    propagators = (FlowPropagatorPattern(fqn="fake.loads", input_arg=0, output="return"),)
    sinks = (
        TaintSinkPattern(
            fqn="fake.sql",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
        ),
    )
    proxies = (
        StateProxyPattern(
            fqn="fake.current_user",
            resolves_to="fake.g.user",
            scope="REQUEST",
        ),
    )


class BuiltinProvider(Provider):
    meta = ProviderMeta(
        id="builtin",
        name="Builtin",
        version="0.1.0",
        library="Python standard library",
        library_fqn="builtins",
    )

    sinks = (
        TaintSinkPattern(
            fqn="builtins.open",
            arg=0,
            sink_kind="PATH_TRAVERSAL",
        ),
    )


class PublicReceiverProvider(Provider):
    meta = ProviderMeta(
        id="public-receiver",
        name="Public Receiver",
        library="Public Receiver",
        library_fqn="publicreceiver",
    )

    effects = (
        EffectCallPattern(
            fqn=("publicreceiver.PublicClient.write", "publicreceiver.impl.Mixin.write"),
            category="CACHE_WRITE",
        ),
    )
    sinks = (
        TaintSinkPattern(
            fqn=("publicreceiver.PublicClient.write", "publicreceiver.impl.Mixin.write"),
            arg=0,
            sink_kind="KEY_INJECTION",
        ),
    )


class FailingHookProvider(Provider):
    meta = ProviderMeta(
        id="hook-fail",
        name="Hook Fail",
        library="Hook Fail",
        library_fqn="hookfail",
    )

    def extract_routes(self, idx: object) -> tuple[object, ...]:
        raise RuntimeError("route hook exploded")


class TypePredicateProvider(Provider):
    meta = ProviderMeta(
        id="types",
        name="Types",
        library="Types",
        library_fqn="typeslib",
    )

    effects = (
        EffectCallPattern(
            fqn="types.Session.execute",
            category="DB_WRITE",
            when=arg(0).type_is("types.Insert"),
        ),
    )


class TypedReceiverProvider(Provider):
    meta = ProviderMeta(
        id="typed-receiver",
        name="Typed Receiver",
        library="Typed Receiver",
        library_fqn="typedpkg",
    )

    fqn_aliases: ClassVar[dict[str, str]] = {
        "typedpkg.PublicSession": "typedpkg.impl.Session",
    }
    effects = (
        EffectCallPattern(
            fqn="typedpkg.impl.Session.commit",
            category="DB_WRITE",
        ),
    )


class InstanceMemberSubscriptProvider(Provider):
    meta = ProviderMeta(
        id="instance-member-subscript",
        name="Instance Member Subscript",
        library="Instance Member Subscript",
        library_fqn="instancefw",
    )

    effects = (
        EffectSubscriptPattern(
            receiver_fqn="instancefw.App.config",
            category="CONFIG_WRITE",
        ),
    )


class DescriptorCallProvider(Provider):
    meta = ProviderMeta(
        id="descriptor-calls",
        name="Descriptor Calls",
        library="Descriptor Calls",
        library_fqn="descriptorcalls",
    )

    lifecycle = (
        LifecycleRegistrationPattern(
            registration_fqn="app.before_request",
            hook_type=HookType.BEFORE_HANDLER,
        ),
        CheckRegistrationPattern(
            registration_fqn="app.limit",
            hook_type=HookType.BEFORE_HANDLER,
            check_category="RATE_LIMITING",
            target_arg=0,
            target_kind="router_group",
        ),
    )
    dependencies = (DependencyPattern(inject_fqn="fastapi.Depends"),)
    dispatches = (
        DispatchPattern(
            source_fqn="blinker.signal.send",
            target_method_names=("receiver",),
            dispatch_type="signal",
        ),
    )


class ClassLifecycleProvider(Provider):
    meta = ProviderMeta(
        id="class-lifecycle",
        name="Class Lifecycle",
        library="Class Lifecycle",
        library_fqn="classlife",
    )

    lifecycle = (
        MiddlewareClassPattern(
            base_class_fqn="classlife.BaseMiddleware",
            method_hooks={"before": HookType.BEFORE_HANDLER},
        ),
    )


class SignalMethodProvider(Provider):
    meta = ProviderMeta(
        id="signal-method",
        name="Signal Method",
        library="Signal Method",
        library_fqn="signalmethod",
    )

    dispatches = (
        DispatchPattern(
            source_fqn="signalmethod.signals.ready",
            target_method_names=("connect",),
            dispatch_type="signal",
        ),
    )


def _make_index(
    *,
    repo_root: Path = _ROOT,
    imports: tuple[ImportFact, ...] = (),
    decorators: tuple[DecoratorFact, ...] = (),
    attributes: tuple[AttributeAccess, ...] = (),
    call_edges: tuple[CallEdge, ...] = (),
    symbol_refs: tuple[SymbolRef, ...] = (),
    value_flow_edges: tuple[ValueFlowEdge, ...] = (),
    functions: tuple[FunctionRecord, ...] = (),
    classes: tuple[ClassRecord, ...] = (),
) -> CodeIndex:
    return CodeIndex(
        repo_root=repo_root,
        functions=functions,
        classes=classes,
        decorators=decorators,
        imports=imports,
        attributes=attributes,
        call_edges=call_edges,
        cfgs={},
        value_flow_edges=value_flow_edges,
        symbol_refs=symbol_refs,
        errors=(),
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


def _decorator(fqn: str, *, target_fqn: str = "app.handler") -> DecoratorFact:
    return DecoratorFact(
        name=fqn.rsplit(".", 1)[-1],
        fqn=fqn,
        args=(),
        kwargs=(),
        target_fqn=target_fqn,
        application_order=0,
        location=_SPAN,
        provenance=_PROV,
    )


def _call(
    fqn: str,
    *,
    caller_fqn: str = "app.handler",
    args: tuple[CallArgument, ...] = (),
    call_expression: str | None = None,
) -> CallEdge:
    return CallEdge(
        caller_fqn=caller_fqn,
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
    return CallArgument(
        position=position,
        keyword=None,
        expression=expression,
        location=_SPAN,
    )


def _kwarg(keyword: str, expression: str) -> CallArgument:
    return CallArgument(
        position=None,
        keyword=keyword,
        expression=expression,
        location=_SPAN,
    )


def _vf_assign(source_expr: str, target_expr: str, *, file: str = "app.py") -> ValueFlowEdge:
    return _vf_assign_at(source_expr, target_expr, file=file)


def _vf_assign_at(
    source_expr: str,
    target_expr: str,
    *,
    file: str = "app.py",
    line: int = 1,
    containing_function_fqn: str | None = None,
) -> ValueFlowEdge:
    return ValueFlowEdge(
        source_expr=source_expr,
        source_location=SourceSpan(file=file, line=line, column=0, end_line=line, end_column=10),
        target_expr=target_expr,
        target_location=SourceSpan(file=file, line=line, column=0, end_line=line, end_column=10),
        kind=FlowKind.ASSIGN,
        containing_function_fqn=containing_function_fqn,
        provenance=_PROV,
    )


def _vf_argument(
    source_expr: str, target_expr: str, *, line: int = 10, file: str = "app.py"
) -> ValueFlowEdge:
    return ValueFlowEdge(
        source_expr=source_expr,
        source_location=SourceSpan(file=file, line=line, column=0, end_line=line, end_column=10),
        target_expr=target_expr,
        target_location=SourceSpan(file=file, line=line, column=0, end_line=line, end_column=10),
        kind=FlowKind.ARGUMENT,
        containing_function_fqn=None,
        provenance=_PROV,
    )


def _attribute(
    target_expr: str,
    attr_name: str,
    *,
    is_write: bool = False,
    access_kind: AccessKind = AccessKind.ATTR,
    line: int = 1,
) -> AttributeAccess:
    return AttributeAccess(
        target_expr=target_expr,
        attr_name=attr_name,
        is_write=is_write,
        access_kind=access_kind,
        value_expr="value" if is_write else None,
        containing_function_fqn="app.handler",
        location=SourceSpan(file="app.py", line=line, column=0, end_line=line, end_column=10),
        provenance=_PROV,
    )


def _symbol(name: str, fqn: str, *, file: str = "app.py", line: int = 1) -> SymbolRef:
    return SymbolRef(
        name=name,
        fqn=fqn,
        resolution=ResolutionStatus.RESOLVED,
        location=SourceSpan(file=file, line=line, column=0, end_line=line, end_column=10),
        provenance=_PROV,
    )


def test_builtin_provider_discovery_returns_stable_provider_ids() -> None:
    providers = discover_builtin_provider_classes()

    provider_ids = tuple(provider.meta.id for provider in providers)
    assert provider_ids == tuple(sorted(provider_ids))
    assert "flask" in provider_ids
    assert "python-stdlib" in provider_ids
    assert "sqlalchemy" in provider_ids


def test_explicit_provider_ids_select_only_requested_provider() -> None:
    idx = _make_index(imports=(_import("fakepkg"), _import("typeslib")))
    result = ProviderEngine(providers=(FakeProvider, TypePredicateProvider)).run(
        idx,
        provider_ids=("types",),
    )

    assert result.active_provider_ids == ("types",)


def test_unknown_explicit_provider_id_returns_gap() -> None:
    idx = _make_index()
    result = ProviderEngine(providers=(FakeProvider,)).run(idx, provider_ids=("missing",))

    assert result.active_provider_ids == ()
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == GapKind.INTERPRETER_ERROR
    assert "missing" in result.gaps[0].message


def test_auto_activation_uses_imported_library_fqn_and_empty_imports_are_noop() -> None:
    engine = ProviderEngine(providers=(FakeProvider,))

    no_import_result = engine.run(_make_index())
    assert no_import_result.active_provider_ids == ()
    assert no_import_result.matches == ()
    assert no_import_result.gaps == ()

    imported_result = engine.run(_make_index(imports=(_import("fakepkg.submodule"),)))
    assert imported_result.active_provider_ids == ("fake",)


def test_builtin_fqn_provider_auto_activates_without_import_fact() -> None:
    idx = _make_index(call_edges=(_call("builtins.open", args=(_arg(0, "path"),)),))

    result = ProviderEngine(providers=(BuiltinProvider, FakeProvider)).run(idx)

    assert result.active_provider_ids == ("builtin",)
    assert [(match.phase, match.canonical_fqn) for match in result.matches] == [
        (ProviderPhase.SINKS, "builtins.open"),
    ]


def test_python_stdlib_provider_matches_command_and_code_execution_sinks() -> None:
    idx = _make_index(
        call_edges=(
            _call("os.system", args=(_arg(0, "command"),)),
            _call("subprocess.run", args=(_arg(0, "command"),)),
            _call("subprocess.run", args=(_kwarg("args", "command"),)),
            _call("builtins.eval", args=(_arg(0, "code"),)),
            _call("builtins.exec", args=(_arg(0, "code"),)),
        ),
    )

    result = ProviderEngine(providers=(PythonStdlibProvider,)).run(idx)

    assert result.active_provider_ids == ("python-stdlib",)
    assert [
        (match.canonical_fqn, match.descriptor.sink_kind)
        for match in result.matches
        if isinstance(match.descriptor, TaintSinkPattern)
    ] == [
        ("os.system", "COMMAND_INJECTION"),
        ("subprocess.run", "COMMAND_INJECTION"),
        ("subprocess.run", "COMMAND_INJECTION"),
        ("builtins.eval", "CODE_INJECTION"),
        ("builtins.exec", "CODE_INJECTION"),
    ]


def test_python_stdlib_provider_suppresses_literal_command_and_code_sinks() -> None:
    idx = _make_index(
        call_edges=(
            _call("os.system", args=(_arg(0, '"true"'),)),
            _call("subprocess.run", args=(_arg(0, '["echo", "safe"]'),)),
            _call("builtins.eval", args=(_arg(0, '"1 + 1"'),)),
            _call("builtins.exec", args=(_arg(0, '"result = 1"'),)),
        ),
    )

    result = ProviderEngine(providers=(PythonStdlibProvider,)).run(idx)

    assert result.active_provider_ids == ("python-stdlib",)
    assert result.matches == ()


def test_matches_are_emitted_in_documented_phase_order() -> None:
    idx = _make_index(
        imports=(_import("fakepkg"),),
        decorators=(
            _decorator("fake.alias.route"),
            _decorator("fake.login_required"),
            _decorator("fake.before_request"),
        ),
        attributes=(
            _attribute("fake.request", "args"),
            _attribute(
                "fake.session",
                "'user_id'",
                is_write=True,
                access_kind=AccessKind.SUBSCRIPT,
            ),
        ),
        call_edges=(
            _call("fake.canonical.add_route"),
            _call("fake.Request.get_json"),
            _call("fake.db.write"),
            _call("fake.Depends"),
            _call("fake.signal"),
            _call("fake.loads"),
            _call("fake.sql", args=(_arg(0, "user_sql"),)),
        ),
        symbol_refs=(_symbol("current_user", "fake.current_user"),),
    )

    result = ProviderEngine(providers=(FakeProvider,)).run(idx)

    assert tuple(match.phase for match in result.matches) == (
        ProviderPhase.ROUTES,
        ProviderPhase.ROUTES,
        ProviderPhase.INPUTS,
        ProviderPhase.INPUTS,
        ProviderPhase.EFFECTS,
        ProviderPhase.EFFECTS,
        ProviderPhase.CHECKS,
        ProviderPhase.LIFECYCLE,
        ProviderPhase.DEPENDENCIES,
        ProviderPhase.DISPATCHES,
        ProviderPhase.PROPAGATORS,
        ProviderPhase.SINKS,
        ProviderPhase.PROXIES,
    )


def test_security_decorator_matches_class_target_decorator_fact() -> None:
    """Class-level decorator facts still match decorator security checks."""
    idx = _make_index(
        imports=(_import("fakepkg"),),
        decorators=(_decorator("fake.login_required", target_fqn="app.AdminView"),),
    )

    matches = ProviderEngine(providers=(FakeProvider,)).run(idx).matches

    assert len(matches) == 1
    assert matches[0].phase is ProviderPhase.CHECKS
    assert isinstance(matches[0].source_fact, DecoratorFact)
    assert matches[0].source_fact.target_fqn == "app.AdminView"


def test_lifecycle_registration_pattern_matches_call_edge() -> None:
    idx = _make_index(
        imports=(_import("descriptorcalls"),),
        call_edges=(_call("app.before_request"),),
    )

    matches = ProviderEngine(providers=(DescriptorCallProvider,)).run(idx).matches

    assert len(matches) == 1
    assert matches[0].phase == ProviderPhase.LIFECYCLE
    assert matches[0].descriptor == DescriptorCallProvider.lifecycle[0]
    assert matches[0].observed_fqn == "app.before_request"
    assert matches[0].canonical_fqn == "app.before_request"


def test_check_registration_pattern_matches_call_edge() -> None:
    idx = _make_index(
        imports=(_import("descriptorcalls"),),
        call_edges=(_call("app.limit", args=(_arg(0, "api"),)),),
    )

    matches = ProviderEngine(providers=(DescriptorCallProvider,)).run(idx).matches

    assert len(matches) == 1
    assert matches[0].phase == ProviderPhase.LIFECYCLE
    assert matches[0].descriptor == DescriptorCallProvider.lifecycle[1]
    assert isinstance(matches[0].source_fact, CallEdge)
    assert matches[0].source_fact.arguments[0].expression == "api"


def test_flask_limiter_blueprint_limit_registration_matches_call_edge() -> None:
    idx = _make_index(
        imports=(_import("flask_limiter"),),
        symbol_refs=(_symbol("Limiter", "flask_limiter.Limiter"),),
        value_flow_edges=(_vf_assign("Limiter(app)", "limiter"),),
        call_edges=(
            _call(
                "app.limiter.limit",
                caller_fqn="<module>",
                args=(_arg(0, "auth"),),
                call_expression='limiter.limit("5/minute")(auth)',
            ),
        ),
    )

    matches = ProviderEngine(providers=(FlaskLimiterProvider,)).run(idx).matches

    assert len(matches) == 1
    assert matches[0].phase == ProviderPhase.LIFECYCLE
    assert isinstance(matches[0].descriptor, CheckRegistrationPattern)
    assert matches[0].canonical_fqn == "flask_limiter.Limiter.limit"
    assert isinstance(matches[0].source_fact, CallEdge)
    assert matches[0].source_fact.arguments[0].expression == "auth"


def test_flask_limiter_route_limit_factory_call_is_not_lifecycle_registration() -> None:
    idx = _make_index(
        imports=(_import("flask_limiter"),),
        symbol_refs=(_symbol("Limiter", "flask_limiter.Limiter"),),
        value_flow_edges=(_vf_assign("Limiter(app)", "limiter"),),
        call_edges=(
            _call(
                "app.limiter.limit",
                caller_fqn="<module>",
                args=(_arg(0, '"5/minute"'),),
                call_expression='limiter.limit("5/minute")',
            ),
        ),
    )

    matches = ProviderEngine(providers=(FlaskLimiterProvider,)).run(idx).matches

    assert all(match.phase is not ProviderPhase.LIFECYCLE for match in matches)


def test_dependency_pattern_matches_parameter_default_call_edge() -> None:
    idx = _make_index(
        imports=(_import("descriptorcalls"),),
        call_edges=(
            _call(
                "fastapi.Depends",
                args=(_arg(0, "current_user"),),
                call_expression="fastapi.Depends(current_user)",
            ),
        ),
    )

    matches = ProviderEngine(providers=(DescriptorCallProvider,)).run(idx).matches

    assert len(matches) == 1
    assert matches[0].phase == ProviderPhase.DEPENDENCIES
    assert matches[0].descriptor == DescriptorCallProvider.dependencies[0]
    assert isinstance(matches[0].source_fact, CallEdge)
    assert matches[0].source_fact.arguments[0].expression == "current_user"
    assert matches[0].observed_fqn == "fastapi.Depends"
    assert matches[0].canonical_fqn == "fastapi.Depends"


def test_dispatch_pattern_matches_call_edge() -> None:
    idx = _make_index(
        imports=(_import("descriptorcalls"),),
        call_edges=(_call("blinker.signal.send"),),
    )

    matches = ProviderEngine(providers=(DescriptorCallProvider,)).run(idx).matches

    assert len(matches) == 1
    assert matches[0].phase == ProviderPhase.DISPATCHES
    assert matches[0].descriptor == DescriptorCallProvider.dispatches[0]
    assert matches[0].observed_fqn == "blinker.signal.send"
    assert matches[0].canonical_fqn == "blinker.signal.send"


def test_dispatch_pattern_matches_target_method_call_edge() -> None:
    idx = _make_index(
        imports=(_import("signalmethod"),),
        call_edges=(_call("signalmethod.signals.ready.connect"),),
    )

    matches = ProviderEngine(providers=(SignalMethodProvider,)).run(idx).matches

    assert len(matches) == 1
    assert matches[0].phase == ProviderPhase.DISPATCHES
    assert matches[0].descriptor == SignalMethodProvider.dispatches[0]
    assert matches[0].observed_fqn == "signalmethod.signals.ready.connect"
    assert matches[0].canonical_fqn == "signalmethod.signals.ready.connect"


def test_dispatch_pattern_matches_decorator_registration() -> None:
    idx = _make_index(
        imports=(_import("signalmethod"),),
        decorators=(
            _decorator(
                "signalmethod.signals.ready.connect",
                target_fqn="app.on_ready",
            ),
        ),
    )

    matches = ProviderEngine(providers=(SignalMethodProvider,)).run(idx).matches

    assert len(matches) == 1
    assert matches[0].phase == ProviderPhase.DISPATCHES
    assert matches[0].descriptor == SignalMethodProvider.dispatches[0]
    assert isinstance(matches[0].source_fact, DecoratorFact)
    assert matches[0].source_fact.target_fqn == "app.on_ready"


def test_call_descriptor_patterns_do_not_match_without_call_edges() -> None:
    idx = _make_index(imports=(_import("descriptorcalls"),))

    result = ProviderEngine(providers=(DescriptorCallProvider,)).run(idx)

    assert result.active_provider_ids == ("descriptor-calls",)
    assert result.matches == ()


def test_fqn_aliases_canonicalize_observed_fqns_before_matching() -> None:
    idx = _make_index(
        imports=(_import("fakepkg"),),
        decorators=(_decorator("fake.alias.route"),),
    )

    match = ProviderEngine(providers=(FakeProvider,)).run(idx).matches[0]

    assert match.observed_fqn == "fake.alias.route"
    assert match.canonical_fqn == "fake.canonical.route"
    assert match.provider_id == "fake"


def test_public_constructor_assignment_aliases_effect_and_sink_methods() -> None:
    idx = _make_index(
        imports=(_import("publicreceiver"),),
        functions=(_function_record("app.handler"),),
        symbol_refs=(_symbol("PublicClient", "publicreceiver.PublicClient"),),
        value_flow_edges=(_vf_assign("PublicClient()", "cache"),),
        call_edges=(
            _call(
                "app.cache.write",
                args=(_arg(0, "key"),),
                call_expression="cache.write(key)",
            ),
        ),
    )

    matches = ProviderEngine(providers=(PublicReceiverProvider,)).run(idx).matches

    assert [(match.phase, match.canonical_fqn) for match in matches] == [
        (ProviderPhase.EFFECTS, "publicreceiver.PublicClient.write"),
        (ProviderPhase.SINKS, "publicreceiver.PublicClient.write"),
    ]


def test_exact_call_attribute_and_subscript_patterns_match_l1_facts() -> None:
    idx = _make_index(
        imports=(_import("fakepkg"),),
        attributes=(
            _attribute("fake.request", "args"),
            _attribute(
                "fake.session",
                "'user_id'",
                is_write=True,
                access_kind=AccessKind.SUBSCRIPT,
            ),
        ),
        call_edges=(
            _call("fake.Request.get_json"),
            _call("fake.db.write"),
        ),
    )

    matches = ProviderEngine(providers=(FakeProvider,)).run(idx).matches

    assert [(match.phase, match.canonical_fqn) for match in matches] == [
        (ProviderPhase.INPUTS, "fake.request.args"),
        (ProviderPhase.INPUTS, "fake.Request.get_json"),
        (ProviderPhase.EFFECTS, "fake.db.write"),
        (ProviderPhase.EFFECTS, "fake.session['user_id']"),
    ]


def test_local_receiver_alias_matches_input_attribute_pattern() -> None:
    idx = _make_index(
        imports=(_import("fakepkg"),),
        attributes=(_attribute("local_request", "args", line=20),),
        value_flow_edges=(
            _vf_assign_at(
                "fake.request",
                "local_request",
                line=10,
                containing_function_fqn="app.handler",
            ),
        ),
    )

    matches = ProviderEngine(providers=(FakeProvider,)).run(idx).matches

    assert [(match.phase, match.canonical_fqn) for match in matches] == [
        (ProviderPhase.INPUTS, "fake.request.args"),
    ]


def test_local_receiver_alias_defined_after_access_does_not_match() -> None:
    idx = _make_index(
        imports=(_import("fakepkg"),),
        attributes=(_attribute("local_request", "args", line=20),),
        value_flow_edges=(
            _vf_assign_at(
                "fake.request",
                "local_request",
                line=30,
                containing_function_fqn="app.handler",
            ),
        ),
    )

    matches = ProviderEngine(providers=(FakeProvider,)).run(idx).matches

    assert matches == ()


def test_type_comment_local_receiver_alias_matches_method_descriptor(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """\
def handler():
    session = source()  # type: PublicSession
    session.commit()
"""
    )
    idx = _make_index(
        repo_root=tmp_path,
        imports=(_import("typedpkg"),),
        symbol_refs=(_symbol("PublicSession", "typedpkg.PublicSession"),),
        value_flow_edges=(
            _vf_assign_at(
                "source()",
                "session",
                line=2,
                containing_function_fqn="app.handler",
            ),
        ),
        call_edges=(_call("app.handler.<locals>.session.commit"),),
    )

    matches = ProviderEngine(providers=(TypedReceiverProvider,)).run(idx).matches

    assert [(match.phase, match.canonical_fqn) for match in matches] == [
        (ProviderPhase.EFFECTS, "typedpkg.impl.Session.commit"),
    ]


def test_annotated_local_receiver_alias_matches_method_descriptor(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        """\
def handler():
    session: PublicSession = source()
    session.commit()
"""
    )
    idx = _make_index(
        repo_root=tmp_path,
        imports=(_import("typedpkg"),),
        symbol_refs=(_symbol("PublicSession", "typedpkg.PublicSession"),),
        value_flow_edges=(
            ValueFlowEdge(
                source_expr="source()",
                source_location=SourceSpan(
                    file="app.py",
                    line=2,
                    column=29,
                    end_line=2,
                    end_column=37,
                ),
                target_expr="session",
                target_location=SourceSpan(
                    file="app.py",
                    line=2,
                    column=4,
                    end_line=2,
                    end_column=11,
                ),
                kind=FlowKind.ANNOTATED_ASSIGN,
                containing_function_fqn="app.handler",
                provenance=_PROV,
            ),
        ),
        call_edges=(_call("app.handler.<locals>.session.commit"),),
    )

    matches = ProviderEngine(providers=(TypedReceiverProvider,)).run(idx).matches

    assert [(match.phase, match.canonical_fqn) for match in matches] == [
        (ProviderPhase.EFFECTS, "typedpkg.impl.Session.commit"),
    ]


def test_instance_member_subscript_alias_matches_constructor_assignment() -> None:
    idx = _make_index(
        imports=(_import("instancefw"),),
        functions=(_function_record("app.handler"),),
        symbol_refs=(
            _symbol("App", "instancefw.App"),
            _symbol("app", "app.app"),
        ),
        value_flow_edges=(_vf_assign("App()", "app"),),
        attributes=(
            _attribute(
                "app.config",
                '"DEBUG"',
                is_write=True,
                access_kind=AccessKind.SUBSCRIPT,
            ),
        ),
    )

    matches = ProviderEngine(providers=(InstanceMemberSubscriptProvider,)).run(idx).matches

    assert [(match.phase, match.canonical_fqn) for match in matches] == [
        (ProviderPhase.EFFECTS, 'instancefw.App.config["DEBUG"]'),
    ]


def test_local_shadow_blocks_dotted_receiver_symbol_resolution() -> None:
    idx = _make_index(
        imports=(_import("instancefw"),),
        functions=(_function_record("app.handler"),),
        symbol_refs=(
            _symbol("App", "instancefw.App"),
            _symbol("app", "app.app"),
        ),
        value_flow_edges=(
            _vf_assign("App()", "app"),
            _vf_assign_at(
                "other_app()",
                "app",
                line=10,
                containing_function_fqn="app.handler",
            ),
        ),
        attributes=(
            _attribute(
                "app.config",
                '"DEBUG"',
                is_write=True,
                access_kind=AccessKind.SUBSCRIPT,
                line=20,
            ),
        ),
    )

    matches = ProviderEngine(providers=(InstanceMemberSubscriptProvider,)).run(idx).matches

    assert matches == ()


def test_dynamic_local_receiver_assignment_shadows_symbol_resolution() -> None:
    idx = _make_index(
        imports=(_import("fakepkg"),),
        attributes=(_attribute("request", "args", line=20),),
        symbol_refs=(_symbol("request", "fake.request"),),
        value_flow_edges=(
            _vf_assign_at(
                "make_request()",
                "request",
                line=10,
                containing_function_fqn="app.handler",
            ),
        ),
    )

    matches = ProviderEngine(providers=(FakeProvider,)).run(idx).matches

    assert matches == ()


def test_literal_string_when_predicates_filter_call_matches() -> None:
    idx = _make_index(
        imports=(_import("fakepkg"),),
        call_edges=(
            _call("fake.sql", args=(_arg(0, '"SELECT 1"'),)),
            _call("fake.sql", args=(_arg(0, '["admin@example.com"]'),)),
            _call("fake.sql", args=(_arg(0, "user_sql"),)),
        ),
    )

    matches = ProviderEngine(providers=(FakeProvider,)).run(idx).matches

    assert len(matches) == 1
    assert isinstance(matches[0].source_fact, CallEdge)
    assert matches[0].source_fact.arguments[0].expression == "user_sql"
    assert matches[0].predicate_status == PredicateStatus.PASSED


def test_type_check_when_predicates_create_unknown_match_with_gap() -> None:
    idx = _make_index(
        imports=(_import("typeslib"),),
        call_edges=(_call("types.Session.execute", args=(_arg(0, "stmt"),)),),
    )

    result = ProviderEngine(providers=(TypePredicateProvider,)).run(idx)

    assert len(result.matches) == 1
    assert result.matches[0].predicate_status == PredicateStatus.UNKNOWN
    assert result.matches[0].predicate_gaps[0].kind == GapKind.INFERENCE_FAILURE
    assert result.gaps == result.matches[0].predicate_gaps


def test_provider_hook_failure_becomes_gap_and_does_not_abort_execution() -> None:
    idx = _make_index(imports=(_import("hookfail"),))

    result = ProviderEngine(providers=(FailingHookProvider,)).run(idx)

    assert result.active_provider_ids == ("hook-fail",)
    assert result.matches == ()
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == GapKind.INTERPRETER_ERROR
    assert "route hook exploded" in result.gaps[0].message


# =====================================================================
# Router-group DSL tests (generic, no framework names)
# =====================================================================


class RouterGroupProvider(Provider):
    """Fake provider declaring router-group and mount patterns."""

    meta = ProviderMeta(
        id="routerfw",
        name="RouterFW",
        version="0.1.0",
        library="RouterFW",
        library_fqn="routerfw",
    )

    router_groups = (
        RouterGroupPattern(
            constructor_fqn="routerfw.Group",
            name_arg=0,
            prefix_kwarg="url_prefix",
        ),
    )

    routes = (RouteDecorator(fqn="routerfw.Group.route"),)

    router_group_mounts = (
        RouterGroupMountPattern(
            app_fqn="routerfw.App",
            mount_method="mount",
            group_arg=0,
            prefix_kwarg="url_prefix",
        ),
    )


class AltPrefixProvider(Provider):
    """Fake provider with a different prefix_kwarg name."""

    meta = ProviderMeta(
        id="altfw",
        name="AltFW",
        version="0.1.0",
        library="AltFW",
        library_fqn="altfw",
    )

    router_groups = (
        RouterGroupPattern(
            constructor_fqn="altfw.Router",
            name_arg=0,
            prefix_kwarg="prefix",
        ),
    )

    router_group_mounts = (
        RouterGroupMountPattern(
            app_fqn="altfw.App",
            mount_method="include",
            group_arg=0,
            prefix_kwarg="prefix",
        ),
    )


def _function_record(fqn: str, *, file: str = "app.py") -> FunctionRecord:
    from flawed._index._types import FunctionKind as L1FunctionKind
    from flawed._index._types import Parameter as L1Parameter
    from flawed._index._types import ParameterKind as L1ParameterKind

    return FunctionRecord(
        fqn=fqn,
        name=fqn.rsplit(".", 1)[-1],
        file=file,
        line=30,
        params=(
            L1Parameter(
                name="request",
                annotation=None,
                default=None,
                kind=L1ParameterKind.POSITIONAL_OR_KEYWORD,
                position=0,
                location=_SPAN,
            ),
        ),
        decorator_names=(),
        decorator_fqns=(),
        kind=L1FunctionKind.TOP_LEVEL,
        is_method=False,
        is_nested=False,
        is_async=False,
        parent_class=None,
        location=_SPAN,
        provenance=_PROV,
    )


def test_router_group_info_extracted_from_fake_provider_declarations() -> None:
    """RouterGroupPattern with constructor produces RouterGroupInfo."""
    idx = _make_index(
        imports=(_import("routerfw"),),
        symbol_refs=(_symbol("Group", "routerfw.Group"),),
        value_flow_edges=(
            _vf_assign(
                source_expr='Group("admin", __name__, url_prefix="/admin")',
                target_expr="grp",
            ),
        ),
        functions=(_function_record("app.handler"),),
    )

    result = ProviderEngine(providers=(RouterGroupProvider,)).run(idx)

    assert len(result.router_group_info) == 1
    info = result.router_group_info[0]
    assert info.group == "admin"
    assert info.url_prefix == "/admin"
    assert info.group_gaps == ()
    assert info.prefix_gaps == ()


def test_imported_router_group_receiver_matches_package_init_constructor(tmp_path: Path) -> None:
    """A route receiver imported from package __init__ resolves to its constructor type."""
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("from routerfw import Group\ngrp = Group('api')\n")
    (package / "routes.py").write_text(
        "from . import grp\n\n@grp.route('/items')\ndef items(): ...\n"
    )
    decorator_location = SourceSpan(
        file="pkg/routes.py",
        line=3,
        column=0,
        end_line=3,
        end_column=21,
    )
    idx = _make_index(
        repo_root=tmp_path,
        imports=(_import("routerfw"),),
        symbol_refs=(
            _symbol("Group", "routerfw.Group", file="pkg/__init__.py"),
            _symbol("grp.route", "pkg.grp.route", file="pkg/routes.py", line=3),
        ),
        value_flow_edges=(
            _vf_assign(
                source_expr='Group("api", url_prefix="/api")',
                target_expr="grp",
                file="pkg/__init__.py",
            ),
        ),
        decorators=(
            DecoratorFact(
                name="grp.route",
                fqn=".grp.route",
                args=('"/items"',),
                kwargs=(),
                target_fqn="pkg.routes.items",
                application_order=0,
                location=decorator_location,
                provenance=_PROV,
            ),
        ),
        functions=(_function_record("pkg.routes.items", file="pkg/routes.py"),),
    )

    result = ProviderEngine(providers=(RouterGroupProvider,)).run(idx)

    route_matches = [match for match in result.matches if match.phase is ProviderPhase.ROUTES]
    assert [(match.observed_fqn, match.canonical_fqn) for match in route_matches] == [
        ("pkg.grp.route", "routerfw.Group.route"),
    ]
    assert len(result.router_group_info) == 1
    info = result.router_group_info[0]
    assert info.variable_fqn == "pkg.grp"
    assert info.group == "api"
    assert info.url_prefix == "/api"


def test_router_group_mount_overrides_constructor_prefix() -> None:
    """Mount call with prefix kwarg overrides the constructor prefix."""
    idx = _make_index(
        imports=(_import("routerfw"),),
        symbol_refs=(
            _symbol("Group", "routerfw.Group"),
            _symbol("App", "routerfw.App"),
        ),
        value_flow_edges=(
            _vf_assign(
                source_expr='Group("api", __name__, url_prefix="/old")',
                target_expr="grp",
            ),
            _vf_assign(
                source_expr="App(__name__)",
                target_expr="app",
            ),
        ),
        call_edges=(
            CallEdge(
                caller_fqn="app",
                callee_fqn="app.app.mount",
                arguments=(
                    _arg(0, "grp"),
                    _kwarg("url_prefix", '"/api/v1"'),
                ),
                resolution=ResolutionStatus.RESOLVED,
                source=EdgeSource.AST,
                unresolved_reason=None,
                location=_SPAN,
                provenance=_PROV,
                call_expression="app.mount(grp, url_prefix='/api/v1')",
            ),
        ),
        functions=(_function_record("app.handler"),),
    )

    result = ProviderEngine(providers=(RouterGroupProvider,)).run(idx)

    assert len(result.router_group_info) == 1
    info = result.router_group_info[0]
    assert info.group == "api"
    assert info.url_prefix == "/api/v1"


def test_router_group_mount_with_different_prefix_kwarg() -> None:
    """RouterGroupMountPattern with prefix_kwarg='prefix' works."""
    idx = _make_index(
        imports=(_import("altfw"),),
        symbol_refs=(
            _symbol("Router", "altfw.Router"),
            _symbol("App", "altfw.App"),
        ),
        value_flow_edges=(
            _vf_assign(
                source_expr='Router("admin", prefix="/old")',
                target_expr="rtr",
            ),
            _vf_assign(
                source_expr="App()",
                target_expr="app",
            ),
        ),
        call_edges=(
            CallEdge(
                caller_fqn="app",
                callee_fqn="app.app.include",
                arguments=(
                    _arg(0, "rtr"),
                    _kwarg("prefix", '"/new"'),
                ),
                resolution=ResolutionStatus.RESOLVED,
                source=EdgeSource.AST,
                unresolved_reason=None,
                location=_SPAN,
                provenance=_PROV,
                call_expression="app.include(rtr, prefix='/new')",
            ),
        ),
        functions=(_function_record("app.handler"),),
    )

    result = ProviderEngine(providers=(AltPrefixProvider,)).run(idx)

    assert len(result.router_group_info) == 1
    info = result.router_group_info[0]
    assert info.group == "admin"
    assert info.url_prefix == "/new"


def test_router_group_dynamic_name_produces_gap() -> None:
    """Non-literal group name argument produces an inference gap."""
    idx = _make_index(
        imports=(_import("routerfw"),),
        symbol_refs=(_symbol("Group", "routerfw.Group"),),
        value_flow_edges=(
            _vf_assign(
                source_expr="Group(config.NAME, __name__)",
                target_expr="grp",
            ),
        ),
        functions=(_function_record("app.handler"),),
    )

    result = ProviderEngine(providers=(RouterGroupProvider,)).run(idx)

    assert len(result.router_group_info) == 1
    info = result.router_group_info[0]
    assert info.group is None
    assert len(info.group_gaps) == 1
    assert info.group_gaps[0].kind == GapKind.INFERENCE_FAILURE
    assert "dynamic name" in info.group_gaps[0].message.lower()


def test_router_group_no_mount_preserves_constructor_prefix() -> None:
    """Without a mount call, the constructor prefix is preserved."""
    idx = _make_index(
        imports=(_import("routerfw"),),
        symbol_refs=(_symbol("Group", "routerfw.Group"),),
        value_flow_edges=(
            _vf_assign(
                source_expr='Group("api", __name__, url_prefix="/api")',
                target_expr="grp",
            ),
        ),
        functions=(_function_record("app.handler"),),
    )

    result = ProviderEngine(providers=(RouterGroupProvider,)).run(idx)

    assert len(result.router_group_info) == 1
    info = result.router_group_info[0]
    assert info.group == "api"
    assert info.url_prefix == "/api"


def test_router_group_no_prefix_anywhere_yields_none() -> None:
    """Group with no prefix in constructor or mount yields None prefix."""
    idx = _make_index(
        imports=(_import("routerfw"),),
        symbol_refs=(_symbol("Group", "routerfw.Group"),),
        value_flow_edges=(
            _vf_assign(
                source_expr='Group("public", __name__)',
                target_expr="grp",
            ),
        ),
        functions=(_function_record("app.handler"),),
    )

    result = ProviderEngine(providers=(RouterGroupProvider,)).run(idx)

    assert len(result.router_group_info) == 1
    info = result.router_group_info[0]
    assert info.group == "public"
    assert info.url_prefix is None
    assert info.prefix_gaps == ()


def test_router_group_dynamic_prefix_produces_gap() -> None:
    """Non-literal prefix in constructor produces an inference gap."""
    idx = _make_index(
        imports=(_import("routerfw"),),
        symbol_refs=(_symbol("Group", "routerfw.Group"),),
        value_flow_edges=(
            _vf_assign(
                source_expr='Group("api", __name__, url_prefix=config.PREFIX)',
                target_expr="grp",
            ),
        ),
        functions=(_function_record("app.handler"),),
    )

    result = ProviderEngine(providers=(RouterGroupProvider,)).run(idx)

    assert len(result.router_group_info) == 1
    info = result.router_group_info[0]
    assert info.group == "api"
    assert info.url_prefix is None
    assert len(info.prefix_gaps) == 1
    assert info.prefix_gaps[0].kind == GapKind.INFERENCE_FAILURE


# =====================================================================
# ClassViewPattern — fake-provider generic class-view matching
# =====================================================================


class ClassViewFakeProvider(Provider):
    """Fake provider declaring a ClassViewPattern with fictional FQNs."""

    meta = ProviderMeta(
        id="classview-fake",
        name="ClassView Fake",
        version="0.1.0",
        library="ClassView Fake",
        library_fqn="fakeview",
    )

    routes = (
        ClassViewPattern(
            base_class_fqn="fakeview.BaseView",
            method_map={"get": "GET", "post": "POST"},
            as_view_method="as_factory",
        ),
    )


def _class_record(
    fqn: str,
    *,
    bases: tuple[str, ...] = (),
    method_names: tuple[str, ...] = (),
    file: str = "app.py",
    line: int = 10,
) -> ClassRecord:
    loc = SourceSpan(file=file, line=line, column=0, end_line=line, end_column=10)
    return ClassRecord(
        fqn=fqn,
        name=fqn.rsplit(".", 1)[-1],
        file=file,
        bases=bases,
        mro_chain=(),
        mro_complete=False,
        method_names=method_names,
        class_var_names=(),
        is_abstract=False,
        metaclass=None,
        subclasses=(),
        all_subclasses=(),
        inherited_methods=(),
        hierarchy_gaps=(),
        location=loc,
        provenance=_PROV,
    )


def test_class_view_fake_provider_matches_subclass_by_base_fqn() -> None:
    """ClassViewPattern matches a class whose base resolves to the declared FQN."""
    idx = _make_index(
        imports=(_import("fakeview"),),
        symbol_refs=(_symbol("BaseView", "fakeview.BaseView"),),
        classes=(
            _class_record(
                "app.MyView",
                bases=("BaseView",),
                method_names=("get", "post"),
            ),
        ),
        functions=(_function_record("app.handler"),),
    )

    result = ProviderEngine(providers=(ClassViewFakeProvider,)).run(idx)

    route_matches = [m for m in result.matches if m.phase is ProviderPhase.ROUTES]
    assert len(route_matches) == 1
    match = route_matches[0]
    assert match.observed_fqn == "app.MyView"
    assert isinstance(match.descriptor, ClassViewPattern)
    assert match.provider_id == "classview-fake"


def test_class_view_fake_provider_ignores_unrelated_class() -> None:
    """ClassViewPattern does not match a class that does not extend the base."""
    idx = _make_index(
        imports=(_import("fakeview"),),
        symbol_refs=(_symbol("BaseView", "fakeview.BaseView"),),
        classes=(
            _class_record(
                "app.Unrelated",
                bases=("object",),
                method_names=("get",),
            ),
        ),
        functions=(_function_record("app.handler"),),
    )

    result = ProviderEngine(providers=(ClassViewFakeProvider,)).run(idx)

    route_matches = [m for m in result.matches if m.phase is ProviderPhase.ROUTES]
    assert route_matches == []


def test_middleware_class_pattern_matches_subclass_by_base_fqn() -> None:
    idx = _make_index(
        imports=(_import("classlife"),),
        classes=(
            _class_record(
                "app.AuthMiddleware",
                bases=("classlife.BaseMiddleware",),
                method_names=("before",),
            ),
        ),
    )

    matches = ProviderEngine(providers=(ClassLifecycleProvider,)).run(idx).matches

    assert len(matches) == 1
    assert matches[0].phase == ProviderPhase.LIFECYCLE
    assert matches[0].descriptor == ClassLifecycleProvider.lifecycle[0]
    assert matches[0].observed_fqn == "app.AuthMiddleware"
    assert isinstance(matches[0].source_fact, (DecoratorFact, SymbolRef))
    assert matches[0].source_fact.fqn == "app.AuthMiddleware"


# =====================================================================
# ImperativeRoutePattern matching
# =====================================================================


class ImperativeRouteFakeProvider(Provider):
    meta = ProviderMeta(
        id="imp-route",
        name="Imperative Route Fake",
        library="impfw",
        library_fqn="impfw",
    )

    fqn_aliases: ClassVar[dict[str, str]] = {}

    routes = (
        ImperativeRoutePattern(
            entry_fqn="impfw.routing.Route",
            rule_arg=0,
            view_arg=1,
            view_kwarg="endpoint",
            methods_kwarg="methods",
            nested_fqn="impfw.routing.Mount",
        ),
    )


def test_imperative_route_pattern_matches_constructor_in_list_assignment() -> None:
    """Module-level list containing Route(...) constructors produces matches."""
    idx = _make_index(
        imports=(_import("impfw"),),
        symbol_refs=(_symbol("Route", "impfw.routing.Route"),),
        value_flow_edges=(
            _vf_assign(
                source_expr='[Route("/users", list_users), Route("/items", list_items)]',
                target_expr="routes",
            ),
        ),
        functions=(_function_record("app.handler"),),
    )

    result = ProviderEngine(providers=(ImperativeRouteFakeProvider,)).run(idx)

    route_matches = [m for m in result.matches if m.phase is ProviderPhase.ROUTES]
    assert len(route_matches) == 2
    assert all(isinstance(m.descriptor, ImperativeRoutePattern) for m in route_matches)
    # Source facts carry the constructor call expressions.
    names = {
        m.source_fact.name
        for m in route_matches
        if isinstance(m.source_fact, (DecoratorFact, SymbolRef))
    }
    assert "Route('/users', list_users)" in names
    assert "Route('/items', list_items)" in names


def test_imperative_route_pattern_matches_single_assignment() -> None:
    """A bare Route(...) assignment (not in a list) still produces a match."""
    idx = _make_index(
        imports=(_import("impfw"),),
        symbol_refs=(_symbol("Route", "impfw.routing.Route"),),
        value_flow_edges=(
            _vf_assign(
                source_expr='Route("/home", home_handler)',
                target_expr="route",
            ),
        ),
        functions=(_function_record("app.handler"),),
    )

    result = ProviderEngine(providers=(ImperativeRouteFakeProvider,)).run(idx)

    route_matches = [m for m in result.matches if m.phase is ProviderPhase.ROUTES]
    assert len(route_matches) == 1
    assert isinstance(route_matches[0].source_fact, (DecoratorFact, SymbolRef))
    assert route_matches[0].source_fact.name == "Route('/home', home_handler)"


def test_imperative_route_pattern_ignores_function_scoped_assignments() -> None:
    """Value-flow edges inside functions are NOT module-level routes."""
    idx = _make_index(
        imports=(_import("impfw"),),
        symbol_refs=(_symbol("Route", "impfw.routing.Route"),),
        value_flow_edges=(
            _vf_assign_at(
                source_expr='Route("/local", handler)',
                target_expr="r",
                containing_function_fqn="app.setup",
            ),
        ),
        functions=(_function_record("app.handler"),),
    )

    result = ProviderEngine(providers=(ImperativeRouteFakeProvider,)).run(idx)

    route_matches = [m for m in result.matches if m.phase is ProviderPhase.ROUTES]
    assert route_matches == []


def test_imperative_route_pattern_nested_fqn_produces_match_with_nested_fqn() -> None:
    """Mount(...) entries matching nested_fqn also produce matches."""
    idx = _make_index(
        imports=(_import("impfw"),),
        symbol_refs=(
            _symbol("Route", "impfw.routing.Route"),
            _symbol("Mount", "impfw.routing.Mount"),
        ),
        value_flow_edges=(
            _vf_assign(
                source_expr=(
                    '[Route("/a", handler_a), Mount("/api", routes=[Route("/b", handler_b)])]'
                ),
                target_expr="routes",
            ),
        ),
        functions=(_function_record("app.handler"),),
    )

    result = ProviderEngine(providers=(ImperativeRouteFakeProvider,)).run(idx)

    route_matches = [m for m in result.matches if m.phase is ProviderPhase.ROUTES]
    # Should match the Route entry and the Mount entry.
    assert len(route_matches) >= 2
    fqns = {m.canonical_fqn for m in route_matches}
    assert "impfw.routing.Route" in fqns
    assert "impfw.routing.Mount" in fqns


# =====================================================================
# Provider alias-based activation
# =====================================================================


class AliasedProvider(Provider):
    """Provider that should activate when a forked library is imported."""

    meta = ProviderMeta(
        id="aliased",
        name="Aliased",
        version="0.1.0",
        library="original_lib",
        library_fqn="original_lib",
    )

    fqn_aliases: ClassVar[dict[str, str]] = {
        "forked_lib": "original_lib",
        "forked_lib.submod": "original_lib",
    }


def test_provider_activates_on_alias_import():
    """Provider activates when a forked library (alias source) is imported."""
    assert _provider_is_imported(
        AliasedProvider,
        ("forked_lib",),
    )


def test_provider_activates_on_alias_submodule_import():
    """Provider activates when a submodule of the fork is imported."""
    assert _provider_is_imported(
        AliasedProvider,
        ("forked_lib.views",),
    )


def test_provider_activates_on_canonical_import():
    """Provider still activates on the canonical library name."""
    assert _provider_is_imported(
        AliasedProvider,
        ("original_lib",),
    )


def test_provider_does_not_activate_on_unrelated_import():
    """Provider does not activate on unrelated modules."""
    assert not _provider_is_imported(
        AliasedProvider,
        ("some_other_lib",),
    )


class WrapperActivatedProvider(Provider):
    """Provider that also activates on a wrapper/re-export library (FLAW-190)."""

    meta = ProviderMeta(
        id="wrapped",
        name="Wrapped",
        version="0.1.0",
        library="core_lib",
        library_fqn="core_lib",
        activation_imports=("wrapper_lib",),
    )


def test_provider_activates_on_activation_import():
    """Provider activates when a declared wrapper library is imported."""
    assert _provider_is_imported(
        WrapperActivatedProvider,
        ("wrapper_lib",),
    )


def test_provider_activates_on_activation_import_submodule():
    """Provider activates on a submodule of a declared wrapper library."""
    assert _provider_is_imported(
        WrapperActivatedProvider,
        ("wrapper_lib.extension",),
    )


def test_provider_with_activation_imports_still_activates_on_canonical():
    """activation_imports does not displace the canonical library_fqn trigger."""
    assert _provider_is_imported(
        WrapperActivatedProvider,
        ("core_lib",),
    )


def test_provider_with_activation_imports_ignores_unrelated():
    """activation_imports does not over-activate on unrelated modules."""
    assert not _provider_is_imported(
        WrapperActivatedProvider,
        ("some_other_lib",),
    )


def test_sqlalchemy_provider_activates_on_flask_sqlalchemy_import():
    """FLAW-190: the real SQLAlchemy provider fires on flask_sqlalchemy alone."""
    from flawed._semantic.providers.sqlalchemy_orm import SQLAlchemyProvider

    assert _provider_is_imported(SQLAlchemyProvider, ("flask_sqlalchemy",))
    assert not _provider_is_imported(SQLAlchemyProvider, ("flask",))
