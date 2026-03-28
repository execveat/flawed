"""Provider-driven state effect conversion tests."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from flawed._index import CodeIndex
from flawed._index._types import (
    AccessKind,
    AttributeAccess,
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
from flawed._index._types import FunctionKind as L1FunctionKind
from flawed._semantic import WebApp
from flawed._semantic._provider_engine import ProviderEngine
from flawed._semantic.providers import (
    EffectAttributePattern,
    EffectCallPattern,
    EffectSubscriptPattern,
    Provider,
    ProviderMeta,
    RouteDecorator,
    StateProxyPattern,
)
from flawed.effects import EffectCategory, State, StateScope

if TYPE_CHECKING:
    from flawed.repo import RepoView
    from flawed.route import Route

_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="")
_ROOT = Path("/tmp/test-repo")


class StateEffectProvider(Provider):
    """Fake provider declaring state effects with fictional FQNs."""

    meta = ProviderMeta(
        id="statefx",
        name="StateFX",
        version="0.1.0",
        library="StateFX",
        library_fqn="statefx",
    )

    fqn_aliases: ClassVar[dict[str, str]] = {
        "statefx.local": "statefx",
    }

    routes = (RouteDecorator(fqn="statefx.App.route"),)
    effects = (
        EffectCallPattern(
            fqn="statefx.login",
            category="STATE_WRITE",
            scope="SESSION",
            keys=("actor_id", "fresh"),
        ),
        EffectAttributePattern(
            receiver_fqn="statefx.request_state",
            category="STATE_READ",
            scope="REQUEST",
        ),
        EffectAttributePattern(
            receiver_fqn="statefx.request_state",
            category="STATE_WRITE",
            scope="REQUEST",
        ),
        EffectSubscriptPattern(
            receiver_fqn="statefx.session_state",
            category="STATE_READ",
            scope="SESSION",
        ),
        EffectSubscriptPattern(
            receiver_fqn="statefx.session_state",
            category="STATE_WRITE",
            scope="SESSION",
        ),
    )
    proxies = (
        StateProxyPattern(
            fqn="statefx.current_actor",
            resolves_to="statefx.request_state.actor",
            scope="REQUEST",
        ),
    )


def test_fake_provider_request_state_attribute_write_becomes_state_effect() -> None:
    idx = _make_index(
        attributes=(
            _attribute(
                "statefx.request_state",
                "actor",
                is_write=True,
                value_expr="actor",
                line=21,
            ),
        ),
    )

    effect = _only_route(idx).body.effects(State.write(scope=StateScope.REQUEST)).one()

    assert effect.category is EffectCategory.STATE_WRITE
    assert effect.scope is StateScope.REQUEST
    assert effect.key == "actor"
    assert effect.expression == "statefx.request_state.actor"
    assert effect.function.fqn == "app.handler"


def test_fake_provider_session_subscript_read_and_write_filter_by_key() -> None:
    idx = _make_index(
        attributes=(
            _attribute(
                "statefx.session_state",
                '"actor_id"',
                access_kind=AccessKind.SUBSCRIPT,
                line=21,
            ),
            _attribute(
                "statefx.session_state",
                '"actor_id"',
                access_kind=AccessKind.SUBSCRIPT,
                is_write=True,
                value_expr="actor.id",
                line=22,
            ),
        ),
    )
    route = _only_route(idx)

    read = route.body.effects(State.read(scope=StateScope.SESSION, key="actor_id")).one()
    write = route.body.effects(State.write(scope=StateScope.SESSION, key="actor_id")).one()

    assert read.category is EffectCategory.STATE_READ
    assert read.key == "actor_id"
    assert read.expression == 'statefx.session_state["actor_id"]'
    assert write.category is EffectCategory.STATE_WRITE
    assert write.key == "actor_id"
    assert tuple(route.body.effects(State.write(scope=StateScope.SESSION, key="missing"))) == ()


def test_fake_provider_state_proxy_usage_becomes_request_state_read() -> None:
    idx = _make_index(
        attributes=(_attribute("actor", "id", line=21),),
        symbols=(_symbol("actor", "statefx.current_actor", line=21),),
    )

    effect = _only_route(idx).body.effects(State.read(scope=StateScope.REQUEST)).one()

    assert effect.category is EffectCategory.STATE_READ
    assert effect.scope is StateScope.REQUEST
    assert effect.key == "actor"
    assert effect.expression == "actor.id"


def test_fake_provider_dynamic_subscript_key_stays_wildcard_only() -> None:
    idx = _make_index(
        attributes=(
            _attribute(
                "statefx.session_state",
                "dynamic_key",
                access_kind=AccessKind.SUBSCRIPT,
                line=21,
            ),
        ),
    )
    route = _only_route(idx)

    effect = route.body.effects(State.read(scope=StateScope.SESSION)).one()

    assert effect.key is None
    assert effect.expression == "statefx.session_state[dynamic_key]"
    assert tuple(route.body.effects(State.read(scope=StateScope.SESSION, key="dynamic_key"))) == ()


def test_fake_provider_state_call_expands_declared_keys() -> None:
    idx = _make_index(
        attributes=(),
        call_edges=(_call("statefx.login", expression="statefx.login(actor)", line=21),),
    )

    effects = tuple(_only_route(idx).body.effects(State.write(scope=StateScope.SESSION)))

    assert [(effect.key, effect.expression) for effect in effects] == [
        ("actor_id", "statefx.login(actor)"),
        ("fresh", "statefx.login(actor)"),
    ]


def test_module_level_subscript_write_becomes_server_state_effect() -> None:
    idx = _make_index(
        attributes=(
            _attribute(
                "FEATURE_FLAGS",
                '"enabled"',
                access_kind=AccessKind.SUBSCRIPT,
                is_write=True,
                value_expr="enabled",
                line=21,
            ),
        ),
        value_flow_edges=(_module_state_edge("FEATURE_FLAGS"),),
    )

    effect = _only_route(idx).body.effects(State.write(scope=StateScope.SERVER)).one()

    assert effect.category is EffectCategory.STATE_WRITE
    assert effect.scope is StateScope.SERVER
    assert effect.key == "enabled"
    assert effect.expression == 'FEATURE_FLAGS["enabled"]'


def test_alias_to_module_level_container_becomes_server_state_effect() -> None:
    idx = _make_index(
        attributes=(
            _attribute(
                "flags",
                '"enabled"',
                access_kind=AccessKind.SUBSCRIPT,
                is_write=True,
                value_expr="enabled",
                line=22,
            ),
        ),
        value_flow_edges=(
            _module_state_edge("FEATURE_FLAGS"),
            _flow_edge("FEATURE_FLAGS", "flags", line=21),
        ),
    )

    effect = _only_route(idx).body.effects(State.write(scope=StateScope.SERVER)).one()

    assert effect.scope is StateScope.SERVER
    assert effect.key == "enabled"
    assert effect.expression == 'flags["enabled"]'


def test_class_attribute_write_becomes_server_state_effect() -> None:
    idx = _make_index(
        classes=(_class("FeatureFlags"),),
        attributes=(
            _attribute(
                "FeatureFlags",
                "enabled",
                is_write=True,
                value_expr="enabled",
                line=21,
            ),
        ),
    )

    effect = _only_route(idx).body.effects(State.write(scope=StateScope.SERVER)).one()

    assert effect.scope is StateScope.SERVER
    assert effect.key == "enabled"
    assert effect.expression == "FeatureFlags.enabled"


def test_alias_to_class_object_becomes_server_state_effect() -> None:
    idx = _make_index(
        classes=(_class("FeatureFlags"),),
        attributes=(
            _attribute(
                "flags",
                "enabled",
                is_write=True,
                value_expr="enabled",
                line=22,
            ),
        ),
        value_flow_edges=(_flow_edge("FeatureFlags", "flags", line=21),),
    )

    effect = _only_route(idx).body.effects(State.write(scope=StateScope.SERVER)).one()

    assert effect.scope is StateScope.SERVER
    assert effect.key == "enabled"
    assert effect.expression == "flags.enabled"


def test_local_container_subscript_write_is_not_server_state_effect() -> None:
    idx = _make_index(
        attributes=(
            _attribute(
                "flags",
                '"enabled"',
                access_kind=AccessKind.SUBSCRIPT,
                is_write=True,
                value_expr="enabled",
                line=22,
            ),
        ),
        value_flow_edges=(_flow_edge("{}", "flags", line=21),),
    )

    route = _only_route(idx)

    assert tuple(route.body.effects(State.write(scope=StateScope.SERVER))) == ()


def test_flask_g_attribute_write_becomes_request_state_write(flask_basic: RepoView) -> None:
    route = _route(flask_basic, "effect_state_write_attr")

    effect = route.body.effects(State.write(scope=StateScope.REQUEST, key="user")).one()

    assert effect.category is EffectCategory.STATE_WRITE
    assert effect.scope is StateScope.REQUEST
    assert effect.key == "user"
    assert effect.expression == "g.user"


def test_flask_session_subscript_reads_and_writes_become_session_state_effects(
    flask_basic: RepoView,
) -> None:
    write_route = _route(flask_basic, "effect_session_write")
    read_route = _route(flask_basic, "effect_session_read")

    writes = tuple(write_route.body.effects(State.write(scope=StateScope.SESSION)))
    read = read_route.body.effects(State.read(scope=StateScope.SESSION, key="user_id")).one()

    assert [(effect.key, effect.expression) for effect in writes] == [
        ("user_id", 'session["user_id"]'),
        ("role", 'session["role"]'),
    ]
    assert read.key == "user_id"
    assert read.expression == 'session["user_id"]'


def test_flask_login_current_user_proxy_becomes_request_state_read(flask_basic: RepoView) -> None:
    route = _route(flask_basic, "proxy_current_user")

    effect = route.body.effects(State.read(scope=StateScope.REQUEST, key="_login_user")).one()

    assert effect.category is EffectCategory.STATE_READ
    assert effect.scope is StateScope.REQUEST
    assert effect.expression == "current_user.name"


def test_flask_login_state_call_declares_session_keys(flask_basic: RepoView) -> None:
    route = _route(flask_basic, "do_login")

    effects = tuple(route.body.effects(State.write(scope=StateScope.SESSION)))

    assert [(effect.key, effect.expression) for effect in effects] == [
        ("_user_id", "login_user(current_user)"),
        ("_fresh", "login_user(current_user)"),
        ("_id", "login_user(current_user)"),
        ("_remember", "login_user(current_user)"),
    ]


# -- Aliased state effect resolution tests --------------------------------


def test_aliased_attribute_write_resolves_via_value_flow() -> None:
    """Local alias `state = statefx.request_state` then `state.actor = x`."""
    idx = _make_index(
        attributes=(_attribute("state", "actor", is_write=True, value_expr="actor", line=21),),
        value_flow_edges=(_flow_edge("statefx.request_state", "state", line=20),),
    )

    effect = _only_route(idx).body.effects(State.write(scope=StateScope.REQUEST)).one()

    assert effect.category is EffectCategory.STATE_WRITE
    assert effect.scope is StateScope.REQUEST
    assert effect.key == "actor"
    assert effect.function.fqn == "app.handler"


def test_aliased_subscript_read_resolves_via_value_flow() -> None:
    """Local alias `store = statefx.session_state` then `store["user_id"]`."""
    idx = _make_index(
        attributes=(
            _attribute(
                "store",
                '"user_id"',
                access_kind=AccessKind.SUBSCRIPT,
                line=21,
            ),
        ),
        value_flow_edges=(_flow_edge("statefx.session_state", "store", line=20),),
    )

    effect = _only_route(idx).body.effects(State.read(scope=StateScope.SESSION)).one()

    assert effect.category is EffectCategory.STATE_READ
    assert effect.key == "user_id"
    assert effect.scope is StateScope.SESSION


def test_chained_alias_resolves_through_multi_hop() -> None:
    """Chained aliases a→b resolve through recursive local alias resolution."""
    idx = _make_index(
        attributes=(_attribute("b", "actor", is_write=True, value_expr="actor", line=22),),
        value_flow_edges=(
            _flow_edge("statefx.request_state", "a", line=20),
            _flow_edge("a", "b", line=21),
        ),
    )

    effect = _only_route(idx).body.effects(State.write(scope=StateScope.REQUEST)).one()

    assert effect.category is EffectCategory.STATE_WRITE
    assert effect.key == "actor"


def test_aliased_proxy_attribute_resolves_via_value_flow() -> None:
    """Local alias `user = actor` where actor is proxy, then `user.id`."""
    idx = _make_index(
        attributes=(_attribute("user", "id", line=21),),
        symbols=(_symbol("actor", "statefx.current_actor", line=20),),
        value_flow_edges=(_flow_edge("actor", "user", line=20),),
    )

    effect = _only_route(idx).body.effects(State.read(scope=StateScope.REQUEST)).one()

    assert effect.category is EffectCategory.STATE_READ
    assert effect.scope is StateScope.REQUEST
    assert effect.key == "actor"


def test_alias_from_different_function_does_not_leak() -> None:
    """Alias in app.other_fn must not affect state matching in app.handler."""
    idx = _make_index(
        attributes=(_attribute("state", "actor", is_write=True, value_expr="actor", line=21),),
        value_flow_edges=(
            _flow_edge(
                "statefx.request_state",
                "state",
                line=20,
                containing_function_fqn="app.other_fn",
            ),
        ),
    )

    effects = tuple(_only_route(idx).body.effects(State.write(scope=StateScope.REQUEST)))

    assert effects == ()


def test_flask_aliased_g_attribute_write_resolves_state_effect(flask_basic: RepoView) -> None:
    route = _route(flask_basic, "effect_state_write_aliased")

    effect = route.body.effects(State.write(scope=StateScope.REQUEST, key="user")).one()

    assert effect.category is EffectCategory.STATE_WRITE
    assert effect.scope is StateScope.REQUEST
    assert effect.key == "user"


def test_flask_aliased_session_subscript_read_resolves_state_effect(flask_basic: RepoView) -> None:
    route = _route(flask_basic, "effect_session_read_aliased")

    read = route.body.effects(State.read(scope=StateScope.SESSION, key="user_id")).one()

    assert read.category is EffectCategory.STATE_READ
    assert read.key == "user_id"


# -- Import-aliased state effect resolution tests (flask_aliased) ----------


def test_flask_aliased_import_g_attribute_write_resolves_state_effect(
    flask_aliased: RepoView,
) -> None:
    """Import alias: from flask import g as ctx → ctx.user STATE_WRITE."""
    route = _route(flask_aliased, "effect_state_attr")

    effect = route.body.effects(State.write(scope=StateScope.REQUEST, key="user")).one()

    assert effect.category is EffectCategory.STATE_WRITE
    assert effect.scope is StateScope.REQUEST
    assert effect.key == "user"


def test_flask_aliased_import_session_subscript_write_resolves_state_effect(
    flask_aliased: RepoView,
) -> None:
    """Import alias: from flask import session as sess → sess["user_id"] STATE_WRITE."""
    route = _route(flask_aliased, "effect_session_write")

    effect = route.body.effects(State.write(scope=StateScope.SESSION, key="user_id")).one()

    assert effect.category is EffectCategory.STATE_WRITE
    assert effect.scope is StateScope.SESSION
    assert effect.key == "user_id"


def test_flask_aliased_import_login_user_call_declares_session_keys(
    flask_aliased: RepoView,
) -> None:
    """Import alias: from flask_login import login_user as sign_in → session STATE_WRITE."""
    route = _route(flask_aliased, "do_login")

    effects = tuple(route.body.effects(State.write(scope=StateScope.SESSION)))

    assert len(effects) == 4
    assert all(e.category is EffectCategory.STATE_WRITE for e in effects)


def test_flask_aliased_import_proxy_resolves_state_read(flask_aliased: RepoView) -> None:
    """Import alias: from flask_login import current_user as me → me.name STATE_READ."""
    route = _route(flask_aliased, "proxy")

    effect = route.body.effects(State.read(scope=StateScope.REQUEST)).one()

    assert effect.category is EffectCategory.STATE_READ
    assert effect.scope is StateScope.REQUEST


def test_property_setter_constructor_assignment_becomes_request_state_write(
    flask_basic: RepoView,
) -> None:
    """Constructor ``self.<property> = ...`` invokes setter-side state writes."""
    route = flask_basic.routes.where(
        lambda route: route.endpoint == "gadget_auth_constructor_property_writes"
    ).one()

    writes = tuple(route.full_stack.effects(State.write(scope=StateScope.REQUEST)))
    keys = {write.key for write in writes}

    assert {"email", "user", "name", "balance"} <= keys
    assert any(
        write.function.fqn.endswith("PropertyBackedAuthBase.email")
        for write in writes
        if write.key == "email"
    )


def test_benign_constructor_instance_assignment_does_not_become_request_state_write(
    flask_basic: RepoView,
) -> None:
    """Plain instance writes without a property setter are not state effects."""
    route = flask_basic.routes.where(
        lambda route: route.endpoint == "gadget_benign_constructor_only"
    ).one()

    writes = route.full_stack.effects(State.write(scope=StateScope.REQUEST))

    assert not any(
        write.function.fqn.endswith("BenignProfileBuilder.__init__") for write in writes
    )


def _route(repo: RepoView, endpoint: str) -> Route:
    return repo.routes.where(lambda route: route.endpoint == endpoint).one()


def _only_route(idx: CodeIndex) -> Route:
    engine = ProviderEngine(providers=(StateEffectProvider,))
    return WebApp.from_index(idx, provider_engine=engine).repo_view().routes.one()


def _span(line: int, *, file: str = "app.py") -> SourceSpan:
    return SourceSpan(file=file, line=line, column=0, end_line=line, end_column=10)


def _function(fqn: str, *, line: int = 20) -> FunctionRecord:
    return FunctionRecord(
        fqn=fqn,
        name=fqn.rsplit(".", 1)[-1],
        file="app.py",
        line=line,
        params=(),
        decorator_names=(),
        decorator_fqns=(),
        kind=L1FunctionKind.TOP_LEVEL,
        is_method=False,
        is_nested=False,
        is_async=False,
        parent_class=None,
        location=_span(line),
        provenance=_PROV,
    )


def _decorator() -> DecoratorFact:
    return DecoratorFact(
        name="route",
        fqn="statefx.App.route",
        args=('"/state"',),
        kwargs=(),
        target_fqn="app.handler",
        application_order=0,
        location=_span(10),
        provenance=_PROV,
    )


def _attribute(
    target_expr: str,
    attr_name: str,
    *,
    access_kind: AccessKind = AccessKind.ATTR,
    is_write: bool = False,
    value_expr: str | None = None,
    line: int,
) -> AttributeAccess:
    return AttributeAccess(
        target_expr=target_expr,
        attr_name=attr_name,
        is_write=is_write,
        access_kind=access_kind,
        value_expr=value_expr,
        containing_function_fqn="app.handler",
        location=_span(line),
        provenance=_PROV,
    )


def _call(callee_fqn: str, *, expression: str, line: int) -> CallEdge:
    return CallEdge(
        caller_fqn="app.handler",
        callee_fqn=callee_fqn,
        arguments=(),
        resolution=ResolutionStatus.RESOLVED,
        source=EdgeSource.AST,
        unresolved_reason=None,
        location=_span(line),
        provenance=_PROV,
        call_expression=expression,
    )


def _symbol(name: str, fqn: str, *, line: int) -> SymbolRef:
    return SymbolRef(
        name=name,
        fqn=fqn,
        resolution=ResolutionStatus.RESOLVED,
        location=_span(line),
        provenance=_PROV,
    )


def _import(module: str) -> ImportFact:
    return ImportFact(
        module=module,
        names=(),
        aliases=(),
        is_from_import=False,
        location=_span(1),
        provenance=_PROV,
    )


def _class(name: str) -> ClassRecord:
    return ClassRecord(
        fqn=f"app.{name}",
        name=name,
        file="app.py",
        bases=("object",),
        mro_chain=(f"app.{name}", "object"),
        mro_complete=True,
        method_names=(),
        class_var_names=("enabled",),
        is_abstract=False,
        metaclass=None,
        subclasses=(),
        all_subclasses=(),
        inherited_methods=(),
        hierarchy_gaps=(),
        location=_span(5),
        provenance=_PROV,
    )


def _flow_edge(
    source_expr: str,
    target_expr: str,
    *,
    kind: FlowKind = FlowKind.ASSIGN,
    line: int,
    containing_function_fqn: str = "app.handler",
) -> ValueFlowEdge:
    return ValueFlowEdge(
        source_expr=source_expr,
        target_expr=target_expr,
        source_location=_span(line),
        target_location=_span(line),
        kind=kind,
        containing_function_fqn=containing_function_fqn,
        provenance=_PROV,
    )


def _module_state_edge(
    target_expr: str, *, source_expr: str = "{}", line: int = 5
) -> ValueFlowEdge:
    return ValueFlowEdge(
        source_expr=source_expr,
        source_location=_span(line),
        target_expr=target_expr,
        target_location=_span(line),
        kind=FlowKind.ASSIGN,
        containing_function_fqn=None,
        provenance=_PROV,
    )


def _make_index(
    *,
    attributes: tuple[AttributeAccess, ...],
    classes: tuple[ClassRecord, ...] = (),
    call_edges: tuple[CallEdge, ...] = (),
    symbols: tuple[SymbolRef, ...] = (),
    value_flow_edges: tuple[ValueFlowEdge, ...] = (),
) -> CodeIndex:
    return CodeIndex(
        repo_root=_ROOT,
        functions=(_function("app.handler"),),
        classes=classes,
        decorators=(_decorator(),),
        imports=(_import("statefx"),),
        attributes=attributes,
        call_edges=call_edges,
        cfgs={},
        value_flow_edges=value_flow_edges,
        symbol_refs=symbols,
        errors=(),
        provenance=_PROV,
    )
