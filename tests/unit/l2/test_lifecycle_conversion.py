"""Tests for provider lifecycle conversion."""

from __future__ import annotations

from flawed._index._types import (
    CallArgument,
    CallEdge,
    EdgeSource,
    ExtractionProvenance,
    ResolutionStatus,
    SourceSpan,
    SymbolRef,
)
from flawed._semantic._collections import ConcreteDecoratorCollection, ConcreteFunctionCollection
from flawed._semantic._enriched import EnrichedFunction
from flawed._semantic._lifecycle_conversion import convert_lifecycle_match
from flawed._semantic._provider_engine import ProviderMatch, ProviderPhase, RouterGroupInfo
from flawed._semantic.providers import (
    CheckRegistrationPattern,
    HookType,
    LifecycleRegistrationPattern,
    MiddlewareClassPattern,
)
from flawed.core import GapKind, Location, Provenance
from flawed.function import FunctionKind

_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="")
_SPAN = SourceSpan(file="middleware.py", line=10, column=0, end_line=20, end_column=0)


def test_middleware_class_match_converts_declared_hook_methods() -> None:
    pattern = MiddlewareClassPattern(
        base_class_fqn="generic.BaseMiddleware",
        method_hooks={
            "before": HookType.BEFORE_HANDLER,
            "after": HookType.AFTER_HANDLER,
        },
    )
    match = _middleware_match(pattern, "app.AuthMiddleware")
    before = _function("app.AuthMiddleware.before", name="before")
    after = _function("app.AuthMiddleware.after", name="after")

    result = convert_lifecycle_match(
        match,
        {before.fqn: before, after.fqn: after},
        {},
    )

    assert result.gaps == ()
    assert [(hook.handler.fqn, hook.hook_type) for hook in result.hooks] == [
        ("app.AuthMiddleware.before", HookType.BEFORE_HANDLER),
        ("app.AuthMiddleware.after", HookType.AFTER_HANDLER),
    ]
    assert all(hook.scope == "global" for hook in result.hooks)


def test_middleware_class_match_with_no_modeled_methods_records_gap() -> None:
    pattern = MiddlewareClassPattern(
        base_class_fqn="generic.BaseMiddleware",
        method_hooks={"before": HookType.BEFORE_HANDLER},
    )
    match = _middleware_match(pattern, "app.AuthMiddleware")

    result = convert_lifecycle_match(match, {}, {})

    assert result.hooks == ()
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == GapKind.INFERENCE_FAILURE
    assert result.gaps[0].affected_function == "app.AuthMiddleware"
    assert "no modeled hook methods" in result.gaps[0].message


def test_lifecycle_registration_match_records_explicit_gap() -> None:
    pattern = LifecycleRegistrationPattern(
        registration_fqn="ext.Extension.init_app",
        hook_type=HookType.BEFORE_HANDLER,
    )
    match = _registration_match(pattern, "ext.Extension.init_app")

    result = convert_lifecycle_match(match, {}, {})

    assert result.hooks == ()
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == GapKind.INFERENCE_FAILURE
    assert result.gaps[0].affected_function == "app.configure"
    assert "ext.Extension.init_app" in result.gaps[0].message


def test_lifecycle_registration_with_check_category_produces_implicit_check() -> None:
    """Registration with check_category produces an ImplicitCheck alongside the gap."""
    pattern = LifecycleRegistrationPattern(
        registration_fqn="flask_wtf.csrf.CSRFProtect.init_app",
        hook_type=HookType.BEFORE_HANDLER,
        check_category="CSRF",
    )
    match = _registration_match(pattern, "flask_wtf.csrf.CSRFProtect.init_app")

    result = convert_lifecycle_match(match, {}, {})

    # Still produces the gap (no user-code handler)
    assert result.hooks == ()
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == GapKind.INFERENCE_FAILURE

    # But also produces the implicit check
    assert len(result.implicit_checks) == 1
    check = result.implicit_checks[0]
    assert check.category == "CSRF"
    assert check.hook_type == HookType.BEFORE_HANDLER
    assert check.provider_id == "generic"
    assert "CSRFProtect.init_app" in check.expression


def test_lifecycle_registration_without_check_category_produces_no_implicit_check() -> None:
    """Registration without check_category produces only a gap, no implicit check."""
    pattern = LifecycleRegistrationPattern(
        registration_fqn="ext.Extension.init_app",
        hook_type=HookType.BEFORE_HANDLER,
    )
    match = _registration_match(pattern, "ext.Extension.init_app")

    result = convert_lifecycle_match(match, {}, {})

    assert result.hooks == ()
    assert result.implicit_checks == ()
    assert len(result.gaps) == 1


def test_check_registration_pattern_produces_group_scoped_implicit_check() -> None:
    pattern = CheckRegistrationPattern(
        registration_fqn="ext.Limiter.limit",
        hook_type=HookType.BEFORE_HANDLER,
        check_category="RATE_LIMITING",
        target_arg=0,
        target_kind="router_group",
    )
    match = _registration_match(pattern, "app.limiter.limit", arguments=(_arg(0, "auth"),))
    group = RouterGroupInfo(
        variable_fqn="app.auth",
        constructor_fqn="web.Blueprint",
        group="auth",
        url_prefix="/auth",
    )

    result = convert_lifecycle_match(match, {}, {group.variable_fqn: group})

    assert result.gaps == ()
    assert result.hooks == ()
    assert len(result.implicit_checks) == 1
    check = result.implicit_checks[0]
    assert check.category == "RATE_LIMITING"
    assert check.scope == "group"
    assert check.group == "auth"
    assert check.router_group_variable_fqn == "app.auth"
    assert check.provider_id == "generic"
    assert check.expression == "app.limiter.limit()"


def test_check_registration_unknown_group_target_records_gap() -> None:
    pattern = CheckRegistrationPattern(
        registration_fqn="ext.Limiter.limit",
        hook_type=HookType.BEFORE_HANDLER,
        check_category="RATE_LIMITING",
        target_arg=0,
        target_kind="router_group",
    )
    match = _registration_match(pattern, "app.limiter.limit", arguments=(_arg(0, "unknown"),))

    result = convert_lifecycle_match(match, {}, {})

    assert result.implicit_checks == ()
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == GapKind.SYMBOL_UNRESOLVED
    assert "unknown" in result.gaps[0].message
    assert result.gaps[0].origin_provider == "generic"


def test_check_registration_ambiguous_group_target_records_gap() -> None:
    pattern = CheckRegistrationPattern(
        registration_fqn="ext.Limiter.limit",
        hook_type=HookType.BEFORE_HANDLER,
        check_category="RATE_LIMITING",
        target_arg=0,
        target_kind="router_group",
    )
    match = _registration_match(pattern, "limiter.limit", arguments=(_arg(0, "auth"),))
    groups = {
        "pkg.one.auth": RouterGroupInfo(
            variable_fqn="pkg.one.auth",
            constructor_fqn="web.Blueprint",
            group="auth",
            url_prefix="/one",
        ),
        "pkg.two.auth": RouterGroupInfo(
            variable_fqn="pkg.two.auth",
            constructor_fqn="web.Blueprint",
            group="auth",
            url_prefix="/two",
        ),
    }

    result = convert_lifecycle_match(match, {}, groups)

    assert result.implicit_checks == ()
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == GapKind.INFERENCE_FAILURE
    assert "Ambiguous router-group check target auth" in result.gaps[0].message


def _middleware_match(pattern: MiddlewareClassPattern, class_fqn: str) -> ProviderMatch:
    return ProviderMatch(
        provider_id="generic",
        phase=ProviderPhase.LIFECYCLE,
        descriptor=pattern,
        source_fact=SymbolRef(
            name=class_fqn.rsplit(".", 1)[-1],
            fqn=class_fqn,
            resolution=ResolutionStatus.RESOLVED,
            location=_SPAN,
            provenance=_PROV,
        ),
        observed_fqn=class_fqn,
        canonical_fqn=class_fqn,
        location=_SPAN,
    )


def _registration_match(
    pattern: LifecycleRegistrationPattern | CheckRegistrationPattern,
    registration_fqn: str,
    *,
    arguments: tuple[CallArgument, ...] = (),
) -> ProviderMatch:
    return ProviderMatch(
        provider_id="generic",
        phase=ProviderPhase.LIFECYCLE,
        descriptor=pattern,
        source_fact=CallEdge(
            caller_fqn="app.configure",
            callee_fqn=registration_fqn,
            arguments=arguments,
            resolution=ResolutionStatus.RESOLVED,
            source=EdgeSource.AST,
            unresolved_reason=None,
            location=_SPAN,
            provenance=_PROV,
            call_expression=f"{registration_fqn}()",
        ),
        observed_fqn=registration_fqn,
        canonical_fqn=registration_fqn,
        location=_SPAN,
    )


def _arg(position: int, expression: str) -> CallArgument:
    return CallArgument(position=position, keyword=None, expression=expression, location=_SPAN)


def _function(fqn: str, *, name: str) -> EnrichedFunction:
    fn = EnrichedFunction(
        fqn=fqn,
        name=name,
        params=(),
        kind=FunctionKind.METHOD,
        parent_class=fqn.rsplit(".", 1)[0],
        parent_function=None,
        location=Location(file="middleware.py", line=12, column=4, end_line=14, end_column=0),
        provenance=Provenance(source_layer="L2", interpreter="test", confidence=1.0),
    )
    object.__setattr__(fn, "_decorators", ConcreteDecoratorCollection(()))
    object.__setattr__(fn, "_gaps", ())
    object.__setattr__(fn, "_calls", ConcreteFunctionCollection(()))
    object.__setattr__(fn, "_called_by", ConcreteFunctionCollection(()))
    return fn
