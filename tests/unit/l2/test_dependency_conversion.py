"""Tests for dependency-injection conversion."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from flawed._index import CodeIndex
from flawed._index._types import (
    CallArgument,
    CallEdge,
    EdgeSource,
    ExtractionProvenance,
    FlowKind,
    FunctionRecord,
    Parameter,
    ParameterKind,
    ResolutionStatus,
    SourceSpan,
    SymbolRef,
    ValueFlowEdge,
)
from flawed._index._types import FunctionKind as L1FunctionKind
from flawed._semantic._conversion import convert_function
from flawed._semantic._dependency_conversion import convert_dependency_matches
from flawed._semantic._provider_engine import ProviderMatch, ProviderPhase
from flawed._semantic.providers import CheckKind, DependencyPattern, SecurityCheckPattern
from flawed.core import GapKind
from flawed.inputs import DependencyInput

if TYPE_CHECKING:
    from flawed.inputs import InputRead

_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="")
_ROOT = Path("/tmp/test-repo")


def _provider_fqn(read: InputRead) -> str | None:
    """Provider FQN of a dependency-injected read (asserts the source kind)."""
    assert isinstance(read.source, DependencyInput)
    return read.source.provider_fqn


def test_dependency_match_converts_input_and_lifecycle_edge() -> None:
    """Depends(dep) produces a DependencyInput and synthetic lifecycle edge."""
    handler_record = _function(
        "app.handler",
        params=(_param("db", default="Depends(get_db)", line=10),),
    )
    dependency_record = _function("app.get_db", line=20)
    idx = _index(
        functions=(handler_record, dependency_record),
        symbols=(_symbol("get_db", "app.get_db", line=10),),
    )
    handler = convert_function(handler_record)
    dependency = convert_function(dependency_record)
    match = _dependency_match(_call("app.handler", "fastapi.Depends", _arg(0, "get_db")))

    result = convert_dependency_matches(
        (match,),
        (match,),
        idx=idx,
        functions_by_fqn={handler.fqn: handler, dependency.fqn: dependency},
    )

    assert result.gaps == ()
    assert len(result.dispatch_edges) == 1
    assert result.dispatch_edges[0].caller_fqn == "app.handler"
    assert result.dispatch_edges[0].target.fqn == "app.get_db"
    read = result.reads_by_function["app.handler"][0]
    assert read.expression == "db"
    assert _provider_fqn(read) == "app.get_db"


def test_depends_chain_propagates_security_scheme_guard() -> None:
    """Depends(get_current_user) inherits guard from Depends(oauth2_scheme)."""
    handler_record = _function(
        "app.protected",
        params=(_param("user", default="Depends(get_current_user)", line=10),),
        line=10,
    )
    dependency_record = _function(
        "app.get_current_user",
        params=(_param("token", default="Depends(oauth2_scheme)", line=20),),
        line=20,
    )
    idx = _index(
        functions=(handler_record, dependency_record),
        symbols=(_symbol("get_current_user", "app.get_current_user", line=10),),
        value_flow_edges=(
            _vf(
                "OAuth2PasswordBearer(tokenUrl='token')",
                "oauth2_scheme",
                containing_function_fqn=None,
                line=2,
                column=16,
            ),
        ),
    )
    handler = convert_function(handler_record)
    dependency = convert_function(dependency_record)
    handler_depends = _dependency_match(
        _call("app.protected", "fastapi.Depends", _arg(0, "get_current_user"))
    )
    security_depends = _dependency_match(
        _call(
            "app.get_current_user",
            "fastapi.Depends",
            _arg(0, "oauth2_scheme", line=20),
            line=20,
        )
    )
    check = _check_match(
        _call("<module>", "fastapi.security.OAuth2PasswordBearer", line=2, column=16)
    )

    result = convert_dependency_matches(
        (handler_depends, security_depends),
        (handler_depends, security_depends, check),
        idx=idx,
        functions_by_fqn={handler.fqn: handler, dependency.fqn: dependency},
    )

    assert result.gaps == ()
    assert {edge.target.fqn for edge in result.dispatch_edges} == {"app.get_current_user"}
    assert _provider_fqn(result.reads_by_function["app.protected"][0]) == ("app.get_current_user")
    assert _provider_fqn(result.reads_by_function["app.get_current_user"][0]) == (
        "app.oauth2_scheme"
    )
    assert result.conditions_by_function["app.protected"][0].category == "AUTHENTICATION"
    assert result.conditions_by_function["app.get_current_user"][0].category == "AUTHENTICATION"


def test_security_scheme_dependency_produces_guard_without_callable_function() -> None:
    """Security(oauth2_scheme) is terminal guard input, not unresolved."""
    handler_record = _function(
        "app.secure",
        params=(_param("token", default="Security(oauth2_scheme)", line=10),),
    )
    idx = _index(
        functions=(handler_record,),
        value_flow_edges=(
            _vf(
                "OAuth2PasswordBearer(tokenUrl='token')",
                "oauth2_scheme",
                containing_function_fqn=None,
                line=2,
                column=16,
            ),
        ),
    )
    handler = convert_function(handler_record)
    dependency = _dependency_match(
        _call("app.secure", "fastapi.Security", _arg(0, "oauth2_scheme"))
    )
    check = _check_match(
        _call("<module>", "fastapi.security.OAuth2PasswordBearer", line=2, column=16)
    )

    result = convert_dependency_matches(
        (dependency,),
        (dependency, check),
        idx=idx,
        functions_by_fqn={handler.fqn: handler},
    )

    assert result.gaps == ()
    assert result.dispatch_edges == ()
    read = result.reads_by_function["app.secure"][0]
    assert _provider_fqn(read) == "app.oauth2_scheme"
    condition = result.conditions_by_function["app.secure"][0]
    assert condition.category == "AUTHENTICATION"
    assert condition.guard is not None


def test_unresolved_dependency_callable_produces_gap() -> None:
    """Unknown dependency callable is an AnalysisGap, not a silent miss."""
    handler_record = _function(
        "app.handler",
        params=(_param("value", default="Depends(missing)", line=10),),
    )
    idx = _index(functions=(handler_record,))
    handler = convert_function(handler_record)
    match = _dependency_match(_call("app.handler", "fastapi.Depends", _arg(0, "missing")))

    result = convert_dependency_matches(
        (match,),
        (match,),
        idx=idx,
        functions_by_fqn={handler.fqn: handler},
    )

    assert result.dispatch_edges == ()
    assert result.reads_by_function == {}
    assert len(result.gaps) == 1
    assert result.gaps[0].kind is GapKind.SYMBOL_UNRESOLVED
    assert result.gaps[0].affected_function == "app.handler"


def test_missing_dependency_callable_argument_produces_gap() -> None:
    """Depends() without a callable produces an explicit gap."""
    handler_record = _function(
        "app.handler",
        params=(_param("value", default="Depends()", line=10),),
    )
    idx = _index(functions=(handler_record,))
    handler = convert_function(handler_record)
    match = _dependency_match(_call("app.handler", "fastapi.Depends"))

    result = convert_dependency_matches(
        (match,),
        (match,),
        idx=idx,
        functions_by_fqn={handler.fqn: handler},
    )

    assert result.dispatch_edges == ()
    assert result.reads_by_function == {}
    assert len(result.gaps) == 1
    assert result.gaps[0].kind is GapKind.INFERENCE_FAILURE
    assert result.gaps[0].source_error == "dependency_conversion: missing callable argument"


def _span(line: int, *, column: int = 0, file: str = "app.py") -> SourceSpan:
    return SourceSpan(file=file, line=line, column=column, end_line=line, end_column=column + 10)


def _function(
    fqn: str,
    *,
    params: tuple[Parameter, ...] = (),
    line: int = 5,
) -> FunctionRecord:
    return FunctionRecord(
        fqn=fqn,
        name=fqn.rsplit(".", maxsplit=1)[-1],
        file="app.py",
        line=line,
        params=params,
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


def _param(name: str, *, default: str, line: int) -> Parameter:
    return Parameter(
        name=name,
        annotation=None,
        default=default,
        kind=ParameterKind.POSITIONAL_OR_KEYWORD,
        position=0,
        location=_span(line),
    )


def _arg(position: int, expression: str, *, line: int = 10) -> CallArgument:
    return CallArgument(
        position=position,
        keyword=None,
        expression=expression,
        location=_span(line, column=20),
    )


def _call(
    caller_fqn: str,
    callee_fqn: str,
    *args: CallArgument,
    line: int = 10,
    column: int = 12,
) -> CallEdge:
    return CallEdge(
        caller_fqn=caller_fqn,
        callee_fqn=callee_fqn,
        arguments=args,
        resolution=ResolutionStatus.RESOLVED,
        source=EdgeSource.AST,
        unresolved_reason=None,
        location=_span(line, column=column),
        provenance=_PROV,
        call_expression=callee_fqn.rsplit(".", maxsplit=1)[-1],
    )


def _vf(
    source_expr: str,
    target_expr: str,
    *,
    containing_function_fqn: str | None,
    line: int,
    column: int = 0,
) -> ValueFlowEdge:
    return ValueFlowEdge(
        source_expr=source_expr,
        source_location=_span(line, column=column),
        target_expr=target_expr,
        target_location=_span(line),
        kind=FlowKind.ASSIGN,
        containing_function_fqn=containing_function_fqn,
        provenance=_PROV,
    )


def _symbol(name: str, fqn: str, *, line: int) -> SymbolRef:
    return SymbolRef(
        name=name,
        fqn=fqn,
        resolution=ResolutionStatus.RESOLVED,
        location=_span(line),
        provenance=_PROV,
    )


def _dependency_match(edge: CallEdge) -> ProviderMatch:
    pattern = DependencyPattern(inject_fqn=edge.callee_fqn or "fastapi.Depends")
    return ProviderMatch(
        provider_id="test",
        phase=ProviderPhase.DEPENDENCIES,
        descriptor=pattern,
        source_fact=edge,
        observed_fqn=edge.callee_fqn or "",
        canonical_fqn=edge.callee_fqn or "",
        location=edge.location,
    )


def _check_match(edge: CallEdge) -> ProviderMatch:
    pattern = SecurityCheckPattern(
        fqn=edge.callee_fqn or "fastapi.security.OAuth2PasswordBearer",
        kind=CheckKind.CALL,
        category="AUTHENTICATION",
    )
    return ProviderMatch(
        provider_id="test",
        phase=ProviderPhase.CHECKS,
        descriptor=pattern,
        source_fact=edge,
        observed_fqn=edge.callee_fqn or "",
        canonical_fqn=edge.callee_fqn or "",
        location=edge.location,
    )


def _index(
    *,
    functions: tuple[FunctionRecord, ...],
    symbols: tuple[SymbolRef, ...] = (),
    value_flow_edges: tuple[ValueFlowEdge, ...] = (),
) -> CodeIndex:
    return CodeIndex(
        repo_root=_ROOT,
        functions=functions,
        classes=(),
        decorators=(),
        imports=(),
        attributes=(),
        call_edges=(),
        cfgs={},
        value_flow_edges=value_flow_edges,
        symbol_refs=symbols,
        errors=(),
        provenance=_PROV,
    )
