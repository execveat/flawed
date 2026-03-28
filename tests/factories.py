"""Shared test factories for L1 and L2 test object construction.

This module consolidates the repeated factory functions that were previously
copy-pasted across 15+ unit test files. Every factory uses sensible defaults
with keyword overrides for the fields that tests actually care about.

Two factory layers:

- **L1 factories** build ``_index._types`` structural records (``CallEdge``,
  ``FunctionRecord``, ``SourceSpan``, etc.) and ``CodeIndex`` instances.
- **L2 factories** build ``_semantic`` / ``_enriched`` objects
  (``EnrichedFunction``, ``ProviderMatch``) used by conversion tests.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from flawed._index import CodeIndex
from flawed._index._types import (
    AccessKind,
    AttributeAccess,
    CallArgument,
    CallEdge,
    DecoratorFact,
    EdgeSource,
    ExtractionProvenance,
    FunctionRecord,
    ImportFact,
    ResolutionStatus,
    SourceSpan,
    SymbolRef,
)
from flawed._index._types import FunctionKind as L1FunctionKind
from flawed._index._types import Parameter as L1Parameter
from flawed._index._types import ParameterKind as L1ParameterKind
from flawed._semantic._collections import (
    ConcreteDecoratorCollection,
    ConcreteFunctionCollection,
)
from flawed._semantic._enriched import EnrichedFunction
from flawed._semantic._provider_engine import (
    ParameterFact,
    ProviderMatch,
    ProviderPhase,
)
from flawed.core import Location, Provenance
from flawed.function import FunctionKind

# -- Shared constants ---------------------------------------------------------

TEST_PROVENANCE = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="")
TEST_ROOT = Path("/tmp/test-repo")
TEST_FILE = "app.py"

L2_PROVENANCE = Provenance(source_layer="L2", interpreter="test", confidence=1.0)


# -- L1 factories: structural records ----------------------------------------


def make_span(
    *,
    line: int = 10,
    column: int = 0,
    end_column: int = 10,
    file: str = TEST_FILE,
) -> SourceSpan:
    return SourceSpan(
        file=file,
        line=line,
        column=column,
        end_line=line,
        end_column=end_column,
    )


def make_call_arg(
    position: int,
    expression: str,
    location: SourceSpan | None = None,
) -> CallArgument:
    return CallArgument(
        position=position,
        keyword=None,
        expression=expression,
        location=location or make_span(),
    )


def make_kwarg(
    keyword: str,
    expression: str,
    location: SourceSpan | None = None,
) -> CallArgument:
    return CallArgument(
        position=None,
        keyword=keyword,
        expression=expression,
        location=location or make_span(),
    )


def make_call_edge(
    callee_fqn: str,
    *arguments: CallArgument,
    caller_fqn: str = "app.handler",
    call_expression: str | None = None,
    line: int = 21,
) -> CallEdge:
    return CallEdge(
        caller_fqn=caller_fqn,
        callee_fqn=callee_fqn,
        arguments=arguments,
        resolution=ResolutionStatus.RESOLVED,
        source=EdgeSource.AST,
        unresolved_reason=None,
        location=make_span(line=line),
        provenance=TEST_PROVENANCE,
        call_expression=(
            call_expression or f"{callee_fqn}({', '.join(a.expression for a in arguments)})"
        ),
    )


def make_function_record(
    fqn: str,
    *,
    params: tuple[L1Parameter, ...] = (),
    line: int = 20,
    file: str = TEST_FILE,
    kind: L1FunctionKind = L1FunctionKind.TOP_LEVEL,
    is_method: bool = False,
    parent_class: str | None = None,
    decorator_names: tuple[str, ...] = (),
    decorator_fqns: tuple[str, ...] = (),
) -> FunctionRecord:
    return FunctionRecord(
        fqn=fqn,
        name=fqn.rsplit(".", 1)[-1],
        file=file,
        line=line,
        params=params,
        decorator_names=decorator_names,
        decorator_fqns=decorator_fqns,
        kind=kind,
        is_method=is_method,
        is_nested=False,
        is_async=False,
        parent_class=parent_class,
        location=make_span(line=line, file=file),
        provenance=TEST_PROVENANCE,
    )


def make_param(
    name: str,
    *,
    default: str | None = None,
    annotation: str | None = None,
    kind: L1ParameterKind = L1ParameterKind.POSITIONAL_OR_KEYWORD,
    position: int = 0,
    line: int = 21,
) -> L1Parameter:
    return L1Parameter(
        name=name,
        annotation=annotation,
        default=default,
        kind=kind,
        position=position,
        location=make_span(line=line),
    )


def make_decorator(
    fqn: str,
    *args: str,
    name: str | None = None,
    target_fqn: str = "app.handler",
    application_order: int = 0,
    line: int = 10,
) -> DecoratorFact:
    return DecoratorFact(
        name=name or fqn.rsplit(".", 1)[-1],
        fqn=fqn,
        args=args,
        kwargs=(),
        target_fqn=target_fqn,
        application_order=application_order,
        location=make_span(line=line),
        provenance=TEST_PROVENANCE,
    )


def make_import(
    module: str,
    *,
    names: tuple[str, ...] = (),
    is_from_import: bool = True,
    line: int = 1,
) -> ImportFact:
    return ImportFact(
        module=module,
        names=names,
        aliases=(),
        is_from_import=is_from_import,
        location=make_span(line=line),
        provenance=TEST_PROVENANCE,
    )


def make_attribute(
    target_expr: str,
    attr_name: str,
    *,
    containing_function_fqn: str = "app.handler",
    is_write: bool = False,
    access_kind: AccessKind = AccessKind.ATTR,
    value_expr: str | None = None,
    line: int = 21,
) -> AttributeAccess:
    return AttributeAccess(
        target_expr=target_expr,
        attr_name=attr_name,
        is_write=is_write,
        access_kind=access_kind,
        value_expr=value_expr,
        containing_function_fqn=containing_function_fqn,
        location=make_span(line=line),
        provenance=TEST_PROVENANCE,
    )


def make_symbol(
    name: str,
    fqn: str,
    *,
    line: int = 1,
) -> SymbolRef:
    return SymbolRef(
        name=name,
        fqn=fqn,
        resolution=ResolutionStatus.RESOLVED,
        location=make_span(line=line),
        provenance=TEST_PROVENANCE,
    )


def make_index(
    *,
    functions: tuple[FunctionRecord, ...] = (),
    classes: tuple[Any, ...] = (),
    decorators: tuple[DecoratorFact, ...] = (),
    imports: tuple[ImportFact, ...] = (),
    attributes: tuple[AttributeAccess, ...] = (),
    call_edges: tuple[CallEdge, ...] = (),
    value_flow_edges: tuple[Any, ...] = (),
    symbol_refs: tuple[SymbolRef, ...] = (),
    errors: tuple[Any, ...] = (),
    root: Path = TEST_ROOT,
) -> CodeIndex:
    return CodeIndex(
        repo_root=root,
        functions=functions,
        classes=classes,
        decorators=decorators,
        imports=imports,
        attributes=attributes,
        call_edges=call_edges,
        cfgs={},
        value_flow_edges=value_flow_edges,
        symbol_refs=symbol_refs,
        errors=errors,
        provenance=TEST_PROVENANCE,
    )


# -- L2 factories: enriched / semantic objects --------------------------------


def make_enriched_function(
    fqn: str,
    *,
    name: str | None = None,
    params: tuple[Any, ...] = (),
    kind: FunctionKind = FunctionKind.TOP_LEVEL,
    parent_class: str | None = None,
    parent_function: str | None = None,
    file: str = TEST_FILE,
    line: int = 1,
    end_line: int = 5,
) -> EnrichedFunction:
    fn = EnrichedFunction(
        fqn=fqn,
        name=name or fqn.rsplit(".", 1)[-1],
        params=params,
        kind=kind,
        parent_class=parent_class,
        parent_function=parent_function,
        location=Location(file=file, line=line, column=0, end_line=end_line, end_column=0),
        provenance=L2_PROVENANCE,
    )
    object.__setattr__(fn, "_decorators", ConcreteDecoratorCollection(()))
    object.__setattr__(fn, "_gaps", ())
    object.__setattr__(fn, "_calls", ConcreteFunctionCollection(()))
    object.__setattr__(fn, "_called_by", ConcreteFunctionCollection(()))
    return fn


def make_provider_match(
    descriptor: Any,
    source_fact: Any,
    *,
    provider_id: str = "test",
    phase: ProviderPhase = ProviderPhase.EFFECTS,
    observed_fqn: str | None = None,
    canonical_fqn: str | None = None,
) -> ProviderMatch:
    loc = source_fact.location if hasattr(source_fact, "location") else make_span()
    obs = observed_fqn or (
        source_fact.callee_fqn if hasattr(source_fact, "callee_fqn") else "test.unknown"
    )
    return ProviderMatch(
        provider_id=provider_id,
        phase=phase,
        descriptor=descriptor,
        source_fact=cast("Any", source_fact),
        observed_fqn=obs,
        canonical_fqn=canonical_fqn or obs,
        location=loc,
    )


def make_parameter_fact(
    param: L1Parameter,
    *,
    function_fqn: str = "app.handler",
) -> ParameterFact:
    return ParameterFact(
        param=param,
        function_fqn=function_fqn,
        location=param.location,
    )
