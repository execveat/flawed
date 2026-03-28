"""Literal dispatch-table resolution (FLAW-239).

FLAW-231 records a ``VALUE_FLOW_INCOMPLETE`` gap for every dynamic-dispatch
``table[key](...)`` call. FLAW-239 deepens that: when the table is provably a
static literal of project functions, the dispatched-to functions become real
reachability edges so their reads/effects enter the caller's scope.

The contract is *monotone by construction* — resolution happens only under
closed-world conditions, so it can only ADD a correct attribution or defer to
the gap; it never guesses a callee. These tests pin both the positive
resolution and each give-up condition that keeps it from mis-resolving:
mutation, parameter-sourcing, reassignment, an unresolvable value, and a
non-literal source.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flawed._index import CodeIndex
from flawed._index._types import (
    AccessKind,
    AttributeAccess,
    CallEdge,
    EdgeSource,
    ExtractionProvenance,
    FlowKind,
    FunctionRecord,
    ResolutionStatus,
    SourceSpan,
    SymbolRef,
    ValueFlowEdge,
)
from flawed._index._types import FunctionKind as L1FunctionKind
from flawed._index._types import Parameter as L1Parameter
from flawed._index._types import ParameterKind as L1ParameterKind
from flawed._semantic._conversion import convert_function
from flawed._semantic._table_dispatch import infer_table_dispatch_edges

_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="")
_ROOT = Path("/tmp/test-repo")
_FILE = "app.py"
_CALLER = "app.view"


def _span(line: int) -> SourceSpan:
    return SourceSpan(file=_FILE, line=line, column=0, end_line=line, end_column=20)


def _param(name: str) -> L1Parameter:
    return L1Parameter(
        name=name,
        annotation=None,
        default=None,
        kind=L1ParameterKind.POSITIONAL_OR_KEYWORD,
        position=0,
        location=_span(20),
    )


def _function(fqn: str, *, params: tuple[L1Parameter, ...] = ()) -> FunctionRecord:
    return FunctionRecord(
        fqn=fqn,
        name=fqn.rsplit(".", 1)[-1],
        file=_FILE,
        line=20,
        params=params,
        decorator_names=(),
        decorator_fqns=(),
        kind=L1FunctionKind.TOP_LEVEL,
        is_method=False,
        is_nested=False,
        is_async=False,
        parent_class=None,
        location=_span(20),
        provenance=_PROV,
    )


def _dispatch_edge(call_expression: str = "handlers[key](user_input)") -> CallEdge:
    return CallEdge(
        caller_fqn=_CALLER,
        callee_fqn=None,
        arguments=(),
        resolution=ResolutionStatus.UNRESOLVED,
        source=EdgeSource.AST,
        unresolved_reason="dynamic_dispatch_table",
        location=_span(30),
        provenance=_PROV,
        call_expression=call_expression,
        dynamic_dispatch_kind="table",
    )


def _binding(source_expr: str, *, kind: FlowKind = FlowKind.ASSIGN) -> ValueFlowEdge:
    return ValueFlowEdge(
        source_expr=source_expr,
        source_location=_span(25),
        target_expr="handlers",
        target_location=_span(25),
        kind=kind,
        containing_function_fqn=_CALLER,
        provenance=_PROV,
    )


def _symbol(name: str, fqn: str | None) -> SymbolRef:
    return SymbolRef(
        name=name,
        fqn=fqn,
        resolution=(ResolutionStatus.RESOLVED if fqn is not None else ResolutionStatus.UNRESOLVED),
        location=_span(25),
        provenance=_PROV,
    )


def _write_access(attr_name: str, access_kind: AccessKind) -> AttributeAccess:
    return AttributeAccess(
        target_expr="handlers",
        attr_name=attr_name,
        is_write=True,
        access_kind=access_kind,
        value_expr="x",
        containing_function_fqn=_CALLER,
        location=_span(26),
        provenance=_PROV,
    )


def _index(
    *,
    functions: tuple[FunctionRecord, ...],
    call_edges: tuple[CallEdge, ...] = (),
    value_flow_edges: tuple[ValueFlowEdge, ...] = (),
    symbol_refs: tuple[SymbolRef, ...] = (),
    attributes: tuple[AttributeAccess, ...] = (),
) -> CodeIndex:
    return CodeIndex(
        repo_root=_ROOT,
        functions=functions,
        classes=(),
        decorators=(),
        imports=(),
        attributes=attributes,
        call_edges=call_edges,
        cfgs={},
        value_flow_edges=value_flow_edges,
        symbol_refs=symbol_refs,
        errors=(),
        provenance=_PROV,
    )


def _functions_by_fqn(records: tuple[FunctionRecord, ...]) -> dict[str, Any]:
    return {record.fqn: convert_function(record) for record in records}


def _two_handler_setup(
    *,
    caller_params: tuple[L1Parameter, ...] = (),
    bindings: tuple[ValueFlowEdge, ...] | None = None,
    symbols: tuple[SymbolRef, ...] | None = None,
    attributes: tuple[AttributeAccess, ...] = (),
) -> tuple[CodeIndex, dict[str, Any]]:
    records = (
        _function(_CALLER, params=caller_params),
        _function("app.handle_a"),
        _function("app.handle_b"),
    )
    idx = _index(
        functions=records,
        call_edges=(_dispatch_edge(),),
        value_flow_edges=(
            bindings if bindings is not None else (_binding("{'a': handle_a, 'b': handle_b}"),)
        ),
        symbol_refs=(
            symbols
            if symbols is not None
            else (_symbol("handle_a", "app.handle_a"), _symbol("handle_b", "app.handle_b"))
        ),
        attributes=attributes,
    )
    return idx, _functions_by_fqn(records)


def test_literal_table_resolves_to_all_values() -> None:
    """The core win: every value of a static literal table becomes a reachability edge."""
    idx, functions_by_fqn = _two_handler_setup()

    edges = infer_table_dispatch_edges(idx, functions_by_fqn=functions_by_fqn)

    assert {e.target.fqn for e in edges} == {"app.handle_a", "app.handle_b"}
    assert all(e.caller_fqn == _CALLER for e in edges)
    assert all(e.dispatch_type == "literal_table" for e in edges)


def test_mutated_table_stays_a_gap() -> None:
    """A ``handlers[k] = v`` subscript write means the table is not closed-world."""
    idx, functions_by_fqn = _two_handler_setup(
        attributes=(_write_access("__setitem__", AccessKind.SUBSCRIPT),)
    )
    assert infer_table_dispatch_edges(idx, functions_by_fqn=functions_by_fqn) == ()


def test_mutator_call_table_stays_a_gap() -> None:
    """A ``handlers.update(...)`` mutator call also disqualifies resolution."""
    idx, functions_by_fqn = _two_handler_setup(
        attributes=(_write_access("update", AccessKind.ATTR),)
    )
    assert infer_table_dispatch_edges(idx, functions_by_fqn=functions_by_fqn) == ()


def test_parameter_sourced_table_stays_a_gap() -> None:
    """A table supplied as a parameter is not provably the local literal."""
    idx, functions_by_fqn = _two_handler_setup(caller_params=(_param("handlers"),))
    assert infer_table_dispatch_edges(idx, functions_by_fqn=functions_by_fqn) == ()


def test_reassigned_table_stays_a_gap() -> None:
    """More than one binding of the table name -> not a single clean literal."""
    idx, functions_by_fqn = _two_handler_setup(
        bindings=(
            _binding("{'a': handle_a, 'b': handle_b}"),
            _binding("{'a': handle_a}"),
        )
    )
    assert infer_table_dispatch_edges(idx, functions_by_fqn=functions_by_fqn) == ()


def test_unresolvable_value_stays_a_gap() -> None:
    """A single value that does not resolve to a known function gaps the whole site."""
    idx, functions_by_fqn = _two_handler_setup(
        symbols=(_symbol("handle_a", "app.handle_a"), _symbol("handle_b", None)),
    )
    assert infer_table_dispatch_edges(idx, functions_by_fqn=functions_by_fqn) == ()


def test_non_literal_source_stays_a_gap() -> None:
    """A dict comprehension / non-display source is not a static literal."""
    idx, functions_by_fqn = _two_handler_setup(
        bindings=(_binding("{k: v for k, v in pairs}"),),
    )
    assert infer_table_dispatch_edges(idx, functions_by_fqn=functions_by_fqn) == ()


def test_non_table_dispatch_is_ignored() -> None:
    """getattr-style dispatch is out of scope here and must produce no edge."""
    records = (_function(_CALLER), _function("app.handle_a"))
    idx = _index(
        functions=records,
        call_edges=(
            CallEdge(
                caller_fqn=_CALLER,
                callee_fqn=None,
                arguments=(),
                resolution=ResolutionStatus.UNRESOLVED,
                source=EdgeSource.AST,
                unresolved_reason="dynamic_dispatch_getattr",
                location=_span(30),
                provenance=_PROV,
                call_expression="getattr(obj, name)()",
                dynamic_dispatch_kind="getattr",
            ),
        ),
        value_flow_edges=(_binding("{'a': handle_a}"),),
        symbol_refs=(_symbol("handle_a", "app.handle_a"),),
    )
    assert infer_table_dispatch_edges(idx, functions_by_fqn=_functions_by_fqn(records)) == ()
