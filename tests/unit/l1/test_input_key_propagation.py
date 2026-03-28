"""Indirected input-key propagation through pass-through accessor helpers (FLAW-229).

A request key passed as a *variable* into a helper -- e.g.
``get_param("quantity") -> get_param(name) -> request.args.get(name)`` -- used to
lose the literal ``"quantity"`` at the ``request.args.get(name)`` access, leaving
the ``InputRead`` keyed on ``None``. That defeated every whitelist-keyed rule
(the request-input-key family). These tests pin that the literal key is now
recovered from the helper's call sites (one or more bounded hops), and that an
unresolvable hop surfaces an ``AnalysisGap`` instead of failing open.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from flawed._index import CodeIndex
from flawed._index._types import (
    CallArgument,
    CallEdge,
    EdgeSource,
    ExtractionProvenance,
    FunctionRecord,
    ResolutionStatus,
    SourceSpan,
)
from flawed._index._types import FunctionKind as L1FunctionKind
from flawed._index._types import Parameter as L1Parameter
from flawed._index._types import ParameterKind as L1ParameterKind
from flawed._semantic._conversion import convert_function
from flawed._semantic._input_conversion import convert_input_match
from flawed._semantic._provider_engine import ProviderMatch, ProviderPhase
from flawed._semantic.providers import InputMethodPattern
from flawed.core import GapKind, Key
from flawed.inputs import Query

_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="")
_ROOT = Path("/tmp/test-repo")
_ACCESSOR = "flask.Request.args.get"


def _span(line: int) -> SourceSpan:
    return SourceSpan(file="app.py", line=line, column=0, end_line=line, end_column=10)


def _param(name: str, position: int) -> L1Parameter:
    return L1Parameter(
        name=name,
        annotation=None,
        default=None,
        kind=L1ParameterKind.POSITIONAL_OR_KEYWORD,
        position=position,
        location=_span(21),
    )


def _function(fqn: str, *, params: tuple[L1Parameter, ...] = (), line: int = 20) -> FunctionRecord:
    return FunctionRecord(
        fqn=fqn,
        name=fqn.rsplit(".", 1)[-1],
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


def _arg(expression: str, *, position: int | None = 0, keyword: str | None = None) -> CallArgument:
    return CallArgument(
        position=position, keyword=keyword, expression=expression, location=_span(30)
    )


def _edge(caller: str, callee: str, args: tuple[CallArgument, ...]) -> CallEdge:
    return CallEdge(
        caller_fqn=caller,
        callee_fqn=callee,
        arguments=args,
        resolution=ResolutionStatus.RESOLVED,
        source=EdgeSource.AST,
        unresolved_reason=None,
        location=_span(30),
        provenance=_PROV,
        call_expression=f"{callee}(...)",
    )


def _accessor_fact(caller_fqn: str, key_expr: str) -> CallEdge:
    """The ``request.args.get(<key_expr>)`` access inside ``caller_fqn``."""
    return CallEdge(
        caller_fqn=caller_fqn,
        callee_fqn=_ACCESSOR,
        arguments=(_arg(key_expr),),
        resolution=ResolutionStatus.RESOLVED,
        source=EdgeSource.AST,
        unresolved_reason=None,
        location=_span(15),
        provenance=_PROV,
        call_expression=f"request.args.get({key_expr})",
    )


def _match(fact: CallEdge) -> ProviderMatch:
    return ProviderMatch(
        provider_id="flask",
        phase=ProviderPhase.INPUTS,
        descriptor=InputMethodPattern(fqn=_ACCESSOR, source_type="Query", key_arg=0),
        source_fact=cast("Any", fact),
        observed_fqn=_ACCESSOR,
        canonical_fqn=_ACCESSOR,
        location=fact.location,
    )


def _index(
    *, functions: tuple[FunctionRecord, ...], call_edges: tuple[CallEdge, ...]
) -> CodeIndex:
    return CodeIndex(
        repo_root=_ROOT,
        functions=functions,
        classes=(),
        decorators=(),
        imports=(),
        attributes=(),
        call_edges=call_edges,
        cfgs={},
        value_flow_edges=(),
        symbol_refs=(),
        errors=(),
        provenance=_PROV,
    )


def _converted(records: tuple[FunctionRecord, ...]) -> dict[str, Any]:
    return {record.fqn: convert_function(record) for record in records}


def test_direct_literal_key_is_unchanged() -> None:
    """A literal key at the access site keeps the existing direct behaviour."""
    view = _function("app.view")
    fact = _accessor_fact("app.view", '"quantity"')
    result = convert_input_match(
        _match(fact),
        _index(functions=(view,), call_edges=(fact,)),
        _converted((view,)),
    )

    assert result.gaps == ()
    assert [read.source for read in result.reads] == [Query(key=Key("quantity"))]


def test_single_hop_pass_through_recovers_literal_key() -> None:
    """``get_param("quantity")`` -> ``request.args.get(name)`` recovers ``quantity``."""
    get_param = _function("app.get_param", params=(_param("name", 0),))
    view = _function("app.view")
    fact = _accessor_fact("app.get_param", "name")
    result = convert_input_match(
        _match(fact),
        _index(
            functions=(get_param, view),
            call_edges=(fact, _edge("app.view", "app.get_param", (_arg('"quantity"'),))),
        ),
        _converted((get_param, view)),
    )

    assert result.gaps == ()
    assert [read.source for read in result.reads] == [Query(key=Key("quantity"))]


def test_two_hop_pass_through_chain_recovers_literal_key() -> None:
    """``get_int_param("quantity")`` -> ``get_param(name)`` -> access recovers ``quantity``."""
    get_param = _function("app.get_param", params=(_param("name", 0),))
    get_int = _function("app.get_int_param", params=(_param("name", 0), _param("default", 1)))
    view = _function("app.view")
    fact = _accessor_fact("app.get_param", "name")
    result = convert_input_match(
        _match(fact),
        _index(
            functions=(get_param, get_int, view),
            call_edges=(
                fact,
                _edge("app.get_int_param", "app.get_param", (_arg("name"),)),
                _edge(
                    "app.view",
                    "app.get_int_param",
                    (_arg('"quantity"'), _arg("1", position=1)),
                ),
            ),
        ),
        _converted((get_param, get_int, view)),
    )

    assert result.gaps == ()
    assert [read.source for read in result.reads] == [Query(key=Key("quantity"))]


def test_keyword_call_site_recovers_literal_key() -> None:
    """A caller passing the key by keyword (``get_param(name="quantity")``) resolves."""
    get_param = _function("app.get_param", params=(_param("name", 0),))
    view = _function("app.view")
    fact = _accessor_fact("app.get_param", "name")
    result = convert_input_match(
        _match(fact),
        _index(
            functions=(get_param, view),
            call_edges=(
                fact,
                _edge(
                    "app.view",
                    "app.get_param",
                    (_arg('"quantity"', position=None, keyword="name"),),
                ),
            ),
        ),
        _converted((get_param, view)),
    )

    assert result.gaps == ()
    assert [read.source for read in result.reads] == [Query(key=Key("quantity"))]


def test_multiple_distinct_keys_stay_wildcard_with_gap() -> None:
    """A generic accessor called with several literals can't be route-keyed here.

    The read is anchored at the helper (route-agnostic), so attaching every key
    would leak each into every reaching route.  Keep the conservative wildcard
    and surface an honest gap; per-route resolution is the FLAW-229 follow-up.
    """
    get_param = _function("app.get_param", params=(_param("name", 0),))
    view_a = _function("app.view_a")
    view_b = _function("app.view_b")
    fact = _accessor_fact("app.get_param", "name")
    result = convert_input_match(
        _match(fact),
        _index(
            functions=(get_param, view_a, view_b),
            call_edges=(
                fact,
                _edge("app.view_a", "app.get_param", (_arg('"quantity"'),)),
                _edge("app.view_b", "app.get_param", (_arg('"coupon"'),)),
            ),
        ),
        _converted((get_param, view_a, view_b)),
    )

    assert [read.source for read in result.reads] == [Query()]
    assert len(result.gaps) == 1
    gap = result.gaps[0]
    assert gap.source_error == "input_conversion: unresolved indirected input key"
    assert "coupon" in gap.message and "quantity" in gap.message


def test_unresolvable_indirected_key_emits_gap_not_silent_miss() -> None:
    """No call site supplies a literal -> wildcard read PLUS an AnalysisGap."""
    get_param = _function("app.get_param", params=(_param("name", 0),))
    view = _function("app.view")
    fact = _accessor_fact("app.get_param", "name")
    result = convert_input_match(
        _match(fact),
        _index(
            functions=(get_param, view),
            # caller forwards a non-literal that is not itself a resolvable parameter
            call_edges=(fact, _edge("app.view", "app.get_param", (_arg("user_supplied"),))),
        ),
        _converted((get_param, view)),
    )

    assert [read.source for read in result.reads] == [Query()]
    assert len(result.gaps) == 1
    gap = result.gaps[0]
    assert gap.kind is GapKind.INFERENCE_FAILURE
    assert gap.source_error == "input_conversion: unresolved indirected input key"
    assert gap.affected_function == "app.get_param"


def test_partial_resolution_stays_wildcard_with_gap() -> None:
    """One literal call site, one dynamic -> conservative wildcard + honest gap.

    Attaching the single literal would mis-key the route that reaches the helper
    via the dynamic call site, so resolution requires unanimity.
    """
    get_param = _function("app.get_param", params=(_param("name", 0),))
    view_a = _function("app.view_a")
    view_b = _function("app.view_b")
    fact = _accessor_fact("app.get_param", "name")
    result = convert_input_match(
        _match(fact),
        _index(
            functions=(get_param, view_a, view_b),
            call_edges=(
                fact,
                _edge("app.view_a", "app.get_param", (_arg('"quantity"'),)),
                _edge("app.view_b", "app.get_param", (_arg("dynamic_key"),)),
            ),
        ),
        _converted((get_param, view_a, view_b)),
    )

    assert [read.source for read in result.reads] == [Query()]
    assert len(result.gaps) == 1
    assert result.gaps[0].source_error == "input_conversion: unresolved indirected input key"
