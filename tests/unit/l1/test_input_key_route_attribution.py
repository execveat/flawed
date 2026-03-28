"""Per-route key resolution for generic multi-key input accessors (FLAW-243).

FLAW-229 recovers a literal request key through a *single-key* pass-through
accessor, but a generic multi-key accessor -- ``get_param(name)`` called with
``"quantity"`` on one route and ``"coupon"`` on another -- stays a route-agnostic
wildcard (attaching either key would leak it into the other route).  FLAW-243
re-resolves that wildcard *per scope* via :func:`rekey_read_for_scope`, confining
the call-site walk to the scope's own reachable callers: each route recovers its
own literal key, and no route ever sees another's.

These tests pin the core attribution helper directly (the scope-construction
wiring in ``_semantic.__init__`` is covered by the semantic-model suites): a
marked wildcard read resolves to the route-specific key, two-hop chains resolve,
a route that genuinely reaches the accessor via two keys stays a wildcard (no
silent mis-key), and an unmarked read is left untouched.
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
from flawed._semantic._input_conversion import (
    convert_input_match,
    rekey_read_for_scope,
)
from flawed._semantic._provider_engine import ProviderMatch, ProviderPhase
from flawed._semantic.providers import InputMethodPattern
from flawed.core import Key
from flawed.inputs import InputRead, Query

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


def _function(fqn: str, *, params: tuple[L1Parameter, ...] = ()) -> FunctionRecord:
    return FunctionRecord(
        fqn=fqn,
        name=fqn.rsplit(".", 1)[-1],
        file="app.py",
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


def _multikey_wildcard_read(idx: CodeIndex, functions_by_fqn: dict[str, Any]) -> InputRead:
    """The route-agnostic wildcard read produced for a generic multi-key accessor."""
    fact = _accessor_fact("app.get_param", "name")
    result = convert_input_match(_match(fact), idx, functions_by_fqn)
    assert [read.source for read in result.reads] == [Query()], "expected a wildcard read"
    assert len(result.gaps) == 1, "multi-key accessor should still carry the honest gap"
    read = result.reads[0]
    # The wildcard is marked for per-route re-resolution (the FLAW-243 hook).
    assert getattr(read, "_unresolved_key_param", None) == "name"
    return read


def test_per_route_resolution_recovers_each_routes_own_key() -> None:
    """The core guarantee: each route recovers its own key; neither sees the other's."""
    get_param = _function("app.get_param", params=(_param("name", 0),))
    view_a = _function("app.view_a")
    view_b = _function("app.view_b")
    functions = (get_param, view_a, view_b)
    idx = _index(
        functions=functions,
        call_edges=(
            _accessor_fact("app.get_param", "name"),
            _edge("app.view_a", "app.get_param", (_arg('"quantity"'),)),
            _edge("app.view_b", "app.get_param", (_arg('"coupon"'),)),
        ),
    )
    fqns = _converted(functions)
    read = _multikey_wildcard_read(idx, fqns)

    # view_a's reachable closure reaches get_param only via the "quantity" call.
    rekeyed_a = rekey_read_for_scope(
        read,
        allowed_caller_fqns=frozenset({"app.view_a", "app.get_param"}),
        idx=idx,
        functions_by_fqn=fqns,
    )
    assert rekeyed_a is not None
    assert rekeyed_a.source == Query(key=Key("quantity"))
    # No cross-route contamination: the resolved copy is no longer a re-key candidate.
    assert getattr(rekeyed_a, "_unresolved_key_param", None) is None

    # view_b independently recovers "coupon" -- not "quantity".
    rekeyed_b = rekey_read_for_scope(
        read,
        allowed_caller_fqns=frozenset({"app.view_b", "app.get_param"}),
        idx=idx,
        functions_by_fqn=fqns,
    )
    assert rekeyed_b is not None
    assert rekeyed_b.source == Query(key=Key("coupon"))

    # The shared anchor read is never mutated: it stays a marked wildcard.
    assert read.source == Query()
    assert getattr(read, "_unresolved_key_param", None) == "name"


def test_two_hop_chain_resolves_per_route() -> None:
    """A two-hop chain (view -> get_int_param -> get_param -> access) resolves per route."""
    get_param = _function("app.get_param", params=(_param("name", 0),))
    get_int = _function("app.get_int_param", params=(_param("name", 0), _param("default", 1)))
    view_a = _function("app.view_a")
    view_b = _function("app.view_b")
    functions = (get_param, get_int, view_a, view_b)
    idx = _index(
        functions=functions,
        call_edges=(
            _accessor_fact("app.get_param", "name"),
            _edge("app.get_int_param", "app.get_param", (_arg("name"),)),
            _edge("app.view_a", "app.get_int_param", (_arg('"quantity"'), _arg("1", position=1))),
            _edge("app.view_b", "app.get_int_param", (_arg('"coupon"'), _arg("1", position=1))),
        ),
    )
    fqns = _converted(functions)
    read = _multikey_wildcard_read(idx, fqns)

    rekeyed = rekey_read_for_scope(
        read,
        allowed_caller_fqns=frozenset({"app.view_a", "app.get_int_param", "app.get_param"}),
        idx=idx,
        functions_by_fqn=fqns,
    )
    assert rekeyed is not None
    assert rekeyed.source == Query(key=Key("quantity"))


def test_route_reaching_two_keys_stays_wildcard() -> None:
    """A single route that genuinely reaches the accessor via two keys is not mis-keyed."""
    get_param = _function("app.get_param", params=(_param("name", 0),))
    view = _function("app.view")
    other = _function("app.other")
    functions = (get_param, view, other)
    idx = _index(
        functions=functions,
        call_edges=(
            _accessor_fact("app.get_param", "name"),
            _edge("app.view", "app.get_param", (_arg('"quantity"'),)),
            # The same route also reads "limit" through the same accessor.
            _edge("app.view", "app.get_param", (_arg('"limit"'),)),
            _edge("app.other", "app.get_param", (_arg('"coupon"'),)),
        ),
    )
    fqns = _converted(functions)
    read = _multikey_wildcard_read(idx, fqns)

    rekeyed = rekey_read_for_scope(
        read,
        allowed_caller_fqns=frozenset({"app.view", "app.get_param"}),
        idx=idx,
        functions_by_fqn=fqns,
    )
    # Two literals reach the accessor along this route -> no single key, keep wildcard
    # (FN-first: the honest gap is preserved, nothing silently mis-keyed).
    assert rekeyed is None


def test_unmarked_read_is_left_untouched() -> None:
    """A read with no re-key marker (the common case) returns None -> caller keeps it."""
    view = _function("app.view")
    idx = _index(
        functions=(view,),
        call_edges=(_accessor_fact("app.view", '"quantity"'),),
    )
    fqns = _converted((view,))
    fact = _accessor_fact("app.view", '"quantity"')
    direct = convert_input_match(_match(fact), idx, fqns).reads[0]
    assert direct.source == Query(key=Key("quantity"))
    assert getattr(direct, "_unresolved_key_param", None) is None

    assert (
        rekey_read_for_scope(
            direct,
            allowed_caller_fqns=frozenset({"app.view"}),
            idx=idx,
            functions_by_fqn=fqns,
        )
        is None
    )


def test_callers_outside_scope_do_not_resolve() -> None:
    """If no in-scope caller supplies a literal, the wildcard is kept (no contamination)."""
    get_param = _function("app.get_param", params=(_param("name", 0),))
    view_a = _function("app.view_a")
    view_b = _function("app.view_b")
    functions = (get_param, view_a, view_b)
    idx = _index(
        functions=functions,
        call_edges=(
            _accessor_fact("app.get_param", "name"),
            _edge("app.view_a", "app.get_param", (_arg('"quantity"'),)),
            _edge("app.view_b", "app.get_param", (_arg('"coupon"'),)),
        ),
    )
    fqns = _converted(functions)
    read = _multikey_wildcard_read(idx, fqns)

    # A scope that does not actually reach get_param via any modelled caller.
    rekeyed = rekey_read_for_scope(
        read,
        allowed_caller_fqns=frozenset({"app.unrelated", "app.get_param"}),
        idx=idx,
        functions_by_fqn=fqns,
    )
    assert rekeyed is None
