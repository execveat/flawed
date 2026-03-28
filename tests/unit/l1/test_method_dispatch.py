"""Self/cls method-dispatch resolution (FLAW-266a).

L1 leaves ``self.handler()`` / ``getattr(self, "handler")()`` unresolved
(``callee_fqn is None``): ``self`` has no statically-known class at the call
site, so the dispatched method's reads/effects never enter the caller's reachable
scope. This pass recovers the receiver's class from the enclosing method's
``parent_class`` and walks the class MRO to the method that runs.

The contract is *monotone, resolve-or-gap*: it only fills an unresolved edge,
fires only on a bare ``self``/``cls`` receiver of a class whose MRO is fully
known, and resolves to the single monomorphic target. These tests pin the
positive resolutions and each give-up condition that keeps it from mis-resolving:
incomplete MRO, dynamic member name, an unknown member, an already-resolved edge,
and a non-self / attribute-rooted receiver.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flawed._index import CodeIndex
from flawed._index._types import (
    CallEdge,
    ClassRecord,
    EdgeSource,
    ExtractionProvenance,
    FunctionRecord,
    ResolutionStatus,
    SourceSpan,
)
from flawed._index._types import FunctionKind as L1FunctionKind
from flawed._semantic._conversion import convert_function
from flawed._semantic._method_dispatch import infer_method_dispatch_edges

_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="")
_ROOT = Path("/tmp/test-repo")
_FILE = "app.py"
_DISPATCH = "app.C.dispatch"


def _span(line: int) -> SourceSpan:
    return SourceSpan(file=_FILE, line=line, column=0, end_line=line, end_column=20)


def _method(fqn: str, *, parent_class: str) -> FunctionRecord:
    return FunctionRecord(
        fqn=fqn,
        name=fqn.rsplit(".", 1)[-1],
        file=_FILE,
        line=20,
        params=(),
        decorator_names=(),
        decorator_fqns=(),
        kind=L1FunctionKind.METHOD,
        is_method=True,
        is_nested=False,
        is_async=False,
        parent_class=parent_class,
        location=_span(20),
        provenance=_PROV,
    )


def _class(
    fqn: str,
    *,
    mro_chain: tuple[str, ...],
    mro_complete: bool = True,
) -> ClassRecord:
    return ClassRecord(
        fqn=fqn,
        name=fqn.rsplit(".", 1)[-1],
        file=_FILE,
        bases=(),
        mro_chain=mro_chain,
        mro_complete=mro_complete,
        method_names=(),
        class_var_names=(),
        is_abstract=False,
        metaclass=None,
        subclasses=(),
        all_subclasses=(),
        inherited_methods=(),
        hierarchy_gaps=(),
        location=_span(10),
        provenance=_PROV,
    )


def _call(
    *,
    call_expression: str,
    callee_fqn: str | None = None,
    dynamic_dispatch_kind: str | None = None,
    receiver_expression: str | None = None,
) -> CallEdge:
    return CallEdge(
        caller_fqn=_DISPATCH,
        callee_fqn=callee_fqn,
        arguments=(),
        resolution=(ResolutionStatus.RESOLVED if callee_fqn else ResolutionStatus.UNRESOLVED),
        source=EdgeSource.AST,
        unresolved_reason=None if callee_fqn else "dynamic_dispatch",
        location=_span(30),
        provenance=_PROV,
        call_expression=call_expression,
        dynamic_dispatch_kind=dynamic_dispatch_kind,
        receiver_expression=receiver_expression,
    )


def _getattr_call() -> CallEdge:
    """``getattr(self, "handler")()`` — call_expression holds the getattr call."""
    return _call(call_expression='getattr(self, "handler")', dynamic_dispatch_kind="getattr")


def _plain_call() -> CallEdge:
    """``self.handler()`` — unresolved attribute call with a self receiver."""
    return _call(call_expression="self.handler", receiver_expression="self")


def _index(
    *,
    functions: tuple[FunctionRecord, ...],
    classes: tuple[ClassRecord, ...],
    call_edges: tuple[CallEdge, ...],
) -> CodeIndex:
    return CodeIndex(
        repo_root=_ROOT,
        functions=functions,
        classes=classes,
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


def _functions_by_fqn(records: tuple[FunctionRecord, ...]) -> dict[str, Any]:
    return {record.fqn: convert_function(record) for record in records}


def _single_class_setup(call_edge: CallEdge) -> tuple[CodeIndex, dict[str, Any]]:
    records = (
        _method("app.C.dispatch", parent_class="app.C"),
        _method("app.C.handler", parent_class="app.C"),
    )
    idx = _index(
        functions=records,
        classes=(_class("app.C", mro_chain=("app.C",)),),
        call_edges=(call_edge,),
    )
    return idx, _functions_by_fqn(records)


def test_getattr_self_resolves_to_local_method() -> None:
    """The core win: ``getattr(self, "handler")()`` becomes a reachability edge."""
    idx, functions_by_fqn = _single_class_setup(_getattr_call())

    edges = infer_method_dispatch_edges(idx, functions_by_fqn=functions_by_fqn)

    assert [(e.caller_fqn, e.target.fqn) for e in edges] == [(_DISPATCH, "app.C.handler")]
    assert all(e.dispatch_type == "method_self" for e in edges)


def test_plain_self_attribute_resolves() -> None:
    """An unresolved ``self.handler()`` attribute call also resolves via parent_class."""
    idx, functions_by_fqn = _single_class_setup(_plain_call())

    edges = infer_method_dispatch_edges(idx, functions_by_fqn=functions_by_fqn)

    assert [e.target.fqn for e in edges] == ["app.C.handler"]


def test_inherited_method_resolves_via_mro() -> None:
    """A method defined on a base resolves through the subclass's MRO chain."""
    records = (
        _method("app.C.dispatch", parent_class="app.C"),
        _method("app.B.handler", parent_class="app.B"),
    )
    idx = _index(
        functions=records,
        classes=(
            _class("app.C", mro_chain=("app.C", "app.B")),
            _class("app.B", mro_chain=("app.B",)),
        ),
        call_edges=(_getattr_call(),),
    )

    edges = infer_method_dispatch_edges(idx, functions_by_fqn=_functions_by_fqn(records))

    assert [e.target.fqn for e in edges] == ["app.B.handler"]


def test_incomplete_mro_stays_a_gap() -> None:
    """An external/unresolved base (mro_complete=False) leaves FLAW-231's gap."""
    records = (
        _method("app.C.dispatch", parent_class="app.C"),
        _method("app.C.handler", parent_class="app.C"),
    )
    idx = _index(
        functions=records,
        classes=(_class("app.C", mro_chain=("app.C",), mro_complete=False),),
        call_edges=(_getattr_call(),),
    )
    assert infer_method_dispatch_edges(idx, functions_by_fqn=_functions_by_fqn(records)) == ()


def test_dynamic_member_name_stays_a_gap() -> None:
    """``getattr(self, name)()`` with a non-literal member must not resolve."""
    idx, functions_by_fqn = _single_class_setup(
        _call(call_expression="getattr(self, name)", dynamic_dispatch_kind="getattr")
    )
    assert infer_method_dispatch_edges(idx, functions_by_fqn=functions_by_fqn) == ()


def test_unknown_member_stays_a_gap() -> None:
    """A member with no method in the MRO is never (mis)attributed."""
    idx, functions_by_fqn = _single_class_setup(
        _call(call_expression='getattr(self, "missing")', dynamic_dispatch_kind="getattr")
    )
    assert infer_method_dispatch_edges(idx, functions_by_fqn=functions_by_fqn) == ()


def test_resolved_edge_is_not_shadowed() -> None:
    """An edge L1 already resolved (callee_fqn set) is left untouched."""
    idx, functions_by_fqn = _single_class_setup(
        _call(
            call_expression="self.handler",
            callee_fqn="app.C.handler",
            receiver_expression="self",
        )
    )
    assert infer_method_dispatch_edges(idx, functions_by_fqn=functions_by_fqn) == ()


def test_non_self_receiver_ignored() -> None:
    """A non-self receiver (``obj.handler()``) is out of scope for 266a."""
    idx, functions_by_fqn = _single_class_setup(
        _call(call_expression="obj.handler", receiver_expression="obj")
    )
    assert infer_method_dispatch_edges(idx, functions_by_fqn=functions_by_fqn) == ()


def test_attribute_rooted_receiver_ignored() -> None:
    """``self.client.handler()`` is an instance-attribute receiver (FLAW-249), not 266a."""
    idx, functions_by_fqn = _single_class_setup(
        _call(call_expression="self.client.handler", receiver_expression="self.client")
    )
    assert infer_method_dispatch_edges(idx, functions_by_fqn=functions_by_fqn) == ()
