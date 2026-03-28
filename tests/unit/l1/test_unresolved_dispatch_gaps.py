"""Unit tests for FLAW-231 reachable-closure truncation gaps.

When a route/function reachable scope is built, a *dynamic-dispatch* call
whose target cannot be resolved silently truncates the closure: reads and
effects in the dispatched-to function are not attributed, with no signal. The
``_unresolved_dispatch_gaps`` helper converts that silent false negative into
an honest ``VALUE_FLOW_INCOMPLETE`` gap (the scope-level analog of the tracer
dead-end closed in FLAW-217).

The behavioural contract under test, with the noise-control gate that keeps
ordinary library/builtin/method boundaries from producing gaps:

* a dynamic-dispatch unresolved edge -> exactly one gap;
* a resolved edge -> no gap (closure is complete there);
* an unresolved edge that is NOT dynamic dispatch (``no_qualified_name`` --
  a library/builtin/bound-method boundary) -> no gap;
* the same dispatch site reachable from several functions -> one gap (dedup).
"""

from __future__ import annotations

from flawed._index._graphs import CallGraph
from flawed._index._types import (
    CallEdge,
    EdgeSource,
    ExtractionProvenance,
    ResolutionStatus,
    SourceSpan,
)
from flawed._semantic import _unresolved_dispatch_gaps
from flawed.core import GapKind


def _prov() -> ExtractionProvenance:
    return ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="test")


def _span(file: str, line: int) -> SourceSpan:
    return SourceSpan(file=file, line=line, column=0, end_line=line, end_column=10)


def _edge(
    caller_fqn: str,
    *,
    callee_fqn: str | None,
    file: str = "app.py",
    line: int = 10,
    dynamic_dispatch_kind: str | None = None,
    unresolved_reason: str | None = None,
    call_expression: str | None = None,
) -> CallEdge:
    resolution = (
        ResolutionStatus.RESOLVED if callee_fqn is not None else ResolutionStatus.UNRESOLVED
    )
    return CallEdge(
        caller_fqn=caller_fqn,
        callee_fqn=callee_fqn,
        arguments=(),
        resolution=resolution,
        source=EdgeSource.AST,
        unresolved_reason=unresolved_reason,
        location=_span(file, line),
        provenance=_prov(),
        call_expression=call_expression,
        dynamic_dispatch_kind=dynamic_dispatch_kind,
    )


def test_dynamic_dispatch_unresolved_edge_emits_gap() -> None:
    graph = CallGraph(
        (
            _edge(
                "app.handler",
                callee_fqn=None,
                line=12,
                dynamic_dispatch_kind="subscript",
                unresolved_reason="dynamic_dispatch_subscript",
                call_expression="handlers[name]()",
            ),
        )
    )

    gaps = _unresolved_dispatch_gaps(("app.handler",), graph, origin_phase="reachable_closure")

    assert len(gaps) == 1
    gap = gaps[0]
    assert gap.kind is GapKind.VALUE_FLOW_INCOMPLETE
    assert gap.affected_function == "app.handler"
    assert gap.affected_file == "app.py"
    assert gap.origin_phase == "reachable_closure"
    assert "handlers[name]()" in gap.message


def test_resolved_edge_emits_no_gap() -> None:
    graph = CallGraph((_edge("app.handler", callee_fqn="app.helper"),))
    gaps = _unresolved_dispatch_gaps(("app.handler",), graph, origin_phase="reachable_closure")
    assert gaps == []


def test_unresolved_non_dispatch_edge_emits_no_gap() -> None:
    """A library/builtin/bound-method boundary (no dynamic dispatch) is expected,
    not a closure truncation, so it must not produce noise."""
    graph = CallGraph(
        (
            _edge(
                "app.handler",
                callee_fqn=None,
                unresolved_reason="no_qualified_name",
                call_expression="request.args.get('x')",
            ),
        )
    )
    gaps = _unresolved_dispatch_gaps(("app.handler",), graph, origin_phase="reachable_closure")
    assert gaps == []


def test_same_dispatch_site_from_many_functions_dedupes() -> None:
    """One physical dispatch site reachable from two functions yields one gap."""

    def _shared(caller: str) -> CallEdge:
        return _edge(
            caller,
            callee_fqn=None,
            file="app.py",
            line=20,
            dynamic_dispatch_kind="attribute",
            call_expression="getattr(obj, name)()",
        )

    graph = CallGraph((_shared("app.a"), _shared("app.b")))
    gaps = _unresolved_dispatch_gaps(("app.a", "app.b"), graph, origin_phase="full_stack_closure")
    assert len(gaps) == 1
