"""Focused tests for rule-time flow query caching."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from flawed._index._graphs import CallGraph
from flawed._index._types import ExtractionProvenance, FlowKind, SourceSpan, ValueFlowEdge
from flawed._semantic import _SemanticFlowEngine  # type: ignore[attr-defined]
from flawed._semantic._collections import (
    ConcreteFunctionCollection,
    ConcreteRouteCollection,
    ConcreteTaintSinkCollection,
)
from flawed.core import Location

if TYPE_CHECKING:
    from flawed.sinks import TaintSink


def _prov() -> ExtractionProvenance:
    return ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="test")


def _span(file: str, line: int) -> SourceSpan:
    return SourceSpan(file=file, line=line, column=0, end_line=line, end_column=5)


def _edge(src_expr: str, src_line: int, tgt_expr: str, tgt_line: int) -> ValueFlowEdge:
    return ValueFlowEdge(
        source_expr=src_expr,
        source_location=_span("app.py", src_line),
        target_expr=tgt_expr,
        target_location=_span("app.py", tgt_line),
        kind=FlowKind.ASSIGN,
        containing_function_fqn="app.handler",
        provenance=_prov(),
    )


class CountingValueFlowGraph:
    """Minimal value-flow graph that exposes edge access count."""

    def __init__(self, edges: tuple[ValueFlowEdge, ...]) -> None:
        self._edges = edges
        self.edge_accesses = 0

    @property
    def edges(self) -> tuple[ValueFlowEdge, ...]:
        self.edge_accesses += 1
        return self._edges


def _engine(value_flow: CountingValueFlowGraph) -> _SemanticFlowEngine:
    return _SemanticFlowEngine(
        value_flow=value_flow,  # type: ignore[arg-type]
        call_graph=CallGraph(()),
        function_records=(),
        functions=ConcreteFunctionCollection(()),
        routes=ConcreteRouteCollection(()),
    )


def test_edges_at_uses_prebuilt_line_index_for_repeated_queries() -> None:
    off_line_edges = tuple(
        _edge(f"src_{line}", line, f"dst_{line}", line) for line in range(10, 5010)
    )
    relevant_edge = _edge("request.args['q']", 5, "query", 5)
    value_flow = CountingValueFlowGraph((*off_line_edges, relevant_edge))
    engine = _engine(value_flow)
    init_edge_accesses = value_flow.edge_accesses

    location = Location(file="app.py", line=5, column=0)

    assert engine._edges_at(location) == (relevant_edge,)
    assert engine._edges_at(location) == (relevant_edge,)
    assert value_flow.edge_accesses == init_edge_accesses


@dataclass(frozen=True)
class FakeTarget:
    expression: str


class FakeReadValue:
    def __init__(self) -> None:
        self.flow_checks = 0

    def flows_to(self, target: FakeTarget) -> bool:
        self.flow_checks += 1
        return True


@dataclass(frozen=True)
class FakeInputRead:
    value: FakeReadValue


@dataclass(frozen=True)
class FakeSink:
    target: FakeTarget


def test_taint_sink_collection_reuses_flow_reached_items_across_accesses() -> None:
    read_value = FakeReadValue()
    sinks = (FakeSink(FakeTarget("first")), FakeSink(FakeTarget("second")))
    collection = ConcreteTaintSinkCollection(
        sinks,  # type: ignore[arg-type]
        input_reads=(FakeInputRead(read_value),),  # type: ignore[arg-type]
    )

    assert bool(collection) is True
    assert list(collection) == cast("list[TaintSink]", list(sinks))
    assert read_value.flow_checks == len(sinks)
