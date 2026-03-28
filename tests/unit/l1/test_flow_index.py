"""Unit tests for the per-function value-flow lookup index (FLAW-106).

``FunctionFlowIndex`` precomputes the source/target endpoint sets and the
source-expression adjacency map that the tracer previously rebuilt on every
query.  These tests pin its lookups directly; the equivalence with the prior
linear-scan behaviour is additionally guaranteed by the unchanged
``test_flow_tracer`` suite, which now runs through the index.
"""

from __future__ import annotations

from flawed._index._graphs import ValueFlowGraph
from flawed._index._types import (
    ExtractionProvenance,
    FlowKind,
    SourceSpan,
    ValueFlowEdge,
)
from flawed._semantic._flow_index import FunctionFlowIndex


def _prov() -> ExtractionProvenance:
    return ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="test")


def _span(file: str, line: int, col: int = 0) -> SourceSpan:
    return SourceSpan(file=file, line=line, column=col, end_line=line, end_column=col + 5)


def _edge(
    src_expr: str,
    src_line: int,
    tgt_expr: str,
    tgt_line: int,
    kind: FlowKind = FlowKind.ASSIGN,
    file: str = "app.py",
) -> ValueFlowEdge:
    return ValueFlowEdge(
        source_expr=src_expr,
        source_location=_span(file, src_line),
        target_expr=tgt_expr,
        target_location=_span(file, tgt_line),
        kind=kind,
        containing_function_fqn="mod.func",
        provenance=_prov(),
    )


class TestEmpty:
    def test_empty_index_reports_empty(self) -> None:
        assert FunctionFlowIndex(()).is_empty is True

    def test_non_empty_index_reports_not_empty(self) -> None:
        index = FunctionFlowIndex((_edge("a", 1, "b", 1),))
        assert index.is_empty is False


class TestHasSourceNode:
    def test_exact_expression_match(self) -> None:
        index = FunctionFlowIndex((_edge("request.args['q']", 5, "query", 5),))
        assert index.has_source_node(_span("app.py", 5), "request.args['q']", exact=True) is True

    def test_exact_rejects_different_expression_same_line(self) -> None:
        index = FunctionFlowIndex((_edge("url_for('x') + suffix", 5, "target", 5),))
        assert index.has_source_node(_span("app.py", 5), "url_for('x')", exact=True) is False

    def test_relaxed_accepts_any_expression_on_line(self) -> None:
        index = FunctionFlowIndex((_edge("url_for('x') + suffix", 5, "target", 5),))
        assert index.has_source_node(_span("app.py", 5), "url_for('x')", exact=False) is True

    def test_missing_line_is_absent(self) -> None:
        index = FunctionFlowIndex((_edge("a", 5, "b", 5),))
        assert index.has_source_node(_span("app.py", 99), "a", exact=False) is False

    def test_empty_expression_matches_line(self) -> None:
        index = FunctionFlowIndex((_edge("a", 5, "b", 5),))
        assert index.has_source_node(_span("app.py", 5), "", exact=True) is True


class TestHasSinkNode:
    def test_target_side_match(self) -> None:
        index = FunctionFlowIndex((_edge("a", 5, "query", 5),))
        assert index.has_sink_node(_span("app.py", 5), "query") is True

    def test_source_side_match(self) -> None:
        """A sink present only as a variable *use* (an edge source) is found."""
        index = FunctionFlowIndex((_edge("query", 6, "sql", 6),))
        assert index.has_sink_node(_span("app.py", 6), "query") is True

    def test_absent_sink(self) -> None:
        index = FunctionFlowIndex((_edge("a", 5, "b", 5),))
        assert index.has_sink_node(_span("app.py", 5), "missing") is False

    def test_empty_expression_matches_any_node_on_line(self) -> None:
        index = FunctionFlowIndex((_edge("a", 5, "b", 5),))
        assert index.has_sink_node(_span("app.py", 5), "") is True


class TestBfsPath:
    def test_direct_edge_reachable(self) -> None:
        index = FunctionFlowIndex((_edge("a", 5, "b", 5),))
        path = index.bfs_path(
            source_location=_span("app.py", 5),
            source_expr="a",
            sink_location=_span("app.py", 5),
            sink_expr="b",
        )
        assert path is not None
        assert [e.source_expr for e in path] == ["a"]

    def test_two_hop_chain_reachable(self) -> None:
        index = FunctionFlowIndex((_edge("a", 5, "b", 5), _edge("b", 6, "c", 6)))
        path = index.bfs_path(
            source_location=_span("app.py", 5),
            source_expr="a",
            sink_location=_span("app.py", 6),
            sink_expr="c",
        )
        assert path is not None
        assert len(path) == 2

    def test_disconnected_unreachable(self) -> None:
        index = FunctionFlowIndex((_edge("a", 5, "b", 5), _edge("x", 10, "y", 10)))
        path = index.bfs_path(
            source_location=_span("app.py", 5),
            source_expr="a",
            sink_location=_span("app.py", 10),
            sink_expr="y",
        )
        assert path is None

    def test_sink_use_returns_alias_terminal(self) -> None:
        """Reaching a variable that is used as a source yields an ALIAS terminal step."""
        index = FunctionFlowIndex((_edge("a", 5, "query", 5), _edge("query", 6, "sql", 6)))
        path = index.bfs_path(
            source_location=_span("app.py", 5),
            source_expr="a",
            sink_location=_span("app.py", 6),
            sink_expr="query",
        )
        assert path is not None
        assert path[-1].kind == FlowKind.ALIAS

    def test_exact_source_does_not_relax(self) -> None:
        index = FunctionFlowIndex((_edge("expr + suffix", 5, "target", 5),))
        path = index.bfs_path(
            source_location=_span("app.py", 5),
            source_expr="expr",
            sink_location=_span("app.py", 5),
            sink_expr="target",
            exact_source=True,
        )
        assert path is None


class TestEquivalenceWithGraph:
    """The index built from a function's edges answers the same as the raw scan."""

    def test_index_over_full_graph(self) -> None:
        vfg = ValueFlowGraph(
            (
                _edge("request.args['q']", 5, "query", 5),
                _edge("query", 6, "sql", 6),
            )
        )
        index = FunctionFlowIndex(vfg.edges)
        path = index.bfs_path(
            source_location=_span("app.py", 5),
            source_expr="request.args['q']",
            sink_location=_span("app.py", 6),
            sink_expr="sql",
        )
        assert path is not None
        assert len(path) == 2
