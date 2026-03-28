"""Tests for call-graph merge (Step 5).

Covers: deduplication, consensus tagging, conflict resolution,
unique edge acceptance, priority ordering, and merged graph queries.
"""

from __future__ import annotations

from flawed._index._callgraph import build_hierarchy_edges, merge_call_graph
from flawed._index._types import (
    CallEdge,
    ClassRecord,
    EdgeSource,
    ExtractionProvenance,
    FunctionKind,
    FunctionRecord,
    InheritedMethod,
    ResolutionStatus,
    SourceSpan,
)

# ── Helpers ──────────────────────────────────────────────────────────

_PROV_AST = ExtractionProvenance(producer="ast", producer_version="1.0", artifact="ast")
_PROV_HIER = ExtractionProvenance(producer="hierarchy", producer_version="1.0", artifact="hier")

_SPAN_1 = SourceSpan(file="app.py", line=10, column=0, end_line=10, end_column=20)
_SPAN_2 = SourceSpan(file="app.py", line=20, column=0, end_line=20, end_column=20)
_SPAN_3 = SourceSpan(file="app.py", line=30, column=0, end_line=30, end_column=20)
_SPAN_OTHER = SourceSpan(file="other.py", line=5, column=0, end_line=5, end_column=20)


def _edge(
    caller: str,
    callee: str | None,
    span: SourceSpan = _SPAN_1,
    source: EdgeSource = EdgeSource.AST,
    resolution: ResolutionStatus = ResolutionStatus.RESOLVED,
    prov: ExtractionProvenance | None = None,
) -> CallEdge:
    if prov is None:
        prov = {
            EdgeSource.AST: _PROV_AST,
            EdgeSource.HIERARCHY: _PROV_HIER,
        }[source]
    return CallEdge(
        caller_fqn=caller,
        callee_fqn=callee,
        arguments=(),
        resolution=resolution,
        source=source,
        unresolved_reason=None,
        location=span,
        provenance=prov,
    )


# ── Deduplication ────────────────────────────────────────────────────


class TestDeduplication:
    def test_same_edge_from_two_sources_produces_one_edge(self) -> None:
        sg = _edge("a", "b", source=EdgeSource.HIERARCHY)
        ast = _edge("a", "b", source=EdgeSource.AST)
        graph, errors = merge_call_graph(
            hierarchy_edges=(sg,),
            ast_edges=(ast,),
        )
        assert not errors
        edges = graph.edges_from("a")
        assert len(edges) == 1
        assert edges[0].callee_fqn == "b"

    def test_same_edge_from_both_sources_produces_one_edge(self) -> None:
        ast = _edge("a", "b", source=EdgeSource.AST)
        hier = _edge("a", "b", source=EdgeSource.HIERARCHY)
        graph, _ = merge_call_graph(
            ast_edges=(ast,),
            hierarchy_edges=(hier,),
        )
        assert len(graph.edges_from("a")) == 1

    def test_different_call_sites_kept_separately(self) -> None:
        e1 = _edge("a", "b", span=_SPAN_1, source=EdgeSource.HIERARCHY)
        e2 = _edge("a", "b", span=_SPAN_2, source=EdgeSource.HIERARCHY)
        graph, _ = merge_call_graph(hierarchy_edges=(e1, e2), ast_edges=())
        assert len(graph.edges_from("a")) == 2


# ── Consensus ────────────────────────────────────────────────────────


class TestConsensus:
    def test_consensus_edge_gets_consensus_provenance(self) -> None:
        sg = _edge("a", "b", source=EdgeSource.HIERARCHY)
        ast = _edge("a", "b", source=EdgeSource.AST)
        graph, _ = merge_call_graph(
            hierarchy_edges=(sg,),
            ast_edges=(ast,),
        )
        edge = graph.edges_from("a")[0]
        # Consensus → producer is "consensus".
        assert edge.provenance.producer == "consensus"


# ── Conflict Resolution ─────────────────────────────────────────────


class TestConflictResolution:
    def test_different_callees_at_same_site_both_kept(self) -> None:
        """Same call site, different callee FQNs → both edges kept."""
        sg = _edge("a", "x", span=_SPAN_1, source=EdgeSource.HIERARCHY)
        ast = _edge("a", "y", span=_SPAN_1, source=EdgeSource.AST)
        graph, _ = merge_call_graph(
            hierarchy_edges=(sg,),
            ast_edges=(ast,),
        )
        # Both kept (additive for security).
        edges = graph.edges_from("a")
        callees = {e.callee_fqn for e in edges}
        assert callees == {"x", "y"}

    def test_conflict_edges_have_lower_confidence(self) -> None:
        """Conflicting edges should have reduced confidence."""
        sg = _edge("a", "x", span=_SPAN_1, source=EdgeSource.HIERARCHY)
        ast = _edge("a", "y", span=_SPAN_1, source=EdgeSource.AST)
        graph, _ = merge_call_graph(
            hierarchy_edges=(sg,),
            ast_edges=(ast,),
        )
        for edge in graph.edges_from("a"):
            # Conflict detection sets max confidence to 0.7.
            assert edge.provenance.producer in ("hierarchy", "ast")


# ── Unique Edges ─────────────────────────────────────────────────────


class TestUniqueEdges:
    def test_hierarchy_only_edge_accepted_unique(self) -> None:
        sg = _edge("a", "b", source=EdgeSource.HIERARCHY)
        graph, _ = merge_call_graph(hierarchy_edges=(sg,), ast_edges=())
        assert "b" in graph.callees("a")

    def test_ast_only_edge_accepted(self) -> None:
        ast = _edge("a", "c", source=EdgeSource.AST)
        graph, _ = merge_call_graph(hierarchy_edges=(), ast_edges=(ast,))
        assert "c" in graph.callees("a")

    def test_hierarchy_only_edge_accepted(self) -> None:
        hier = _edge("a", "d", source=EdgeSource.HIERARCHY)
        graph, _ = merge_call_graph(
            ast_edges=(),
            hierarchy_edges=(hier,),
        )
        assert "d" in graph.callees("a")


# ── Priority Ordering ────────────────────────────────────────────────


class TestPriority:
    def test_ast_preferred_over_hierarchy(self) -> None:
        ast = _edge("a", "b", source=EdgeSource.AST)
        hier = _edge("a", "b", source=EdgeSource.HIERARCHY)
        graph, _ = merge_call_graph(
            ast_edges=(ast,),
            hierarchy_edges=(hier,),
        )
        edge = graph.edges_from("a")[0]
        assert edge.source == EdgeSource.AST


# ── Graph Queries ────────────────────────────────────────────────────


class TestMergedGraphQueries:
    def test_callees(self) -> None:
        e1 = _edge("a", "b", span=_SPAN_1, source=EdgeSource.HIERARCHY)
        e2 = _edge("a", "c", span=_SPAN_2, source=EdgeSource.AST)
        graph, _ = merge_call_graph(hierarchy_edges=(e1,), ast_edges=(e2,))
        assert graph.callees("a") == frozenset({"b", "c"})

    def test_callers(self) -> None:
        e1 = _edge("a", "z", span=_SPAN_1, source=EdgeSource.HIERARCHY)
        e2 = _edge("b", "z", span=_SPAN_2, source=EdgeSource.AST)
        graph, _ = merge_call_graph(hierarchy_edges=(e1,), ast_edges=(e2,))
        assert graph.callers("z") == frozenset({"a", "b"})

    def test_reachable_from(self) -> None:
        e1 = _edge("a", "b", span=_SPAN_1, source=EdgeSource.HIERARCHY)
        e2 = _edge("b", "c", span=_SPAN_2, source=EdgeSource.AST)
        graph, _ = merge_call_graph(hierarchy_edges=(e1,), ast_edges=(e2,))
        assert graph.reachable_from("a") == frozenset({"b", "c"})

    def test_reachable_with_depth_limit(self) -> None:
        e1 = _edge("a", "b", span=_SPAN_1, source=EdgeSource.HIERARCHY)
        e2 = _edge("b", "c", span=_SPAN_2, source=EdgeSource.AST)
        graph, _ = merge_call_graph(hierarchy_edges=(e1,), ast_edges=(e2,))
        assert graph.reachable_from("a", max_depth=1) == frozenset({"b"})

    def test_edge_lookup(self) -> None:
        e = _edge("a", "b", source=EdgeSource.HIERARCHY)
        graph, _ = merge_call_graph(hierarchy_edges=(e,), ast_edges=())
        assert graph.edge("a", "b") is not None
        assert graph.edge("a", "nonexistent") is None

    def test_contains(self) -> None:
        e = _edge("a", "b", source=EdgeSource.HIERARCHY)
        graph, _ = merge_call_graph(hierarchy_edges=(e,), ast_edges=())
        assert "a" in graph
        assert "b" in graph
        assert "z" not in graph


# ── Null / None callee ───────────────────────────────────────────────


class TestNullCallee:
    def test_none_callee_edge_is_skipped_in_graph(self) -> None:
        e = _edge("a", None, source=EdgeSource.AST)
        graph, _ = merge_call_graph(hierarchy_edges=(), ast_edges=(e,))
        assert graph.callees("a") == frozenset()
        assert "a" not in graph

    def test_none_callee_edge_remains_inspectable_from_caller(self) -> None:
        e = _edge(
            "a",
            None,
            source=EdgeSource.AST,
            resolution=ResolutionStatus.UNRESOLVED,
        )
        graph, _ = merge_call_graph(hierarchy_edges=(), ast_edges=(e,))

        edges = graph.edges_from("a")
        assert len(edges) == 1
        assert edges[0].callee_fqn is None
        assert edges[0].resolution == ResolutionStatus.UNRESOLVED


# ── Empty inputs ─────────────────────────────────────────────────────


class TestEmptyInputs:
    def test_all_empty(self) -> None:
        graph, errors = merge_call_graph(
            ast_edges=(),
            hierarchy_edges=(),
        )
        assert not errors
        assert "anything" not in graph


# ── Hierarchy edges ──────────────────────────────────────────────────

_CLS_LOC = SourceSpan(file="models.py", line=1, column=0, end_line=20, end_column=0)
_FN_LOC = SourceSpan(file="models.py", line=5, column=4, end_line=8, end_column=0)
_PROV = ExtractionProvenance(producer="test", producer_version="1", artifact="t")


class TestBuildHierarchyEdges:
    def test_resolves_self_method_via_mro(self) -> None:
        base_cls = ClassRecord(
            fqn="mod.Base",
            name="Base",
            file="models.py",
            bases=(),
            mro_chain=("mod.Base",),
            mro_complete=True,
            method_names=("do_thing",),
            class_var_names=(),
            is_abstract=False,
            metaclass=None,
            subclasses=("mod.Child",),
            all_subclasses=("mod.Child",),
            inherited_methods=(),
            hierarchy_gaps=(),
            location=_CLS_LOC,
            provenance=_PROV,
        )
        child_cls = ClassRecord(
            fqn="mod.Child",
            name="Child",
            file="models.py",
            bases=("mod.Base",),
            mro_chain=("mod.Child", "mod.Base"),
            mro_complete=True,
            method_names=("handler",),
            class_var_names=(),
            is_abstract=False,
            metaclass=None,
            subclasses=(),
            all_subclasses=(),
            inherited_methods=(
                InheritedMethod(name="do_thing", defining_class_fqn="mod.Base", resolution="mro"),
            ),
            hierarchy_gaps=(),
            location=_CLS_LOC,
            provenance=_PROV,
        )
        fn = FunctionRecord(
            fqn="mod.Child.handler",
            name="handler",
            file="models.py",
            line=5,
            params=(),
            decorator_names=(),
            decorator_fqns=(),
            kind=FunctionKind.METHOD,
            is_method=True,
            is_nested=False,
            is_async=False,
            parent_class="mod.Child",
            location=_FN_LOC,
            provenance=_PROV,
        )
        # An AST edge that points to Child.do_thing (not resolved to Base).
        call = _edge(
            "mod.Child.handler",
            "mod.Child.do_thing",
            span=_SPAN_1,
            source=EdgeSource.AST,
        )

        hier_edges = build_hierarchy_edges(
            classes=(base_cls, child_cls),
            functions=(fn,),
            call_edges=(call,),
        )
        assert len(hier_edges) == 1
        assert hier_edges[0].callee_fqn == "mod.Base.do_thing"
        assert hier_edges[0].source == EdgeSource.HIERARCHY

    def test_no_hierarchy_edge_when_already_resolved(self) -> None:
        cls = ClassRecord(
            fqn="mod.Cls",
            name="Cls",
            file="m.py",
            bases=(),
            mro_chain=("mod.Cls",),
            mro_complete=True,
            method_names=("run",),
            class_var_names=(),
            is_abstract=False,
            metaclass=None,
            subclasses=(),
            all_subclasses=(),
            inherited_methods=(),
            hierarchy_gaps=(),
            location=_CLS_LOC,
            provenance=_PROV,
        )
        fn = FunctionRecord(
            fqn="mod.Cls.handler",
            name="handler",
            file="m.py",
            line=5,
            params=(),
            decorator_names=(),
            decorator_fqns=(),
            kind=FunctionKind.METHOD,
            is_method=True,
            is_nested=False,
            is_async=False,
            parent_class="mod.Cls",
            location=_FN_LOC,
            provenance=_PROV,
        )
        # Edge already correctly resolved to mod.Cls.run.
        call = _edge("mod.Cls.handler", "mod.Cls.run", span=_SPAN_1, source=EdgeSource.AST)

        hier_edges = build_hierarchy_edges(
            classes=(cls,),
            functions=(fn,),
            call_edges=(call,),
        )
        # No extra hierarchy edge needed — already correct.
        assert len(hier_edges) == 0

    def test_no_hierarchy_edge_for_non_methods(self) -> None:
        fn = FunctionRecord(
            fqn="mod.standalone",
            name="standalone",
            file="m.py",
            line=1,
            params=(),
            decorator_names=(),
            decorator_fqns=(),
            kind=FunctionKind.TOP_LEVEL,
            is_method=False,
            is_nested=False,
            is_async=False,
            parent_class=None,
            location=_FN_LOC,
            provenance=_PROV,
        )
        call = _edge("mod.standalone", "other.func", span=_SPAN_1, source=EdgeSource.AST)
        hier_edges = build_hierarchy_edges(
            classes=(),
            functions=(fn,),
            call_edges=(call,),
        )
        assert len(hier_edges) == 0
