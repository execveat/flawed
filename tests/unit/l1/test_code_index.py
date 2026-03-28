"""Tests for the CodeIndex API surface: collections, graphs, and entry point."""

from __future__ import annotations

from pathlib import Path

import pytest

from flawed._index import CodeIndex
from flawed._index._collections import (
    ClassCollection,
    DecoratorCollection,
    FunctionCollection,
)
from flawed._index._graphs import CallGraph, ControlFlowGraph, SymbolIndex, ValueFlowGraph
from flawed._index._types import (
    BranchCondition,
    CallEdge,
    CFGBlock,
    CFGEdge,
    ClassRecord,
    DecoratorFact,
    EdgeSource,
    ExtractionProvenance,
    FlowKind,
    FunctionKind,
    FunctionRecord,
    ResolutionStatus,
    SourceSpan,
    SymbolRef,
    ValueFlowEdge,
)

# -- Test helpers --------------------------------------------------------


def _span(file: str = "app.py", line: int = 1) -> SourceSpan:
    return SourceSpan(file=file, line=line, column=0, end_line=line, end_column=10)


def _prov() -> ExtractionProvenance:
    return ExtractionProvenance(producer="test", producer_version="0.0.1", artifact="")


def _fn(fqn: str, *, name: str = "", file: str = "app.py", line: int = 1, **kw):
    return FunctionRecord(
        fqn=fqn,
        name=name or fqn.rsplit(".", 1)[-1],
        file=file,
        line=line,
        params=(),
        decorator_names=kw.get("decorator_names", ()),
        decorator_fqns=kw.get("decorator_fqns", ()),
        kind=kw.get("kind", FunctionKind.TOP_LEVEL),
        is_method=kw.get("is_method", False),
        is_nested=kw.get("is_nested", False),
        is_async=kw.get("is_async", False),
        parent_class=kw.get("parent_class"),
        location=_span(file, line),
        provenance=_prov(),
    )


def _cls(fqn: str, *, name: str = "", file: str = "models.py", **kw):
    return ClassRecord(
        fqn=fqn,
        name=name or fqn.rsplit(".", 1)[-1],
        file=file,
        bases=kw.get("bases", ()),
        mro_chain=kw.get("mro_chain", ()),
        mro_complete=kw.get("mro_complete", True),
        method_names=kw.get("method_names", ()),
        class_var_names=kw.get("class_var_names", ()),
        is_abstract=kw.get("is_abstract", False),
        metaclass=kw.get("metaclass"),
        subclasses=kw.get("subclasses", ()),
        all_subclasses=kw.get("all_subclasses", ()),
        inherited_methods=kw.get("inherited_methods", ()),
        hierarchy_gaps=kw.get("hierarchy_gaps", ()),
        location=_span(file, 1),
        provenance=_prov(),
    )


def _edge(caller: str, callee: str, *, line: int = 1) -> CallEdge:
    return CallEdge(
        caller_fqn=caller,
        callee_fqn=callee,
        arguments=(),
        resolution=ResolutionStatus.RESOLVED,
        source=EdgeSource.AST,
        unresolved_reason=None,
        location=_span(line=line),
        provenance=_prov(),
    )


def _dec(name: str, target_fqn: str, *, fqn: str | None = None) -> DecoratorFact:
    return DecoratorFact(
        name=name,
        fqn=fqn,
        args=(),
        kwargs=(),
        target_fqn=target_fqn,
        application_order=0,
        location=_span(),
        provenance=_prov(),
    )


# =====================================================================
# CodeIndex.empty
# =====================================================================


class TestCodeIndexEmpty:
    def test_empty_factory(self):
        idx = CodeIndex.empty(Path("/tmp/test"))
        assert len(idx.functions) == 0
        assert len(idx.classes) == 0
        assert len(idx.errors) == 0
        assert idx.repo_root == Path("/tmp/test")

    def test_empty_call_graph(self):
        idx = CodeIndex.empty(Path("/tmp"))
        assert idx.call_graph.callees("x") == frozenset()
        assert idx.call_graph.callers("x") == frozenset()

    def test_empty_cfg(self):
        idx = CodeIndex.empty(Path("/tmp"))
        assert idx.cfg("x") is None

    def test_empty_dominance(self):
        idx = CodeIndex.empty(Path("/tmp"))
        assert idx.dominance("x") is None

    def test_empty_type_enrichment(self):
        idx = CodeIndex.empty(Path("/tmp"))
        assert idx.type_enrichment.facts == ()
        assert idx.type_enrichment.errors == ()


# =====================================================================
# FunctionCollection
# =====================================================================


class TestFunctionCollection:
    @pytest.fixture
    def fns(self):
        return FunctionCollection(
            (
                _fn("app.views.index", file="app/views.py", line=10),
                _fn(
                    "app.views.login",
                    file="app/views.py",
                    line=20,
                    decorator_names=("route",),
                    decorator_fqns=("flask.Flask.route",),
                ),
                _fn(
                    "app.models.User.save",
                    file="app/models.py",
                    line=5,
                    kind=FunctionKind.METHOD,
                    is_method=True,
                    parent_class="app.models.User",
                ),
                _fn("utils.helper", file="utils.py", line=1),
            )
        )

    def test_decorated_with_syntactic_dotted_name(self, fns):
        dotted = FunctionCollection(
            (
                _fn(
                    "app.views.index",
                    decorator_names=("app.route",),
                    decorator_fqns=("flask.Flask.route",),
                ),
            )
        )

        result = dotted.decorated_with("app.route")

        assert result.one().fqn == "app.views.index"

    def test_len(self, fns):
        assert len(fns) == 4

    def test_named(self, fns):
        result = fns.named("index")
        assert len(result) == 1
        assert result.first().fqn == "app.views.index"

    def test_with_fqn(self, fns):
        result = fns.with_fqn("app.views.login")
        assert len(result) == 1

    def test_by_fqn(self, fns):
        assert fns.by_fqn("app.views.index") is not None
        assert fns.by_fqn("nonexistent") is None

    def test_in_file(self, fns):
        result = fns.in_file("app/views.py")
        assert len(result) == 2

    def test_in_dir(self, fns):
        result = fns.in_dir("app/")
        assert len(result) == 3

    def test_methods(self, fns):
        result = fns.methods()
        assert len(result) == 1
        assert result.first().fqn == "app.models.User.save"

    def test_in_class(self, fns):
        result = fns.in_class("app.models.User")
        assert len(result) == 1

    def test_top_level(self, fns):
        result = fns.top_level()
        assert len(result) == 3

    def test_decorated_with_short(self, fns):
        result = fns.decorated_with("route")
        assert len(result) == 1
        assert result.first().fqn == "app.views.login"

    def test_decorated_with_fqn(self, fns):
        result = fns.decorated_with("flask.Flask.route")
        assert len(result) == 1

    def test_where(self, fns):
        result = fns.where(lambda f: "views" in f.file)
        assert len(result) == 2

    def test_chaining(self, fns):
        result = fns.in_dir("app/").methods()
        assert len(result) == 1

    def test_first_empty(self):
        assert FunctionCollection(()).first() is None

    def test_one_raises(self, fns):
        with pytest.raises(ValueError, match="expected exactly 1"):
            fns.one()

    def test_one_works(self, fns):
        result = fns.named("helper")
        assert result.one().fqn == "utils.helper"

    def test_exists(self, fns):
        assert fns.exists()
        assert not FunctionCollection(()).exists()

    def test_bool(self, fns):
        assert bool(fns)
        assert not bool(FunctionCollection(()))

    def test_iter(self, fns):
        fqns = [f.fqn for f in fns]
        assert len(fqns) == 4

    def test_getitem(self, fns):
        assert fns[0].fqn == "app.views.index"


# =====================================================================
# ClassCollection
# =====================================================================


class TestClassCollection:
    @pytest.fixture
    def classes(self):
        return ClassCollection(
            (
                _cls(
                    "app.models.Base",
                    subclasses=("app.models.User",),
                    all_subclasses=("app.models.User", "app.models.Admin"),
                ),
                _cls("app.models.User", bases=("app.models.Base",)),
                _cls("app.models.Admin", bases=("app.models.User",)),
            ),
            (
                _dec(
                    "dataclass",
                    "app.models.User",
                    fqn="dataclasses.dataclass",
                ),
                _dec(
                    "app.model_marker",
                    "app.models.Admin",
                    fqn="app.decorators.model_marker",
                ),
                _dec(
                    "dataclass",
                    "app.make_user",
                    fqn="dataclasses.dataclass",
                ),
            ),
        )

    def test_subclasses_of(self, classes):
        result = classes.subclasses_of("app.models.Base")
        assert len(result) == 2
        fqns = {c.fqn for c in result}
        assert fqns == {"app.models.User", "app.models.Admin"}

    def test_direct_subclasses_of(self, classes):
        result = classes.direct_subclasses_of("app.models.Base")
        assert len(result) == 1
        assert result.first().fqn == "app.models.User"

    def test_decorated_with_short_name(self, classes):
        result = classes.decorated_with("dataclass")

        assert [cls.fqn for cls in result] == ["app.models.User"]

    def test_decorated_with_fqn(self, classes):
        result = classes.decorated_with("app.decorators.model_marker")

        assert [cls.fqn for cls in result] == ["app.models.Admin"]

    def test_decorated_with_preserves_query_context_when_chained(self, classes):
        result = classes.named("User").decorated_with("dataclasses.dataclass")

        assert result.one().fqn == "app.models.User"


# =====================================================================
# DecoratorCollection
# =====================================================================


class TestDecoratorCollection:
    @pytest.fixture
    def decs(self):
        return DecoratorCollection(
            (
                _dec("route", "app.views.index", fqn="flask.Flask.route"),
                _dec("login_required", "app.views.index", fqn="flask_login.login_required"),
                _dec("route", "app.views.login", fqn="flask.Flask.route"),
            )
        )

    def test_named(self, decs):
        assert len(decs.named("route")) == 2

    def test_with_fqn(self, decs):
        assert len(decs.with_fqn("flask_login.login_required")) == 1

    def test_on_function(self, decs):
        assert len(decs.on_function("app.views.index")) == 2

    def test_on_function_named(self, decs):
        assert len(decs.on_function_named("login")) == 1


# =====================================================================
# CallGraph
# =====================================================================


class TestCallGraph:
    @pytest.fixture
    def cg(self):
        return CallGraph(
            (
                _edge("app.main", "app.views.index"),
                _edge("app.views.index", "app.models.get_user"),
                _edge("app.views.index", "app.utils.helper"),
                _edge("app.views.login", "app.models.get_user"),
            )
        )

    def test_callees(self, cg):
        assert cg.callees("app.views.index") == {"app.models.get_user", "app.utils.helper"}

    def test_callers(self, cg):
        assert cg.callers("app.models.get_user") == {"app.views.index", "app.views.login"}

    def test_reachable_from(self, cg):
        reachable = cg.reachable_from("app.main")
        assert "app.views.index" in reachable
        assert "app.models.get_user" in reachable
        assert "app.utils.helper" in reachable

    def test_reachable_from_max_depth(self, cg):
        reachable = cg.reachable_from("app.main", max_depth=1)
        assert reachable == {"app.views.index"}

    def test_edges_from(self, cg):
        edges = cg.edges_from("app.views.index")
        assert len(edges) == 2

    def test_edges_to(self, cg):
        edges = cg.edges_to("app.models.get_user")
        assert len(edges) == 2

    def test_edge_specific(self, cg):
        e = cg.edge("app.main", "app.views.index")
        assert e is not None
        assert e.caller_fqn == "app.main"

    def test_edge_missing(self, cg):
        assert cg.edge("app.main", "nonexistent") is None

    def test_nonexistent_node(self, cg):
        assert cg.callees("nonexistent") == frozenset()
        assert cg.callers("nonexistent") == frozenset()
        assert cg.reachable_from("nonexistent") == frozenset()

    def test_contains(self, cg):
        assert "app.main" in cg
        assert "nonexistent" not in cg


# =====================================================================
# ControlFlowGraph
# =====================================================================


class TestControlFlowGraph:
    @pytest.fixture
    def cfg(self):
        blocks = (
            CFGBlock(
                id=0,
                statements=(_span(line=1),),
                successors=(1, 2),
                predecessors=(),
                condition_expr="x > 0",
            ),
            CFGBlock(
                id=1,
                statements=(_span(line=3),),
                successors=(3,),
                predecessors=(0,),
                condition_expr=None,
            ),
            CFGBlock(
                id=2,
                statements=(_span(line=5),),
                successors=(3,),
                predecessors=(0,),
                condition_expr=None,
            ),
            CFGBlock(
                id=3,
                statements=(_span(line=7),),
                successors=(),
                predecessors=(1, 2),
                condition_expr=None,
            ),
        )
        edges = (
            CFGEdge(source_id=0, target_id=1, label="true", is_exceptional=False),
            CFGEdge(source_id=0, target_id=2, label="false", is_exceptional=False),
            CFGEdge(source_id=1, target_id=3, label="fallthrough", is_exceptional=False),
            CFGEdge(source_id=2, target_id=3, label="fallthrough", is_exceptional=False),
        )
        return ControlFlowGraph(blocks, edges)

    def test_blocks(self, cfg):
        assert len(cfg.blocks) == 4

    def test_entry(self, cfg):
        assert cfg.entry is not None
        assert cfg.entry.id == 0

    def test_exits(self, cfg):
        exits = cfg.exits
        assert len(exits) == 1
        assert exits[0].id == 3

    def test_successors(self, cfg):
        succs = cfg.successors(0)
        assert len(succs) == 2

    def test_predecessors(self, cfg):
        preds = cfg.predecessors(3)
        assert len(preds) == 2

    def test_dominates(self, cfg):
        # Block 0 dominates everything
        assert cfg.dominates(_span(line=1), _span(line=3))
        assert cfg.dominates(_span(line=1), _span(line=7))
        # Block 1 does NOT dominate block 3 (block 2 also reaches 3)
        assert not cfg.dominates(_span(line=3), _span(line=7))

    def test_block_for(self, cfg):
        b = cfg.block_for(_span(line=5))
        assert b is not None
        assert b.id == 2

    def test_block_for_missing(self, cfg):
        assert cfg.block_for(_span(line=99)) is None

    def test_precedes_same_block(self, cfg):
        loc_a = SourceSpan(file="app.py", line=1, column=0, end_line=1, end_column=5)
        loc_b = SourceSpan(file="app.py", line=1, column=6, end_line=1, end_column=10)
        assert cfg.precedes(loc_a, loc_b)

    def test_paths_between(self, cfg):
        paths = cfg.paths_between(_span(line=1), _span(line=7))
        assert len(paths) == 2
        assert [tuple(block.id for block in path.blocks) for path in paths] == [
            (0, 1, 3),
            (0, 2, 3),
        ]

    def test_paths_between_records_branch_conditions(self):
        condition = _span(line=1)
        blocks = (
            CFGBlock(
                id=0,
                statements=(condition,),
                successors=(1, 2),
                predecessors=(),
                condition_expr="x > 0",
                condition_location=condition,
            ),
            CFGBlock(
                id=1,
                statements=(_span(line=3),),
                successors=(3,),
                predecessors=(0,),
                condition_expr=None,
            ),
            CFGBlock(
                id=2,
                statements=(_span(line=5),),
                successors=(3,),
                predecessors=(0,),
                condition_expr=None,
            ),
            CFGBlock(
                id=3,
                statements=(_span(line=7),),
                successors=(),
                predecessors=(1, 2),
                condition_expr=None,
            ),
        )
        cfg = ControlFlowGraph(
            blocks,
            (
                CFGEdge(source_id=0, target_id=1, label="true", is_exceptional=False),
                CFGEdge(source_id=0, target_id=2, label="false", is_exceptional=False),
                CFGEdge(source_id=1, target_id=3, label="fallthrough", is_exceptional=False),
                CFGEdge(source_id=2, target_id=3, label="fallthrough", is_exceptional=False),
            ),
        )

        true_path = cfg.paths_between(condition, _span(line=3))
        false_path = cfg.paths_between(condition, _span(line=5))

        assert len(true_path) == 1
        assert true_path[0].conditions == (
            BranchCondition(condition_expr="x > 0", direction=True, location=condition),
        )
        assert len(false_path) == 1
        assert false_path[0].conditions == (
            BranchCondition(condition_expr="x > 0", direction=False, location=condition),
        )

    def test_reachable_between(self, cfg):
        assert cfg.reachable_between(_span(line=1), _span(line=7))
        assert cfg.reachable_between(_span(line=1), _span(line=1))
        assert not cfg.reachable_between(_span(line=3), _span(line=5))
        assert not cfg.reachable_between(_span(line=99), _span(line=7))

    def test_reachable_between_terminates_on_loop(self):
        blocks = (
            CFGBlock(
                id=0,
                statements=(_span(line=1),),
                successors=(1,),
                predecessors=(1,),
                condition_expr="keep_going",
            ),
            CFGBlock(
                id=1,
                statements=(_span(line=2),),
                successors=(0, 2),
                predecessors=(0,),
                condition_expr=None,
            ),
            CFGBlock(
                id=2,
                statements=(_span(line=3),),
                successors=(),
                predecessors=(1,),
                condition_expr=None,
            ),
        )
        cfg = ControlFlowGraph(
            blocks,
            (
                CFGEdge(source_id=0, target_id=1, label="true", is_exceptional=False),
                CFGEdge(source_id=1, target_id=0, label="back", is_exceptional=False),
                CFGEdge(source_id=1, target_id=2, label="false", is_exceptional=False),
            ),
        )

        assert cfg.reachable_between(_span(line=2), _span(line=3))
        assert not cfg.reachable_between(_span(line=3), _span(line=2))

    def test_unreachable_block_is_not_dominated_by_entry(self):
        blocks = (
            CFGBlock(
                id=0,
                statements=(_span(line=1),),
                successors=(1,),
                predecessors=(),
                condition_expr=None,
            ),
            CFGBlock(
                id=1,
                statements=(_span(line=2),),
                successors=(),
                predecessors=(0,),
                condition_expr=None,
            ),
            CFGBlock(
                id=2,
                statements=(_span(line=3),),
                successors=(),
                predecessors=(),
                condition_expr=None,
            ),
        )
        cfg = ControlFlowGraph(
            blocks,
            (CFGEdge(source_id=0, target_id=1, label="fallthrough", is_exceptional=False),),
        )

        assert not cfg.dominates(_span(line=1), _span(line=3))
        assert not cfg.reachable_between(_span(line=1), _span(line=3))


# =====================================================================
# ValueFlowGraph
# =====================================================================


class TestValueFlowGraph:
    @pytest.fixture
    def vfg(self):
        return ValueFlowGraph(
            (
                ValueFlowEdge(
                    source_expr="request.args",
                    source_location=_span(line=10),
                    target_expr="q",
                    target_location=_span(line=11),
                    kind=FlowKind.ASSIGN,
                    containing_function_fqn="app.views.search",
                    provenance=_prov(),
                ),
                ValueFlowEdge(
                    source_expr="q",
                    source_location=_span(line=11),
                    target_expr="query",
                    target_location=_span(line=12),
                    kind=FlowKind.ALIAS,
                    containing_function_fqn="app.views.search",
                    provenance=_prov(),
                ),
            )
        )

    def test_flows_from(self, vfg):
        edges = vfg.flows_from(_span(line=10))
        assert len(edges) == 1

    def test_flows_to(self, vfg):
        edges = vfg.flows_to(_span(line=11))
        assert len(edges) == 1

    def test_connected(self, vfg):
        assert vfg.connected(_span(line=10), _span(line=12))
        assert not vfg.connected(_span(line=12), _span(line=10))

    def test_connected_same_existing_location(self, vfg):
        assert vfg.connected(_span(line=10), _span(line=10))

    def test_connected_preserves_chain_and_cycle_behavior(self):
        vfg = ValueFlowGraph(
            (
                ValueFlowEdge(
                    source_expr="a",
                    source_location=_span(line=20),
                    target_expr="b",
                    target_location=_span(line=21),
                    kind=FlowKind.ASSIGN,
                    containing_function_fqn="app.views.search",
                    provenance=_prov(),
                ),
                ValueFlowEdge(
                    source_expr="b",
                    source_location=_span(line=21),
                    target_expr="c",
                    target_location=_span(line=22),
                    kind=FlowKind.ALIAS,
                    containing_function_fqn="app.views.search",
                    provenance=_prov(),
                ),
                ValueFlowEdge(
                    source_expr="c",
                    source_location=_span(line=22),
                    target_expr="b",
                    target_location=_span(line=21),
                    kind=FlowKind.ALIAS,
                    containing_function_fqn="app.views.search",
                    provenance=_prov(),
                ),
            )
        )

        assert vfg.connected(_span(line=20), _span(line=22))
        assert vfg.connected(_span(line=22), _span(line=21))
        assert not vfg.connected(_span(line=22), _span(line=20))


# =====================================================================
# SymbolIndex
# =====================================================================


class TestSymbolIndex:
    @pytest.fixture
    def si(self):
        return SymbolIndex(
            (
                SymbolRef(
                    name="request",
                    fqn="flask.globals.request",
                    resolution=ResolutionStatus.RESOLVED,
                    location=_span(line=5),
                    provenance=_prov(),
                ),
                SymbolRef(
                    name="unknown_thing",
                    fqn=None,
                    resolution=ResolutionStatus.UNRESOLVED,
                    location=_span(line=8),
                    provenance=_prov(),
                ),
            )
        )

    def test_resolve(self, si):
        assert si.resolve("request", "app.py") == "flask.globals.request"
        assert si.resolve("nonexistent", "app.py") is None

    def test_fqn_exists(self, si):
        assert si.fqn_exists("flask.globals.request")
        assert not si.fqn_exists("nonexistent")

    def test_usages(self, si):
        locs = si.usages("flask.globals.request")
        assert len(locs) == 1
        assert locs[0].line == 5

    def test_unresolved(self, si):
        unresolved = si.unresolved()
        assert len(unresolved) == 1
        assert unresolved.first().name == "unknown_thing"


# =====================================================================
# CodeIndex integration
# =====================================================================


class TestCodeIndexIntegration:
    @pytest.fixture
    def idx(self):
        return CodeIndex(
            repo_root=Path("/tmp/test-repo"),
            functions=(
                _fn(
                    "app.index",
                    decorator_names=("route",),
                    decorator_fqns=("flask.Flask.route",),
                ),
                _fn("app.login"),
            ),
            classes=(_cls("app.User"),),
            decorators=(_dec("route", "app.index", fqn="flask.Flask.route"),),
            imports=(),
            attributes=(),
            call_edges=(_edge("app.index", "app.login"),),
            cfgs={},
            value_flow_edges=(),
            symbol_refs=(),
            errors=(),
            provenance=_prov(),
        )

    def test_functions(self, idx):
        assert len(idx.functions) == 2
        assert idx.functions.decorated_with("route").first().fqn == "app.index"

    def test_classes(self, idx):
        assert len(idx.classes) == 1

    def test_call_graph(self, idx):
        assert idx.call_graph.callees("app.index") == {"app.login"}

    def test_decorators(self, idx):
        assert len(idx.decorators) == 1
        assert idx.decorators.on_function("app.index").first().name == "route"

    def test_repr(self, idx):
        r = repr(idx)
        assert "2 functions" in r
        assert "1 classes" in r
