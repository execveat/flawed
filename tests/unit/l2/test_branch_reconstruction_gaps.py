"""Tests for branch reconstruction failure gap classification."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from flawed._index._graphs import ControlFlowGraph
from flawed._index._types import CFGBlock, SourceSpan
from flawed._semantic._branch import attach_condition_branch_scopes, build_method_branch_scopes
from flawed._semantic._collections import ConcreteDecoratorCollection, ConcreteFunctionCollection
from flawed._semantic._condition_conversion import ConcreteStructuralCondition
from flawed._semantic._enriched import EnrichedFunction, EnrichedRoute
from flawed.conditions import ConditionKind
from flawed.core import GapKind, Location, Provenance
from flawed.function import FunctionKind
from flawed.route import GET, POST

if TYPE_CHECKING:
    from flawed._index import CodeIndex


_EMPTY_FUNCTIONS = ConcreteFunctionCollection(())
_PROVENANCE = Provenance(source_layer="L2", interpreter="test", confidence=1.0)


class _IndexWithCfg:
    def __init__(self, graph: ControlFlowGraph) -> None:
        self._graph = graph

    def cfg(self, fqn: str) -> ControlFlowGraph:
        return self._graph


def test_method_branch_reconstruction_failure_uses_cfg_reconstruction_gap() -> None:
    function = _function()
    route = _route(function)
    idx = cast("CodeIndex", _IndexWithCfg(_graph_without_branch_edges()))
    condition = _condition(function)

    branches, gaps = build_method_branch_scopes(
        route,
        idx,
        {function.fqn: function},
        input_reads_by_function={},
        effects_by_function={},
        sinks_by_function={},
        safe_generated_urls_by_function={},
        conditions_by_function={function.fqn: [condition]},
        call_sites_by_caller={},
        callee_graph={},
    )

    assert branches == {}
    assert {gap.kind for gap in gaps} == {GapKind.CFG_RECONSTRUCTION_FAILURE}
    assert {gap.origin_phase for gap in gaps} == {"branch_reconstruction"}
    assert {gap.affected_function for gap in gaps} == {function.fqn}
    assert {POST.value, GET.value} <= {gap.message.split()[3] for gap in gaps}


def test_condition_branch_reconstruction_failure_uses_cfg_reconstruction_gap() -> None:
    function = _function()
    idx = cast("CodeIndex", _IndexWithCfg(_graph_without_branch_edges()))
    condition = _condition(function)

    gaps = attach_condition_branch_scopes(
        idx,
        {function.fqn: function},
        input_reads_by_function={},
        effects_by_function={},
        sinks_by_function={},
        safe_generated_urls_by_function={},
        conditions_by_function={function.fqn: [condition]},
        call_sites_by_caller={},
        callee_graph={},
    )

    assert {gap.kind for gap in gaps} == {GapKind.CFG_RECONSTRUCTION_FAILURE}
    assert {gap.origin_phase for gap in gaps} == {"branch_reconstruction"}
    assert {gap.affected_function for gap in gaps} == {function.fqn}
    assert condition.true_branch.gaps == (gaps[0],)
    assert condition.false_branch.gaps == (gaps[1],)


def _function() -> EnrichedFunction:
    function = EnrichedFunction(
        fqn="app.handler",
        name="handler",
        params=(),
        kind=FunctionKind.TOP_LEVEL,
        parent_class=None,
        parent_function=None,
        location=Location(file="app.py", line=1, column=0, end_line=5, end_column=0),
        provenance=_PROVENANCE,
    )
    object.__setattr__(function, "_decorators", ConcreteDecoratorCollection(()))
    object.__setattr__(function, "_gaps", ())
    object.__setattr__(function, "_calls", _EMPTY_FUNCTIONS)
    object.__setattr__(function, "_called_by", _EMPTY_FUNCTIONS)
    return function


def _route(function: EnrichedFunction) -> EnrichedRoute:
    route = EnrichedRoute(
        endpoint="handler",
        url_rule="/handler",
        methods=frozenset({GET, POST}),
        handler=function,
        group=None,
        location=function.location,
        provenance=_PROVENANCE,
    )
    object.__setattr__(route, "_gaps", ())
    return route


def _condition(function: EnrichedFunction) -> ConcreteStructuralCondition:
    return ConcreteStructuralCondition(
        expression='request.method == "POST"',
        location=Location(file="app.py", line=2, column=7, end_line=2, end_column=31),
        function=function,
        kind=ConditionKind.COMPARISON,
        provenance=_PROVENANCE,
    )


def _graph_without_branch_edges() -> ControlFlowGraph:
    condition_span = SourceSpan(
        file="app.py",
        line=2,
        column=7,
        end_line=2,
        end_column=31,
    )
    return ControlFlowGraph(
        blocks=(
            CFGBlock(
                id=0,
                statements=(),
                successors=(),
                predecessors=(),
                condition_expr='request.method == "POST"',
                condition_location=condition_span,
            ),
        ),
        edges=(),
    )
