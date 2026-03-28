"""Tests for the intra-function value-flow extraction (Step 6)."""

from __future__ import annotations

from flawed._index._graphs import ValueFlowGraph
from flawed._index._types import (
    AccessKind,
    AliasFact,
    AliasMechanism,
    AssignmentFact,
    AssignmentKind,
    AttributeAccess,
    CallArgument,
    CallEdge,
    ComprehensionBindingFact,
    EdgeSource,
    ExtractionProvenance,
    FlowKind,
    FunctionKind,
    FunctionRecord,
    Parameter,
    ParameterKind,
    ResolutionStatus,
    ReturnFact,
    SourceSpan,
    YieldFact,
)
from flawed._index._valueflow import extract_value_flow

_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="test")


def _span(line: int) -> SourceSpan:
    return SourceSpan(file="test.py", line=line, column=0, end_line=line, end_column=10)


def _assignment(
    target: str, value: str, line_target: int, line_value: int, fn_fqn: str | None = "mod.fn"
) -> AssignmentFact:
    return AssignmentFact(
        target=target,
        target_location=_span(line_target),
        value_expression=value,
        value_location=_span(line_value),
        kind=AssignmentKind.SIMPLE,
        containing_function_fqn=fn_fqn,
    )


def _alias(original: str, alias: str, line: int) -> AliasFact:
    return AliasFact(
        original_fqn=original,
        alias_name=alias,
        mechanism=AliasMechanism.IMPORT_ALIAS,
        location=_span(line),
    )


def _argument(
    expression: str,
    line: int,
    *,
    position: int | None = 0,
    keyword: str | None = None,
) -> CallArgument:
    return CallArgument(
        position=position,
        keyword=keyword,
        expression=expression,
        location=_span(line),
    )


def _call_edge(
    *,
    caller_fqn: str = "mod.run",
    callee_fqn: str | None = "mod.helper",
    arguments: tuple[CallArgument, ...],
    line: int = 20,
    call_expression: str | None = "helper",
    unresolved_reason: str | None = None,
) -> CallEdge:
    return CallEdge(
        caller_fqn=caller_fqn,
        callee_fqn=callee_fqn,
        arguments=arguments,
        resolution=ResolutionStatus.RESOLVED if callee_fqn else ResolutionStatus.UNRESOLVED,
        source=EdgeSource.AST,
        unresolved_reason=unresolved_reason,
        location=_span(line),
        provenance=_PROV,
        call_expression=call_expression,
    )


def _function(fqn: str, params: tuple[Parameter, ...] = ()) -> FunctionRecord:
    return FunctionRecord(
        fqn=fqn,
        name=fqn.rsplit(".", maxsplit=1)[-1],
        file="test.py",
        line=1,
        params=params,
        decorator_names=(),
        decorator_fqns=(),
        kind=FunctionKind.TOP_LEVEL,
        is_method=False,
        is_nested=False,
        is_async=False,
        parent_class=None,
        location=_span(1),
        provenance=_PROV,
    )


def _param(name: str, default: str | None = None, line: int = 1) -> Parameter:
    return Parameter(
        name=name,
        annotation=None,
        default=default,
        kind=ParameterKind.POSITIONAL_OR_KEYWORD,
        position=0,
        location=_span(line),
    )


def _return_fact(
    expression: str | None,
    line: int,
    *,
    fn_fqn: str = "mod.helper",
) -> ReturnFact:
    return ReturnFact(
        expression=expression,
        expression_location=_span(line) if expression is not None else None,
        statement_location=_span(line),
        containing_function_fqn=fn_fqn,
        provenance=_PROV,
    )


def _comprehension_binding(
    target: str,
    iterable: str,
    line: int,
    *,
    fn_fqn: str | None = "mod.collect",
) -> ComprehensionBindingFact:
    return ComprehensionBindingFact(
        target=target,
        target_location=_span(line),
        iterable_expression=iterable,
        iterable_location=_span(line),
        comprehension_expr=f"[... for {target} in {iterable}]",
        comprehension_location=_span(line),
        containing_function_fqn=fn_fqn,
        provenance=_PROV,
    )


class TestAssignmentEdges:
    def test_simple_assignment(self) -> None:
        edges, errors = extract_value_flow(
            assignments=(_assignment("x", "1 + 2", 5, 5),),
            aliases=(),
            functions=(),
        )
        assert len(edges) == 1
        assert edges[0].kind == FlowKind.ASSIGN
        assert edges[0].source_expr == "1 + 2"
        assert edges[0].target_expr == "x"
        assert not errors

    def test_augmented_assignment(self) -> None:
        a = AssignmentFact(
            target="x",
            target_location=_span(10),
            value_expression="x + 1",
            value_location=_span(10),
            kind=AssignmentKind.AUGMENTED,
            containing_function_fqn="fn",
        )
        edges, _ = extract_value_flow(assignments=(a,), aliases=(), functions=())
        assert edges[0].kind == FlowKind.AUGMENTED_ASSIGN

    def test_unpacking_assignment(self) -> None:
        a = AssignmentFact(
            target="a, b",
            target_location=_span(3),
            value_expression="(1, 2)",
            value_location=_span(3),
            kind=AssignmentKind.UNPACKING,
            containing_function_fqn="fn",
        )
        edges, _ = extract_value_flow(assignments=(a,), aliases=(), functions=())
        assert edges[0].kind == FlowKind.UNPACK

    def test_multiple_assignments(self) -> None:
        edges, _ = extract_value_flow(
            assignments=(
                _assignment("x", "10", 1, 1),
                _assignment("y", "x + 1", 2, 2),
                _assignment("z", "y * 2", 3, 3),
            ),
            aliases=(),
            functions=(),
        )
        assert len(edges) == 3

    def test_containing_function_propagated(self) -> None:
        edges, _ = extract_value_flow(
            assignments=(_assignment("x", "1", 1, 1, "mod.my_func"),),
            aliases=(),
            functions=(),
        )
        assert edges[0].containing_function_fqn == "mod.my_func"

    def test_value_flow_graph_exposes_edges_in_extraction_order(self) -> None:
        edges, _ = extract_value_flow(
            assignments=(
                _assignment("first", "1", 1, 1, None),
                _assignment("second", "first", 2, 2, None),
            ),
            aliases=(),
            functions=(),
        )

        graph = ValueFlowGraph(edges)

        assert graph.edges == edges


class TestContainerLiteralEdges:
    def test_list_literal_elements_flow_to_assignment_target(self) -> None:
        a = _assignment("payload", "[raw, token.attr, items[0]]", 5, 5)

        edges, errors = extract_value_flow(assignments=(a,), aliases=(), functions=())

        pairs = {(e.source_expr, e.target_expr, e.kind) for e in edges}
        assert ("[raw, token.attr, items[0]]", "payload", FlowKind.ASSIGN) in pairs
        assert ("raw", "payload", FlowKind.ASSIGN) in pairs
        assert ("token.attr", "payload", FlowKind.ASSIGN) in pairs
        assert ("items[0]", "payload", FlowKind.ASSIGN) in pairs
        assert not errors

    def test_tuple_literal_elements_flow_to_assignment_target(self) -> None:
        a = _assignment("pair", "(left, right)", 6, 6)

        edges, _ = extract_value_flow(assignments=(a,), aliases=(), functions=())

        pairs = {(e.source_expr, e.target_expr) for e in edges if e.kind == FlowKind.ASSIGN}
        assert ("left", "pair") in pairs
        assert ("right", "pair") in pairs

    def test_set_literal_elements_flow_to_assignment_target(self) -> None:
        a = _assignment("seen", "{user_id, session_id}", 7, 7)

        edges, _ = extract_value_flow(assignments=(a,), aliases=(), functions=())

        pairs = {(e.source_expr, e.target_expr) for e in edges if e.kind == FlowKind.ASSIGN}
        assert ("user_id", "seen") in pairs
        assert ("session_id", "seen") in pairs

    def test_dict_literal_values_and_spreads_flow_to_assignment_target(self) -> None:
        a = _assignment("payload", '{"user": user_id, dynamic_key: value, **extra}', 8, 8)

        edges, _ = extract_value_flow(assignments=(a,), aliases=(), functions=())

        sources = {e.source_expr for e in edges if e.target_expr == "payload"}
        assert "user_id" in sources
        assert "value" in sources
        assert "dynamic_key" not in sources
        assert "extra" in sources

    def test_conditional_expression_arms_flow_to_assignment_target(self) -> None:
        a = _assignment("payload", "request.json if request.is_json else request.form", 9, 9)

        edges, _ = extract_value_flow(assignments=(a,), aliases=(), functions=())

        sources = {e.source_expr for e in edges if e.target_expr == "payload"}
        assert "request.json" in sources
        assert "request.is_json" in sources
        assert "request.form" in sources


class TestTransformInputEdges:
    """Call-transform operands flow to the assignment target as TRANSFORM_INPUT.

    Provenance (``derived_from`` / ``flows_to`` / ``shares_origin``) must follow
    a value through an intra-function transform (``y = x.lower()``), so the
    receiver / non-literal arguments of a right-hand-side call get a dedicated
    edge.  The kind is distinct from ASSIGN precisely so the transform is *not*
    treated as whole-value-preserving (FLAW-172).
    """

    def test_method_receiver_flows_to_target(self) -> None:
        a = _assignment("lowered", "email.lower()", 5, 5)

        edges, errors = extract_value_flow(assignments=(a,), aliases=(), functions=())

        pairs = {(e.source_expr, e.target_expr, e.kind) for e in edges}
        assert ("email.lower()", "lowered", FlowKind.ASSIGN) in pairs
        assert ("email", "lowered", FlowKind.TRANSFORM_INPUT) in pairs
        assert not errors

    def test_non_literal_arguments_flow_to_target(self) -> None:
        a = _assignment("norm", 'normalize("NFKC", email)', 6, 6)

        edges, _ = extract_value_flow(assignments=(a,), aliases=(), functions=())

        transform = {
            (e.source_expr, e.target_expr) for e in edges if e.kind == FlowKind.TRANSFORM_INPUT
        }
        # The literal "NFKC" is skipped; the value operand flows through.
        assert ("email", "norm") in transform
        assert all(src != '"NFKC"' for src, _ in transform)

    def test_chained_transform_peels_to_origin(self) -> None:
        a = _assignment("out", "a.b().c(d)", 7, 7)

        edges, _ = extract_value_flow(assignments=(a,), aliases=(), functions=())

        transform = {e.source_expr for e in edges if e.kind == FlowKind.TRANSFORM_INPUT}
        assert "a" in transform
        assert "d" in transform

    def test_literal_arguments_are_not_peeled(self) -> None:
        a = _assignment("token", "secrets.token_hex(16)", 8, 8)

        edges, _ = extract_value_flow(assignments=(a,), aliases=(), functions=())

        transform = {e.source_expr for e in edges if e.kind == FlowKind.TRANSFORM_INPUT}
        # The integer literal ``16`` carries no provenance and must be skipped.
        assert "16" not in transform

    def test_transform_input_excluded_from_preserving_kinds(self) -> None:
        # Guards the core invariant: a transform operand edge must NOT be in the
        # whole-value-preserving set, or preserves_whole_value would wrongly
        # treat ``y = x.lower()`` as preserving x's whole value.
        from flawed._semantic import _WHOLE_VALUE_PRESERVING_STEP_KINDS

        assert FlowKind.TRANSFORM_INPUT.value not in _WHOLE_VALUE_PRESERVING_STEP_KINDS


class TestChainedAssignmentEdges:
    """Chained assignments like ``x = y = val`` produce per-target edges
    plus inter-target flow links."""

    def test_chained_two_targets_produces_three_edges(self) -> None:
        """``x = y = val`` → val→x, val→y, x→y (inter-target chain link).

        The structural pass emits targets in source order (left-to-right),
        so ``x`` appears first, then ``y``.  Chain links follow source order.
        """
        a_x = AssignmentFact(
            target="x",
            target_location=_span(5),
            value_expression="val",
            value_location=_span(5),
            kind=AssignmentKind.SIMPLE,
            containing_function_fqn="mod.fn",
        )
        a_y = AssignmentFact(
            target="y",
            target_location=_span(5),
            value_expression="val",
            value_location=_span(5),
            kind=AssignmentKind.SIMPLE,
            containing_function_fqn="mod.fn",
        )
        edges, errors = extract_value_flow(
            assignments=(a_x, a_y),
            aliases=(),
            functions=(),
        )
        # Expect 3 edges: val→x, val→y, plus x→y (inter-target chain link)
        assert len(edges) == 3
        chain_edges = [e for e in edges if e.kind == FlowKind.CHAIN]
        assert len(chain_edges) == 1
        assert chain_edges[0].source_expr == "x"
        assert chain_edges[0].target_expr == "y"
        assert not errors

    def test_chained_three_targets_produces_chain_links(self) -> None:
        """``a = b = c = val`` → val→a, val→b, val→c, a→b, b→c.

        Structural pass emits left-to-right: a, b, c.  Chain links follow
        the same source order.
        """
        a_a = AssignmentFact(
            target="a",
            target_location=_span(5),
            value_expression="val",
            value_location=_span(5),
            kind=AssignmentKind.SIMPLE,
            containing_function_fqn="mod.fn",
        )
        a_b = AssignmentFact(
            target="b",
            target_location=_span(5),
            value_expression="val",
            value_location=_span(5),
            kind=AssignmentKind.SIMPLE,
            containing_function_fqn="mod.fn",
        )
        a_c = AssignmentFact(
            target="c",
            target_location=_span(5),
            value_expression="val",
            value_location=_span(5),
            kind=AssignmentKind.SIMPLE,
            containing_function_fqn="mod.fn",
        )
        edges, _ = extract_value_flow(
            assignments=(a_a, a_b, a_c),
            aliases=(),
            functions=(),
        )
        # 3 val→target edges + 2 chain edges (a→b, b→c)
        assert len(edges) == 5
        chain_edges = [e for e in edges if e.kind == FlowKind.CHAIN]
        assert len(chain_edges) == 2
        chain_pairs = [(e.source_expr, e.target_expr) for e in chain_edges]
        assert ("a", "b") in chain_pairs
        assert ("b", "c") in chain_pairs

    def test_non_chained_same_value_no_chain_edge(self) -> None:
        """Two assignments from the same value on different lines are NOT a chain."""
        a1 = AssignmentFact(
            target="x",
            target_location=_span(3),
            value_expression="val",
            value_location=_span(3),
            kind=AssignmentKind.SIMPLE,
            containing_function_fqn="mod.fn",
        )
        a2 = AssignmentFact(
            target="y",
            target_location=_span(7),
            value_expression="val",
            value_location=_span(7),
            kind=AssignmentKind.SIMPLE,
            containing_function_fqn="mod.fn",
        )
        edges, _ = extract_value_flow(
            assignments=(a1, a2),
            aliases=(),
            functions=(),
        )
        # Two separate assignments, no chain — only 2 edges
        assert len(edges) == 2
        chain_edges = [e for e in edges if e.kind == FlowKind.CHAIN]
        assert len(chain_edges) == 0


class TestPerElementUnpackingEdges:
    """Per-element unpacking like ``a, b = x, y`` should produce
    element-level edges when arity matches."""

    def test_matching_arity_produces_per_element_edges(self) -> None:
        """``a, b = x, y`` → x→a, y→b (per-element, not aggregate)."""
        a = AssignmentFact(
            target="a, b",
            target_location=_span(10),
            value_expression="x, y",
            value_location=_span(10),
            kind=AssignmentKind.UNPACKING,
            containing_function_fqn="mod.fn",
        )
        edges, _ = extract_value_flow(assignments=(a,), aliases=(), functions=())
        # Should produce per-element edges, not one aggregate
        unpack_edges = [e for e in edges if e.kind == FlowKind.UNPACK]
        assert len(unpack_edges) == 2
        pairs = {(e.source_expr, e.target_expr) for e in unpack_edges}
        assert ("x", "a") in pairs
        assert ("y", "b") in pairs

    def test_mismatched_arity_produces_aggregate_edge(self) -> None:
        """``a, b = some_func()`` → one aggregate edge (can't decompose)."""
        a = AssignmentFact(
            target="a, b",
            target_location=_span(10),
            value_expression="some_func()",
            value_location=_span(10),
            kind=AssignmentKind.UNPACKING,
            containing_function_fqn="mod.fn",
        )
        edges, _ = extract_value_flow(assignments=(a,), aliases=(), functions=())
        assert len(edges) == 1
        assert edges[0].kind == FlowKind.UNPACK
        assert edges[0].source_expr == "some_func()"
        assert edges[0].target_expr == "a, b"

    def test_three_element_unpack(self) -> None:
        """``a, b, c = x, y, z`` → three per-element edges."""
        a = AssignmentFact(
            target="a, b, c",
            target_location=_span(10),
            value_expression="x, y, z",
            value_location=_span(10),
            kind=AssignmentKind.UNPACKING,
            containing_function_fqn="mod.fn",
        )
        edges, _ = extract_value_flow(assignments=(a,), aliases=(), functions=())
        unpack_edges = [e for e in edges if e.kind == FlowKind.UNPACK]
        assert len(unpack_edges) == 3

    def test_starred_unpack_produces_aggregate_edge(self) -> None:
        """``a, *b = items`` → one aggregate edge (starred can't be decomposed)."""
        a = AssignmentFact(
            target="a, *b",
            target_location=_span(10),
            value_expression="items",
            value_location=_span(10),
            kind=AssignmentKind.UNPACKING,
            containing_function_fqn="mod.fn",
        )
        edges, _ = extract_value_flow(assignments=(a,), aliases=(), functions=())
        assert len(edges) == 1
        assert edges[0].kind == FlowKind.UNPACK
        assert edges[0].target_expr == "a, *b"


class TestAnnotatedAssignmentEdges:
    def test_annotated_assignment_uses_annotated_kind(self) -> None:
        a = AssignmentFact(
            target="x",
            target_location=_span(10),
            value_expression="42",
            value_location=_span(10),
            kind=AssignmentKind.ANNOTATED,
            containing_function_fqn="mod.fn",
        )
        edges, _ = extract_value_flow(assignments=(a,), aliases=(), functions=())
        assert len(edges) == 1
        assert edges[0].kind == FlowKind.ANNOTATED_ASSIGN
        assert edges[0].source_expr == "42"
        assert edges[0].target_expr == "x"

    def test_annotated_assignment_preserves_containing_function(self) -> None:
        a = AssignmentFact(
            target="name",
            target_location=_span(15),
            value_expression='"default"',
            value_location=_span(15),
            kind=AssignmentKind.ANNOTATED,
            containing_function_fqn="mod.init",
        )
        edges, _ = extract_value_flow(assignments=(a,), aliases=(), functions=())
        assert edges[0].containing_function_fqn == "mod.init"


class TestAliasEdges:
    def test_import_alias(self) -> None:
        edges, errors = extract_value_flow(
            assignments=(),
            aliases=(_alias("flask.request", "req", 1),),
            functions=(),
        )
        assert len(edges) == 1
        assert edges[0].kind == FlowKind.ALIAS
        assert edges[0].source_expr == "flask.request"
        assert edges[0].target_expr == "req"
        assert not errors

    def test_alias_function_fqn_is_none(self) -> None:
        """Aliases are module-level, not inside a function."""
        edges, _ = extract_value_flow(
            assignments=(),
            aliases=(_alias("os.path", "p", 1),),
            functions=(),
        )
        assert edges[0].containing_function_fqn is None


class TestParameterDefaultEdges:
    def test_default_creates_edge(self) -> None:
        fn = _function("mod.fn", params=(_param("x", default="42", line=5),))
        edges, _ = extract_value_flow(assignments=(), aliases=(), functions=(fn,))
        assert len(edges) == 1
        assert edges[0].source_expr == "42"
        assert edges[0].target_expr == "x"
        assert edges[0].kind == FlowKind.ASSIGN

    def test_no_default_no_edge(self) -> None:
        fn = _function("mod.fn", params=(_param("x"),))
        edges, _ = extract_value_flow(assignments=(), aliases=(), functions=(fn,))
        assert len(edges) == 0

    def test_multiple_params_mixed(self) -> None:
        fn = _function(
            "mod.fn",
            params=(
                _param("a"),
                _param("b", default="10"),
                _param("c"),
                _param("d", default="None"),
            ),
        )
        edges, _ = extract_value_flow(assignments=(), aliases=(), functions=(fn,))
        assert len(edges) == 2
        defaults = {e.source_expr for e in edges}
        assert defaults == {"10", "None"}


class TestCallArgumentEdges:
    def test_positional_argument_creates_callsite_edge(self) -> None:
        call = _call_edge(arguments=(_argument("raw", 20),), line=20)

        edges, errors = extract_value_flow(
            assignments=(),
            aliases=(),
            functions=(),
            call_edges=(call,),
            returns=(),
        )

        assert len(edges) == 1
        edge = edges[0]
        assert edge.kind == FlowKind.ARGUMENT
        assert edge.source_expr == "raw"
        assert edge.source_location == _span(20)
        assert edge.target_expr == "helper"
        assert edge.target_location == _span(20)
        assert edge.containing_function_fqn == "mod.run"
        assert edge.callsite_callee_fqn == "mod.helper"
        assert edge.callsite_expr == "helper"
        assert edge.argument_position == 0
        assert edge.argument_keyword is None
        assert not errors

    def test_keyword_argument_preserves_keyword_metadata(self) -> None:
        call = _call_edge(
            arguments=(_argument("True", 21, position=None, keyword="strict"),),
            line=21,
        )

        edges, _ = extract_value_flow(
            assignments=(),
            aliases=(),
            functions=(),
            call_edges=(call,),
            returns=(),
        )

        assert len(edges) == 1
        assert edges[0].kind == FlowKind.ARGUMENT
        assert edges[0].source_expr == "True"
        assert edges[0].argument_position is None
        assert edges[0].argument_keyword == "strict"

    def test_dict_spread_argument_sources_flow_to_callsite(self) -> None:
        call = _call_edge(
            arguments=(_argument("{**user_data, **safe_data}", 22),),
            line=22,
        )

        edges, _ = extract_value_flow(
            assignments=(),
            aliases=(),
            functions=(),
            call_edges=(call,),
            returns=(),
        )

        pairs = {(edge.source_expr, edge.target_expr) for edge in edges}
        assert ("{**user_data, **safe_data}", "helper") in pairs
        assert ("user_data", "{**user_data, **safe_data}") in pairs
        assert ("safe_data", "{**user_data, **safe_data}") in pairs
        assert ("user_data", "helper") in pairs
        assert ("safe_data", "helper") in pairs
        assert {edge.kind for edge in edges} == {FlowKind.ARGUMENT, FlowKind.ASSIGN}

    def test_unresolved_callsite_argument_keeps_dispatch_metadata(self) -> None:
        call = _call_edge(
            callee_fqn=None,
            arguments=(_argument("payload", 30),),
            line=30,
            call_expression="handlers[action]",
            unresolved_reason="dynamic_dispatch_table",
        )

        edges, _ = extract_value_flow(
            assignments=(),
            aliases=(),
            functions=(),
            call_edges=(call,),
            returns=(),
        )

        assert len(edges) == 1
        assert edges[0].kind == FlowKind.ARGUMENT
        assert edges[0].target_expr == "handlers[action]"
        assert edges[0].callsite_callee_fqn is None
        assert edges[0].callsite_expr == "handlers[action]"
        assert edges[0].argument_position == 0


class TestReturnEdges:
    def test_return_expression_creates_return_edge(self) -> None:
        return_fact = _return_fact("value", 12)

        edges, errors = extract_value_flow(
            assignments=(),
            aliases=(),
            functions=(),
            call_edges=(),
            returns=(return_fact,),
        )

        assert len(edges) == 1
        edge = edges[0]
        assert edge.kind == FlowKind.RETURN
        assert edge.source_expr == "value"
        assert edge.source_location == _span(12)
        assert edge.target_expr == "return"
        assert edge.target_location == _span(12)
        assert edge.containing_function_fqn == "mod.helper"
        assert edge.callsite_callee_fqn is None
        assert edge.callsite_expr is None
        assert edge.argument_position is None
        assert edge.argument_keyword is None
        assert not errors

    def test_bare_return_creates_no_value_edge(self) -> None:
        edges, errors = extract_value_flow(
            assignments=(),
            aliases=(),
            functions=(),
            call_edges=(),
            returns=(_return_fact(None, 12),),
        )

        assert edges == ()
        assert not errors


class TestComprehensionBindingEdges:
    def test_comprehension_binding_creates_binding_edge(self) -> None:
        binding = _comprehension_binding("item", "items", 12)

        edges, errors = extract_value_flow(
            assignments=(),
            aliases=(),
            functions=(),
            comprehension_bindings=(binding,),
        )

        assert len(edges) == 1
        edge = edges[0]
        assert edge.kind == FlowKind.COMPREHENSION_BINDING
        assert edge.source_expr == "items"
        assert edge.source_location == _span(12)
        assert edge.target_expr == "item"
        assert edge.target_location == _span(12)
        assert edge.containing_function_fqn == "mod.collect"
        assert not errors

    def test_nested_comprehension_bindings_preserve_each_generator(self) -> None:
        edges, _ = extract_value_flow(
            assignments=(),
            aliases=(),
            functions=(),
            comprehension_bindings=(
                _comprehension_binding("group", "groups", 20),
                _comprehension_binding("user", "group.users", 20),
            ),
        )

        pairs = {(e.source_expr, e.target_expr) for e in edges}
        assert pairs == {("groups", "group"), ("group.users", "user")}
        assert {e.kind for e in edges} == {FlowKind.COMPREHENSION_BINDING}


class TestCombined:
    def test_all_edge_types(self) -> None:
        fn = _function("mod.fn", params=(_param("x", default="0"),))
        call = _call_edge(arguments=(_argument("raw", 20),), line=20)
        return_fact = _return_fact("y", 21, fn_fqn="mod.fn")
        edges, errors = extract_value_flow(
            assignments=(_assignment("y", "x + 1", 10, 10),),
            aliases=(_alias("os.path", "p", 1),),
            functions=(fn,),
            call_edges=(call,),
            returns=(return_fact,),
        )
        assert len(edges) == 5
        kinds = {e.kind for e in edges}
        assert FlowKind.ASSIGN in kinds
        assert FlowKind.ALIAS in kinds
        assert FlowKind.ARGUMENT in kinds
        assert FlowKind.RETURN in kinds
        assert not errors

    def test_empty_inputs(self) -> None:
        edges, errors = extract_value_flow(
            assignments=(),
            aliases=(),
            functions=(),
        )
        assert len(edges) == 0
        assert not errors

    def test_provenance_set(self) -> None:
        edges, _ = extract_value_flow(
            assignments=(_assignment("x", "1", 1, 1),),
            aliases=(),
            functions=(),
        )
        assert edges[0].provenance.producer == "value_flow"


# ── Helpers for new edge types ──────────────────────────────────────


def _attribute_write(
    target_expr: str,
    attr_name: str,
    value_expr: str,
    line: int,
    *,
    fn_fqn: str | None = "mod.fn",
) -> AttributeAccess:
    return AttributeAccess(
        target_expr=target_expr,
        attr_name=attr_name,
        is_write=True,
        access_kind=AccessKind.ATTR,
        value_expr=value_expr,
        containing_function_fqn=fn_fqn,
        location=_span(line),
        provenance=_PROV,
    )


def _yield_fact(
    expression: str | None,
    line: int,
    *,
    is_from: bool = False,
    fn_fqn: str = "mod.gen",
) -> YieldFact:
    return YieldFact(
        expression=expression,
        expression_location=_span(line) if expression is not None else None,
        statement_location=_span(line),
        is_from=is_from,
        containing_function_fqn=fn_fqn,
        provenance=_PROV,
    )


# ── Attribute write edges ────────────────────────────────────────────


class TestAttributeWriteEdges:
    def test_attribute_write_creates_edge(self) -> None:
        attr = _attribute_write("self", "name", '"alice"', 10)

        edges, errors = extract_value_flow(
            assignments=(),
            aliases=(),
            functions=(),
            attribute_writes=(attr,),
        )

        assert len(edges) == 1
        edge = edges[0]
        assert edge.kind == FlowKind.ATTRIBUTE_WRITE
        assert edge.source_expr == '"alice"'
        assert edge.target_expr == "self.name"
        assert edge.target_location == _span(10)
        assert edge.containing_function_fqn == "mod.fn"
        assert not errors

    def test_attribute_write_preserves_containing_function(self) -> None:
        attr = _attribute_write("obj", "x", "42", 5, fn_fqn="mod.setup")

        edges, _ = extract_value_flow(
            assignments=(),
            aliases=(),
            functions=(),
            attribute_writes=(attr,),
        )

        assert edges[0].containing_function_fqn == "mod.setup"

    def test_module_level_attribute_write(self) -> None:
        attr = _attribute_write("config", "debug", "True", 3, fn_fqn=None)

        edges, _ = extract_value_flow(
            assignments=(),
            aliases=(),
            functions=(),
            attribute_writes=(attr,),
        )

        assert edges[0].containing_function_fqn is None
        assert edges[0].target_expr == "config.debug"


# ── Yield edges ──────────────────────────────────────────────────────


class TestYieldEdges:
    def test_yield_expression_creates_edge(self) -> None:
        yld = _yield_fact("value", 15)

        edges, errors = extract_value_flow(
            assignments=(),
            aliases=(),
            functions=(),
            yields=(yld,),
        )

        assert len(edges) == 1
        edge = edges[0]
        assert edge.kind == FlowKind.YIELD
        assert edge.source_expr == "value"
        assert edge.target_expr == "yield"
        assert edge.target_location == _span(15)
        assert edge.containing_function_fqn == "mod.gen"
        assert not errors

    def test_bare_yield_creates_no_value_edge(self) -> None:
        edges, errors = extract_value_flow(
            assignments=(),
            aliases=(),
            functions=(),
            yields=(_yield_fact(None, 10),),
        )

        assert edges == ()
        assert not errors

    def test_yield_from_creates_edge(self) -> None:
        yld = _yield_fact("other_gen()", 20, is_from=True)

        edges, _ = extract_value_flow(
            assignments=(),
            aliases=(),
            functions=(),
            yields=(yld,),
        )

        assert len(edges) == 1
        assert edges[0].kind == FlowKind.YIELD
        assert edges[0].source_expr == "other_gen()"
        assert edges[0].target_expr == "yield"
