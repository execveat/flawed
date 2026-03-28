"""Convert L1 control-flow branch conditions into public Condition objects."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import TYPE_CHECKING

from flawed._index._types import FlowKind
from flawed._semantic._conversion_utils import location
from flawed._semantic._expr_cache import parse_expression as _parse_expression
from flawed.conditions import CodeScope, Condition, ConditionKind, Predicate
from flawed.core import Location, Provenance
from flawed.flow import ValueHandle, make_value_handle

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flawed._index import CodeIndex
    from flawed._index._types import CFGBlock, ValuePredicate
    from flawed.function import Function


# Value-flow edge kinds that *define* a local variable (assignment-family).
# A predicate operand that is a bare name is anchored at the target of one of
# these edges so ``derived_from`` resolves from the variable's definition site.
_DEFINITION_FLOW_KINDS = frozenset(
    {
        FlowKind.ASSIGN,
        FlowKind.AUGMENTED_ASSIGN,
        FlowKind.ANNOTATED_ASSIGN,
        FlowKind.ALIAS,
        FlowKind.UNPACK,
        FlowKind.CHAIN,
    }
)


_L2_STRUCTURAL_CONDITION_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="structural_conditions",
    confidence=0.9,
    supporting_facts=("L1 control-flow graph branch condition",),
)
_OPERATOR_TEXT_BY_TYPE: dict[type[ast.cmpop], str] = {
    ast.Eq: "==",
    ast.NotEq: "!=",
    ast.Lt: "<",
    ast.LtE: "<=",
    ast.Gt: ">",
    ast.GtE: ">=",
    ast.Is: "is",
    ast.IsNot: "is not",
    ast.In: "in",
    ast.NotIn: "not in",
}


@dataclass(frozen=True)
class ConcreteStructuralCondition(Condition):
    """Concrete Condition backed by an L1 CFG branch expression.

    The ``left`` / ``right`` operands are resolved **lazily** through
    :func:`_lazy_operand_handle` (mirroring :class:`ConcretePredicate`), so a
    bare-name operand defined via a *callee* can trace its provenance
    interprocedurally by the time a rule queries ``derived_from`` (FLAW-117).
    Bare-name operand locations are anchored at the variable's value-flow
    *definition* site (see :func:`_definition_locations_by_function`), because
    the use site carries no value-flow node.  Before FLAW-117 these operands
    were eager bare handles anchored at the use site, so branch-condition
    ``derived_from`` queries silently returned ``False`` for the interprocedural
    shape (a false negative on the FLAW-104 r02c/g012 ``conditions()`` arm).
    """

    _operator: str | None = None
    _left_expression: str | None = None
    _left_location: Location | None = None
    _right_expression: str | None = None
    _right_location: Location | None = None
    _true_branch: CodeScope | None = None
    _false_branch: CodeScope | None = None

    @property
    def operator(self) -> str | None:
        return self._operator

    @property
    def true_branch(self) -> CodeScope:
        if self._true_branch is None:
            return _empty_scope()
        return self._true_branch

    @property
    def false_branch(self) -> CodeScope:
        if self._false_branch is None:
            return _empty_scope()
        return self._false_branch

    @property
    def left(self) -> ValueHandle | None:
        return _lazy_operand_handle(
            self, self.function, self._left_expression, self._left_location
        )

    @property
    def right(self) -> ValueHandle | None:
        return _lazy_operand_handle(
            self, self.function, self._right_expression, self._right_location
        )

    @property
    def guard(self) -> None:
        return None


def convert_structural_conditions(
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> dict[str, list[ConcreteStructuralCondition]]:
    """Convert CFG branch expressions to function-scoped conditions.

    Bare-name operands are anchored at their value-flow definition site and
    rebuilt as lazy, flow-aware handles (mirroring
    :func:`convert_value_predicates`), so a branch condition over a variable
    produced by a callee resolves ``derived_from`` interprocedurally (FLAW-117).
    """
    def_locations_by_fqn = _definition_locations_by_function(idx)
    conditions_by_function: dict[str, list[ConcreteStructuralCondition]] = {}
    for fqn, function in functions_by_fqn.items():
        cfg = idx.cfg(fqn)
        if cfg is None:
            continue
        def_locations = def_locations_by_fqn.get(fqn, {})
        seen: set[tuple[str, int, int]] = set()
        for block in cfg.blocks:
            if block.condition_expr is None or block.condition_location is None:
                continue
            key = (
                block.condition_expr,
                block.condition_location.line,
                block.condition_location.column,
            )
            if key in seen:
                continue
            seen.add(key)
            conditions_by_function.setdefault(fqn, []).append(
                _condition_for_block(block, function, def_locations)
            )
    return conditions_by_function


def _condition_for_block(
    block: CFGBlock, function: Function, def_locations: dict[str, Location]
) -> ConcreteStructuralCondition:
    assert block.condition_expr is not None
    assert block.condition_location is not None
    loc = location(block.condition_location)
    details = _classify_expression(block.condition_expr, loc)
    left_expr, left_loc = _operand_parts(details.left, def_locations)
    right_expr, right_loc = _operand_parts(details.right, def_locations)
    return ConcreteStructuralCondition(
        expression=block.condition_expr,
        location=loc,
        function=function,
        kind=details.kind,
        provenance=_L2_STRUCTURAL_CONDITION_PROVENANCE,
        _operator=details.operator,
        _left_expression=left_expr,
        _left_location=left_loc,
        _right_expression=right_expr,
        _right_location=right_loc,
    )


_L2_VALUE_PREDICATE_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="value_predicates",
    confidence=0.9,
    supporting_facts=("L1 control-flow graph value predicate",),
)


@dataclass(frozen=True)
class ConcretePredicate(Predicate):
    """Concrete Predicate backed by an L1 CFG value-predicate expression.

    The ``left`` / ``right`` operands are resolved **lazily** through
    :func:`~flawed.flow.make_value_handle`, which wires the
    ``_trace_flow`` / ``_derived_from`` callbacks from the owning
    :attr:`~flawed.conditions.Predicate.function`.  This is load-bearing:
    those callbacks are attached to each ``Function`` *after* this
    conversion runs (in ``SemanticContext._attach_context``), so eager
    bare-handle construction (as ``conditions()`` uses) would capture no
    flow context and answer ``derived_from`` ``False`` unconditionally.
    Resolving from ``self.function`` at access time means the operand can
    trace its provenance interprocedurally — across a call boundary to a
    request read in a callee — by the time a rule queries it.
    """

    _operator: str | None = None
    _left_expression: str | None = None
    _left_location: Location | None = None
    _right_expression: str | None = None
    _right_location: Location | None = None

    @property
    def operator(self) -> str | None:
        return self._operator

    @property
    def left(self) -> ValueHandle | None:
        return self._operand_handle(self._left_expression, self._left_location)

    @property
    def right(self) -> ValueHandle | None:
        return self._operand_handle(self._right_expression, self._right_location)

    def _operand_handle(self, expression: str | None, loc: Location | None) -> ValueHandle | None:
        # Resolve flow callbacks lazily from the owning function: it carries
        # ``_trace_flow`` / ``_derived_from`` by the time a rule queries.
        return _lazy_operand_handle(self, self.function, expression, loc)


def convert_value_predicates(
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> dict[str, list[ConcretePredicate]]:
    """Convert L1 value-position predicate expressions to function-scoped predicates.

    Sibling to :func:`convert_structural_conditions`.  Reads each CFG
    block's ``value_predicates`` (predicate expressions captured at
    return / assignment / ternary value positions, with no branch edges)
    and classifies them with the same ``_classify_expression`` vocabulary
    used for branch conditions.
    """
    def_locations_by_fqn = _definition_locations_by_function(idx)
    predicates_by_function: dict[str, list[ConcretePredicate]] = {}
    for fqn, function in functions_by_fqn.items():
        cfg = idx.cfg(fqn)
        if cfg is None:
            continue
        def_locations = def_locations_by_fqn.get(fqn, {})
        seen: set[tuple[str, int, int]] = set()
        for block in cfg.blocks:
            for value_predicate in block.value_predicates:
                key = (
                    value_predicate.expression,
                    value_predicate.location.line,
                    value_predicate.location.column,
                )
                if key in seen:
                    continue
                seen.add(key)
                predicates_by_function.setdefault(fqn, []).append(
                    _predicate_for_value(value_predicate, function, def_locations)
                )
    return predicates_by_function


def _definition_locations_by_function(idx: CodeIndex) -> dict[str, dict[str, Location]]:
    """Map each function FQN to its locals' value-flow definition sites.

    A bare-name operand of a value predicate (``token`` in ``token is not
    None``) has no value-flow node at its *use* site — the flow graph
    anchors the variable at its *definition* (the assignment target, e.g.
    ``token = extract_credential()``).  Anchoring the operand handle there
    lets ``derived_from`` trace the variable back through the callee that
    produced it.  When a name is defined more than once we keep the first
    definition; the interprocedural trace fans out from there regardless.
    """
    by_fqn: dict[str, dict[str, Location]] = {}
    for edge in idx.value_flow.edges:
        fqn = edge.containing_function_fqn
        if fqn is None or edge.kind not in _DEFINITION_FLOW_KINDS:
            continue
        if not _is_simple_name(edge.target_expr):
            continue
        names = by_fqn.setdefault(fqn, {})
        names.setdefault(edge.target_expr, location(edge.target_location))
    return by_fqn


def _is_simple_name(expression: str) -> bool:
    """True for a bare identifier (no attribute / subscript / call)."""
    return expression.isidentifier()


def _predicate_for_value(
    value_predicate: ValuePredicate,
    function: Function,
    def_locations: dict[str, Location],
) -> ConcretePredicate:
    loc = location(value_predicate.location)
    details = _classify_expression(value_predicate.expression, loc)
    left_expr, left_loc = _operand_parts(details.left, def_locations)
    right_expr, right_loc = _operand_parts(details.right, def_locations)
    return ConcretePredicate(
        expression=value_predicate.expression,
        location=loc,
        function=function,
        kind=details.kind,
        provenance=_L2_VALUE_PREDICATE_PROVENANCE,
        _operator=details.operator,
        _left_expression=left_expr,
        _left_location=left_loc,
        _right_expression=right_expr,
        _right_location=right_loc,
    )


def _lazy_operand_handle(
    owner: object,
    function: Function,
    expression: str | None,
    loc: Location | None,
) -> ValueHandle | None:
    """Build a flow-aware operand handle lazily from the owning function.

    Shared by :class:`ConcreteStructuralCondition` and :class:`ConcretePredicate`.
    The operand's ``_trace_flow`` / ``_derived_from`` callbacks are attached to
    the owning ``Function`` only *after* conversion runs (in
    ``SemanticContext._attach_context``), so the handle must resolve them at
    access time — eager bare-handle construction would capture no flow context
    and answer ``derived_from`` ``False`` unconditionally.
    """
    if expression is None or loc is None:
        return None
    return make_value_handle(
        owner=owner,
        function=function,
        location=loc,
        expression=expression,
    )


def _operand_parts(
    handle: ValueHandle | None, def_locations: dict[str, Location]
) -> tuple[str | None, Location | None]:
    """Decompose a classifier operand handle into raw expression + location.

    ``_classify_expression`` builds eager bare handles for operands; we keep
    only their source text and rebuild flow-aware handles lazily in
    :class:`ConcretePredicate`.

    For a bare-name operand we anchor the location at the variable's
    value-flow *definition* site (its assignment target) when one is known,
    because the use site carries no value-flow node.  Other operands
    (calls, attributes, ``None``) keep the operand's own location.
    """
    if handle is None:
        return None, None
    expression = handle.expression
    loc = def_locations.get(expression, handle.location)
    return expression, loc


@dataclass(frozen=True)
class _ConditionDetails:
    kind: ConditionKind
    operator: str | None = None
    left: ValueHandle | None = None
    right: ValueHandle | None = None


def _classify_expression(expression: str, loc: Location) -> _ConditionDetails:
    tree = _parse_expression(expression)
    if tree is None:
        return _ConditionDetails(ConditionKind.UNKNOWN)
    return _details_for_node(tree.body, loc)


def _details_for_node(node: ast.expr, loc: Location) -> _ConditionDetails:
    if isinstance(node, ast.BoolOp):
        return _ConditionDetails(ConditionKind.COMPOUND)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _details_for_negated_node(node.operand, loc)
    if isinstance(node, ast.Compare):
        return _details_for_comparison(node, loc)
    if isinstance(node, ast.Call):
        return _ConditionDetails(ConditionKind.CALL_RESULT, left=_handle(ast.unparse(node), loc))
    if isinstance(node, ast.Name | ast.Attribute | ast.Subscript):
        return _ConditionDetails(ConditionKind.TRUTHINESS, left=_handle(ast.unparse(node), loc))
    return _ConditionDetails(ConditionKind.UNKNOWN)


def _details_for_negated_node(node: ast.expr, loc: Location) -> _ConditionDetails:
    if isinstance(node, ast.Call):
        return _ConditionDetails(ConditionKind.CALL_RESULT, left=_handle(ast.unparse(node), loc))
    if isinstance(node, ast.Name | ast.Attribute | ast.Subscript):
        return _ConditionDetails(ConditionKind.TRUTHINESS, left=_handle(ast.unparse(node), loc))
    return _details_for_node(node, loc)


def _details_for_comparison(node: ast.Compare, loc: Location) -> _ConditionDetails:
    if not node.ops or not node.comparators:
        return _ConditionDetails(ConditionKind.UNKNOWN)
    operator = _operator_text(node.ops[0])
    return _ConditionDetails(
        kind=_kind_for_operator(node.ops[0]),
        operator=operator,
        left=_handle(ast.unparse(node.left), loc),
        right=_handle(ast.unparse(node.comparators[0]), loc),
    )


def _kind_for_operator(op: ast.cmpop) -> ConditionKind:
    if isinstance(op, ast.In | ast.NotIn):
        return ConditionKind.MEMBERSHIP
    if isinstance(op, ast.Is | ast.IsNot):
        return ConditionKind.IDENTITY
    return ConditionKind.COMPARISON


def _operator_text(op: ast.cmpop) -> str | None:
    return _OPERATOR_TEXT_BY_TYPE.get(type(op))


def _handle(expression: str, loc: Location) -> ValueHandle:
    return ValueHandle(location=loc, expression=expression)


def _empty_scope() -> CodeScope:
    from flawed._semantic._scope import ConcreteCodeScope

    return ConcreteCodeScope()
