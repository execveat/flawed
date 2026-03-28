"""Step 6: Intra-function value-flow extraction.

Builds structural value-flow edges from assignments, aliases, parameter
defaults, call-site arguments, return expressions, comprehension bindings,
attribute writes, and yield expressions.  This is **intra-function only** —
interprocedural stitching (argument→parameter, return→caller) is deferred
to Layer 2's flow tracer which builds those links on-demand.

Edge creation is conservative: only edges derivable from syntactic
structure are emitted.  No inference, no type-based reasoning, no
cross-function tracking.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import libcst as cst

from flawed._index._types import (
    ExtractionProvenance,
    FlowKind,
    ValueFlowEdge,
)

if TYPE_CHECKING:
    from flawed._index._types import (
        AliasFact,
        AssignmentFact,
        AttributeAccess,
        CallEdge,
        ComprehensionBindingFact,
        ExtractionError,
        FunctionRecord,
        ReturnFact,
        YieldFact,
    )

_PASS_NAME = "value_flow"
_PASS_VERSION = "0.1.0"


def _provenance() -> ExtractionProvenance:
    return ExtractionProvenance(
        producer=_PASS_NAME,
        producer_version=_PASS_VERSION,
        artifact="value_flow_edges",
    )


def extract_value_flow(
    *,
    assignments: tuple[AssignmentFact, ...],
    aliases: tuple[AliasFact, ...],
    functions: tuple[FunctionRecord, ...],
    call_edges: tuple[CallEdge, ...] = (),
    returns: tuple[ReturnFact, ...] = (),
    comprehension_bindings: tuple[ComprehensionBindingFact, ...] = (),
    attribute_writes: tuple[AttributeAccess, ...] = (),
    yields: tuple[YieldFact, ...] = (),
) -> tuple[tuple[ValueFlowEdge, ...], tuple[ExtractionError, ...]]:
    """Build intra-function value-flow edges from structural facts.

    Parameters
    ----------
    assignments:
        All assignment facts from the structural entity pass.
    aliases:
        All alias facts (import aliases, assignment aliases).
    functions:
        All function records (for parameter default flow edges).
    call_edges:
        AST call-site records whose arguments become argument-to-call-site
        structural flow edges.
    returns:
        Return statement facts whose expressions become expression-to-return
        structural flow edges.
    comprehension_bindings:
        Comprehension ``for`` bindings whose iterable expressions become
        binding-to-target structural flow edges.
    attribute_writes:
        Attribute access records with ``is_write=True`` whose value
        expressions become attribute-write structural flow edges.
    yields:
        Yield expression facts whose yielded values become yield
        structural flow edges.

    Returns
    -------
    tuple:
        ``(edges, errors)`` — the edges and any extraction errors.
    """
    prov = _provenance()
    edges: list[ValueFlowEdge] = []

    # 1. Assignment edges: value flows from the value expression to the target.
    #
    # Chained assignments (``x = y = val``) produce inter-target chain
    # edges in addition to the val→target edges.  Per-element unpacking
    # (``a, b = x, y``) decomposes into element-level edges when arity
    # matches structurally.

    chained_groups = _detect_chained_groups(assignments)
    chained_set: set[int] = set()
    for group in chained_groups.values():
        for a in group:
            chained_set.add(id(a))

    for a in assignments:
        kind = _assignment_kind_to_flow(a.kind)

        # Per-element unpacking decomposition.
        if kind == FlowKind.UNPACK:
            pairs = _try_decompose_unpack(a.target, a.value_expression)
            if pairs is not None:
                for val_elem, tgt_elem in pairs:
                    edges.append(
                        ValueFlowEdge(
                            source_expr=val_elem,
                            source_location=a.value_location,
                            target_expr=tgt_elem,
                            target_location=a.target_location,
                            kind=FlowKind.UNPACK,
                            containing_function_fqn=a.containing_function_fqn,
                            provenance=prov,
                        )
                    )
                continue

        edges.append(
            ValueFlowEdge(
                source_expr=a.value_expression,
                source_location=a.value_location,
                target_expr=a.target,
                target_location=a.target_location,
                kind=kind,
                containing_function_fqn=a.containing_function_fqn,
                provenance=prov,
            )
        )
        if kind in (FlowKind.ASSIGN, FlowKind.ANNOTATED_ASSIGN):
            edges.extend(
                ValueFlowEdge(
                    source_expr=element_expr,
                    source_location=a.value_location,
                    target_expr=a.target,
                    target_location=a.target_location,
                    kind=kind,
                    containing_function_fqn=a.containing_function_fqn,
                    provenance=prov,
                )
                for element_expr in _expression_component_sources(a.value_expression)
            )
            # Transform operands: ``y = x.lower()`` / ``y = f(x)`` derive ``y``
            # from ``x``.  Emitted as TRANSFORM_INPUT (provenance-carrying but
            # NOT whole-value-preserving) so derived_from/flows_to follow the
            # value through the transform while preserves_whole_value rejects it.
            edges.extend(
                ValueFlowEdge(
                    source_expr=operand_expr,
                    source_location=a.value_location,
                    target_expr=a.target,
                    target_location=a.target_location,
                    kind=FlowKind.TRANSFORM_INPUT,
                    containing_function_fqn=a.containing_function_fqn,
                    provenance=prov,
                )
                for operand_expr in _transform_operand_sources(a.value_expression)
            )

    # Chained assignment inter-target edges (rightmost → next left).
    for group in chained_groups.values():
        for i in range(len(group) - 1):
            right = group[i]
            left = group[i + 1]
            edges.append(
                ValueFlowEdge(
                    source_expr=right.target,
                    source_location=right.target_location,
                    target_expr=left.target,
                    target_location=left.target_location,
                    kind=FlowKind.CHAIN,
                    containing_function_fqn=right.containing_function_fqn,
                    provenance=prov,
                )
            )

    # 2. Alias edges: value flows from the original name to the alias.
    edges.extend(
        ValueFlowEdge(
            source_expr=alias.original_fqn,
            source_location=alias.location,
            target_expr=alias.alias_name,
            target_location=alias.location,
            kind=FlowKind.ALIAS,
            containing_function_fqn=None,
            provenance=prov,
        )
        for alias in aliases
    )

    # 3. Parameter default edges: if a parameter has a default value,
    #    the default flows to the parameter name at the function definition.
    edges.extend(
        ValueFlowEdge(
            source_expr=param.default,
            source_location=param.location,
            target_expr=param.name,
            target_location=param.location,
            kind=FlowKind.ASSIGN,
            containing_function_fqn=fn.fqn,
            provenance=prov,
        )
        for fn in functions
        for param in fn.params
        if param.default is not None
    )

    # 4. Call argument edges: arguments flow to the call site.  L2 owns the
    #    later argument-to-parameter stitching through the call graph.
    for call_edge in call_edges:
        target_expr = call_edge.call_expression or call_edge.callee_fqn or "<call>"
        containing_function_fqn = (
            None if call_edge.caller_fqn == "<module>" else call_edge.caller_fqn
        )
        edges.extend(
            ValueFlowEdge(
                source_expr=argument.expression,
                source_location=argument.location,
                target_expr=target_expr,
                target_location=call_edge.location,
                kind=FlowKind.ARGUMENT,
                containing_function_fqn=containing_function_fqn,
                provenance=prov,
                callsite_callee_fqn=call_edge.callee_fqn,
                callsite_expr=call_edge.call_expression,
                argument_position=argument.position,
                argument_keyword=argument.keyword,
            )
            for argument in call_edge.arguments
        )
        for argument in call_edge.arguments:
            edges.extend(
                ValueFlowEdge(
                    source_expr=element_expr,
                    source_location=argument.location,
                    target_expr=argument.expression,
                    target_location=argument.location,
                    kind=FlowKind.ASSIGN,
                    containing_function_fqn=containing_function_fqn,
                    provenance=prov,
                )
                for element_expr in _expression_component_sources(argument.expression)
            )
            edges.extend(
                ValueFlowEdge(
                    source_expr=element_expr,
                    source_location=argument.location,
                    target_expr=target_expr,
                    target_location=call_edge.location,
                    kind=FlowKind.ARGUMENT,
                    containing_function_fqn=containing_function_fqn,
                    provenance=prov,
                    callsite_callee_fqn=call_edge.callee_fqn,
                    callsite_expr=call_edge.call_expression,
                    argument_position=argument.position,
                    argument_keyword=argument.keyword,
                )
                for element_expr in _expression_component_sources(argument.expression)
            )

    # 5. Return expression edges: expression values flow to the return
    #    statement.  L2 owns return-to-caller stitching.
    edges.extend(
        ValueFlowEdge(
            source_expr=return_fact.expression,
            source_location=return_fact.expression_location,
            target_expr="return",
            target_location=return_fact.statement_location,
            kind=FlowKind.RETURN,
            containing_function_fqn=return_fact.containing_function_fqn,
            provenance=prov,
        )
        for return_fact in returns
        if return_fact.expression is not None and return_fact.expression_location is not None
    )

    # 6. Comprehension binding edges: the iterable feeding a ``for`` clause
    #    flows structurally into the bound target name/expression.
    edges.extend(
        ValueFlowEdge(
            source_expr=binding.iterable_expression,
            source_location=binding.iterable_location,
            target_expr=binding.target,
            target_location=binding.target_location,
            kind=FlowKind.COMPREHENSION_BINDING,
            containing_function_fqn=binding.containing_function_fqn,
            provenance=prov,
        )
        for binding in comprehension_bindings
    )

    # 7. Attribute write edges: value flows from the written expression to
    #    the ``target.attr`` composite name.
    edges.extend(
        ValueFlowEdge(
            source_expr=attr.value_expr,
            source_location=attr.location,
            target_expr=f"{attr.target_expr}.{attr.attr_name}",
            target_location=attr.location,
            kind=FlowKind.ATTRIBUTE_WRITE,
            containing_function_fqn=attr.containing_function_fqn,
            provenance=prov,
        )
        for attr in attribute_writes
        if attr.value_expr is not None
    )

    # 8. Yield expression edges: value flows from the yielded expression
    #    to the yield point.  Bare ``yield`` (no expression) produces no
    #    value edge, matching the return-edge convention.
    edges.extend(
        ValueFlowEdge(
            source_expr=yld.expression,
            source_location=yld.expression_location,
            target_expr="yield",
            target_location=yld.statement_location,
            kind=FlowKind.YIELD,
            containing_function_fqn=yld.containing_function_fqn,
            provenance=prov,
        )
        for yld in yields
        if yld.expression is not None and yld.expression_location is not None
    )

    # No errors expected in this pass — it's purely structural transformation.
    return tuple(edges), ()


def _assignment_kind_to_flow(kind: object) -> FlowKind:
    """Map AssignmentKind to FlowKind."""
    from flawed._index._types import AssignmentKind

    if kind == AssignmentKind.AUGMENTED:
        return FlowKind.AUGMENTED_ASSIGN
    if kind == AssignmentKind.UNPACKING:
        return FlowKind.UNPACK
    if kind == AssignmentKind.ANNOTATED:
        return FlowKind.ANNOTATED_ASSIGN
    return FlowKind.ASSIGN


def _try_decompose_unpack(
    target_csv: str,
    value_csv: str,
) -> list[tuple[str, str]] | None:
    """Try to decompose matching-arity unpacking into per-element pairs.

    Returns a list of ``(value_element, target_element)`` pairs if both
    sides are comma-separated with equal arity and no starred targets.
    Returns ``None`` if decomposition is not structurally safe.
    """
    if "*" in target_csv:
        return None
    targets = [t.strip() for t in target_csv.split(",") if t.strip()]
    values = [v.strip() for v in value_csv.split(",") if v.strip()]
    if len(targets) < 2 or len(targets) != len(values):
        return None
    return list(zip(values, targets, strict=True))


def _expression_component_sources(value_expression: str) -> tuple[str, ...]:
    """Return meaningful source components nested inside compound expressions.

    Starred list/tuple/set elements are deliberately skipped because they
    require sequence expansion semantics.  Dict spreads are retained as
    container sources: ``{**request_data, "safe": value}`` still carries the
    request-derived mapping into the resulting dict, even though exact key
    precedence is modeled by higher layers.  Conditional expressions contribute
    their test and both arms so ``request.json if request.is_json else
    request.form`` preserves flow from both possible request containers.
    """
    try:
        expression = cst.parse_expression(value_expression)
    except cst.ParserSyntaxError:
        return ()

    elements: list[str] = []
    _collect_expression_sources(expression, elements)
    return tuple(elements)


def _collect_expression_sources(
    expression: cst.BaseExpression,
    elements: list[str],
) -> None:
    if isinstance(expression, (cst.List, cst.Tuple, cst.Set)):
        for element in expression.elements:
            if isinstance(element, cst.StarredElement):
                continue
            _append_container_source(element.value, elements)
        return

    if isinstance(expression, cst.Dict):
        for dict_element in expression.elements:
            if isinstance(dict_element, cst.StarredDictElement):
                _append_container_source(dict_element.value, elements)
                continue
            _append_container_source(dict_element.value, elements)
        return

    if isinstance(expression, cst.IfExp):
        _append_container_source(expression.test, elements)
        _append_container_source(expression.body, elements)
        _append_container_source(expression.orelse, elements)


def _append_container_source(
    expression: cst.BaseExpression,
    elements: list[str],
) -> None:
    if isinstance(expression, (cst.List, cst.Tuple, cst.Set, cst.Dict)):
        _collect_expression_sources(expression, elements)
        return
    if isinstance(expression, cst.IfExp):
        _collect_expression_sources(expression, elements)
        return
    if isinstance(expression, (cst.ListComp, cst.SetComp, cst.DictComp, cst.GeneratorExp)):
        return
    elements.append(_render_expression(expression))


def _transform_operand_sources(value_expression: str) -> tuple[str, ...]:
    """Return value-reference operands feeding a call-transform expression.

    For ``email.lower()`` returns ``("email",)``; for
    ``normalize("NFKC", email)`` returns ``("email",)`` (string/number literals
    are skipped); for ``a.b().c(d)`` returns ``("a", "d")``.  These operands
    carry the *provenance* of the transform's result — ``y = x.lower()`` derives
    ``y`` from ``x`` — without claiming whole-value preservation, which is why
    callers emit them as :attr:`~flawed._index._types.FlowKind.TRANSFORM_INPUT`
    edges rather than assignment edges.

    Only call receivers and arguments are peeled; bare names, arithmetic, and
    container literals are handled by their own structural passes.
    """
    try:
        expression = cst.parse_expression(value_expression)
    except cst.ParserSyntaxError:
        return ()

    operands: list[str] = []
    _collect_transform_operands(expression, operands)
    return tuple(dict.fromkeys(operands))


def _collect_transform_operands(
    expression: cst.BaseExpression,
    operands: list[str],
) -> None:
    """Collect value-reference operands of a call expression.

    Peels the receiver of a method call (``x`` in ``x.lower()``) and each
    non-starred, non-literal argument, recursing through nested calls so chained
    transforms (``a.b().c()``) resolve back to their originating value.
    """
    if not isinstance(expression, cst.Call):
        return
    func = expression.func
    if isinstance(func, cst.Attribute):
        _append_transform_operand(func.value, operands)
    for argument in expression.args:
        if argument.star:
            continue
        _append_transform_operand(argument.value, operands)


def _append_transform_operand(
    expression: cst.BaseExpression,
    operands: list[str],
) -> None:
    if isinstance(expression, (cst.SimpleString, cst.ConcatenatedString, cst.FormattedString)):
        return
    if isinstance(expression, (cst.Integer, cst.Float, cst.Imaginary)):
        return
    if isinstance(expression, cst.Call):
        # A nested transform: peel ITS operands rather than the call expression
        # itself (which is not a stable value reference).
        _collect_transform_operands(expression, operands)
        return
    if isinstance(expression, (cst.Name, cst.Attribute, cst.Subscript)):
        operands.append(_render_expression(expression))


def _render_expression(expression: cst.CSTNode) -> str:
    return cst.Module(body=()).code_for_node(expression).strip()


def _detect_chained_groups(
    assignments: tuple[AssignmentFact, ...],
) -> dict[tuple[str, str, str | None], list[AssignmentFact]]:
    """Group assignments that form a chain (``x = y = val``).

    Chained assignments share the same value expression, the same value
    location, and the same containing function. The structural pass emits
    one ``AssignmentFact`` per target in source order (rightmost target first).

    Returns a mapping from ``(value_expression, value_location_key,
    containing_function_fqn)`` to the list of assignments in that chain,
    but only when the chain has 2+ targets.
    """
    from collections import defaultdict

    groups: dict[tuple[str, str, str | None], list[AssignmentFact]] = defaultdict(list)
    for a in assignments:
        loc_key = f"{a.value_location.file}:{a.value_location.line}:{a.value_location.column}"
        groups[(a.value_expression, loc_key, a.containing_function_fqn)].append(a)
    return {k: v for k, v in groups.items() if len(v) >= 2}
