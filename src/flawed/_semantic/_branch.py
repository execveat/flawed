"""Reconstruct branch-restricted scopes from CFG condition structure."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from flawed._semantic._budget import budgeted
from flawed._semantic._callee_graph import reachable_callees
from flawed._semantic._cfgview import ControlFlowView
from flawed._semantic._conversion_utils import dedupe_domain as _dedupe_domain
from flawed._semantic._conversion_utils import location as _location
from flawed._semantic._expr_cache import parse_expression as _parse_expression
from flawed._semantic._scope import ConcreteCodeScope, dedupe_gaps
from flawed.core import AnalysisGap, GapKind
from flawed.route import HttpMethod

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flawed._index import CodeIndex
    from flawed.calls import CallSite
    from flawed.conditions import Condition
    from flawed.core import Location
    from flawed.effects import Effect
    from flawed.function import Decorator, Function
    from flawed.generated import SafeGeneratedURL
    from flawed.inputs import InputRead
    from flawed.route import Route
    from flawed.sinks import TaintSink
    from flawed.validation import ValidatedValue


@dataclass(frozen=True)
class _BranchContext:
    idx: CodeIndex
    functions_by_fqn: Mapping[str, Function]
    input_reads_by_function: dict[str, list[InputRead]]
    effects_by_function: dict[str, list[Effect]]
    sinks_by_function: dict[str, list[TaintSink]]
    safe_generated_urls_by_function: dict[str, list[SafeGeneratedURL]]
    validated_values_by_function: dict[str, list[ValidatedValue]]
    conditions_by_function: dict[str, list[Condition]]
    call_sites_by_caller: dict[str, list[CallSite]]
    callee_graph: dict[str, set[str]]


def attach_condition_branch_scopes(
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
    *,
    input_reads_by_function: dict[str, list[InputRead]],
    effects_by_function: dict[str, list[Effect]],
    sinks_by_function: dict[str, list[TaintSink]],
    safe_generated_urls_by_function: dict[str, list[SafeGeneratedURL]],
    validated_values_by_function: dict[str, list[ValidatedValue]] | None = None,
    conditions_by_function: dict[str, list[Condition]],
    call_sites_by_caller: dict[str, list[CallSite]],
    callee_graph: dict[str, set[str]],
) -> tuple[AnalysisGap, ...]:
    """Populate ``Condition.true_branch`` / ``false_branch`` CFG scopes."""
    context = _BranchContext(
        idx=idx,
        functions_by_fqn=functions_by_fqn,
        input_reads_by_function=input_reads_by_function,
        effects_by_function=effects_by_function,
        sinks_by_function=sinks_by_function,
        safe_generated_urls_by_function=safe_generated_urls_by_function,
        validated_values_by_function=validated_values_by_function or {},
        conditions_by_function=conditions_by_function,
        call_sites_by_caller=call_sites_by_caller,
        callee_graph=callee_graph,
    )
    gaps: list[AnalysisGap] = []
    for fqn, conditions in budgeted(conditions_by_function.items()):
        if not conditions:
            continue
        function = functions_by_fqn.get(fqn)
        if function is None:
            continue
        cfg_view = ControlFlowView(idx.cfg(fqn), gaps=function.gaps)
        for condition in conditions:
            if not _is_cfg_condition(condition, cfg_view):
                continue
            true_scope, true_gaps = _condition_arm_scope(
                condition,
                direction=True,
                fqn=fqn,
                function=function,
                cfg_view=cfg_view,
                context=context,
            )
            false_scope, false_gaps = _condition_arm_scope(
                condition,
                direction=False,
                fqn=fqn,
                function=function,
                cfg_view=cfg_view,
                context=context,
            )
            object.__setattr__(condition, "_true_branch", true_scope)
            object.__setattr__(condition, "_false_branch", false_scope)
            gaps.extend(true_gaps)
            gaps.extend(false_gaps)
    return dedupe_gaps(tuple(gaps))


def build_method_branch_scopes(
    route: Route,
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
    *,
    input_reads_by_function: dict[str, list[InputRead]],
    effects_by_function: dict[str, list[Effect]],
    sinks_by_function: dict[str, list[TaintSink]],
    safe_generated_urls_by_function: dict[str, list[SafeGeneratedURL]],
    validated_values_by_function: dict[str, list[ValidatedValue]] | None = None,
    conditions_by_function: dict[str, list[Condition]],
    call_sites_by_caller: dict[str, list[CallSite]],
    callee_graph: dict[str, set[str]],
    route_input_reads: tuple[InputRead, ...] = (),
) -> tuple[dict[HttpMethod, ConcreteCodeScope], tuple[AnalysisGap, ...]]:
    """Build per-method branch scopes for a route handler."""
    context = _BranchContext(
        idx=idx,
        functions_by_fqn=functions_by_fqn,
        input_reads_by_function=input_reads_by_function,
        effects_by_function=effects_by_function,
        sinks_by_function=sinks_by_function,
        safe_generated_urls_by_function=safe_generated_urls_by_function,
        validated_values_by_function=validated_values_by_function or {},
        conditions_by_function=conditions_by_function,
        call_sites_by_caller=call_sites_by_caller,
        callee_graph=callee_graph,
    )
    handler_fqn = route.handler.fqn
    function = functions_by_fqn.get(handler_fqn)
    if function is None:
        return {}, ()

    cfg_view = ControlFlowView(idx.cfg(handler_fqn), gaps=function.gaps)
    scopes_by_method: dict[HttpMethod, ConcreteCodeScope] = {}
    gaps: list[AnalysisGap] = []
    for condition in conditions_by_function.get(handler_fqn, ()):
        directions = _method_directions(getattr(condition, "expression", ""), route.methods)
        if not directions:
            continue
        for method, direction in directions.items():
            block_ids = cfg_view.branch_path_block_ids(condition.location, direction=direction)
            if not block_ids:
                gap = _branch_gap(
                    function,
                    f"Could not reconstruct {method.value} branch for {handler_fqn}",
                )
                gaps.append(gap)
                continue
            scope = _scope_for_branch_blocks(
                handler_fqn,
                block_ids=block_ids,
                cfg_view=cfg_view,
                context=context,
                route_input_reads=route_input_reads,
            )
            scopes_by_method[method] = _merge_scope(scopes_by_method.get(method), scope)
    return scopes_by_method, dedupe_gaps(tuple(gaps))


def _condition_arm_scope(
    condition: Condition,
    *,
    direction: bool,
    fqn: str,
    function: Function,
    cfg_view: ControlFlowView,
    context: _BranchContext,
) -> tuple[ConcreteCodeScope, tuple[AnalysisGap, ...]]:
    path_ids = cfg_view.branch_path_block_ids(condition.location, direction=direction)
    if not path_ids:
        gap = _branch_gap(
            function,
            f"Could not reconstruct {'true' if direction else 'false'} branch "
            f"for condition at {condition.location.file}:{condition.location.line}",
        )
        return _empty_scope(gaps=(gap,), cfg_view=cfg_view), (gap,)

    block_ids = cfg_view.branch_arm_block_ids(condition.location, direction=direction)
    if not block_ids:
        return _empty_scope(cfg_view=cfg_view), ()

    scope = _scope_for_branch_blocks(
        fqn,
        block_ids=block_ids,
        cfg_view=cfg_view,
        context=context,
    )
    return scope, ()


def _scope_for_branch_blocks(
    fqn: str,
    *,
    block_ids: frozenset[int],
    cfg_view: ControlFlowView,
    context: _BranchContext,
    route_input_reads: tuple[InputRead, ...] = (),
) -> ConcreteCodeScope:
    root_reads = _items_in_blocks_or_preceding(
        context.input_reads_by_function.get(fqn, ()),
        cfg_view,
        block_ids,
    )
    root_effects = _items_in_blocks_or_preceding(
        context.effects_by_function.get(fqn, ()),
        cfg_view,
        block_ids,
    )
    root_sinks = _items_in_blocks_or_preceding(
        context.sinks_by_function.get(fqn, ()),
        cfg_view,
        block_ids,
    )
    root_safe_generated_urls = _items_in_blocks_or_preceding(
        context.safe_generated_urls_by_function.get(fqn, ()),
        cfg_view,
        block_ids,
    )
    root_validated_values = _items_in_blocks_or_preceding(
        context.validated_values_by_function.get(fqn, ()),
        cfg_view,
        block_ids,
    )
    root_call_sites = _items_in_blocks(
        context.call_sites_by_caller.get(fqn, ()),
        cfg_view,
        block_ids,
    )
    root_conditions = _conditions_in_blocks_or_whole_function(
        context.conditions_by_function.get(fqn, ()),
        cfg_view,
        block_ids,
    )

    reads: list[InputRead] = [*route_input_reads, *root_reads]
    effects: list[Effect] = list(root_effects)
    sinks: list[TaintSink] = list(root_sinks)
    safe_generated_urls: list[SafeGeneratedURL] = list(root_safe_generated_urls)
    validated_values: list[ValidatedValue] = list(root_validated_values)
    call_sites: list[CallSite] = list(root_call_sites)
    conditions: list[Condition] = list(root_conditions)
    decorators: list[Decorator] = []
    gaps: list[AnalysisGap] = []

    root_function = context.functions_by_fqn.get(fqn)
    if root_function is not None:
        decorators.extend(root_function.decorators)
        gaps.extend(root_function.gaps)

    for callee_fqn in _branch_reachable_callees(
        root_call_sites,
        fqn,
        context,
    ):
        reads.extend(context.input_reads_by_function.get(callee_fqn, ()))
        effects.extend(context.effects_by_function.get(callee_fqn, ()))
        sinks.extend(context.sinks_by_function.get(callee_fqn, ()))
        safe_generated_urls.extend(context.safe_generated_urls_by_function.get(callee_fqn, ()))
        validated_values.extend(context.validated_values_by_function.get(callee_fqn, ()))
        call_sites.extend(context.call_sites_by_caller.get(callee_fqn, ()))
        conditions.extend(context.conditions_by_function.get(callee_fqn, ()))
        callee = context.functions_by_fqn.get(callee_fqn)
        if callee is not None:
            decorators.extend(callee.decorators)
            gaps.extend(callee.gaps)

    return ConcreteCodeScope(
        input_reads=_dedupe_domain(reads),
        effects=_dedupe_domain(effects),
        sinks=_dedupe_domain(sinks),
        safe_generated_urls=_dedupe_domain(safe_generated_urls),
        validated_values=_dedupe_domain(validated_values),
        call_sites=_dedupe_domain(call_sites),
        conditions=_dedupe_domain(conditions),
        decorators=_dedupe_domain(decorators),
        gaps=dedupe_gaps(tuple(gaps)),
        cfg=cfg_view.restricted_to(block_ids),
    )


def _empty_scope(
    *,
    gaps: tuple[AnalysisGap, ...] = (),
    cfg_view: ControlFlowView | None = None,
) -> ConcreteCodeScope:
    return ConcreteCodeScope(gaps=gaps, cfg=cfg_view)


def _merge_scope(
    left: ConcreteCodeScope | None,
    right: ConcreteCodeScope,
) -> ConcreteCodeScope:
    if left is None:
        return right

    return ConcreteCodeScope(
        input_reads=_dedupe_domain([*left.reads(), *right.reads()]),
        effects=_dedupe_domain([*left.effects(), *right.effects()]),
        sinks=_dedupe_domain([*left.sinks(), *right.sinks()]),
        safe_generated_urls=_dedupe_domain(
            [*_scope_safe_generated_urls(left), *_scope_safe_generated_urls(right)]
        ),
        validated_values=_dedupe_domain(
            [*_scope_validated_values(left), *_scope_validated_values(right)]
        ),
        call_sites=_dedupe_domain([*left.calls(), *right.calls()]),
        conditions=_dedupe_domain([*left.conditions(), *right.conditions()]),
        decorators=_dedupe_domain([*left.decorators(), *right.decorators()]),
        gaps=dedupe_gaps((*left.gaps, *right.gaps)),
        cfg=right.cfg,
    )


def _scope_safe_generated_urls(scope: ConcreteCodeScope) -> tuple[SafeGeneratedURL, ...]:
    try:
        value = object.__getattribute__(scope, "_safe_generated_urls")
    except AttributeError:
        return ()
    return cast("tuple[SafeGeneratedURL, ...]", value)


def _scope_validated_values(scope: ConcreteCodeScope) -> tuple[ValidatedValue, ...]:
    try:
        value = object.__getattribute__(scope, "_validated_values")
    except AttributeError:
        return ()
    return cast("tuple[ValidatedValue, ...]", value)


def _items_in_blocks[T](
    items: list[T] | tuple[T, ...],
    cfg_view: ControlFlowView,
    block_ids: frozenset[int],
) -> list[T]:
    return [
        item
        for item in items
        if (block_id := _item_block_id(item, cfg_view)) is not None and block_id in block_ids
    ]


def _items_in_blocks_or_preceding[T](
    items: list[T] | tuple[T, ...],
    cfg_view: ControlFlowView,
    block_ids: frozenset[int],
) -> list[T]:
    """Return child-scope items plus facts inherited from dominating parents."""
    selected_block_locations = _block_locations(cfg_view, block_ids)
    result: list[T] = []
    for item in items:
        item_block_id = _item_block_id(item, cfg_view)
        if item_block_id is not None and item_block_id in block_ids:
            result.append(item)
            continue
        item_location = getattr(item, "location", None)
        if item_location is None:
            continue
        if any(
            cfg_view.precedes(item_location, block_location)
            for block_location in selected_block_locations
        ):
            result.append(item)
    return result


def _block_locations(
    cfg_view: ControlFlowView,
    block_ids: frozenset[int],
) -> tuple[Location, ...]:
    locations: list[Location] = []
    for block in cfg_view.blocks:
        if block.id not in block_ids:
            continue
        span = block.statements[0] if block.statements else block.condition_location
        if span is None:
            continue
        locations.append(_location(span))
    return tuple(locations)


def _conditions_in_blocks_or_whole_function(
    conditions: list[Condition] | tuple[Condition, ...],
    cfg_view: ControlFlowView,
    block_ids: frozenset[int],
) -> list[Condition]:
    result = _items_in_blocks(conditions, cfg_view, block_ids)
    result.extend(
        condition
        for condition in conditions
        if _item_block_id(condition, cfg_view) is None and getattr(condition, "category", None)
    )
    return list(_dedupe_domain(result))


def _item_block_id(item: object, cfg_view: ControlFlowView) -> int | None:
    location = getattr(item, "location", None)
    if location is None:
        return None
    return cfg_view.block_id_for(location)


def _branch_reachable_callees(
    call_sites: list[CallSite],
    root_fqn: str,
    context: _BranchContext,
) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = {root_fqn}
    for call in call_sites:
        target_fqn = _call_target_fqn(call, context.functions_by_fqn)
        if target_fqn is None:
            continue
        for callee in reachable_callees(target_fqn, context.callee_graph):
            if callee in seen:
                continue
            seen.add(callee)
            result.append(callee)
    return tuple(result)


def _call_target_fqn(call: CallSite, functions_by_fqn: Mapping[str, Function]) -> str | None:
    target = call.target
    if target is not None:
        return target.fqn
    if call.target_fqn in functions_by_fqn:
        return call.target_fqn
    return None


def _is_cfg_condition(condition: object, cfg_view: ControlFlowView) -> bool:
    location = getattr(condition, "location", None)
    expression = getattr(condition, "expression", None)
    if location is None or not isinstance(expression, str):
        return False
    block_id = cfg_view.block_id_for(location)
    if block_id is None:
        return False
    for block in cfg_view.blocks:
        if block.id == block_id and block.condition_expr == expression:
            return True
    return False


@dataclass(frozen=True)
class _MethodPredicate:
    true_methods: frozenset[HttpMethod] = frozenset()
    false_methods: frozenset[HttpMethod] = frozenset()


def _method_directions(
    expression: str,
    route_methods: frozenset[HttpMethod],
) -> dict[HttpMethod, bool]:
    predicate = _method_predicate(expression)
    if predicate is None:
        return {}

    directions: dict[HttpMethod, bool] = {}
    for method in predicate.true_methods & route_methods:
        directions[method] = True
    for method in predicate.false_methods & route_methods:
        directions[method] = False

    if predicate.true_methods:
        remaining = route_methods - predicate.true_methods
        if len(remaining) == 1:
            directions[next(iter(remaining))] = False
    if predicate.false_methods:
        remaining = route_methods - predicate.false_methods
        if len(remaining) == 1:
            directions[next(iter(remaining))] = True
    return directions


def _method_predicate(expression: str) -> _MethodPredicate | None:
    tree = _parse_expression(expression)
    if tree is None:
        return None
    return _method_predicate_for_node(tree.body)


def _method_predicate_for_node(node: ast.expr) -> _MethodPredicate | None:
    if isinstance(node, ast.Compare):
        return _method_predicate_for_compare(node)
    if isinstance(node, ast.BoolOp):
        parts = [_method_predicate_for_node(value) for value in node.values]
        if any(part is None for part in parts):
            return None
        predicates = [part for part in parts if part is not None]
        if isinstance(node.op, ast.Or) and all(not part.false_methods for part in predicates):
            return _MethodPredicate(
                true_methods=frozenset().union(*(part.true_methods for part in predicates))
            )
        if isinstance(node.op, ast.And) and all(not part.true_methods for part in predicates):
            return _MethodPredicate(
                false_methods=frozenset().union(*(part.false_methods for part in predicates))
            )
    return None


def _method_predicate_for_compare(node: ast.Compare) -> _MethodPredicate | None:
    if len(node.ops) != 1 or len(node.comparators) != 1:
        return None

    left = node.left
    right = node.comparators[0]
    op = node.ops[0]

    if _is_method_expr(left):
        methods = _method_literals(right)
    elif _is_method_expr(right):
        methods = _method_literals(left)
    else:
        return None
    if not methods:
        return None

    predicate: _MethodPredicate | None = None
    if isinstance(op, ast.Eq):
        predicate = _MethodPredicate(true_methods=methods)
    elif isinstance(op, ast.NotEq):
        predicate = _MethodPredicate(false_methods=methods)
    elif isinstance(op, ast.In):
        predicate = _MethodPredicate(true_methods=methods)
    elif isinstance(op, ast.NotIn):
        predicate = _MethodPredicate(false_methods=methods)
    return predicate


def _is_method_expr(node: ast.expr) -> bool:
    if isinstance(node, ast.Attribute):
        return node.attr == "method" and _is_request_value(node.value)
    if isinstance(node, ast.Name):
        return node.id in {"method", "http_method", "request_method"}
    return False


def _is_request_value(node: ast.expr) -> bool:
    if isinstance(node, ast.Name):
        return node.id in {"request", "req"}
    return isinstance(node, ast.Attribute) and node.attr == "request"


def _method_literals(node: ast.expr) -> frozenset[HttpMethod]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        method = _http_method(node.value)
        return frozenset({method}) if method is not None else frozenset()
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        methods: list[HttpMethod] = []
        for elt in node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                method = _http_method(elt.value)
                if method is not None:
                    methods.append(method)
        return frozenset(methods)
    return frozenset()


def _http_method(value: str) -> HttpMethod | None:
    try:
        return HttpMethod(value.upper())
    except ValueError:
        return None


def _branch_gap(function: Function, message: str) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.CFG_RECONSTRUCTION_FAILURE,
        message=message,
        affected_file=function.location.file,
        affected_function=function.fqn,
        origin_phase="branch_reconstruction",
    )
