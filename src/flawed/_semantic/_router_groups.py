"""Router group extraction for the provider engine.

This module scans Layer 1 value-flow and call-graph edges to extract
router-group metadata (group name, URL prefix) from constructor
assignments and mount calls declared by providers.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from flawed._index._types import FlowKind
from flawed._semantic._conversion_utils import simple_name as _simple_name
from flawed._semantic._expr_cache import parse_expression as _parse_expression
from flawed._semantic._matching import _as_tuple, _module_fqns_by_file
from flawed._semantic._predicate_eval import _find_argument
from flawed._semantic._provider_engine import (
    RouterGroupInfo,
    canonicalize_fqn,
)
from flawed.core import AnalysisGap, GapKind

if TYPE_CHECKING:
    from flawed._index import CodeIndex
    from flawed._semantic.providers import Provider, RouterGroupMountPattern, RouterGroupPattern


def _collect_group_constructor_fqns(
    providers: tuple[Provider, ...],
) -> dict[str, RouterGroupPattern]:
    """Collect router-group constructor FQNs from active providers.

    Returns a mapping from canonical constructor FQN to the pattern
    that declared it, so the engine knows which name_arg and prefix_kwarg
    to use when parsing the constructor call.
    """
    result: dict[str, RouterGroupPattern] = {}
    for provider in providers:
        for pattern in provider.router_groups:
            for fqn in _as_tuple(pattern.constructor_fqn):
                result[fqn] = pattern
    return result


def _collect_mount_patterns(
    providers: tuple[Provider, ...],
) -> tuple[RouterGroupMountPattern, ...]:
    """Collect router-group mount patterns from active providers."""
    return tuple(pattern for provider in providers for pattern in provider.router_group_mounts)


def _extract_router_group_info(
    idx: CodeIndex,
    aliases: dict[str, str],
    providers: tuple[Provider, ...],
) -> tuple[RouterGroupInfo, ...]:
    """Extract router-group metadata from module-level constructor assignments.

    Scans the same value-flow ASSIGN edges as ``_instance_method_aliases``
    but extracts the constructor's name argument and prefix keyword.
    Then scans call edges and value-flow for mount calls that may
    override the prefix.
    """
    group_patterns = _collect_group_constructor_fqns(providers)
    if not group_patterns:
        return ()

    mount_patterns = _collect_mount_patterns(providers)

    module_by_file = _module_fqns_by_file(idx)
    infos: dict[str, RouterGroupInfo] = {}
    # Track variable FQN → canonical class FQN for all constructor
    # assignments so mount-call resolution can identify app instances.
    instance_classes: dict[str, str] = {}

    for edge in idx.value_flow.edges:
        if edge.kind is not FlowKind.ASSIGN:
            continue

        target_name = _simple_name(edge.target_expr)
        if target_name is None:
            continue

        # Compute the assigned variable's FQN. A module-level constructor
        # (``bp = Blueprint(...)`` at top level) keys by module. A constructor
        # inside a factory / ``init_app`` function (the
        # ``load_blueprints(app)`` factory pattern, where the Blueprint is a
        # function-local) keys by the enclosing function's ``<locals>`` scope,
        # so the FQN matches the receiver L1 records for in-function route
        # registrations — e.g. ``app.load_blueprints.<locals>.auth`` for an
        # ``auth.add_url_rule(...)`` call site. Without this, factory-pattern
        # blueprints are never found and every route gets group=None.
        if edge.containing_function_fqn is None:
            module_fqn = module_by_file.get(edge.target_location.file)
            if module_fqn is None:
                continue
            variable_fqn = f"{module_fqn}.{target_name}"
        else:
            variable_fqn = f"{edge.containing_function_fqn}.<locals>.{target_name}"

        call_node = _parse_call_node(edge.source_expr)
        if call_node is None:
            continue

        constructor_expr_str = ast.unparse(call_node.func)
        constructor_fqn = idx.symbols.resolve(constructor_expr_str, edge.source_location.file)
        if constructor_fqn is None:
            constructor_fqn = constructor_expr_str
        constructor_fqn = canonicalize_fqn(constructor_fqn, aliases)

        instance_classes[variable_fqn] = constructor_fqn

        pattern = group_patterns.get(constructor_fqn)
        if pattern is None:
            continue

        group, group_gaps = _extract_group_name(call_node, variable_fqn, pattern.name_arg)
        prefix, prefix_gaps = _extract_group_prefix(call_node, variable_fqn, pattern.prefix_kwarg)

        infos[variable_fqn] = RouterGroupInfo(
            variable_fqn=variable_fqn,
            constructor_fqn=constructor_fqn,
            group=group,
            url_prefix=prefix,
            group_gaps=group_gaps,
            prefix_gaps=prefix_gaps,
        )

    # Scan call edges and value-flow for mount-call prefix overrides.
    _apply_mount_overrides(infos, instance_classes, idx, aliases, mount_patterns)

    return tuple(infos.values())


def _extract_group_name(
    call_node: ast.Call,
    variable_fqn: str,
    name_arg: int,
) -> tuple[str | None, tuple[AnalysisGap, ...]]:
    """Extract the router-group name from a positional constructor arg."""
    if name_arg >= len(call_node.args):
        return None, (
            AnalysisGap(
                kind=GapKind.INFERENCE_FAILURE,
                message=f"Router group {variable_fqn}: missing name argument",
                source_error="router_group_extraction: no positional args",
                origin_phase="router_group_extraction",
            ),
        )
    arg_node = call_node.args[name_arg]
    literal = _try_ast_literal_string(arg_node)
    if literal is not None:
        return literal, ()
    return None, (
        AnalysisGap(
            kind=GapKind.INFERENCE_FAILURE,
            message=f"Router group {variable_fqn}: dynamic name ({ast.unparse(arg_node)})",
            source_error="router_group_extraction: non-literal name",
            origin_phase="router_group_extraction",
        ),
    )


def _extract_group_prefix(
    call_node: ast.Call,
    variable_fqn: str,
    prefix_kwarg: str,
) -> tuple[str | None, tuple[AnalysisGap, ...]]:
    """Extract URL prefix from the constructor keyword args."""
    for kw in call_node.keywords:
        if kw.arg == prefix_kwarg:
            literal = _try_ast_literal_string(kw.value)
            if literal is not None:
                return literal, ()
            return None, (
                AnalysisGap(
                    kind=GapKind.INFERENCE_FAILURE,
                    message=(
                        f"Router group {variable_fqn}: "
                        f"dynamic {prefix_kwarg} ({ast.unparse(kw.value)})"
                    ),
                    source_error="router_group_extraction: non-literal prefix",
                    origin_phase="router_group_extraction",
                ),
            )
    return None, ()


def _apply_mount_overrides(
    infos: dict[str, RouterGroupInfo],
    instance_classes: dict[str, str],
    idx: CodeIndex,
    aliases: dict[str, str],
    mount_patterns: tuple[RouterGroupMountPattern, ...],
) -> None:
    """Override URL prefix from mount calls declared by providers.

    Checks both call graph edges (for in-function calls) and module-level
    value-flow argument edges (for top-level mount calls that L1 records
    as argument flows rather than call edges).
    """
    if not mount_patterns:
        return
    _apply_mount_from_call_edges(infos, instance_classes, idx, aliases, mount_patterns)
    _apply_mount_from_value_flow(infos, idx, mount_patterns)


def _apply_mount_from_call_edges(
    infos: dict[str, RouterGroupInfo],
    instance_classes: dict[str, str],
    idx: CodeIndex,
    aliases: dict[str, str],
    mount_patterns: tuple[RouterGroupMountPattern, ...],
) -> None:
    """Extract mount calls from in-function call edges."""
    for mount_pattern in mount_patterns:
        app_fqns = frozenset(_as_tuple(mount_pattern.app_fqn))
        mount_method = mount_pattern.mount_method

        for edge in idx.call_graph.edges:
            if edge.callee_fqn is None:
                continue

            receiver, sep, method = edge.callee_fqn.rpartition(".")
            if not sep or method != mount_method:
                continue
            receiver_class = instance_classes.get(receiver)
            if receiver_class is None:
                canonical_receiver = canonicalize_fqn(receiver, aliases)
                receiver_class = instance_classes.get(canonical_receiver)
            if receiver_class not in app_fqns:
                continue

            prefix_arg = _find_argument(
                edge.arguments, position=None, keyword=mount_pattern.prefix_kwarg
            )
            if prefix_arg is None:
                continue

            group_arg = _find_argument(
                edge.arguments, position=mount_pattern.group_arg, keyword=None
            )
            if group_arg is None:
                continue
            group_name = _simple_name(group_arg.expression)
            if group_name is None:
                continue

            _update_group_prefix(infos, group_name, prefix_arg.expression)


def _apply_mount_from_value_flow(
    infos: dict[str, RouterGroupInfo],
    idx: CodeIndex,
    mount_patterns: tuple[RouterGroupMountPattern, ...],
) -> None:
    """Extract mount calls from module-level argument flow edges.

    Module-level mount calls don't appear in the call graph (no
    containing function).  L1 records the arguments as
    ``FlowKind.ARGUMENT`` value-flow edges with ``target_expr``
    ending in the mount method name.  We group by (file, line) to
    reconstruct individual call sites.
    """
    mount_suffixes = tuple(f".{p.mount_method}" for p in mount_patterns)
    if not mount_suffixes:
        return

    call_site_args: dict[tuple[str, int], list[str]] = {}

    for edge in idx.value_flow.edges:
        if edge.kind is not FlowKind.ARGUMENT or edge.containing_function_fqn is not None:
            continue
        if not any(edge.target_expr.endswith(suffix) for suffix in mount_suffixes):
            continue
        key = (edge.target_location.file, edge.target_location.line)
        call_site_args.setdefault(key, []).append(edge.source_expr)

    for args in call_site_args.values():
        if not args:
            continue
        # First non-string-literal arg is likely the group variable.
        group_name: str | None = None
        prefix_expr: str | None = None
        for a in args:
            name = _simple_name(a)
            if name is not None and group_name is None:
                group_name = name
            elif _try_literal_string_from_expression(a) is not None and prefix_expr is None:
                prefix_expr = a

        if group_name is not None and prefix_expr is not None:
            _update_group_prefix(infos, group_name, prefix_expr)


def _update_group_prefix(
    infos: dict[str, RouterGroupInfo],
    group_var_name: str,
    prefix_expression: str,
) -> None:
    """Update a router group's URL prefix from a mount call."""
    prefix_literal = _try_literal_string_from_expression(prefix_expression)
    for var_fqn, info in infos.items():
        if var_fqn.endswith(f".{group_var_name}"):
            if prefix_literal is not None:
                infos[var_fqn] = RouterGroupInfo(
                    variable_fqn=info.variable_fqn,
                    constructor_fqn=info.constructor_fqn,
                    group=info.group,
                    url_prefix=prefix_literal,
                    group_gaps=info.group_gaps,
                    prefix_gaps=(),
                )
            else:
                infos[var_fqn] = RouterGroupInfo(
                    variable_fqn=info.variable_fqn,
                    constructor_fqn=info.constructor_fqn,
                    group=info.group,
                    url_prefix=None,
                    group_gaps=info.group_gaps,
                    prefix_gaps=(
                        AnalysisGap(
                            kind=GapKind.INFERENCE_FAILURE,
                            message=(f"Router group {var_fqn}: dynamic prefix in mount call"),
                            source_error="router_group_extraction: non-literal mount prefix",
                            origin_phase="router_group_extraction",
                        ),
                    ),
                )
            break


def _parse_call_node(expression: str) -> ast.Call | None:
    """Parse a source expression and return its Call AST node, or None."""
    tree = _parse_expression(expression)
    if tree is None:
        return None
    node = tree.body
    if isinstance(node, ast.Call):
        return node
    return None


def _try_ast_literal_string(node: ast.expr) -> str | None:
    """Extract a literal string from an AST expression node."""
    try:
        value = ast.literal_eval(node)
    except (SyntaxError, ValueError):
        return None
    return value if isinstance(value, str) else None


def _try_literal_string_from_expression(expression: str) -> str | None:
    """Extract a literal string value from a source expression string."""
    try:
        value = ast.literal_eval(expression)
    except (SyntaxError, ValueError):
        return None
    return value if isinstance(value, str) else None
