"""FQN alias resolution for the provider engine.

This module bridges structural Layer 1 facts (module-level constructor
assignments, type-annotated local variables) back to provider-declared
class-method FQNs.  It produces the alias mapping that canonicalize_fqn
uses during descriptor matching.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from flawed._index._parsing import parse_analyzed_module
from flawed._index._types import FlowKind, ValueFlowEdge
from flawed._semantic._conversion_utils import simple_name as _simple_name
from flawed._semantic._expr_cache import parse_expression as _parse_expression
from flawed._semantic._matching import (
    _call_callee_expr,
    _dotted_name_parts,
    _module_fqns_by_file,
    _module_level_vf_for_file_all,
    _provider_descriptor_methods,
    _value_flow_for_function,
)
from flawed._semantic._provider_engine import canonicalize_fqn

if TYPE_CHECKING:
    from flawed._index import CodeIndex
    from flawed._semantic.providers import Provider


def _provider_fqn_aliases(provider: Provider, idx: CodeIndex) -> dict[str, str]:
    """Provider aliases plus L1-derived instance-method aliases.

    L1 deliberately records framework object usage structurally. For an object
    assigned from a provider-declared constructor and later used through a
    method reference, the reference resolves to the project variable FQN. This
    L2 helper uses module-level constructor assignments to bridge that
    structural fact back to provider-declared class-method FQNs.
    """
    aliases = dict(provider.fqn_aliases)
    aliases.update(_instance_method_aliases(provider, idx, aliases))
    aliases.update(_local_typed_instance_method_aliases(provider, idx, aliases))
    return aliases


def _instance_method_aliases(
    provider: Provider,
    idx: CodeIndex,
    base_aliases: dict[str, str],
) -> dict[str, str]:
    descriptor_methods = _provider_descriptor_methods(provider)
    if not descriptor_methods:
        return {}

    module_by_file = _module_fqns_by_file(idx)
    aliases: dict[str, str] = {}
    for file, edges in _module_level_vf_for_file_all(idx).items():
        module_fqn = module_by_file.get(file)
        if module_fqn is None:
            continue
        for edge in edges:
            if edge.kind is not FlowKind.ASSIGN:
                continue

            target_name = _simple_name(edge.target_expr)
            if target_name is None:
                continue

            constructor_expr = _call_callee_expr(edge.source_expr)
            if constructor_expr is None:
                continue

            constructor_fqn = idx.symbols.resolve(constructor_expr, edge.source_location.file)
            if constructor_fqn is None:
                constructor_fqn = constructor_expr
            constructor_fqn = canonicalize_fqn(constructor_fqn, base_aliases)

            method_names = descriptor_methods.get(constructor_fqn)
            if method_names is None:
                continue

            variable_fqn = f"{module_fqn}.{target_name}"
            for method_name in method_names:
                aliases[f"{variable_fqn}.{method_name}"] = f"{constructor_fqn}.{method_name}"
    return aliases


def _local_typed_instance_method_aliases(
    provider: Provider,
    idx: CodeIndex,
    base_aliases: dict[str, str],
) -> dict[str, str]:
    """Bridge local typed variables back to provider-declared receiver methods.

    L1 resolves calls on local variables to structural pseudo-FQNs such as
    ``module.handler.<locals>.db.commit``.  When a local assignment carries a
    type annotation or ``# type:`` comment, the provider engine can safely
    canonicalize those receiver calls to the provider's method descriptors.
    """
    descriptor_methods = _provider_descriptor_methods(provider)
    if not descriptor_methods:
        return {}

    local_receivers = _local_call_receiver_keys(idx)
    if not local_receivers:
        return {}

    # Group local_receivers by function FQN, then scan only relevant edges.
    fns_with_receivers: dict[str, set[str]] = {}
    for fn_fqn, target_name in local_receivers:
        fns_with_receivers.setdefault(fn_fqn, set()).add(target_name)

    aliases: dict[str, str] = {}
    for fn_fqn, receiver_names in fns_with_receivers.items():
        for edge in _value_flow_for_function(idx, fn_fqn):
            if edge.kind not in {FlowKind.ASSIGN, FlowKind.ANNOTATED_ASSIGN}:
                continue

            edge_target = _simple_name(edge.target_expr)
            if edge_target is None or edge_target not in receiver_names:
                continue

            annotation = _assignment_type_annotation(edge, idx)
            if annotation is None:
                continue

            receiver_fqn = _resolve_type_annotation_fqn(
                annotation,
                edge.target_location.file,
                idx,
            )
            if receiver_fqn is None:
                continue

            receiver_fqn = canonicalize_fqn(receiver_fqn, base_aliases)
            method_names = descriptor_methods.get(receiver_fqn)
            if method_names is None:
                continue

            local_fqn = f"{fn_fqn}.<locals>.{edge_target}"
            for method_name in method_names:
                aliases[f"{local_fqn}.{method_name}"] = f"{receiver_fqn}.{method_name}"
    return aliases


def _local_call_receiver_keys(idx: CodeIndex) -> frozenset[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for edge in idx.call_graph.edges:
        if edge.callee_fqn is None:
            continue
        prefix = f"{edge.caller_fqn}.<locals>."
        if not edge.callee_fqn.startswith(prefix):
            continue
        receiver_name = edge.callee_fqn.removeprefix(prefix).split(".", maxsplit=1)[0]
        if receiver_name:
            keys.add((edge.caller_fqn, receiver_name))
    return frozenset(keys)


def _assignment_type_annotation(edge: ValueFlowEdge, idx: CodeIndex) -> str | None:
    """Return the syntactic type annotation for a value-flow assignment edge."""
    source = idx.source(edge.target_location)
    if not source:
        return None
    if edge.kind is FlowKind.ASSIGN and "# type:" not in source:
        return None
    if edge.kind is FlowKind.ANNOTATED_ASSIGN and ":" not in source.split("=", maxsplit=1)[0]:
        return None

    try:
        module = parse_analyzed_module(source.strip(), type_comments=True)
    except SyntaxError:
        return None

    for statement in module.body:
        annotation = _statement_type_annotation(statement, edge.target_expr)
        if annotation is not None:
            return annotation
    return None


def _statement_type_annotation(statement: ast.stmt, target_expr: str) -> str | None:
    if isinstance(statement, ast.AnnAssign):
        if ast.unparse(statement.target) == target_expr and statement.value is not None:
            return ast.unparse(statement.annotation)
        return None

    if not isinstance(statement, ast.Assign):
        return None
    if statement.type_comment is None:
        return None
    if any(ast.unparse(target) == target_expr for target in statement.targets):
        return statement.type_comment
    return None


def _resolve_type_annotation_fqn(annotation: str, file: str, idx: CodeIndex) -> str | None:
    """Resolve a source annotation expression to a best-effort FQN."""
    tree = _parse_expression(annotation)
    if tree is None:
        return idx.symbols.resolve(annotation, file) or annotation

    expression = tree.body

    if isinstance(expression, ast.Constant) and isinstance(expression.value, str):
        return _resolve_type_annotation_fqn(expression.value, file, idx)

    while isinstance(expression, ast.Subscript):
        expression = expression.value

    annotation_name = ast.unparse(expression)
    resolved = idx.symbols.resolve(annotation_name, file)
    if resolved is not None:
        return resolved

    dotted = _dotted_name_parts(annotation_name)
    if dotted is None:
        return annotation_name

    head, *tail = dotted
    resolved_head = idx.symbols.resolve(head, file)
    if resolved_head is None:
        return annotation_name
    return ".".join((resolved_head, *tail))
