"""Infer dynamic dispatch through a locally-constructed literal dict table.

Resolves ``table[key](...)`` where ``table`` is bound *exactly once* in the
calling function to a dict **display literal** whose values are all bare
references to project functions, and ``table`` is never mutated, reassigned,
unpacked, or parameter-sourced within that function. Under those closed-world
conditions the set of possible dispatch targets is statically known (the union
of the literal's values, since any key could be selected at runtime), so each
becomes a synthetic caller -> target reachability edge — letting the dispatched
function's reads/effects enter the caller's (and transitively the route's)
reachable scope.

This deepens FLAW-231, which records a ``VALUE_FLOW_INCOMPLETE`` gap for every
dynamic-dispatch call. This pass *adds* reachability only when it can be proven
correct by construction; **any** uncertainty (mutation, reassignment,
non-literal or unresolvable value, attribute-rooted base, parameter/global
source) yields no edge, leaving FLAW-231's honest gap in place. It therefore
only ever ADDS correctly-attributed reachability or defers to the gap — it never
guesses a callee, so it cannot introduce a wrong attribution (an FP and a masked
FN) the way a heuristic resolver would.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from flawed._index._types import FlowKind
from flawed._semantic._conversion_utils import location
from flawed._semantic._dispatch_conversion import DispatchEdge
from flawed._semantic._expr_cache import parse_expression as _parse_expression
from flawed.core import Provenance

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flawed._index import CodeIndex
    from flawed._index._types import FunctionRecord
    from flawed.function import Function

# L1 records this string in ``CallEdge.dynamic_dispatch_kind`` for ``table[k](...)``
# call shapes (see ``_index/_structural.py`` ``_DYNAMIC_DISPATCH_TABLE``).
_TABLE_DISPATCH_KIND = "table"

# Value-flow edge kinds that count as a *binding* of the table name. Anything
# else targeting the name (ALIAS, UNPACK, AUGMENTED_ASSIGN, CHAIN, ARGUMENT,
# RETURN) means the binding is not a single clean literal assignment, so we bail.
_BINDING_KINDS = frozenset({FlowKind.ASSIGN, FlowKind.ANNOTATED_ASSIGN})

_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="literal_table_dispatch",
    confidence=0.85,
    supporting_facts=(
        "call dispatches through table[key](...)",
        "table is bound once to a dict literal of resolvable project functions",
        "table is never mutated, reassigned, or parameter-sourced in the caller",
    ),
)


def infer_table_dispatch_edges(
    idx: CodeIndex,
    *,
    functions_by_fqn: Mapping[str, Function],
) -> tuple[DispatchEdge, ...]:
    """Infer caller -> target edges for statically-resolvable literal dispatch tables."""
    records_by_fqn = {fn.fqn: fn for fn in idx.functions}
    edges: list[DispatchEdge] = []
    seen: set[tuple[str, str, str, int, int | None]] = set()

    for call_edge in idx.call_graph.edges:
        if call_edge.dynamic_dispatch_kind != _TABLE_DISPATCH_KIND:
            continue
        base = _subscript_base_name(call_edge.call_expression)
        if base is None:
            continue
        caller_fqn = call_edge.caller_fqn

        binding = _sole_literal_binding(base, caller_fqn, idx, records_by_fqn)
        if binding is None:
            continue
        source_expr, source_file = binding

        targets = _literal_function_targets(source_expr, source_file, idx, functions_by_fqn)
        if targets is None:
            continue

        for target in targets:
            key = (
                caller_fqn,
                target.fqn,
                call_edge.location.file,
                call_edge.location.line,
                call_edge.location.column,
            )
            if key in seen:
                continue
            seen.add(key)
            edges.append(
                DispatchEdge(
                    caller_fqn=caller_fqn,
                    target=target,
                    dispatch_type="literal_table",
                    location=location(call_edge.location),
                    provenance=_PROVENANCE,
                )
            )
    return tuple(edges)


def _subscript_base_name(call_expression: str | None) -> str | None:
    """Return the base variable of a ``base[key](...)`` call, or ``None``.

    Only the direct ``Name[...]( ... )`` shape qualifies: the called object must
    be the subscript value itself. Attribute-rooted bases (``self.table[k]``,
    ``obj.table[k]``) and method-suffixed dispatch (``table[k].run()``) cannot be
    proven from a single local binding, so they return ``None`` (kept as a gap).
    """
    if not call_expression:
        return None
    parsed = _parse_expression(call_expression)
    if parsed is None or not isinstance(parsed.body, ast.Call):
        return None
    func = parsed.body.func
    if not isinstance(func, ast.Subscript):
        return None
    return func.value.id if isinstance(func.value, ast.Name) else None


def _sole_literal_binding(
    base: str,
    caller_fqn: str,
    idx: CodeIndex,
    records_by_fqn: Mapping[str, FunctionRecord],
) -> tuple[str, str] | None:
    """Return ``(dict_source_expr, file)`` iff *base* is provably a static table.

    Requires, within *caller_fqn*: exactly one value-flow edge targeting *base*,
    of a binding kind (``=`` / annotated ``=``); no write access of any kind to
    *base* (subscript-set, ``.update()``, ``del``, augmented, attribute write);
    and *base* not being a parameter. Any deviation returns ``None``.
    """
    target_edges = [
        e
        for e in idx.value_flow.edges
        if e.target_expr == base and e.containing_function_fqn == caller_fqn
    ]
    if len(target_edges) != 1:
        return None
    binding = target_edges[0]
    if binding.kind not in _BINDING_KINDS:
        return None

    # Any write-access to the name (handlers[k]=v, handlers.update(...), del,
    # augmented, attribute write) means the table is mutated -> not closed-world.
    for access in idx.attributes:
        if (
            access.is_write
            and access.target_expr == base
            and access.containing_function_fqn == caller_fqn
        ):
            return None

    # A parameter-sourced table is supplied by the caller -> not closed-world.
    record = records_by_fqn.get(caller_fqn)
    if record is not None and any(param.name == base for param in record.params):
        return None

    return binding.source_expr, binding.source_location.file


def _literal_function_targets(
    source_expr: str,
    file: str,
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> list[Function] | None:
    """Resolve a dict-literal's values to project functions, or ``None``.

    All-or-nothing: the source must parse to a non-empty dict **display** literal
    (not a comprehension, not ``dict(...)``) whose every value is a bare ``Name``
    resolving — via the symbol index in *file* — to a function present in
    *functions_by_fqn*. A single unresolvable or non-bare-name value returns
    ``None`` so the site stays a gap rather than being partially (mis)attributed.
    """
    parsed = _parse_expression(source_expr)
    if parsed is None or not isinstance(parsed.body, ast.Dict) or not parsed.body.values:
        return None

    targets: list[Function] = []
    for value in parsed.body.values:
        if not isinstance(value, ast.Name):
            return None
        fqn = idx.symbols.resolve(value.id, file)
        if fqn is None:
            return None
        target = functions_by_fqn.get(fqn)
        if target is None:
            return None
        targets.append(target)
    return targets
