"""Infer dynamic dispatch from ``self``/``cls`` method calls to their MRO target.

A call like ``self.handler()`` or ``getattr(self, "handler")()`` is left
*unresolved* by the L1 static call graph: ``self`` has no statically-known class
at the call site, so L1 records the edge with ``callee_fqn is None`` (a
FLAW-231 ``VALUE_FLOW_INCOMPLETE`` / dynamic-dispatch gap) and the dispatched
method's reads and effects never enter the caller's (and transitively the
route's) reachable scope. In practice this starves provider matching: authz
helpers, validators, and guard methods invoked through ``self`` look unreachable.

This pass recovers the receiver's class from the *enclosing* method
(``FunctionRecord.parent_class`` — the static class of ``self``/``cls``) and
walks that class's locally-resolved C3 MRO to find the method that runs. It
mirrors ``_property_setter_dispatch`` and ``_table_dispatch`` and holds the same
monotone, resolve-or-gap contract:

* it only ever resolves an edge L1 left *unresolved* (``callee_fqn is None``) — it
  never shadows or duplicates an edge L1 already resolved;
* it fires only when the receiver is a bare ``self``/``cls`` (so the static class
  is exactly the enclosing class) AND that class's MRO is fully known
  (``mro_complete``); any external/unresolved base leaves FLAW-231's gap in place;
* it resolves to the single monomorphic MRO target (the method that runs when the
  instance is exactly the enclosing class) and does **not** over-approximate to
  subclass overrides — that would attribute a subclass body to a base-rooted
  scope (an FP and a masked FN), the very thing the sibling passes refuse to do.

So it only ever ADDS a correctly-attributed reachability edge or defers to the
gap; it cannot introduce a wrong attribution the way a heuristic resolver would,
and adding an edge can only grow reachable scope, so it can only reduce false
negatives. Constructor-bound, annotated, and instance-attribute receivers beyond
bare ``self``/``cls`` are deliberately out of scope (FLAW-266b / FLAW-249).
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from flawed._semantic._conversion_utils import location
from flawed._semantic._dispatch_conversion import DispatchEdge
from flawed._semantic._expr_cache import parse_expression as _parse_expression
from flawed.core import Provenance

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from flawed._index import CodeIndex
    from flawed._index._types import CallEdge, ClassRecord, FunctionRecord
    from flawed.function import Function

# Bare receivers whose static class is exactly the enclosing class.
_SELF_RECEIVERS = frozenset({"self", "cls"})

# L1 records this in ``CallEdge.dynamic_dispatch_kind`` for ``getattr(x, "m")()``
# (see ``_index/_structural.py`` ``_DYNAMIC_DISPATCH_GETATTR``).
_GETATTR_DISPATCH_KIND = "getattr"

_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="method_dispatch",
    confidence=0.85,
    supporting_facts=(
        "call dispatches on a bare self/cls receiver",
        "the enclosing class MRO is fully resolved and defines the method",
    ),
)


def infer_method_dispatch_edges(
    idx: CodeIndex,
    *,
    functions_by_fqn: Mapping[str, Function],
) -> tuple[DispatchEdge, ...]:
    """Infer caller -> target edges for unresolved ``self``/``cls`` method calls."""
    records_by_fqn = _records_by_fqn(idx.functions)
    classes_by_fqn = {cls.fqn: cls for cls in idx.classes}
    methods_by_class = _methods_by_class(idx.functions)
    edges: list[DispatchEdge] = []
    seen: set[tuple[str, str, str, int, int | None]] = set()

    for call_edge in idx.call_graph.edges:
        # Only fill genuine L1 gaps; never shadow an edge L1 already resolved.
        if call_edge.callee_fqn is not None:
            continue
        member = _self_dispatch_member(call_edge)
        if member is None:
            continue
        caller = records_by_fqn.get(call_edge.caller_fqn)
        if caller is None or caller.parent_class is None:
            continue
        target_fqn = _resolve_via_mro(
            caller.parent_class,
            member,
            classes_by_fqn=classes_by_fqn,
            methods_by_class=methods_by_class,
        )
        if target_fqn is None:
            continue
        target = functions_by_fqn.get(target_fqn)
        if target is None:
            continue
        key = (
            call_edge.caller_fqn,
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
                caller_fqn=call_edge.caller_fqn,
                target=target,
                dispatch_type="method_self",
                location=location(call_edge.location),
                provenance=_PROVENANCE,
            )
        )
    return tuple(edges)


def _records_by_fqn(functions: Iterable[FunctionRecord]) -> dict[str, FunctionRecord]:
    # Duplicate FQNs can occur (e.g. property getter/setter pairs). Keep the first
    # record; this lookup is only used for the caller's containing class.
    records: dict[str, FunctionRecord] = {}
    for fn in functions:
        records.setdefault(fn.fqn, fn)
    return records


def _methods_by_class(functions: Iterable[FunctionRecord]) -> dict[tuple[str, str], str]:
    """Map ``(class_fqn, method_short_name) -> method_fqn`` for class-defined methods."""
    methods: dict[tuple[str, str], str] = {}
    for fn in functions:
        if fn.parent_class is None:
            continue
        methods.setdefault((fn.parent_class, fn.name), fn.fqn)
    return methods


def _self_dispatch_member(call_edge: CallEdge) -> str | None:
    """Recover the called member name for a bare ``self``/``cls`` dispatch, else ``None``.

    Two unresolved shapes qualify, both recovered from ``call_expression``:

    * ``getattr(self, "name")()`` — ``dynamic_dispatch_kind == "getattr"``; the
      receiver and the literal member name live inside the ``getattr`` call (which
      is what ``call_expression`` stores for this shape).
    * ``self.name()`` — ``receiver_expression in {self, cls}`` with an unresolved
      ``callee_fqn``; the member is the attribute name.
    """
    expr = call_edge.call_expression
    if expr is None:
        return None
    if call_edge.dynamic_dispatch_kind == _GETATTR_DISPATCH_KIND:
        return _getattr_self_member(expr)
    if call_edge.receiver_expression in _SELF_RECEIVERS:
        return _attribute_self_member(expr)
    return None


def _getattr_self_member(call_expression: str) -> str | None:
    """Member name from ``getattr(self|cls, "literal")``, else ``None`` (gap stays).

    Only a bare ``self``/``cls`` first argument and a *string-literal* second
    argument qualify. A non-literal name (``getattr(self, name)``) or a non-self
    receiver keeps the gap — never a guess.
    """
    parsed = _parse_expression(call_expression)
    if parsed is None or not isinstance(parsed.body, ast.Call):
        return None
    call = parsed.body
    if not (isinstance(call.func, ast.Name) and call.func.id == "getattr"):
        return None
    if call.keywords or len(call.args) < 2:
        return None
    receiver, member = call.args[0], call.args[1]
    if not (isinstance(receiver, ast.Name) and receiver.id in _SELF_RECEIVERS):
        return None
    if isinstance(member, ast.Constant) and isinstance(member.value, str):
        return member.value
    return None


def _attribute_self_member(call_expression: str) -> str | None:
    """Member name from a bare ``self.name`` / ``cls.name`` attribute, else ``None``.

    Attribute-rooted receivers (``self.client.name``) are not bare ``self``/``cls``
    and leave the gap — they are out of scope (FLAW-249, instance-attribute typing).
    """
    parsed = _parse_expression(call_expression)
    if parsed is None or not isinstance(parsed.body, ast.Attribute):
        return None
    attribute = parsed.body
    if isinstance(attribute.value, ast.Name) and attribute.value.id in _SELF_RECEIVERS:
        return attribute.attr
    return None


def _resolve_via_mro(
    owner_class_fqn: str,
    member: str,
    *,
    classes_by_fqn: Mapping[str, ClassRecord],
    methods_by_class: Mapping[tuple[str, str], str],
) -> str | None:
    """Return the FQN *member* resolves to under the owner class's MRO, else ``None``.

    Resolves only when the owner class's MRO is fully known (``mro_complete``); an
    external or unresolved base leaves FLAW-231's gap. Walks the C3 ``mro_chain`` in
    order and returns the first ancestor that defines *member* — the monomorphic
    target for an instance of exactly the owner class.
    """
    owner = classes_by_fqn.get(owner_class_fqn)
    if owner is None or not owner.mro_complete:
        return None
    for class_fqn in owner.mro_chain or (owner_class_fqn,):
        resolved = methods_by_class.get((class_fqn, member))
        if resolved is not None:
            return resolved
    return None
