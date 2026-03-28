"""Infer credential-presence reads from ``key in container`` membership tests (FLAW-336).

A ``"x" in session`` / ``"x" in g`` membership test is a presence check on a
provider-recognised identity container, but it produces no ``AttributeAccess`` or
``CallEdge`` fact for the fact-driven container matcher
(:func:`flawed._semantic._matching._match_container_descriptor`) to key on -- the
container is a bare ``Name`` inside an ``ast.Compare``. This pass recovers the read
from the already-parsed ``MEMBERSHIP`` branch conditions so presence-not-validity
rules see the session/g credential instead of silently missing it.

Framework knowledge stays in providers: the recognised containers arrive as
:class:`~flawed._semantic._provider_engine.MembershipContainerSpec` values on the
provider-engine result (derived from ``InputContainerPattern`` descriptors whose
``access`` includes ``"membership"``); nothing here names a framework.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from flawed._semantic._input_conversion import _make_source
from flawed._semantic._provider_engine import canonicalize_fqn
from flawed.conditions import ConditionKind
from flawed.core import Provenance
from flawed.inputs import AccessPattern, Cardinality, InputRead

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flawed._index import CodeIndex
    from flawed._semantic._provider_engine import MembershipContainerSpec
    from flawed.conditions import Condition
    from flawed.flow import ValueHandle
    from flawed.inputs import InputSource

_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="membership_inputs",
    confidence=0.9,
    supporting_facts=("membership test (`key in container`) on a provider identity container",),
)


def infer_membership_reads(
    idx: CodeIndex,
    *,
    conditions_by_function: Mapping[str, list[Condition]],
    membership_specs: tuple[MembershipContainerSpec, ...],
    aliases: Mapping[str, str],
    existing_reads_by_function: Mapping[str, list[InputRead]],
) -> dict[str, list[InputRead]]:
    """Emit a read for each ``key in container`` presence test on a recognised container.

    Returns reads keyed by function FQN, deduplicated against the reads already
    converted from facts (a membership test anchors at the ``Compare`` location, so
    it should never collide -- the dedup is belt-and-braces).
    """
    if not membership_specs:
        return {}
    alias_map = dict(aliases)
    source_type_by_receiver = {
        receiver: spec.source_type for spec in membership_specs for receiver in spec.receiver_fqns
    }
    existing = _existing_read_keys(existing_reads_by_function)
    reads_by_function: dict[str, list[InputRead]] = {}
    for conditions in conditions_by_function.values():
        for condition in conditions:
            if condition.kind is not ConditionKind.MEMBERSHIP:
                continue
            read = _membership_read(condition, idx, source_type_by_receiver, alias_map)
            if read is None:
                continue
            key = _read_key(read)
            if key in existing:
                continue
            existing.add(key)
            reads_by_function.setdefault(read.function.fqn, []).append(read)
    return reads_by_function


def _membership_read(
    condition: Condition,
    idx: CodeIndex,
    source_type_by_receiver: Mapping[str, str],
    aliases: dict[str, str],
) -> InputRead | None:
    right = condition.right
    function = condition.function
    if right is None or function is None:
        return None
    receiver_expr = right.expression.strip()
    resolved = idx.symbols.resolve(receiver_expr, function.location.file) or receiver_expr
    source_type = source_type_by_receiver.get(canonicalize_fqn(resolved, aliases))
    if source_type is None:
        return None
    source = _make_source(source_type, _literal_key(condition.left))
    if source is None:
        return None
    return InputRead(
        source=source,
        access_pattern=AccessPattern.MEMBERSHIP,
        cardinality=Cardinality.SINGLE,
        function=function,
        location=condition.location,
        expression=condition.expression,
        provenance=_PROVENANCE,
    )


def _literal_key(left: ValueHandle | None) -> str | None:
    """The membership key when it is a string literal (``"account" in session``).

    A non-literal key (``var in session``) yields ``None`` -- still a real presence
    test, emitted as an unkeyed identity read so the rule layer can see it (FN-first).
    """
    if left is None:
        return None
    try:
        value = ast.literal_eval(left.expression)
    except (ValueError, SyntaxError, TypeError):
        return None
    return value if isinstance(value, str) else None


def _existing_read_keys(
    reads_by_function: Mapping[str, list[InputRead]],
) -> set[tuple[object, ...]]:
    return {_read_key(read) for reads in reads_by_function.values() for read in reads}


def _read_key(read: InputRead) -> tuple[object, ...]:
    return (
        read.function.fqn,
        read.location.file,
        read.location.line,
        read.location.column or 0,
        read.access_pattern,
        type(read.source),
        _source_identity(read.source),
    )


def _source_identity(source: InputSource) -> object | None:
    for attr in ("key", "name", "field", "path"):
        if hasattr(source, attr):
            value: object = getattr(source, attr)
            return value
    return None
