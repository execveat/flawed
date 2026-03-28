"""Infer dynamic dispatch from ``self.attr = value`` to property setters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from flawed._index._types import AccessKind
from flawed._semantic._conversion_utils import location
from flawed._semantic._dispatch_conversion import DispatchEdge
from flawed.core import Provenance

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from flawed._index import CodeIndex
    from flawed._index._types import AttributeAccess, ClassRecord, FunctionRecord
    from flawed.function import Function


_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="property_setter_dispatch",
    confidence=0.85,
    supporting_facts=(
        "method assigns to self attribute",
        "class hierarchy defines a matching property setter",
    ),
)


@dataclass(frozen=True)
class _Setter:
    property_name: str
    owner_class_fqn: str
    function_fqn: str


def infer_property_setter_dispatch_edges(
    idx: CodeIndex,
    *,
    functions_by_fqn: Mapping[str, Function],
) -> tuple[DispatchEdge, ...]:
    """Infer calls from instance attribute writes to matching property setters.

    Python invokes ``@property`` setters when code assigns ``self.attr = value``.
    The static call graph does not represent this dynamic dispatch, so route and
    constructor reachable scopes miss side effects inside the setter body.  This
    pass stays conservative: only direct ``self.<name> = ...`` writes in methods
    are linked, and only when the local class MRO contains an explicit
    ``@<name>.setter`` method.
    """
    setters = _property_setters(idx.functions)
    if not setters:
        return ()

    classes_by_fqn = {cls.fqn: cls for cls in idx.classes}
    functions_records_by_fqn = _function_records_by_fqn(idx.functions)
    edges: list[DispatchEdge] = []
    seen: set[tuple[str, str, str, int, int | None]] = set()

    for access in idx.attributes:
        if not _is_self_attribute_write(access):
            continue
        caller_fqn = access.containing_function_fqn
        if caller_fqn is None:
            continue
        caller_record = functions_records_by_fqn.get(caller_fqn)
        if caller_record is None or caller_record.parent_class is None:
            continue
        setter = _resolve_setter(
            access.attr_name,
            owner_class_fqn=caller_record.parent_class,
            classes_by_fqn=classes_by_fqn,
            setters=setters,
        )
        if setter is None:
            continue
        target = functions_by_fqn.get(setter.function_fqn)
        if target is None:
            continue
        key = (
            caller_fqn,
            target.fqn,
            access.location.file,
            access.location.line,
            access.location.column,
        )
        if key in seen:
            continue
        seen.add(key)
        edges.append(
            DispatchEdge(
                caller_fqn=caller_fqn,
                target=target,
                dispatch_type="property_setter",
                location=location(access.location),
                provenance=_PROVENANCE,
            )
        )
    return tuple(edges)


def _property_setters(functions: Iterable[FunctionRecord]) -> dict[tuple[str, str], _Setter]:
    setters: dict[tuple[str, str], _Setter] = {}
    for fn in functions:
        if fn.parent_class is None:
            continue
        property_name = _setter_property_name(fn)
        if property_name is None:
            continue
        setters[(fn.parent_class, property_name)] = _Setter(
            property_name=property_name,
            owner_class_fqn=fn.parent_class,
            function_fqn=fn.fqn,
        )
    return setters


def _setter_property_name(fn: FunctionRecord) -> str | None:
    for decorator_name in fn.decorator_names:
        if decorator_name.endswith(".setter"):
            return decorator_name.removesuffix(".setter").split(".")[-1]
    for decorator_fqn in fn.decorator_fqns:
        if decorator_fqn and decorator_fqn.endswith(".setter"):
            return decorator_fqn.removesuffix(".setter").split(".")[-1]
    return None


def _is_self_attribute_write(access: AttributeAccess) -> bool:
    return (
        access.is_write
        and access.access_kind is AccessKind.ATTR
        and access.target_expr == "self"
        and access.containing_function_fqn is not None
    )


def _function_records_by_fqn(functions: Iterable[FunctionRecord]) -> dict[str, FunctionRecord]:
    # Duplicate FQNs can occur for property getter/setter pairs.  Keep the first
    # record that tells us the containing class; this lookup is used only for
    # caller ownership, not setter identification.
    records: dict[str, FunctionRecord] = {}
    for fn in functions:
        records.setdefault(fn.fqn, fn)
    return records


def _resolve_setter(
    property_name: str,
    *,
    owner_class_fqn: str,
    classes_by_fqn: Mapping[str, ClassRecord],
    setters: Mapping[tuple[str, str], _Setter],
) -> _Setter | None:
    owner_class = classes_by_fqn.get(owner_class_fqn)
    if owner_class is None:
        return None
    for class_fqn in owner_class.mro_chain or (owner_class_fqn,):
        setter = setters.get((class_fqn, property_name))
        if setter is not None:
            return setter
    return None
