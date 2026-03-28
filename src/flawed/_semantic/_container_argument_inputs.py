"""Infer request-container reads performed through helper parameters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from flawed._semantic._conversion_utils import call_expression, call_target_expression, location
from flawed._semantic._input_conversion import _literal_arg
from flawed.core import JsonPath, Key, Provenance
from flawed.inputs import (
    AccessPattern,
    Cardinality,
    Cookie,
    FileUpload,
    Form,
    Header,
    InputRead,
    InputSource,
    Json,
    Query,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flawed._index import CodeIndex
    from flawed._index._types import CallEdge, FunctionRecord, Parameter
    from flawed.function import Function


_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="container_argument_inputs",
    confidence=0.85,
    supporting_facts=(
        "request container passed to helper parameter",
        "helper parameter used with keyed container accessor",
    ),
)


@dataclass(frozen=True)
class _ContainerBinding:
    param_name: str
    source_type: str


def infer_container_argument_reads(
    idx: CodeIndex,
    *,
    l1_fn_by_fqn: Mapping[str, FunctionRecord],
    functions_by_fqn: Mapping[str, Function],
    existing_reads_by_function: Mapping[str, list[InputRead]],
) -> dict[str, list[InputRead]]:
    """Infer reads like ``helper(request.form)`` followed by ``data.get(...)``.

    Provider input descriptors intentionally model framework objects such as
    ``request.form.get("x")``.  Real apps often pass that request container into
    helpers, where the receiver becomes an ordinary parameter.  This pass keeps
    the framework-specific part at the call site and generically replays keyed
    parameter accessors inside the callee.
    """
    reads_by_function: dict[str, list[InputRead]] = {}
    existing_keys = _existing_read_keys(existing_reads_by_function)
    for edge in idx.call_graph.edges:
        if edge.callee_fqn is None:
            continue
        callee_record = l1_fn_by_fqn.get(edge.callee_fqn)
        callee_function = functions_by_fqn.get(edge.callee_fqn)
        if callee_record is None or callee_function is None:
            continue
        bindings = _container_bindings(edge, callee_record)
        if not bindings:
            continue
        for read in _reads_from_callee_bindings(
            idx.call_graph.edges,
            callee_function=callee_function,
            callee_fqn=edge.callee_fqn,
            bindings=bindings,
        ):
            key = _read_key(read)
            if key in existing_keys:
                continue
            existing_keys.add(key)
            reads_by_function.setdefault(read.function.fqn, []).append(read)
    return reads_by_function


def _existing_read_keys(
    reads_by_function: Mapping[str, list[InputRead]],
) -> set[tuple[str, str, int, int, str, type[InputSource], object | None, Cardinality]]:
    return {_read_key(read) for reads in reads_by_function.values() for read in reads}


def _read_key(
    read: InputRead,
) -> tuple[str, str, int, int, str, type[InputSource], object | None, Cardinality]:
    return (
        read.function.fqn,
        read.location.file,
        read.location.line,
        read.location.column or 0,
        read.expression,
        type(read.source),
        _source_identity(read.source),
        read.cardinality,
    )


def _source_identity(source: InputSource) -> object | None:
    for attr in ("key", "name", "field", "path"):
        if hasattr(source, attr):
            value: object = getattr(source, attr)
            return value
    return None


def _container_bindings(edge: CallEdge, callee: FunctionRecord) -> tuple[_ContainerBinding, ...]:
    bindings: list[_ContainerBinding] = []
    for arg in edge.arguments:
        source_type = _request_container_source_type(arg.expression)
        if source_type is None:
            continue
        param = _parameter_for_argument(arg.position, arg.keyword, callee.params)
        if param is None:
            continue
        bindings.append(
            _ContainerBinding(
                param_name=param.name,
                source_type=source_type,
            )
        )
    return tuple(bindings)


def _parameter_for_argument(
    position: int | None,
    keyword: str | None,
    params: tuple[Parameter, ...],
) -> Parameter | None:
    if keyword is not None:
        return next((param for param in params if param.name == keyword), None)
    if position is None or position >= len(params):
        return None
    return params[position]


def _request_container_source_type(expression: str) -> str | None:
    normalized = expression.strip()
    return {
        "request.args": "Query",
        "request.form": "Form",
        "request.json": "Json",
        "request.headers": "Header",
        "request.cookies": "Cookie",
        "request.files": "FileUpload",
        "request.values": "Form",
    }.get(normalized)


def _reads_from_callee_bindings(
    edges: tuple[CallEdge, ...],
    *,
    callee_function: Function,
    callee_fqn: str,
    bindings: tuple[_ContainerBinding, ...],
) -> tuple[InputRead, ...]:
    reads: list[InputRead] = []
    for edge in edges:
        if edge.caller_fqn != callee_fqn or edge.call_expression is None:
            continue
        for binding in bindings:
            read = _read_from_parameter_call(edge, binding, callee_function)
            if read is not None:
                reads.append(read)
    return tuple(reads)


def _read_from_parameter_call(
    edge: CallEdge,
    binding: _ContainerBinding,
    function: Function,
) -> InputRead | None:
    expression = edge.call_expression
    if expression is None:
        return None
    target = call_target_expression(expression) or expression
    prefix = f"{binding.param_name}."
    if not target.startswith(prefix):
        return None
    method_name = target[len(prefix) :].split("(", maxsplit=1)[0].split(".", maxsplit=1)[0]
    if method_name not in {"get", "getlist"}:
        return None
    key = _literal_arg(edge.arguments, position=0, keyword=None)
    source = _make_source(binding.source_type, key)
    if source is None:
        return None
    access_pattern = AccessPattern.GETLIST if method_name == "getlist" else AccessPattern.GET
    cardinality = Cardinality.MULTI if method_name == "getlist" else Cardinality.SINGLE
    return InputRead(
        source=source,
        access_pattern=access_pattern,
        cardinality=cardinality,
        function=function,
        location=location(edge.location),
        expression=call_expression(edge),
        provenance=_PROVENANCE,
    )


def _make_source(source_type: str, key: str | None) -> InputSource | None:
    typed_key = Key(key) if key is not None else None
    return {
        "Query": Query(key=typed_key),
        "Form": Form(key=typed_key),
        "Json": Json(path=JsonPath(f"$.{key}") if key is not None else None),
        "Header": Header(name=typed_key),
        "Cookie": Cookie(name=typed_key),
        "FileUpload": FileUpload(field=typed_key),
    }.get(source_type)
