"""L1 → L3 domain object conversion.

Converts Layer 1 structural facts (frozen records from the Code Index)
into Layer 3 domain objects (the public Rule API).  This module is the
single point where L1 types cross the boundary into L3 types.

L2 owns this conversion — Rule API modules never import L1 types.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed.calls import Argument
from flawed.class_ import InheritedMethod
from flawed.core import AnalysisGap, GapKind, Location, Provenance
from flawed.function import Decorator, FunctionKind, OverloadSignature
from flawed.function import Parameter as L3Parameter

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from flawed._index._types import (
        CallEdge,
        ClassRecord,
        DecoratorFact,
        ExtractionError,
        FunctionRecord,
        SourceSpan,
    )
    from flawed._index._types import Parameter as L1Parameter
    from flawed.function import Function

from flawed._semantic._enriched import EnrichedCallSite, EnrichedClass, EnrichedFunction

# Map L1 FunctionKind enum values to L3 FunctionKind enum values.
_FUNCTION_KIND_MAP: dict[str, FunctionKind] = {
    "top_level": FunctionKind.TOP_LEVEL,
    "method": FunctionKind.METHOD,
    "nested": FunctionKind.NESTED,
    "lambda": FunctionKind.LAMBDA,
}

_L2_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="structural_passthrough",
    confidence=1.0,
    supporting_facts=("converted from L1 CodeIndex",),
)

# Map L1 ErrorKind enum values to L3 GapKind enum values.
_ERROR_TO_GAP_KIND: dict[str, GapKind] = {
    "parse": GapKind.PARSE_FAILURE,
    "cfg": GapKind.CFG_UNAVAILABLE,
    "resolution": GapKind.SYMBOL_UNRESOLVED,
    "astroid": GapKind.INFERENCE_FAILURE,
    "basedpyright": GapKind.INFERENCE_FAILURE,
    "mypy": GapKind.INFERENCE_FAILURE,
    "value_flow": GapKind.VALUE_FLOW_INCOMPLETE,
}


def _convert_params(params: tuple[L1Parameter, ...]) -> tuple[L3Parameter, ...]:
    """Convert L1 parameter records to L3 ``Parameter`` value objects."""
    return tuple(
        L3Parameter(
            name=p.name,
            annotation=p.annotation,
            default=p.default,
            kind=p.kind.value,
        )
        for p in params
    )


def _convert_location(span: SourceSpan) -> Location:
    """Convert an L1 ``SourceSpan`` to an L3 ``Location``."""
    return Location(
        file=span.file,
        line=span.line,
        column=span.column,
        end_line=span.end_line,
        end_column=span.end_column,
    )


def _is_overload_stub(rec: FunctionRecord) -> bool:
    """True if ``rec`` is a ``typing.overload`` stub declaration.

    Matches both the syntactic short name (``@overload``) and a resolved
    ``typing.overload`` FQN, mirroring decorator matching in
    ``_index/_collections.py``.
    """
    if any(name == "overload" or name.endswith(".overload") for name in rec.decorator_names):
        return True
    return any(
        fqn is not None and (fqn == "typing.overload" or fqn.endswith(".overload"))
        for fqn in rec.decorator_fqns
    )


def convert_function(
    rec: FunctionRecord,
    *,
    overloads: tuple[OverloadSignature, ...] = (),
) -> EnrichedFunction:
    """Convert an L1 ``FunctionRecord`` to an L3 ``Function``.

    Returns an ``EnrichedFunction`` (subclass of ``Function``) with
    navigation properties initialized to empty defaults.  The caller
    must enrich them via ``EnrichedFunction.from_base`` or by calling
    ``object.__setattr__`` to attach lookup context.

    ``overloads`` carries the ``@overload`` stub signatures when ``rec`` is
    the surviving implementation of an overloaded function (see
    :func:`convert_functions_grouped`).
    """
    from flawed._semantic._collections import (
        ConcreteDecoratorCollection,
        ConcreteFunctionCollection,
    )

    kind = _FUNCTION_KIND_MAP.get(rec.kind.value, FunctionKind.TOP_LEVEL)
    base_fn = EnrichedFunction(
        fqn=rec.fqn,
        name=rec.name,
        params=_convert_params(rec.params),
        kind=kind,
        parent_class=rec.parent_class,
        parent_function=rec.parent_function,
        location=_convert_location(rec.location),
        provenance=_L2_PROVENANCE,
        overloads=overloads,
    )
    # Initialize with empty navigation — WebApp.from_index enriches later.
    object.__setattr__(base_fn, "_decorators", ConcreteDecoratorCollection(()))
    object.__setattr__(base_fn, "_gaps", ())
    object.__setattr__(base_fn, "_calls", ConcreteFunctionCollection(()))
    object.__setattr__(base_fn, "_called_by", ConcreteFunctionCollection(()))
    return base_fn


def convert_functions_grouped(
    records: Iterable[FunctionRecord],
) -> dict[str, EnrichedFunction]:
    """Project L1 function records to L3 keyed by FQN, preserving overloads.

    Layer 1 emits one ``FunctionRecord`` per ``def`` -- including each
    ``@overload`` stub.  A naive ``{rec.fqn: convert_function(rec)}`` keyed
    by FQN collapses an overloaded function's records last-wins, keeping
    only the implementation signature and silently dropping the stub
    signatures (FLAW-265).  Selector parameters narrowed to
    ``Literal[True]`` / ``Literal[False]`` then become invisible to any
    overload-reasoning rule -- a false negative.

    This groups records by FQN and, for each group, selects the
    implementation as the surviving typed :class:`Function` -- the last
    record *without* an ``@overload`` decorator, falling back to the last
    record overall (matching the previous last-wins projection) -- then
    attaches the remaining ``@overload`` stub signatures as
    :attr:`Function.overloads`.  No signature is lost: the survivor's lives
    on :attr:`Function.params`, the rest on :attr:`Function.overloads`.
    """
    groups: dict[str, list[FunctionRecord]] = {}
    for rec in records:
        groups.setdefault(rec.fqn, []).append(rec)

    result: dict[str, EnrichedFunction] = {}
    for fqn, recs in groups.items():
        if len(recs) == 1:
            result[fqn] = convert_function(recs[0])
            continue
        non_overloads = [r for r in recs if not _is_overload_stub(r)]
        survivor = non_overloads[-1] if non_overloads else recs[-1]
        stub_signatures = tuple(
            OverloadSignature(
                params=_convert_params(r.params),
                location=_convert_location(r.location),
            )
            for r in recs
            if r is not survivor and _is_overload_stub(r)
        )
        result[fqn] = convert_function(survivor, overloads=stub_signatures)
    return result


def convert_class(rec: ClassRecord) -> EnrichedClass:
    """Convert an L1 ``ClassRecord`` to an L3 ``Class``.

    Returns an ``EnrichedClass`` (subclass of ``Class``) with
    navigation properties initialized to empty defaults.
    """
    from flawed._semantic._collections import (
        ConcreteDecoratorCollection,
        ConcreteFunctionCollection,
    )

    inherited = tuple(
        InheritedMethod(
            name=m.name,
            defining_class=m.defining_class_fqn,
        )
        for m in rec.inherited_methods
    )
    base_cls = EnrichedClass(
        fqn=rec.fqn,
        name=rec.name,
        bases=rec.bases,
        mro=rec.mro_chain,
        method_names=rec.method_names,
        inherited_methods=inherited,
        location=Location(
            file=rec.location.file,
            line=rec.location.line,
            column=rec.location.column,
            end_line=rec.location.end_line,
            end_column=rec.location.end_column,
        ),
        provenance=_L2_PROVENANCE,
    )
    # Initialize with empty navigation — WebApp.from_index enriches later.
    object.__setattr__(base_cls, "_decorators", ConcreteDecoratorCollection(()))
    object.__setattr__(base_cls, "_methods", ConcreteFunctionCollection(()))
    object.__setattr__(base_cls, "_is_abstract", rec.is_abstract)
    object.__setattr__(base_cls, "_gaps", ())
    return base_cls


def convert_decorator(fact: DecoratorFact) -> Decorator:
    """Convert an L1 ``DecoratorFact`` to an L3 ``Decorator``."""
    return Decorator(
        name=fact.name,
        fqn=fact.fqn,
        arguments=fact.args,
        location=Location(
            file=fact.location.file,
            line=fact.location.line,
            column=fact.location.column,
            end_line=fact.location.end_line,
            end_column=fact.location.end_column,
        ),
    )


def convert_extraction_error(err: ExtractionError) -> AnalysisGap:
    """Convert an L1 ``ExtractionError`` to an L3 ``AnalysisGap``."""
    gap_kind = _ERROR_TO_GAP_KIND.get(err.error_kind.value, GapKind.PARSE_FAILURE)
    return AnalysisGap(
        kind=gap_kind,
        message=err.message,
        affected_file=err.file,
        source_error=f"{err.pass_name}: {err.message}",
        origin_phase="l1_structural",
    )


def convert_call_edge(
    edge: CallEdge,
    caller_fn: Function,
    fn_by_fqn: Mapping[str, Function],
) -> EnrichedCallSite:
    """Convert an L1 ``CallEdge`` to an L3 ``CallSite``.

    Resolves the callee target via *fn_by_fqn* and converts arguments.
    """
    target = fn_by_fqn.get(edge.callee_fqn) if edge.callee_fqn else None
    arguments = tuple(
        Argument(
            index=arg.position if arg.position is not None else i,
            name=arg.keyword,
            expression=arg.expression,
            location=Location(
                file=arg.location.file,
                line=arg.location.line,
                column=arg.location.column,
                end_line=arg.location.end_line,
                end_column=arg.location.end_column,
            ),
        )
        for i, arg in enumerate(edge.arguments)
    )
    for argument in arguments:
        object.__setattr__(argument, "_function", caller_fn)
    return EnrichedCallSite(
        target=target,
        target_expression=edge.call_expression or "",
        arguments=arguments,
        location=Location(
            file=edge.location.file,
            line=edge.location.line,
            column=edge.location.column,
            end_line=edge.location.end_line,
            end_column=edge.location.end_column,
        ),
        function=caller_fn,
        target_fqn=edge.callee_fqn,
        receiver_expression=edge.receiver_expression,
        receiver_location=(
            Location(
                file=edge.receiver_location.file,
                line=edge.receiver_location.line,
                column=edge.receiver_location.column,
                end_line=edge.receiver_location.end_line,
                end_column=edge.receiver_location.end_column,
            )
            if edge.receiver_location is not None
            else None
        ),
    )
