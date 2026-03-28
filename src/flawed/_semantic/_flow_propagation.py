"""Generic conversion for provider-declared flow propagators."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from flawed._index._types import CallArgument, CallEdge, SourceSpan
from flawed._semantic._conversion_utils import conversion_gap as _conversion_gap
from flawed._semantic._expr_cache import parse_expression as _parse_expression
from flawed._semantic._provider_engine import ProviderMatch, ProviderPhase
from flawed._semantic.providers import FlowPropagatorPattern
from flawed.core import AnalysisGap, GapKind


@dataclass(frozen=True)
class FlowPropagationEdge:
    """A generic data-flow edge declared by a provider propagator."""

    provider_id: str
    observed_fqn: str
    canonical_fqn: str
    source_expression: str
    source_location: SourceSpan
    target_expression: str
    target_location: SourceSpan
    containing_function_fqn: str
    description: str = ""


@dataclass(frozen=True)
class FlowPropagationResult:
    """Converted propagator edges plus conversion gaps."""

    propagators: tuple[FlowPropagationEdge, ...]
    gaps: tuple[AnalysisGap, ...]


def convert_flow_propagator_matches(
    matches: tuple[ProviderMatch, ...],
) -> FlowPropagationResult:
    """Convert PROPAGATORS provider matches into generic flow edges."""
    propagators: list[FlowPropagationEdge] = []
    gaps: list[AnalysisGap] = []
    for match in matches:
        if match.phase is not ProviderPhase.PROPAGATORS:
            continue
        converted = _convert_match(match)
        if converted is None:
            continue
        if isinstance(converted, AnalysisGap):
            gaps.append(converted)
        elif isinstance(converted, FlowPropagationEdge):
            propagators.append(converted)
        else:
            propagators.extend(converted)
    return FlowPropagationResult(tuple(propagators), tuple(gaps))


def _convert_match(
    match: ProviderMatch,
) -> FlowPropagationEdge | tuple[FlowPropagationEdge, ...] | AnalysisGap | None:
    if not isinstance(match.descriptor, FlowPropagatorPattern):
        return _gap(match, "propagator match does not carry a FlowPropagatorPattern")
    if not isinstance(match.source_fact, CallEdge):
        return _gap(match, "propagator match does not carry a call edge")

    pattern = match.descriptor
    edge = match.source_fact
    source_args = _source_arguments(edge, pattern)
    if not source_args:
        target = _argument_target_label(pattern.input_arg, pattern.input_keyword)
        if not pattern.input_required:
            return None
        return _gap(match, f"propagator input arg {target} is missing")

    return _build_edges(match, pattern, edge, source_args)


def _build_edges(
    match: ProviderMatch,
    pattern: FlowPropagatorPattern,
    edge: CallEdge,
    source_args: tuple[CallArgument, ...],
) -> FlowPropagationEdge | tuple[FlowPropagationEdge, ...] | AnalysisGap:
    target = _target(match, pattern, edge)
    if isinstance(target, AnalysisGap):
        return target
    target_expr, target_location = target
    edges = tuple(
        FlowPropagationEdge(
            provider_id=match.provider_id,
            observed_fqn=match.observed_fqn,
            canonical_fqn=match.canonical_fqn,
            source_expression=source_arg.expression,
            source_location=source_arg.location,
            target_expression=target_expr,
            target_location=target_location,
            containing_function_fqn=edge.caller_fqn,
            description=pattern.description,
        )
        for source_arg in source_args
    )
    if len(edges) == 1:
        return edges[0]
    return edges


def _target(
    match: ProviderMatch,
    pattern: FlowPropagatorPattern,
    edge: CallEdge,
) -> tuple[str, SourceSpan] | AnalysisGap:
    output = pattern.output
    if output == "return":
        return edge.call_expression or f"{edge.callee_fqn or '<unknown>'}()", edge.location
    if output == "receiver":
        receiver = _receiver_expression(edge.call_expression)
        if receiver is None:
            return _gap(match, "propagator receiver output requires a receiver call expression")
        return receiver, edge.location
    if output.startswith(("arg:", "kwarg:")):
        return _argument_target(match, edge, output)
    return _gap(match, f"unsupported propagator output {output!r}")


def _argument_target(
    match: ProviderMatch,
    edge: CallEdge,
    output: str,
) -> tuple[str, SourceSpan] | AnalysisGap:
    if output.startswith("kwarg:"):
        keyword = output.removeprefix("kwarg:")
        if not keyword:
            return _gap(match, f"unsupported propagator output {output!r}")
        target_arg = _argument(edge, position=None, keyword=keyword)
        if target_arg is None:
            return _gap(match, f"propagator output kwarg {keyword!r} is missing")
        return target_arg.expression, target_arg.location

    try:
        position = int(output.removeprefix("arg:"))
    except ValueError:
        return _gap(match, f"unsupported propagator output {output!r}")
    target_arg = _argument(edge, position=position, keyword=None)
    if target_arg is None:
        return _gap(match, f"propagator output arg {position} is missing")
    return target_arg.expression, target_arg.location


def _argument(
    edge: CallEdge,
    *,
    position: int | None,
    keyword: str | None,
) -> CallArgument | None:
    for arg in edge.arguments:
        if keyword is not None and arg.keyword == keyword:
            return arg
        if keyword is None and position is not None and arg.position == position:
            return arg
    if keyword is not None and position is not None:
        for arg in edge.arguments:
            if arg.position == position:
                return arg
    return None


def _source_arguments(edge: CallEdge, pattern: FlowPropagatorPattern) -> tuple[CallArgument, ...]:
    if pattern.input_variadic:
        return tuple(
            arg
            for arg in edge.arguments
            if arg.position not in pattern.excluded_input_args
            and (arg.keyword is None or arg.keyword not in pattern.excluded_input_keywords)
        )

    arg = _argument(edge, position=pattern.input_arg, keyword=pattern.input_keyword)
    if arg is None:
        return ()
    return (arg,)


def _argument_target_label(position: int | None, keyword: str | None) -> str:
    if keyword is not None and position is not None:
        return f"{keyword!r}/position {position}"
    if keyword is not None:
        return repr(keyword)
    if position is not None:
        return str(position)
    return "<unspecified>"


def _receiver_expression(call_expression: str | None) -> str | None:
    if call_expression is None:
        return None
    tree = _parse_expression(call_expression)
    if tree is None:
        return None
    node = tree.body
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return ast.unparse(node.func.value)
    return None


def _gap(match: ProviderMatch, message: str) -> AnalysisGap:
    return _conversion_gap(
        match,
        message,
        origin_phase="flow_propagator_conversion",
        kind=GapKind.VALUE_FLOW_INCOMPLETE,
    )
