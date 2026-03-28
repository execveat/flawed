"""Convert provider dependency-injection matches into semantic observations."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import TYPE_CHECKING

from flawed._index._types import CallEdge, FlowKind
from flawed._semantic._check_conversion import ConcreteCondition
from flawed._semantic._conversion_utils import (
    location,
)
from flawed._semantic._conversion_utils import (
    simple_name as _simple_name,
)
from flawed._semantic._dispatch_conversion import DispatchEdge
from flawed._semantic._expr_cache import parse_expression as _parse_expression
from flawed._semantic.providers import DependencyPattern, SecurityCheckPattern
from flawed.conditions import CodeScope, ConditionKind, DenialKind, GuardClassification
from flawed.core import AnalysisGap, GapKind, Key, Provenance
from flawed.inputs import AccessPattern, Cardinality, DependencyInput, InputRead

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from flawed._index import CodeIndex
    from flawed._index._types import CallArgument, FunctionRecord, SourceSpan
    from flawed._semantic._provider_engine import ProviderMatch
    from flawed.function import Function


_L2_DEPENDENCY_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="provider_dependencies",
    confidence=0.9,
    supporting_facts=("provider dependency descriptor matched L1 structural fact",),
)
_DEFAULT_GUARD_CATEGORY = "AUTHORIZATION"


@dataclass(frozen=True)
class DependencyConversionResult:
    """Converted dependency observations and non-fatal conversion gaps."""

    reads_by_function: dict[str, list[InputRead]]
    conditions_by_function: dict[str, list[ConcreteCondition]]
    dispatch_edges: tuple[DispatchEdge, ...]
    gaps: tuple[AnalysisGap, ...] = ()


@dataclass(frozen=True)
class _DependencyObservation:
    match: ProviderMatch
    descriptor: DependencyPattern
    caller: Function
    expression: str
    parameter_name: str | None
    target_function: Function | None
    provider_fqn: str | None
    security_category: str | None


def convert_dependency_matches(
    dependency_matches: Iterable[ProviderMatch],
    all_matches: Iterable[ProviderMatch],
    *,
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> DependencyConversionResult:
    """Convert dependency matches into lifecycle edges, guards, and inputs."""
    matches = tuple(dependency_matches)
    security_sources = _security_source_categories(tuple(all_matches), idx)
    observations: list[_DependencyObservation] = []
    gaps: list[AnalysisGap] = []

    for match in matches:
        result = _observe_dependency(match, idx, functions_by_fqn, security_sources)
        gaps.extend(result.gaps)
        if result.observation is not None:
            observations.append(result.observation)

    reads_by_function: dict[str, list[InputRead]] = {}
    conditions_by_function: dict[str, list[ConcreteCondition]] = {}
    dispatch_edges: list[DispatchEdge] = []
    observations_by_caller = _observations_by_caller(observations)

    for observation in observations:
        gaps.extend(observation.match.predicate_gaps)
        read = _input_read(observation)
        if read is not None:
            reads_by_function.setdefault(observation.caller.fqn, []).append(read)

        if observation.target_function is not None:
            dispatch_edges.append(_dispatch_edge(observation))

        for category in _guard_categories_for_observation(
            observation,
            observations_by_caller,
            seen=frozenset(),
        ):
            conditions_by_function.setdefault(observation.caller.fqn, []).append(
                _guard_condition(observation, category)
            )

    return DependencyConversionResult(
        reads_by_function=reads_by_function,
        conditions_by_function=conditions_by_function,
        dispatch_edges=tuple(dispatch_edges),
        gaps=tuple(gaps),
    )


@dataclass(frozen=True)
class _ObservationResult:
    observation: _DependencyObservation | None = None
    gaps: tuple[AnalysisGap, ...] = ()


def _observe_dependency(
    match: ProviderMatch,
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
    security_sources: Mapping[str, str],
) -> _ObservationResult:
    descriptor = match.descriptor
    if not isinstance(descriptor, DependencyPattern):
        return _ObservationResult()

    fact = match.source_fact
    if not isinstance(fact, CallEdge):
        return _ObservationResult(gaps=(_source_fact_gap(match),))

    caller = functions_by_fqn.get(fact.caller_fqn)
    if caller is None:
        return _ObservationResult(gaps=(_caller_gap(match, fact.caller_fqn),))

    argument = _callable_argument(fact, descriptor.callable_arg)
    if argument is None:
        return _ObservationResult(gaps=(_callable_argument_gap(match, fact.caller_fqn),))

    expression = argument.expression
    resolved_fqn = _resolve_expression(expression, fact.location.file, idx)
    target_function = functions_by_fqn.get(resolved_fqn) if resolved_fqn is not None else None
    security_category = security_sources.get(resolved_fqn) if resolved_fqn is not None else None
    if descriptor.scope == "guard" and security_category is None and resolved_fqn is not None:
        security_category = _DEFAULT_GUARD_CATEGORY

    if target_function is None and security_category is None:
        return _ObservationResult(gaps=(_target_gap(match, fact.caller_fqn, expression),))

    parameter_name, parameter_gaps = _injected_parameter_name(match, fact, idx)
    provider_fqn = target_function.fqn if target_function is not None else resolved_fqn
    return _ObservationResult(
        observation=_DependencyObservation(
            match=match,
            descriptor=descriptor,
            caller=caller,
            expression=expression,
            parameter_name=parameter_name,
            target_function=target_function,
            provider_fqn=provider_fqn,
            security_category=security_category,
        ),
        gaps=parameter_gaps,
    )


def _security_source_categories(
    matches: tuple[ProviderMatch, ...],
    idx: CodeIndex,
) -> dict[str, str]:
    categories: dict[str, str] = {}
    for match in matches:
        descriptor = match.descriptor
        fact = match.source_fact
        if not isinstance(descriptor, SecurityCheckPattern) or not isinstance(fact, CallEdge):
            continue
        for variable_fqn in _assigned_variable_fqns(match.location, idx):
            categories[variable_fqn] = descriptor.category
    return categories


def _assigned_variable_fqns(span: SourceSpan, idx: CodeIndex) -> tuple[str, ...]:
    from flawed._semantic._matching import _module_level_vf_for_file

    module_fqn = _module_fqn_for_file(span.file, idx)
    if module_fqn is None:
        return ()
    return tuple(
        f"{module_fqn}.{edge.target_expr}"
        for edge in _module_level_vf_for_file(idx, span.file)
        if edge.kind is FlowKind.ASSIGN
        and _same_span(edge.source_location, span)
        and _simple_name(edge.target_expr) is not None
    )


def _callable_argument(edge: CallEdge, position: int) -> CallArgument | None:
    for argument in edge.arguments:
        if argument.position == position:
            return argument
    return None


def _resolve_expression(expression: str, file: str, idx: CodeIndex) -> str | None:
    resolved = idx.symbols.resolve(expression, file)
    if resolved is not None:
        return resolved

    name = _simple_name(expression)
    if name is None:
        return None
    return _module_local_function_fqn(name, file, idx) or _module_level_fqn(name, file, idx)


def _injected_parameter_name(
    match: ProviderMatch,
    edge: CallEdge,
    idx: CodeIndex,
) -> tuple[str | None, tuple[AnalysisGap, ...]]:
    record = _function_record(edge.caller_fqn, idx)
    if record is None:
        return None, (_caller_gap(match, edge.caller_fqn),)

    for param in record.params:
        if param.default is None:
            continue
        default_call = _call_details(param.default)
        if default_call is None:
            continue
        edge_callee = _edge_call_callee(edge)
        if edge_callee is None or not _same_callee(default_call.callee, edge_callee):
            continue
        if default_call.arguments != tuple(argument.expression for argument in edge.arguments):
            continue
        return param.name, ()

    return None, (_parameter_gap(match, edge.caller_fqn),)


@dataclass(frozen=True)
class _CallDetails:
    callee: str
    arguments: tuple[str, ...]


def _call_details(expression: str) -> _CallDetails | None:
    tree = _parse_expression(expression)
    if tree is None:
        return None
    node = tree.body
    if not isinstance(node, ast.Call):
        return None
    return _CallDetails(
        callee=ast.unparse(node.func),
        arguments=tuple(ast.unparse(argument) for argument in node.args),
    )


def _edge_call_callee(edge: CallEdge) -> str | None:
    expression = edge.call_expression or edge.callee_fqn
    if expression is None:
        return None
    tree = _parse_expression(expression)
    if tree is None:
        return expression
    node = tree.body
    if isinstance(node, ast.Call):
        return ast.unparse(node.func)
    return expression


def _same_callee(left: str, right: str) -> bool:
    return left == right or left.rsplit(".", maxsplit=1)[-1] == right.rsplit(".", maxsplit=1)[-1]


def _input_read(observation: _DependencyObservation) -> InputRead | None:
    if observation.parameter_name is None:
        return None
    return InputRead(
        source=DependencyInput(
            parameter=Key(observation.parameter_name),
            provider_fqn=observation.provider_fqn,
        ),
        access_pattern=AccessPattern.UNKNOWN,
        cardinality=Cardinality.SINGLE,
        function=observation.caller,
        location=location(observation.match.location),
        expression=observation.parameter_name,
        provenance=_L2_DEPENDENCY_PROVENANCE,
    )


def _dispatch_edge(observation: _DependencyObservation) -> DispatchEdge:
    assert observation.target_function is not None
    return DispatchEdge(
        caller_fqn=observation.caller.fqn,
        target=observation.target_function,
        dispatch_type="dependency_injection",
        location=location(observation.match.location),
        provenance=_L2_DEPENDENCY_PROVENANCE,
    )


def _guard_condition(observation: _DependencyObservation, category: str) -> ConcreteCondition:
    branch = _empty_scope()
    return ConcreteCondition(
        expression=f"{observation.match.observed_fqn}({observation.expression})",
        location=location(observation.match.location),
        function=observation.caller,
        kind=ConditionKind.CALL_RESULT,
        provenance=_L2_DEPENDENCY_PROVENANCE,
        category=category,
        provider_id=observation.match.provider_id,
        _true_branch=branch,
        _false_branch=branch,
        _guard=GuardClassification(
            guarded_branch=branch,
            denied_branch=branch,
            denial_kind=DenialKind.UNKNOWN,
            confidence=0.8,
        ),
    )


def _observations_by_caller(
    observations: list[_DependencyObservation],
) -> dict[str, tuple[_DependencyObservation, ...]]:
    grouped: dict[str, list[_DependencyObservation]] = {}
    for observation in observations:
        grouped.setdefault(observation.caller.fqn, []).append(observation)
    return {caller: tuple(items) for caller, items in grouped.items()}


def _guard_categories_for_observation(
    observation: _DependencyObservation,
    observations_by_caller: Mapping[str, tuple[_DependencyObservation, ...]],
    *,
    seen: frozenset[str],
) -> tuple[str, ...]:
    categories: list[str] = []
    if observation.security_category is not None:
        categories.append(observation.security_category)

    target = observation.target_function
    if target is None or target.fqn in seen:
        return tuple(dict.fromkeys(categories))

    for child in observations_by_caller.get(target.fqn, ()):
        categories.extend(
            _guard_categories_for_observation(
                child,
                observations_by_caller,
                seen=seen | {target.fqn},
            )
        )
    return tuple(dict.fromkeys(categories))


def _function_record(fqn: str, idx: CodeIndex) -> FunctionRecord | None:
    for function in idx.functions:
        if function.fqn == fqn:
            return function
    return None


def _module_fqn_for_file(file: str, idx: CodeIndex) -> str | None:
    for function in idx.functions:
        if function.file == file and not function.is_nested:
            return function.fqn.rsplit(".", maxsplit=1)[0]
    for klass in idx.classes:
        if klass.file == file:
            return klass.fqn.rsplit(".", maxsplit=1)[0]
    return None


def _module_level_fqn(name: str, file: str, idx: CodeIndex) -> str | None:
    from flawed._semantic._matching import _module_level_vf_for_file

    module_fqn = _module_fqn_for_file(file, idx)
    if module_fqn is None:
        return None
    for edge in _module_level_vf_for_file(idx, file):
        if edge.kind is FlowKind.ASSIGN and _simple_name(edge.target_expr) == name:
            return f"{module_fqn}.{name}"
    return None


def _module_local_function_fqn(name: str, file: str, idx: CodeIndex) -> str | None:
    for function in idx.functions:
        if function.file == file and function.name == name and not function.is_nested:
            return function.fqn
    return None


def _same_span(left: SourceSpan, right: SourceSpan) -> bool:
    return (
        left.file == right.file
        and left.line == right.line
        and left.column == right.column
        and left.end_line == right.end_line
        and left.end_column == right.end_column
    )


def _empty_scope() -> CodeScope:
    from flawed._semantic._scope import ConcreteCodeScope

    return ConcreteCodeScope()


def _source_fact_gap(match: ProviderMatch) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INTERPRETER_ERROR,
        message="Dependency match does not carry a call edge",
        affected_file=match.location.file,
        source_error="dependency_conversion: invalid source fact",
        origin_phase="dependency_conversion",
        origin_provider=match.provider_id,
    )


def _caller_gap(match: ProviderMatch, caller_fqn: str) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=f"Dependency caller function not found: {caller_fqn}",
        affected_file=match.location.file,
        affected_function=caller_fqn,
        source_error="dependency_conversion: missing caller function",
        origin_phase="dependency_conversion",
        origin_provider=match.provider_id,
    )


def _callable_argument_gap(match: ProviderMatch, caller_fqn: str) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=f"Dependency callable argument not found for {match.observed_fqn}",
        affected_file=match.location.file,
        affected_function=caller_fqn,
        source_error="dependency_conversion: missing callable argument",
        origin_phase="dependency_conversion",
        origin_provider=match.provider_id,
    )


def _target_gap(match: ProviderMatch, caller_fqn: str, expression: str) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.SYMBOL_UNRESOLVED,
        message=f"Dependency callable could not be resolved: {expression}",
        affected_file=match.location.file,
        affected_function=caller_fqn,
        source_error="dependency_conversion: unresolved dependency callable",
        origin_phase="dependency_conversion",
        origin_provider=match.provider_id,
    )


def _parameter_gap(match: ProviderMatch, caller_fqn: str) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message=f"Dependency injection parameter not found for {match.observed_fqn}",
        affected_file=match.location.file,
        affected_function=caller_fqn,
        source_error="dependency_conversion: missing injected parameter",
        origin_phase="dependency_conversion",
        origin_provider=match.provider_id,
    )
