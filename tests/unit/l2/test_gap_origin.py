"""Tests for AnalysisGap origin_phase/origin_provider metadata.

Every AnalysisGap production site in the semantic layer should set
origin_phase.  Provider-derived gaps should also set origin_provider.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest

from flawed._index._types import (
    CallEdge,
    EdgeSource,
    ErrorKind,
    ExtractionError,
    ExtractionProvenance,
    ResolutionStatus,
    SourceSpan,
)
from flawed._semantic._conversion import convert_extraction_error
from flawed._semantic._flow_propagation import convert_flow_propagator_matches
from flawed._semantic._provider_engine import ProviderMatch, ProviderPhase
from flawed._semantic._sink_conversion import convert_sink_match
from flawed._semantic.providers import FlowPropagatorPattern, TaintSinkPattern
from flawed.core import GapKind

if TYPE_CHECKING:
    from flawed._semantic._provider_engine import ProviderDescriptor

_PROV = ExtractionProvenance(producer="test", producer_version="0", artifact="")
_SPAN = SourceSpan(file="app.py", line=1, column=0, end_line=1, end_column=10)


def _edge(*, callee_fqn: str = "flask.url_for") -> CallEdge:
    return CallEdge(
        caller_fqn="app.handler",
        callee_fqn=callee_fqn,
        location=_SPAN,
        arguments=(),
        provenance=_PROV,
        call_expression=f"{callee_fqn}()",
        resolution=ResolutionStatus.RESOLVED,
        source=EdgeSource.AST,
        unresolved_reason=None,
    )


def _match(
    descriptor: object,
    *,
    phase: ProviderPhase = ProviderPhase.PROPAGATORS,
    provider_id: str = "flask",
    callee_fqn: str = "flask.url_for",
) -> ProviderMatch:
    return ProviderMatch(
        provider_id=provider_id,
        phase=phase,
        descriptor=cast("ProviderDescriptor", descriptor),
        source_fact=_edge(callee_fqn=callee_fqn),
        observed_fqn=callee_fqn,
        canonical_fqn=callee_fqn,
        location=_SPAN,
        predicate_gaps=(),
    )


def test_flow_propagation_gap_has_origin_phase_and_provider() -> None:
    pattern = FlowPropagatorPattern(
        fqn="flask.url_for",
        input_arg=0,
        input_keyword="endpoint",
        output="return",
        description="url_for flow",
    )
    match = _match(pattern)
    result = convert_flow_propagator_matches((match,))

    assert len(result.gaps) == 1
    gap = result.gaps[0]
    assert gap.origin_phase == "flow_propagator_conversion"
    assert gap.origin_provider == "flask"


def test_sink_conversion_gap_has_origin_phase_and_provider() -> None:
    pattern = TaintSinkPattern(
        fqn="flask.send_file",
        arg=0,
        sink_kind="PATH_TRAVERSAL",
    )
    match = _match(
        pattern,
        phase=ProviderPhase.SINKS,
        callee_fqn="flask.send_file",
    )
    result = convert_sink_match(match, {})

    assert len(result.sinks) == 0
    assert len(result.gaps) == 1
    gap = result.gaps[0]
    assert gap.origin_phase == "sink_conversion"
    assert gap.origin_provider == "flask"


def test_l1_structural_gap_has_origin_phase() -> None:
    err = ExtractionError(
        file="app.py",
        pass_name="cfg_builder",
        error_kind=ErrorKind.CFG,
        message="cannot build CFG",
        is_fatal=False,
        location=None,
    )
    gap = convert_extraction_error(err)

    assert gap.origin_phase == "l1_structural"
    assert gap.origin_provider is None
    assert gap.kind == GapKind.CFG_UNAVAILABLE


def test_basedpyright_error_converts_to_inference_failure_gap() -> None:
    """L1 BASEDPYRIGHT ExtractionError → INFERENCE_FAILURE AnalysisGap."""
    err = ExtractionError(
        file="app.py",
        pass_name="basedpyright_type_enrichment",
        error_kind=ErrorKind.BASEDPYRIGHT,
        message="timed out after 30s",
        is_fatal=False,
        location=SourceSpan(file="app.py", line=10, column=0, end_line=10, end_column=5),
    )

    gap = convert_extraction_error(err)

    assert gap.kind is GapKind.INFERENCE_FAILURE
    assert gap.affected_file == "app.py"
    assert gap.origin_phase == "l1_structural"
    assert "timed out" in gap.message
    assert gap.source_error is not None
    assert "basedpyright_type_enrichment" in gap.source_error


@pytest.mark.parametrize(
    ("error_kind", "expected_gap_kind"),
    [
        (ErrorKind.PARSE, GapKind.PARSE_FAILURE),
        (ErrorKind.CFG, GapKind.CFG_UNAVAILABLE),
        (ErrorKind.RESOLUTION, GapKind.SYMBOL_UNRESOLVED),
        (ErrorKind.ASTROID, GapKind.INFERENCE_FAILURE),
        (ErrorKind.BASEDPYRIGHT, GapKind.INFERENCE_FAILURE),
        (ErrorKind.MYPY, GapKind.INFERENCE_FAILURE),
        (ErrorKind.VALUE_FLOW, GapKind.VALUE_FLOW_INCOMPLETE),
    ],
)
def test_error_kind_to_gap_kind_mapping(error_kind: ErrorKind, expected_gap_kind: GapKind) -> None:
    """Every L1 ErrorKind maps to the correct L3 GapKind."""
    err = ExtractionError(
        file="test.py",
        pass_name="test_pass",
        error_kind=error_kind,
        message="test error",
        is_fatal=False,
        location=None,
    )

    gap = convert_extraction_error(err)

    assert gap.kind is expected_gap_kind
