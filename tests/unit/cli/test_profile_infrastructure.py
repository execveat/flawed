"""Tests for low-level scan profile infrastructure."""

from __future__ import annotations

import json
import resource
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple, cast

import pytest

import flawed._cli._profile_phases as profile_phases
import flawed._cli._profile_summaries as profile_summaries
import flawed._cli.profile as profile_module
from flawed._cli._profile_metrics import (
    TRACEBACK_LIMIT,
    elapsed_ms,
    rss_high_water_bytes,
    top_tracemalloc_diffs,
)
from flawed._cli._profile_phases import CompletedPhase, PhaseTimer
from flawed._cli.profile import ScanProfiler
from flawed._cli.rules import RuleFinding, RuleProfile
from flawed._config.paths import RepoIdentity
from flawed._config.schema import ResolvedConfig
from flawed._index._pipeline import IndexBuildPhase
from flawed.core import AnalysisGap, GapKind
from flawed.evidence import Finding

if TYPE_CHECKING:
    import tracemalloc

    from flawed._index import CodeIndex
    from flawed._semantic._provider_engine import ProviderEngineResult
    from flawed.repo import RepoView


class _Usage(NamedTuple):
    ru_maxrss: int


class _Frame(NamedTuple):
    filename: str
    lineno: int


@dataclass(frozen=True)
class _TraceStat:
    size_diff: int
    count_diff: int
    traceback: tuple[_Frame, ...]


class _Snapshot:
    def __init__(self, stats: tuple[_TraceStat, ...] = ()) -> None:
        self._stats = stats

    def compare_to(self, _before: _Snapshot, key_type: str) -> tuple[_TraceStat, ...]:
        assert key_type == "lineno"
        return self._stats


class _TracingDisabled:
    def is_tracing(self) -> bool:
        return False

    def take_snapshot(self) -> object:
        raise AssertionError("disabled tracemalloc should not snapshot")


class _TracingEnabled:
    def __init__(self) -> None:
        self._snapshots = [_Snapshot(), _Snapshot()]

    def is_tracing(self) -> bool:
        return True

    def take_snapshot(self) -> _Snapshot:
        return self._snapshots.pop(0)

    def get_traced_memory(self) -> tuple[int, int]:
        return (128, 512)


class _FakeTraceMallocController:
    def __init__(self, *, tracing: bool = False) -> None:
        self.tracing = tracing
        self.started_with: list[int] = []
        self.stop_calls = 0

    def is_tracing(self) -> bool:
        return self.tracing

    def start(self, limit: int) -> None:
        self.started_with.append(limit)
        self.tracing = True

    def stop(self) -> None:
        self.stop_calls += 1
        self.tracing = False


@dataclass(frozen=True)
class _FunctionRecord:
    fqn: str


@dataclass(frozen=True)
class _ExtractionError:
    is_fatal: bool


@dataclass(frozen=True)
class _Graph:
    edges: tuple[object, ...]


class _TypeEnrichment:
    facts: tuple[object, ...] = ()
    errors: tuple[object, ...] = ()


class _Index:
    functions = (_FunctionRecord("app.handler"), _FunctionRecord("app.helper"))
    classes = (object(),)
    decorators = (object(), object())
    imports = (object(),)
    attributes = (object(), object(), object())
    call_graph = _Graph((object(), object()))
    value_flow = _Graph((object(),))
    symbols = (object(), object(), object(), object())
    errors = (_ExtractionError(False), _ExtractionError(True))
    type_enrichment = _TypeEnrichment()

    def cfg(self, fqn: str) -> object | None:
        return object() if fqn == "app.handler" else None


@dataclass(frozen=True)
class _Phase:
    value: str


@dataclass(frozen=True)
class _ProviderMatch:
    provider_id: str
    phase: _Phase
    predicate_gaps: tuple[AnalysisGap, ...] = ()


@dataclass(frozen=True)
class _ProviderResult:
    active_provider_ids: tuple[str, ...]
    matches: tuple[_ProviderMatch, ...]
    router_group_info: tuple[object, ...]
    gaps: tuple[AnalysisGap, ...]


@dataclass(frozen=True)
class _GappedThing:
    gaps: tuple[AnalysisGap, ...]


class _RepoView:
    def __init__(self, gap: AnalysisGap) -> None:
        self.gaps = (gap,)
        self.routes = (_GappedThing((gap,)), _GappedThing(()))
        self.functions = (_GappedThing(()),)
        self.classes = (_GappedThing((gap,)),)


def test_rss_high_water_normalizes_platform_units(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getrusage(_resource_id: int) -> _Usage:
        return _Usage(7)

    monkeypatch.setattr(resource, "getrusage", fake_getrusage)
    monkeypatch.setattr(sys, "platform", "linux")
    assert rss_high_water_bytes() == 7 * 1024

    monkeypatch.setattr(sys, "platform", "darwin")
    assert rss_high_water_bytes() == 7


def test_elapsed_ms_rounds_nanoseconds_to_milliseconds() -> None:
    assert elapsed_ms(1_000_000, 2_234_567) == 1.235


def test_top_tracemalloc_diffs_keeps_positive_deltas_only() -> None:
    before = cast("tracemalloc.Snapshot", _Snapshot())
    after = cast(
        "tracemalloc.Snapshot",
        _Snapshot(
            (
                _TraceStat(0, 4, (_Frame("ignored.py", 1),)),
                _TraceStat(2048, 3, (_Frame("kept.py", 10),)),
                _TraceStat(-1, 1, (_Frame("freed.py", 20),)),
                _TraceStat(1024, 2, (_Frame("also_kept.py", 30),)),
            )
        ),
    )

    assert top_tracemalloc_diffs(before, after) == (
        {"file": "kept.py", "line": 10, "size_diff_bytes": 2048, "count_diff": 3},
        {"file": "also_kept.py", "line": 30, "size_diff_bytes": 1024, "count_diff": 2},
    )


def test_completed_phase_to_dict_includes_optional_tracemalloc_fields() -> None:
    phase = CompletedPhase(
        name="l1",
        status="completed",
        wall_ms=1.0,
        cpu_ms=0.5,
        rss_high_water_start_bytes=100,
        rss_high_water_end_bytes=175,
        details={"count": 2},
        tracemalloc_current_bytes=20,
        tracemalloc_peak_bytes=30,
        tracemalloc_top_allocations=({"file": "a.py", "line": 1},),
    )

    assert phase.to_dict() == {
        "name": "l1",
        "status": "completed",
        "wall_ms": 1.0,
        "cpu_ms": 0.5,
        "rss_high_water_start_bytes": 100,
        "rss_high_water_end_bytes": 175,
        "rss_high_water_delta_bytes": 75,
        "details": {"count": 2},
        "tracemalloc_current_bytes": 20,
        "tracemalloc_peak_bytes": 30,
        "tracemalloc_top_allocations": [{"file": "a.py", "line": 1}],
    }


def test_phase_timer_records_completed_phase_without_tracemalloc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phases: list[CompletedPhase] = []
    _patch_phase_clocks(monkeypatch)
    monkeypatch.setattr(profile_phases, "tracemalloc", _TracingDisabled())

    with PhaseTimer(phases.append, "l1") as phase:
        phase.set("items", 3)

    assert len(phases) == 1
    payload = phases[0].to_dict()
    assert payload["status"] == "completed"
    assert payload["wall_ms"] == 250.0
    assert payload["cpu_ms"] == 125.0
    assert payload["rss_high_water_start_bytes"] == 100
    assert payload["rss_high_water_end_bytes"] == 180
    assert payload["rss_high_water_delta_bytes"] == 80
    assert payload["details"] == {"items": 3}
    assert "tracemalloc_current_bytes" not in payload
    assert "tracemalloc_peak_bytes" not in payload
    assert "tracemalloc_top_allocations" not in payload


def test_phase_timer_records_failed_phase_and_propagates_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phases: list[CompletedPhase] = []
    _patch_phase_clocks(monkeypatch)
    monkeypatch.setattr(profile_phases, "tracemalloc", _TracingDisabled())

    with pytest.raises(RuntimeError, match="boom"):
        _raise_during_phase(phases)

    assert len(phases) == 1
    assert phases[0].status == "failed"
    assert phases[0].details == {"before_error": True}


def test_phase_timer_records_tracemalloc_snapshot_diffs(monkeypatch: pytest.MonkeyPatch) -> None:
    phases: list[CompletedPhase] = []
    top_allocations = ({"file": "hot.py", "line": 9, "size_diff_bytes": 40, "count_diff": 1},)
    _patch_phase_clocks(monkeypatch)
    monkeypatch.setattr(profile_phases, "tracemalloc", _TracingEnabled())
    monkeypatch.setattr(
        profile_phases,
        "top_tracemalloc_diffs",
        lambda _start, _end: top_allocations,
    )

    with PhaseTimer(phases.append, "l3"):
        pass

    assert phases[0].tracemalloc_current_bytes == 128
    assert phases[0].tracemalloc_peak_bytes == 512
    assert phases[0].tracemalloc_top_allocations == top_allocations


def test_scan_profiler_records_errors_skipped_phases_and_owned_tracemalloc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_tracemalloc = _FakeTraceMallocController()
    monkeypatch.setattr(profile_module, "tracemalloc", fake_tracemalloc)
    monkeypatch.setattr(profile_module, "rss_high_water_bytes", lambda: 4096)
    profiler = _profiler(tmp_path, enable_tracemalloc=True)

    profiler.record_skipped_phase("semantic", reason="disabled")
    profiler.record_error("scan failed")

    payload = profiler.to_dict(exit_code=2)
    assert fake_tracemalloc.started_with == [TRACEBACK_LIMIT]
    assert payload["status"] == "failed"
    assert payload["error"] == "scan failed"
    assert payload["profiling"] == {
        "rss_source": "resource.getrusage(RUSAGE_SELF).ru_maxrss",
        "rss_unit": "bytes",
        "tracemalloc_enabled": True,
        "tracemalloc_traceback_limit": TRACEBACK_LIMIT,
    }
    assert payload["phases"] == [
        {
            "name": "semantic",
            "status": "skipped",
            "wall_ms": 0.0,
            "cpu_ms": 0.0,
            "rss_high_water_start_bytes": 4096,
            "rss_high_water_end_bytes": 4096,
            "rss_high_water_delta_bytes": 0,
            "details": {"reason": "disabled"},
        }
    ]

    profiler.write(exit_code=2)

    assert fake_tracemalloc.stop_calls == 1
    written_payload = json.loads((tmp_path / "profile.json").read_text(encoding="utf-8"))
    assert written_payload["error"] == "scan failed"


def test_scan_profiler_reports_tracemalloc_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_tracemalloc = _FakeTraceMallocController()
    monkeypatch.setattr(profile_module, "tracemalloc", fake_tracemalloc)

    payload = _profiler(tmp_path, enable_tracemalloc=False).to_dict(exit_code=0)

    assert fake_tracemalloc.started_with == []
    assert payload["status"] == "completed"
    assert payload["profiling"] == {
        "rss_source": "resource.getrusage(RUSAGE_SELF).ru_maxrss",
        "rss_unit": "bytes",
        "tracemalloc_enabled": False,
        "tracemalloc_traceback_limit": None,
    }


def test_scan_profiler_records_index_build_subphase(tmp_path: Path) -> None:
    profiler = _profiler(tmp_path)

    profiler.record_index_build_phase(
        IndexBuildPhase(
            name="l1_value_flow",
            status="completed",
            wall_ms=12.5,
            cpu_ms=10.0,
            rss_high_water_start_bytes=1000,
            rss_high_water_end_bytes=1750,
            details={"edge_count": 3},
        )
    )

    payload = profiler.to_dict(exit_code=0)

    assert payload["phases"] == [
        {
            "name": "l1_value_flow",
            "status": "completed",
            "wall_ms": 12.5,
            "cpu_ms": 10.0,
            "rss_high_water_start_bytes": 1000,
            "rss_high_water_end_bytes": 1750,
            "rss_high_water_delta_bytes": 750,
            "details": {"edge_count": 3},
        }
    ]
    assert payload["phase_summary"] == {
        "l1_value_flow": {
            "count": 1,
            "completed_count": 1,
            "failed_count": 0,
            "skipped_count": 0,
            "wall_ms_total": 12.5,
            "cpu_ms_total": 10.0,
            "wall_ms_max": 12.5,
            "rss_high_water_end_bytes_max": 1750,
            "rss_high_water_delta_bytes_max": 750,
        }
    }


def test_scan_profiler_records_l1_l2_and_l3_sections(tmp_path: Path) -> None:
    profiler = _profiler(tmp_path)
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "summary.json").write_text("{}", encoding="utf-8")
    gap = AnalysisGap(
        kind=GapKind.INFERENCE_FAILURE,
        message="predicate incomplete",
        affected_file="app.py",
    )
    provider_gap = AnalysisGap(
        kind=GapKind.INTERPRETER_ERROR,
        message="provider failed",
        origin_phase="routes",
        origin_provider="provider-a",
    )

    with profiler.phase("index") as phase:
        profiler.record_l1_index(
            cast("CodeIndex", _Index()),
            artifact_dir=artifact_dir,
            content_hash="abc123",
            cache_status="miss",
            phase=phase,
        )
    profiler.record_semantic_result(
        repo_view=cast("RepoView", _RepoView(gap)),
        active_provider_ids=("provider-a",),
        provider_result=cast(
            "ProviderEngineResult",
            _ProviderResult(
                active_provider_ids=("provider-a",),
                matches=(
                    _ProviderMatch(
                        provider_id="provider-a",
                        phase=_Phase("routes"),
                        predicate_gaps=(gap,),
                    ),
                ),
                router_group_info=(object(),),
                gaps=(provider_gap,),
            ),
        ),
    )
    profiler.record_l3_result(
        rule_files=2,
        detectors=3,
        findings=(
            RuleFinding(
                rule_id="rule-a",
                rule_path=Path("rule_a.py"),
                finding=Finding(route_endpoint="app.handler", summary="example", gaps=(gap,)),
            ),
        ),
        actual_finding_count=10,
        retained_finding_count=1,
        findings_truncated=True,
        rule_profiles=(
            RuleProfile("slow", wall_ms=3.0, finding_count=1, finding_gap_count=1),
            RuleProfile("fast", wall_ms=1.0, finding_count=0, finding_gap_count=0),
        ),
    )

    payload: dict[str, Any] = profiler.to_dict(exit_code=0)

    assert payload["l1"] == {
        "cache_status": "miss",
        "content_hash": "abc123",
        "artifact_dir": str(artifact_dir),
        "counts": {
            "functions": 2,
            "classes": 1,
            "decorators": 2,
            "imports": 1,
            "attributes": 3,
            "call_edges": 2,
            "value_flow_edges": 1,
            "symbol_refs": 4,
            "errors": 2,
            "fatal_errors": 1,
            "cfgs": 1,
        },
        "type_enrichment": {
            "fact_count": 0,
            "concrete_fact_count": 0,
            "imprecise_fact_count": 0,
            "facts_by_tool": {},
            "concrete_facts_by_tool": {},
            "imprecise_facts_by_tool": {},
            "error_count": 0,
            "errors_by_kind": {},
            "errors_by_pass": {},
            "concrete_disagreement_count": 0,
        },
        "artifacts": {
            "root": str(artifact_dir),
            "exists": True,
            "total_bytes": 2,
            "file_count": 1,
            "by_extension": {".json": {"count": 1, "bytes": 2}},
            "by_category": {"(root)": {"count": 1, "bytes": 2}},
            "largest_files": [{"path": "summary.json", "bytes": 2}],
        },
    }
    assert payload["phases"][0]["details"] == {
        "artifact_bytes_total": 2,
        "cache_status": "miss",
        "counts": payload["l1"]["counts"],
        "type_enrichment": payload["l1"]["type_enrichment"],
    }
    assert payload["l2"]["provider_engine"] == {
        "active_providers": ["provider-a"],
        "match_count": 1,
        "matches_by_provider": {"provider-a": 1},
        "matches_by_phase": {"routes": 1},
        "matches_by_provider_phase": {"provider-a": {"routes": 1}},
        "router_group_count": 1,
        "engine_gap_count": 1,
        "engine_gaps": {
            "total": 1,
            "by_kind": {"interpreter_error": 1},
            "by_message": {"provider failed": 1},
            "by_source_error": {"(none)": 1},
            "by_file": {"(global)": 1},
            "by_function": {"(global)": 1},
            "known_context_count": 1,
            "unknown_context_count": 0,
            "by_phase": {"routes": 1},
            "by_provider": {"provider-a": 1},
        },
    }
    assert payload["l2"]["active_providers"] == ["provider-a"]
    assert payload["l2"]["route_count"] == 2
    assert payload["l2"]["app_partitions"] == {
        "partition_count": 1,
        "route_count_by_partition": {"(root)": 2},
        "routes": [
            {
                "endpoint": "(unknown)",
                "handler": "",
                "partition": "(root)",
                "url_rule": "",
                "methods": [],
            },
            {
                "endpoint": "(unknown)",
                "handler": "",
                "partition": "(root)",
                "url_rule": "",
                "methods": [],
            },
        ],
    }
    assert payload["l2"]["routes_with_gaps"] == 1
    assert payload["l2"]["classes_with_gaps"] == 1
    assert payload["l2"]["gaps"]["known_context_count"] == 1
    assert payload["l2"]["gaps"]["unknown_context_count"] == 2
    assert payload["l3"] == {
        "rule_file_count": 2,
        "detector_count": 3,
        "finding_count": 10,
        "retained_finding_count": 1,
        "findings_truncated": True,
        "findings_by_rule": {"rule-a": 1},
        "finding_gaps": {
            "total": 1,
            "by_kind": {"inference_failure": 1},
            "by_message": {"predicate incomplete": 1},
            "by_source_error": {"(none)": 1},
            "by_file": {"app.py": 1},
            "by_function": {"(global)": 1},
            "known_context_count": 0,
            "unknown_context_count": 1,
            "by_phase": {},
            "by_provider": {},
        },
        "rule_profiles": [
            {
                "rule_id": "slow",
                "wall_ms": 3.0,
                "finding_count": 1,
                "finding_gap_count": 1,
                "flow_query_count": 0,
                "bfs_count": 0,
            },
            {
                "rule_id": "fast",
                "wall_ms": 1.0,
                "finding_count": 0,
                "finding_gap_count": 0,
                "flow_query_count": 0,
                "bfs_count": 0,
            },
        ],
    }


def test_scan_profiler_records_l2_without_provider_result(tmp_path: Path) -> None:
    gap = AnalysisGap(kind=GapKind.INFERENCE_FAILURE, message="repo gap")
    profiler = _profiler(tmp_path)

    profiler.record_semantic_result(
        repo_view=cast("RepoView", _RepoView(gap)),
        active_provider_ids=("provider-a",),
        provider_result=None,
    )

    payload: dict[str, Any] = profiler.to_dict(exit_code=0)
    assert "provider_engine" not in payload["l2"]
    assert payload["l2"]["active_providers"] == ["provider-a"]


def test_counter_helpers_return_sorted_dicts() -> None:
    assert profile_summaries.counter_dict(Counter({"b": 2, "a": 1})) == {"a": 1, "b": 2}
    assert profile_summaries.nested_counter_dict(
        {"b": Counter({"d": 1, "c": 2}), "a": Counter({"z": 1})}
    ) == {"a": {"z": 1}, "b": {"c": 2, "d": 1}}


def _patch_phase_clocks(monkeypatch: pytest.MonkeyPatch) -> None:
    wall_times = iter((1_000_000_000, 1_250_000_000))
    cpu_times = iter((5_000_000_000, 5_125_000_000))
    rss_values = iter((100, 180))
    monkeypatch.setattr(time, "perf_counter_ns", lambda: next(wall_times))
    monkeypatch.setattr(time, "process_time_ns", lambda: next(cpu_times))
    monkeypatch.setattr(profile_phases, "rss_high_water_bytes", lambda: next(rss_values))


def _raise_during_phase(phases: list[CompletedPhase]) -> None:
    with PhaseTimer(phases.append, "l2") as phase:
        phase.set("before_error", True)
        raise RuntimeError("boom")


def _profiler(tmp_path: Path, *, enable_tracemalloc: bool = False) -> ScanProfiler:
    return ScanProfiler(
        output_path=tmp_path / "profile.json",
        identity=RepoIdentity(canonical="repo", path=tmp_path, hash="abc"),
        config=ResolvedConfig(data_dir=tmp_path / "data", state_dir=tmp_path / "state"),
        options={"profile": True},
        enable_tracemalloc=enable_tracemalloc,
    )
