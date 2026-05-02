"""Per-phase measurement harness for memory stress testing.

Calls pipeline functions individually to bracket each phase with
RSS, wall-time, and object-count measurements.  Does NOT use
tracemalloc by default — P10.5 showed tracer overhead makes L2/L3
scans impractical (4-10 min on r03/r04 with tracemalloc enabled).

Usage from other modules::

    from tools.stress.measure import measure_scan, write_results

    result = measure_scan(Path("local/stress/app_25_files"))
    write_results([result], Path("local/stress/results"))
"""

from __future__ import annotations

import csv
import gc
import json
import os
import resource
import sys
import time
import tracemalloc
from dataclasses import dataclass, field
from pathlib import Path  # noqa: TC003 — runtime use
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from flawed._index._structural import ParsedFile
    from flawed._index._types import ExtractionError, FunctionRecord

# ---------------------------------------------------------------------------
# Memory / timing helpers
# ---------------------------------------------------------------------------


def _rss_high_water_bytes() -> int:
    """Process RSS high-water mark in bytes (macOS returns bytes, Linux KB)."""
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return raw if sys.platform == "darwin" else raw * 1024


def _rss_current_bytes() -> int:
    """Current live RSS in bytes.  Falls back to high-water if unavailable."""
    try:
        raw = int(os.popen(f"ps -o rss= -p {os.getpid()}").read().strip())
        return raw * 1024  # ps reports in KB
    except Exception:
        return _rss_high_water_bytes()


def _elapsed_ms(start_ns: int, end_ns: int) -> float:
    return round((end_ns - start_ns) / 1_000_000, 3)


def _object_count() -> int:
    gc.collect()
    return len(gc.get_objects())


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PhaseMetrics:
    """Timing and memory for one pipeline subphase."""

    name: str
    wall_ms: float
    cpu_ms: float
    rss_before_bytes: int
    rss_after_bytes: int
    rss_high_water_bytes: int
    object_count_before: int
    object_count_after: int
    details: dict[str, object] = field(default_factory=dict)

    @property
    def rss_delta_bytes(self) -> int:
        return self.rss_after_bytes - self.rss_before_bytes

    @property
    def object_delta(self) -> int:
        return self.object_count_after - self.object_count_before


@dataclass(frozen=True)
class StressResult:
    """Full measurement result for one synthetic app scan."""

    config_label: str
    phases: tuple[PhaseMetrics, ...]
    total_wall_ms: float
    peak_rss_bytes: int
    file_count: int
    function_count: int
    route_count: int
    gap_count: int
    error_count: int
    tracemalloc_enabled: bool = False


# ---------------------------------------------------------------------------
# Phase context manager
# ---------------------------------------------------------------------------


class _PhaseMeter:
    """Context manager that brackets one phase with measurements."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._wall_start = 0
        self._cpu_start = 0
        self._rss_before = 0
        self._obj_before = 0
        self.details: dict[str, object] = {}

    def __enter__(self) -> _PhaseMeter:
        self._rss_before = _rss_current_bytes()
        self._obj_before = _object_count()
        self._wall_start = time.perf_counter_ns()
        self._cpu_start = time.process_time_ns()
        return self

    def __exit__(self, *_: object) -> None:
        self._wall_end = time.perf_counter_ns()
        self._cpu_end = time.process_time_ns()
        self._rss_after = _rss_current_bytes()
        self._obj_after = _object_count()

    def result(self) -> PhaseMetrics:
        return PhaseMetrics(
            name=self.name,
            wall_ms=_elapsed_ms(self._wall_start, self._wall_end),
            cpu_ms=_elapsed_ms(self._cpu_start, self._cpu_end),
            rss_before_bytes=self._rss_before,
            rss_after_bytes=self._rss_after,
            rss_high_water_bytes=_rss_high_water_bytes(),
            object_count_before=self._obj_before,
            object_count_after=self._obj_after,
            details=dict(self.details),
        )


# ---------------------------------------------------------------------------
# Scope introspection helpers
# ---------------------------------------------------------------------------


def _scope_obs_count(scope: object) -> dict[str, int]:
    """Count observations in a scope by type."""
    return {
        "reads": len(scope.reads()),  # type: ignore[attr-defined]
        "effects": len(scope.effects()),  # type: ignore[attr-defined]
        "calls": len(scope.calls()),  # type: ignore[attr-defined]
        "sinks": len(scope.sinks()),  # type: ignore[attr-defined]
        "conditions": len(scope.conditions()),  # type: ignore[attr-defined]
        "gaps": len(scope.gaps),  # type: ignore[attr-defined]
    }


def _scope_total(counts: dict[str, int]) -> int:
    return sum(counts.values())


def _collect_scope_metrics(view: object) -> dict[str, object]:
    """Collect per-scope tuple histograms and duplication metrics."""
    obs_types = ("reads", "effects", "calls", "sinks", "conditions", "gaps")

    # -- Route scopes --
    route_reachable_sizes: list[dict[str, int]] = []
    route_fullstack_sizes: list[dict[str, int]] = []
    route_labels: list[str] = []

    for route in view.routes:  # type: ignore[attr-defined]
        label = getattr(route, "url_rule", None) or getattr(route, "endpoint", "?")
        route_labels.append(str(label))
        route_reachable_sizes.append(_scope_obs_count(route.reachable))
        route_fullstack_sizes.append(_scope_obs_count(route.full_stack))

    # -- Function scopes --
    fn_reachable_sizes: list[dict[str, int]] = []
    fn_labels: list[str] = []

    for fn in view.functions:  # type: ignore[attr-defined]
        label = getattr(fn, "fqn", "?")
        fn_labels.append(str(label))
        fn_reachable_sizes.append(_scope_obs_count(fn.reachable))

    # -- Histograms: observation type → sorted list of sizes --
    route_histogram: dict[str, list[int]] = {t: [] for t in obs_types}
    for counts in route_reachable_sizes:
        for t in obs_types:
            route_histogram[t].append(counts[t])
    for v in route_histogram.values():
        v.sort()

    fn_histogram: dict[str, list[int]] = {t: [] for t in obs_types}
    for counts in fn_reachable_sizes:
        for t in obs_types:
            fn_histogram[t].append(counts[t])
    for v in fn_histogram.values():
        v.sort()

    # -- Totals --
    route_reachable_total = sum(_scope_total(c) for c in route_reachable_sizes)
    route_fullstack_total = sum(_scope_total(c) for c in route_fullstack_sizes)
    fn_reachable_total = sum(_scope_total(c) for c in fn_reachable_sizes)
    total_observation_refs = route_reachable_total + route_fullstack_total + fn_reachable_total

    # -- Top-N by total observation count --
    route_totals = [
        (route_labels[i], _scope_total(route_reachable_sizes[i])) for i in range(len(route_labels))
    ]
    route_totals.sort(key=lambda x: x[1], reverse=True)

    fn_totals = [
        (fn_labels[i], _scope_total(fn_reachable_sizes[i])) for i in range(len(fn_labels))
    ]
    fn_totals.sort(key=lambda x: x[1], reverse=True)

    route_sizes = [t[1] for t in route_totals]
    fn_sizes = [t[1] for t in fn_totals]

    return {
        "scope_histogram_routes": route_histogram,
        "scope_histogram_functions": fn_histogram,
        "top_routes_by_reachable_size": route_totals[:5],
        "top_functions_by_reachable_size": fn_totals[:5],
        "total_observation_refs": total_observation_refs,
        "route_reachable_total_refs": route_reachable_total,
        "route_fullstack_total_refs": route_fullstack_total,
        "fn_reachable_total_refs": fn_reachable_total,
        "avg_route_reachable_size": round(sum(route_sizes) / max(len(route_sizes), 1), 1),
        "max_route_reachable_size": max(route_sizes, default=0),
        "avg_fn_reachable_size": round(sum(fn_sizes) / max(len(fn_sizes), 1), 1),
        "max_fn_reachable_size": max(fn_sizes, default=0),
    }


# ---------------------------------------------------------------------------
# Main measurement function
# ---------------------------------------------------------------------------


def measure_scan(  # noqa: PLR0915
    app_root: Path,
    *,
    label: str = "",
    enable_tracemalloc: bool = False,
    skip_l3: bool = False,
) -> StressResult:
    """Run the full pipeline with per-phase measurement.

    Reproduces ``build_index()`` step-by-step so each L1 subphase
    can be independently bracketed.  Then runs L2 and L3.

    Parameters
    ----------
    app_root:
        Path to a synthetic Flask app directory.
    label:
        Human-readable config label for result identification.
    enable_tracemalloc:
        If True, start tracemalloc before the scan.  Significantly
        increases overhead — use only for line-attribution deep dives.
    skip_l3:
        If True, skip L3 rule execution (saves significant time when
        profiling L1/L2 memory behavior).
    """
    # Deferred imports — keep module loadable without full flawed env
    from flawed._cli.rules import discover_rule_files, load_configured_detectors, run_detectors
    from flawed._config.schema import ResolvedConfig
    from flawed._index import CodeIndex
    from flawed._index._callgraph import build_hierarchy_edges, merge_call_graph
    from flawed._index._pipeline import (
        _build_file_cfgs,
        _extract_all_call_edges,
        _write_normalized_artifacts,
    )
    from flawed._index._structural import discover_python_files, extract_structural
    from flawed._index._types import ExtractionProvenance
    from flawed._index._valueflow import extract_value_flow
    from flawed._semantic import WebApp
    from flawed._semantic._provider_engine import ProviderEngine

    app_root = app_root.expanduser().resolve()
    if not app_root.is_dir():
        msg = f"App root is not a directory: {app_root}"
        raise ValueError(msg)

    owns_tracemalloc = False
    if enable_tracemalloc and not tracemalloc.is_tracing():
        tracemalloc.start(10)
        owns_tracemalloc = True

    phases: list[PhaseMetrics] = []
    all_errors: list[ExtractionError] = []
    total_start = time.perf_counter_ns()

    # -- Phase 1: LibCST structural extraction -----------------------------

    with _PhaseMeter("libcst_extraction") as meter:
        python_files = discover_python_files(app_root)
        cfgs: dict[str, Any] = {}
        cfg_errors: list[ExtractionError] = []

        def capture_file_cfgs(
            parsed_file: ParsedFile,
            functions: tuple[FunctionRecord, ...],
        ) -> tuple[ExtractionError, ...]:
            errors = _build_file_cfgs(parsed_file, functions, cfgs)
            cfg_errors.extend(errors)
            return errors

        structural = extract_structural(
            app_root,
            python_files,
            per_file_callback=capture_file_cfgs,
        )
        all_errors.extend(structural.errors)
        meter.details["python_files"] = len(python_files)
        meter.details["functions"] = len(structural.functions)
        meter.details["classes"] = len(structural.classes)
        meter.details["decorators"] = len(structural.decorators)
        meter.details["imports"] = len(structural.imports)
        meter.details["call_edges"] = len(structural.call_edges)
    phases.append(meter.result())

    # -- Phase 3: CFG construction -----------------------------------------

    with _PhaseMeter("cfg_construction") as meter:
        meter.details["built_during_structural"] = True
        meter.details["cfgs_built"] = len(cfgs)
        meter.details["cfg_errors"] = len(cfg_errors)
    phases.append(meter.result())

    # -- Phase 4: Call graph merge -----------------------------------------

    with _PhaseMeter("callgraph_merge") as meter:
        hierarchy_edges = build_hierarchy_edges(
            structural.classes,
            structural.functions,
            structural.call_edges,
        )
        call_graph, merge_errors = merge_call_graph(
            ast_edges=structural.call_edges,
            hierarchy_edges=hierarchy_edges,
        )
        all_errors.extend(merge_errors)
        merged_call_edges = _extract_all_call_edges(call_graph)
        meter.details["hierarchy_edges"] = len(hierarchy_edges)
        meter.details["merged_edges"] = len(merged_call_edges)
        meter.details["merge_errors"] = len(merge_errors)
    phases.append(meter.result())

    # -- Phase 5: Value flow extraction ------------------------------------

    with _PhaseMeter("value_flow") as meter:
        attribute_writes = tuple(attr for attr in structural.attributes if attr.is_write)
        value_flow_edges, vf_errors = extract_value_flow(
            assignments=structural.assignments,
            aliases=structural.aliases,
            functions=structural.functions,
            call_edges=structural.call_edges,
            returns=structural.returns,
            comprehension_bindings=structural.comprehension_bindings,
            attribute_writes=attribute_writes,
            yields=structural.yields,
        )
        all_errors.extend(vf_errors)
        meter.details["value_flow_edges"] = len(value_flow_edges)
        meter.details["vf_errors"] = len(vf_errors)
    phases.append(meter.result())

    # -- Phase 6: Artifact write + CodeIndex assembly ----------------------

    with _PhaseMeter("artifact_write") as meter:
        artifact_root = app_root / ".flawed-artifacts"
        artifact_root.mkdir(parents=True, exist_ok=True)
        _write_normalized_artifacts(
            artifact_root,
            functions=structural.functions,
            classes=structural.classes,
            decorators=structural.decorators,
            imports=structural.imports,
            attributes=structural.attributes,
            call_edges=merged_call_edges,
            cfgs=cfgs,
            fqn_to_file={fn.fqn: fn.file for fn in structural.functions},
            value_flow_edges=value_flow_edges,
            symbol_refs=structural.symbol_refs,
            errors=tuple(all_errors),
        )
        index = CodeIndex(
            repo_root=app_root,
            functions=structural.functions,
            classes=structural.classes,
            decorators=structural.decorators,
            imports=structural.imports,
            attributes=structural.attributes,
            call_edges=merged_call_edges,
            cfgs=cfgs,
            value_flow_edges=value_flow_edges,
            symbol_refs=structural.symbol_refs,
            errors=tuple(all_errors),
            provenance=ExtractionProvenance(
                producer="stress_harness",
                producer_version="0.1.0",
                artifact=str(app_root),
            ),
        )
        meter.details["total_errors"] = len(all_errors)
    phases.append(meter.result())

    # -- Phase 7: Provider matching ----------------------------------------

    with _PhaseMeter("provider_matching") as meter:
        engine = ProviderEngine()
        engine_result = engine.run(index)
        meter.details["active_providers"] = list(engine_result.active_provider_ids)
        meter.details["match_count"] = len(engine_result.matches)
        meter.details["provider_gaps"] = len(engine_result.gaps)
    phases.append(meter.result())

    # -- Phase 8: Semantic conversion + scope attachment --------------------

    with _PhaseMeter("semantic_conversion") as meter:
        webapp = WebApp.from_index(index, provider_engine_result=engine_result)
        view = webapp.repo_view()
        meter.details["route_count"] = len(view.routes)
        meter.details["function_count"] = len(view.functions)
        meter.details["class_count"] = len(view.classes)
        meter.details["gap_count"] = len(view.gaps)
        meter.details.update(_collect_scope_metrics(view))
    phases.append(meter.result())

    # -- Phase 9: L3 rules -------------------------------------------------

    if skip_l3:
        phases.append(
            PhaseMetrics(
                name="l3_rules",
                wall_ms=0.0,
                cpu_ms=0.0,
                rss_before_bytes=_rss_current_bytes(),
                rss_after_bytes=_rss_current_bytes(),
                rss_high_water_bytes=_rss_high_water_bytes(),
                object_count_before=0,
                object_count_after=0,
                details={"skipped": True},
            )
        )
    else:
        with _PhaseMeter("l3_rules") as meter:
            config = ResolvedConfig()
            rule_files = discover_rule_files(config)
            detectors = load_configured_detectors(config, rule_files)
            findings = run_detectors(view, detectors)
            meter.details["rule_files"] = len(rule_files)
            meter.details["detectors"] = len(detectors)
            meter.details["findings"] = len(findings)
        phases.append(meter.result())

    total_end = time.perf_counter_ns()

    if owns_tracemalloc and tracemalloc.is_tracing():
        tracemalloc.stop()

    return StressResult(
        config_label=label or app_root.name,
        phases=tuple(phases),
        total_wall_ms=_elapsed_ms(total_start, total_end),
        peak_rss_bytes=_rss_high_water_bytes(),
        file_count=len(python_files),
        function_count=len(structural.functions),
        route_count=len(view.routes),
        gap_count=len(view.gaps),
        error_count=len(all_errors),
        tracemalloc_enabled=enable_tracemalloc,
    )


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

_CSV_COLUMNS = [
    "config_label",
    "phase",
    "wall_ms",
    "cpu_ms",
    "rss_before_bytes",
    "rss_after_bytes",
    "rss_delta_bytes",
    "rss_high_water_bytes",
    "object_count_before",
    "object_count_after",
    "object_delta",
]


def write_results(
    results: list[StressResult],
    output_dir: Path,
) -> tuple[Path, Path]:
    """Write JSON and CSV results.  Returns ``(json_path, csv_path)``."""
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "stress_results.json"
    csv_path = output_dir / "stress_results.csv"

    # JSON — full structured data
    payload = [_result_to_dict(r) for r in results]
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    # CSV — one row per phase per config
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_CSV_COLUMNS)
        writer.writeheader()
        for result in results:
            for phase in result.phases:
                writer.writerow(
                    {
                        "config_label": result.config_label,
                        "phase": phase.name,
                        "wall_ms": phase.wall_ms,
                        "cpu_ms": phase.cpu_ms,
                        "rss_before_bytes": phase.rss_before_bytes,
                        "rss_after_bytes": phase.rss_after_bytes,
                        "rss_delta_bytes": phase.rss_delta_bytes,
                        "rss_high_water_bytes": phase.rss_high_water_bytes,
                        "object_count_before": phase.object_count_before,
                        "object_count_after": phase.object_count_after,
                        "object_delta": phase.object_delta,
                    }
                )

    return json_path, csv_path


def _result_to_dict(result: StressResult) -> dict[str, object]:
    """Serialize a StressResult for JSON output."""
    return {
        "config_label": result.config_label,
        "total_wall_ms": result.total_wall_ms,
        "peak_rss_bytes": result.peak_rss_bytes,
        "file_count": result.file_count,
        "function_count": result.function_count,
        "route_count": result.route_count,
        "gap_count": result.gap_count,
        "error_count": result.error_count,
        "tracemalloc_enabled": result.tracemalloc_enabled,
        "phases": [
            {
                "name": p.name,
                "wall_ms": p.wall_ms,
                "cpu_ms": p.cpu_ms,
                "rss_before_bytes": p.rss_before_bytes,
                "rss_after_bytes": p.rss_after_bytes,
                "rss_delta_bytes": p.rss_delta_bytes,
                "rss_high_water_bytes": p.rss_high_water_bytes,
                "object_count_before": p.object_count_before,
                "object_count_after": p.object_count_after,
                "object_delta": p.object_delta,
                "details": p.details,
            }
            for p in result.phases
        ],
    }
