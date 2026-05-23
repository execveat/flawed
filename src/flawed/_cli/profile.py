"""Structured scan profiling for the development CLI.

The report is intentionally dependency-light: phase timing comes from the
standard-library clocks, RSS from ``resource.getrusage()``, and allocation
hotspots from opt-in ``tracemalloc`` snapshots.  Heavier tools such as memray
remain external deep-dive profilers for follow-up investigations.
"""

from __future__ import annotations

import json
import tracemalloc
from collections import Counter
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from flawed._cli._profile_metrics import (
    TRACEBACK_LIMIT,
    rss_high_water_bytes,
)
from flawed._cli._profile_phases import CompletedPhase, PhaseTimer, ProfilePhase
from flawed._cli._profile_summaries import (
    GapContext,
    artifact_summary,
    collect_repo_gaps,
    counter_dict,
    gap_summary,
    index_counts,
    provider_gap_contexts,
    provider_summary,
    type_enrichment_summary,
)

__all__ = ["ProfilePhase", "ScanProfiler"]


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

    from flawed._cli.rules import RuleFinding, RuleProfile
    from flawed._config.paths import RepoIdentity
    from flawed._config.schema import ResolvedConfig
    from flawed._index import CodeIndex
    from flawed._index._pipeline import IndexBuildPhase
    from flawed._semantic._provider_engine import ProviderEngineResult
    from flawed.repo import RepoView


class ScanProfiler:
    """Collect and write a machine-readable scan report."""

    def __init__(
        self,
        *,
        output_path: Path,
        identity: RepoIdentity,
        config: ResolvedConfig,
        options: Mapping[str, object],
        enable_tracemalloc: bool = False,
    ) -> None:
        self._output_path = output_path
        self._target = {
            "path": str(identity.path),
            "canonical": identity.canonical,
            "hash": identity.hash,
            "data_dir": str(config.data_dir),
            "state_dir": str(config.state_dir),
        }
        self._options = dict(options)
        self._started_at = datetime.now(UTC)
        self._phases: list[CompletedPhase] = []
        self._sections: dict[str, object] = {}
        self._error: str | None = None
        self._owns_tracemalloc = enable_tracemalloc and not tracemalloc.is_tracing()
        if self._owns_tracemalloc:
            tracemalloc.start(TRACEBACK_LIMIT)
        self._tracemalloc_enabled = tracemalloc.is_tracing()

    def phase(self, name: str) -> PhaseTimer:
        """Record timing/memory details for one named phase."""
        return PhaseTimer(self._append_phase, name)

    def record_skipped_phase(self, name: str, *, reason: str) -> None:
        """Add a phase entry for work intentionally skipped by CLI options."""
        rss = rss_high_water_bytes()
        self._append_phase(
            CompletedPhase(
                name=name,
                status="skipped",
                wall_ms=0.0,
                cpu_ms=0.0,
                rss_high_water_start_bytes=rss,
                rss_high_water_end_bytes=rss,
                details={"reason": reason},
            )
        )

    def record_index_build_phase(self, phase: IndexBuildPhase) -> None:
        """Add a Layer 1 build subphase measured inside the index pipeline."""
        self._append_phase(
            CompletedPhase(
                name=phase.name,
                status=phase.status,
                wall_ms=phase.wall_ms,
                cpu_ms=phase.cpu_ms,
                rss_high_water_start_bytes=phase.rss_high_water_start_bytes,
                rss_high_water_end_bytes=phase.rss_high_water_end_bytes,
                details=dict(phase.details),
            )
        )

    def record_l1_index(
        self,
        index: CodeIndex,
        *,
        artifact_dir: Path,
        content_hash: str,
        cache_status: str,
        phase: ProfilePhase | None = None,
    ) -> None:
        """Record Layer 1 artifact and structural-index counts."""
        artifacts = artifact_summary(artifact_dir)
        counts = index_counts(index)
        type_enrichment = type_enrichment_summary(index)
        payload = {
            "cache_status": cache_status,
            "content_hash": content_hash,
            "artifact_dir": str(artifact_dir),
            "counts": counts,
            "type_enrichment": type_enrichment,
            "artifacts": artifacts,
        }
        self._sections["l1"] = payload
        if phase is not None:
            phase.set("cache_status", cache_status)
            phase.set("counts", counts)
            phase.set("type_enrichment", type_enrichment)
            phase.set("artifact_bytes_total", artifacts["total_bytes"])

    def record_semantic_result(
        self,
        *,
        repo_view: RepoView,
        active_provider_ids: Sequence[str],
        provider_result: ProviderEngineResult | None,
    ) -> None:
        """Record Layer 2 route/provider/gap telemetry."""
        provider_payload: dict[str, object] = {}
        gap_contexts: tuple[GapContext, ...] = ()
        if provider_result is not None:
            provider_payload = provider_summary(provider_result)
            gap_contexts = provider_gap_contexts(provider_result)

        gaps = collect_repo_gaps(repo_view)
        provider_payload.update(
            {
                "active_providers": list(active_provider_ids),
                "route_count": len(repo_view.routes),
                "function_count": len(repo_view.functions),
                "class_count": len(repo_view.classes),
                "app_partitions": app_partition_summary(repo_view),
                "routes_with_gaps": sum(1 for route in repo_view.routes if route.gaps),
                "functions_with_gaps": sum(1 for function in repo_view.functions if function.gaps),
                "classes_with_gaps": sum(1 for klass in repo_view.classes if klass.gaps),
                "gaps": gap_summary(gaps, contexts=gap_contexts),
            }
        )
        self._sections["l2"] = provider_payload

    def record_l3_result(
        self,
        *,
        rule_files: int,
        detectors: int,
        findings: Sequence[RuleFinding],
        actual_finding_count: int | None = None,
        retained_finding_count: int | None = None,
        findings_truncated: bool = False,
        rule_profiles: Sequence[RuleProfile] = (),
        phase: ProfilePhase | None = None,
    ) -> None:
        """Record Layer 3 rule/finding telemetry with optional per-rule profiles."""
        actual_count = len(findings) if actual_finding_count is None else actual_finding_count
        retained_count = (
            len(findings) if retained_finding_count is None else retained_finding_count
        )
        findings_by_rule = Counter(item.rule_id for item in findings)
        finding_gaps = tuple(gap for item in findings for gap in item.finding.gaps)
        payload: dict[str, object] = {
            "rule_file_count": rule_files,
            "detector_count": detectors,
            "finding_count": actual_count,
            "retained_finding_count": retained_count,
            "findings_truncated": findings_truncated,
            "findings_by_rule": counter_dict(findings_by_rule),
            "finding_gaps": gap_summary(finding_gaps),
        }
        if rule_profiles:
            payload["rule_profiles"] = [
                {
                    "rule_id": rp.rule_id,
                    "wall_ms": round(rp.wall_ms, 2),
                    "finding_count": rp.finding_count,
                    "finding_gap_count": rp.finding_gap_count,
                    # FLAW-194 flow-query budget telemetry.
                    "flow_query_count": rp.flow_query_count,
                    "bfs_count": rp.bfs_count,
                }
                for rp in sorted(rule_profiles, key=lambda r: r.wall_ms, reverse=True)
            ]
        self._sections["l3"] = payload
        if phase is not None:
            phase.set("rule_file_count", rule_files)
            phase.set("detector_count", detectors)
            phase.set("finding_count", actual_count)
            phase.set("retained_finding_count", retained_count)
            phase.set("findings_truncated", findings_truncated)

    def record_error(self, message: str) -> None:
        """Record a pipeline error in the report."""
        self._error = message

    def write(self, *, exit_code: int | None) -> None:
        """Write the final JSON report."""
        payload = self.to_dict(exit_code=exit_code)
        self._output_path.parent.mkdir(parents=True, exist_ok=True)
        self._output_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if self._owns_tracemalloc and tracemalloc.is_tracing():
            tracemalloc.stop()
            self._owns_tracemalloc = False

    def to_dict(self, *, exit_code: int | None) -> dict[str, object]:
        """Return the report payload without writing it."""
        status = "failed" if self._error is not None else "completed"
        payload: dict[str, object] = {
            "schema_version": 1,
            "generated_at": datetime.now(UTC).isoformat(),
            "started_at": self._started_at.isoformat(),
            "status": status,
            "exit_code": exit_code,
            "target": self._target,
            "options": self._options,
            "phases": [phase.to_dict() for phase in self._phases],
            "phase_summary": self._phase_summary(),
            "profiling": {
                "rss_source": "resource.getrusage(RUSAGE_SELF).ru_maxrss",
                "rss_unit": "bytes",
                "tracemalloc_enabled": self._tracemalloc_enabled,
                "tracemalloc_traceback_limit": (
                    TRACEBACK_LIMIT if self._tracemalloc_enabled else None
                ),
            },
        }
        payload.update(self._sections)
        if self._error is not None:
            payload["error"] = self._error
        return payload

    def _append_phase(self, phase: CompletedPhase) -> None:
        self._phases.append(phase)

    def _phase_summary(self) -> dict[str, dict[str, object]]:
        summary: dict[str, dict[str, int | float]] = {}
        for phase in self._phases:
            row = summary.setdefault(
                phase.name,
                {
                    "count": 0,
                    "completed_count": 0,
                    "failed_count": 0,
                    "skipped_count": 0,
                    "wall_ms_total": 0.0,
                    "cpu_ms_total": 0.0,
                    "wall_ms_max": 0.0,
                    "rss_high_water_end_bytes_max": 0,
                    "rss_high_water_delta_bytes_max": 0,
                },
            )
            row["count"] = int(row["count"]) + 1
            status_key = f"{phase.status}_count"
            if status_key in row:
                row[status_key] = int(row[status_key]) + 1
            row["wall_ms_total"] = round(float(row["wall_ms_total"]) + phase.wall_ms, 3)
            row["cpu_ms_total"] = round(float(row["cpu_ms_total"]) + phase.cpu_ms, 3)
            row["wall_ms_max"] = max(float(row["wall_ms_max"]), phase.wall_ms)
            row["rss_high_water_end_bytes_max"] = max(
                int(row["rss_high_water_end_bytes_max"]),
                phase.rss_high_water_end_bytes,
            )
            row["rss_high_water_delta_bytes_max"] = max(
                int(row["rss_high_water_delta_bytes_max"]),
                phase.rss_high_water_end_bytes - phase.rss_high_water_start_bytes,
            )
        return {name: dict(row) for name, row in sorted(summary.items())}


def app_partition_summary(repo_view: RepoView) -> dict[str, object]:
    """Summarize top-level app/package partitions represented by routes.

    This is intentionally generic and additive: when a scan root contains
    multiple import packages, each route is attributed to the first package
    segment of its handler FQN. Single-app repositories naturally collapse to
    one partition.
    """
    route_counts: Counter[str] = Counter()
    routes: list[dict[str, object]] = []
    for route in repo_view.routes:
        partition = _route_partition(route)
        route_counts[partition] += 1
        handler_fqn = getattr(getattr(route, "handler", None), "fqn", "")
        methods = getattr(route, "methods", ())
        routes.append(
            {
                "endpoint": getattr(route, "endpoint", "(unknown)"),
                "handler": handler_fqn if isinstance(handler_fqn, str) else "",
                "partition": partition,
                "url_rule": getattr(route, "url_rule", ""),
                "methods": sorted(getattr(method, "value", str(method)) for method in methods),
            }
        )
    return {
        "partition_count": len(route_counts),
        "route_count_by_partition": counter_dict(route_counts),
        "routes": routes,
    }


def _route_partition(route: object) -> str:
    handler_fqn = getattr(getattr(route, "handler", None), "fqn", "")
    if isinstance(handler_fqn, str) and "." in handler_fqn:
        return handler_fqn.split(".", maxsplit=1)[0]
    location = getattr(route, "location", None)
    file = getattr(location, "file", "") if location is not None else ""
    if isinstance(file, str) and "/" in file:
        return file.split("/", maxsplit=1)[0]
    return "(root)"
