"""Always-on, durable per-scan observability record.

Every ``flawed`` scan emits one :class:`ScanRecord` — a structured, timestamped
snapshot of timing (per-phase and per-L1-sub-phase), cache lifecycle (status +
the derived invalidation reason), artifact sizes, per-rule timing, and a memory
trajectory.  It is written twice:

- **Per-repo sidecar** (``scan_metrics.jsonl`` beside the cache) — single writer
  per repo directory, so no lock is needed.
- **Central run-log** (one append-only JSONL for all scans) — guarded by a short,
  *write-only* ``flock`` around the append, since records can exceed the 4 KiB
  atomic-append bound and concurrent cross-repo scans would otherwise interleave.

This module is a pure DATA contract plus its writers; the pipeline populates the
record.  It deliberately does **not** persist anything into the L1 index records,
so it never moves ``record_schema_fingerprint`` and never invalidates a cache.
"""

from __future__ import annotations

import fcntl
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from flawed._cli._profile_summaries import artifact_summary

if TYPE_CHECKING:
    from pathlib import Path

#: Schema version for the scan record (independent of the package + L1 schema).
SCAN_RECORD_SCHEMA_VERSION = "1"

#: Filename of the per-repo sidecar, written beside the cache artifacts.
SIDECAR_FILENAME = "scan_metrics.jsonl"

#: Default central run-log filename (under ``state_dir``).
CENTRAL_LOG_FILENAME = "runs.jsonl"


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with millisecond precision."""
    return datetime.now(UTC).isoformat(timespec="milliseconds")


@dataclass(frozen=True)
class PhaseTiming:
    """Timing + memory for one top-level pipeline phase (L1/L2/L3)."""

    name: str
    wall_ms: float
    served_from_cache: bool = False
    completed: bool = True
    cpu_ms: float | None = None
    rss_start_bytes: int | None = None
    rss_end_bytes: int | None = None
    rss_source: str = ""

    def to_jsonable(self) -> dict[str, object]:
        return {
            "name": self.name,
            "wall_ms": self.wall_ms,
            "served_from_cache": self.served_from_cache,
            "completed": self.completed,
            "cpu_ms": self.cpu_ms,
            "rss_start_bytes": self.rss_start_bytes,
            "rss_end_bytes": self.rss_end_bytes,
            "rss_source": self.rss_source,
        }


@dataclass(frozen=True)
class SubPhaseTiming:
    """Timing for one L1 sub-phase (parse / CFG / call-graph / value-flow / type-enrich)."""

    name: str
    wall_ms: float
    cpu_ms: float | None = None
    rss_end_bytes: int | None = None

    def to_jsonable(self) -> dict[str, object]:
        return {
            "name": self.name,
            "wall_ms": self.wall_ms,
            "cpu_ms": self.cpu_ms,
            "rss_end_bytes": self.rss_end_bytes,
        }


@dataclass(frozen=True)
class CacheInfo:
    """Cache lifecycle for one scan, including *why* the L1 index was rebuilt."""

    l1_cache_status: str | None = None
    """One of hit / miss / incremental / forced / corrupt_reextract (``None`` if unknown)."""
    invalidation_reason: str | None = None
    """When L1 was rebuilt: which key component changed (``None`` on a hit)."""
    l2_cache: str | None = None
    """Provider-engine cache outcome: ``hit`` / ``miss`` (``None`` if not consulted)."""
    results_cache: str | None = None
    """Per-detector results cache outcome: ``hit`` / ``miss`` / ``partial`` (``None`` if off)."""

    def to_jsonable(self) -> dict[str, object]:
        return {
            "l1_cache_status": self.l1_cache_status,
            "invalidation_reason": self.invalidation_reason,
            "l2_cache": self.l2_cache,
            "results_cache": self.results_cache,
        }


@dataclass(frozen=True)
class RuleTiming:
    """Wall time + yield for a single L3 rule."""

    rule_id: str
    wall_ms: float
    finding_count: int = 0

    def to_jsonable(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "wall_ms": self.wall_ms,
            "finding_count": self.finding_count,
        }


@dataclass(frozen=True)
class MemorySample:
    """One point on the memory trajectory: elapsed-since-scan-start vs current RSS."""

    elapsed_ms: float
    rss_bytes: int
    source: str

    def to_jsonable(self) -> dict[str, object]:
        return {
            "elapsed_ms": self.elapsed_ms,
            "rss_bytes": self.rss_bytes,
            "source": self.source,
        }


@dataclass(frozen=True)
class ScanRecord:
    """One durable observability record for a complete scan.

    Frozen + JSONL-serialized (one object per line), so the format is
    migration-friendly and survives across engine versions.
    """

    schema_version: str
    started_at: str
    ended_at: str
    repo: str
    flawed_version: str
    l1_schema_version: str
    exit_code: int | None = None
    incomplete: bool = False
    overall_timed_out: bool = False
    timed_out_layers: tuple[str, ...] = ()
    timed_out_rules: tuple[str, ...] = ()
    budget_capped_layers: tuple[str, ...] = ()
    phases: tuple[PhaseTiming, ...] = ()
    l1_sub_phases: tuple[SubPhaseTiming, ...] = ()
    cache: CacheInfo = field(default_factory=CacheInfo)
    artifacts: dict[str, object] = field(default_factory=dict)
    rule_timings: tuple[RuleTiming, ...] = ()
    memory_trajectory: tuple[MemorySample, ...] = ()

    def to_jsonable(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "repo": self.repo,
            "flawed_version": self.flawed_version,
            "l1_schema_version": self.l1_schema_version,
            "exit_code": self.exit_code,
            "incomplete": self.incomplete,
            "overall_timed_out": self.overall_timed_out,
            "timed_out_layers": list(self.timed_out_layers),
            "timed_out_rules": list(self.timed_out_rules),
            "budget_capped_layers": list(self.budget_capped_layers),
            "phases": [phase.to_jsonable() for phase in self.phases],
            "l1_sub_phases": [sub.to_jsonable() for sub in self.l1_sub_phases],
            "cache": self.cache.to_jsonable(),
            "artifacts": self.artifacts,
            "rule_timings": [rule.to_jsonable() for rule in self.rule_timings],
            "memory_trajectory": [sample.to_jsonable() for sample in self.memory_trajectory],
        }


def artifact_size_summary(artifact_dir: Path) -> dict[str, object]:
    """Return the on-disk artifact size summary for *artifact_dir*.

    Thin wrapper over :func:`flawed._cli._profile_summaries.artifact_summary` so
    callers have a single observability entry point (and the JSONL-vs-pickle
    byte breakdown lives in one place).
    """
    return artifact_summary(artifact_dir)


def default_central_log_path(state_dir: Path) -> Path:
    """Return the default central run-log path under *state_dir*."""
    return state_dir / CENTRAL_LOG_FILENAME


def _record_line(record: ScanRecord) -> str:
    return json.dumps(record.to_jsonable(), sort_keys=True) + "\n"


def write_sidecar(artifact_dir: Path, record: ScanRecord) -> None:
    """Append *record* to the per-repo sidecar (``scan_metrics.jsonl``).

    Single writer per repo directory, so no lock is taken.
    """
    artifact_dir.mkdir(parents=True, exist_ok=True)
    with (artifact_dir / SIDECAR_FILENAME).open("a", encoding="utf-8") as handle:
        handle.write(_record_line(record))


def write_central(log_path: Path, record: ScanRecord) -> None:
    """Append *record* to the central run-log under a narrow write-only ``flock``.

    The exclusive lock spans only the open+write+close, so concurrent cross-repo
    scans serialize their *appends* (preventing interleaved lines) without ever
    blocking the read/analysis paths.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    line = _record_line(record)
    with log_path.open("a", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            handle.write(line)
            handle.flush()
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
