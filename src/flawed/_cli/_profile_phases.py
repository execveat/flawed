"""Phase timing primitives for structured scan profiling."""

from __future__ import annotations

import time
import tracemalloc
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from flawed._cli._profile_metrics import (
    elapsed_ms,
    rss_high_water_bytes,
    top_tracemalloc_diffs,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType


@dataclass
class ProfilePhase:
    """Mutable phase handle populated by the pipeline while a phase runs."""

    name: str
    details: dict[str, object] = field(default_factory=dict)

    def set(self, key: str, value: object) -> None:
        """Attach structured detail to the running phase."""
        self.details[key] = value


@dataclass(frozen=True)
class CompletedPhase:
    """Immutable metrics collected after a phase exits."""

    name: str
    status: str
    wall_ms: float
    cpu_ms: float
    rss_high_water_start_bytes: int
    rss_high_water_end_bytes: int
    details: dict[str, object]
    tracemalloc_current_bytes: int | None = None
    tracemalloc_peak_bytes: int | None = None
    tracemalloc_top_allocations: tuple[dict[str, object], ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-ready phase payload."""
        rss_delta = self.rss_high_water_end_bytes - self.rss_high_water_start_bytes
        payload: dict[str, object] = {
            "name": self.name,
            "status": self.status,
            "wall_ms": self.wall_ms,
            "cpu_ms": self.cpu_ms,
            "rss_high_water_start_bytes": self.rss_high_water_start_bytes,
            "rss_high_water_end_bytes": self.rss_high_water_end_bytes,
            "rss_high_water_delta_bytes": rss_delta,
            "details": self.details,
        }
        if self.tracemalloc_current_bytes is not None:
            payload["tracemalloc_current_bytes"] = self.tracemalloc_current_bytes
        if self.tracemalloc_peak_bytes is not None:
            payload["tracemalloc_peak_bytes"] = self.tracemalloc_peak_bytes
        if self.tracemalloc_top_allocations:
            payload["tracemalloc_top_allocations"] = list(self.tracemalloc_top_allocations)
        return payload


class PhaseTimer:
    """Context manager that records one scan phase."""

    def __init__(self, append_phase: Callable[[CompletedPhase], None], name: str) -> None:
        self._append_phase = append_phase
        self._handle = ProfilePhase(name)
        self._wall_start_ns = 0
        self._cpu_start_ns = 0
        self._rss_start = 0
        self._snapshot_start: tracemalloc.Snapshot | None = None

    def __enter__(self) -> ProfilePhase:
        self._wall_start_ns = time.perf_counter_ns()
        self._cpu_start_ns = time.process_time_ns()
        self._rss_start = rss_high_water_bytes()
        if tracemalloc.is_tracing():
            self._snapshot_start = tracemalloc.take_snapshot()
        return self._handle

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        del exc, traceback
        snapshot_end = tracemalloc.take_snapshot() if tracemalloc.is_tracing() else None
        current_bytes: int | None = None
        peak_bytes: int | None = None
        top_allocations: tuple[dict[str, object], ...] = ()
        if tracemalloc.is_tracing():
            current_bytes, peak_bytes = tracemalloc.get_traced_memory()
        if self._snapshot_start is not None and snapshot_end is not None:
            top_allocations = top_tracemalloc_diffs(self._snapshot_start, snapshot_end)

        self._append_phase(
            CompletedPhase(
                name=self._handle.name,
                status="failed" if exc_type is not None else "completed",
                wall_ms=elapsed_ms(self._wall_start_ns, time.perf_counter_ns()),
                cpu_ms=elapsed_ms(self._cpu_start_ns, time.process_time_ns()),
                rss_high_water_start_bytes=self._rss_start,
                rss_high_water_end_bytes=rss_high_water_bytes(),
                details=dict(self._handle.details),
                tracemalloc_current_bytes=current_bytes,
                tracemalloc_peak_bytes=peak_bytes,
                tracemalloc_top_allocations=top_allocations,
            )
        )
        return False
