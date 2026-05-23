"""Observability primitives for the CLI pipeline.

Provides structured timing, RSS measurement, per-layer/per-rule
timeouts, and scan metadata collection.  All diagnostic output goes
through ``logging`` so library users can also benefit.

Timeout hierarchy:
  overall  →  per-layer  →  per-rule
Nested timeouts share one monotonic deadline stack.  The active ``SIGALRM``
is always armed for the nearest absolute deadline, so an outer deadline that
expires inside an inner context raises the outer typed exception.
"""

from __future__ import annotations

import logging
import platform
import resource
import signal
import sys
import time
import traceback
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from types import FrameType
    from typing import Any

logger = logging.getLogger("flawed")


# ── RSS measurement ──────────────────────────────────────────────


def current_rss_mb() -> float:
    """Return current process RSS in megabytes (best-effort).

    Uses ``ru_maxrss`` (process high-water peak), so this can grow but never
    shrink across a process.  For a *true* current-RSS reading that can reveal
    memory being freed, use :func:`sample_rss_bytes`.
    """
    usage = resource.getrusage(resource.RUSAGE_SELF)
    rss_bytes = usage.ru_maxrss
    # macOS reports bytes, Linux reports kilobytes
    if platform.system() == "Darwin":
        return rss_bytes / (1024 * 1024)
    return rss_bytes / 1024


_PROC_SELF_STATUS = "/proc/self/status"

#: Source label when the trajectory sample is a true current RSS reading.
RSS_SOURCE_PROC = "proc_status_vmrss"
#: Source label when only the peak high-water mark is available (macOS dev).
RSS_SOURCE_PEAK = "rusage_maxrss_peak"


def _parse_vmrss_bytes(status_text: str) -> int | None:
    """Return the ``VmRSS`` value (bytes) from ``/proc/self/status`` text.

    Returns ``None`` if no parseable ``VmRSS`` line is present — a pure
    function so tests can feed fixture text without a live ``/proc``.
    """
    for line in status_text.splitlines():
        if not line.startswith("VmRSS:"):
            continue
        parts = line.split()
        # Expected shape: ["VmRSS:", "<number>", "kB"]
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1]) * 1024
    return None


def _read_proc_vmrss_bytes(path: str = _PROC_SELF_STATUS) -> int | None:
    """Best-effort true current RSS from ``/proc/self/status`` (Linux)."""
    try:
        with Path(path).open(encoding="utf-8") as handle:
            return _parse_vmrss_bytes(handle.read())
    except OSError:
        return None


def _peak_rss_bytes() -> int:
    """Return the process RSS high-water peak normalized to bytes."""
    raw = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if sys.platform == "darwin":
        return raw
    return raw * 1024


def sample_rss_bytes() -> tuple[int, str]:
    """Return ``(current_rss_bytes, source_label)`` — TRUE current RSS where possible.

    On Linux the value is the live ``VmRSS`` from ``/proc/self/status``, so a
    trajectory built from repeated samples *can decrease* and reveal memory
    being freed.  On other platforms (macOS dev) no dependency-free current-RSS
    source exists, so we fall back to the ``ru_maxrss`` peak and label it
    ``rusage_maxrss_peak`` so consumers know the value is monotonic high-water,
    not live.
    """
    if sys.platform == "linux":
        live = _read_proc_vmrss_bytes()
        if live is not None:
            return live, RSS_SOURCE_PROC
    return _peak_rss_bytes(), RSS_SOURCE_PEAK


# ── Timeout exceptions ──────────────────────────────────────────


class LayerTimeoutError(Exception):
    """Raised when a layer exceeds its time budget."""

    def __init__(self, layer: str, limit_seconds: int | float) -> None:
        self.layer = layer
        self.limit_seconds = limit_seconds
        super().__init__(f"Layer {layer!r} exceeded {_format_seconds(limit_seconds)}s timeout")


class RuleTimeoutError(Exception):
    """Raised when a single rule exceeds its time budget."""

    def __init__(self, rule_id: str, limit_seconds: int | float) -> None:
        self.rule_id = rule_id
        self.limit_seconds = limit_seconds
        super().__init__(f"Rule {rule_id!r} exceeded {_format_seconds(limit_seconds)}s timeout")


class OverallTimeoutError(Exception):
    """Raised when the whole scan exceeds its time budget."""

    def __init__(self, limit_seconds: int | float) -> None:
        self.limit_seconds = limit_seconds
        super().__init__(f"Overall scan exceeded {_format_seconds(limit_seconds)}s timeout")


# ── Timeout context managers ────────────────────────────────────


@contextmanager
def overall_timeout(seconds: int | float | None) -> Iterator[None]:
    """Raise ``OverallTimeoutError`` if the scan exceeds *seconds*."""
    if seconds is None or not _signals_supported():
        yield
        return

    with _deadline(
        description="overall scan",
        seconds=seconds,
        exception_factory=lambda: OverallTimeoutError(seconds),
    ):
        yield


@contextmanager
def layer_timeout(layer: str, seconds: int | float | None) -> Iterator[None]:
    """Raise ``LayerTimeoutError`` if the body exceeds *seconds*.

    Uses a process-wide ``SIGALRM`` deadline stack on Unix.  On platforms
    without ``SIGALRM`` the timeout is a no-op.
    """
    if seconds is None or not _signals_supported():
        yield
        return

    with _deadline(
        description=f"layer {layer}",
        seconds=seconds,
        exception_factory=lambda: LayerTimeoutError(layer, seconds),
    ):
        yield


@contextmanager
def rule_timeout(rule_id: str, seconds: int | float | None) -> Iterator[None]:
    """Raise ``RuleTimeoutError`` if a single rule exceeds *seconds*.

    Uses the shared deadline stack, preserving outer overall/layer deadlines.
    """
    if seconds is None or not _signals_supported():
        yield
        return

    with _deadline(
        description=f"rule {rule_id}",
        seconds=seconds,
        exception_factory=lambda: RuleTimeoutError(rule_id, seconds),
    ):
        yield


@dataclass(frozen=True)
class _Deadline:
    description: str
    seconds: int | float
    expires_at: float
    exception_factory: Callable[[], Exception]


@dataclass
class _AlarmState:
    deadline_stack: list[_Deadline] = field(default_factory=list)
    previous_alarm_handler: (
        signal.Handlers | Callable[[int, FrameType | None], Any] | int | None
    ) = None
    previous_timer: tuple[float, float] | None = None
    previous_timer_started_at: float = 0.0


_alarm_state = _AlarmState()


@contextmanager
def _deadline(
    *,
    description: str,
    seconds: int | float,
    exception_factory: Callable[[], Exception],
) -> Iterator[None]:
    deadline = _Deadline(
        description=description,
        seconds=seconds,
        expires_at=time.monotonic() + float(seconds),
        exception_factory=exception_factory,
    )
    _push_deadline(deadline)
    try:
        yield
    finally:
        _pop_deadline(deadline)


def _signals_supported() -> bool:
    return hasattr(signal, "SIGALRM") and hasattr(signal, "setitimer")


def _push_deadline(deadline: _Deadline) -> None:
    if not _alarm_state.deadline_stack:
        _alarm_state.previous_alarm_handler = signal.getsignal(signal.SIGALRM)
        _alarm_state.previous_timer = signal.getitimer(signal.ITIMER_REAL)
        _alarm_state.previous_timer_started_at = time.monotonic()
        signal.signal(signal.SIGALRM, _deadline_handler)

    _alarm_state.deadline_stack.append(deadline)
    _arm_nearest_deadline()


def _pop_deadline(deadline: _Deadline) -> None:
    try:
        _alarm_state.deadline_stack.remove(deadline)
    except ValueError:
        logger.debug("deadline already removed: %s", deadline.description)

    if _alarm_state.deadline_stack:
        _arm_nearest_deadline()
        return

    _restore_previous_alarm()


def _deadline_handler(signum: int, frame: FrameType | None) -> None:  # noqa: ARG001
    if not _alarm_state.deadline_stack:
        return

    deadline = _nearest_deadline()
    logger.warning(
        "TIMEOUT: %s exceeded %ss limit — stack trace:\n%s",
        deadline.description,
        _format_seconds(deadline.seconds),
        "".join(traceback.format_stack(frame)),
    )
    _alarm_state.deadline_stack.remove(deadline)
    raise deadline.exception_factory()


def _nearest_deadline() -> _Deadline:
    return min(_alarm_state.deadline_stack, key=lambda item: item.expires_at)


def _arm_nearest_deadline() -> None:
    delay = max(_nearest_deadline().expires_at - time.monotonic(), 0.001)
    signal.setitimer(signal.ITIMER_REAL, delay)


def _restore_previous_alarm() -> None:
    signal.setitimer(signal.ITIMER_REAL, 0.0)
    if _alarm_state.previous_alarm_handler is not None:
        signal.signal(signal.SIGALRM, _alarm_state.previous_alarm_handler)

    if _alarm_state.previous_timer is not None:
        remaining, interval = _alarm_state.previous_timer
        elapsed = time.monotonic() - _alarm_state.previous_timer_started_at
        restored_remaining = max(0.0, remaining - elapsed) if remaining > 0 else 0.0
        if restored_remaining > 0 or interval > 0:
            signal.setitimer(signal.ITIMER_REAL, restored_remaining, interval)

    _alarm_state.previous_alarm_handler = None
    _alarm_state.previous_timer = None
    _alarm_state.previous_timer_started_at = 0.0


def _format_seconds(seconds: int | float) -> str:
    return f"{seconds:g}"


# ── Scan metrics ────────────────────────────────────────────────


@dataclass
class PhaseMetrics:
    """Timing and metadata for a single pipeline phase."""

    name: str
    elapsed_seconds: float = 0.0
    rss_mb: float = 0.0
    """Peak (``ru_maxrss``) RSS in MB at phase end — monotonic high-water."""
    rss_start_bytes: int | None = None
    """True current RSS (bytes) sampled at phase ENTRY (see ``rss_source``)."""
    rss_end_bytes: int | None = None
    """True current RSS (bytes) sampled at phase EXIT — a drop vs start reveals freeing."""
    rss_source: str = ""
    """Label of the RSS sampler used for ``rss_start_bytes``/``rss_end_bytes``."""
    completed: bool = True
    timeout_hit: bool = False
    detail: dict[str, object] = field(default_factory=dict)


@dataclass
class ScanMetrics:
    """Aggregate metrics for a complete scan invocation."""

    target: str = ""
    flawed_version: str = ""
    rules_loaded: int = 0
    rules_executed: int = 0
    rules_skipped: int = 0
    finding_count: int = 0
    retained_finding_count: int = 0
    findings_truncated: bool = False
    gap_count: int = 0
    index_error_count: int = 0
    """L1 extraction errors (e.g. unparsable files gapped from the index)."""
    incomplete: bool = False
    overall_timed_out: bool = False
    timed_out_layers: list[str] = field(default_factory=list)
    timed_out_rules: list[str] = field(default_factory=list)
    budget_capped_layers: list[str] = field(default_factory=list)
    """Layers that hit a construction memory/size budget (FLAW-345).

    Distinct from ``timed_out_layers``: a budget breach is a fail-closed guard
    against an OOM kill, not a wall-clock timeout. Both force ``incomplete``.
    """
    phases: list[PhaseMetrics] = field(default_factory=list)

    @property
    def total_seconds(self) -> float:
        return sum(p.elapsed_seconds for p in self.phases)

    def phase_seconds(self, name_prefix: str) -> float:
        return sum(p.elapsed_seconds for p in self.phases if p.name.startswith(name_prefix))

    def status_label(self) -> str:
        if not self.incomplete:
            return "COMPLETE"
        parts = []
        if self.overall_timed_out:
            parts.append("overall timed out")
        if self.timed_out_layers:
            parts.append(f"{', '.join(self.timed_out_layers)} timed out")
        if self.timed_out_rules:
            parts.append(f"{len(self.timed_out_rules)} rule(s) timed out")
        if self.budget_capped_layers:
            parts.append(f"{', '.join(self.budget_capped_layers)} memory-capped")
        if self.rules_skipped > 0:
            parts.append(f"{self.rules_skipped} rule(s) skipped")
        detail = ", ".join(parts) if parts else "partial execution"
        return f"INCOMPLETE ({detail})"

    def to_metadata_dict(self) -> dict[str, object]:
        """Return metadata dict suitable for JSON output."""
        l1_seconds = _json_seconds(self.phase_seconds("L1"))
        l2_seconds = _json_seconds(self.phase_seconds("L2"))
        l3_seconds = _json_seconds(self.phase_seconds("L3"))
        total_seconds = _json_seconds(self.total_seconds)
        return {
            "flawed_version": self.flawed_version,
            "target": self.target,
            "rules_loaded": self.rules_loaded,
            "rules_executed": self.rules_executed,
            "incomplete": self.incomplete,
            "overall_timed_out": self.overall_timed_out,
            "timed_out_layers": self.timed_out_layers,
            "timed_out_rules": self.timed_out_rules,
            "budget_capped_layers": self.budget_capped_layers,
            "finding_count": self.finding_count,
            "retained_finding_count": self.retained_finding_count,
            "findings_truncated": self.findings_truncated,
            "index_error_count": self.index_error_count,
            "timing": {
                "l1_extraction": l1_seconds,
                "l2_semantic": l2_seconds,
                "l3_rules": l3_seconds,
                "total": total_seconds,
                "index_seconds": l1_seconds,
                "semantic_seconds": l2_seconds,
                "rules_seconds": l3_seconds,
                "total_seconds": total_seconds,
            },
        }


def _json_seconds(seconds: float) -> float:
    """Round positive JSON durations without erasing sub-millisecond work."""
    if seconds <= 0:
        return 0.0
    return max(round(seconds, 3), 0.001)


@contextmanager
def record_scan_phase(metrics: ScanMetrics, name: str) -> Iterator[None]:
    """Append elapsed time/RSS for one scan phase to *metrics*.

    Samples true current RSS at both entry and exit so the recorded
    ``rss_start_bytes``/``rss_end_bytes`` form a cross-phase trajectory that can
    reveal accumulation (or freeing) — not just the ``ru_maxrss`` peak.
    """
    start = time.monotonic()
    start_rss, rss_source = sample_rss_bytes()
    try:
        yield
    except BaseException as exc:
        metrics.phases.append(_phase_metrics(name, start, start_rss, rss_source, exc=exc))
        raise
    else:
        metrics.phases.append(_phase_metrics(name, start, start_rss, rss_source))


def _phase_metrics(
    name: str,
    start: float,
    start_rss: int,
    rss_source: str,
    *,
    exc: BaseException | None = None,
) -> PhaseMetrics:
    end_rss, _ = sample_rss_bytes()
    return PhaseMetrics(
        name=name,
        elapsed_seconds=time.monotonic() - start,
        rss_mb=current_rss_mb(),
        rss_start_bytes=start_rss,
        rss_end_bytes=end_rss,
        rss_source=rss_source,
        completed=exc is None,
        timeout_hit=isinstance(exc, LayerTimeoutError),
    )


# ── Logging setup ───────────────────────────────────────────────


def configure_logging(verbosity: int) -> None:
    """Set up the ``flawed`` logger hierarchy.

    - verbosity=0: WARNING
    - verbosity=1: INFO  (``-v``)
    - verbosity=2: DEBUG (``-vv``)
    """
    level = logging.WARNING
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity >= 1:
        level = logging.INFO

    root_logger = logging.getLogger("flawed")
    root_logger.setLevel(level)

    # Only add handler if none exist (avoid duplicates)
    if not root_logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        fmt = "%(asctime)s [%(name)s] %(message)s"
        handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
        root_logger.addHandler(handler)
