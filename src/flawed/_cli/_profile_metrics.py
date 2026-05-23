"""Low-level timing and memory metrics for scan profiling."""

from __future__ import annotations

import resource
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import tracemalloc

TRACEBACK_LIMIT = 10
TOP_ALLOCATION_LIMIT = 8


def rss_high_water_bytes() -> int:
    """Return process RSS high-water mark normalized to bytes."""
    raw = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if sys.platform == "darwin":
        return raw
    return raw * 1024


def elapsed_ms(start_ns: int, end_ns: int) -> float:
    """Convert a nanosecond start/end pair to rounded milliseconds."""
    return round((end_ns - start_ns) / 1_000_000, 3)


def top_tracemalloc_diffs(
    before: tracemalloc.Snapshot,
    after: tracemalloc.Snapshot,
) -> tuple[dict[str, object], ...]:
    """Return the largest positive allocation deltas between two snapshots."""
    rows: list[dict[str, object]] = []
    for stat in after.compare_to(before, "lineno"):
        if stat.size_diff <= 0:
            continue
        frame = stat.traceback[0]
        rows.append(
            {
                "file": frame.filename,
                "line": frame.lineno,
                "size_diff_bytes": stat.size_diff,
                "count_diff": stat.count_diff,
            }
        )
        if len(rows) >= TOP_ALLOCATION_LIMIT:
            break
    return tuple(rows)
