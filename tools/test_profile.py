"""Per-test timing breakdown — fixture-setup vs test-body — from persisted data.

Two sources, neither requiring a test re-run:

* ``local/test-results.json`` — the full ``pytest-json-report`` the gate writes,
  carrying per-test **setup / call / teardown** durations. This is where the
  setup-vs-call split comes from: a "30s test" is almost always a 30s fixture
  *setup* (a live build), not a slow test body. It covers only the LAST run's
  executed tests (a scoped commit -> just those).
* ``.testmondata`` — testmon's per-test **total** duration (one number, no phase
  split), accumulated across runs -> full suite breadth. Used as the breadth view
  and the fallback when no full report is present.

Run via ``mise run test-profile`` after any run; for a full-suite split, run
``mise run check`` (or ``mise run test -- --all``) first so the report covers
everything.
"""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_DB = Path(".testmondata")
_REPORT = Path("local/test-results.json")

# Detection specs that still live-build (spawn semgrep/basedpyright) inside the
# fast tier — the subprocess-guard conversion-debt allowlist (FLAW-302). Keep in
# sync with tests/_guards/subprocess_guard.py::_ALLOWLIST_PATH_SUBSTRINGS.
_LIVE_BUILD_SPECS: tuple[str, ...] = (
    "test_c02a_effect_labels",
    "test_c02a_incidental_writes",
    "test_c02a_lifecycle_effects",
    "test_c04b_decorator_coverage",
    "test_c04b_lifecycle_mutation",
    "test_csrf_unresolved_decorator",
    "test_g091_configured_target",
    "test_r03c_disjunctive_auth",
    "test_r03e_auth_in_where",
    "test_r04_cardinality_shapes",
    "test_r04f_session_replay",
    "test_session_identity_emission",
    "test_sso_email_claim_divergence",
    "test_u005_getlist_precision",
)


def _tier(nodeid: str) -> str:
    parts = nodeid.split("::", 1)[0].split("/")
    if len(parts) >= 3 and parts[1] in {"unit", "specs"}:
        return "/".join(parts[:3])
    return "/".join(parts[:2]) if len(parts) >= 2 else nodeid


@dataclass
class _Phase:
    count: int = 0
    setup: float = 0.0
    call: float = 0.0
    total: float = 0.0  # setup + call + teardown

    def add(self, setup: float, call: float, teardown: float) -> None:
        self.count += 1
        self.setup += setup
        self.call += call
        self.total += setup + call + teardown


@dataclass
class _TotalOnly:
    count: int = 0
    total: float = 0.0
    longest: float = 0.0

    def add(self, duration: float) -> None:
        self.count += 1
        self.total += duration
        self.longest = max(self.longest, duration)


def _load_testmon() -> dict[str, float]:
    if not _DB.exists():
        return {}
    with sqlite3.connect(_DB) as conn:
        rows = conn.execute("SELECT test_name, duration FROM test_execution").fetchall()
    return {str(name): float(dur or 0.0) for name, dur in rows}


def _phase_duration(entry: dict[str, Any], phase: str) -> float:
    block = entry.get(phase)
    return float(block.get("duration", 0.0)) if isinstance(block, dict) else 0.0


def _load_phases() -> dict[str, tuple[float, float, float]]:
    """nodeid -> (setup, call, teardown) seconds, from the full json report."""
    if not _REPORT.exists():
        return {}
    try:
        data = json.loads(_REPORT.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    out: dict[str, tuple[float, float, float]] = {}
    for entry in data.get("tests", []):
        nodeid = entry.get("nodeid")
        if not isinstance(nodeid, str):
            continue
        out[nodeid] = (
            _phase_duration(entry, "setup"),
            _phase_duration(entry, "call"),
            _phase_duration(entry, "teardown"),
        )
    return out


def _print_phase_breakdown(phases: dict[str, tuple[float, float, float]]) -> None:
    buckets: dict[str, _Phase] = defaultdict(_Phase)
    grand = 0.0
    for nodeid, (setup, call, teardown) in phases.items():
        buckets[_tier(nodeid)].add(setup, call, teardown)
        grand += setup + call + teardown

    print("Per-phase breakdown (from the last run's full pytest report)")
    print(f"{'tier':<28}{'count':>6}{'setup_s':>9}{'call_s':>9}{'total_s':>9}{'%':>7}")
    print("-" * 68)
    for tier, b in sorted(buckets.items(), key=lambda kv: -kv[1].total):
        share = 100 * b.total / grand if grand else 0.0
        print(f"{tier:<28}{b.count:>6}{b.setup:>9.1f}{b.call:>9.1f}{b.total:>9.1f}{share:>6.1f}%")
    print("-" * 68)
    setup_total = sum(s for s, _, _ in phases.values())
    call_total = sum(c for _, c, _ in phases.values())
    print(f"{'TOTAL':<28}{len(phases):>6}{setup_total:>9.1f}{call_total:>9.1f}{grand:>9.1f}")
    print(
        f"  setup (fixture builds) {100 * setup_total / grand:.0f}%  |  "
        f"call (test bodies) {100 * call_total / grand:.0f}%"
        if grand
        else ""
    )

    print("\nTop 15 by CALL time (genuinely slow test bodies):")
    for nodeid, (_, call, _) in sorted(phases.items(), key=lambda kv: -kv[1][1])[:15]:
        print(f"  {call:6.2f}s  {nodeid}")

    print("\nTop 15 by SETUP time (heavy fixture builds — usually the live-builders):")
    for nodeid, (setup, _, _) in sorted(phases.items(), key=lambda kv: -kv[1][0])[:15]:
        print(f"  {setup:6.2f}s  {nodeid}")


def _print_total_breakdown(totals: dict[str, float]) -> None:
    buckets: dict[str, _TotalOnly] = defaultdict(_TotalOnly)
    grand = 0.0
    for nodeid, dur in totals.items():
        buckets[_tier(nodeid)].add(dur)
        grand += dur
    if grand <= 0:
        return
    print("\nFull-breadth totals (testmon; total duration only, no phase split)")
    print(f"{'tier':<28}{'count':>6}{'total_s':>9}{'mean_ms':>9}{'max_s':>8}{'%':>7}")
    print("-" * 67)
    for tier, b in sorted(buckets.items(), key=lambda kv: -kv[1].total):
        mean_ms = 1000 * b.total / b.count if b.count else 0.0
        share = 100 * b.total / grand
        print(
            f"{tier:<28}{b.count:>6}{b.total:>9.1f}{mean_ms:>9.0f}{b.longest:>8.2f}{share:>6.1f}%"
        )
    print("-" * 67)
    print(f"{'TOTAL':<28}{len(totals):>6}{grand:>9.1f}")


def _print_live_build(best_total: dict[str, float]) -> None:
    if not best_total:
        return
    grand = sum(best_total.values())
    live = {n: d for n, d in best_total.items() if any(s in n for s in _LIVE_BUILD_SPECS)}
    live_total = sum(live.values())
    if grand <= 0:
        return
    print(
        f"\nLive-build (subprocess-spawning) specs still in the fast tier: "
        f"{len(live)} tests, {live_total:.1f}s ({100 * live_total / grand:.0f}% of total). "
        f"Their cost is fixture SETUP; converting them (FLAW-302) is the largest single speedup."
    )


def main() -> int:
    totals = _load_testmon()
    phases = _load_phases()

    if not totals and not phases:
        print("No timing data — run `mise run test` (or `mise run check`) first.")
        return 1

    if phases:
        _print_phase_breakdown(phases)
        if totals:
            covered = len(phases)
            known = len(totals)
            if covered < known:
                print(
                    f"\nNote: the per-phase report covers {covered} tests from the LAST run; "
                    f"testmon knows {known}. That run was scoped (e.g. a commit). "
                    f"Run `mise run check` (or `mise run test -- --all`) for a full split. "
                    f"Full-breadth totals below."
                )
                _print_total_breakdown(totals)
    else:
        print(
            "No full pytest report at local/test-results.json — showing testmon totals only "
            "(no setup/call split). Run `mise run check` to capture per-phase timings.\n"
        )
        _print_total_breakdown(totals)

    # Live-build summary: prefer testmon breadth; fall back to phase totals.
    best_total = dict(totals)
    for nodeid, (setup, call, teardown) in phases.items():
        best_total.setdefault(nodeid, setup + call + teardown)
    _print_live_build(best_total)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
