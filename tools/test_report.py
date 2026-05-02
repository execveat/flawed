"""Read and display the latest pytest JSON report without re-running tests.

Usage:
    uv run python -m tools.test_report          # summary
    uv run python -m tools.test_report --full   # include failure details
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "local" / "test-results.json"


def main(argv: list[str] | None = None) -> int:
    """Print the latest test report summary."""
    argv = argv if argv is not None else sys.argv[1:]
    full = "--full" in argv

    if not REPORT_PATH.exists():
        print(
            "No test report found at local/test-results.json.\n"
            "Run `mise run test` first to generate one.",
            file=sys.stderr,
        )
        return 1

    data = json.loads(REPORT_PATH.read_text())
    summary = data.get("summary", {})

    # Core counts
    passed = summary.get("passed", 0)
    failed = summary.get("failed", 0)
    xfailed = summary.get("xfailed", 0)
    xpassed = summary.get("xpassed", 0)
    errored = summary.get("error", 0)
    deselected = summary.get("deselected", 0)
    total = summary.get("total", 0)
    duration = summary.get("duration", 0.0)

    print(
        f"passed={passed} failed={failed} error={errored} "
        f"xfailed={xfailed} xpassed={xpassed} "
        f"deselected={deselected} total={total} "
        f"duration={duration:.1f}s"
    )

    if failed == 0 and errored == 0:
        print("All tests passed.")
    else:
        print(f"FAILURES: {failed}  ERRORS: {errored}")

    if full:
        tests = data.get("tests", [])
        failures = [t for t in tests if t.get("outcome") in ("failed", "error")]
        if failures:
            print(f"\n--- {len(failures)} failure(s) ---")
            for t in failures:
                nodeid = t.get("nodeid", "?")
                outcome = t.get("outcome", "?")
                msg = t.get("call", {}).get("crash", {}).get("message", "")
                print(f"  [{outcome}] {nodeid}")
                if msg:
                    print(f"    {msg}")

    return 1 if (failed or errored) else 0


if __name__ == "__main__":
    raise SystemExit(main())
