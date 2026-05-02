"""CLI entry point for the memory stress harness.

Usage::

    uv run python -m tools.stress [OPTIONS]
    mise run stress [-- OPTIONS]

Generates synthetic Flask apps at increasing scale, scans each through
the full flawed pipeline, and records per-phase RSS / wall-time / object
counts.  Results are written as JSON and CSV to the output directory.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from pathlib import Path

from .generate import StressConfig, generate_stress_app
from .measure import StressResult, measure_scan, write_results

# ---------------------------------------------------------------------------
# Scale presets — vary file_count with constant per-file density
# ---------------------------------------------------------------------------

_SCALES: dict[str, list[int]] = {
    "quick": [25],
    "standard": [25, 50, 100],
    "full": [25, 50, 100, 150],
}

_MB = 1024 * 1024


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------


def _print_summary(results: list[StressResult]) -> None:
    print("\nMemory Stress Results")
    print("=" * 78)
    header = (
        f"{'Scale':<8} {'Files':>5} {'Funcs':>6} {'Routes':>7} "
        f"{'Peak RSS (MB)':>14} {'Wall (s)':>9} {'Dominant Phase'}"
    )
    print(header)
    print("-" * 78)
    for r in results:
        dominant = max(r.phases, key=lambda p: p.rss_delta_bytes)
        print(
            f"{r.config_label:<8} {r.file_count:>5} "
            f"{r.function_count:>6} {r.route_count:>7} "
            f"{r.peak_rss_bytes / _MB:>14.1f} "
            f"{r.total_wall_ms / 1000:>9.1f} "
            f"{dominant.name}"
        )

    # Phase breakdown for the largest scale
    largest = results[-1]
    print(f"\nPhase Breakdown ({largest.config_label}):")
    for phase in largest.phases:
        rss_mb = phase.rss_delta_bytes / _MB
        print(
            f"  {phase.name + ':':<28} "
            f"{phase.wall_ms / 1000:>6.1f}s "
            f"{rss_mb:>+8.1f} MB RSS "
            f"{phase.object_delta:>+8} objects"
        )
    print()


# ---------------------------------------------------------------------------
# Scope duplication analysis
# ---------------------------------------------------------------------------


def _print_scope_analysis(results: list[StressResult]) -> None:
    """Print per-scale scope duplication metrics from Phase 8 details."""
    # Only print if the semantic_conversion phase has scope metrics
    has_scope = any(
        _get_semantic_details(r).get("total_observation_refs") is not None for r in results
    )
    if not has_scope:
        return

    print("Scope Duplication Analysis")
    print("=" * 78)
    header = (
        f"{'Scale':<8} {'Routes':>7} {'Funcs':>6} "
        f"{'Rt Reach':>9} {'Rt FullSt':>10} {'Fn Reach':>9} "
        f"{'Total Refs':>11}"
    )
    print(header)
    print("-" * 78)
    for r in results:
        d = _get_semantic_details(r)
        print(
            f"{r.config_label:<8} {r.route_count:>7} "
            f"{r.function_count:>6} "
            f"{d.get('route_reachable_total_refs', 0):>9} "
            f"{d.get('route_fullstack_total_refs', 0):>10} "
            f"{d.get('fn_reachable_total_refs', 0):>9} "
            f"{d.get('total_observation_refs', 0):>11}"
        )

    # Scaling ratio: if we have 2+ results, show refs/route growth
    if len(results) >= 2:
        print(f"\nScaling Ratios (relative to {results[0].config_label}):")
        base_d = _get_semantic_details(results[0])
        base_routes = max(results[0].route_count, 1)
        base_refs_per_route = int(base_d.get("total_observation_refs", 0)) / base_routes  # type: ignore[call-overload]
        for r in results[1:]:
            d = _get_semantic_details(r)
            routes = max(r.route_count, 1)
            refs_per_route = int(d.get("total_observation_refs", 0)) / routes  # type: ignore[call-overload]
            ratio = refs_per_route / base_refs_per_route if base_refs_per_route else 0
            print(
                f"  {r.config_label}: refs/route = {refs_per_route:.1f} "
                f"({ratio:.2f}x baseline {base_refs_per_route:.1f})"
            )

    # Detailed breakdown for largest scale
    largest = results[-1]
    d = _get_semantic_details(largest)
    print(f"\nLargest Scale Detail ({largest.config_label}):")
    print(f"  Avg route reachable size: {d.get('avg_route_reachable_size', 0)}")
    print(f"  Max route reachable size: {d.get('max_route_reachable_size', 0)}")
    print(f"  Avg fn reachable size:    {d.get('avg_fn_reachable_size', 0)}")
    print(f"  Max fn reachable size:    {d.get('max_fn_reachable_size', 0)}")

    top_routes = d.get("top_routes_by_reachable_size", [])
    if top_routes:
        print("  Top routes by reachable scope size:")
        for entry in top_routes[:5]:  # type: ignore[index]
            print(f"    {entry[1]:>6}  {entry[0]}")

    top_fns = d.get("top_functions_by_reachable_size", [])
    if top_fns:
        print("  Top functions by reachable scope size:")
        for entry in top_fns[:5]:  # type: ignore[index]
            print(f"    {entry[1]:>6}  {entry[0]}")

    print()


def _get_semantic_details(result: StressResult) -> dict[str, object]:
    """Extract Phase 8 (semantic_conversion) details from a result."""
    for phase in result.phases:
        if phase.name == "semantic_conversion":
            return phase.details
    return {}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tools.stress",
        description="Memory stress harness for the flawed scan pipeline.",
    )
    parser.add_argument(
        "--scales",
        choices=list(_SCALES),
        default="standard",
        help="Scale preset (default: standard)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("local/stress"),
        help="Directory for results (default: local/stress)",
    )
    parser.add_argument(
        "--tracemalloc",
        action="store_true",
        help="Enable tracemalloc line attribution (slow)",
    )
    parser.add_argument(
        "--keep-fixtures",
        action="store_true",
        help="Keep generated fixture directories after measurement",
    )
    parser.add_argument(
        "--providers",
        default="flask,sqlalchemy",
        help="Comma-separated provider list (default: flask,sqlalchemy)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducible generation (default: 42)",
    )
    parser.add_argument(
        "--with-l3",
        action="store_true",
        help="Include L3 rule execution (skipped by default for speed)",
    )
    args = parser.parse_args(argv)

    file_counts = _SCALES[args.scales]
    providers = tuple(p.strip() for p in args.providers.split(","))

    output_dir: Path = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    fixture_base = output_dir / "fixtures"
    fixture_base.mkdir(parents=True, exist_ok=True)

    print(f"Stress harness: {len(file_counts)} scale(s), providers={list(providers)}")
    print(f"Output: {output_dir}")
    overall_start = time.monotonic()

    results: list[StressResult] = []
    for n_files in file_counts:
        config = StressConfig(file_count=n_files, providers=providers, seed=args.seed)
        label = f"{n_files}f"

        print(f"\n--- Scale {label} ({n_files} files) ---")
        print("  Generating synthetic app...")
        gen = generate_stress_app(config, output_dir=fixture_base)
        print(
            f"  Generated: {gen.file_count} files, "
            f"~{gen.function_count} functions, "
            f"~{gen.route_count} routes, "
            f"{gen.line_count} lines"
        )

        print("  Running pipeline measurement...")
        result = measure_scan(
            gen.app_dir,
            label=label,
            enable_tracemalloc=args.tracemalloc,
            skip_l3=not args.with_l3,
        )
        results.append(result)
        print(
            f"  Done: {result.total_wall_ms / 1000:.1f}s, "
            f"peak RSS {result.peak_rss_bytes / _MB:.1f} MB"
        )

        if not args.keep_fixtures and gen.app_dir.exists():
            shutil.rmtree(gen.app_dir)

    # Write results
    json_path, csv_path = write_results(results, output_dir)
    print(f"\nResults written to:\n  {json_path}\n  {csv_path}")

    elapsed = time.monotonic() - overall_start
    print(f"Total elapsed: {elapsed:.1f}s")

    _print_summary(results)
    _print_scope_analysis(results)

    return 0


if __name__ == "__main__":
    sys.exit(main())
