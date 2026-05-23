"""Pipeline orchestration for the development CLI.

Supports two modes:

- **L1-only** (default): runs the Code Index pipeline, refreshes the
  per-repo artifact cache, and reports extraction status.
- **Semantic** (``--semantic``): additionally runs the Layer 2 provider
  engine, builds the full semantic model (``WebApp``), and executes
  configured Layer 3 detection rules against the resulting ``RepoView``.
"""

from __future__ import annotations

import json
import logging
import shutil
from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from flawed._cli._code_signature import code_signature
from flawed._cli._observability import (
    LayerTimeoutError,
    PhaseMetrics,
    RuleTimeoutError,
    ScanMetrics,
    layer_timeout,
    record_scan_phase,
    rule_timeout,
)
from flawed._cli.rules import (
    RuleExecutionError,
    RuleProfile,
    discover_rule_files,
    flow_query_stats_of,
    iter_detector_findings,
    load_configured_detectors,
)
from flawed._cli.scan_record import (
    SCAN_RECORD_SCHEMA_VERSION,
    CacheInfo,
    MemorySample,
    PhaseTiming,
    RuleTiming,
    ScanRecord,
    SubPhaseTiming,
    artifact_size_summary,
    default_central_log_path,
    utc_now_iso,
    write_central,
    write_sidecar,
)
from flawed._cli.suppression import (
    IgnoreSpec,
    SuppressionRecord,
    compute_suppressions,
    deduplicate_findings,
    load_baseline,
    suppress_findings,
    write_baseline,
)
from flawed._config.paths import repo_cache_name, repo_content_hash, repo_data_dir
from flawed._index._pipeline import (
    _CACHE_KEY_FILE,
    L1_SCHEMA_VERSION,
    CorruptCacheError,
    build_index,
    cache_key_matches,
    detect_changed_files,
    incremental_build,
    load_index_from_artifacts,
    read_file_manifest,
    record_schema_fingerprint,
    type_enrichment_signature,
    write_cache_key,
)
from flawed._index._structural import discover_python_files
from flawed._index._types import ErrorKind
from flawed.severity import DEFAULT_SEVERITY, Severity

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

    from flawed._cli.output import Console
    from flawed._cli.profile import ProfilePhase, ScanProfiler
    from flawed._cli.provider_engine_cache import ProviderEngineCache
    from flawed._cli.result_cache import ResultCache
    from flawed._cli.rules import RuleDetector, RuleEntry, RuleFinding
    from flawed._config.paths import RepoIdentity
    from flawed._config.schema import ResolvedConfig
    from flawed._index import CodeIndex
    from flawed._index._pipeline import IndexBuildPhase
    from flawed._semantic._provider_engine import ProviderEngine, ProviderEngineResult
    from flawed.repo import RepoView

_log = logging.getLogger("flawed.pipeline")
MAX_RETAINED_L3_FINDINGS = 10_000

# FLAW-194: a rule whose wall time reaches this fraction of the per-rule timeout
# is flagged as a near-timeout — close enough that the next repo (or a colder
# cache) may push it over and silently drop its findings.
_NEAR_TIMEOUT_FRACTION = 0.8

# Exit-code contract (FLAW-147) — decouples "ran ok" from "found things", the
# decisive trivy/grype CI lesson. Documented in `flawed scan --help`.
EXIT_OK = 0  # completed; no findings at/above the --fail-on threshold
EXIT_FINDINGS = 1  # completed; findings at/above threshold exist
EXIT_USAGE = 2  # usage/config error (bad flag, missing target/config)
EXIT_INTERNAL = 3  # internal/analysis error (pipeline crash, lock held)
EXIT_TIMEOUT = 124  # a layer or the overall scan timed out (matches GNU timeout)


def _finding_sev(item: RuleFinding) -> Severity:
    """Severity of a finding for threshold/filter comparison (default when unset)."""
    sev = item.finding.severity
    return sev if sev is not None else DEFAULT_SEVERITY


def scan_exit_code(
    findings: Sequence[RuleFinding],
    *,
    fail_on: Severity,
    error: bool = True,
    incomplete: bool = False,
) -> int:
    """Resolve the process exit code from a completed scan (FLAW-147).

    ``incomplete`` (a layer timed out) wins — an incomplete scan must never read
    as clean. Otherwise ``--no-error`` (``error=False``) forces success, and the
    code is ``EXIT_FINDINGS`` iff a finding at/above ``fail_on`` exists.
    """
    if incomplete:
        return EXIT_TIMEOUT
    if not error:
        return EXIT_OK
    if any(_finding_sev(f) >= fail_on for f in findings):
        return EXIT_FINDINGS
    return EXIT_OK


#: Glob (relative to the ``flawed`` package root) over the Layer 1 extraction
#: source.  Its content hash (``extraction_code_signature``) was the L1 cache's
#: identity gate (FLAW-207); under FLAW-344 (scheme C) it is **demoted to recorded
#: provenance** — the gate is now ``L1_SCHEMA_VERSION`` + the record-schema
#: fingerprint, so a behaviour-preserving ``_index`` refactor no longer
#: invalidates the corpus.  The byte-hash is still computed and written for
#: auditing, and ``tools.check_l1_schema`` uses it at commit time to enforce that
#: any ``_index`` change is declared (preserving the anti-silent-FN guarantee).
_L1_EXTRACTION_SIGNATURE_PATTERNS: tuple[str, ...] = ("_index/**/*.py",)


class PipelineError(Exception):
    """Raised when a CLI pipeline step cannot continue."""


@dataclass(frozen=True)
class SemanticResult:
    """Layer 2 semantic result needed by the CLI pipeline."""

    repo_view: RepoView
    active_provider_ids: tuple[str, ...]
    provider_engine_result: ProviderEngineResult | None = None


def _warn_extraction_gaps(console: Console, index: CodeIndex) -> None:
    """Surface L1 extraction errors honestly, distinguishing gapped files.

    A file that fails to parse is gapped (absent from the index), so any finding
    in it is missed.  That miss must stay VISIBLE — an honest gap, never read as
    a clean "no findings" (the no-fail-open prime directive, FLAW-264).
    """
    if not index.errors:
        return
    gapped_files = sorted({e.file for e in index.errors if e.error_kind is ErrorKind.PARSE})
    if gapped_files:
        shown = ", ".join(gapped_files[:5]) + (" …" if len(gapped_files) > 5 else "")
        console.warn(
            f"L1 gapped {len(gapped_files)} unparsable file(s) — excluded from analysis, "
            f"so findings there are missed: {shown}"
        )
    other = len(index.errors) - sum(1 for e in index.errors if e.error_kind is ErrorKind.PARSE)
    if other > 0:
        console.warn(f"L1 completed with {other} other non-fatal extraction warning(s).")


@dataclass
class _ScanObservation:
    """Mutable, always-on collector for the durable scan record (FLAW-355).

    Threaded through the pipeline like ``profiler`` — but always present and
    lightweight.  Each stage fills its slice; ``run_scan`` assembles the final
    :class:`ScanRecord` from this plus :class:`ScanMetrics`.  Defaults make every
    field optional so non-scan callers (``flawed index``) can ignore it.
    """

    l1_cache_status: str | None = None
    l1_invalidation_reason: str | None = None
    l1_sub_phases: list[IndexBuildPhase] = field(default_factory=list)
    l2_cache: str | None = None
    results_cache: str | None = None
    rule_timings: list[RuleProfile] = field(default_factory=list)
    memory_trajectory: tuple[tuple[float, int, str], ...] = ()


def _index_phase_recorder(
    profiler: ScanProfiler | None,
    observation: _ScanObservation | None,
) -> Callable[[IndexBuildPhase], None] | None:
    """Build the L1 sub-phase recorder feeding the profiler and/or the observation.

    Sub-phase measurement is gated only on a recorder being present
    (``_index/_pipeline.py``), so returning a non-``None`` callback here is what
    makes per-index-type timing *always-on* — no ``_index`` change required.
    Returns ``None`` when neither consumer is present (preserving the old
    no-measurement fast path).
    """
    if profiler is None and observation is None:
        return None

    def _record(phase: IndexBuildPhase) -> None:
        if profiler is not None:
            profiler.record_index_build_phase(phase)
        if observation is not None:
            observation.l1_sub_phases.append(phase)

    return _record


def _l1_invalidation_reason(  # noqa: PLR0911
    artifact_dir: Path,
    *,
    content_hash: str,
    type_enrichment_sig: str,
) -> str:
    """Return *why* a cached L1 index would be rebuilt (read-only, no ``_index`` edit).

    Reads the *existing* ``cache_key.json`` (before any re-extraction overwrites
    it) and compares the four validity components in the same fail-fast order as
    :func:`cache_key_matches`, naming the first that diverged.  ``cache_key_match``
    means the components all matched (so a rebuild was caused by something else,
    e.g. corrupt artifacts), and ``no_prior_cache`` means a first-ever build.
    """
    key_path = artifact_dir / _CACHE_KEY_FILE
    if not key_path.exists():
        return "no_prior_cache"
    try:
        data = json.loads(key_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return "unreadable_cache_key"
    if not isinstance(data, dict):
        return "unreadable_cache_key"
    if data.get("content_hash") != content_hash:
        return "repo_content_changed"
    if data.get("l1_schema_version") != L1_SCHEMA_VERSION:
        return "l1_schema_version_bumped"
    if data.get("record_schema_fingerprint") != record_schema_fingerprint():
        return "record_dataclass_schema_changed"
    if data.get("type_enrichment_signature", "") != type_enrichment_sig:
        return "type_enrichment_config_changed"
    return "cache_key_match"


def _phase_timing(phase: PhaseMetrics, *, served_from_cache: bool = False) -> PhaseTiming:
    """Map a :class:`PhaseMetrics` into the durable :class:`PhaseTiming`.

    Phase names are normalized to ``L1``/``L2``/``L3`` (from ``"L1 extraction"``
    etc.) so the record's phase keys are stable across releases.
    """
    return PhaseTiming(
        name=phase.name.split(" ", 1)[0],
        wall_ms=phase.elapsed_seconds * 1000.0,
        served_from_cache=served_from_cache,
        completed=phase.completed,
        rss_start_bytes=phase.rss_start_bytes,
        rss_end_bytes=phase.rss_end_bytes,
        rss_source=phase.rss_source,
    )


def _assemble_scan_record(
    *,
    metrics: ScanMetrics,
    observation: _ScanObservation,
    artifact_dir: Path | None,
    started_at: str,
    ended_at: str,
    exit_code: int,
    results_cache_full_hit: bool,
) -> ScanRecord:
    """Build the durable :class:`ScanRecord` from the scan's metrics + observation."""
    phases = [_phase_timing(p) for p in metrics.phases]
    # A full results-cache hit skips L2/L3 entirely (no ``record_scan_phase`` for
    # them), so synthesize cache-served phases — the warm-path economics the
    # campaign mines are exactly these near-zero L2/L3 entries on a cache hit.
    if results_cache_full_hit:
        present = {p.name for p in phases}
        phases.extend(
            PhaseTiming(name=name, wall_ms=0.0, served_from_cache=True)
            for name in ("L2", "L3")
            if name not in present
        )
    return ScanRecord(
        schema_version=SCAN_RECORD_SCHEMA_VERSION,
        started_at=started_at,
        ended_at=ended_at,
        repo=metrics.target,
        flawed_version=metrics.flawed_version,
        l1_schema_version=L1_SCHEMA_VERSION,
        exit_code=exit_code,
        incomplete=metrics.incomplete,
        overall_timed_out=metrics.overall_timed_out,
        timed_out_layers=tuple(metrics.timed_out_layers),
        timed_out_rules=tuple(metrics.timed_out_rules),
        budget_capped_layers=tuple(metrics.budget_capped_layers),
        phases=tuple(phases),
        l1_sub_phases=tuple(
            SubPhaseTiming(
                name=p.name,
                wall_ms=p.wall_ms,
                cpu_ms=p.cpu_ms,
                rss_end_bytes=p.rss_high_water_end_bytes,
            )
            for p in observation.l1_sub_phases
        ),
        cache=CacheInfo(
            l1_cache_status=observation.l1_cache_status,
            invalidation_reason=observation.l1_invalidation_reason,
            l2_cache=observation.l2_cache,
            results_cache=observation.results_cache,
        ),
        artifacts=artifact_size_summary(artifact_dir) if artifact_dir is not None else {},
        rule_timings=tuple(
            RuleTiming(rule_id=rp.rule_id, wall_ms=rp.wall_ms, finding_count=rp.finding_count)
            for rp in observation.rule_timings
        ),
        memory_trajectory=tuple(
            MemorySample(elapsed_ms=elapsed_ms, rss_bytes=rss_bytes, source=source)
            for (elapsed_ms, rss_bytes, source) in observation.memory_trajectory
        ),
    )


def _write_scan_record(
    *,
    config: ResolvedConfig,
    identity: RepoIdentity,
    record: ScanRecord,
    console: Console,
) -> None:
    """Persist *record* to the per-repo sidecar and the central run-log.

    Observability is non-load-bearing: a write failure (e.g. an unwritable log
    dir) is logged loudly and swallowed, never failing the scan it describes.
    """
    try:
        artifact_dir = repo_data_dir(config.data_dir, identity)
        write_sidecar(artifact_dir, record)
        log_path = config.observability_log_path or default_central_log_path(config.state_dir)
        write_central(log_path, record)
    except OSError as exc:
        console.warn(f"Could not write observability record: {exc}")
        _log.warning("observability record write failed: %s", exc)


def run_index(  # noqa: PLR0912, PLR0915
    *,
    identity: RepoIdentity,
    config: ResolvedConfig,
    console: Console,
    force: bool = False,
    profile_phase: ProfilePhase | None = None,
    profiler: ScanProfiler | None = None,
    observation: _ScanObservation | None = None,
) -> CodeIndex:
    """Run Layer 1 extraction only.

    Checks the artifact cache first: if a previous extraction matches the
    current repo content hash, pipeline version, type-enrichment signature,
    and L1 extraction-code signature (FLAW-207), the cached artifacts are
    loaded without re-running LibCST extraction.

    Args:
        identity: The target repository.
        config: Fully resolved configuration.
        console: Output console.
        force: Re-extract even if a cached index exists.
    """
    artifact_dir = repo_data_dir(config.data_dir, identity)
    mypy_batch_cache_dir = (
        config.state_dir / "mypy_batch" / repo_cache_name(identity)
        if config.type_enrichment.enable_mypy_batch
        else None
    )
    console.status(f"Target: {identity.path}")
    console.status(f"Cache:  {artifact_dir}")

    content_hash = repo_content_hash(identity.path, config.cache_invalidation)
    te_sig = type_enrichment_signature(
        enable_mypy_batch=config.type_enrichment.enable_mypy_batch,
        basedpyright_max_queries=config.type_enrichment.basedpyright_max_queries,
        basedpyright_max_probe_files=config.type_enrichment.basedpyright_max_probe_files,
        basedpyright_max_source_files=config.type_enrichment.basedpyright_max_source_files,
        basedpyright_max_workspace_bytes=config.type_enrichment.basedpyright_max_workspace_bytes,
    )
    extraction_sig = code_signature(_L1_EXTRACTION_SIGNATURE_PATTERNS)
    cache_status = "miss"
    # Derive the rebuild reason from the *existing* cache_key.json before any
    # re-extraction overwrites it (read-only; observation-only so a profiler-less
    # path pays nothing).
    rebuild_reason = (
        _l1_invalidation_reason(
            artifact_dir, content_hash=content_hash, type_enrichment_sig=te_sig
        )
        if observation is not None
        else "cache_key_match"
    )
    phase_recorder = _index_phase_recorder(profiler, observation)
    if profile_phase is not None:
        profile_phase.set("artifact_dir", str(artifact_dir))
        profile_phase.set("content_hash", content_hash)

    # -- Cache hit path ------------------------------------------------
    if not force and cache_key_matches(
        artifact_dir,
        content_hash=content_hash,
        type_enrichment_signature=te_sig,
        extraction_code_signature=extraction_sig,
    ):
        cache_status = "hit"
        console.success("Cache hit — reusing cached L1 artifacts")
        try:
            index = load_index_from_artifacts(
                identity.path,
                artifact_dir,
                progress=lambda message: console.verbose(message, level=1),
            )
        except CorruptCacheError as exc:
            cache_status = "corrupt_reextract"
            console.warn(f"Corrupt cache artifacts ({exc}), re-extracting")
        else:
            console.success(
                "L1 loaded from cache: "
                f"{len(index.functions)} functions, "
                f"{len(index.classes)} classes, "
                f"{len(index.decorators)} decorators, "
                f"{len(index.symbols)} symbols",
            )
            if profiler is not None:
                profiler.record_l1_index(
                    index,
                    artifact_dir=artifact_dir,
                    content_hash=content_hash,
                    cache_status=cache_status,
                    phase=profile_phase,
                )
            if observation is not None:
                observation.l1_cache_status = "hit"
                observation.l1_invalidation_reason = None
            return index

    # -- Incremental path (cache miss but file manifest exists) ----------
    if not force:
        result = _try_incremental(
            identity=identity,
            artifact_dir=artifact_dir,
            content_hash=content_hash,
            type_enrichment_sig=te_sig,
            extraction_code_sig=extraction_sig,
            config=config,
            mypy_batch_cache_dir=mypy_batch_cache_dir,
            console=console,
            profiler=profiler,
            profile_phase=profile_phase,
            phase_recorder=phase_recorder,
        )
        if result is not None:
            if observation is not None:
                observation.l1_cache_status = "incremental"
                observation.l1_invalidation_reason = rebuild_reason
            return result

    # -- Cache miss path (full extraction) --------------------------------
    if force:
        cache_status = "forced"
        console.status("Force re-extraction requested")

    if artifact_dir.exists():
        console.status("Clearing previous cache contents")
        shutil.rmtree(artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    console.status("Running Layer 1 structural extraction")
    with console.phase("L1 extraction"):
        index = build_index(
            identity.path,
            artifact_root=artifact_dir,
            enable_mypy_batch=config.type_enrichment.enable_mypy_batch,
            basedpyright_max_queries=config.type_enrichment.basedpyright_max_queries,
            basedpyright_max_probe_files=config.type_enrichment.basedpyright_max_probe_files,
            basedpyright_max_source_files=config.type_enrichment.basedpyright_max_source_files,
            basedpyright_max_workspace_bytes=(
                config.type_enrichment.basedpyright_max_workspace_bytes
            ),
            basedpyright_timeout_seconds=config.type_enrichment.basedpyright_timeout_seconds,
            mypy_batch_timeout_seconds=config.type_enrichment.mypy_batch_timeout_seconds,
            mypy_batch_max_files=config.type_enrichment.mypy_batch_max_files,
            mypy_batch_cache_dir=mypy_batch_cache_dir,
            extraction_code_signature=extraction_sig,
            progress=lambda message: console.verbose(message, level=1),
            phase_recorder=phase_recorder,
        )

    # Only genuinely repo-wide failures abort the scan. A single unparsable
    # file is `is_fatal` (per-file) but NOT `aborts_pipeline` — it is gapped and
    # recorded, and the rest of the repo is still analyzed (FLAW-264). Using
    # `is_fatal` here would let one bad file silently yield zero findings for an
    # entire repo — a false negative, the #1 enemy.
    fatal_errors = [error for error in index.errors if error.aborts_pipeline]
    if fatal_errors:
        first = fatal_errors[0]
        raise PipelineError(f"Layer 1 extraction failed: {first.message}") from None

    # Write cache key after successful extraction
    write_cache_key(
        artifact_dir,
        content_hash=content_hash,
        type_enrichment_signature=te_sig,
        extraction_code_signature=extraction_sig,
    )

    console.success(
        "L1 complete: "
        f"{len(index.functions)} functions, "
        f"{len(index.classes)} classes, "
        f"{len(index.decorators)} decorators, "
        f"{len(index.symbols)} symbols",
    )
    console.verbose(f"Artifacts written to {artifact_dir}", level=1)
    if len(index.errors) > 0:
        _warn_extraction_gaps(console, index)
    if profiler is not None:
        profiler.record_l1_index(
            index,
            artifact_dir=artifact_dir,
            content_hash=content_hash,
            cache_status=cache_status,
            phase=profile_phase,
        )
    if observation is not None:
        observation.l1_cache_status = cache_status
        observation.l1_invalidation_reason = (
            "forced_reextraction"
            if cache_status == "forced"
            else "corrupt_cache"
            if cache_status == "corrupt_reextract"
            else rebuild_reason
        )
    return index


def _try_incremental(
    *,
    identity: RepoIdentity,
    artifact_dir: Path,
    content_hash: str,
    type_enrichment_sig: str,
    extraction_code_sig: str,
    config: ResolvedConfig,
    mypy_batch_cache_dir: Path | None,
    console: Console,
    profiler: ScanProfiler | None,
    profile_phase: ProfilePhase | None,
    phase_recorder: Callable[[IndexBuildPhase], None] | None = None,
) -> CodeIndex | None:
    """Attempt incremental L1 rebuild.  Returns ``None`` on failure or inapplicability.

    The type-enrichment kwargs MUST mirror the values passed to
    :func:`build_index` on the full path (above), otherwise an incremental
    rebuild re-probes changed files under default enrichment settings and
    diverges from a full build under non-default configuration (FLAW-120 /
    follow-on to FLAW-083).
    """
    manifest_files = read_file_manifest(
        artifact_dir, extraction_code_signature=extraction_code_sig
    )
    if manifest_files is None:
        return None

    python_files = discover_python_files(identity.path)
    file_changes = detect_changed_files(manifest_files, identity.path, python_files)
    total_affected = (
        len(file_changes.changed) + len(file_changes.added) + len(file_changes.removed)
    )
    if total_affected == 0 or total_affected > len(python_files) // 2:
        return None

    console.status(
        f"Incremental rebuild: {len(file_changes.changed)} changed, "
        f"{len(file_changes.added)} added, {len(file_changes.removed)} removed"
    )
    try:
        with console.phase("L1 incremental"):
            index = incremental_build(
                identity.path,
                artifact_dir,
                file_changes,
                python_files,
                enable_mypy_batch=config.type_enrichment.enable_mypy_batch,
                basedpyright_max_queries=config.type_enrichment.basedpyright_max_queries,
                basedpyright_max_probe_files=config.type_enrichment.basedpyright_max_probe_files,
                basedpyright_max_source_files=config.type_enrichment.basedpyright_max_source_files,
                basedpyright_max_workspace_bytes=(
                    config.type_enrichment.basedpyright_max_workspace_bytes
                ),
                basedpyright_timeout_seconds=config.type_enrichment.basedpyright_timeout_seconds,
                mypy_batch_timeout_seconds=config.type_enrichment.mypy_batch_timeout_seconds,
                mypy_batch_max_files=config.type_enrichment.mypy_batch_max_files,
                mypy_batch_cache_dir=mypy_batch_cache_dir,
                extraction_code_signature=extraction_code_sig,
                progress=lambda message: console.verbose(message, level=1),
                phase_recorder=phase_recorder,
            )
    except (CorruptCacheError, OSError, KeyError, ValueError) as exc:
        console.warn(f"Incremental build failed ({exc}), falling back to full")
        return None

    write_cache_key(
        artifact_dir,
        content_hash=content_hash,
        type_enrichment_signature=type_enrichment_sig,
        extraction_code_signature=extraction_code_sig,
    )
    console.success(
        "L1 incremental: "
        f"{len(index.functions)} functions, "
        f"{len(index.classes)} classes, "
        f"{len(index.decorators)} decorators, "
        f"{len(index.symbols)} symbols",
    )
    if len(index.errors) > 0:
        _warn_extraction_gaps(console, index)
    if profiler is not None:
        profiler.record_l1_index(
            index,
            artifact_dir=artifact_dir,
            content_hash=content_hash,
            cache_status="incremental",
            phase=profile_phase,
        )
    return index


def run_semantic(
    *,
    index: CodeIndex,
    config: ResolvedConfig,
    console: Console,
    profiler: ScanProfiler | None = None,
    provider_cache: ProviderEngineCache | None = None,
    observation: _ScanObservation | None = None,
) -> SemanticResult:
    """Run Layer 2 semantic analysis on a completed L1 index.

    Returns:
        RepoView and active provider IDs.
    """
    from flawed._semantic import WebApp
    from flawed._semantic._budget import (
        ConstructionBudget,
        construction_budget,
        current_trajectory,
    )
    from flawed._semantic._provider_engine import ProviderEngine

    console.status("Running Layer 2 semantic analysis")

    engine = ProviderEngine()
    # FLAW-345: bound L2 construction memory. A runaway value-flow graph would
    # otherwise grow until the OS SIGKILLs the process — leaving no result
    # document at all, which a batch harness misreads as a clean zero. Under this
    # budget the hot construction loops fail CLOSED (ValueFlowBudgetError, caught
    # in run_scan -> metrics.incomplete) the same way the layer timeout does.
    with construction_budget(ConstructionBudget.resolved()):
        with console.phase("L2 provider engine"):  # noqa: SIM117
            with (
                profiler.phase("l2_provider_engine") if profiler is not None else nullcontext(None)
            ) as provider_phase:
                engine_result = run_provider_engine(
                    engine, index, config=config, cache=provider_cache, observation=observation
                )
                if provider_phase is not None:
                    provider_phase.set("match_count", len(engine_result.matches))
                    provider_phase.set("gap_count", len(engine_result.gaps))
                    provider_phase.set("active_providers", list(engine_result.active_provider_ids))
        active_ids = engine_result.active_provider_ids

        if active_ids:
            console.success(f"Active providers: {', '.join(active_ids)}")
        else:
            console.warn("No providers activated for this repository.")

        console.status("Building semantic model")
        with console.phase("L2 semantic conversion"):  # noqa: SIM117
            with (
                profiler.phase("l2_conversion") if profiler is not None else nullcontext(None)
            ) as conversion_phase:
                webapp = WebApp.from_index(index, provider_engine_result=engine_result)
                view = webapp.repo_view()
                if conversion_phase is not None:
                    conversion_phase.set("route_count", len(view.routes))
                    conversion_phase.set("gap_count", len(view.gaps))

        # Capture the intra-L2 RSS trajectory while the budget context is still
        # active — it resets on block exit (FLAW-355).
        if observation is not None:
            observation.memory_trajectory = current_trajectory()

    route_count = len(view.routes)
    gap_count = len(view.gaps)

    console.show_semantic_summary(
        active_providers=active_ids,
        route_count=route_count,
        gap_count=gap_count,
    )

    return SemanticResult(
        repo_view=view,
        active_provider_ids=active_ids,
        provider_engine_result=engine_result,
    )


def run_scan(  # noqa: PLR0912, PLR0915
    *,
    identity: RepoIdentity,
    config: ResolvedConfig,
    console: Console,
    skip_index: bool = False,
    force_index: bool = False,
    semantic: bool = False,
    profiler: ScanProfiler | None = None,
    show_summary: bool = False,
    metrics: ScanMetrics | None = None,
    deduplicate: bool = True,
    baseline_path: Path | None = None,
    write_baseline_path: Path | None = None,
    ignore_spec: IgnoreSpec | None = None,
    baseline_commit_keys: frozenset[str] | None = None,
    strict: bool = False,
    fail_on: Severity = DEFAULT_SEVERITY,
    min_severity: Severity | None = None,
    error: bool = True,
    use_cache: bool = True,
    refresh_cache: bool = False,
) -> int:
    """Run the full analysis pipeline.

    Returns one of the ``EXIT_*`` codes (FLAW-147):

    * ``EXIT_OK`` (0) — completed; no retained finding at/above ``fail_on``.
    * ``EXIT_FINDINGS`` (1) — completed; a finding at/above ``fail_on`` exists.
    * ``EXIT_TIMEOUT`` (124) — a layer timed out; the result is incomplete and
      must not be read as "clean" by CI.

    ``fail_on`` governs the exit code independently of what is *displayed*:
    ``min_severity`` filters only the human findings list (machine ``--json`` /
    ``--sarif`` stay complete so code-scanning uploads never silently drop
    findings — the trivy footgun). ``error=False`` (``--no-error``) forces
    ``EXIT_OK`` for report-only CI.
    """
    if metrics is None:
        metrics = ScanMetrics()
    metrics.target = identity.display_name

    try:
        from flawed import __version__

        metrics.flawed_version = __version__
    except Exception:
        metrics.flawed_version = "unknown"

    # Always-on observability (FLAW-355): collected through the scan, then written
    # durably (per-repo sidecar + central run-log) at the end.
    observation = _ScanObservation()
    scan_started_at = utc_now_iso()
    results_cache_full_hit = False

    timeouts = config.timeouts

    # Resolve and filter detection rules up front. Rule discovery + include/
    # exclude matching is pure config work with no dependency on the L1 index or
    # the L2 model, so resolving here lets an empty or over-filtered rule set
    # fail in ~1s instead of after minutes of L1/L2 work that would find nothing.
    # Detector EXECUTION still happens at L3 (_run_l3_rules); only resolution and
    # the emptiness check move earlier.
    resolved_rule_files: tuple[RuleEntry, ...] | None = None
    resolved_detectors: tuple[RuleDetector, ...] | None = None
    if semantic and not skip_index:
        resolved_rule_files = discover_rule_files(config)
        try:
            resolved_detectors = load_configured_detectors(config, resolved_rule_files)
        except RuleExecutionError as exc:
            raise PipelineError(str(exc)) from exc
        metrics.rules_loaded = len(resolved_rule_files)
        if not resolved_detectors:
            console.warn("No detection rules matched the configured rule paths and filters.")
            console.show_scan_metrics(metrics)
            return 0

    # Phase 1: Layer 1 index
    index: CodeIndex | None = None
    # A layer timeout aborts the *remaining* analysis but must NOT skip the
    # output-emission block below: an incomplete scan still emits its machine
    # document (carrying `incomplete: true`) so a --json/--sarif consumer can
    # tell "incomplete" from "clean, 0 findings". Returning early here produced
    # 0-byte JSON — a fail-open masking findings. L3 already falls through; this
    # makes L1/L2 consistent with it.
    analysis_aborted = False
    if not skip_index:
        try:
            with (
                record_scan_phase(metrics, "L1 extraction"),
                (
                    profiler.phase("l1_index") if profiler is not None else nullcontext(None)
                ) as profile_phase,
                layer_timeout("L1", timeouts.per_layer),
            ):
                index = run_index(
                    identity=identity,
                    config=config,
                    console=console,
                    force=force_index,
                    profile_phase=profile_phase,
                    profiler=profiler,
                    observation=observation,
                )
        except LayerTimeoutError as exc:
            console.error(f"TIMEOUT: {exc}")
            metrics.incomplete = True
            metrics.timed_out_layers.append("L1")
            analysis_aborted = True
    else:
        console.warn("Skipping Layer 1 extraction (--no-index)")
        if profiler is not None:
            profiler.record_skipped_phase("l1_index", reason="--no-index")

    if index is not None:
        # Record the L1 extraction-error count so --json/--summary surface it:
        # gapped files are missed-finding sites and must stay visible.
        metrics.index_error_count = len(index.errors)

    # Phase 2: Layer 2 semantic analysis (opt-in)
    findings: tuple[RuleFinding, ...] = ()
    if semantic and not analysis_aborted:
        if index is None:
            raise PipelineError(
                "--semantic requires Layer 1 index (cannot combine with --no-index)"
            )

        # Results cache (FLAW-137): persist per-detector findings so an
        # unchanged re-run (same engine, rules, target) skips re-execution.
        # --no-cache disables it entirely; --refresh recomputes then repopulates.
        result_cache = None
        provider_cache = None
        if use_cache:
            from flawed._cli.provider_engine_cache import ProviderEngineCache
            from flawed._cli.result_cache import ResultCache

            result_cache = ResultCache.create(
                config=config,
                identity=identity,
                read_enabled=not refresh_cache,
                write_enabled=True,
            )
            # FLAW-189: cache the ~167s provider-engine build across scans. Keyed
            # on the same L1 content hash plus an analysis-source signature, so a
            # providers/_semantic edit (which _PIPELINE_VERSION does not track)
            # never serves a stale result.
            provider_cache = ProviderEngineCache.create(
                cache_dir=repo_data_dir(config.data_dir, identity),
                config=config,
                content_hash=repo_content_hash(identity.path, config.cache_invalidation),
                read_enabled=not refresh_cache,
                write_enabled=True,
            )

        # Fast path: if EVERY selected detector is already cached for this key,
        # assemble findings straight from cache and skip L2 *and* L3 — the
        # "unchanged re-run is ~free" win. L2 still runs whenever any detector
        # is a miss (the missing detectors need the RepoView). Disabled under
        # --profile, whose whole purpose is to measure real layer timings.
        cached_all = (
            _full_results_cache_hit(result_cache, resolved_detectors, metrics=metrics)
            if profiler is None
            else None
        )
        if cached_all is not None:
            findings = cached_all
            results_cache_full_hit = True
            observation.results_cache = "hit"
            n = len(resolved_detectors) if resolved_detectors else 0
            console.success(
                f"Results cache: {n}/{n} detector(s) served from cache — skipping L2/L3"
            )
        else:
            # FLAW-345: a memory-budget breach during L2 construction is caught
            # here, beside the timeout, and converted to the same honest
            # incomplete:true — never an uncatchable OOM kill / silent zero.
            from flawed._semantic._budget import ValueFlowBudgetError

            try:
                with (
                    record_scan_phase(metrics, "L2 semantic"),
                    layer_timeout("L2", timeouts.per_layer),
                ):
                    semantic_result = run_semantic(
                        index=index,
                        config=config,
                        console=console,
                        profiler=profiler,
                        provider_cache=provider_cache,
                        observation=observation,
                    )
            except LayerTimeoutError as exc:
                console.error(f"TIMEOUT: {exc}")
                metrics.incomplete = True
                metrics.timed_out_layers.append("L2")
                analysis_aborted = True
            except ValueFlowBudgetError as exc:
                console.error(f"MEMORY: {exc}")
                metrics.incomplete = True
                metrics.budget_capped_layers.append("L2")
                analysis_aborted = True

            if not analysis_aborted:
                if profiler is not None:
                    profiler.record_semantic_result(
                        repo_view=semantic_result.repo_view,
                        active_provider_ids=semantic_result.active_provider_ids,
                        provider_result=semantic_result.provider_engine_result,
                    )

                try:
                    profile_timer = (
                        profiler.phase("l3_rules") if profiler is not None else nullcontext(None)
                    )
                    with (
                        record_scan_phase(metrics, "L3 rule execution"),
                        console.phase("L3 rule execution"),
                        layer_timeout("L3", timeouts.per_layer),
                        profile_timer as profile_phase,
                    ):
                        findings = _run_l3_rules(
                            semantic_result.repo_view,
                            config=config,
                            console=console,
                            profile_phase=profile_phase,
                            profiler=profiler,
                            rule_timeout_seconds=timeouts.per_rule,
                            metrics=metrics,
                            rule_files=resolved_rule_files,
                            detectors=resolved_detectors,
                            result_cache=result_cache,
                            observation=observation,
                        )
                except LayerTimeoutError as exc:
                    console.error(f"TIMEOUT: {exc}")
                    metrics.incomplete = True
                    metrics.timed_out_layers.append("L3")
    elif not semantic:
        console.status("L2 semantic analysis skipped (use --semantic to enable)")
        if profiler is not None:
            profiler.record_skipped_phase("l2_provider_engine", reason="--semantic not enabled")
            profiler.record_skipped_phase("l2_conversion", reason="--semantic not enabled")
            profiler.record_skipped_phase("l3_rules", reason="--semantic not enabled")
    # else: semantic requested but L1 timed out (analysis_aborted) — fall through
    # to emit the incomplete machine document; there is nothing left to analyze.

    # -- Post-processing: dedup and suppression -----------------------------
    raw_count = len(findings)
    if deduplicate and findings:
        findings = deduplicate_findings(findings)
        dedup_removed = raw_count - len(findings)
        if dedup_removed > 0:
            console.verbose(f"Deduplicated: removed {dedup_removed} duplicate finding(s)", level=1)

    if baseline_path is not None and findings:
        suppressed = load_baseline(baseline_path)
        if suppressed:
            before = len(findings)
            findings = suppress_findings(findings, suppressed)
            suppressed_count = before - len(findings)
            if suppressed_count > 0:
                console.status(f"Suppressed {suppressed_count} baselined finding(s)")

    if write_baseline_path is not None and findings:
        write_baseline(write_baseline_path, findings)
        console.status(f"Baseline written: {write_baseline_path}")

    # Surfaced suppression (FLAW-148/149/150): inline `# flawed: ignore`
    # directives, `.flawedignore`, and `--baseline-commit`. Suppressed findings
    # leave the active set (and the headline count / exit code) but are kept as
    # records so --json/--sarif still emit them flagged — never a silent drop.
    # Inline directives are always honoured, so this runs whenever findings
    # exist (not only when a suppression flag was passed).
    suppressed_records: tuple[SuppressionRecord, ...] = ()
    if findings:
        outcome = compute_suppressions(
            findings,
            root=identity.path,
            ignore_spec=ignore_spec,
            baseline_commit_keys=baseline_commit_keys,
            strict=strict,
            warn=console.warn,
        )
        findings = outcome.active
        suppressed_records = outcome.suppressed
        if suppressed_records:
            console.status(
                f"Suppressed {len(suppressed_records)} finding(s) "
                f"({outcome.counts_by_source}) — still in --json/--sarif"
            )

    metrics.retained_finding_count = len(findings)
    # Single source of truth (FLAW-142): the real finding count is the
    # post-dedup/post-suppression total. The pre-dedup raw count (logged
    # above) is a diagnostic, not the headline number, so finding_count must
    # equal len(findings) whenever output was not truncated. Only a genuine
    # output-truncation (the MAX_RETAINED cap) keeps finding_count above the
    # number of emitted findings, with findings_truncated flagging the gap.
    if not metrics.findings_truncated:
        metrics.finding_count = len(findings)

    # --min-severity filters only the HUMAN findings list; machine formats
    # (--json/--sarif) stay complete so code-scanning uploads never silently
    # drop findings (the trivy footgun). See FLAW-146/147.
    display_findings = findings
    if min_severity is not None and not (console.json_mode or console.sarif_mode):
        display_findings = tuple(f for f in findings if _finding_sev(f) >= min_severity)

    if semantic:
        console.show_findings(display_findings, metrics=metrics, suppressed=suppressed_records)
    rules_with_findings = len({f.rule_id for f in findings}) if findings else 0
    console.finding_count(metrics.finding_count, rule_count=rules_with_findings)
    console.show_scan_metrics(metrics)
    if show_summary:
        console.show_scan_summary(findings)

    # Exit-code contract (FLAW-147): decouple "found things" from "fail build".
    exit_code = scan_exit_code(
        findings, fail_on=fail_on, error=error, incomplete=metrics.incomplete
    )

    # Always-on durable observability (FLAW-355): record the scan unless disabled.
    if config.observability_enabled:
        record = _assemble_scan_record(
            metrics=metrics,
            observation=observation,
            artifact_dir=None if skip_index else repo_data_dir(config.data_dir, identity),
            started_at=scan_started_at,
            ended_at=utc_now_iso(),
            exit_code=exit_code,
            results_cache_full_hit=results_cache_full_hit,
        )
        _write_scan_record(config=config, identity=identity, record=record, console=console)

    return exit_code


def _full_results_cache_hit(
    result_cache: ResultCache | None,
    detectors: tuple[RuleDetector, ...] | None,
    *,
    metrics: ScanMetrics | None,
) -> tuple[RuleFinding, ...] | None:
    """Assemble findings from cache iff EVERY detector is a hit (FLAW-137).

    Returns ``None`` — meaning the caller must run L2 + L3 — when caching is
    off, reads are disabled (``--refresh``), there are no detectors, or any
    single detector is a miss.  Assembly order matches ``_run_l3_rules`` so the
    retention cap truncates identically to a fresh run.
    """
    if result_cache is None or not result_cache.read_enabled or not detectors:
        return None
    per_detector: list[tuple[RuleFinding, ...]] = []
    for detector in detectors:
        cached = result_cache.get(detector)
        if cached is None:
            return None
        per_detector.append(cached)

    all_findings: list[RuleFinding] = []
    total = 0
    truncated = False
    for items in per_detector:
        for finding in items:
            total += 1
            if len(all_findings) < MAX_RETAINED_L3_FINDINGS:
                all_findings.append(finding)
            else:
                truncated = True

    if metrics is not None:
        metrics.rules_executed = 0
        metrics.rules_skipped = 0
        metrics.finding_count = total
        metrics.retained_finding_count = len(all_findings)
        metrics.findings_truncated = truncated
    return tuple(all_findings)


def _run_l3_rules(  # noqa: PLR0912, PLR0915
    repo_view: RepoView,
    *,
    config: ResolvedConfig,
    console: Console,
    profile_phase: ProfilePhase | None = None,
    profiler: ScanProfiler | None = None,
    rule_timeout_seconds: int | None = None,
    metrics: ScanMetrics | None = None,
    rule_files: tuple[RuleEntry, ...] | None = None,
    detectors: tuple[RuleDetector, ...] | None = None,
    result_cache: ResultCache | None = None,
    observation: _ScanObservation | None = None,
) -> tuple[RuleFinding, ...]:
    # Rules may have been resolved up front (run_scan hoists resolution so an
    # empty rule set fails fast). Fall back to resolving here for callers that
    # do not pre-resolve (e.g. direct unit-test invocation).
    if rule_files is None:
        rule_files = discover_rule_files(config)
    try:
        if detectors is None:
            detectors = load_configured_detectors(config, rule_files)
        console.status(
            f"Running Layer 3 rules: {len(detectors)} detector(s) from {len(rule_files)} file(s)"
        )
        if metrics is not None:
            metrics.rules_loaded = len(rule_files)

        all_findings: list[RuleFinding] = []
        rule_profiles: list[RuleProfile] = []
        executed = 0
        skipped = 0
        cache_hits = 0
        total_finding_count = 0
        retained_finding_count = 0
        truncated = False

        def _assemble(items: tuple[RuleFinding, ...]) -> None:
            """Append a detector's findings, honouring the global retention cap.

            Order is detector-stable, so the cap truncates identically whether a
            detector's results were freshly run or served from cache (FLAW-137).
            """
            nonlocal total_finding_count, retained_finding_count, truncated
            for finding in items:
                total_finding_count += 1
                if len(all_findings) < MAX_RETAINED_L3_FINDINGS:
                    all_findings.append(finding)
                    retained_finding_count += 1
                else:
                    truncated = True

        for detector in detectors:
            # Results-cache hit (FLAW-137): replay persisted findings without
            # re-executing the detector. An empty tuple is a genuine hit (the
            # detector ran before and found nothing); None means recompute.
            cached = result_cache.get(detector) if result_cache is not None else None
            if cached is not None:
                cache_hits += 1
                _assemble(cached)
                rule_profiles.append(
                    RuleProfile(
                        rule_id=detector.rule_id,
                        wall_ms=0.0,
                        finding_count=len(cached),
                        finding_gap_count=sum(len(f.finding.gaps) for f in cached),
                        # A results-cache hit replays persisted findings without
                        # re-executing the detector, so it incurs no flow work.
                        flow_query_count=0,
                        bfs_count=0,
                    )
                )
                continue
            try:
                with rule_timeout(detector.rule_id, rule_timeout_seconds):
                    import time as _time

                    q0, b0 = flow_query_stats_of(repo_view)
                    start = _time.monotonic()
                    # Materialise fully before persisting/assembling so a
                    # mid-iteration timeout discards the detector's partial
                    # output (an incomplete detector caches nothing).
                    detector_findings = tuple(iter_detector_findings(repo_view, detector))
                    elapsed = _time.monotonic() - start
                    q1, b1 = flow_query_stats_of(repo_view)
                    if result_cache is not None:
                        result_cache.put(detector, detector_findings)
                    executed += 1
                    _assemble(detector_findings)
                    rule_profiles.append(
                        RuleProfile(
                            rule_id=detector.rule_id,
                            wall_ms=elapsed * 1000,
                            finding_count=len(detector_findings),
                            finding_gap_count=sum(len(f.finding.gaps) for f in detector_findings),
                            flow_query_count=q1 - q0,
                            bfs_count=b1 - b0,
                        )
                    )
                    _log.info(
                        "[L3:rule:%s] %d findings in %.1fs (flow q=%d bfs=%d)",
                        detector.rule_id,
                        len(detector_findings),
                        elapsed,
                        q1 - q0,
                        b1 - b0,
                    )
                    # FLAW-194: warn when a rule consumes most of its time budget,
                    # so an operator sees the rule approaching a timeout before it
                    # actually trips (and silently drops findings).
                    if (
                        rule_timeout_seconds
                        and elapsed >= _NEAR_TIMEOUT_FRACTION * rule_timeout_seconds
                    ):
                        console.warn(
                            f"{detector.rule_id} used {elapsed:.0f}s of the "
                            f"{rule_timeout_seconds}s rule budget "
                            f"({b1 - b0} BFS traversals from {q1 - q0} flow queries)"
                        )
            except RuleTimeoutError as exc:
                console.warn(f"TIMEOUT: {exc}")
                skipped += 1
                if metrics is not None:
                    metrics.timed_out_rules.append(detector.rule_id)
                    metrics.incomplete = True
            except RuleExecutionError as exc:
                console.warn(f"Rule error: {exc}")
                skipped += 1

        findings = tuple(all_findings)
        if metrics is not None:
            metrics.rules_executed = executed
            metrics.rules_skipped = skipped
            metrics.finding_count = total_finding_count
            metrics.retained_finding_count = retained_finding_count
            metrics.findings_truncated = truncated
        if result_cache is not None and cache_hits:
            console.success(
                f"Results cache: {cache_hits}/{len(detectors)} detector(s) served from cache"
            )
        if observation is not None:
            observation.rule_timings = list(rule_profiles)
            if result_cache is None or not result_cache.read_enabled:
                observation.results_cache = "disabled"
            elif cache_hits == 0:
                observation.results_cache = "miss"
            elif cache_hits == len(detectors):
                observation.results_cache = "hit"
            else:
                observation.results_cache = "partial"
    except RuleExecutionError as exc:
        raise PipelineError(str(exc)) from exc

    if not detectors:
        console.warn("No detection rules matched the configured rule paths and filters.")

    if profiler is not None:
        profiler.record_l3_result(
            rule_files=len(rule_files),
            detectors=len(detectors),
            findings=findings,
            actual_finding_count=metrics.finding_count if metrics is not None else len(findings),
            retained_finding_count=len(findings),
            findings_truncated=metrics.findings_truncated if metrics is not None else False,
            rule_profiles=tuple(rule_profiles),
            phase=profile_phase,
        )
    return findings


def _run_single_detector(
    repo: RepoView,
    detector: object,
) -> tuple[RuleFinding, ...]:
    """Run one detector, returning its findings."""
    from flawed._cli.rules import iter_detector_findings

    return tuple(iter_detector_findings(repo, detector))  # type: ignore[arg-type]


def run_provider_engine(
    engine: ProviderEngine,
    index: CodeIndex,
    *,
    config: ResolvedConfig,
    cache: ProviderEngineCache | None = None,
    observation: _ScanObservation | None = None,
) -> ProviderEngineResult:
    """Run the Layer 2 provider engine, reusing a cached result when available.

    The engine build is the largest fixed cost of a scan (~167s on large repos)
    and is otherwise recomputed every run (only L1 is cached). When *cache* is
    provided, a keyed hit short-circuits the build; otherwise the result is
    computed and stored (FLAW-189). A cache miss/corruption never fails the
    scan — it recomputes (see :mod:`flawed._cli.provider_engine_cache`).
    """
    if cache is not None:
        cached = cache.load()
        if cached is not None:
            if observation is not None:
                observation.l2_cache = "hit"
            return cached
    if observation is not None:
        # ``cache is None`` ⇒ caching disabled (--no-cache); record it distinctly
        # from a genuine keyed miss so the sweep can tell the two apart.
        observation.l2_cache = "miss" if cache is not None else "disabled"
    result = _run_provider_engine_uncached(engine, index, config=config)
    if cache is not None:
        cache.store(result)
    return result


def _run_provider_engine_uncached(
    engine: ProviderEngine,
    index: CodeIndex,
    *,
    config: ResolvedConfig,
) -> ProviderEngineResult:
    result = engine.run(index)

    entries = config.providers.entries
    if not entries:
        return result

    disabled = {provider_id for provider_id, entry in entries.items() if entry.enable is False}
    forced = {provider_id for provider_id, entry in entries.items() if entry.enable is not False}
    active = set(result.active_provider_ids)
    selected = (active - disabled) | forced
    if selected == active:
        return result
    return engine.run(index, provider_ids=tuple(sorted(selected)))
