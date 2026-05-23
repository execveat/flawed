"""Pipeline-side assembly of the durable scan record (FLAW-355).

Hermetic unit tests for the always-on observability glue in
``flawed._cli.pipeline``: the cache-invalidation reason derivation, the
``ScanRecord`` assembly (including the warm-cache synthetic phases), and the
degrade-don't-fail write guard.  No real scan, no subprocess.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING

from flawed._cli import pipeline
from flawed._cli._observability import PhaseMetrics, ScanMetrics
from flawed._cli.rules import RuleProfile
from flawed._index._pipeline import L1_SCHEMA_VERSION, record_schema_fingerprint

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def _write_cache_key(
    artifact_dir: Path,
    *,
    content_hash: str = "ch",
    te_sig: str = "te",
    schema_version: str = L1_SCHEMA_VERSION,
    fingerprint: str | None = None,
) -> None:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "content_hash": content_hash,
        "l1_schema_version": schema_version,
        "record_schema_fingerprint": fingerprint or record_schema_fingerprint(),
        "type_enrichment_signature": te_sig,
    }
    (artifact_dir / "cache_key.json").write_text(json.dumps(payload), encoding="utf-8")


# ── invalidation reason ──────────────────────────────────────────────


def test_invalidation_reason_no_prior_cache(tmp_path: Path) -> None:
    assert (
        pipeline._l1_invalidation_reason(tmp_path, content_hash="ch", type_enrichment_sig="te")
        == "no_prior_cache"
    )


def test_invalidation_reason_content_changed(tmp_path: Path) -> None:
    _write_cache_key(tmp_path, content_hash="old")
    assert (
        pipeline._l1_invalidation_reason(tmp_path, content_hash="new", type_enrichment_sig="te")
        == "repo_content_changed"
    )


def test_invalidation_reason_schema_bump(tmp_path: Path) -> None:
    _write_cache_key(tmp_path, schema_version="999")
    assert (
        pipeline._l1_invalidation_reason(tmp_path, content_hash="ch", type_enrichment_sig="te")
        == "l1_schema_version_bumped"
    )


def test_invalidation_reason_fingerprint_changed(tmp_path: Path) -> None:
    _write_cache_key(tmp_path, fingerprint="deadbeefdeadbeef")
    assert (
        pipeline._l1_invalidation_reason(tmp_path, content_hash="ch", type_enrichment_sig="te")
        == "record_dataclass_schema_changed"
    )


def test_invalidation_reason_type_enrichment_changed(tmp_path: Path) -> None:
    _write_cache_key(tmp_path, te_sig="old")
    assert (
        pipeline._l1_invalidation_reason(tmp_path, content_hash="ch", type_enrichment_sig="new")
        == "type_enrichment_config_changed"
    )


def test_invalidation_reason_match(tmp_path: Path) -> None:
    _write_cache_key(tmp_path)
    assert (
        pipeline._l1_invalidation_reason(tmp_path, content_hash="ch", type_enrichment_sig="te")
        == "cache_key_match"
    )


# ── record assembly ──────────────────────────────────────────────────


def _metrics_with_phases(*names: str) -> ScanMetrics:
    metrics = ScanMetrics(target="org/repo", flawed_version="0.7.1")
    for name in names:
        metrics.phases.append(
            PhaseMetrics(
                name=name,
                elapsed_seconds=0.5,
                rss_start_bytes=1_000,
                rss_end_bytes=900,  # a DROP — proves frees are representable
                rss_source="proc_status_vmrss",
            )
        )
    return metrics


def test_assemble_maps_phases_and_normalizes_names() -> None:
    metrics = _metrics_with_phases("L1 extraction", "L2 semantic", "L3 rule execution")
    obs = pipeline._ScanObservation(
        l1_cache_status="miss", l1_invalidation_reason="repo_content_changed"
    )
    record = pipeline._assemble_scan_record(
        metrics=metrics,
        observation=obs,
        artifact_dir=None,
        started_at="2026-06-04T00:00:00.000+00:00",
        ended_at="2026-06-04T00:01:00.000+00:00",
        exit_code=1,
        results_cache_full_hit=False,
    )
    assert [p.name for p in record.phases] == ["L1", "L2", "L3"]
    # True current-RSS at entry/exit survives; a drop (frees) is representable.
    l1 = record.phases[0]
    assert l1.rss_start_bytes == 1_000
    assert l1.rss_end_bytes == 900
    assert record.cache.l1_cache_status == "miss"
    assert record.cache.invalidation_reason == "repo_content_changed"
    assert record.l1_schema_version == L1_SCHEMA_VERSION
    assert record.exit_code == 1


def test_assemble_synthesizes_warm_cache_phases() -> None:
    # A full results-cache hit runs only L1; L2/L3 are served from cache and must
    # still appear in the record (the warm-path economics the sweep mines).
    metrics = _metrics_with_phases("L1 extraction")
    obs = pipeline._ScanObservation(l1_cache_status="hit", results_cache="hit")
    record = pipeline._assemble_scan_record(
        metrics=metrics,
        observation=obs,
        artifact_dir=None,
        started_at="s",
        ended_at="e",
        exit_code=0,
        results_cache_full_hit=True,
    )
    by_name = {p.name: p for p in record.phases}
    assert set(by_name) == {"L1", "L2", "L3"}
    assert by_name["L2"].served_from_cache is True
    assert by_name["L3"].served_from_cache is True
    assert by_name["L1"].served_from_cache is False


def test_assemble_carries_rule_timings_and_trajectory() -> None:
    metrics = _metrics_with_phases("L1 extraction")
    obs = pipeline._ScanObservation(
        rule_timings=[
            RuleProfile(rule_id="demo-rule", wall_ms=12.5, finding_count=3, finding_gap_count=0)
        ],
        memory_trajectory=((1.0, 2048, "rusage_maxrss_peak"),),
    )
    record = pipeline._assemble_scan_record(
        metrics=metrics,
        observation=obs,
        artifact_dir=None,
        started_at="s",
        ended_at="e",
        exit_code=0,
        results_cache_full_hit=False,
    )
    assert record.rule_timings[0].rule_id == "demo-rule"
    assert record.rule_timings[0].wall_ms == 12.5
    assert record.memory_trajectory[0].rss_bytes == 2048
    # The whole record is JSON-serializable (one JSONL line).
    json.dumps(record.to_jsonable())


# ── write guard ──────────────────────────────────────────────────────


def test_write_guard_swallows_oserror(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    warnings: list[str] = []
    console = SimpleNamespace(warn=warnings.append)
    config = SimpleNamespace(
        data_dir=tmp_path / "data",
        state_dir=tmp_path / "state",
        observability_log_path=None,
    )
    identity = SimpleNamespace(
        path=tmp_path, display_name="org/repo", canonical="org/repo", hash="abc"
    )

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(pipeline, "write_sidecar", boom)
    record = pipeline._assemble_scan_record(
        metrics=ScanMetrics(target="org/repo"),
        observation=pipeline._ScanObservation(),
        artifact_dir=None,
        started_at="s",
        ended_at="e",
        exit_code=0,
        results_cache_full_hit=False,
    )
    # Must NOT raise — observability is non-load-bearing — but must warn loudly.
    pipeline._write_scan_record(config=config, identity=identity, record=record, console=console)  # type: ignore[arg-type]
    assert warnings and "observability" in warnings[0].lower()
