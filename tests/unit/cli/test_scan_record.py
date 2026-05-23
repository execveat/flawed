"""ScanRecord contract + durable sidecar/central writers (FLAW-355)."""

from __future__ import annotations

import json
import threading
from typing import TYPE_CHECKING

from flawed._cli.scan_record import (
    CENTRAL_LOG_FILENAME,
    SCAN_RECORD_SCHEMA_VERSION,
    SIDECAR_FILENAME,
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

if TYPE_CHECKING:
    from pathlib import Path


def _record(repo: str = "acme/app") -> ScanRecord:
    return ScanRecord(
        schema_version=SCAN_RECORD_SCHEMA_VERSION,
        started_at=utc_now_iso(),
        ended_at=utc_now_iso(),
        repo=repo,
        flawed_version="0.7.1",
        l1_schema_version="1",
        exit_code=0,
        phases=(
            PhaseTiming(
                name="L1 extraction",
                wall_ms=12.5,
                rss_start_bytes=1,
                rss_end_bytes=2,
                rss_source="proc_status_vmrss",
            ),
        ),
        l1_sub_phases=(SubPhaseTiming(name="parse", wall_ms=3.0),),
        cache=CacheInfo(l1_cache_status="miss", invalidation_reason="repo_content_changed"),
        artifacts={"total_bytes": 10},
        rule_timings=(RuleTiming(rule_id="demo-rule", wall_ms=1.0, finding_count=2),),
        memory_trajectory=(
            MemorySample(elapsed_ms=0.0, rss_bytes=100, source="proc_status_vmrss"),
        ),
    )


def test_to_jsonable_round_trips() -> None:
    payload = json.loads(json.dumps(_record().to_jsonable(), sort_keys=True))
    assert payload["schema_version"] == "1"
    assert payload["repo"] == "acme/app"
    assert payload["cache"]["invalidation_reason"] == "repo_content_changed"
    assert payload["phases"][0]["rss_end_bytes"] == 2
    assert payload["l1_sub_phases"][0]["name"] == "parse"
    assert payload["rule_timings"][0]["rule_id"] == "demo-rule"
    assert payload["memory_trajectory"][0]["rss_bytes"] == 100


def test_utc_now_iso_has_date_and_milliseconds() -> None:
    ts = utc_now_iso()
    assert "T" in ts  # full ISO timestamp, not time-only
    assert "." in ts  # millisecond fraction present
    assert ts.endswith("+00:00")  # explicit UTC offset


def test_default_central_log_path(tmp_path: Path) -> None:
    assert default_central_log_path(tmp_path) == tmp_path / CENTRAL_LOG_FILENAME


def test_write_sidecar_appends_one_line_per_scan(tmp_path: Path) -> None:
    cache_dir = tmp_path / "repo-cache"
    write_sidecar(cache_dir, _record())
    write_sidecar(cache_dir, _record(repo="acme/other"))
    lines = (cache_dir / SIDECAR_FILENAME).read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["repo"] == "acme/other"


def test_write_central_creates_parents_and_appends(tmp_path: Path) -> None:
    log = tmp_path / "nested" / "runs.jsonl"
    write_central(log, _record())
    assert log.exists()
    assert json.loads(log.read_text(encoding="utf-8").splitlines()[0])["repo"] == "acme/app"


def test_write_central_concurrent_appends_do_not_interleave(tmp_path: Path) -> None:
    log = tmp_path / "runs.jsonl"
    n_threads, per_thread = 8, 25

    def worker() -> None:
        for _ in range(per_thread):
            write_central(log, _record())

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == n_threads * per_thread
    # The write-only flock guarantees every line is one complete JSON object.
    for line in lines:
        assert json.loads(line)["repo"] == "acme/app"


def test_artifact_size_summary_reports_bytes(tmp_path: Path) -> None:
    (tmp_path / "facts.jsonl").write_text("x" * 50, encoding="utf-8")
    summary = artifact_size_summary(tmp_path)
    assert summary["exists"] is True
    assert isinstance(summary["total_bytes"], int)
    assert summary["total_bytes"] >= 50
