"""True current-RSS sampling and phase entry/exit trajectory (FLAW-355)."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import flawed._cli._observability as obs
from flawed._cli._observability import (
    RSS_SOURCE_PEAK,
    RSS_SOURCE_PROC,
    ScanMetrics,
    _parse_vmrss_bytes,
    record_scan_phase,
    sample_rss_bytes,
)

if TYPE_CHECKING:
    import pytest

_STATUS_TEXT = "Name:\tpython\nVmPeak:\t  500000 kB\nVmRSS:\t  123456 kB\nThreads:\t1\n"


def test_parse_vmrss_bytes_extracts_kb_as_bytes() -> None:
    assert _parse_vmrss_bytes(_STATUS_TEXT) == 123456 * 1024


def test_parse_vmrss_bytes_absent_returns_none() -> None:
    assert _parse_vmrss_bytes("Name:\tpython\nThreads:\t1\n") is None


def test_sample_rss_bytes_returns_positive_and_known_source() -> None:
    rss, source = sample_rss_bytes()
    assert rss > 0
    assert source in {RSS_SOURCE_PROC, RSS_SOURCE_PEAK}


def test_sample_rss_uses_proc_vmrss_on_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(obs, "_read_proc_vmrss_bytes", lambda: 777 * 1024)
    assert sample_rss_bytes() == (777 * 1024, RSS_SOURCE_PROC)


def test_sample_rss_falls_back_to_peak_when_proc_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(obs, "_read_proc_vmrss_bytes", lambda: None)
    rss, source = sample_rss_bytes()
    assert source == RSS_SOURCE_PEAK
    assert rss > 0


def test_record_scan_phase_captures_entry_and_exit_rss() -> None:
    metrics = ScanMetrics()
    with record_scan_phase(metrics, "L1 extraction"):
        pass
    assert len(metrics.phases) == 1
    phase = metrics.phases[0]
    assert phase.rss_start_bytes is not None
    assert phase.rss_start_bytes > 0
    assert phase.rss_end_bytes is not None
    assert phase.rss_end_bytes > 0
    assert phase.rss_source in {RSS_SOURCE_PROC, RSS_SOURCE_PEAK}
    assert phase.completed is True
