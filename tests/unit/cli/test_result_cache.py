"""Unit coverage for the per-detector results cache (FLAW-137).

The cache persists raw ``RuleFinding`` tuples per detector, keyed by
``(engine version, pipeline version, target content hash, rule id, rule-file
content hash, provider/analysis config)``.  Every read fails closed: a missing
payload, a key mismatch, a version mismatch, or a corrupt file is treated as a
miss and recomputed — never served stale.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, cast

import pytest

from flawed._cli.result_cache import ResultCache
from flawed._cli.rules import RuleDetector, RuleFinding
from flawed._config.schema import ResolvedConfig
from flawed.evidence import Finding

if TYPE_CHECKING:
    from pathlib import Path


def _detector(rule_id: str, rule_path: Path) -> RuleDetector:
    return RuleDetector(rule_id=rule_id, path=rule_path, function=lambda _repo: ())


def _finding(rule_id: str, rule_path: Path, summary: str) -> RuleFinding:
    return RuleFinding(
        rule_id=rule_id,
        rule_path=rule_path,
        finding=Finding(route_endpoint="endpoint", summary=summary),
    )


def _write_rule(
    tmp_path: Path, name: str, body: str = "def detect(repo):\n    return ()\n"
) -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def _cache(tmp_path: Path, target: Path, **kw: object) -> ResultCache:
    config = dataclasses.replace(ResolvedConfig(), data_dir=tmp_path / "data")
    from flawed._config.paths import RepoIdentity

    identity = RepoIdentity.from_path(target)
    return ResultCache.create(
        config=config,
        identity=identity,
        read_enabled=kw.get("read_enabled", True),  # type: ignore[arg-type]
        write_enabled=kw.get("write_enabled", True),  # type: ignore[arg-type]
    )


@pytest.fixture
def target_dir(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n", encoding="utf-8")
    return target


def test_put_then_get_round_trips_findings(tmp_path: Path, target_dir: Path) -> None:
    rule = _write_rule(tmp_path, "g001_demo.py")
    det = _detector("demo-01", rule)
    cache = _cache(tmp_path, target_dir)
    findings = (_finding("demo-01", rule, "alpha"), _finding("demo-01", rule, "beta"))

    assert cache.get(det) is None  # cold miss
    cache.put(det, findings)
    restored = cache.get(det)

    assert restored is not None
    assert [f.fingerprint for f in restored] == [f.fingerprint for f in findings]
    assert [f.finding.summary for f in restored] == ["alpha", "beta"]


def test_empty_findings_are_cached_as_a_hit(tmp_path: Path, target_dir: Path) -> None:
    rule = _write_rule(tmp_path, "g002_demo.py")
    det = _detector("demo-02", rule)
    cache = _cache(tmp_path, target_dir)

    cache.put(det, ())
    # An empty result must be a HIT (None), not indistinguishable from a miss.
    assert cache.get(det) == ()


def test_rule_file_edit_invalidates(tmp_path: Path, target_dir: Path) -> None:
    rule = _write_rule(tmp_path, "g003_demo.py")
    det = _detector("demo-03", rule)
    cache = _cache(tmp_path, target_dir)
    cache.put(det, (_finding("demo-03", rule, "x"),))
    assert cache.get(det) is not None

    rule.write_text("def detect(repo):\n    return ()  # edited\n", encoding="utf-8")
    assert cache.get(det) is None  # rule content changed -> miss


def test_target_content_change_invalidates(tmp_path: Path, target_dir: Path) -> None:
    rule = _write_rule(tmp_path, "g004_demo.py")
    det = _detector("demo-04", rule)
    cache = _cache(tmp_path, target_dir)
    cache.put(det, (_finding("demo-04", rule, "x"),))
    assert cache.get(det) is not None

    # A fresh cache instance bound to a changed target must miss.
    (target_dir / "new_module.py").write_text("y = 2\n", encoding="utf-8")
    cache2 = _cache(tmp_path, target_dir)
    assert cache2.get(det) is None


def test_read_disabled_never_hits(tmp_path: Path, target_dir: Path) -> None:
    rule = _write_rule(tmp_path, "g005_demo.py")
    det = _detector("demo-05", rule)
    writer = _cache(tmp_path, target_dir)
    writer.put(det, (_finding("demo-05", rule, "x"),))

    reader = _cache(tmp_path, target_dir, read_enabled=False)
    assert reader.get(det) is None  # --refresh semantics: ignore existing
    # but it still repopulates
    reader.put(det, (_finding("demo-05", rule, "y"),))
    assert _cache(tmp_path, target_dir).get(det) is not None


def test_write_disabled_persists_nothing(tmp_path: Path, target_dir: Path) -> None:
    rule = _write_rule(tmp_path, "g006_demo.py")
    det = _detector("demo-06", rule)
    cache = _cache(tmp_path, target_dir, write_enabled=False)
    cache.put(det, (_finding("demo-06", rule, "x"),))
    assert _cache(tmp_path, target_dir).get(det) is None


def test_corrupt_payload_fails_closed(tmp_path: Path, target_dir: Path) -> None:
    rule = _write_rule(tmp_path, "g007_demo.py")
    det = _detector("demo-07", rule)
    cache = _cache(tmp_path, target_dir)
    cache.put(det, (_finding("demo-07", rule, "x"),))
    # Corrupt every payload file in the cache dir.
    for payload in cache.root.glob("*"):
        payload.write_bytes(b"not a pickle")
    assert cache.get(det) is None  # no exception, treated as miss


class _HeavyFact:
    """A stand-in evidence fact carrying a large payload (module-level so it
    pickles), to prove the cache elides facts rather than persisting them."""

    def __init__(self, location: object) -> None:
        self.location = location
        self.blob = b"x" * 2_000_000  # 2 MB of dead weight


def test_evidence_facts_are_elided_but_render_fields_survive(
    tmp_path: Path, target_dir: Path
) -> None:
    from flawed.core import Location
    from flawed.evidence import Evidence, EvidenceFact, Finding

    loc = Location(file="app.py", line=10, column=1)
    heavy = _HeavyFact(loc)
    ev = Evidence(fact=cast("EvidenceFact", heavy), description="why this matters", location=loc)
    finding = Finding(route_endpoint="ep", summary="heavy", evidence_items=(ev,), location=loc)
    rule = _write_rule(tmp_path, "g009_demo.py")
    det = _detector("demo-09", rule)
    rf = RuleFinding(rule_id="demo-09", rule_path=rule, finding=finding)

    cache = _cache(tmp_path, target_dir)
    cache.put(det, (rf,))

    # The 2 MB fact blob must NOT be persisted.
    payload = next(cache.root.glob("demo-09*.pkl"))
    assert payload.stat().st_size < 50_000, f"fact not elided: {payload.stat().st_size} bytes"

    restored = cache.get(det)
    assert restored is not None
    got = restored[0]
    # Everything renderers/fingerprint read is preserved.
    assert got.fingerprint == rf.fingerprint
    assert got.finding.summary == "heavy"
    assert got.finding.evidence_items[0].description == "why this matters"
    assert got.finding.evidence_items[0].location == loc
    # ...but the heavy fact object itself is gone.
    assert not isinstance(got.finding.evidence_items[0].fact, _HeavyFact)


def test_analysis_code_change_invalidates(
    tmp_path: Path, target_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An engine / L2 / L3-core / shared-_rules edit must invalidate cached
    findings even when the version, ``_PIPELINE_VERSION``, config, and the rule
    file are all unchanged — the FLAW-198 stale-findings fix.

    The edit is modelled by a changed analysis-code signature: every other key
    input is held identical, so a surviving HIT here would be exactly the
    silent-stale bug (a provider/L2 change altering a rule's findings while the
    cache returns the pre-change result).
    """
    import flawed._cli.result_cache as rc

    rule = _write_rule(tmp_path, "g010_demo.py")
    det = _detector("demo-10", rule)
    cache = _cache(tmp_path, target_dir)
    cache.put(det, (_finding("demo-10", rule, "x"),))
    assert cache.get(det) is not None  # baseline hit, same engine

    # Simulate an analysis-source edit: only the shared code signature changes.
    monkeypatch.setattr(rc, "code_signature", lambda patterns: "engine-edited")
    cache_after_edit = _cache(tmp_path, target_dir)
    assert cache_after_edit.get(det) is None  # stale entry must NOT be served


def test_unchanged_analysis_code_still_hits(tmp_path: Path, target_dir: Path) -> None:
    """The complement of the FLAW-198 test: with analysis code unchanged, the
    cache must stay warm (a re-scan of an unchanged repo with the same engine is
    the whole reason the cache exists — the signature must not bust needlessly).
    """
    rule = _write_rule(tmp_path, "g011_demo.py")
    det = _detector("demo-11", rule)
    cache = _cache(tmp_path, target_dir)
    cache.put(det, (_finding("demo-11", rule, "x"),))
    # A fresh handle computing the real (unchanged) signature must still hit.
    assert _cache(tmp_path, target_dir).get(det) is not None


def test_format_version_mismatch_fails_closed(
    tmp_path: Path, target_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import flawed._cli.result_cache as rc

    rule = _write_rule(tmp_path, "g008_demo.py")
    det = _detector("demo-08", rule)
    cache = _cache(tmp_path, target_dir)
    cache.put(det, (_finding("demo-08", rule, "x"),))

    monkeypatch.setattr(rc, "_CACHE_FORMAT_VERSION", "999")
    cache2 = _cache(tmp_path, target_dir)
    assert cache2.get(det) is None  # stored under old format version -> miss
