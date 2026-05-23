"""Per-detector results cache (FLAW-137).

Persists Layer 3 detector findings so an unchanged re-run — same engine, same
rules, same target — is served from disk without re-executing detectors.  The
cache is keyed *per detector* so that a subset re-run (``-i`` a subset of
previously-run rules) hits the cache for every rule it shares with an earlier
full run.

**Why pickle.** A finding is a deep tree (``Finding`` -> ``Evidence`` ->
framework-specific fact objects -> ``Location``/``AnalysisGap``).  Pickling the
raw ``RuleFinding`` tuple is *render-lossless*: the JSON, SARIF, and fingerprint
projections are byte-identical after a round-trip (verified empirically — the
only thing that differs is object identity on nested facts, which no renderer
reads).  Replaying cached findings through the unchanged post-processing and
rendering path therefore produces exactly the same output as a fresh scan, in
every format.  A hand-written JSON codec for the whole tree would be a large,
drift-prone surface and a fail-open risk if it silently dropped a field.

**Fail closed.** Every read is defensive: a missing payload, a key mismatch, a
format/engine/pipeline-version mismatch, or a corrupt file is treated as a miss
and recomputed.  Stale or partial results are never served.

The cache key combines:

* ``_CACHE_FORMAT_VERSION`` — the on-disk payload schema,
* ``flawed.__version__`` — the engine package version,
* ``_PIPELINE_VERSION`` — the index pipeline version (already gates L1),
* ``repo_content_hash(target, cache_invalidation)`` — the repo content hash
  under the configured strategy (auto: git HEAD + dirty suffix, else mtime;
  or a forced mtime / content-hash / git-hash),
* the analysis-relevant config (providers, meta-effects, effect routing,
  groups) — anything that changes how L2/L3 interpret the same source,
* an **analysis-code signature** (FLAW-198) — a content hash of every source
  layer a finding depends on: ``_index`` (L1), ``_semantic`` (L2), the Layer 3
  rule-API core (``flawed/*.py``), and the shared ``_rules`` helpers. Without
  this, an engine edit that changes *how* a rule computes its findings — but
  leaves the version, ``_PIPELINE_VERSION``, config, and the rule file itself
  untouched — would silently serve STALE findings (a real bug: a provider
  activation change altered modelled effects yet a cached rule still hit). The
  signature is shared with the provider-engine cache via
  :func:`flawed._cli._code_signature.code_signature` — one source of truth for
  "did analysis code change".
* and, per detector, ``rule_id`` + the SHA-256 of the rule file's contents
  (leaf rule files are hashed individually, preserving per-rule granularity: an
  edit to one rule invalidates only that rule, while an edit to a *shared*
  ``_rules`` helper or any engine layer invalidates via the code signature).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import os
import pickle
import re
import shutil
from dataclasses import dataclass
from typing import TYPE_CHECKING

from flawed._cli._code_signature import code_signature
from flawed._config.paths import repo_cache_name, repo_content_hash
from flawed._index._pipeline import _PIPELINE_VERSION

if TYPE_CHECKING:
    from pathlib import Path

    from flawed._cli.rules import RuleDetector, RuleFinding
    from flawed._config.paths import RepoIdentity
    from flawed._config.schema import ResolvedConfig
    from flawed.core import Location

_log = logging.getLogger("flawed.result_cache")

# Bump whenever the on-disk payload layout or the set of key inputs changes, so
# payloads written by an older engine are rejected (treated as a miss) rather
# than silently mis-deserialized. "2" added the analysis-code signature input
# (FLAW-198).
_CACHE_FORMAT_VERSION = "2"

_SAFE_RULE_RE = re.compile(r"[^A-Za-z0-9._-]+")

#: Source layers whose contents determine a finding, hashed into the cache key
#: so an analysis-code edit invalidates cached results even when the version,
#: ``_PIPELINE_VERSION``, config, and rule file are unchanged (FLAW-198):
#: L1 extraction, L2 interpretation, the Layer 3 rule-API core (top-level
#: ``flawed/*.py``), and the shared ``_rules`` helpers (``_shared.py`` / package
#: ``__init__``; leaf rule files stay per-detector for fine-grained
#: invalidation). ``**`` matches zero or more directories, so a tree pattern
#: also covers files directly under its root.
_RESULTS_CODE_SIGNATURE_PATTERNS = (
    "_index/**/*.py",
    "_semantic/**/*.py",
    "*.py",
    "_rules/**/_*.py",
)


def _engine_version() -> str:
    try:
        from flawed import __version__

        return str(__version__)
    except Exception:  # pragma: no cover - defensive; version is normally present
        return "unknown"


def _analysis_config_digest(config: ResolvedConfig) -> str:
    """Deterministic digest of the config fields that affect L2/L3 results.

    Detector identity (rule id + file hash) is keyed separately, so this covers
    only the *interpretation* inputs: which providers run and how effects,
    routing, and groups are modelled.  Conservative by design — including a
    field that turns out not to matter only causes an extra (safe) recompute.
    """
    relevant = {
        "providers": dataclasses.asdict(config.providers),
        "meta_effects": config.meta_effects,
        "effect_routing": {k: dataclasses.asdict(v) for k, v in config.effect_routing.items()},
        "groups": {k: dataclasses.asdict(v) for k, v in config.groups.items()},
    }
    blob = json.dumps(relevant, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


@dataclass(frozen=True)
class _ElidedFact:
    """Stand-in for an evidence fact in a *cached* finding.

    A live finding's evidence facts transitively reference large shared analysis
    structures (the value-flow graph, taint traces): on a real repo a single
    finding pickles to ~20 MB.  Nothing that consumes a cached finding — the
    fingerprint, dedup, suppression, or any renderer — reads the fact object
    itself; they read the finding's summary, severity, location, evidence
    *descriptions* and *locations*, and gaps.  So the fact is elided before
    persisting (the small ``location`` is preserved for safety), which shrinks
    the payload by ~450x with byte-identical JSON/SARIF/fingerprint output.
    """

    location: Location | None = None


def _slim_finding(rule_finding: RuleFinding) -> RuleFinding:
    """Return a copy of *rule_finding* with heavy evidence facts elided.

    Preserves every field the cache's consumers read (summary, severity,
    location, gaps, and each evidence item's description + location); only the
    unread ``Evidence.fact`` object graph is dropped.
    """
    finding = rule_finding.finding
    slim_evidence = tuple(
        # _ElidedFact is deliberately not an EvidenceFact: no cached-finding
        # consumer reads .fact, and keeping the real fact bloats the pickle.
        dataclasses.replace(ev, fact=_ElidedFact(location=ev.location))  # type: ignore[arg-type]
        for ev in finding.evidence_items
    )
    return dataclasses.replace(
        rule_finding, finding=dataclasses.replace(finding, evidence_items=slim_evidence)
    )


def _rule_file_hash(path: Path) -> str:
    """SHA-256 of a rule file's bytes; a sentinel if it cannot be read.

    An unreadable rule file yields a sentinel that differs from any real hash,
    so the detector reliably misses (and is recomputed) rather than colliding
    with a stale entry.
    """
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return f"unreadable:{path}"


@dataclass(frozen=True)
class ResultCache:
    """A per-repo, per-detector results store rooted at a results directory.

    Construct via :meth:`create`.  ``read_enabled`` False models ``--refresh``
    (ignore existing entries but still repopulate); both flags False is
    equivalent to no cache at all (the pipeline passes ``None`` for
    ``--no-cache``).
    """

    root: Path
    base_key: str
    read_enabled: bool
    write_enabled: bool

    @classmethod
    def results_root(cls, data_dir: Path, identity: RepoIdentity) -> Path:
        """Return the per-repo results directory (sibling of the L1 artifact dir).

        Kept separate from the L1 artifact directory so a forced L1
        re-extraction (which clears that directory) does not wipe results, and
        vice versa — each cache invalidates on its own key.
        """
        return data_dir / "results" / repo_cache_name(identity)

    @classmethod
    def create(
        cls,
        *,
        config: ResolvedConfig,
        identity: RepoIdentity,
        read_enabled: bool = True,
        write_enabled: bool = True,
    ) -> ResultCache:
        base = "\0".join(
            (
                _CACHE_FORMAT_VERSION,
                _engine_version(),
                _PIPELINE_VERSION,
                repo_content_hash(identity.path, config.cache_invalidation),
                _analysis_config_digest(config),
                code_signature(_RESULTS_CODE_SIGNATURE_PATTERNS),
            )
        )
        base_key = hashlib.sha256(base.encode()).hexdigest()
        return cls(
            root=cls.results_root(config.data_dir, identity),
            base_key=base_key,
            read_enabled=read_enabled,
            write_enabled=write_enabled,
        )

    def _detector_key(self, detector: RuleDetector) -> str:
        material = "\0".join((self.base_key, detector.rule_id, _rule_file_hash(detector.path)))
        return hashlib.sha256(material.encode()).hexdigest()

    def _payload_path(self, detector: RuleDetector) -> Path:
        safe_id = _SAFE_RULE_RE.sub("_", detector.rule_id).strip("._-") or "rule"
        return self.root / f"{safe_id}-{self._detector_key(detector)[:16]}.pkl"

    def get(self, detector: RuleDetector) -> tuple[RuleFinding, ...] | None:
        """Return cached findings for *detector*, or ``None`` on any miss.

        An empty tuple is a genuine hit (the detector ran and found nothing);
        ``None`` means recompute.
        """
        if not self.read_enabled:
            return None
        path = self._payload_path(detector)
        try:
            raw = path.read_bytes()
        except OSError:
            return None
        try:
            # Trusted input: our own version-keyed cache dir, never user-supplied.
            payload = pickle.loads(raw)
        except Exception as exc:  # corrupt / incompatible pickle -> fail closed
            _log.debug("results-cache: discarding unreadable payload %s (%s)", path, exc)
            return None
        if not self._payload_valid(payload, detector):
            _log.debug("results-cache: stale payload header for %s", detector.rule_id)
            return None
        findings = payload.get("findings")
        if not isinstance(findings, tuple):
            return None
        return findings

    def _payload_valid(self, payload: object, detector: RuleDetector) -> bool:
        return (
            isinstance(payload, dict)
            and payload.get("v") == _CACHE_FORMAT_VERSION
            and payload.get("engine") == _engine_version()
            and payload.get("pipeline") == _PIPELINE_VERSION
            and payload.get("rule_id") == detector.rule_id
            and payload.get("key") == self._detector_key(detector)
        )

    def put(self, detector: RuleDetector, findings: tuple[RuleFinding, ...]) -> None:
        """Persist *findings* for *detector* atomically (no-op if writes off)."""
        if not self.write_enabled:
            return
        payload = {
            "v": _CACHE_FORMAT_VERSION,
            "engine": _engine_version(),
            "pipeline": _PIPELINE_VERSION,
            "rule_id": detector.rule_id,
            "key": self._detector_key(detector),
            "findings": tuple(_slim_finding(f) for f in findings),
        }
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            path = self._payload_path(detector)
            tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
            tmp.write_bytes(pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL))
            tmp.replace(path)
        except OSError as exc:  # a cache write must never break a scan
            _log.debug("results-cache: failed to persist %s (%s)", detector.rule_id, exc)


@dataclass(frozen=True)
class ResultCacheStatus:
    """Summary of an on-disk results cache for ``flawed cache status``."""

    root: Path
    entry_count: int
    total_bytes: int

    @property
    def exists(self) -> bool:
        return self.entry_count > 0


def cache_status(data_dir: Path, identity: RepoIdentity) -> ResultCacheStatus:
    """Inspect the results cache for a repo without computing any scan key."""
    root = ResultCache.results_root(data_dir, identity)
    entries = sorted(root.glob("*.pkl")) if root.is_dir() else []
    total = sum(p.stat().st_size for p in entries)
    return ResultCacheStatus(root=root, entry_count=len(entries), total_bytes=total)


def clear_cache(data_dir: Path, identity: RepoIdentity) -> int:
    """Delete the results cache for a repo; return the number of entries removed."""
    status = cache_status(data_dir, identity)
    root = ResultCache.results_root(data_dir, identity)
    if root.is_dir():
        shutil.rmtree(root, ignore_errors=True)
    return status.entry_count
