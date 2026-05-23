"""Disk cache for the Layer 2 provider-engine result (FLAW-189).

``ProviderEngine.run`` is the single largest *fixed* cost of a semantic scan
(~167s on a large real-world repo) and, unlike Layer 1, was recomputed on every scan because
nothing persisted its output. This module adds a content-addressed disk cache
for the :class:`~flawed._semantic._provider_engine.ProviderEngineResult` so a
warm re-run of an unchanged repository skips the rebuild.

Layering
--------
This lives in ``_cli`` (infrastructure), **not** ``_semantic``. Disk I/O and
repo-path knowledge inside ``_semantic`` would create a ``_semantic -> _config``
dependency that violates the layer contract. The engine stays a pure function
of ``(index, providers)``; persistence is an orchestration concern, mirroring
the existing Layer 1 content-hash cache in :mod:`flawed._cli.pipeline`.

Correctness invariants
-----------------------
* **No fail-open.** A missing, unreadable, corrupt, or key-mismatched entry
  returns ``None`` and the caller recomputes. The cache never returns a partial
  or stale result, and a write failure never aborts a scan.
* **The key covers everything the result depends on.** ``_PIPELINE_VERSION``
  tracks only Layer 1 artifacts, so a ``providers/*.py`` or ``_semantic`` edit
  would *not* bump it and would otherwise yield a stale L2 result. The key
  therefore combines:

  - the Layer 1 ``content_hash`` (repo source state — the same value the L1
    cache keys on; required because the incremental L1 path rebuilds in place
    without clearing the per-repo dir, so it cannot be relied on to evict us);
  - a content hash of all analysis source whose types appear in the pickled
    graph (``_index`` + ``_semantic`` + ``core``) — see :func:`_code_signature`;
  - the resolved provider configuration (enable/disable selection changes which
    providers run, hence the result — see :func:`_provider_config_signature`);
  - a format version constant, bumped on any envelope-shape change.

Serialization
-------------
``ProviderEngineResult`` is a frozen-dataclass graph (matches, gaps, router
groups) whose leaves are Layer 1 structural facts, enums, strings, and ``when=``
*predicate data objects*. ``WhenPredicate`` and its subclasses are frozen
dataclasses holding data (arg positions, type FQNs), **not** callables — the
``arg(0).type_is(...)`` DSL builds objects, not closures. The graph therefore
contains no callables or live references and round-trips faithfully through
:mod:`pickle` (by-value equality is preserved). ``pickle`` is already an
accepted cache format in the index layer (``_mypy_batch_oracle``). The code
signature in the key guarantees a pickle written by one analysis-code version
is never read by another, so a cross-version schema mismatch can never be
deserialized silently — it fails the key check (or raises, caught below) and
recomputes.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import pickle
from dataclasses import dataclass
from typing import TYPE_CHECKING

from flawed._cli._code_signature import code_signature

if TYPE_CHECKING:
    from pathlib import Path

    from flawed._config.schema import ResolvedConfig
    from flawed._semantic._provider_engine import ProviderEngineResult

_log = logging.getLogger("flawed.pipeline")

#: Cache file name, written under the per-repo data directory beside the L1
#: artifacts (so an L1 full re-extraction, which clears that directory, also
#: drops a now-irrelevant L2 entry).
_CACHE_FILENAME = "l2_provider_engine.pickle"

#: Bump when the on-disk envelope shape or the set of key inputs changes.
_L2_CACHE_FORMAT_VERSION = 1


@dataclass(frozen=True)
class _CacheKey:
    """Identity a cached result is valid for. Any mismatch forces recompute."""

    format_version: int
    content_hash: str
    code_signature: str
    provider_config_signature: str


@dataclass(frozen=True)
class _CacheEnvelope:
    """On-disk record: the validating key plus the cached result."""

    key: _CacheKey
    result: ProviderEngineResult


#: Analysis source whose types appear in this cache's pickled graph: the Layer 1
#: fact dataclasses serialized as ``source_fact`` leaves, the Layer 2 engine /
#: matching / provider descriptors, and ``flawed.core`` (``AnalysisGap``). A
#: change to any of these can alter the *content* of a result or the *schema* of
#: its pickled objects, so all must invalidate the cache.
_L2_SIGNATURE_PATTERNS = ("_index/**/*.py", "_semantic/**/*.py", "core.py")


def _code_signature() -> str:
    """Content hash of all analysis source whose types appear in the pickle.

    Delegates to the shared :func:`flawed._cli._code_signature.code_signature`
    (one source of truth for "did analysis code change", shared with the results
    cache) over :data:`_L2_SIGNATURE_PATTERNS`. Intentionally broader than
    ``_PIPELINE_VERSION`` (L1-only, manually bumped): the cache stays correct
    without relying on a human to bump a version.
    """
    return code_signature(_L2_SIGNATURE_PATTERNS)


def _provider_config_signature(config: ResolvedConfig) -> str:
    """Stable hash of the resolved per-provider enable/config selection.

    ``run_provider_engine`` re-runs the engine with a restricted provider set
    when config disables or force-enables providers, so two scans of the same
    repo under different provider config must not share a cache entry.
    """
    entries = config.providers.entries
    parts: list[tuple[str, object, tuple[tuple[str, str], ...]]] = []
    for provider_id in sorted(entries):
        entry = entries[provider_id]
        enable = entry.enable
        enable_repr: object = (
            ("bool", enable) if isinstance(enable, bool) else ("ids", tuple(sorted(enable)))
        )
        config_repr = tuple(sorted((str(k), repr(v)) for k, v in entry.config.items()))
        parts.append((provider_id, enable_repr, config_repr))
    return hashlib.sha256(repr(parts).encode()).hexdigest()


@dataclass(frozen=True)
class ProviderEngineCache:
    """Read/write gate for the on-disk provider-engine result.

    Construct with :meth:`create`; the caller then calls :meth:`load` (returns
    ``None`` on any miss) and, after computing, :meth:`store`.
    """

    cache_path: Path
    key: _CacheKey
    read_enabled: bool
    write_enabled: bool

    @classmethod
    def create(
        cls,
        *,
        cache_dir: Path,
        config: ResolvedConfig,
        content_hash: str,
        read_enabled: bool,
        write_enabled: bool,
    ) -> ProviderEngineCache:
        """Build a cache handle for one repo's per-scan provider-engine result."""
        key = _CacheKey(
            format_version=_L2_CACHE_FORMAT_VERSION,
            content_hash=content_hash,
            code_signature=_code_signature(),
            provider_config_signature=_provider_config_signature(config),
        )
        return cls(
            cache_path=cache_dir / _CACHE_FILENAME,
            key=key,
            read_enabled=read_enabled,
            write_enabled=write_enabled,
        )

    def load(self) -> ProviderEngineResult | None:
        """Return the cached result iff present and keyed identically.

        Fail-closed: any read/unpickle error, an unexpected payload type, or a
        key mismatch returns ``None`` so the caller recomputes. Never raises.
        """
        if not self.read_enabled:
            return None
        try:
            raw = self.cache_path.read_bytes()
        except OSError:
            return None
        try:
            # Local, code-signature-gated cache; a cross-version or corrupt
            # payload can raise many error types — any failure recomputes.
            envelope = pickle.loads(raw)
        except Exception as exc:
            _log.warning("Ignoring corrupt L2 cache (%s): %s", self.cache_path, exc)
            return None
        if not isinstance(envelope, _CacheEnvelope) or envelope.key != self.key:
            return None

        from flawed._semantic._provider_engine import ProviderEngineResult

        if not isinstance(envelope.result, ProviderEngineResult):
            return None
        return envelope.result

    def store(self, result: ProviderEngineResult) -> None:
        """Persist *result* under the current key. Never raises; logs on failure.

        Writes to a per-process temp file then atomically renames, so a
        concurrent reader never observes a half-written entry.
        """
        if not self.write_enabled:
            return
        envelope = _CacheEnvelope(key=self.key, result=result)
        tmp_path = self.cache_path.with_name(f"{_CACHE_FILENAME}.{os.getpid()}.tmp")
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path.write_bytes(pickle.dumps(envelope, pickle.HIGHEST_PROTOCOL))
            tmp_path.replace(self.cache_path)
        except (OSError, pickle.PicklingError) as exc:  # caching is best-effort
            _log.warning("Could not write L2 cache (%s): %s", self.cache_path, exc)
            with contextlib.suppress(OSError):
                tmp_path.unlink(missing_ok=True)
