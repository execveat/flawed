"""Shared analysis-code signature for the disk caches (FLAW-189, FLAW-198).

Both disk caches that persist analysis output — the Layer-2 provider-engine
cache (:mod:`flawed._cli.provider_engine_cache`) and the per-detector results
cache (:mod:`flawed._cli.result_cache`) — must invalidate when the *analysis
source that determines their stored value* changes. ``_PIPELINE_VERSION`` only
tracks Layer 1 and is bumped by hand; ``flawed.__version__`` only moves on a
release. Neither catches a mid-development edit to ``_semantic`` matching, a
provider, or an L3 rule-API module — exactly the edits that change findings.

This module is the **single source of truth** for "hash this analysis source",
so the two caches cannot drift into two subtly-different notions of "did the
engine change". Each cache calls :func:`code_signature` with the set of source
roots whose contents affect *its* stored value:

* the provider-engine cache (an L2 artifact) hashes ``_index`` + ``_semantic`` +
  ``core`` — the layers whose types appear in its pickled graph;
* the results cache (final per-detector findings) hashes a broader set, adding
  the Layer 3 rule-API core and the shared ``_rules`` helpers, because a finding
  depends on all of those.
"""

from __future__ import annotations

import functools
import hashlib
from pathlib import Path


def _package_root() -> Path:
    """Filesystem root of the installed ``flawed`` package."""
    import flawed

    return Path(flawed.__file__).resolve().parent


@functools.cache
def code_signature(patterns: tuple[str, ...]) -> str:
    """SHA-256 over the ``.py`` files matched by glob *patterns*.

    *patterns* are :class:`pathlib.Path` globs evaluated against the ``flawed``
    package root: ``"_semantic/**/*.py"`` (a tree, recursively — ``**`` matches
    zero or more intermediate directories, so files directly under the root dir
    are included too), ``"*.py"`` (top-level files only), ``"core.py"`` (one
    file). Each matched file contributes its package-relative POSIX path *and*
    its bytes to the digest, processed in sorted order so the result is
    deterministic and independent of filesystem iteration order.

    Memoized for the process: analysis source does not change mid-run, and both
    caches query the same constant pattern sets repeatedly.
    """
    root = _package_root()
    files: set[Path] = set()
    for pattern in patterns:
        files.update(p for p in root.glob(pattern) if p.is_file())
    hasher = hashlib.sha256()
    for path in sorted(files):
        hasher.update(path.relative_to(root).as_posix().encode())
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    return hasher.hexdigest()
