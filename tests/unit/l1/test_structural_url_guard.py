"""Unit tests for shape-based URL-safety-guard recognition (FLAW-186).

Indexes an isolated source file through the real L1 pipeline (external extraction stubbed so
the test stays fast and hermetic; CFG value-predicates, branch conditions,
attribute reads and AST call edges — everything the recogniser consumes — come
from the AST/CST pass, not external tools) and asserts which functions
``recognize_structural_url_guards`` classifies as guards.

Pins the soundness boundary: the return-expression shape and the branch shape
are recognised; a function that merely *touches* ``.netloc`` without gating its
verdict on it, and a function with no URL parsing, are not.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flawed._index._pipeline import build_index
from flawed._index._type_enrichment import TypeEnrichmentIndex
from flawed._semantic._structural_url_guard import recognize_structural_url_guards

if TYPE_CHECKING:
    from pathlib import Path

# build_index() runs the full L1 pipeline; bypass the per-test timing guard.
pytestmark = pytest.mark.slow


_SOURCE = '''\
"""Isolated URL-guard shapes for structural recognition."""

from urllib.parse import urlparse

ALLOWED = {"example.com"}


def safe_return_style(target):
    """Verdict is a return-position boolean expression over scheme/netloc."""
    parsed = urlparse(target)
    return parsed.scheme in ("http", "https", "") and (
        not parsed.netloc or parsed.netloc in ALLOWED
    )


def safe_branch_style(target):
    """Verdict is decided by a branch test on netloc/scheme."""
    parsed = urlparse(target)
    if parsed.netloc and parsed.netloc not in ALLOWED:
        return False
    if parsed.scheme and parsed.scheme not in ("http", "https"):
        return False
    return True


def decoy_touches_netloc(target):
    """Parses + reads netloc, but the verdict ignores it (constant return)."""
    parsed = urlparse(target)
    _ = parsed.netloc
    return True


def not_a_guard(value):
    """No URL parsing at all."""
    return value.startswith("/")
'''


class _EmptyOracle:
    def run(self, repo_root: Path, queries: object) -> TypeEnrichmentIndex:
        _ = (repo_root, queries)
        return TypeEnrichmentIndex.empty()


def test_recognizes_guard_shapes_and_rejects_decoys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "guards.py").write_text(_SOURCE)

    idx = build_index(tmp_path, oracle=_EmptyOracle())
    guard_short_names = {fqn.rsplit(".", 1)[-1] for fqn in recognize_structural_url_guards(idx)}

    assert "safe_return_style" in guard_short_names
    assert "safe_branch_style" in guard_short_names
    assert "decoy_touches_netloc" not in guard_short_names
    assert "not_a_guard" not in guard_short_names
