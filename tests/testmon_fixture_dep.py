"""Bridge fixture-app edits into testmon's selection (FLAW-197).

testmon selects which tests to run from coverage of *executed* Python: each
test's dependency set is the set of source files whose lines ran during it.
Fixture apps under ``tests/fixtures/apps/`` are never executed — flawed ingests
them as **data** (``ast.parse`` of the source text; see
``src/flawed/_index/_parsing.py``). Coverage therefore never records them, so
testmon associates them with no test. Editing *only* a fixture app deselects the
very specs whose behaviour it changes — a silent, dangerous test gap (surfaced by
FLAW-195, filed as FLAW-197).

testmon exposes no API to register a non-executed data file as a per-test
dependency (``TestmonData.determine_stable`` derives the whole dependency graph
from coverage fingerprints, ``testmon/testmon_core.py``). The robust fix is
therefore not to teach testmon about the files, but to detect when the fixtures
tree changes and, for that one run, force a full non-selective pass: testmon
still *collects* and writes data, so subsequent runs stay incremental — it just
does not deselect this once.

This module holds the pure, testable core: a content stamp of the fixtures tree.
``tests/conftest.py`` calls it from ``pytest_configure`` and persists the stamp
beside ``.testmondata`` (gitignored) only after a green run.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

#: Directories that never carry fixture-app semantics and must not perturb the
#: stamp (compiled caches differ across interpreters / runs).
_IGNORED_DIR_PARTS = frozenset({"__pycache__", ".pytest_cache", ".mypy_cache"})


def _is_relevant(path: Path) -> bool:
    if not path.is_file():
        return False
    return not (_IGNORED_DIR_PARTS & set(path.parts))


def compute_fixtures_hash(fixtures_root: Path) -> str:
    """Return an order-independent SHA-256 over every file under ``fixtures_root``.

    The hash folds in each file's path *and* bytes, so renames, additions,
    deletions and content edits all change it. A missing root hashes to a stable
    sentinel rather than raising — the caller treats "no fixtures" uniformly.
    """
    digest = hashlib.sha256()
    if not fixtures_root.exists():
        digest.update(b"\0missing-fixtures-root\0")
        return digest.hexdigest()
    for path in sorted(p for p in fixtures_root.rglob("*") if _is_relevant(p)):
        rel = path.relative_to(fixtures_root).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def fixtures_changed(fixtures_root: Path, stamp_path: Path) -> tuple[bool, str]:
    """Return ``(changed, current_hash)`` for the fixtures tree.

    ``changed`` is ``True`` when no stamp exists yet (first run — establish a
    baseline by running everything) or when the stored hash differs from the
    current one. A malformed/unreadable stamp is treated as a miss, never as a
    silent match: fail toward running more tests, not fewer.
    """
    current = compute_fixtures_hash(fixtures_root)
    try:
        previous = stamp_path.read_text(encoding="utf-8").strip()
    except (FileNotFoundError, OSError, UnicodeDecodeError):
        return True, current
    return previous != current, current


def write_stamp(stamp_path: Path, value: str) -> None:
    """Persist ``value`` as the new fixtures stamp (atomic replace)."""
    tmp = stamp_path.with_suffix(stamp_path.suffix + ".tmp")
    tmp.write_text(value, encoding="utf-8")
    tmp.replace(stamp_path)
