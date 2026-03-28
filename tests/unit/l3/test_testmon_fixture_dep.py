"""Unit tests for the testmon fixture-dependency stamp (FLAW-197).

These lock the detection logic that decides when a fixtures-tree edit must force
a full (non-selective) testmon run. The integration behaviour (conftest flipping
``testmon_noselect``) is verified live; see FLAW-197's resolution note.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.testmon_fixture_dep import (
    compute_fixtures_hash,
    fixtures_changed,
    write_stamp,
)

if TYPE_CHECKING:
    from pathlib import Path


def _make_tree(root: Path) -> Path:
    """Build a fixtures tree under ``root/fx`` and return that fixtures root.

    The fixtures root is a *subdirectory* so the stamp file (kept directly under
    ``root``) sits outside the hashed tree — mirroring production, where the stamp
    lives at ``rootpath/.testmondata.fixtures-stamp`` while fixtures live under
    ``tests/fixtures/apps``.
    """
    fx = root / "fx"
    (fx / "app").mkdir(parents=True)
    (fx / "app" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (fx / "app" / "b.py").write_text("y = 2\n", encoding="utf-8")
    return fx


class TestComputeFixturesHash:
    def test_deterministic(self, tmp_path: Path) -> None:
        fx = _make_tree(tmp_path)
        assert compute_fixtures_hash(fx) == compute_fixtures_hash(fx)

    def test_content_edit_changes_hash(self, tmp_path: Path) -> None:
        fx = _make_tree(tmp_path)
        before = compute_fixtures_hash(fx)
        (fx / "app" / "a.py").write_text("x = 999\n", encoding="utf-8")
        assert compute_fixtures_hash(fx) != before

    def test_rename_changes_hash(self, tmp_path: Path) -> None:
        fx = _make_tree(tmp_path)
        before = compute_fixtures_hash(fx)
        (fx / "app" / "a.py").rename(fx / "app" / "renamed.py")
        assert compute_fixtures_hash(fx) != before

    def test_addition_changes_hash(self, tmp_path: Path) -> None:
        fx = _make_tree(tmp_path)
        before = compute_fixtures_hash(fx)
        (fx / "app" / "c.py").write_text("z = 3\n", encoding="utf-8")
        assert compute_fixtures_hash(fx) != before

    def test_pycache_ignored(self, tmp_path: Path) -> None:
        fx = _make_tree(tmp_path)
        before = compute_fixtures_hash(fx)
        cache = fx / "app" / "__pycache__"
        cache.mkdir()
        (cache / "a.cpython-312.pyc").write_bytes(b"\x00\x01compiled")
        assert compute_fixtures_hash(fx) == before

    def test_missing_root_is_stable_not_raising(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist"
        assert compute_fixtures_hash(missing) == compute_fixtures_hash(missing)


class TestFixturesChanged:
    def test_no_stamp_is_changed(self, tmp_path: Path) -> None:
        fx = _make_tree(tmp_path)
        stamp = tmp_path / "stamp"
        changed, current = fixtures_changed(fx, stamp)
        assert changed is True
        assert current == compute_fixtures_hash(fx)

    def test_matching_stamp_is_unchanged(self, tmp_path: Path) -> None:
        fx = _make_tree(tmp_path)
        stamp = tmp_path / "stamp"
        write_stamp(stamp, compute_fixtures_hash(fx))
        changed, _ = fixtures_changed(fx, stamp)
        assert changed is False

    def test_stale_stamp_is_changed(self, tmp_path: Path) -> None:
        fx = _make_tree(tmp_path)
        stamp = tmp_path / "stamp"
        write_stamp(stamp, compute_fixtures_hash(fx))
        (fx / "app" / "a.py").write_text("x = 4242\n", encoding="utf-8")
        changed, current = fixtures_changed(fx, stamp)
        assert changed is True
        assert current == compute_fixtures_hash(fx)

    def test_unreadable_stamp_fails_toward_changed(self, tmp_path: Path) -> None:
        # A directory where the stamp file is expected -> read raises OSError;
        # we must treat that as "changed", never as a silent match.
        fx = _make_tree(tmp_path)
        stamp_as_dir = tmp_path / "stamp_dir"
        stamp_as_dir.mkdir()
        changed, _ = fixtures_changed(fx, stamp_as_dir)
        assert changed is True


class TestWriteStamp:
    def test_round_trip(self, tmp_path: Path) -> None:
        fx = _make_tree(tmp_path)
        stamp = tmp_path / "stamp"
        value = compute_fixtures_hash(fx)
        write_stamp(stamp, value)
        assert stamp.read_text(encoding="utf-8") == value

    def test_overwrite(self, tmp_path: Path) -> None:
        stamp = tmp_path / "stamp"
        write_stamp(stamp, "first")
        write_stamp(stamp, "second")
        assert stamp.read_text(encoding="utf-8") == "second"
