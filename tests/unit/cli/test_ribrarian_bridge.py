"""Tests for the optional ribrarian bridge and multi-target resolution.

ribrarian is an optional dependency and is NOT installed in the gate env, so the
"installed" behavior is simulated by patching the bridge's import surface. The
"absent" behavior is exercised natively.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import flawed._cli.ribrarian_bridge as bridge
from flawed._cli.ribrarian_bridge import RibrarianBridgeError
from flawed._cli.target import TargetError, entered_target, resolve_target, resolve_targets
from flawed._config.paths import RepoIdentity


class _FakeRibrarian:
    """Stand-in for the ribrarian module: selector -> list[Path]."""

    def __init__(self, mapping: dict[str, list[Path]]) -> None:
        self._mapping = mapping

    def resolve(self, selector: str) -> list[Path]:
        return list(self._mapping.get(selector, []))


def _install_fake(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, list[Path]]) -> None:
    monkeypatch.setattr(bridge, "HAS_RIBRARIAN", True)
    monkeypatch.setattr(bridge, "ribrarian", _FakeRibrarian(mapping), raising=False)


# ── bridge.resolve ───────────────────────────────────────────────


def test_resolve_empty_selectors_is_empty_without_ribrarian() -> None:
    # No selectors means no work and no dependency requirement, ever.
    assert bridge.resolve([]) == []


def test_resolve_with_selectors_but_no_ribrarian_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bridge, "HAS_RIBRARIAN", False)
    with pytest.raises(RibrarianBridgeError, match="not installed"):
        bridge.resolve(["class:target"])


def test_resolve_merges_and_dedups_preserving_order(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake(
        monkeypatch,
        {
            "sel1": [Path("/repos/a"), Path("/repos/b")],
            "sel2": [Path("/repos/b"), Path("/repos/c")],
        },
    )
    out = bridge.resolve(["sel1", "sel2"])
    assert out == [Path("/repos/a"), Path("/repos/b"), Path("/repos/c")]


def test_resolve_zero_match_selector_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # Refusing to scan nothing is a false-negative safeguard (priority #1).
    _install_fake(monkeypatch, {"hit": [Path("/repos/a")]})
    with pytest.raises(RibrarianBridgeError, match="matched no repos"):
        bridge.resolve(["hit", "miss"])


# ── resolve_targets ──────────────────────────────────────────────


def test_resolve_targets_empty_falls_back_to_cwd() -> None:
    assert resolve_targets((), ()) == [Path.cwd().resolve()]


def test_resolve_targets_validates_and_dedups_paths(tmp_path: Path) -> None:
    out = resolve_targets((str(tmp_path), str(tmp_path)), ())
    assert out == [tmp_path.resolve()]


def test_resolve_targets_rejects_missing_path(tmp_path: Path) -> None:
    with pytest.raises(TargetError, match="does not exist"):
        resolve_targets((str(tmp_path / "nope"),), ())


def test_resolve_targets_merges_paths_and_selectors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bridge, "resolve", lambda sels: [Path("/repos/x"), tmp_path.resolve()])
    out = resolve_targets((str(tmp_path),), ("sel",))
    # Positional path first; selector result that duplicates it is collapsed.
    assert out == [tmp_path.resolve(), Path("/repos/x")]


def test_resolve_target_single_still_works(tmp_path: Path) -> None:
    assert resolve_target(str(tmp_path)) == tmp_path.resolve()
    assert resolve_target(None) == Path.cwd().resolve()


# ── entered_target (cwd save/restore) ────────────────────────────


def test_entered_target_restores_cwd_on_success(tmp_path: Path) -> None:
    origin = Path.cwd()
    repo = tmp_path / "repo"
    repo.mkdir()
    with entered_target(repo) as identity:
        assert Path.cwd() == repo.resolve()
        assert isinstance(identity, RepoIdentity)
    assert Path.cwd() == origin


def test_entered_target_restores_cwd_on_error(tmp_path: Path) -> None:
    origin = Path.cwd()
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(RuntimeError), entered_target(repo):
        raise RuntimeError("boom")
    assert Path.cwd() == origin
