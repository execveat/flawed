"""Tests for the subprocess guardrail (tests/_guards/subprocess_guard.py).

Proves the guard's decision logic (which tests may spawn) and its enforcement
action (raise vs pass-through), without spawning any real subprocess.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from flawed import _process
from tests._guards import subprocess_guard


class _FakeItem:
    """Minimal stand-in for a pytest.Item for guard-decision tests."""

    def __init__(self, path: str, *, slow: bool = False) -> None:
        self.path = Path(path)
        self.nodeid = f"{path}::test_x"
        self._slow = slow

    def get_closest_marker(self, name: str) -> object | None:
        return object() if (name == "slow" and self._slow) else None


@pytest.fixture
def _restore_guard_state() -> Any:
    """Save/restore the guard's mutable state so a test can drive it."""
    saved = dict(subprocess_guard._state)
    yield
    subprocess_guard._state.clear()
    subprocess_guard._state.update(saved)


def test_external_tier_is_exempt() -> None:
    item = _FakeItem("/repo/tests/external/test_build_index.py")
    assert subprocess_guard._is_exempt(cast("pytest.Item", item)) is True


def test_slow_marked_is_exempt() -> None:
    item = _FakeItem("/repo/tests/unit/l1/test_x.py", slow=True)
    assert subprocess_guard._is_exempt(cast("pytest.Item", item)) is True


def test_allowlisted_path_is_exempt(monkeypatch: pytest.MonkeyPatch) -> None:
    # The conversion-debt allowlist is currently empty, so this exercises the
    # *mechanism* with a controlled entry rather than coupling to a real (and
    # churn-prone) allowlisted file: a path matching an allowlist substring is exempt.
    monkeypatch.setattr(
        subprocess_guard,
        "_ALLOWLIST_PATH_SUBSTRINGS",
        ("tests/specs/example/test_inline_build.py",),
    )
    item = _FakeItem("/repo/tests/specs/example/test_inline_build.py")
    assert subprocess_guard._is_exempt(cast("pytest.Item", item)) is True


def test_ordinary_unit_test_is_not_exempt() -> None:
    item = _FakeItem("/repo/tests/unit/l2/test_flow.py")
    assert subprocess_guard._is_exempt(cast("pytest.Item", item)) is False


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (["/usr/bin/python", "-m", "basedpyright", "x.py"], True),
        (["basedpyright", "x.py"], True),
        (["/opt/basedpyright/bin/basedpyright", "x.py"], True),
        (["git", "rev-parse", "HEAD"], False),
        (["echo", "hi"], False),
        # a path ARGUMENT containing "basedpyright" must NOT trip the matcher
        (["cat", "logs/basedpyright-out.json"], False),
    ],
)
def test_is_analysis_tool_matches_only_the_executable(command: list[str], expected: bool) -> None:
    assert subprocess_guard._is_analysis_tool(command) is expected


@pytest.mark.usefixtures("_restore_guard_state")
def test_guard_raises_for_enforced_spawn() -> None:
    """A non-exempt running test that spawns gets a SubprocessGuardError."""
    subprocess_guard._state["item"] = _FakeItem("/repo/tests/unit/l2/test_flow.py")
    subprocess_guard._state["enforce"] = True
    # The real _start_process is wrapped (installed by the root conftest). An
    # analysis-tool command makes the guard raise BEFORE any process is created.
    with pytest.raises(subprocess_guard.SubprocessGuardError, match="SUBPROCESS GUARD"):
        _process.run(["basedpyright", "--version"], capture_output=True, text=True)


@pytest.mark.usefixtures("_restore_guard_state")
def test_guard_passes_through_when_not_enforced() -> None:
    """When the running test is exempt, spawns pass through to the original."""
    calls: list[tuple[Any, ...]] = []
    wrapped = subprocess_guard._guarded(lambda *a, **k: calls.append(a))
    subprocess_guard._state["item"] = _FakeItem("/repo/tests/external/test_x.py")
    subprocess_guard._state["enforce"] = False
    wrapped(["basedpyright", "--version"])
    assert calls == [(["basedpyright", "--version"],)]


@pytest.mark.usefixtures("_restore_guard_state")
def test_non_analysis_spawn_allowed_even_when_enforced() -> None:
    """git/echo etc. are fine anywhere — only analysis tools are guarded."""
    calls: list[tuple[Any, ...]] = []
    wrapped = subprocess_guard._guarded(lambda *a, **k: calls.append(a))
    subprocess_guard._state["item"] = _FakeItem("/repo/tests/unit/config/test_config.py")
    subprocess_guard._state["enforce"] = True
    wrapped(["git", "rev-parse", "HEAD"])
    assert calls == [(["git", "rev-parse", "HEAD"],)]
