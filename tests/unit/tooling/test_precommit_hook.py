"""Guards the version-controlled pre-commit hook (FLAW-167).

The hook used to live only in ``.git/hooks/`` — untracked, so a fresh clone or
a hook reinstall silently lost it (and, after FLAW-163, lost the ``uv run``
invocations that make worktree commits resolve the *local* ``flawed`` package
instead of the main checkout's source). These tests pin the canonical hook into
the repo so that loss becomes a red test rather than a silent gate regression.
"""

from __future__ import annotations

import stat
import subprocess
import tomllib
from typing import TYPE_CHECKING

from tests.helpers.paths import REPO_ROOT

if TYPE_CHECKING:
    from pathlib import Path

CANONICAL_HOOK = REPO_ROOT / "tools" / "hooks" / "pre-commit"


def test_canonical_hook_is_version_controlled() -> None:
    assert CANONICAL_HOOK.is_file(), (
        "tools/hooks/pre-commit must exist as the tracked source of the hook"
    )


def test_canonical_hook_is_executable() -> None:
    mode = CANONICAL_HOOK.stat().st_mode
    assert mode & stat.S_IXUSR, "tracked hook must carry the executable bit"


def test_hook_delegates_to_quality_via_uv_run() -> None:
    """FLAW-163 + gate-consolidation guard: the hook delegates to quality.py via ``uv run``.

    The check-set now has a single owner (``tools/quality.py``); the hook is a thin
    caller that runs the staged-scoped gate. It must invoke it via ``uv run`` so a
    worktree commit resolves the *local* ``flawed`` package, not a mise shim's wrong
    source (the original FLAW-163 failure class). Reinstalling the hook must never
    reintroduce a bare invocation or bypass the single gate owner.
    """
    text = CANONICAL_HOOK.read_text()
    assert "uv run python -m tools.quality" in text, (
        "hook must delegate to the quality.py gate owner via 'uv run'"
    )
    assert "--staged" in text, "hook must run the staged-scoped gate"


def test_install_hooks_task_is_defined() -> None:
    """A documented one-liner (`mise run install-hooks`) must install the hook."""
    mise_toml = REPO_ROOT / "mise.toml"
    config = tomllib.loads(mise_toml.read_text())
    tasks = config.get("tasks", {})
    assert "install-hooks" in tasks, "mise.toml must define an 'install-hooks' task"
    run = tasks["install-hooks"].get("run", "")
    run_text = run if isinstance(run, str) else "\n".join(run)
    # The installer must reference the tracked hook source and the git hooks dir.
    assert "tools/hooks/pre-commit" in run_text
    assert "hooks" in run_text


def test_installer_produces_canonical_executable_hook(tmp_path: Path) -> None:
    """The installer's copy step must yield an executable, byte-identical hook.

    Exercises the installer contract (``install -m 0755`` of the canonical file)
    in an isolated directory rather than against the shared ``.git/hooks`` dir,
    so the assertion holds regardless of what hook the checkout happens to have
    installed right now.
    """
    dest = tmp_path / "hooks"
    dest.mkdir()
    target = dest / "pre-commit"
    subprocess.run(
        ["install", "-m", "0755", str(CANONICAL_HOOK), str(target)],
        check=True,
    )
    assert target.read_text() == CANONICAL_HOOK.read_text()
    assert target.stat().st_mode & stat.S_IXUSR, "installed hook must be executable"
