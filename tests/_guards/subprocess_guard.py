"""Subprocess guardrail — the mechanical enforcement of the test taxonomy.

The redesign's core invariant: **only `tests/external/` tests (and explicitly
``@pytest.mark.slow`` ones) may run real external tools** (basedpyright).
Everything else must load committed L1 artifacts via
``tests.helpers.artifact_fixtures`` or inject a deterministic oracle, so the
fast default suite spawns zero subprocesses. That convention was previously
*documented* (root ``conftest.py``) but only softly enforced by a 10 s timing
guard, so it eroded silently (a ~0.4 s live build sails under 10 s).

This plugin makes the invariant impossible to violate accidentally: it wraps the
single subprocess choke point ``flawed._process._start_process`` (through which
``run``/``check_output``/``popen`` all pass) and, while a non-exempt test is
running, **fails** the test the instant it spawns a managed subprocess — with an
actionable message. Exempt = under ``tests/external/``, marked ``@slow``, or on
the conversion-debt allowlist below.

Overhead is nil when no subprocess is spawned (one dict lookup per spawn).

Discovery mode: set ``SUBPROCESS_GUARD=warn`` to record-and-report spawns at
session end instead of failing — used to populate the allowlist.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

# --- Conversion-debt allowlist --------------------------------------------------
# POSIX path substrings of test files that still legitimately live-build (run L1
# inline) and have NOT yet been converted to artifact-loading. This list IS the
# tracker for remaining build->load conversion debt: each entry is a test that
# *should* eventually load committed artifacts (or move to tests/external/).
# Add an entry only for a genuinely inline-build test; remove it the moment that
# spec is converted. Currently empty — there is no outstanding conversion debt.
_ALLOWLIST_PATH_SUBSTRINGS: tuple[str, ...] = ()


class SubprocessGuardError(AssertionError):
    """Raised when a non-exempt test spawns a managed subprocess."""


# Mutable per-run state: the running item, whether to enforce, and the saved
# original ``_start_process`` (kept here to avoid a module-level ``global``).
_state: dict[str, Any] = {"item": None, "enforce": False, "original": None}
_warn_spawns: list[tuple[str, str]] = []


def _is_exempt(item: pytest.Item) -> bool:
    """A test may spawn iff it's external/e2e-tier, @slow, or allowlisted debt."""
    path = item.path.as_posix()
    if "/tests/external/" in path or "/tests/e2e/" in path:
        return True
    if item.get_closest_marker("slow") is not None:
        return True
    return any(sub in path for sub in _ALLOWLIST_PATH_SUBSTRINGS)


#: Heavy external analysis tools the de-externalization targets. The guard fires
#: ONLY on these — ordinary subprocesses (git, echo, the _process module's own
#: tests) are fine in any tier.
_ANALYSIS_TOOLS: frozenset[str] = frozenset({"basedpyright"})


def _command_parts(popenargs: tuple[Any, ...], kwargs: dict[str, Any]) -> list[str]:
    cmd = popenargs[0] if popenargs else kwargs.get("args")
    if isinstance(cmd, (str, bytes)):
        return [os.fsdecode(cmd)]
    if cmd is None:
        return []
    try:
        return [os.fsdecode(part) for part in cmd]
    except TypeError:
        return []


def _is_analysis_tool(parts: list[str]) -> bool:
    """True iff the command invokes basedpyright (not a path arg)."""
    if not parts:
        return False
    exe = Path(parts[0]).name.lower()
    if any(exe.startswith(tool) for tool in _ANALYSIS_TOOLS):
        return True
    # ``python -m basedpyright``
    if "-m" in parts:
        idx = parts.index("-m")
        if idx + 1 < len(parts) and parts[idx + 1].lower() in _ANALYSIS_TOOLS:
            return True
    return False


def _format_command(popenargs: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    cmd = popenargs[0] if popenargs else kwargs.get("args")
    if isinstance(cmd, (list, tuple)):
        return " ".join(str(part) for part in cmd)
    return str(cmd)


def _violation_message(nodeid: str, command: str) -> str:
    return (
        f"SUBPROCESS GUARD: test {nodeid!r} spawned an external subprocess:\n"
        f"    {command}\n\n"
        f"Non-external tests must not run real tools (basedpyright). Either:\n"
        f"  - load committed L1 artifacts via tests.helpers.artifact_fixtures.load_fixture\n"
        f"  - inject a deterministic oracle into build_index(...)\n"
        f"  - mark the test @pytest.mark.slow (excluded from the default run), or\n"
        f"  - move it to tests/external/ (the real-tool integration tier).\n"
    )


def _guarded(original: Any) -> Any:
    def wrapper(*popenargs: Any, **kwargs: Any) -> Any:
        item = _state["item"]
        if (
            _state["enforce"]
            and item is not None
            and _is_analysis_tool(_command_parts(popenargs, kwargs))
        ):
            command = _format_command(popenargs, kwargs)
            if os.environ.get("SUBPROCESS_GUARD") == "warn":
                _warn_spawns.append((item.nodeid, command))
            else:
                raise SubprocessGuardError(_violation_message(item.nodeid, command))
        return original(*popenargs, **kwargs)

    return wrapper


def install() -> None:
    """Monkeypatch the subprocess choke point. Idempotent."""
    from flawed import _process

    if _state["original"] is not None:
        return
    _state["original"] = _process._start_process
    _process._start_process = _guarded(_process._start_process)


# --- pytest hooks (registered as a plugin from the root conftest) ----------------


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> None:
    # tryfirst so the flag is set before this item's (possibly spawning) fixtures
    # are set up.
    _state["item"] = item
    _state["enforce"] = not _is_exempt(item)


@pytest.hookimpl(trylast=True)
def pytest_runtest_teardown(item: pytest.Item) -> None:
    # Be permissive outside the setup+call window (session-fixture finalizers,
    # collection, etc. are never attributed to a specific test).
    _state["item"] = None
    _state["enforce"] = False


def pytest_terminal_summary(terminalreporter: Any) -> None:
    if not _warn_spawns:
        return
    write = terminalreporter.write_line
    write("")
    write("SUBPROCESS GUARD (warn mode) — tests that spawned external subprocesses:")
    seen: set[str] = set()
    for nodeid, command in _warn_spawns:
        path = nodeid.split("::", 1)[0]
        if path in seen:
            continue
        seen.add(path)
        write(f"  {path}    (e.g. {command[:60]})")
