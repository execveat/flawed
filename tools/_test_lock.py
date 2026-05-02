"""Advisory lock that serializes the pytest step across concurrent runs in one checkout.

Multiple agents share a single checkout; two concurrent pytest runs corrupt
testmon's ``.testmondata`` (SQLite) and clobber ``local/test-results.json``. This
serializes *only* the pytest step — the other gate steps use self-healing caches
(mypy/grimp rebuild on corruption), so they stay unlocked and parallel-friendly.

Why ``fcntl.flock`` and not a PID file: an advisory ``flock`` is released by the
kernel the instant the holding process dies, so a crashed or ``kill -9``'d runner
frees the lock immediately — there is no stale lock to detect, no PID-liveness
probe, and no PID-reuse / TOCTOU race. Correctness is entirely the kernel's. The
PID written into the lockfile is purely cosmetic: it lets a waiter print a
human-readable "held by PID N" message. (flock is advisory and unreliable on NFS;
that is fine for a local dev checkout, which is the only place this runs.)

The acquire is timeout-capped, so it can never deadlock: if the lock is not free
within the configured budget the caller gets a clear, actionable failure.

(Named ``pytest_lock`` / ``PytestLockTimeoutError`` rather than ``test_*``/``Test*``
to avoid pytest collecting them as a test and ruff applying pytest-style rules.)
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

LOCK_FILENAME = ".pytest.lock"


class PytestLockTimeoutError(RuntimeError):
    """Raised when the pytest lock cannot be acquired within the timeout."""


def _holder_pid(fd: int) -> int | None:
    """Best-effort read of the PID recorded by the current holder (diagnostic only)."""
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        text = os.read(fd, 32).decode(errors="replace").strip()
    except OSError:
        return None
    try:
        return int(text)
    except ValueError:
        return None


@contextlib.contextmanager
def pytest_lock(root: Path, *, timeout: float, poll: float = 0.25) -> Iterator[None]:
    """Hold an exclusive advisory lock on ``root/.pytest.lock`` for the block body.

    Retries non-blockingly every ``poll`` seconds up to ``timeout`` seconds; raises
    :class:`PytestLockTimeoutError` if it cannot acquire in time (no deadlock). The
    lock is released when the block exits *or* if this process dies (kernel-released).
    """
    lock_path = root / LOCK_FILENAME
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        deadline = time.monotonic() + timeout
        announced = False
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    holder = _holder_pid(fd)
                    held_by = f" (PID {holder})" if holder else ""
                    msg = (
                        f"could not acquire the test lock within {timeout:g}s — another "
                        f"test run is active in this checkout{held_by}; retry, or run in a "
                        f"separate git worktree."
                    )
                    raise PytestLockTimeoutError(msg) from None
                if not announced:
                    holder = _holder_pid(fd)
                    held_by = f" (held by PID {holder})" if holder else ""
                    print(f"  ....  waiting to acquire the test lock{held_by} …", flush=True)
                    announced = True
                time.sleep(poll)
        # Acquired. Record our PID so a concurrent waiter can name us. Correctness
        # does not depend on this content — only the flock does.
        with contextlib.suppress(OSError):
            os.ftruncate(fd, 0)
            os.write(fd, str(os.getpid()).encode())
        try:
            yield
        finally:
            # Clear the PID marker on clean exit; on a crash the kernel still frees
            # the flock, so the next acquirer is never blocked by a stale marker.
            with contextlib.suppress(OSError):
                os.ftruncate(fd, 0)
    finally:
        os.close(fd)  # releases the advisory lock
