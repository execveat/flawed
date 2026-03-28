"""Per-repository file locking.

The CLI acquires an exclusive lock before any analysis runs.  This
prevents two ``flawed`` processes from writing to the same repo's
data directory simultaneously.

Properties:
- One lock per repo (keyed by identity hash).
- Non-blocking: if the lock is held, fail immediately.
- Automatic release on process exit (including crashes).
- CLI-level only — the Python API assumes single-writer.
"""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
from typing import TYPE_CHECKING

from flawed._config.paths import RepoIdentity, repo_lock_path

if TYPE_CHECKING:
    from types import TracebackType


class LockHeldError(Exception):
    """Raised when another flawed process holds the repo lock."""

    def __init__(self, identity: RepoIdentity) -> None:
        self.identity = identity
        super().__init__(
            f"Another flawed process is running on {identity.canonical!r}. "
            f"Lock: {repo_lock_path(Path(), identity)}",
        )


class RepoLock:
    """Exclusive per-repo file lock using ``fcntl``.

    Usage::

        lock = RepoLock(state_dir, identity)
        with lock:
            run_analysis()
    """

    def __init__(self, state_dir: Path, identity: RepoIdentity) -> None:
        self._lock_path = repo_lock_path(state_dir, identity)
        self._identity = identity
        self._fd: int | None = None

    def acquire(self) -> None:
        """Acquire the lock.  Raises ``LockHeldError`` if already taken."""
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self._lock_path), os.O_WRONLY | os.O_CREAT, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise LockHeldError(self._identity) from None
        self._fd = fd

    def release(self) -> None:
        """Release the lock if held."""
        if self._fd is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None

    def __enter__(self) -> RepoLock:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.release()
