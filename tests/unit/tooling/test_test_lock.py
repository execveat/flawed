"""Tests for the pytest concurrency lock (tools/_test_lock.py).

Covers the three properties that make it safe for multiple agents in one checkout:
acquire/release, contention fails fast (no deadlock), and a killed holder's lock is
recovered immediately (flock is kernel-released — no stale-lock bookkeeping).
"""

from __future__ import annotations

import subprocess
import sys
import time
from typing import TYPE_CHECKING

import pytest

from tools._test_lock import LOCK_FILENAME, PytestLockTimeoutError, pytest_lock

if TYPE_CHECKING:
    from pathlib import Path

# A subprocess that grabs the flock on <dir>/.pytest.lock, announces LOCKED, then
# blocks — so the parent can test contention against a real, separate-process holder.
_HOLDER_SRC = (
    "import fcntl, os, sys, time\n"
    f"fd = os.open(os.path.join(sys.argv[1], {LOCK_FILENAME!r}), os.O_RDWR | os.O_CREAT)\n"
    "fcntl.flock(fd, fcntl.LOCK_EX)\n"
    "sys.stdout.write('LOCKED\\n'); sys.stdout.flush()\n"
    "time.sleep(60)\n"
)


def _spawn_holder(lock_dir: Path) -> subprocess.Popen[str]:
    proc = subprocess.Popen(
        [sys.executable, "-c", _HOLDER_SRC, str(lock_dir)],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    first_line = proc.stdout.readline()
    assert first_line.strip() == "LOCKED", f"holder failed to acquire: {first_line!r}"
    return proc


def test_acquire_and_release(tmp_path: Path) -> None:
    with pytest_lock(tmp_path, timeout=1.0):
        assert (tmp_path / LOCK_FILENAME).exists()
    # Released on exit -> immediately re-acquirable in the same process.
    with pytest_lock(tmp_path, timeout=1.0):
        pass


def test_contention_times_out_with_clear_message(tmp_path: Path) -> None:
    holder = _spawn_holder(tmp_path)
    try:
        start = time.monotonic()
        with (
            pytest.raises(PytestLockTimeoutError, match="could not acquire the test lock"),
            pytest_lock(tmp_path, timeout=0.5),
        ):
            pass
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"acquire hung ({elapsed:.1f}s) instead of timing out at 0.5s"
    finally:
        holder.terminate()
        holder.wait(timeout=5)


def test_stale_lock_recovered_after_holder_killed(tmp_path: Path) -> None:
    holder = _spawn_holder(tmp_path)
    holder.kill()  # SIGKILL -> kernel releases the flock immediately, no stale state
    holder.wait(timeout=5)
    start = time.monotonic()
    with pytest_lock(tmp_path, timeout=2.0):
        pass
    elapsed = time.monotonic() - start
    assert elapsed < 1.0, f"stale lock not recovered promptly ({elapsed:.2f}s)"
