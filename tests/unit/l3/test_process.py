"""Regression tests for managed subprocess tree cleanup."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from textwrap import dedent
from typing import TYPE_CHECKING

import pytest

from flawed import _process as managed_process
from tests.helpers.paths import SRC

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


_CHILD_SCRIPT = dedent(
    """
    from __future__ import annotations

    import json
    import os
    import subprocess
    import sys
    import time
    from pathlib import Path

    pid_file = Path(sys.argv[1])
    grandchild = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    pid_file.write_text(
        json.dumps({"child": os.getpid(), "grandchild": grandchild.pid}),
        encoding="utf-8",
    )
    try:
        time.sleep(120)
    finally:
        grandchild.terminate()
    """,
)

_PARENT_SCRIPT = dedent(
    """
    from __future__ import annotations

    import sys

    from flawed import _process as managed_process

    managed_process.run(
        [sys.executable, sys.argv[1], sys.argv[2]],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    """,
)


def test_timeout_kills_child_process_group_and_grandchild(tmp_path: Path) -> None:
    child_script = _write_script(tmp_path, "child_tree.py", _CHILD_SCRIPT)
    pid_file = tmp_path / "timeout-pids.json"

    with pytest.raises(managed_process.TimeoutExpired):
        managed_process.run(
            [sys.executable, str(child_script), str(pid_file)],
            capture_output=True,
            text=True,
            timeout=0.5,
            check=False,
        )

    pids = _read_pids(pid_file)
    _assert_pids_dead(pids)


def test_popen_context_exit_kills_child_process_group_and_grandchild(tmp_path: Path) -> None:
    child_script = _write_script(tmp_path, "child_tree.py", _CHILD_SCRIPT)
    pid_file = tmp_path / "context-pids.json"

    with managed_process.popen(
        [sys.executable, str(child_script), str(pid_file)],
        stdout=managed_process.DEVNULL,
        stderr=managed_process.DEVNULL,
    ):
        pids = _wait_for_pids(pid_file)

    _assert_pids_dead(pids)


def test_hard_parent_death_kills_child_process_group_and_grandchild(tmp_path: Path) -> None:
    child_script = _write_script(tmp_path, "child_tree.py", _CHILD_SCRIPT)
    parent_script = _write_script(tmp_path, "parent_runner.py", _PARENT_SCRIPT)
    pid_file = tmp_path / "parent-death-pids.json"
    env = os.environ.copy()
    src_path = str(SRC)
    env["PYTHONPATH"] = (
        f"{src_path}{os.pathsep}{env['PYTHONPATH']}" if env.get("PYTHONPATH") else src_path
    )

    parent = subprocess.Popen(
        [sys.executable, str(parent_script), str(child_script), str(pid_file)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    try:
        pids = _wait_for_pids(pid_file)
        os.kill(parent.pid, signal.SIGKILL)
        parent.wait(timeout=10)
        _assert_pids_dead(pids)
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait()


def _write_script(tmp_path: Path, name: str, content: str) -> Path:
    script = tmp_path / name
    script.write_text(content, encoding="utf-8")
    return script


def _wait_for_pids(pid_file: Path) -> Mapping[str, int]:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if pid_file.exists():
            return _read_pids(pid_file)
        time.sleep(0.05)
    pytest.fail(f"process tree did not report pids to {pid_file}")


def _read_pids(pid_file: Path) -> Mapping[str, int]:
    if not pid_file.exists():
        pytest.fail(f"process tree did not report pids to {pid_file}")
    payload = json.loads(pid_file.read_text(encoding="utf-8"))
    return {name: int(pid) for name, pid in payload.items()}


def _assert_pids_dead(pids: Mapping[str, int]) -> None:
    live = dict(pids)
    deadline = time.monotonic() + 10
    while live and time.monotonic() < deadline:
        live = {name: pid for name, pid in live.items() if _pid_exists(pid)}
        if live:
            time.sleep(0.05)
    assert live == {}


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


# A child that writes valid text around raw non-UTF-8 bytes on stdout. an external tool
# does this in the wild; strict decoding would crash the whole analysis (a repo-wide
# false negative), so managed_process must decode leniently by default.
_NON_UTF8_STDOUT = (
    'import sys; sys.stdout.buffer.write(b"valid\\xff\\xfemore"); sys.stdout.buffer.flush()'
)


def test_run_text_mode_survives_non_utf8_stdout() -> None:
    result = managed_process.run(
        [sys.executable, "-c", _NON_UTF8_STDOUT],
        capture_output=True,
        text=True,
        check=False,
    )
    # No UnicodeDecodeError raised; valid surrounding text preserved; each bad byte
    # becomes U+FFFD, which re-encodes cleanly to UTF-8 downstream.
    assert result.returncode == 0
    assert result.stdout == "valid��more"


def test_check_output_text_mode_survives_non_utf8_stdout() -> None:
    output = managed_process.check_output(
        [sys.executable, "-c", _NON_UTF8_STDOUT],
        text=True,
    )
    assert output == "valid��more"


def test_run_respects_explicit_errors_override() -> None:
    # A caller that explicitly asks for strict decoding keeps full control.
    with pytest.raises(UnicodeDecodeError):
        managed_process.run(
            [sys.executable, "-c", _NON_UTF8_STDOUT],
            capture_output=True,
            text=True,
            errors="strict",
            check=False,
        )
