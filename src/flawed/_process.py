"""Managed subprocess execution with whole-process-group cleanup.

Every engine-owned external command goes through this module.  Each launch is
isolated into its own POSIX session/process group, tracked in a live registry,
and paired with a small death-pipe watchdog.  Linux also gets
``PR_SET_PDEATHSIG`` for the direct child; per-launch cgroup scopes are not used
because unprivileged cgroup delegation and ``systemd-run --scope --pipe`` are not
portable across the laptop, CI, and sandbox command-capture contexts.  Timeouts,
Python shutdown, SIGINT / SIGTERM, and even hard parent death all converge on the
same invariant: any process group started by flawed is terminated as a whole
rather than only reaping its direct child.
"""

from __future__ import annotations

import atexit
import ctypes
import errno
import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, cast, overload

if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import FrameType

CompletedProcess = subprocess.CompletedProcess
CalledProcessError = subprocess.CalledProcessError
TimeoutExpired = subprocess.TimeoutExpired
DEVNULL = subprocess.DEVNULL
PIPE = subprocess.PIPE
STDOUT = subprocess.STDOUT

type _StreamData = str | bytes | None

_TREE_TERMINATE_GRACE_SECONDS = 0.5
_WATCHDOG_EXIT_GRACE_SECONDS = 1.0
_POSIX_PROCESS_GROUPS = hasattr(os, "setsid") and hasattr(os, "killpg") and hasattr(os, "getpgid")
_LINUX = sys.platform.startswith("linux")
_PR_SET_PDEATHSIG = 1

_WATCHDOG_CODE = r"""
import os
import signal
import sys
import time

pgid = int(sys.argv[1])
fd = int(sys.argv[2])
grace = float(sys.argv[3])
try:
    token = os.read(fd, 1)
except OSError:
    token = b""
finally:
    try:
        os.close(fd)
    except OSError:
        pass

# Parent writes one byte before closing the pipe when the launch finished and
# the process group has already been swept.  EOF without a token means the
# parent process died abruptly, so this watchdog is the only remaining cleanup
# path for the group.
if token:
    raise SystemExit(0)

for sig in (signal.SIGTERM, signal.SIGKILL):
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        raise SystemExit(0)
    except OSError:
        raise SystemExit(0)
    if sig == signal.SIGTERM:
        time.sleep(grace)
"""


@dataclass
class _ProcessGroupRecord:
    """Live process-group metadata for one managed launch."""

    pgid: int
    notify_fd: int | None
    watchdog: subprocess.Popen[bytes] | None


_lock = threading.RLock()
_live_groups: dict[int, _ProcessGroupRecord] = {}
_handlers_installed = threading.Event()
_previous_signal_handlers: dict[int, object] = {}


@overload
def run(
    *popenargs: Any,
    input: str | None = None,
    capture_output: bool = False,
    timeout: float | None = None,
    check: bool = False,
    text: Literal[True],
    **kwargs: Any,
) -> subprocess.CompletedProcess[str]: ...


@overload
def run(
    *popenargs: Any,
    input: bytes | None = None,
    capture_output: bool = False,
    timeout: float | None = None,
    check: bool = False,
    text: Literal[False] = False,
    **kwargs: Any,
) -> subprocess.CompletedProcess[bytes]: ...


@overload
def run(
    *popenargs: Any,
    input: _StreamData = None,
    capture_output: bool = False,
    timeout: float | None = None,
    check: bool = False,
    **kwargs: Any,
) -> subprocess.CompletedProcess[Any]: ...


def run(
    *popenargs: Any,
    input: _StreamData = None,  # noqa: A002 - keep subprocess.run-compatible API
    capture_output: bool = False,
    timeout: float | None = None,
    check: bool = False,
    text: bool | None = None,
    **kwargs: Any,
) -> subprocess.CompletedProcess[Any]:
    """Run a command with mandatory whole-process-group cleanup.

    The public contract intentionally follows :func:`subprocess.run` closely so
    engine call sites can migrate without bespoke wrappers.  The difference is
    that every POSIX launch uses a fresh session/process group, and any timeout,
    exception, interpreter shutdown, or parent death kills that group rather than
    only the direct child.
    """
    if text is not None:
        kwargs["text"] = text

    if input is not None:
        if kwargs.get("stdin") is not None:
            msg = "stdin and input arguments may not both be used"
            raise ValueError(msg)
        kwargs["stdin"] = PIPE

    if capture_output:
        if kwargs.get("stdout") is not None or kwargs.get("stderr") is not None:
            msg = "stdout and stderr arguments may not be used with capture_output"
            raise ValueError(msg)
        kwargs["stdout"] = PIPE
        kwargs["stderr"] = PIPE
    stdout: Any = None
    stderr: Any = None
    with _managed_popen(*popenargs, **kwargs) as (process, record):
        try:
            stdout, stderr = process.communicate(input, timeout=timeout)
        except TimeoutExpired as exc:
            _terminate_process_group(record)
            stdout, stderr = process.communicate()
            cast("Any", exc).output = stdout
            cast("Any", exc).stdout = stdout
            cast("Any", exc).stderr = stderr
            raise
        except BaseException:
            _terminate_process_group(record)
            raise

        returncode = process.poll()
        if returncode is None:
            returncode = process.wait()

    if check and returncode:
        raise CalledProcessError(returncode, process.args, output=stdout, stderr=stderr)
    return CompletedProcess(process.args, returncode, stdout, stderr)


@overload
def check_output(
    *popenargs: Any,
    timeout: float | None = None,
    text: Literal[True],
    **kwargs: Any,
) -> str: ...


@overload
def check_output(
    *popenargs: Any,
    timeout: float | None = None,
    text: Literal[False] = False,
    **kwargs: Any,
) -> bytes: ...


@overload
def check_output(
    *popenargs: Any,
    timeout: float | None = None,
    **kwargs: Any,
) -> bytes: ...


def check_output(
    *popenargs: Any,
    timeout: float | None = None,
    text: bool | None = None,
    **kwargs: Any,
) -> str | bytes:
    """Return command stdout using managed whole-tree subprocess execution."""
    if text is not None:
        kwargs["text"] = text

    if kwargs.get("stdout") is not None:
        msg = "stdout argument not allowed, it will be overridden."
        raise ValueError(msg)
    completed = run(*popenargs, stdout=PIPE, timeout=timeout, check=True, **kwargs)
    output = completed.stdout
    if output is None:
        return "" if kwargs.get("text") or kwargs.get("universal_newlines") else b""
    return cast("str | bytes", output)


@contextmanager
def popen(*popenargs: Any, **kwargs: Any) -> Iterator[subprocess.Popen[Any]]:
    """Launch a managed process and kill its process group on context exit.

    This is the low-level boundary for engine code that needs streaming process
    access.  Prefer :func:`run` / :func:`check_output` when possible.  Exiting the
    context always sweeps the whole process group, even if the direct child has
    already returned, so background grandchildren cannot survive normal return,
    timeout, exception, or caller teardown.
    """
    with _managed_popen(*popenargs, **kwargs) as (process, _record):
        yield process


@contextmanager
def _managed_popen(
    *popenargs: Any,
    **kwargs: Any,
) -> Iterator[tuple[subprocess.Popen[Any], _ProcessGroupRecord]]:
    process = _start_process(*popenargs, **kwargs)
    record = _register_process_group(process)
    try:
        yield process, record
    except BaseException:
        _terminate_process_group(record)
        if process.poll() is None:
            with suppress(OSError):
                process.wait()
        raise
    finally:
        _terminate_process_group(record)
        if process.poll() is None:
            with suppress(OSError):
                process.wait()
        _unregister_process_group(record)


def cleanup_all() -> None:
    """Terminate every process group currently tracked by this interpreter."""
    with _lock:
        records = tuple(_live_groups.values())
    for record in records:
        _terminate_process_group(record)
        _unregister_process_group(record)


def _start_process(
    *popenargs: Any,
    **kwargs: Any,
) -> subprocess.Popen[Any]:
    if not _POSIX_PROCESS_GROUPS:
        msg = "flawed managed subprocesses require POSIX process-group support"
        raise RuntimeError(msg)
    if "start_new_session" in kwargs and kwargs["start_new_session"] is not True:
        msg = "managed subprocesses always use start_new_session=True"
        raise ValueError(msg)
    if "preexec_fn" in kwargs:
        msg = "managed subprocesses own preexec_fn for parent-death safety"
        raise ValueError(msg)

    _ensure_shutdown_hooks_installed()
    kwargs["start_new_session"] = True
    if _LINUX:
        kwargs["preexec_fn"] = _linux_set_parent_death_signal
    _apply_lenient_text_decoding(kwargs)
    return subprocess.Popen(*popenargs, **kwargs)


def _apply_lenient_text_decoding(kwargs: dict[str, Any]) -> None:
    """Default text-mode subprocess decoding to never crash on non-UTF-8 output.

    A subprocess we manage (e.g. a type-enrichment oracle) can emit bytes that
    are not valid UTF-8. With Python's default strict decoding, ``communicate()``
    raises ``UnicodeDecodeError`` and aborts the whole analysis — a repo-wide
    false negative, which is the project's #1 sin. We instead decode with
    ``errors="replace"`` so the run survives.

    We deliberately use ``"replace"`` rather than ``"surrogateescape"``: decoded
    stdout may be re-encoded *strictly* to UTF-8 downstream (e.g. when persisting
    raw artifacts via ``Path.write_text(..., encoding="utf-8")``), so lone
    surrogates would merely relocate the crash to write time. ``U+FFFD``
    round-trips cleanly through
    UTF-8 and preserves JSON structure (the bad bytes live inside string values),
    so the replacement is lossy only for the individual undecodable byte. A
    caller that sets ``errors`` explicitly keeps full control.
    """
    text_mode = bool(
        kwargs.get("text")
        or kwargs.get("universal_newlines")
        or kwargs.get("encoding")
        or kwargs.get("errors")
    )
    if text_mode and "errors" not in kwargs:
        kwargs.setdefault("encoding", "utf-8")
        kwargs["errors"] = "replace"


REPLACEMENT_CHARACTER = "�"
"""Codepoint ``errors="replace"`` substitutes for each undecodable input byte.

Paired with :func:`_apply_lenient_text_decoding`: that function chooses the
``"replace"`` error handler, and this constant is the marker it leaves behind.
Keep the two together so a future change to the decode policy updates both the
substitution and its detector in one place.
"""


def contains_decode_replacement(text: str) -> bool:
    """Report whether lenient text decoding dropped any undecodable bytes.

    :func:`_apply_lenient_text_decoding` decodes managed-subprocess text with
    ``errors="replace"`` so a non-UTF-8 byte can never crash the whole run (a
    repo-wide false negative, the project's #1 sin).  The cost is silence: the
    caller receives a ``str`` with no signal that ``U+FFFD`` stands in for a byte
    that was lost.  This predicate recovers that signal so a caller can surface
    an honest gap (e.g. an L1 ``AnalysisGap``) instead of analysing the corrupted
    text as if it were faithful.

    This is a pure string check by design — it stays free of any Layer-1 type so
    that low-level process plumbing never has to depend on the analysis layers.
    """
    return REPLACEMENT_CHARACTER in text


def _register_process_group(process: subprocess.Popen[Any]) -> _ProcessGroupRecord:
    try:
        pgid = os.getpgid(process.pid)
    except OSError:
        pgid = process.pid

    notify_fd: int | None = None
    watchdog: subprocess.Popen[bytes] | None = None
    read_fd, write_fd = os.pipe()
    try:
        watchdog = _start_watchdog(read_fd, pgid)
        notify_fd = write_fd
    except OSError:
        os.close(write_fd)
        _terminate_process_group(_ProcessGroupRecord(pgid=pgid, notify_fd=None, watchdog=None))
        raise
    finally:
        os.close(read_fd)
    record = _ProcessGroupRecord(pgid=pgid, notify_fd=notify_fd, watchdog=watchdog)
    with _lock:
        _live_groups[pgid] = record
    return record


def _start_watchdog(read_fd: int, pgid: int) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            _WATCHDOG_CODE,
            str(pgid),
            str(read_fd),
            str(_TREE_TERMINATE_GRACE_SECONDS),
        ],
        stdin=DEVNULL,
        stdout=DEVNULL,
        stderr=DEVNULL,
        close_fds=True,
        pass_fds=(read_fd,),
        start_new_session=True,
    )


def _terminate_process_group(record: _ProcessGroupRecord) -> None:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(record.pgid, sig)
        except ProcessLookupError:
            return
        except OSError as exc:
            if exc.errno == errno.ESRCH:
                return
            return
        if sig == signal.SIGTERM:
            time.sleep(_TREE_TERMINATE_GRACE_SECONDS)


def _unregister_process_group(record: _ProcessGroupRecord) -> None:
    with _lock:
        current = _live_groups.get(record.pgid)
        if current is record:
            del _live_groups[record.pgid]
    _disarm_watchdog(record)


def _disarm_watchdog(record: _ProcessGroupRecord) -> None:
    if record.notify_fd is not None:
        with suppress(OSError):
            os.write(record.notify_fd, b".")
        with suppress(OSError):
            os.close(record.notify_fd)
        record.notify_fd = None

    watchdog = record.watchdog
    if watchdog is None:
        return
    try:
        watchdog.wait(timeout=_WATCHDOG_EXIT_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        watchdog.terminate()
        try:
            watchdog.wait(timeout=_WATCHDOG_EXIT_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            watchdog.kill()
            watchdog.wait()
    record.watchdog = None


def _ensure_shutdown_hooks_installed() -> None:
    with _lock:
        if _handlers_installed.is_set():
            return
        atexit.register(cleanup_all)
        for signum in _shutdown_signals():
            try:
                _previous_signal_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, _handle_shutdown_signal)
            except (OSError, ValueError):
                continue
        _handlers_installed.set()


def _shutdown_signals() -> tuple[int, ...]:
    signals: list[int] = []
    for name in ("SIGINT", "SIGTERM"):
        signum = getattr(signal, name, None)
        if isinstance(signum, signal.Signals):
            signals.append(int(signum))
    return tuple(signals)


def _handle_shutdown_signal(signum: int, frame: FrameType | None) -> None:
    cleanup_all()
    previous = _previous_signal_handlers.get(signum, signal.SIG_DFL)
    if callable(previous):
        previous(signum, frame)
        return
    if previous == signal.SIG_IGN:
        return
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


def _linux_set_parent_death_signal() -> None:
    """Ask Linux to kill the direct child immediately if flawed dies.

    Process groups and the death-pipe watchdog are the cross-platform subtree
    mechanism.  ``PR_SET_PDEATHSIG`` is an extra Linux floor for the small window
    before the watchdog is armed and for direct-child death latency.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = cast("Any", libc.prctl)
    prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)
    if os.getppid() == 1:
        os.kill(os.getpid(), signal.SIGKILL)


# Keep the watchdog code syntactically compact for ``python -c`` without relying
# on indentation from this module's source layout.
_WATCHDOG_CODE = textwrap.dedent(_WATCHDOG_CODE).strip()
