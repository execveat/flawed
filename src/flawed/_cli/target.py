"""Target resolution — map CLI arguments to verified repository paths.

``flawed``  with no args        → cwd
``flawed /path/to/repo``        → resolved path, validate it's a directory
``flawed -r 'class:target'``    → ribrarian selector(s) → repo root(s)

A command may receive several positional paths and/or several ``-r`` selectors;
:func:`resolve_targets` merges them into an ordered, deduplicated list of repo
roots. The engine always operates on cwd, so each repo is scanned inside
:func:`entered_target`, which changes into the repo and *restores the previous
cwd afterwards* — this is what lets a single invocation scan multiple repos
without leaking the working directory between them.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from flawed._config.paths import RepoIdentity

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence


class TargetError(Exception):
    """Raised when the target cannot be resolved."""


def _validate_dir(raw: str) -> Path:
    """Resolve and validate a single filesystem target path.

    Raises:
        TargetError: If the target does not exist or is not a directory.
    """
    path = Path(raw).expanduser().resolve()
    if not path.exists():
        msg = f"Target does not exist: {raw}"
        raise TargetError(msg)
    if not path.is_dir():
        msg = f"Target is not a directory: {raw}"
        raise TargetError(msg)
    return path


def resolve_target(raw: str | None) -> Path:
    """Turn a single CLI target argument into a validated directory path.

    Args:
        raw: A filesystem path, or ``None`` for cwd.

    Returns:
        Resolved absolute path to the target directory.

    Raises:
        TargetError: If the target does not exist or is not a directory.
    """
    if raw is None:
        return Path.cwd().resolve()
    return _validate_dir(raw)


def resolve_targets(paths: Sequence[str], selectors: Sequence[str]) -> list[Path]:
    """Resolve positional *paths* and ribrarian *selectors* to ordered repo roots.

    Positional paths are validated as directories; selectors are resolved through
    the optional ribrarian bridge (see :mod:`flawed._cli.ribrarian_bridge`). The
    two sets are merged in order — paths first, then selector results — with
    duplicate roots collapsed, keeping first-seen order so scan order is stable.

    When both are empty the result is ``[cwd]``, preserving the historical
    no-argument behavior (scan the current directory).

    Args:
        paths: Positional filesystem path arguments (possibly empty).
        selectors: ribrarian selector strings from ``-r/--ribrarian`` (possibly empty).

    Returns:
        A non-empty, deduplicated list of repo-root paths.

    Raises:
        TargetError: If a positional path does not exist or is not a directory.
        flawed._cli.ribrarian_bridge.RibrarianBridgeError: If a selector cannot
            be resolved (ribrarian missing, or zero matches with source on disk).
    """
    if not paths and not selectors:
        return [Path.cwd().resolve()]

    resolved: list[Path] = []
    seen: set[Path] = set()

    def _add(path: Path) -> None:
        if path not in seen:
            seen.add(path)
            resolved.append(path)

    for raw in paths:
        _add(_validate_dir(raw))

    if selectors:
        # Deferred import keeps the ribrarian seam out of module import time and
        # avoids a target<->bridge import cycle.
        # INTERNAL-INTEGRATION(ribrarian): optional private integration reached only
        # through the bridge; injected at install time. Do NOT remove. See
        # ribrarian_bridge.py.
        from flawed._cli.ribrarian_bridge import resolve as resolve_selectors

        for path in resolve_selectors(selectors):
            _add(path)

    return resolved


@contextmanager
def entered_target(target: Path) -> Iterator[RepoIdentity]:
    """Enter *target* for the duration of the block, then restore the prior cwd.

    The engine always operates on cwd, so scanning a repo means ``os.chdir`` into
    it. Yielding inside a context manager that restores the original cwd in a
    ``finally`` is what makes multi-target runs safe: cwd is returned to its
    starting value between repos and after the run, even if the body raises (or
    calls ``sys.exit``, which unwinds as an exception).

    Yields:
        The :class:`RepoIdentity` for *target* (used for config overrides, the
        data directory, and locking).
    """
    previous = Path.cwd()
    os.chdir(target)
    try:
        yield RepoIdentity.from_path(target)
    finally:
        os.chdir(previous)
