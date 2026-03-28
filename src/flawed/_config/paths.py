"""XDG path resolution and repository identity.

This module is the single owner of:
- XDG base directory resolution
- Repository identity derivation (git remote or filesystem path)
- Per-repo data/state directory computation
- Lock file path computation
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from flawed import _process as managed_process
from flawed._config.schema import CacheInvalidation, ConfigError

if TYPE_CHECKING:
    from collections.abc import Iterator

_HASH_PREFIX_LEN = 16
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
_GIT_TIMEOUT_SECONDS = 5

_IGNORED_SOURCE_DIR_NAMES = frozenset(
    {
        "__pycache__",
        "cache",
        "local",
        "venv",
        "env",
        "virtualenv",
        "node_modules",
        "vendor",
        "vendors",
        "third_party",
        "site-packages",
        "dist-packages",
    }
)


def xdg_config_home() -> Path:
    """Return ``$XDG_CONFIG_HOME`` or ``~/.config``."""
    raw = os.environ.get("XDG_CONFIG_HOME")
    return Path(raw) if raw else Path.home() / ".config"


def xdg_data_home() -> Path:
    """Return ``$XDG_DATA_HOME`` or ``~/.local/share``."""
    raw = os.environ.get("XDG_DATA_HOME")
    return Path(raw) if raw else Path.home() / ".local" / "share"


def xdg_state_home() -> Path:
    """Return ``$XDG_STATE_HOME`` or ``~/.local/state``."""
    raw = os.environ.get("XDG_STATE_HOME")
    return Path(raw) if raw else Path.home() / ".local" / "state"


def flawed_config_dir() -> Path:
    """Return the flawed configuration directory."""
    return xdg_config_home() / "flawed"


def flawed_data_dir() -> Path:
    """Return the default flawed data directory."""
    return xdg_data_home() / "flawed"


def flawed_state_dir() -> Path:
    """Return the default flawed state directory."""
    return xdg_state_home() / "flawed"


# ── Repository content hashing ────────────────────────────────────


def repo_content_hash(
    repo_path: Path,
    strategy: CacheInvalidation = CacheInvalidation.AUTO,
) -> str:
    """Return a content hash for the repository at *repo_path*.

    The *strategy* selects how the hash is derived (see
    :class:`~flawed._config.schema.CacheInvalidation` for the full rationale):

    - ``AUTO`` (default): git ``HEAD`` (+ dirty-tree suffix) for git repos,
      falling back to an mtime digest for non-git directories.  This is the
      historical behaviour and the recommended default.
    - ``GIT_HASH``: force the git ``HEAD`` (+ dirty) hash.  Raises
      ``ConfigError`` for a non-git target rather than silently falling back.
    - ``MTIME``: digest of sorted ``(relative_path, mtime_ns)`` pairs over all
      ``.py`` files.  Fast and git-agnostic; trusts filesystem mtimes.
    - ``CONTENT_HASH``: digest of sorted ``(relative_path, file_bytes)`` over
      all ``.py`` files.  Strongest (catches edits mtime would miss) and slowest.
    """
    resolved = repo_path.resolve()

    if strategy is CacheInvalidation.MTIME:
        return _mtime_digest(resolved)
    if strategy is CacheInvalidation.CONTENT_HASH:
        return _content_digest(resolved)
    if strategy is CacheInvalidation.GIT_HASH:
        git_hash = _git_content_hash(resolved)
        if git_hash is None:
            msg = (
                f"cache_invalidation='git-hash' requires a git repository, but "
                f"{resolved} is not one (or git is unavailable). Use 'auto', "
                f"'mtime', or 'content-hash' for non-git targets."
            )
            raise ConfigError(msg)
        return git_hash

    # AUTO: git when available, else the mtime digest.
    git_hash = _git_content_hash(resolved)
    if git_hash is not None:
        return git_hash
    return _mtime_digest(resolved)


def _git_content_hash(resolved: Path) -> str | None:
    """Return the git ``HEAD`` (+ dirty suffix) hash, or ``None`` if not git.

    For git repos, combines the HEAD commit hash with a dirty-tree suffix when
    uncommitted ``.py`` changes exist (staged or unstaged), preventing stale
    cache hits after editing files without committing.  Returns ``None`` when
    *resolved* is not a git worktree or git is unavailable.
    """
    try:
        head = managed_process.check_output(
            ["git", "-C", str(resolved), "rev-parse", "HEAD"],
            stderr=managed_process.DEVNULL,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
        ).strip()
        dirty_status = managed_process.check_output(
            ["git", "-C", str(resolved), "status", "--porcelain=v1", "-z", "--", "*.py"],
            stderr=managed_process.DEVNULL,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except (managed_process.CalledProcessError, FileNotFoundError, managed_process.TimeoutExpired):
        return None
    dirty_status = _filter_git_status(dirty_status)
    if dirty_status:
        suffix = _git_dirty_suffix(resolved, dirty_status)
        return f"{head}:{suffix}"
    return head


def _mtime_digest(resolved: Path) -> str:
    """SHA-256 digest of ``(relative_path, mtime_ns)`` over all ``.py`` files."""
    hasher = hashlib.sha256()
    for py_file in iter_python_source_files(resolved):
        rel = py_file.relative_to(resolved)
        hasher.update(f"{rel}:{py_file.stat().st_mtime_ns}\n".encode())
    return hasher.hexdigest()[:32]


def _content_digest(resolved: Path) -> str:
    """SHA-256 digest of ``(relative_path, file_bytes)`` over all ``.py`` files.

    Hashes each file's content (not its mtime), so it detects edits that leave
    mtime unchanged at the cost of reading every source file.
    """
    hasher = hashlib.sha256()
    for py_file in iter_python_source_files(resolved):
        rel = py_file.relative_to(resolved)
        hasher.update(f"{rel}:".encode())
        hasher.update(hashlib.sha256(py_file.read_bytes()).digest())
        hasher.update(b"\n")
    return hasher.hexdigest()[:32]


def iter_python_source_files(root: Path) -> Iterator[Path]:
    """Yield Python files under *root* while pruning irrelevant trees."""
    try:
        children = sorted(root.iterdir())
    except OSError:
        return

    for child in children:
        if child.is_dir() and not child.is_symlink():
            if not _is_ignored_source_dir(child.name):
                yield from iter_python_source_files(child)
            continue
        if child.is_file() and child.name.endswith(".py"):
            yield child


def _is_ignored_source_dir(name: str) -> bool:
    return name.startswith(".") or name in _IGNORED_SOURCE_DIR_NAMES or name.endswith(".egg-info")


def _is_ignored_source_path(path: Path) -> bool:
    return any(_is_ignored_source_dir(part) for part in path.parts[:-1])


def _filter_git_status(dirty_status: bytes) -> bytes:
    records = _git_status_records(dirty_status)
    kept = [
        record
        for record in records
        if not all(_is_ignored_source_path(path) for path in _git_status_record_paths(record))
    ]
    if not kept:
        return b""
    return b"\0".join(part for record in kept for part in record) + b"\0"


def _git_dirty_suffix(repo_path: Path, dirty_status: bytes) -> str:
    hasher = hashlib.sha256()
    hasher.update(dirty_status)
    hasher.update(_git_tracked_python_index(repo_path))

    for record in _git_status_records(dirty_status):
        for rel_path in _git_status_record_paths(record):
            path = repo_path / rel_path
            if not path.exists():
                continue
            stat = path.stat()
            hasher.update(f"{rel_path}:{stat.st_size}:{stat.st_mtime_ns}\n".encode())

    return hasher.hexdigest()[:16]


def _git_status_records(dirty_status: bytes) -> tuple[tuple[bytes, ...], ...]:
    records: list[tuple[bytes, ...]] = []
    parts = [part for part in dirty_status.split(b"\0") if part]
    index = 0
    while index < len(parts):
        entry = parts[index]
        status = entry[:2]
        index += 1
        if status[:1] in (b"R", b"C") and index < len(parts):
            records.append((entry, parts[index]))
            index += 1
        else:
            records.append((entry,))
    return tuple(records)


def _git_status_record_paths(record: tuple[bytes, ...]) -> tuple[Path, ...]:
    entry = record[0]
    paths: list[Path] = []
    if len(entry) > 3:
        paths.append(Path(entry[3:].decode(errors="surrogateescape")))
    paths.extend(Path(extra_path.decode(errors="surrogateescape")) for extra_path in record[1:])
    return tuple(paths)


def _git_tracked_python_index(repo_path: Path) -> bytes:
    try:
        return managed_process.check_output(
            ["git", "-C", str(repo_path), "ls-files", "-s", "-z", "--", "*.py"],
            stderr=managed_process.DEVNULL,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except (managed_process.CalledProcessError, FileNotFoundError, managed_process.TimeoutExpired):
        return b""


# ── Repository identity ────────────────────────────────────────────


@dataclass(frozen=True)
class RepoIdentity:
    """Stable identity for a repository.

    Attributes:
        canonical: The primary identifier — a GitHub slug
            (``owner/name``) when available, otherwise the resolved
            absolute filesystem path.
        path: The absolute filesystem path where the repo lives.
        hash: A short deterministic hash derived from *canonical*,
            used for directory and lock-file naming.
    """

    canonical: str
    path: Path
    hash: str

    @property
    def display_name(self) -> str:
        """A portable, never-absolute label for the repo.

        The :attr:`canonical` slug (``owner/name``) when available; for a local
        repo — whose canonical identity falls back to the absolute filesystem
        path — the repo directory name instead. Use this for human display and
        machine output (``--json`` metadata, summaries) so neither leaks a home
        or install path that would differ across machines.
        """
        if Path(self.canonical).is_absolute():
            return self.path.name
        return self.canonical

    @staticmethod
    def from_path(repo_path: Path) -> RepoIdentity:
        """Derive identity from a filesystem path.

        Uses a GitHub slug from the git ``origin`` remote only when
        *repo_path* is the git worktree root.  A subdirectory target is a
        distinct analysis target, even when it lives inside a larger checkout,
        so it falls back to the resolved target path.  This keeps cache,
        profile, and lock identity scoped to the directory the user asked to
        scan.
        """
        resolved = repo_path.resolve()
        canonical = _extract_github_slug(resolved) or str(resolved)
        h = hashlib.sha256(canonical.encode()).hexdigest()[:_HASH_PREFIX_LEN]
        return RepoIdentity(canonical=canonical, path=resolved, hash=h)


def _extract_github_slug(repo_path: Path) -> str | None:
    """Return ``owner/name`` from the git origin URL for worktree roots only."""
    root = _git_worktree_root(repo_path)
    if root is None or root != repo_path.resolve():
        return None

    try:
        url = managed_process.check_output(
            ["git", "-C", str(root), "remote", "get-url", "origin"],
            stderr=managed_process.DEVNULL,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
        ).strip()
    except (managed_process.CalledProcessError, FileNotFoundError, managed_process.TimeoutExpired):
        return None

    for prefix in ("https://github.com/", "git@github.com:"):
        if url.startswith(prefix):
            return url[len(prefix) :].removesuffix(".git")
    return None


def _git_worktree_root(repo_path: Path) -> Path | None:
    """Return the enclosing git worktree root for *repo_path*, if any."""
    try:
        raw_root = managed_process.check_output(
            ["git", "-C", str(repo_path), "rev-parse", "--show-toplevel"],
            stderr=managed_process.DEVNULL,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
        ).strip()
    except (managed_process.CalledProcessError, FileNotFoundError, managed_process.TimeoutExpired):
        return None
    return Path(raw_root).resolve()


# ── Per-repo directory helpers ─────────────────────────────────────


def repo_cache_name(identity: RepoIdentity) -> str:
    """Return the readable per-repo cache directory name.

    GitHub slugs use ``owner__repo`` so cache paths are easy to inspect.
    Non-Git paths keep the directory basename and append the stable identity
    hash to avoid collisions between unrelated repositories with the same name.
    """
    if "/" in identity.canonical and not identity.canonical.startswith("/"):
        raw_name = identity.canonical.replace("/", "__")
        return _SAFE_NAME_RE.sub("_", raw_name).strip("._-") or identity.hash

    basename = identity.path.name or "repo"
    safe = _SAFE_NAME_RE.sub("_", basename).strip("._-") or "repo"
    return f"{safe}--{identity.hash}"


def repo_data_dir(data_dir: Path, identity: RepoIdentity) -> Path:
    """Return the per-repo cache/artifact directory under *data_dir*."""
    return data_dir / repo_cache_name(identity)


def repo_lock_path(state_dir: Path, identity: RepoIdentity) -> Path:
    """Return ``<state_dir>/locks/<hash>.lock``."""
    return state_dir / "locks" / f"{identity.hash}.lock"


def resolve_paths(
    raw_paths: tuple[Path | str, ...],
    base_dir: Path | None,
) -> tuple[Path | str, ...]:
    """Resolve relative paths against *base_dir*.

    ``"builtin"`` tokens pass through unchanged.
    Absolute paths are used as-is.
    Relative paths are joined to *base_dir* (or left relative if
    *base_dir* is ``None``).
    """
    result: list[Path | str] = []
    for entry in raw_paths:
        if isinstance(entry, str) and entry in ("builtin", "!reset"):
            result.append(entry)
        elif isinstance(entry, Path):
            if entry.is_absolute():
                result.append(entry)
            elif base_dir is not None:
                result.append(base_dir / entry)
            else:
                result.append(entry)
        else:
            result.append(entry)
    return tuple(result)
