"""Load committed L1 fixture artifacts into a RepoView — zero external tools.

Tests that only need to query an already-built index should call
:func:`load_fixture` instead of building the index from source.  It goes through
the public seam (``flawed.open_repo(path, artifact_root=...)``), so no
basedpyright subprocess runs: the committed ``normalized/`` JSONL under
``tests/fixtures/artifacts/<app>/`` already carries every L1 fact L2/L3 consume.

Regenerate artifacts with ``python -m tools.build_fixture_artifacts <app>`` when
the extractor's ``_PIPELINE_VERSION`` changes (the committed ``PIPELINE_VERSION``
stamp records the producing version).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import flawed

if TYPE_CHECKING:
    from flawed._index import CodeIndex
    from flawed.repo import RepoView

_REPO_ROOT = Path(__file__).resolve().parents[2]
_APPS_DIR = _REPO_ROOT / "tests" / "fixtures" / "apps"
_ARTIFACTS_DIR = _REPO_ROOT / "tests" / "fixtures" / "artifacts"


def fixture_app_path(name: str) -> Path:
    """Absolute path to a fixture app's source tree (file or directory)."""
    return _APPS_DIR / name


def _load_repo_root(name: str) -> Path:
    """The ``repo_root`` to load *name*'s artifacts against.

    ``build_index`` normalizes a single-file ``repo_root`` to its parent
    directory (``_pipeline.py``: ``if repo_root.is_file(): repo_root = parent``)
    and records paths relative to that parent. Single-file fixtures (e.g.
    ``detection/foo.py``) must therefore load against the file's parent so the
    committed relative paths resolve identically — passing the file itself would
    desync the sentinel rebasing. Directory apps load against the directory.
    """
    src = _APPS_DIR / name
    return src.parent if src.is_file() else src


def has_artifacts(name: str) -> bool:
    """True if committed artifacts exist for *name*."""
    return (_ARTIFACTS_DIR / name / "normalized").is_dir()


def load_fixture(name: str) -> RepoView:
    """Return a :class:`RepoView` for fixture app *name* from committed artifacts.

    Raises ``FileNotFoundError`` if the artifacts are absent (generate them with
    ``python -m tools.build_fixture_artifacts <name>``).
    """
    artifact_root = _ARTIFACTS_DIR / name
    if not (artifact_root / "normalized").is_dir():
        msg = (
            f"no committed artifacts for fixture {name!r} at {artifact_root}; "
            f"run: python -m tools.build_fixture_artifacts {name}"
        )
        raise FileNotFoundError(msg)
    return flawed.open_repo(str(_load_repo_root(name)), artifact_root=str(artifact_root))


def load_index(name: str) -> CodeIndex:
    """Return the raw L1 :class:`CodeIndex` for fixture app *name* from artifacts.

    Like :func:`load_fixture`, but yields the index itself rather than a
    ``RepoView`` — for specs that drive the provider engine (or other L1
    consumers) directly. No external tools run; the committed ``normalized/``
    JSONL is deserialized in-process.

    Raises ``FileNotFoundError`` if the artifacts are absent.
    """
    from flawed._index._pipeline import load_index_from_artifacts

    artifact_root = _ARTIFACTS_DIR / name
    if not (artifact_root / "normalized").is_dir():
        msg = (
            f"no committed artifacts for fixture {name!r} at {artifact_root}; "
            f"run: python -m tools.build_fixture_artifacts {name}"
        )
        raise FileNotFoundError(msg)
    return load_index_from_artifacts(_load_repo_root(name), artifact_root)
