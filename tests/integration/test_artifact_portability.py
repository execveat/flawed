"""Committed L1 artifacts must be portable across directories and machines.

The fixture artifacts are generated in one location (a developer's checkout or an
agent worktree) and loaded in another (CI, another machine, a different worktree).
A live L1 build embeds absolute roots into extractor-derived paths/FQNs; the builder
rewrites those to portability sentinels and ``load_index_from_artifacts`` rebases
them to the load-time root. These tests guard that contract so a regression that
re-introduces absolute paths fails here instead of silently binding the artifacts
to one machine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import flawed
from flawed.inputs import Json
from tests.helpers.artifact_fixtures import fixture_app_path, has_artifacts

_ARTIFACTS_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "artifacts"

pytestmark = pytest.mark.skipif(
    not has_artifacts("flask_basic"),
    reason="committed artifacts absent; run: python -m tools.build_fixture_artifacts flask_basic",
)


def test_committed_artifacts_contain_no_absolute_paths() -> None:
    """No committed artifact may embed an absolute path from its producer."""
    home = str(Path.home())
    offenders = [
        str(path.relative_to(_ARTIFACTS_DIR))
        for path in sorted(_ARTIFACTS_DIR.rglob("*"))
        if path.is_file()
        and (home in (text := path.read_text(encoding="utf-8")) or "/Users/" in text)
    ]
    assert offenders == [], f"absolute paths leaked into committed artifacts: {offenders}"


def test_load_is_independent_of_repo_root_path(tmp_path: Path) -> None:
    """Loading the same artifacts under two different repo_root paths is identical.

    The committed artifacts were generated in a third location entirely, so equal
    results under both load paths proves the sentinel rebasing makes the load
    location irrelevant — i.e. the artifacts are portable.
    """
    artifact_root = str(_ARTIFACTS_DIR / "flask_basic")
    real = flawed.open_repo(str(fixture_app_path("flask_basic")), artifact_root=artifact_root)
    elsewhere = flawed.open_repo(str(tmp_path / "flask_basic"), artifact_root=artifact_root)

    assert len(real.routes) == len(elsewhere.routes)
    assert {f.name for f in real.functions} == {f.name for f in elsewhere.functions}

    # A flow-dependent fact must hold regardless of the load location.
    for view in (real, elsewhere):
        fn = view.functions.named("create_user").one()
        assert fn is not None
        read = fn.body.reads(Json()).first()
        assert read is not None
        assert read.value.derived_from(Json())
