"""Tests for tools.quality scope planning (which checks apply to which targets).

Planning is separated from execution in tools.quality precisely so it can be
verified cheaply here, without running ruff/mypy/pytest.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tools.quality import build_scope, planned_check_names

if TYPE_CHECKING:
    from pathlib import Path


def _touch(path: Path, text: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _plan(targets: list[str], root: Path) -> list[str]:
    return planned_check_names(build_scope(targets, root=root))


def test_l2_provider_runs_the_full_layered_gate(tmp_path: Path) -> None:
    _touch(tmp_path / "src/flawed/_semantic/providers/flask_login.py")

    assert _plan(["src/flawed/_semantic/providers/flask_login.py"], tmp_path) == [
        "lint",
        "format",
        "typecheck",
        "layers",
        "framework-names",
        "runtime-deps",
        "managed-subprocess",
        "tests",
        "pipeline-version",
    ]


def test_index_source_file_runs_l1_schema_check(tmp_path: Path) -> None:
    # FLAW-344: an _index change must re-validate the L1 schema lock.
    _touch(tmp_path / "src/flawed/_index/_pipeline.py")

    assert "l1-schema" in _plan(["src/flawed/_index/_pipeline.py"], tmp_path)


def test_core_source_file_skips_framework_name_check(tmp_path: Path) -> None:
    _touch(tmp_path / "src/flawed/core.py")

    # framework-names is L2-semantic-only; core.py is not under _semantic/.
    assert _plan(["src/flawed/core.py"], tmp_path) == [
        "lint",
        "format",
        "typecheck",
        "layers",
        "runtime-deps",
        "managed-subprocess",
        "tests",
        "pipeline-version",
    ]


def test_tools_file_runs_lint_format_typecheck_and_affected_tests(tmp_path: Path) -> None:
    _touch(tmp_path / "tools/quality.py")

    # tools/ is now ruff-gated (previously a gap); no layer/framework/dep checks.
    assert _plan(["tools/quality.py"], tmp_path) == ["lint", "format", "typecheck", "tests"]


def test_pytest_node_runs_lint_format_typecheck_and_tests(tmp_path: Path) -> None:
    _touch(tmp_path / "tests/unit/test_thing.py")

    assert _plan(["tests/unit/test_thing.py::test_x"], tmp_path) == [
        "lint",
        "format",
        "typecheck",
        "tests",
    ]


def test_fixture_py_is_linted_and_drives_affected_tests_but_is_not_a_test_target(
    tmp_path: Path,
) -> None:
    _touch(tmp_path / "tests/fixtures/apps/semantic/flask_basic/app.py")

    scope = build_scope(["tests/fixtures/apps/semantic/flask_basic/app.py"], root=tmp_path)
    # It is a .py file, so it is linted/typechecked and (via testmon) drives
    # affected tests — but it is NOT itself collected as a pytest target.
    assert planned_check_names(scope) == ["lint", "format", "typecheck", "tests"]
    from tools.quality import _test_targets

    assert _test_targets(scope) == ()


def test_pyproject_runs_lockfile_typecheck_basedpyright_layers_and_tests(tmp_path: Path) -> None:
    # A pyproject change can alter [tool.basedpyright], so the erasure gate re-runs (FLAW-262).
    _touch(tmp_path / "pyproject.toml")

    assert _plan(["pyproject.toml"], tmp_path) == [
        "lockfile",
        "typecheck",
        "basedpyright",
        "layers",
        "tests",
    ]


def test_lockfile_change_runs_lockfile_and_tests(tmp_path: Path) -> None:
    # A uv.lock change can alter test outcomes — the lockfile is the right place
    # to run the affected tests (design §8).
    _touch(tmp_path / "uv.lock")

    assert _plan(["uv.lock"], tmp_path) == ["lockfile", "tests"]


def test_docs_only_target_plans_no_checks(tmp_path: Path) -> None:
    _touch(tmp_path / "docs/guide.md")

    assert _plan(["docs/guide.md"], tmp_path) == []


def test_no_targets_means_full_gate(tmp_path: Path) -> None:
    assert planned_check_names(build_scope([], root=tmp_path)) == _ALL_NAMES


def test_missing_target_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Target does not exist"):
        build_scope(["missing.py"], root=tmp_path)


def test_missing_staged_target_is_skipped_not_an_error(tmp_path: Path) -> None:
    # In --staged mode a file can vanish before the hook runs; skip, don't crash.
    scope = build_scope(["gone.py"], root=tmp_path, staged=True)
    assert scope.full  # nothing resolved -> full is vacuously true, no targets
    assert scope.raw_targets == ()


_ALL_NAMES = [
    "lockfile",
    "lint",
    "format",
    "typecheck",
    "basedpyright",
    "layers",
    "framework-names",
    "runtime-deps",
    "managed-subprocess",
    "l1-schema",
    "tests",
    "pipeline-version",
]
