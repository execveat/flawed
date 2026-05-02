"""Tests for the managed subprocess source gate."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tools.check_managed_subprocess import find_violations

if TYPE_CHECKING:
    from pathlib import Path


def test_rejects_direct_subprocess_import_under_engine_src(tmp_path: Path) -> None:
    source = tmp_path / "src" / "flawed" / "bad.py"
    source.parent.mkdir(parents=True)
    source.write_text("import subprocess\nsubprocess.run(['true'])\n", encoding="utf-8")

    violations = find_violations((source,))

    assert [(item.lineno, item.detail) for item in violations] == [
        (1, "direct import subprocess"),
        (2, "direct subprocess.run call"),
    ]


def test_allows_central_process_module_to_own_raw_subprocess_import(tmp_path: Path) -> None:
    central = tmp_path / "src" / "flawed" / "_process.py"
    central.parent.mkdir(parents=True)
    central.write_text("import subprocess\nsubprocess.Popen(['true'])\n", encoding="utf-8")

    assert find_violations((central,)) == ()


def test_rejects_other_spawn_apis_under_engine_src(tmp_path: Path) -> None:
    source = tmp_path / "src" / "flawed" / "bad.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "import os as posix\n"
        "import asyncio as aio\n"
        "posix.spawnlp(posix.P_NOWAIT, 'x', 'x')\n"
        "aio.create_subprocess_exec('x')\n",
        encoding="utf-8",
    )

    violations = find_violations((source,))

    assert [(item.lineno, item.detail) for item in violations] == [
        (3, "direct posix.spawnlp call"),
        (4, "direct aio.create_subprocess_exec call"),
    ]


def test_rejects_spawn_apis_imported_directly_under_engine_src(tmp_path: Path) -> None:
    source = tmp_path / "src" / "flawed" / "bad.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "from os import spawnlp as spawn\n"
        "from asyncio import create_subprocess_shell\n"
        "spawn(0, 'x', 'x')\n"
        "create_subprocess_shell('x')\n",
        encoding="utf-8",
    )

    violations = find_violations((source,))

    assert [(item.lineno, item.detail) for item in violations] == [
        (1, "direct from os import spawnlp"),
        (2, "direct from asyncio import create_subprocess_shell"),
        (3, "direct spawn call"),
        (4, "direct create_subprocess_shell call"),
    ]
