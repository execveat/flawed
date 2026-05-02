"""Enforce the engine-wide managed subprocess boundary.

Raw process launch APIs in ``src/flawed`` bypass the process-group registry,
timeout tree-kill, parent-death watchdog, and shutdown handlers in
``flawed._process``.  Runtime code may import and call that central module only;
this guard fails closed on any direct stdlib subprocess import or other spawn API.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src" / "flawed"
CENTRAL_MODULE = SRC_DIR / "_process.py"


@dataclass(frozen=True)
class Violation:
    """One raw subprocess boundary violation."""

    path: Path
    lineno: int
    detail: str


def find_violations(paths: Iterable[Path] | None = None) -> tuple[Violation, ...]:
    """Return direct process-spawn API usage under ``src/flawed``."""
    roots = tuple(paths) if paths is not None else (SRC_DIR,)
    violations: list[Violation] = []
    for file in _python_files(roots):
        if _is_central_module(file):
            continue
        tree = ast.parse(file.read_text(encoding="utf-8"), filename=str(file))
        visitor = _Visitor(file)
        visitor.visit(tree)
        violations.extend(visitor.violations)
    return tuple(violations)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for the managed-subprocess gate."""
    raw_paths = argv if argv is not None else sys.argv[1:]
    paths = tuple(Path(raw) for raw in raw_paths) if raw_paths else None
    violations = find_violations(paths)
    if not violations:
        return 0
    print("Raw subprocess/spawn APIs are forbidden in src/flawed; use flawed._process:")
    for violation in violations:
        rel = violation.path.relative_to(ROOT)
        print(f"  {rel}:{violation.lineno}: {violation.detail}")
    return 1


class _Visitor(ast.NodeVisitor):
    """AST visitor that records direct process-spawn usage."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.violations: list[Violation] = []
        self._os_aliases = {"os"}
        self._asyncio_aliases = {"asyncio"}
        self._direct_os_spawn_names: set[str] = set()
        self._direct_asyncio_subprocess_names: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local_name = alias.asname or alias.name
            if alias.name == "subprocess":
                self._add(node, "direct import subprocess")
            elif alias.name == "os":
                self._os_aliases.add(local_name)
            elif alias.name == "asyncio":
                self._asyncio_aliases.add(local_name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "subprocess":
            self._add(node, "direct from subprocess import")
        elif node.module == "os":
            for alias in node.names:
                if alias.name.startswith("spawn"):
                    self._direct_os_spawn_names.add(alias.asname or alias.name)
                    self._add(node, f"direct from os import {alias.name}")
        elif node.module == "asyncio":
            for alias in node.names:
                if alias.name.startswith("create_subprocess"):
                    self._direct_asyncio_subprocess_names.add(alias.asname or alias.name)
                    self._add(node, f"direct from asyncio import {alias.name}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        if self._is_forbidden_call(name):
            self._add(node, f"direct {name} call")
        self.generic_visit(node)

    def _is_forbidden_call(self, name: str) -> bool:
        if name.startswith("subprocess."):
            return True
        head, _, tail = name.partition(".")
        if head in self._direct_os_spawn_names or head in self._direct_asyncio_subprocess_names:
            return True
        if head in self._os_aliases and tail.startswith("spawn"):
            return True
        return head in self._asyncio_aliases and tail.startswith("create_subprocess")

    def _add(self, node: ast.AST, detail: str) -> None:
        self.violations.append(Violation(self.path, getattr(node, "lineno", 1), detail))


def _python_files(roots: Iterable[Path]) -> tuple[Path, ...]:
    files: set[Path] = set()
    for root in roots:
        path = root if root.is_absolute() else ROOT / root
        if path.is_file() and path.suffix == ".py":
            files.add(path.resolve())
        elif path.is_dir():
            files.update(child.resolve() for child in path.rglob("*.py"))
    return tuple(sorted(files))


def _call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _is_central_module(path: Path) -> bool:
    return path.name == "_process.py" and path.parent.name == "flawed"


if __name__ == "__main__":
    raise SystemExit(main())
