"""Guard against undeclared runtime dependencies.

Failure class: runtime code that *imports* a package, or *invokes* a tool via
``python -m <pkg>``, while that package is present only transitively (pulled in
by a dev dependency) passes the editable-venv quality gate but raises
``ModuleNotFoundError`` in the packaged/global install (``uv tool install`` /
pip). The editable venv installs the dev group and all transitive deps, so the
gap is invisible there; only a clean install from ``[project.dependencies]``
exposes it.

This has bitten the project three times, all three encoded as regression
fixtures in ``tests/unit/test_check_runtime_deps.py``:

1. ``pathspec`` — ``import pathspec`` in ``_cli/suppression.py``; only present
   transitively via ``mypy``. Fixed by declaring ``pathspec`` (commit d528567).
2. ``astroid`` — top-level import in ``_index/_brains/``; fixed by declaring it.
3. ``basedpyright`` — NOT an import: invoked as ``sys.executable -m basedpyright``
   in ``_index/_type_enrichment.py``. The global build ran the type-enrichment
   oracle dead until it was promoted to a runtime dep. An import-only audit
   misses this class entirely — hence we also scan ``-m <module>`` invocations.

The check cross-references every runtime import root AND every ``-m <module>``
subprocess invocation under ``src/flawed/`` against the declared
``[project.dependencies]`` in ``pyproject.toml``. Standard-library modules and
the first-party ``flawed`` package are exempt. Imports guarded by
``if TYPE_CHECKING:`` are excluded — they never execute at runtime, so they
cannot break the install (they are not a runtime requirement).

FN-first: when a name cannot be resolved to a *declared* distribution it is
reported, never silently passed.

Exit 0 if clean, exit 1 if any undeclared runtime requirement is found.
"""

from __future__ import annotations

import ast
import itertools
import re
import sys
import tomllib
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src" / "flawed"
PYPROJECT = ROOT / "pyproject.toml"

# The package itself — its own modules are not an external requirement.
FIRST_PARTY = frozenset({"flawed"})

# Intentional optional integrations: guarded imports deliberately absent from
# pyproject (see flawed._cli.ribrarian_bridge). This allowlist tells the gate the
# undeclared import is expected, not a mistake — do not remove.
INTERNAL_OPTIONAL = frozenset({"ribrarian"})

_NORMALIZE_RE = re.compile(r"[-_.]+")


def _normalize(name: str) -> str:
    """PEP 503 normalization so import-name/dist-name casing and separators agree.

    ``PyYAML`` -> ``pyyaml``, ``Jinja2`` -> ``jinja2``, ``import_linter`` ->
    ``import-linter``.
    """
    return _NORMALIZE_RE.sub("-", name).strip("-").lower()


def _dep_name(spec: str) -> str:
    """Strip a PEP 508 spec down to its bare, normalized distribution name.

    Removes version specifiers (``>=1.0``), extras (``pkg[extra]``), markers
    (``; python_version``), and direct-reference URLs (``pkg @ git+...``).
    """
    name = re.split(r"[<>=!~;\[\s@]", spec, maxsplit=1)[0]
    return _normalize(name) if name else ""


def parse_declared_dependencies(pyproject_text: str) -> set[str]:
    """Return the normalized distribution names from ``[project.dependencies]``.

    Only the runtime ``[project.dependencies]`` table is read — never the dev
    group or transitive closure. That is the whole point: a name installed only
    via dev/transitive deps must still register as *undeclared* for runtime.
    """
    data = tomllib.loads(pyproject_text)
    raw = data.get("project", {}).get("dependencies", [])
    return {name for spec in raw if (name := _dep_name(spec))}


def parse_optional_dependencies(pyproject_text: str) -> set[str]:
    """Return normalized names from every ``[project.optional-dependencies]`` group.

    These are *optional* extras: a base install does not pull them in, so an
    unguarded import of one WOULD raise ``ModuleNotFoundError``. They are only
    safe to import behind a ``try/except ImportError`` guard — :func:`find_undeclared`
    enforces exactly that pairing (declared-as-optional AND guarded).
    """
    data = tomllib.loads(pyproject_text)
    groups = data.get("project", {}).get("optional-dependencies", {})
    return {name for specs in groups.values() for spec in specs if (name := _dep_name(spec))}


@dataclass(frozen=True)
class Requirement:
    """A single runtime requirement discovered in source."""

    kind: str  # "import" or "subprocess -m"
    name: str  # the import root or the ``-m`` module root
    file: Path
    lineno: int
    guarded: bool = False  # import inside a ``try/except ImportError`` (optional dep)


def _import_roots(tree: ast.AST) -> list[tuple[str, int, bool]]:
    """Collect ``(root_module, lineno, guarded)`` for every runtime import.

    Imports nested under an ``if TYPE_CHECKING:`` guard are excluded (they do
    not execute at runtime). Imports in the body of a ``try`` that catches
    ``ImportError``/``ModuleNotFoundError`` are flagged ``guarded=True``: their
    absence is handled, so they cannot break the install on their own — they are
    the shape an *optional* dependency takes. Relative imports (``from . import
    x``) are first-party and skipped.
    """
    roots: list[tuple[str, int, bool]] = []

    def visit(node: ast.AST, *, guarded: bool) -> None:
        if isinstance(node, ast.If) and _is_type_checking_guard(node.test):
            # Skip the type-only body; still descend into ``orelse`` (the runtime
            # fallback branch, if any).
            for sub in node.orelse:
                visit(sub, guarded=guarded)
            return
        if isinstance(node, ast.Try):
            # The try body is guarded iff an except clause handles an import
            # failure; handlers/else/finally inherit the surrounding guard.
            body_guarded = guarded or _handles_import_error(node)
            for body_stmt in node.body:
                visit(body_stmt, guarded=body_guarded)
            for other in (*node.handlers, *node.orelse, *node.finalbody):
                visit(other, guarded=guarded)
            return
        if isinstance(node, ast.Import):
            roots.extend((alias.name.split(".")[0], node.lineno, guarded) for alias in node.names)
            return
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.append((node.module.split(".")[0], node.lineno, guarded))
            return
        for child in ast.iter_child_nodes(node):
            visit(child, guarded=guarded)

    visit(tree, guarded=False)
    return roots


def _is_type_checking_guard(test: ast.expr) -> bool:
    """True for ``TYPE_CHECKING`` / ``typing.TYPE_CHECKING`` test expressions."""
    if isinstance(test, ast.Name):
        return test.id == "TYPE_CHECKING"
    if isinstance(test, ast.Attribute):
        return test.attr == "TYPE_CHECKING"
    return False


def _handles_import_error(node: ast.Try) -> bool:
    """True if any ``except`` clause of *node* catches an import failure.

    Recognizes ``ImportError``/``ModuleNotFoundError`` (bare or in a tuple) and a
    bare ``except:`` (which catches everything, import failures included).
    """
    targets = {"ImportError", "ModuleNotFoundError"}
    for handler in node.handlers:
        exc = handler.type
        if exc is None:  # bare ``except:``
            return True
        candidates = exc.elts if isinstance(exc, ast.Tuple) else [exc]
        for candidate in candidates:
            if isinstance(candidate, ast.Name) and candidate.id in targets:
                return True
            if isinstance(candidate, ast.Attribute) and candidate.attr in targets:
                return True
    return False


def _subprocess_modules(tree: ast.AST) -> list[tuple[str, int]]:
    """Collect ``(module_root, lineno)`` for every ``-m <module>`` invocation.

    Two shapes are recognized, covering how subprocess command lines are written
    in this codebase and in general:

    * A sequence (list/tuple/set) or call args where a ``"-m"`` string constant
      is immediately followed by a string-constant module —
      ``(sys.executable, "-m", "basedpyright")``.
    * A single string command beginning with a python-like token that contains
      ``-m <module>`` — ``"python -m pip install ..."``.
    """
    found: list[tuple[str, int]] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Call)):
            elts = node.args if isinstance(node, ast.Call) else node.elts
            for prev, cur in itertools.pairwise(elts):
                if _const_str(prev) == "-m":
                    mod = _const_str(cur)
                    if mod:
                        found.append((mod.split()[0].split(".")[0], node.lineno))

        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            mod = _module_from_command_string(node.value)
            if mod:
                found.append((mod, node.lineno))

    return found


def _const_str(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _module_from_command_string(value: str) -> str | None:
    """Extract a module from a single ``python -m <module> ...`` command string.

    Conservative: only fires when the command's first token looks like a python
    interpreter, so unrelated prose containing ``-m`` is not misread.
    """
    tokens = value.split()
    if len(tokens) < 3:
        return None
    head = tokens[0].rsplit("/", 1)[-1].lower()
    if not (head == "python" or head.startswith("python") or head == "sys.executable"):
        return None
    for i, tok in enumerate(tokens[:-1]):
        if tok == "-m":
            return tokens[i + 1].split(".")[0]
    return None


def iter_runtime_requirements(src_dir: Path = SRC_DIR) -> list[Requirement]:
    """Walk ``src_dir`` and collect every import and ``-m`` requirement."""
    requirements: list[Requirement] = []
    for py_file in sorted(src_dir.rglob("*.py")):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for root, lineno, guarded in _import_roots(tree):
            requirements.append(Requirement("import", root, py_file, lineno, guarded=guarded))
        for mod, lineno in _subprocess_modules(tree):
            requirements.append(Requirement("subprocess -m", mod, py_file, lineno))
    return requirements


def _candidate_dists(name: str, pkg_distributions: Mapping[str, list[str]]) -> set[str]:
    """Normalized distribution names that could satisfy import/module *name*.

    Resolution via :func:`importlib.metadata.packages_distributions` maps an
    import name to its providing distribution(s) (e.g. ``yaml`` -> ``PyYAML``).
    The name itself is always included as a candidate so an unresolved import
    (not installed in this env) is still checked against the declared names by
    its own normalized form rather than being waved through.
    """
    candidates = {_normalize(name)}
    for dist in pkg_distributions.get(name, ()):
        candidates.add(_normalize(dist))
    return candidates


def find_undeclared(
    declared: set[str],
    requirements: list[Requirement],
    *,
    optional: frozenset[str] | set[str] = frozenset(),
    pkg_distributions: Mapping[str, list[str]] | None = None,
    stdlib: frozenset[str] = sys.stdlib_module_names,
) -> list[Requirement]:
    """Return requirements that resolve to no acceptable declared distribution.

    A requirement is exempt when its root is stdlib or the first-party
    ``flawed`` package. Otherwise it must resolve — via name or distribution
    mapping — to either:

    * a name in *declared* (``[project.dependencies]``), unconditionally; or
    * a name in *optional* (``[project.optional-dependencies]``) **and** be
      ``guarded`` (imported behind ``try/except ImportError``). An *unguarded*
      import of an optional dep is still a violation — it breaks the base
      install — and a guarded import of a name in *neither* set is also reported.

    FN-first: unresolved names are reported, not skipped.
    """
    if pkg_distributions is None:
        pkg_distributions = metadata.packages_distributions()

    violations: list[Requirement] = []
    seen: set[tuple[str, str]] = set()
    for req in requirements:
        if req.name in stdlib or req.name in FIRST_PARTY:
            continue
        candidates = _candidate_dists(req.name, pkg_distributions)
        if candidates & declared:
            continue
        if req.guarded and candidates & optional:
            continue
        key = (req.kind, req.name)
        if key in seen:
            continue
        seen.add(key)
        violations.append(req)
    return violations


def main() -> int:
    """Scan ``src/flawed`` for undeclared runtime requirements."""
    pyproject_text = PYPROJECT.read_text(encoding="utf-8")
    declared = parse_declared_dependencies(pyproject_text)
    optional = parse_optional_dependencies(pyproject_text) | {
        _normalize(name) for name in INTERNAL_OPTIONAL
    }
    requirements = iter_runtime_requirements()
    violations = find_undeclared(declared, requirements, optional=optional)

    if not violations:
        return 0

    print(
        "Undeclared runtime dependencies found (imported/invoked at runtime but "
        "absent from pyproject [project.dependencies]):\n"
    )
    for req in sorted(violations, key=lambda r: (r.name, str(r.file), r.lineno)):
        rel = req.file.relative_to(ROOT)
        print(f"  {req.name!r} ({req.kind}) at {rel}:{req.lineno}")
    print(
        f"\n{len(violations)} undeclared runtime requirement(s). "
        "Declare each in pyproject [project.dependencies], or remove the usage. "
        "A transitive/dev-only package breaks `uv tool install` / pip installs."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
