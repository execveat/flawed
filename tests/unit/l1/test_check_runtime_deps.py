"""FLAW-211: guard against undeclared runtime dependencies.

The check (``tools.check_runtime_deps``) exists to make one failure class
impossible to reintroduce silently: runtime code that imports a package, or
invokes a tool via ``python -m <pkg>``, while the package is present only
transitively (via a dev dependency). Such code passes the editable-venv gate
but raises ``ModuleNotFoundError`` in the packaged/global install.

These tests pin three things:

* The pure detector logic on synthetic trees — both the import class and the
  ``-m`` subprocess class are caught, declared/stdlib/first-party/TYPE_CHECKING
  are exempt.
* A regression for the three historical instances against the *real* source
  tree: removing ``pathspec``, ``astroid``, or ``basedpyright`` from the
  declared set must make the check flag exactly that name (and ``basedpyright``
  specifically via the subprocess path, which an import-only audit would miss).
* The current real tree is clean (zero undeclared runtime requirements).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tools.check_runtime_deps import (
    INTERNAL_OPTIONAL,
    PYPROJECT,
    find_undeclared,
    iter_runtime_requirements,
    main,
    parse_declared_dependencies,
    parse_optional_dependencies,
)

if TYPE_CHECKING:
    from pathlib import Path

# A frozen stand-in for ``importlib.metadata.packages_distributions`` so the
# detector tests do not depend on what happens to be installed in the venv.
_PKG_DISTS = {
    "yaml": ["PyYAML"],
    "jinja2": ["Jinja2"],
    "astroid": ["astroid"],
    "pathspec": ["pathspec"],
    "basedpyright": ["basedpyright"],
}
_STDLIB = frozenset({"os", "sys", "subprocess", "typing", "re", "ast"})


def _write(tmp_path: Path, name: str, body: str) -> Path:
    src = tmp_path / "src" / "flawed"
    src.mkdir(parents=True, exist_ok=True)
    target = src / name
    target.write_text(body, encoding="utf-8")
    return src


# --- declared-dependency parsing -----------------------------------------


def test_parse_declared_strips_specifiers_and_normalizes() -> None:
    declared = parse_declared_dependencies(
        """
        [project]
        dependencies = [
            "astroid>=3.0",
            "PyYAML>=6.0",
            "pkg[extra]>=1.0",
            "named @ git+https://example/named.git",
            "marked; python_version >= '3.12'",
        ]
        """
    )
    assert declared == {"astroid", "pyyaml", "pkg", "named", "marked"}


# --- import detection -----------------------------------------------------


def test_undeclared_import_is_flagged(tmp_path: Path) -> None:
    src = _write(tmp_path, "mod.py", "import requests\n")
    violations = find_undeclared(
        {"astroid"}, iter_runtime_requirements(src), pkg_distributions={}, stdlib=_STDLIB
    )
    assert [(v.name, v.kind) for v in violations] == [("requests", "import")]


def test_declared_import_via_distribution_mapping_passes(tmp_path: Path) -> None:
    # ``import yaml`` is satisfied by the declared ``pyyaml`` distribution.
    src = _write(tmp_path, "mod.py", "import yaml\nfrom jinja2 import Template\n")
    violations = find_undeclared(
        {"pyyaml", "jinja2"},
        iter_runtime_requirements(src),
        pkg_distributions=_PKG_DISTS,
        stdlib=_STDLIB,
    )
    assert violations == []


def test_stdlib_and_first_party_imports_are_exempt(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        "mod.py",
        "import os\nimport subprocess\nfrom flawed._index import x\nfrom . import sibling\n",
    )
    violations = find_undeclared(
        set(), iter_runtime_requirements(src), pkg_distributions={}, stdlib=_STDLIB
    )
    assert violations == []


def test_type_checking_only_import_is_excluded(tmp_path: Path) -> None:
    # A type-only import never executes at runtime, so it is not a runtime
    # requirement and must not be flagged even when undeclared.
    src = _write(
        tmp_path,
        "mod.py",
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import only_for_types\n",
    )
    violations = find_undeclared(
        set(), iter_runtime_requirements(src), pkg_distributions={}, stdlib=_STDLIB
    )
    assert violations == []


# --- optional dependencies: guarded imports (FLAW-205) --------------------


def test_guarded_optional_import_passes(tmp_path: Path) -> None:
    # An optional dep imported behind ``try/except ImportError`` cannot break the
    # base install, so it is allowed when declared in optional-dependencies.
    src = _write(
        tmp_path,
        "mod.py",
        "try:\n    import ribrarian\n\n    HAS = True\nexcept ImportError:\n    HAS = False\n",
    )
    violations = find_undeclared(
        set(),
        iter_runtime_requirements(src),
        optional={"ribrarian"},
        pkg_distributions={},
        stdlib=_STDLIB,
    )
    assert violations == []


def test_unguarded_optional_import_is_flagged(tmp_path: Path) -> None:
    # An optional dep imported WITHOUT a guard would raise ModuleNotFoundError in
    # a base install — that is exactly the failure class, so it must be flagged.
    src = _write(tmp_path, "mod.py", "import ribrarian\n")
    violations = find_undeclared(
        set(),
        iter_runtime_requirements(src),
        optional={"ribrarian"},
        pkg_distributions={},
        stdlib=_STDLIB,
    )
    assert [(v.name, v.kind) for v in violations] == [("ribrarian", "import")]


def test_guarded_import_not_in_optional_is_flagged(tmp_path: Path) -> None:
    # FN-first: a guarded import that is declared nowhere is still reported.
    src = _write(
        tmp_path,
        "mod.py",
        "try:\n    import mystery\nexcept ImportError:\n    mystery = None\n",
    )
    violations = find_undeclared(
        set(),
        iter_runtime_requirements(src),
        optional={"ribrarian"},
        pkg_distributions={},
        stdlib=_STDLIB,
    )
    assert [(v.name, v.kind) for v in violations] == [("mystery", "import")]


# --- subprocess ``-m`` detection (the class an import audit misses) -------


def test_undeclared_subprocess_dash_m_tuple_is_flagged(tmp_path: Path) -> None:
    src = _write(
        tmp_path,
        "mod.py",
        'import subprocess, sys\nsubprocess.run((sys.executable, "-m", "sometool", "--flag"))\n',
    )
    violations = find_undeclared(
        set(), iter_runtime_requirements(src), pkg_distributions={}, stdlib=_STDLIB
    )
    assert [(v.name, v.kind) for v in violations] == [("sometool", "subprocess -m")]


def test_subprocess_dash_m_command_string_is_flagged(tmp_path: Path) -> None:
    src = _write(tmp_path, "mod.py", 'CMD = "python -m blacktool --check ."\n')
    violations = find_undeclared(
        set(), iter_runtime_requirements(src), pkg_distributions={}, stdlib=_STDLIB
    )
    assert [(v.name, v.kind) for v in violations] == [("blacktool", "subprocess -m")]


def test_dash_m_in_unrelated_string_is_not_misread(tmp_path: Path) -> None:
    # A ``-m`` in prose (not a python command) must not be treated as a module.
    src = _write(tmp_path, "mod.py", 'DOC = "use the -m switch carefully"\n')
    violations = find_undeclared(
        set(), iter_runtime_requirements(src), pkg_distributions={}, stdlib=_STDLIB
    )
    assert violations == []


# --- regression: the three historical instances on the real tree ---------


def test_real_tree_has_no_undeclared_runtime_deps() -> None:
    text = PYPROJECT.read_text(encoding="utf-8")
    declared = parse_declared_dependencies(text)
    # Mirror main(): the optional set is pyproject extras PLUS the internal
    # allowlist (ribrarian — an optional PRIVATE integration deliberately not in
    # pyproject; see INTERNAL_OPTIONAL).
    optional = parse_optional_dependencies(text) | INTERNAL_OPTIONAL
    violations = find_undeclared(declared, iter_runtime_requirements(), optional=optional)
    assert violations == [], [(v.name, v.kind, str(v.file), v.lineno) for v in violations]


def test_internal_optional_allowlist_permits_undeclared_guarded_ribrarian() -> None:
    # ribrarian is an INTENTIONAL optional PRIVATE integration: deliberately absent
    # from pyproject [project.optional-dependencies] (so the public package leaks no
    # private source), yet the guarded `import ribrarian` in the bridge must still
    # pass the gate. The INTERNAL_OPTIONAL allowlist is exactly what permits it —
    # without it, the guarded import would be (correctly) flagged as undeclared.
    text = PYPROJECT.read_text(encoding="utf-8")
    pyproject_optional = parse_optional_dependencies(text)
    assert "ribrarian" not in pyproject_optional  # not a declared extra (no leak)
    assert "ribrarian" in INTERNAL_OPTIONAL  # but allowlisted as intentional

    declared = parse_declared_dependencies(text)
    requirements = iter_runtime_requirements()
    without = {
        (v.name, v.kind)
        for v in find_undeclared(declared, requirements, optional=pyproject_optional)
    }
    with_allow = {
        (v.name, v.kind)
        for v in find_undeclared(
            declared, requirements, optional=pyproject_optional | INTERNAL_OPTIONAL
        )
    }
    assert ("ribrarian", "import") in without  # would be flagged without the allowlist
    assert ("ribrarian", "import") not in with_allow  # the allowlist clears it


def test_main_passes_on_current_tree() -> None:
    assert main() == 0


def test_historical_instances_would_be_caught() -> None:
    declared = parse_declared_dependencies(PYPROJECT.read_text(encoding="utf-8"))
    requirements = iter_runtime_requirements()

    # pathspec & astroid: undeclared runtime *imports*.
    for dep in ("pathspec", "astroid"):
        violations = find_undeclared(declared - {dep}, requirements)
        caught = {(v.name, v.kind) for v in violations}
        assert (dep, "import") in caught, (dep, caught)

    # basedpyright: invoked as ``sys.executable -m basedpyright`` — NOT an
    # import. This is the class an import-only audit silently misses.
    violations = find_undeclared(declared - {"basedpyright"}, requirements)
    caught = {(v.name, v.kind) for v in violations}
    assert ("basedpyright", "subprocess -m") in caught, caught
