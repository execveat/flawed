"""Single declarative owner of the flawed quality gate.

This module is the ONE place the check-set is defined. Every other entry point is
a thin caller with no independent check logic:

- ``mise run check [-- PATHS] [-- --all]``  -> ``python -m tools.quality [PATHS]``
- ``mise run test  [-- PATHS] [-- --all]``  -> ``python -m tools.quality --tests-only [PATHS]``
- ``mise run fix``                          -> ``python -m tools.quality --format-only``
- the git ``pre-commit`` hook               -> ``python -m tools.quality --staged``
- on-save (``agent-hooks``) nudge           -> ``python -m tools.quality <file> --no-format``

It owns its OUTPUT: each tool is run with captured / machine-readable output
(ruff ``--output-format json``, the pytest json report), and this module emits one
clean, de-noised, actionable summary plus a meaningful exit code. Callers care
only about the exit code and the relayed summary — never raw tool stdout.

Design: the check-set is data (``CHECKS``), each entry a :class:`CheckSpec` with
an ``applies`` predicate and a ``run`` action. Planning (which checks apply to a
scope) is separated from execution so it is cheap to test.

Modes / flags
-------------
- no targets        -> full gate at whole-repo scope
- TARGETS           -> the narrowest correct subset for those files/dirs/nodes
- ``--staged``      -> derive targets from ``git diff --cached`` (the hook path);
                       applies Python autofix and re-stages, then runs the gate
- ``--tests-only``  -> only the pytest+testmon step (the ``mise run test`` path)
- ``--format-only`` -> only ruff lint+format (the ``mise run fix`` path)
- ``--no-format``   -> never mutate: lint and format are check-only (on-save nudge)
- ``--all``         -> include ``@slow`` tests (default excludes via ``-m 'not slow'``)
- trailing unknown args are forwarded to pytest (e.g. ``-k NAME``, ``-x``)

Command-surface rationale (kept minimal; expand only on a verified need):
``check`` (everything, autofix by default) and ``test`` (tests only) are the two
blessed verbs; ``fix`` is retained because "autofix without the full gate" is a
real, recurring inner-loop need. Held back until justified: a dedicated
``--no-tests`` and ``--tier`` (directory paths already select a tier).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from tools._test_lock import PytestLockTimeoutError, pytest_lock

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

ROOT = Path(__file__).resolve().parents[1]

# Ruff lint/format roots for a full run. NOTE: includes ``tools/`` — previously
# ``tools/`` was type-checked but never ruff-gated (a latent gap), now closed.
FULL_RUFF_TARGETS = ("src", "tests", "tools")
# mypy must see the package as a whole to resolve cross-module types, so it always
# runs over these roots regardless of which file changed.
MYPY_TARGETS = ("src", "tools", "tests")

_MAX_DETAIL_LINES = 15


@dataclass(frozen=True)
class Scope:
    """What to check and how, resolved once from CLI args.

    ``rel_paths`` are POSIX paths relative to the scope root, so the applicability
    predicates are pure string logic (root-independent and trivially testable).
    ``paths`` are absolute, used only for filesystem questions (is this a .py?).
    """

    raw_targets: tuple[str, ...]
    paths: tuple[Path, ...]
    rel_paths: tuple[str, ...]
    staged_paths: tuple[str, ...]
    full: bool
    apply_fixes: bool
    include_slow: bool
    staged: bool
    pytest_extra: tuple[str, ...]


@dataclass
class CheckResult:
    """Outcome of one check: ok flag, timing, and a clean summary."""

    name: str
    ok: bool
    duration: float
    detail: str = ""
    advisory: bool = False
    always_detail: bool = False


@dataclass(frozen=True)
class CheckSpec:
    """One gate check: its name, when it applies, and how to run it."""

    name: str
    applies: Callable[[Scope], bool]
    run: Callable[[Scope], CheckResult]


# --------------------------------------------------------------------------- #
# Low-level helpers
# --------------------------------------------------------------------------- #


def _run(argv: Sequence[str], *, capture: bool = True) -> subprocess.CompletedProcess[str]:
    """Run *argv* from the repo root. The ``uv run`` prefix guarantees the venv."""
    return subprocess.run(list(argv), cwd=ROOT, capture_output=capture, text=True, check=False)


def _trim(text: str, *, limit: int = _MAX_DETAIL_LINES) -> str:
    lines = [ln for ln in text.strip().splitlines() if ln.strip()]
    if len(lines) <= limit:
        return "\n".join(lines)
    return "\n".join((*lines[:limit], f"... and {len(lines) - limit} more line(s)"))


def _is_python_path(path: Path) -> bool:
    if path.is_file():
        return path.suffix == ".py"
    return path.is_dir() and any(path.rglob("*.py"))


def _is_test_path(raw: str, path: Path, rel: str) -> bool:
    """A pytest node, a test file, or a directory under tests/ holding tests."""
    if "::" in raw:
        return True
    if not (rel == "tests" or rel.startswith("tests/")):
        return False
    if path.is_file():
        return (
            path.name == "conftest.py"
            or path.name.startswith("test_")
            or path.name.endswith("_test.py")
        )
    if path.is_dir():
        return any(
            c.name == "conftest.py" or c.name.startswith("test_") or c.name.endswith("_test.py")
            for c in path.rglob("*.py")
        )
    return False


# --------------------------------------------------------------------------- #
# Scope predicates (pure functions of rel_paths / filesystem)
# --------------------------------------------------------------------------- #


def _needs_python(scope: Scope) -> bool:
    if scope.full or any(Path(r).name == "pyproject.toml" for r in scope.rel_paths):
        return True
    return any(_is_python_path(p) for p in scope.paths)


def _touches_pyproject_or_lock(scope: Scope) -> bool:
    return scope.full or any(
        Path(r).name in {"pyproject.toml", "uv.lock"} for r in scope.rel_paths
    )


def _touches_pyproject(scope: Scope) -> bool:
    return scope.full or any(Path(r).name == "pyproject.toml" for r in scope.rel_paths)


def _under_src(scope: Scope) -> bool:
    return scope.full or any(r == "src" or r.startswith("src/") for r in scope.rel_paths)


def _under_flawed(scope: Scope) -> bool:
    return scope.full or any(
        r == "src/flawed" or r.startswith("src/flawed/") for r in scope.rel_paths
    )


def _under_semantic(scope: Scope) -> bool:
    return scope.full or any(r.startswith("src/flawed/_semantic") for r in scope.rel_paths)


def _under_rules(scope: Scope) -> bool:
    """FLAW-262 basedpyright erasure gate over ``src/flawed/_rules`` (re-runs on a
    ``pyproject.toml`` change, which can alter its ``[tool.basedpyright]`` config)."""
    return (
        scope.full
        or any(Path(r).name == "pyproject.toml" for r in scope.rel_paths)
        or any(
            r == "src/flawed/_rules" or r.startswith("src/flawed/_rules/") for r in scope.rel_paths
        )
    )


def _applies_l1_schema(scope: Scope) -> bool:
    """FLAW-344: any ``_index`` source or schema-lock change must re-lock the schema."""
    return scope.full or any(
        r == "src/flawed/_index" or r.startswith("src/flawed/_index/") for r in scope.rel_paths
    )


def _ruff_targets(scope: Scope) -> tuple[str, ...]:
    if scope.full:
        return FULL_RUFF_TARGETS
    out = [
        rel
        for path, rel in zip(scope.paths, scope.rel_paths, strict=True)
        if _is_python_path(path)
    ]
    return tuple(dict.fromkeys(out))


def _managed_subprocess_targets(scope: Scope) -> tuple[str, ...]:
    if scope.full:
        return ("src/flawed",)
    scoped = [r for r in scope.rel_paths if r == "src/flawed" or r.startswith("src/flawed/")]
    return tuple(scoped) or ("src/flawed",)


def _test_targets(scope: Scope) -> tuple[str, ...]:
    """Explicit pytest node/path targets; empty means 'let testmon decide'."""
    if scope.full:
        return ()
    return tuple(
        raw
        for raw, path, rel in zip(scope.raw_targets, scope.paths, scope.rel_paths, strict=True)
        if _is_test_path(raw, path, rel)
    )


def _applies_ruff(scope: Scope) -> bool:
    return bool(_ruff_targets(scope))


def _applies_layers(scope: Scope) -> bool:
    return _under_src(scope) or _touches_pyproject(scope)


def _applies_tests(scope: Scope) -> bool:
    # A dependency change (uv.lock / pyproject) can change test outcomes, so it
    # runs the affected tests too (design §8 — the lockfile is the right place to
    # run tests; testmon decides which, kept fresh).
    return (
        scope.full
        or bool(_test_targets(scope))
        or _needs_python(scope)
        or _touches_pyproject_or_lock(scope)
    )


# --------------------------------------------------------------------------- #
# Summarizers (own the output: parse tools, emit clean text)
# --------------------------------------------------------------------------- #


def _summarize_ruff_json(stdout: str) -> str:
    try:
        items = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        return _trim(stdout)
    if not items:
        return ""
    lines: list[str] = []
    for it in items[:_MAX_DETAIL_LINES]:
        loc = it.get("location") or {}
        fname = it.get("filename", "?")
        with contextlib.suppress(ValueError):
            fname = os.path.relpath(fname, ROOT)
        lines.append(
            f"{fname}:{loc.get('row', '?')}:{loc.get('column', '?')} "
            f"{it.get('code', '')} {it.get('message', '')}".rstrip()
        )
    if len(items) > _MAX_DETAIL_LINES:
        lines.append(f"... and {len(items) - _MAX_DETAIL_LINES} more")
    return f"{len(items)} issue(s):\n" + "\n".join(lines)


def _summarize_mypy(stdout: str) -> str:
    errors = [ln for ln in stdout.splitlines() if ": error:" in ln]
    if not errors:
        return _trim(stdout)
    body = "\n".join(errors[:_MAX_DETAIL_LINES])
    if len(errors) > _MAX_DETAIL_LINES:
        body += f"\n... and {len(errors) - _MAX_DETAIL_LINES} more"
    return f"{len(errors)} type error(s):\n{body}"


def _summarize_pytest(report: Path) -> str:
    try:
        data = json.loads(report.read_text())
    except (OSError, json.JSONDecodeError):
        return ""
    summ = data.get("summary", {})
    total = summ.get("total", 0) or summ.get("collected", 0)
    parts = [f"{summ.get('passed', 0)} passed"]
    parts.extend(
        f"{summ[key]} {key}" for key in ("failed", "error", "xfailed", "skipped") if summ.get(key)
    )
    line = ", ".join(parts) + (f" of {total}" if total else "")
    fails = [
        t.get("nodeid", "?")
        for t in data.get("tests", [])
        if t.get("outcome") in {"failed", "error"}
    ]
    if fails:
        shown = "\n".join("  FAILED " + f for f in fails[:_MAX_DETAIL_LINES])
        if len(fails) > _MAX_DETAIL_LINES:
            shown += f"\n  ... and {len(fails) - _MAX_DETAIL_LINES} more"
        line += "\n" + shown
    return line


# --------------------------------------------------------------------------- #
# Check actions (each runs only when its CheckSpec.applies is true)
# --------------------------------------------------------------------------- #


def _restage(scope: Scope) -> None:
    """Re-stage Python files autofix may have rewritten (the hook path)."""
    py = [p for p in scope.staged_paths if p.endswith(".py")]
    if py:
        _run(["git", "add", "--", *py])


def _run_lockfile(scope: Scope) -> CheckResult:  # noqa: ARG001 (uniform CheckSpec.run signature)
    t = time.perf_counter()
    cp = _run(["uv", "lock", "--check"])
    ok = cp.returncode == 0
    detail = "" if ok else _trim((cp.stderr or cp.stdout) + "\nrun `uv lock` to refresh.")
    return CheckResult("lockfile", ok, time.perf_counter() - t, detail)


def _run_lint(scope: Scope) -> CheckResult:
    argv = ["uv", "run", "ruff", "check", "--output-format", "json"]
    if scope.apply_fixes:
        argv.append("--fix")
    argv.extend(_ruff_targets(scope))
    t = time.perf_counter()
    cp = _run(argv)
    return CheckResult(
        "lint", cp.returncode == 0, time.perf_counter() - t, _summarize_ruff_json(cp.stdout)
    )


def _run_format(scope: Scope) -> CheckResult:
    flag = () if scope.apply_fixes else ("--check",)
    t = time.perf_counter()
    cp = _run(["uv", "run", "ruff", "format", *flag, *_ruff_targets(scope)])
    if scope.apply_fixes and scope.staged:
        _restage(scope)
    ok = cp.returncode == 0
    return CheckResult(
        "format", ok, time.perf_counter() - t, "" if ok else _trim(cp.stdout or cp.stderr)
    )


def _run_types(scope: Scope) -> CheckResult:  # noqa: ARG001 (uniform CheckSpec.run signature)
    t = time.perf_counter()
    cp = _run(["uv", "run", "mypy", *MYPY_TARGETS])
    return CheckResult(
        "typecheck", cp.returncode == 0, time.perf_counter() - t, _summarize_mypy(cp.stdout)
    )


def _run_basedpyright(scope: Scope) -> CheckResult:  # noqa: ARG001 (uniform CheckSpec.run signature)
    """FLAW-262 erasure gate: basedpyright over ``_rules``, where reportAny/reportUnknown* are
    errors — the getattr->Any erasure mypy-strict is structurally blind to. Gates on the JSON
    error count, NOT basedpyright's exit status, which is non-zero even when only advisory
    warnings remain (e.g. the reportUnnecessaryComparison dead-guard smells)."""
    t = time.perf_counter()
    cp = _run(["uv", "run", "basedpyright", "--outputjson", "src/flawed/_rules"])
    try:
        error_count = int(json.loads(cp.stdout)["summary"]["errorCount"])
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return CheckResult(
            "basedpyright", False, time.perf_counter() - t, _trim(cp.stderr or cp.stdout)
        )
    if error_count == 0:
        return CheckResult("basedpyright", True, time.perf_counter() - t, "")
    human = _run(["uv", "run", "basedpyright", "src/flawed/_rules"])
    return CheckResult(
        "basedpyright", False, time.perf_counter() - t, _trim(human.stdout or human.stderr)
    )


def _run_layers(scope: Scope) -> CheckResult:  # noqa: ARG001 (uniform CheckSpec.run signature)
    t = time.perf_counter()
    cp = _run(["uv", "run", "lint-imports"])
    ok = cp.returncode == 0
    return CheckResult(
        "layers", ok, time.perf_counter() - t, "" if ok else _trim(cp.stdout or cp.stderr)
    )


def _run_framework_names(scope: Scope) -> CheckResult:  # noqa: ARG001 (uniform CheckSpec.run signature)
    t = time.perf_counter()
    cp = _run(["uv", "run", "python", "-m", "tools.check_framework_names"])
    ok = cp.returncode == 0
    return CheckResult(
        "framework-names", ok, time.perf_counter() - t, "" if ok else _trim(cp.stdout or cp.stderr)
    )


def _run_runtime_deps(scope: Scope) -> CheckResult:  # noqa: ARG001 (uniform CheckSpec.run signature)
    t = time.perf_counter()
    cp = _run(["uv", "run", "python", "-m", "tools.check_runtime_deps"])
    ok = cp.returncode == 0
    return CheckResult(
        "runtime-deps", ok, time.perf_counter() - t, "" if ok else _trim(cp.stdout or cp.stderr)
    )


def _run_managed_subprocess(scope: Scope) -> CheckResult:
    t = time.perf_counter()
    cp = _run(
        [
            "uv",
            "run",
            "python",
            "-m",
            "tools.check_managed_subprocess",
            *_managed_subprocess_targets(scope),
        ]
    )
    ok = cp.returncode == 0
    return CheckResult(
        "managed-subprocess",
        ok,
        time.perf_counter() - t,
        "" if ok else _trim(cp.stdout or cp.stderr),
    )


def _run_l1_schema(scope: Scope) -> CheckResult:  # noqa: ARG001 (uniform CheckSpec.run signature)
    """FLAW-344: fail when ``_index`` source changed without re-locking the L1 schema."""
    t = time.perf_counter()
    cp = _run(["uv", "run", "python", "-m", "tools.check_l1_schema"])
    ok = cp.returncode == 0
    return CheckResult(
        "l1-schema", ok, time.perf_counter() - t, "" if ok else _trim(cp.stdout or cp.stderr)
    )


_DEFAULT_TEST_LOCK_TIMEOUT = 5.0


def _test_lock_timeout() -> float:
    """Seconds to wait for the pytest lock — ``[tool.flawed] test_lock_timeout_seconds``."""
    try:
        with (ROOT / "pyproject.toml").open("rb") as fh:
            cfg = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return _DEFAULT_TEST_LOCK_TIMEOUT
    tool = cfg.get("tool")
    flawed = tool.get("flawed") if isinstance(tool, dict) else None
    value = flawed.get("test_lock_timeout_seconds") if isinstance(flawed, dict) else None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return _DEFAULT_TEST_LOCK_TIMEOUT


def _run_tests(scope: Scope) -> CheckResult:
    report = ROOT / "local" / "test-results.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    argv = [
        "uv",
        "run",
        "pytest",
        "--testmon",
        "-q",
        "--json-report",
        f"--json-report-file={report}",
        # full report (not --json-report-summary): keeps per-test setup/call/teardown
        # durations so `mise run test-profile` can split fixture-build vs test-body time.
        # The `summary` key is still present, so _summarize_pytest / test_report are unaffected.
    ]
    if not scope.include_slow:
        argv += ["-m", "not slow"]
    argv += list(_test_targets(scope))
    argv += list(scope.pytest_extra)
    print("  ....  tests (running; live output below)", flush=True)
    t = time.perf_counter()
    # Serialize ONLY the pytest step across concurrent runs in this checkout: two
    # pytest runs racing on testmon's .testmondata (SQLite) corrupt it. Other gate
    # steps stay unlocked (their caches self-heal). flock-based, timeout-capped.
    try:
        with pytest_lock(ROOT, timeout=_test_lock_timeout()):
            cp = _run(argv, capture=False)  # stream pytest's own concise -q output
    except PytestLockTimeoutError as exc:
        return CheckResult("tests", False, time.perf_counter() - t, str(exc), always_detail=True)
    # exit 5 == "no tests collected" (testmon selected nothing changed) -> pass.
    ok = cp.returncode in {0, 5}
    detail = _summarize_pytest(report) if report.exists() else ""
    return CheckResult("tests", ok, time.perf_counter() - t, detail, always_detail=True)


# L1 extraction modules whose changes typically require a _PIPELINE_VERSION bump to
# invalidate cached artifacts. _pipeline.py is excluded — if it changed, the version
# likely changed with it (checked separately below).
_EXTRACTION_MODULES = (
    "src/flawed/_index/_structural.py",
    "src/flawed/_index/_callgraph.py",
    "src/flawed/_index/_valueflow.py",
    "src/flawed/_index/_resolution.py",
    "src/flawed/_index/_type_enrichment.py",
    "src/flawed/_index/_cfg.py",
)
_PIPELINE_FILE = "src/flawed/_index/_pipeline.py"


def _run_pipeline_version(scope: Scope) -> CheckResult:  # noqa: ARG001 (uniform CheckSpec.run signature)
    """Advisory: warn if L1 extraction modules changed without a _PIPELINE_VERSION
    bump. Stale cache reuse after an extraction-semantics change caused silent
    regressions (P15); this surfaces the risk. Always passes — never gates."""
    t = time.perf_counter()

    def _result(detail: str) -> CheckResult:
        return CheckResult(
            "pipeline-version", True, time.perf_counter() - t, _trim(detail), advisory=True
        )

    # Fail-loud against silent rot: a listed module that no longer exists can never
    # appear in the diff, so the check would silently stop guarding it (this bit us
    # once — a stale _semgrep.py entry outlived semgrep's removal). Surface it instead.
    missing = [m for m in _EXTRACTION_MODULES if not (ROOT / m).exists()]
    stale = (
        f"pipeline-version references {len(missing)} nonexistent module(s); fix "
        f"_EXTRACTION_MODULES in tools/quality.py: {', '.join(missing)}. "
        if missing
        else ""
    )

    # Staged changes take precedence (the hook path); else compare the work tree to HEAD.
    has_staged = _run(["git", "diff", "--cached", "--quiet"]).returncode != 0
    base = "--cached" if has_staged else "HEAD"
    changed = {
        line.strip() for line in _run(["git", "diff", base, "--name-only"]).stdout.splitlines()
    }
    hit = [m for m in _EXTRACTION_MODULES if m in changed]
    if not hit:
        return _result(stale)
    # Extraction changed — OK only if _pipeline.py also changed AND bumped the version.
    if _PIPELINE_FILE in changed:
        pipeline_diff = _run(["git", "diff", base, "--", _PIPELINE_FILE]).stdout
        if "_PIPELINE_VERSION" in pipeline_diff:
            return _result(stale + "extraction modules changed; _PIPELINE_VERSION bumped")
    return _result(
        stale
        + f"L1 extraction module(s) changed without a _PIPELINE_VERSION bump in {_PIPELINE_FILE}. "
        + "If extraction semantics changed, bump the version to invalidate cached artifacts. "
        + f"Changed: {', '.join(hit)}"
    )


# Ordered check-set. lint/format run first so the hook path autofixes + re-stages
# before the heavier verification steps.
CHECKS: tuple[CheckSpec, ...] = (
    CheckSpec("lockfile", _touches_pyproject_or_lock, _run_lockfile),
    CheckSpec("lint", _applies_ruff, _run_lint),
    CheckSpec("format", _applies_ruff, _run_format),
    CheckSpec("typecheck", _needs_python, _run_types),
    CheckSpec("basedpyright", _under_rules, _run_basedpyright),
    CheckSpec("layers", _applies_layers, _run_layers),
    CheckSpec("framework-names", _under_semantic, _run_framework_names),
    CheckSpec("runtime-deps", _under_flawed, _run_runtime_deps),
    CheckSpec("managed-subprocess", _under_flawed, _run_managed_subprocess),
    CheckSpec("l1-schema", _applies_l1_schema, _run_l1_schema),
    CheckSpec("tests", _applies_tests, _run_tests),
    CheckSpec("pipeline-version", _under_flawed, _run_pipeline_version),
)
_FORMAT_CHECKS = tuple(c for c in CHECKS if c.name in {"lint", "format"})
_TEST_CHECKS = tuple(c for c in CHECKS if c.name == "tests")


def planned_check_names(scope: Scope, specs: Sequence[CheckSpec] = CHECKS) -> list[str]:
    """Names of the checks that apply to *scope*, in run order (no execution)."""
    return [c.name for c in specs if c.applies(scope)]


# --------------------------------------------------------------------------- #
# Orchestration + reporting
# --------------------------------------------------------------------------- #


def _report(results: list[CheckResult], *, scope_label: str, total: float) -> int:
    print(f"\nquality gate ({scope_label})")
    hard_failures = 0
    for r in results:
        if not r.ok and not r.advisory:
            mark, hard_failures = "FAIL", hard_failures + 1
        elif not r.ok:
            mark = "warn"
        else:
            mark = " ok "
        print(f"  {mark}  {r.name:<20}{r.duration:6.2f}s")
        if r.detail and (not r.ok or r.advisory or r.always_detail):
            for line in r.detail.splitlines():
                print(f"        {line}")
    verdict = "FAILED" if hard_failures else "PASS"
    suffix = f"  ({hard_failures} check(s) failed)" if hard_failures else ""
    print(f"  ----\n  {verdict} in {total:.2f}s{suffix}")
    return 1 if hard_failures else 0


def run_gate(scope: Scope, specs: Sequence[CheckSpec] = CHECKS) -> int:
    results: list[CheckResult] = []
    start = time.perf_counter()
    for spec in specs:
        if not spec.applies(scope):
            continue
        result = spec.run(scope)
        results.append(result)
        if not result.ok and not result.advisory:
            break  # fail fast, like the legacy gate
    if not results:
        print("quality gate: no checks apply to the supplied targets.")
        return 0
    label = "full" if scope.full else f"scoped: {', '.join(scope.raw_targets)}"
    return _report(results, scope_label=label, total=time.perf_counter() - start)


# --------------------------------------------------------------------------- #
# Scope construction + CLI
# --------------------------------------------------------------------------- #


def build_scope(
    raw_targets: Sequence[str],
    *,
    root: Path = ROOT,
    apply_fixes: bool = True,
    include_slow: bool = False,
    staged: bool = False,
    pytest_extra: Sequence[str] = (),
) -> Scope:
    """Resolve CLI targets into a :class:`Scope`. No targets => full-repo scope.

    A missing explicit target raises ``ValueError``; in ``staged`` mode missing
    paths are skipped (a staged file can vanish before the hook runs).
    """
    kept: list[str] = []
    paths: list[Path] = []
    rels: list[str] = []
    for raw in raw_targets:
        part = raw.split("::", 1)[0]
        path = Path(part)
        absolute = (path if path.is_absolute() else root / path).resolve()
        if not absolute.exists():
            if staged:
                continue
            msg = f"Target does not exist: {part}"
            raise ValueError(msg)
        kept.append(raw)
        paths.append(absolute)
        rels.append(Path(os.path.relpath(absolute, root)).as_posix())
    return Scope(
        raw_targets=tuple(kept),
        paths=tuple(paths),
        rel_paths=tuple(rels),
        staged_paths=tuple(raw_targets) if staged else (),
        full=not kept,
        apply_fixes=apply_fixes,
        include_slow=include_slow,
        staged=staged,
        pytest_extra=tuple(pytest_extra),
    )


def _staged_files() -> list[str]:
    cp = _run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"])
    return [ln for ln in cp.stdout.splitlines() if ln.strip()]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tools.quality", description="The single owner of the flawed quality gate."
    )
    parser.add_argument("targets", nargs="*", help="Files, directories, or pytest nodes.")
    parser.add_argument(
        "--staged", action="store_true", help="Scope to git-staged files (hook path)."
    )
    parser.add_argument(
        "--tests-only", action="store_true", help="Run only the pytest+testmon step."
    )
    parser.add_argument(
        "--format-only", action="store_true", help="Run only ruff lint+format (autofix)."
    )
    parser.add_argument(
        "--no-format", action="store_true", help="Never mutate: lint/format are check-only."
    )
    parser.add_argument(
        "--all", action="store_true", help="Include @slow tests (default excludes them)."
    )
    args, extra = parser.parse_known_args(argv)

    if args.tests_only and args.format_only:
        print("quality: --tests-only and --format-only are mutually exclusive.", file=sys.stderr)
        return 2

    targets = list(args.targets)
    if args.staged:
        if targets:
            print(
                "quality: --staged takes targets from git, not the command line.", file=sys.stderr
            )
            return 2
        targets = _staged_files()
        if not targets:
            print("quality gate: nothing staged.")
            return 0

    try:
        scope = build_scope(
            targets,
            apply_fixes=not args.no_format and not args.tests_only,
            include_slow=args.all,
            staged=args.staged,
            pytest_extra=tuple(extra),
        )
    except ValueError as exc:
        print(f"quality: {exc}", file=sys.stderr)
        return 2

    specs = _TEST_CHECKS if args.tests_only else _FORMAT_CHECKS if args.format_only else CHECKS
    return run_gate(scope, specs)


if __name__ == "__main__":
    raise SystemExit(main())
