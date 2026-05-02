"""Check that framework-specific names stay in providers/ only.

Framework knowledge (Flask, Django, etc.) must not leak into the L2 semantic
core modules. This check scans ``src/flawed/_semantic/`` Python files,
excluding the ``providers/`` subdirectory, for framework identifiers.

Exit 0 if clean, exit 1 if violations found.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEMANTIC_DIR = ROOT / "src" / "flawed" / "_semantic"

# Framework names that must NOT appear in L2 core modules.
# Case-sensitive — only matches the capitalized proper noun forms.
FRAMEWORK_NAMES: tuple[str, ...] = (
    "Flask",
    "Django",
    "FastAPI",
    "Starlette",
    "Sanic",
    "Quart",
    "Falcon",
    "Tornado",
    "Bottle",
    "Pyramid",
    "Litestar",
)

# Compile a pattern that matches any framework name as a standalone word.
_PATTERN = re.compile(r"\b(" + "|".join(re.escape(n) for n in FRAMEWORK_NAMES) + r")\b")

# Lines matching these patterns are exempt (comments about being framework-agnostic, etc.)
_EXEMPT_PATTERNS = (
    re.compile(r"#.*framework.agnostic", re.IGNORECASE),
    re.compile(r"#.*not.*framework.specific", re.IGNORECASE),
    re.compile(r"#.*independent of.*framework", re.IGNORECASE),
    re.compile(r"#.*e\.g\.", re.IGNORECASE),
    re.compile(r"#.*example", re.IGNORECASE),
)


def _is_exempt(line: str) -> bool:
    """True if the line is a comment explaining framework-agnosticism."""
    return any(p.search(line) for p in _EXEMPT_PATTERNS)


def _is_core_file(path: Path) -> bool:
    """True if path is a semantic core module (not in providers/)."""
    try:
        path.relative_to(SEMANTIC_DIR / "providers")
    except ValueError:
        return path.suffix == ".py"
    return False


def main() -> int:
    """Scan L2 core for framework name leaks."""
    violations: list[tuple[Path, int, str, str]] = []

    for py_file in sorted(SEMANTIC_DIR.rglob("*.py")):
        if not _is_core_file(py_file):
            continue

        lines = py_file.read_text(encoding="utf-8").splitlines()
        for lineno, line in enumerate(lines, 1):
            match = _PATTERN.search(line)
            if match and not _is_exempt(line):
                violations.append((py_file, lineno, match.group(), line.strip()))

    if not violations:
        return 0

    print("Framework names found in L2 semantic core (must be in providers/ only):\n")
    for path, lineno, name, line in violations:
        rel = path.relative_to(ROOT)
        print(f"  {rel}:{lineno}: {name!r} in: {line}")
    print(f"\n{len(violations)} violation(s) found.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
