"""Stable filesystem anchors for the test suite.

Resolved from this module (``tests/helpers/``), which never moves, so individual
test files can live in any tier directory (``tests/unit/l1/``, ``tests/external/``,
…) without fragile ``Path(__file__).resolve().parents[N]`` math that silently
breaks when a file is relocated to a different depth.

Usage::

    from tests.helpers.paths import APPS, ARTIFACTS, REPO_ROOT

    fixture = APPS / "flask_basic"
"""

from __future__ import annotations

from pathlib import Path

#: ``tests/`` directory (``tests/helpers/`` -> ``tests/``).
TESTS_DIR = Path(__file__).resolve().parents[1]
#: Repository root.
REPO_ROOT = TESTS_DIR.parent
#: ``src/`` directory.
SRC = REPO_ROOT / "src"
#: ``tests/fixtures/`` directory.
FIXTURES = TESTS_DIR / "fixtures"
#: ``tests/fixtures/apps/`` — fixture application sources.
APPS = FIXTURES / "apps"
#: ``tests/fixtures/artifacts/`` — committed L1 artifacts for fixture apps.
ARTIFACTS = FIXTURES / "artifacts"
