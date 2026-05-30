"""E2E tier — full vertical-slice tests driving the CLI (``flawed scan`` / ``--json``).

These run the whole pipeline end-to-end through the closest-to-CLI entry point
(``CliRunner``), so they spawn real tools (basedpyright) and are
inherently slow. Therefore:

- every test here is auto-marked ``@pytest.mark.slow`` (below), excluding it from
  the fast default ``mise run test`` (``-m "not slow"``); run with
  ``mise run test -- --all``;
- the subprocess guardrail (``tests/_guards/subprocess_guard.py``) permits spawns
  under ``tests/e2e/``.

Keep this tier VERY small and well-chosen: a handful of vertical slices for
well-rounded coverage (a known finding fires, ``--json``/SARIF schema validity,
cache-hit identity, ``--no-semantic`` index-only, clean-repo exit code). Broad
empirical/corpus coverage is out of scope for this tier.
"""

from __future__ import annotations

import pytest


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    """Auto-mark every test in this tier ``slow`` so the default run skips it."""
    for item in items:
        if "/tests/e2e/" in item.path.as_posix():
            item.add_marker(pytest.mark.slow)
