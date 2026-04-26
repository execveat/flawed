"""External tier — tests that genuinely run real tools (basedpyright).

This is the small, explicit minority that exercises actual external-tool
integration (type enrichment, the L1 build pipeline). They
are inherently slow and spawn subprocesses, so:

- every test here is auto-marked ``@pytest.mark.slow`` (below), which excludes it
  from the fast default ``mise run test`` (``-m "not slow"``); run them with
  ``mise run test -- --all``;
- the subprocess guardrail (``tests/_guards/subprocess_guard.py``) permits
  spawns under ``tests/external/``.

Keep this tier SMALL and intentional: a test belongs here only if its *purpose*
is to validate real-tool behavior. Anything that merely needs analysis facts
should load committed artifacts via ``tests.helpers.artifact_fixtures`` instead.
"""

from __future__ import annotations

import pytest


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    """Auto-mark every test in this tier ``slow`` so the default run skips it."""
    for item in items:
        if "/tests/external/" in item.path.as_posix():
            item.add_marker(pytest.mark.slow)
