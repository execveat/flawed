from __future__ import annotations

from pathlib import Path

import pytest

SPECS_DIR = Path(__file__).parent

# Mapping of spec file (relative to SPECS_DIR) to xfail reason with backlog ID.
# Files NOT listed here run normally (no marker applied).
_XFAIL_BY_FILE: dict[str, str] = {
    # basics — all currently scoped basic discovery specs run except node-level future APIs below
    # semantic — unwired L2 subsystems
    # semantic/test_cross_cutting.py — wired in P8.1b
    # detection — all P6 detection spec files are enabled. Remaining known
    # precision gaps are tracked below as node-level xfails.
}

# Node-level xfails for known precision gaps, matched as a substring of the
# nodeid. Currently empty: a prior entry (a removed rule's
# test_crossframe_read_before_write_is_confident) masked a cross-frame
# HIGH->MEDIUM downgrade caused by spurious duplicate/<unknown>-location L1 call
# edges. The AST-only call graph (FLAW-301, ae853748) dropped those edges, so the
# single-hop confidence check resolves cleanly and the spec now asserts the
# confident HIGH ordering directly (FLAW-242) — no longer xfail-masked.
_XFAIL_BY_NODEID: dict[str, str] = {}


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Apply per-file xfail markers to spec tests with unwired APIs."""
    for item in items:
        item_path = Path(item.fspath)
        if not item_path.is_relative_to(SPECS_DIR):
            continue
        try:
            rel = str(item_path.relative_to(SPECS_DIR))
        except ValueError:
            continue

        # File-level xfail
        reason = _XFAIL_BY_FILE.get(rel)
        if reason is not None:
            item.add_marker(pytest.mark.xfail(reason=reason, strict=False))
            continue

        # Individual test xfail (node ID suffix after specs dir)
        node_suffix = (
            item.nodeid.split("tests/specs/")[-1] if "tests/specs/" in item.nodeid else ""
        )
        for node_pattern, node_reason in _XFAIL_BY_NODEID.items():
            if node_suffix.endswith(node_pattern) or node_pattern in node_suffix:
                item.add_marker(pytest.mark.xfail(reason=node_reason, strict=False))
                break
