"""Curated smoke-test rule set — an id-manifest over the built-in library.

A small, fast subset of built-in rules for quick iteration and CI smoke runs
(``flawed scan --smoke`` / the ``"smoke"`` rules.paths token). The full built-in
library lives in :mod:`flawed._rules` and is the default.

The smoke set is a manifest of rule ids (:data:`SMOKE_RULE_IDS`), not a parallel
tree of copied files: the ``"smoke"`` token resolves to the built-in library
filtered to these ids, so the manifest can never drift from the canonical rules.
"""

from __future__ import annotations

from pathlib import Path

#: The curated smoke set, as built-in rule ids. The CLI resolves these against
#: the full built-in library. Single source of truth for "what ``--smoke`` runs".
SMOKE_RULE_IDS: tuple[str, ...] = (
    "endpoints",
    "request-inputs",
    "route-guards",
    "value-flow",
    "type-disagreements",
)


def smoke_rules_dir() -> Path:
    """Return the filesystem path to the smoke pack."""
    return Path(__file__).resolve().parent
