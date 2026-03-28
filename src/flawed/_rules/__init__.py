"""Built-in detection rule library (the default).

This package contains the full, maintained detection-rule library shipped
with flawed (L0 gadgets through L4 ultra-specific rules). It is the default
rule set: a bare ``flawed scan`` runs everything here. Rules are Python files
discovered at runtime by the CLI rule-loading machinery — they are NOT
imported as regular Python modules.

The ``"builtin"`` token in the ``rules.paths`` configuration resolves to this
directory. The smaller, fast curated subset for quick iteration (``flawed scan
--smoke`` / the ``"smoke"`` token) is an id-manifest over this library — see
:mod:`flawed._rules_smoke` — so its canonical entries cannot drift from the
rules maintained here.
"""

from __future__ import annotations

from pathlib import Path


def builtin_rules_dir() -> Path:
    """Return the filesystem path to the built-in rules directory."""
    return Path(__file__).resolve().parent
