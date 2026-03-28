"""The smoke pack is an id-manifest over the built-in library.

Guards: every manifest id resolves to exactly one loaded built-in detector (a
rename/removal fails loudly here instead of silently shrinking the smoke set),
the ``"smoke"`` token resolves to precisely those ids, and the pack ships no
duplicate snapshot files.
"""

from __future__ import annotations

from flawed._cli.rules import (
    discover_rule_files,
    load_configured_detectors,
    smoke_rule_count,
)
from flawed._config.paths import iter_python_source_files
from flawed._config.schema import ResolvedConfig, RuleConfig
from flawed._rules import builtin_rules_dir
from flawed._rules_smoke import SMOKE_RULE_IDS, smoke_rules_dir


def _builtin_rule_ids() -> set[str]:
    config = ResolvedConfig()
    detectors = load_configured_detectors(config, discover_rule_files(config))
    return {d.rule_id for d in detectors}


def test_smoke_pack_has_no_duplicate_snapshot_files() -> None:
    """No smoke file may share a stem with a built-in rule file (snapshots drift)."""
    builtin_stems = {p.stem for p in iter_python_source_files(builtin_rules_dir())}
    smoke_stems = {
        p.stem for p in iter_python_source_files(smoke_rules_dir()) if not p.name.startswith("_")
    }
    overlap = builtin_stems & smoke_stems
    assert not overlap, f"smoke pack still contains duplicate snapshot files: {sorted(overlap)}"


def test_smoke_ids_resolve_in_builtin() -> None:
    """Every manifest id must be a real, currently-loadable built-in rule."""
    missing = set(SMOKE_RULE_IDS) - _builtin_rule_ids()
    assert not missing, f"manifest references ids that no longer exist: {sorted(missing)}"


def test_smoke_manifest_resolves_to_exactly_its_ids() -> None:
    """Loading with the 'smoke' token yields precisely the manifest ids — no more, no less."""
    config = ResolvedConfig(rules=RuleConfig(paths=("smoke",)))
    detectors = load_configured_detectors(config, discover_rule_files(config))
    assert {d.rule_id for d in detectors} == set(SMOKE_RULE_IDS)


def test_smoke_rule_count_matches_manifest() -> None:
    """The dashboard count is the manifest length (no separate file-walk to drift)."""
    assert smoke_rule_count() == len(SMOKE_RULE_IDS)
