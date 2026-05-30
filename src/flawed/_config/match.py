"""Override matching logic.

Given a ``RepoIdentity`` and the resolved groups/overrides configuration,
determines which override blocks apply and merges them into the config.

Match semantics:
- Each override block has a ``MatchCriteria`` with repo/group/tag predicates.
- All present (non-empty) predicates are ANDed.
- An empty ``MatchCriteria`` matches everything (vacuous truth).
- Multiple override blocks apply in order; later blocks win.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from flawed._config.merge import _merge_provider_entry, _merge_rules, _merge_type_enrichment
from flawed._config.schema import (
    GroupDef,
    MatchCriteria,
    OverrideBlock,
    ProviderConfig,
    ResolvedConfig,
    TypeEnrichmentOverride,
)

if TYPE_CHECKING:
    from flawed._config.paths import RepoIdentity


def apply_overrides(
    config: ResolvedConfig,
    identity: RepoIdentity,
) -> ResolvedConfig:
    """Return a new config with all matching overrides applied.

    Iterates through ``config.overrides`` in order, applying each
    block whose ``match`` criteria are satisfied by *identity*.
    """
    result = config
    for block in config.overrides:
        if _matches(block.match, identity, config.groups):
            result = _apply_single(result, block)
    return result


def _matches(
    criteria: MatchCriteria,
    identity: RepoIdentity,
    groups: dict[str, GroupDef],
) -> bool:
    """All non-empty predicates must be satisfied (AND)."""
    if criteria.repo:
        repo_ids = {identity.canonical, str(identity.path)}
        if not repo_ids.intersection(criteria.repo):
            return False

    if criteria.group:
        membership = _groups_for(identity, groups)
        if not membership.intersection(criteria.group):
            return False

    if criteria.tag:
        tags = _tags_for(identity, groups)
        if not tags.intersection(criteria.tag):
            return False

    return True


def _groups_for(
    identity: RepoIdentity,
    groups: dict[str, GroupDef],
) -> set[str]:
    """Return the set of group names this repo belongs to."""
    repo_ids = {identity.canonical, str(identity.path)}
    return {name for name, gdef in groups.items() if repo_ids.intersection(gdef.repos)}


def _tags_for(
    identity: RepoIdentity,
    groups: dict[str, GroupDef],
) -> set[str]:
    """Return the union of tags from all groups this repo belongs to."""
    repo_ids = {identity.canonical, str(identity.path)}
    tags: set[str] = set()
    for gdef in groups.values():
        if repo_ids.intersection(gdef.repos):
            tags.update(gdef.tags)
    return tags


def _apply_single(
    config: ResolvedConfig,
    block: OverrideBlock,
) -> ResolvedConfig:
    """Merge a single override block into the config."""
    providers = config.providers
    if block.providers:
        entries = dict(providers.entries)
        for pid, pentry in block.providers.items():
            if pid in entries:
                entries[pid] = _merge_provider_entry(
                    entries[pid],
                    {"enable": pentry.enable, "config": pentry.config},
                )
            else:
                entries[pid] = pentry
        providers = ProviderConfig(
            base_dir=providers.base_dir,
            paths=providers.paths,
            entries=entries,
        )

    rules = config.rules
    if block.rules is not None:
        br = block.rules
        raw: dict[str, object] = {}
        if br.base_dir is not None:
            raw["base_dir"] = str(br.base_dir)
        if br.paths:
            raw["paths"] = list(br.paths)
        if br.include:
            raw["include"] = list(br.include)
        if br.exclude:
            raw["exclude"] = list(br.exclude)
        if br.include_regex:
            raw["include_regex"] = list(br.include_regex)
        if br.exclude_regex:
            raw["exclude_regex"] = list(br.exclude_regex)
        rules = _merge_rules(rules, raw)

    type_enrichment = config.type_enrichment
    if block.type_enrichment is not None:
        type_enrichment = _merge_type_enrichment(
            type_enrichment,
            _type_enrichment_override_raw(block.type_enrichment),
        )

    # Use ``dataclasses.replace`` so EVERY non-overridden field round-trips
    # automatically. The previous hand-listed ``ResolvedConfig(...)`` silently
    # dropped ``cache_invalidation`` and ``timeouts`` (resetting them to defaults
    # on any override match) — FLAW-351. ``replace`` makes that defect class
    # impossible and is future-proof as fields are added (e.g. observability_*).
    return replace(
        config,
        providers=providers,
        rules=rules,
        type_enrichment=type_enrichment,
    )


def _type_enrichment_override_raw(block: TypeEnrichmentOverride) -> dict[str, object]:
    raw: dict[str, object] = {}
    if block.enable_mypy_batch is not None:
        raw["enable_mypy_batch"] = block.enable_mypy_batch
    if block.basedpyright_max_queries is not None:
        raw["basedpyright_max_queries"] = block.basedpyright_max_queries
    if block.basedpyright_max_probe_files is not None:
        raw["basedpyright_max_probe_files"] = block.basedpyright_max_probe_files
    if block.basedpyright_max_source_files is not None:
        raw["basedpyright_max_source_files"] = block.basedpyright_max_source_files
    if block.basedpyright_max_workspace_bytes is not None:
        raw["basedpyright_max_workspace_bytes"] = block.basedpyright_max_workspace_bytes
    if block.basedpyright_timeout_seconds is not None:
        raw["basedpyright_timeout_seconds"] = block.basedpyright_timeout_seconds
    if block.mypy_batch_timeout_seconds is not None:
        raw["mypy_batch_timeout_seconds"] = block.mypy_batch_timeout_seconds
    if block.mypy_batch_max_files is not None:
        raw["mypy_batch_max_files"] = block.mypy_batch_max_files
    return raw
