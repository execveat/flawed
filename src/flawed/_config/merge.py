"""Hierarchical config merge logic.

Implements the merge semantics from the config spec:

- Scalars: later replaces earlier.
- ``paths``: append (unless ``!reset`` sentinel is first).
- ``providers.<id>.enable``: replace.
- ``providers.<id>.config``: deep-merge (later keys win).
- ``rules.include/exclude``: append.
- ``meta_effects``: merge by name (later wins).
- ``groups``: merge by group name.
- ``overrides``: append (order preserved).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flawed._config.schema import (
    ConfigError,
    ProviderConfig,
    ProviderEntry,
    ResolvedConfig,
    RuleConfig,
    TimeoutConfig,
    TypeEnrichmentConfig,
    parse_cache_invalidation,
    parse_effect_routing,
    parse_group_def,
    parse_override_block,
    parse_provider_entry,
    parse_timeout_config,
    parse_type_enrichment_config,
)


def merge_raw_into(base: ResolvedConfig, raw: dict[str, Any]) -> ResolvedConfig:
    """Return a new ``ResolvedConfig`` with *raw* YAML dict merged in.

    *base* is not mutated — a fresh frozen dataclass is returned.
    """
    data_dir = base.data_dir
    state_dir = base.state_dir
    repo_local = base.repo_local

    if "data_dir" in raw:
        data_dir = Path(str(raw["data_dir"])).expanduser()
    if "state_dir" in raw:
        state_dir = Path(str(raw["state_dir"])).expanduser()
    if "repo_local" in raw:
        repo_local = bool(raw["repo_local"])

    cache_invalidation = base.cache_invalidation
    if "cache_invalidation" in raw:
        cache_invalidation = parse_cache_invalidation(raw["cache_invalidation"])

    observability_enabled = base.observability_enabled
    if "observability_enabled" in raw:
        observability_enabled = bool(raw["observability_enabled"])
    observability_log_path = base.observability_log_path
    if "observability_log_path" in raw:
        log_path_raw = raw["observability_log_path"]
        observability_log_path = (
            Path(str(log_path_raw)).expanduser() if log_path_raw is not None else None
        )
    observability_sampler_hz = base.observability_sampler_hz
    if "observability_sampler_hz" in raw:
        observability_sampler_hz = _parse_sampler_hz(raw["observability_sampler_hz"])

    providers = _merge_providers(base.providers, raw.get("providers"))
    rules = _merge_rules(base.rules, raw.get("rules"))
    type_enrichment = _merge_type_enrichment(
        base.type_enrichment,
        raw.get("type_enrichment"),
    )
    timeouts = _merge_timeouts(base.timeouts, raw.get("timeouts"))

    meta_effects = dict(base.meta_effects)
    for name, expr in (raw.get("meta_effects") or {}).items():
        meta_effects[str(name)] = str(expr)

    effect_routing = dict(base.effect_routing)
    raw_effects = raw.get("effects")
    if isinstance(raw_effects, dict):
        effect_routing.update(parse_effect_routing(raw_effects))

    groups = dict(base.groups)
    for name, gdef in (raw.get("groups") or {}).items():
        if isinstance(gdef, dict):
            groups[str(name)] = parse_group_def(gdef)

    new_overrides = list(base.overrides)
    new_overrides.extend(
        parse_override_block(entry)
        for entry in raw.get("overrides") or []
        if isinstance(entry, dict)
    )

    return ResolvedConfig(
        data_dir=data_dir,
        state_dir=state_dir,
        repo_local=repo_local,
        cache_invalidation=cache_invalidation,
        observability_enabled=observability_enabled,
        observability_log_path=observability_log_path,
        observability_sampler_hz=observability_sampler_hz,
        providers=providers,
        rules=rules,
        type_enrichment=type_enrichment,
        timeouts=timeouts,
        meta_effects=meta_effects,
        effect_routing=effect_routing,
        groups=groups,
        overrides=tuple(new_overrides),
    )


def _parse_sampler_hz(raw: object) -> float:
    """Parse ``observability_sampler_hz`` — a non-negative number (fail-closed)."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        msg = f"'observability_sampler_hz' must be a number, got {type(raw).__name__}"
        raise ConfigError(msg)
    if raw < 0:
        msg = f"'observability_sampler_hz' must be >= 0, got {raw!r}"
        raise ConfigError(msg)
    return float(raw)


# ── Type-enrichment merge ──────────────────────────────────────────


def _merge_type_enrichment(
    base: TypeEnrichmentConfig,
    raw: object,
) -> TypeEnrichmentConfig:
    if raw is None:
        return base
    if not isinstance(raw, dict):
        msg = f"Expected mapping for 'type_enrichment', got {type(raw).__name__}"
        raise ConfigError(msg)
    if not raw:
        return base
    return parse_type_enrichment_config(
        {
            "enable_mypy_batch": raw.get("enable_mypy_batch", base.enable_mypy_batch),
            "basedpyright_max_queries": raw.get(
                "basedpyright_max_queries",
                base.basedpyright_max_queries,
            ),
            "basedpyright_max_probe_files": raw.get(
                "basedpyright_max_probe_files",
                base.basedpyright_max_probe_files,
            ),
            "basedpyright_max_source_files": raw.get(
                "basedpyright_max_source_files",
                base.basedpyright_max_source_files,
            ),
            "basedpyright_max_workspace_bytes": raw.get(
                "basedpyright_max_workspace_bytes",
                base.basedpyright_max_workspace_bytes,
            ),
            "basedpyright_timeout_seconds": raw.get(
                "basedpyright_timeout_seconds",
                base.basedpyright_timeout_seconds,
            ),
            "mypy_batch_timeout_seconds": raw.get(
                "mypy_batch_timeout_seconds",
                base.mypy_batch_timeout_seconds,
            ),
            "mypy_batch_max_files": raw.get(
                "mypy_batch_max_files",
                base.mypy_batch_max_files,
            ),
        }
    )


# ── Timeout merge ─────────────────────────────────────────────────


def _merge_timeouts(base: TimeoutConfig, raw: object) -> TimeoutConfig:
    if raw is None:
        return base
    if not isinstance(raw, dict):
        msg = f"Expected mapping for 'timeouts', got {type(raw).__name__}"
        raise ConfigError(msg)
    if not raw:
        return base
    return parse_timeout_config(
        {
            "overall": raw.get("overall", base.overall),
            "per_layer": raw.get("per_layer", base.per_layer),
            "per_rule": raw.get("per_rule", base.per_rule),
        }
    )


# ── Providers merge ────────────────────────────────────────────────


def _merge_providers(
    base: ProviderConfig,
    raw: object,
) -> ProviderConfig:
    if not isinstance(raw, dict) or not raw:
        return base

    base_dir = base.base_dir
    if "base_dir" in raw and raw["base_dir"] is not None:
        base_dir = Path(str(raw["base_dir"])).expanduser()

    paths = _merge_path_tuples(base.paths, raw.get("paths"))

    entries = dict(base.entries)
    reserved = {"base_dir", "paths"}
    for key, val in raw.items():
        if key in reserved:
            continue
        if isinstance(val, dict):
            if key in entries:
                entries[key] = _merge_provider_entry(entries[key], val)
            else:
                entries[key] = parse_provider_entry(val)

    return ProviderConfig(base_dir=base_dir, paths=paths, entries=entries)


def _merge_provider_entry(
    base: ProviderEntry,
    raw: dict[str, Any],
) -> ProviderEntry:
    enable: bool | tuple[str, ...] = base.enable
    enable_raw = raw.get("enable")
    if enable_raw is not None:
        if isinstance(enable_raw, bool):
            enable = enable_raw
        elif isinstance(enable_raw, list):
            enable = tuple(str(s) for s in enable_raw)
        else:
            msg = f"'enable' must be bool or list, got {type(enable_raw).__name__}"
            raise ConfigError(msg)

    config = _deep_merge_dicts(base.config, raw.get("config") or {})

    return ProviderEntry(enable=enable, config=config)


def _deep_merge_dicts(
    base: dict[str, Any],
    raw: object,
) -> dict[str, Any]:
    """Recursively merge provider config dictionaries."""
    result = dict(base)
    if not isinstance(raw, dict):
        return result
    for key, value in raw.items():
        skey = str(key)
        existing = result.get(skey)
        if isinstance(existing, dict) and isinstance(value, dict):
            result[skey] = _deep_merge_dicts(existing, value)
        else:
            result[skey] = value
    return result


# ── Rules merge ────────────────────────────────────────────────────


def _merge_rules(base: RuleConfig, raw: object) -> RuleConfig:
    if not isinstance(raw, dict) or not raw:
        return base

    base_dir = base.base_dir
    if "base_dir" in raw and raw["base_dir"] is not None:
        base_dir = Path(str(raw["base_dir"])).expanduser()

    return RuleConfig(
        base_dir=base_dir,
        paths=_merge_path_tuples(base.paths, raw.get("paths")),
        include=_merge_str_tuples(base.include, raw.get("include")),
        exclude=_merge_str_tuples(base.exclude, raw.get("exclude")),
        include_regex=_merge_str_tuples(
            base.include_regex,
            raw.get("include_regex"),
        ),
        exclude_regex=_merge_str_tuples(
            base.exclude_regex,
            raw.get("exclude_regex"),
        ),
    )


# ── Tuple merge utilities ──────────────────────────────────────────


def _merge_path_tuples(
    base: tuple[Path | str, ...],
    raw: list[Any] | None,
) -> tuple[Path | str, ...]:
    """Append path entries, or reset if ``!reset`` is first."""
    if not isinstance(raw, list):
        return base

    items: list[Path | str] = []
    reset = bool(raw) and str(raw[0]) == "!reset"
    start = 1 if reset else 0

    if not reset:
        items.extend(base)

    for entry in raw[start:]:
        s = str(entry)
        if s in {"builtin", "!reset"}:
            items.append(s)
        else:
            items.append(Path(s).expanduser())
    return tuple(items)


def _merge_str_tuples(
    base: tuple[str, ...],
    raw: list[Any] | None,
) -> tuple[str, ...]:
    if not isinstance(raw, list):
        return base
    return (*base, *(str(s) for s in raw))
