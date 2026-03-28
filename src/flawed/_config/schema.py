"""Typed configuration schema.

Every configuration structure is a frozen dataclass.  Raw YAML dicts are
converted into these types at load time (parse-at-the-boundary).
Invalid configuration raises ``ConfigError`` immediately with a clear
message.

Invariants enforced by construction:
- Paths are always ``pathlib.Path``, never strings.
- ``enable`` is ``bool | tuple[str, ...]`` (not a raw union with list).
- Pattern lists are tuples (immutable after construction).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class ConfigError(Exception):
    """Raised when configuration is invalid."""


class CacheInvalidation(StrEnum):
    """Strategy for the repo content hash that keys the results cache.

    The content hash decides when a cached scan is reused versus recomputed,
    so the strategy trades freshness-safety against cost:

    - ``AUTO`` (default): the historical, git-aware hybrid — the git ``HEAD``
      commit (plus a dirty-tree suffix when uncommitted ``.py`` changes exist)
      for git repositories, falling back to an mtime digest for non-git trees.
      The recommended default; correct for the common workflow.
    - ``GIT_HASH``: force the git ``HEAD`` (+ dirty) hash.  A non-git target is
      a configuration error (fail-closed), never a silent fallback.
    - ``MTIME``: digest of ``(relative_path, mtime_ns)`` over all ``.py`` files.
      Fastest and git-agnostic, but trusts filesystem mtimes — blind to a change
      that preserves mtime (e.g. some checkout / restore operations).
    - ``CONTENT_HASH``: digest of ``(relative_path, file_bytes)`` over all
      ``.py`` files.  Strongest (catches any content change regardless of
      mtime) and slowest.
    """

    AUTO = "auto"
    GIT_HASH = "git-hash"
    MTIME = "mtime"
    CONTENT_HASH = "content-hash"


# ── Atomic building blocks ──────────────────────────────────────────


@dataclass(frozen=True)
class ProviderEntry:
    """Per-provider settings.

    Attributes:
        enable: True = auto-discover all capabilities.
            False = completely disabled.
            Tuple of strings = only listed capabilities active.
        config: Opaque dict forwarded to the provider.
    """

    enable: bool | tuple[str, ...] = True
    config: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProviderConfig:
    """Providers section of the config file.

    Attributes:
        base_dir: If set, relative paths resolve against this.
        paths: Directories to scan for provider modules.
        entries: Per-provider knobs keyed by provider ID.
    """

    base_dir: Path | None = None
    paths: tuple[Path | str, ...] = ("builtin",)
    entries: dict[str, ProviderEntry] = field(default_factory=dict)


@dataclass(frozen=True)
class RuleConfig:
    """Rules section of the config file."""

    base_dir: Path | None = None
    paths: tuple[Path | str, ...] = ("builtin",)
    include: tuple[str, ...] = ("*",)
    exclude: tuple[str, ...] = ()
    include_regex: tuple[str, ...] = ()
    exclude_regex: tuple[str, ...] = ()


@dataclass(frozen=True)
class TypeEnrichmentConfig:
    """Layer 1 type-enrichment settings."""

    enable_mypy_batch: bool = False
    """Run the experimental mypy batch oracle alongside basedpyright."""

    basedpyright_max_queries: int = 2000
    """Per-batch reveal_type query budget for the basedpyright oracle.

    Not a hard ceiling: a repo whose query count exceeds this is enriched in
    multiple per-file batches against one workspace, never skipped repo-wide.
    """

    basedpyright_max_probe_files: int = 500
    """Per-batch probe-file budget (source files mutated with reveal_type probes).

    A batch size, not a ceiling — see ``basedpyright_max_queries``.
    """

    basedpyright_max_source_files: int = 5000
    """Maximum Python source files in the basedpyright workspace input.

    A hard guard (not batched): it bounds the cost of the shared workspace every
    batch reuses. Over-budget repos skip type enrichment with a visible notice;
    raise this to enrich very large repos.
    """

    basedpyright_max_workspace_bytes: int = 250_000_000
    """Maximum ignore-pruned workspace bytes copied for basedpyright probes.

    A hard guard (not batched), like ``basedpyright_max_source_files``.
    """

    basedpyright_timeout_seconds: int = 120
    """Wall-clock timeout for the single basedpyright enrichment run, in seconds.

    basedpyright runs once over all probe files (FLAW-268). A cold full-project
    check on a large repo can exceed the old 30 s hardcoded cap and lose its type
    facts (degrading type-aware detection — a false-negative pressure source), so
    the default is 120 s; raise it for very large repos.
    """

    mypy_batch_timeout_seconds: int = 120
    """Wall-clock timeout for the mypy batch build, in seconds."""

    mypy_batch_max_files: int = 5000
    """Maximum source files to pass to the mypy batch oracle."""


@dataclass(frozen=True)
class TimeoutConfig:
    """Pipeline timeout settings.

    All values are in seconds.  ``None`` disables the limit at that
    level.  Defaults are tuned for repos up to ~500 Python files.
    """

    overall: int | None = 600
    """Total scan wall-clock limit.  Default: 10 min."""

    per_layer: int | None = 300
    """Max time for any single layer (L1/L2/L3).  Default: 5 min."""

    per_rule: int | None = 60
    """Max time for a single rule's ``detect()``.  Default: 1 min."""


@dataclass(frozen=True)
class TypeEnrichmentOverride:
    """Partial type-enrichment settings for conditional override blocks."""

    enable_mypy_batch: bool | None = None
    basedpyright_max_queries: int | None = None
    basedpyright_max_probe_files: int | None = None
    basedpyright_max_source_files: int | None = None
    basedpyright_max_workspace_bytes: int | None = None
    basedpyright_timeout_seconds: int | None = None
    mypy_batch_timeout_seconds: int | None = None
    mypy_batch_max_files: int | None = None


@dataclass(frozen=True)
class GroupDef:
    """A named set of repositories with optional tags."""

    repos: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class MatchCriteria:
    """Predicates for an override block.  All present predicates are ANDed."""

    repo: tuple[str, ...] = ()
    group: tuple[str, ...] = ()
    tag: tuple[str, ...] = ()


@dataclass(frozen=True)
class OverrideBlock:
    """A conditional configuration overlay."""

    match: MatchCriteria = field(default_factory=MatchCriteria)
    providers: dict[str, ProviderEntry] = field(default_factory=dict)
    rules: RuleConfig | None = None
    type_enrichment: TypeEnrichmentOverride | None = None


@dataclass(frozen=True)
class EffectRoutingEntry:
    """Restricts which providers contribute to a specific effect category."""

    from_providers: tuple[str, ...] = ()


# ── Top-level resolved config ──────────────────────────────────────


def _default_data_dir() -> Path:
    # Lazy import: paths.py imports this module, so importing it at module
    # level would cycle. The XDG-aware default keeps a bare ``ResolvedConfig()``
    # honouring ``$XDG_DATA_HOME`` (so it never writes into the real ~/.local
    # under test isolation, and matches what ``load_config`` resolves).
    from flawed._config.paths import flawed_data_dir

    return flawed_data_dir()


def _default_state_dir() -> Path:
    from flawed._config.paths import flawed_state_dir

    return flawed_state_dir()


@dataclass(frozen=True)
class ResolvedConfig:
    """Fully merged configuration for a single flawed run.

    This is the **output** of the config-loading pipeline.  Once
    constructed it is immutable — no mutation during execution.
    """

    data_dir: Path = field(default_factory=_default_data_dir)
    state_dir: Path = field(default_factory=_default_state_dir)
    repo_local: bool = False
    cache_invalidation: CacheInvalidation = CacheInvalidation.AUTO

    observability_enabled: bool = True
    """Write a durable per-scan record (per-repo sidecar + central run-log)."""
    observability_log_path: Path | None = None
    """Central run-log path; ``None`` resolves to ``state_dir/runs.jsonl`` at the call site."""
    observability_sampler_hz: float = 0.0
    """Periodic background RSS-sampling rate (Hz); ``0`` disables the sampler."""

    providers: ProviderConfig = field(default_factory=ProviderConfig)
    rules: RuleConfig = field(default_factory=RuleConfig)
    type_enrichment: TypeEnrichmentConfig = field(default_factory=TypeEnrichmentConfig)
    timeouts: TimeoutConfig = field(default_factory=TimeoutConfig)

    meta_effects: dict[str, str] = field(default_factory=dict)
    effect_routing: dict[str, EffectRoutingEntry] = field(
        default_factory=dict,
    )

    groups: dict[str, GroupDef] = field(default_factory=dict)
    overrides: tuple[OverrideBlock, ...] = ()


# ── YAML → typed parsing helpers ───────────────────────────────────


def parse_cache_invalidation(raw: object) -> CacheInvalidation:
    """Parse the top-level ``cache_invalidation`` scalar.

    Accepts the enum itself (idempotent) or one of its string values.  An
    unknown or non-string value is a configuration error — never silently
    coerced to a default (fail-closed).
    """
    if isinstance(raw, CacheInvalidation):
        return raw
    if not isinstance(raw, str):
        msg = f"'cache_invalidation' must be a string, got {type(raw).__name__}"
        raise ConfigError(msg)
    try:
        return CacheInvalidation(raw)
    except ValueError:
        valid = ", ".join(member.value for member in CacheInvalidation)
        msg = f"'cache_invalidation' must be one of: {valid}; got {raw!r}"
        raise ConfigError(msg) from None


def _as_str_tuple(raw: object, *, key: str) -> tuple[str, ...]:
    """Coerce a scalar or list into a tuple of strings."""
    if raw is None:
        return ()
    if isinstance(raw, str):
        return (raw,)
    if isinstance(raw, list):
        return tuple(str(item) for item in raw)
    msg = f"Expected string or list for '{key}', got {type(raw).__name__}"
    raise ConfigError(msg)


def _as_path_tuple(raw: object, *, key: str) -> tuple[Path | str, ...]:
    """Coerce a list of paths, preserving 'builtin' as a string token."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        msg = f"Expected list for '{key}', got {type(raw).__name__}"
        raise ConfigError(msg)
    result: list[Path | str] = []
    for item in raw:
        s = str(item)
        if s in {"builtin", "!reset"}:
            result.append(s)
        else:
            result.append(Path(s).expanduser())
    return tuple(result)


def parse_provider_entry(raw: dict[str, Any]) -> ProviderEntry:
    """Parse a single provider block from raw YAML."""
    enable_raw = raw.get("enable", True)
    if isinstance(enable_raw, bool):
        enable: bool | tuple[str, ...] = enable_raw
    elif isinstance(enable_raw, list):
        enable = tuple(str(s) for s in enable_raw)
    else:
        msg = f"'enable' must be bool or list, got {type(enable_raw).__name__}"
        raise ConfigError(msg)
    config = dict(raw.get("config", {}))
    return ProviderEntry(enable=enable, config=config)


def parse_provider_config(raw: dict[str, Any]) -> ProviderConfig:
    """Parse the ``providers:`` section."""
    base_dir_raw = raw.get("base_dir")
    base_dir = Path(base_dir_raw).expanduser() if base_dir_raw else None
    paths = _as_path_tuple(raw.get("paths"), key="providers.paths")

    reserved = {"base_dir", "paths"}
    entries: dict[str, ProviderEntry] = {}
    for key, val in raw.items():
        if key in reserved:
            continue
        if isinstance(val, dict):
            entries[key] = parse_provider_entry(val)
    return ProviderConfig(base_dir=base_dir, paths=paths, entries=entries)


def parse_rule_config(raw: dict[str, Any]) -> RuleConfig:
    """Parse the ``rules:`` section."""
    base_dir_raw = raw.get("base_dir")
    base_dir = Path(base_dir_raw).expanduser() if base_dir_raw else None
    return RuleConfig(
        base_dir=base_dir,
        paths=_as_path_tuple(raw.get("paths"), key="rules.paths"),
        include=_as_str_tuple(raw.get("include"), key="rules.include"),
        exclude=_as_str_tuple(raw.get("exclude"), key="rules.exclude"),
        include_regex=_as_str_tuple(
            raw.get("include_regex"),
            key="rules.include_regex",
        ),
        exclude_regex=_as_str_tuple(
            raw.get("exclude_regex"),
            key="rules.exclude_regex",
        ),
    )


def parse_type_enrichment_config(raw: dict[str, Any]) -> TypeEnrichmentConfig:
    """Parse the ``type_enrichment:`` section."""
    enable_mypy_batch = raw.get("enable_mypy_batch", False)
    if not isinstance(enable_mypy_batch, bool):
        msg = (
            "'type_enrichment.enable_mypy_batch' must be bool, got "
            f"{type(enable_mypy_batch).__name__}"
        )
        raise ConfigError(msg)
    basedpyright_max_queries = raw.get("basedpyright_max_queries", 2000)
    _validate_positive_int(
        basedpyright_max_queries,
        key="type_enrichment.basedpyright_max_queries",
    )
    basedpyright_max_probe_files = raw.get("basedpyright_max_probe_files", 500)
    _validate_positive_int(
        basedpyright_max_probe_files,
        key="type_enrichment.basedpyright_max_probe_files",
    )
    basedpyright_max_source_files = raw.get("basedpyright_max_source_files", 5000)
    _validate_positive_int(
        basedpyright_max_source_files,
        key="type_enrichment.basedpyright_max_source_files",
    )
    basedpyright_max_workspace_bytes = raw.get(
        "basedpyright_max_workspace_bytes",
        250_000_000,
    )
    _validate_positive_int(
        basedpyright_max_workspace_bytes,
        key="type_enrichment.basedpyright_max_workspace_bytes",
    )
    basedpyright_timeout_seconds = raw.get("basedpyright_timeout_seconds", 120)
    _validate_positive_int(
        basedpyright_timeout_seconds,
        key="type_enrichment.basedpyright_timeout_seconds",
    )
    mypy_batch_timeout_seconds = raw.get("mypy_batch_timeout_seconds", 120)
    _validate_positive_int(
        mypy_batch_timeout_seconds,
        key="type_enrichment.mypy_batch_timeout_seconds",
    )
    mypy_batch_max_files = raw.get("mypy_batch_max_files", 5000)
    _validate_positive_int(
        mypy_batch_max_files,
        key="type_enrichment.mypy_batch_max_files",
    )
    return TypeEnrichmentConfig(
        enable_mypy_batch=enable_mypy_batch,
        basedpyright_max_queries=basedpyright_max_queries,
        basedpyright_max_probe_files=basedpyright_max_probe_files,
        basedpyright_max_source_files=basedpyright_max_source_files,
        basedpyright_max_workspace_bytes=basedpyright_max_workspace_bytes,
        basedpyright_timeout_seconds=basedpyright_timeout_seconds,
        mypy_batch_timeout_seconds=mypy_batch_timeout_seconds,
        mypy_batch_max_files=mypy_batch_max_files,
    )


def parse_type_enrichment_override(raw: dict[str, Any]) -> TypeEnrichmentOverride:
    """Parse a partial ``overrides[].type_enrichment`` block."""
    enable_mypy_batch = raw.get("enable_mypy_batch")
    if enable_mypy_batch is not None and not isinstance(enable_mypy_batch, bool):
        msg = (
            "'overrides[].type_enrichment.enable_mypy_batch' must be bool, got "
            f"{type(enable_mypy_batch).__name__}"
        )
        raise ConfigError(msg)

    basedpyright_max_queries = raw.get("basedpyright_max_queries")
    if basedpyright_max_queries is not None:
        _validate_positive_int(
            basedpyright_max_queries,
            key="overrides[].type_enrichment.basedpyright_max_queries",
        )

    basedpyright_max_probe_files = raw.get("basedpyright_max_probe_files")
    if basedpyright_max_probe_files is not None:
        _validate_positive_int(
            basedpyright_max_probe_files,
            key="overrides[].type_enrichment.basedpyright_max_probe_files",
        )

    basedpyright_max_source_files = raw.get("basedpyright_max_source_files")
    if basedpyright_max_source_files is not None:
        _validate_positive_int(
            basedpyright_max_source_files,
            key="overrides[].type_enrichment.basedpyright_max_source_files",
        )

    basedpyright_max_workspace_bytes = raw.get("basedpyright_max_workspace_bytes")
    if basedpyright_max_workspace_bytes is not None:
        _validate_positive_int(
            basedpyright_max_workspace_bytes,
            key="overrides[].type_enrichment.basedpyright_max_workspace_bytes",
        )

    basedpyright_timeout_seconds = raw.get("basedpyright_timeout_seconds")
    if basedpyright_timeout_seconds is not None:
        _validate_positive_int(
            basedpyright_timeout_seconds,
            key="overrides[].type_enrichment.basedpyright_timeout_seconds",
        )

    timeout = raw.get("mypy_batch_timeout_seconds")
    if timeout is not None:
        _validate_positive_int(
            timeout,
            key="overrides[].type_enrichment.mypy_batch_timeout_seconds",
        )

    max_files = raw.get("mypy_batch_max_files")
    if max_files is not None:
        _validate_positive_int(
            max_files,
            key="overrides[].type_enrichment.mypy_batch_max_files",
        )

    return TypeEnrichmentOverride(
        enable_mypy_batch=enable_mypy_batch,
        basedpyright_max_queries=basedpyright_max_queries,
        basedpyright_max_probe_files=basedpyright_max_probe_files,
        basedpyright_max_source_files=basedpyright_max_source_files,
        basedpyright_max_workspace_bytes=basedpyright_max_workspace_bytes,
        basedpyright_timeout_seconds=basedpyright_timeout_seconds,
        mypy_batch_timeout_seconds=timeout,
        mypy_batch_max_files=max_files,
    )


def _validate_positive_int(value: object, *, key: str) -> None:
    if type(value) is int and value >= 1:
        return
    msg = f"'{key}' must be a positive int, got {value!r}"
    raise ConfigError(msg)


def parse_timeout_config(raw: dict[str, Any]) -> TimeoutConfig:
    """Parse the ``timeouts:`` section."""
    overall = raw.get("overall", 600)
    per_layer = raw.get("per_layer", 300)
    per_rule = raw.get("per_rule", 60)

    for key, val in [("overall", overall), ("per_layer", per_layer), ("per_rule", per_rule)]:
        if val is not None and (not isinstance(val, int) or val < 1):
            msg = f"'timeouts.{key}' must be a positive int or null, got {val!r}"
            raise ConfigError(msg)

    return TimeoutConfig(
        overall=overall,
        per_layer=per_layer,
        per_rule=per_rule,
    )


def parse_group_def(raw: dict[str, Any]) -> GroupDef:
    """Parse a single group definition."""
    return GroupDef(
        repos=_as_str_tuple(raw.get("repos"), key="group.repos"),
        tags=_as_str_tuple(raw.get("tags"), key="group.tags"),
    )


def parse_match_criteria(raw: dict[str, Any]) -> MatchCriteria:
    """Parse the ``match:`` block of an override."""
    return MatchCriteria(
        repo=_as_str_tuple(raw.get("repo"), key="match.repo"),
        group=_as_str_tuple(raw.get("group"), key="match.group"),
        tag=_as_str_tuple(raw.get("tag"), key="match.tag"),
    )


def parse_override_block(raw: dict[str, Any]) -> OverrideBlock:
    """Parse a single override block."""
    match = parse_match_criteria(raw.get("match", {}))
    providers: dict[str, ProviderEntry] = {}
    for key, val in raw.get("providers", {}).items():
        if isinstance(val, dict):
            providers[key] = parse_provider_entry(val)
    rules_raw = raw.get("rules")
    rules = parse_rule_config(rules_raw) if isinstance(rules_raw, dict) else None
    type_enrichment_raw = raw.get("type_enrichment")
    if isinstance(type_enrichment_raw, dict) and type_enrichment_raw:
        type_enrichment = parse_type_enrichment_override(type_enrichment_raw)
    elif isinstance(type_enrichment_raw, dict) or type_enrichment_raw is None:
        type_enrichment = None
    else:
        msg = (
            "Expected mapping for 'overrides[].type_enrichment', got "
            f"{type(type_enrichment_raw).__name__}"
        )
        raise ConfigError(msg)
    return OverrideBlock(
        match=match,
        providers=providers,
        rules=rules,
        type_enrichment=type_enrichment,
    )


def parse_effect_routing(raw: dict[str, Any]) -> dict[str, EffectRoutingEntry]:
    """Parse the ``effects:`` section."""
    result: dict[str, EffectRoutingEntry] = {}
    for category, entry_raw in raw.items():
        if isinstance(entry_raw, dict):
            from_raw = entry_raw.get("from", [])
            result[category] = EffectRoutingEntry(
                from_providers=_as_str_tuple(from_raw, key=f"effects.{category}.from"),
            )
    return result
