"""YAML loading and hierarchical config merge.

Loads configuration from the 4-level file hierarchy and produces a
single ``ResolvedConfig``.  YAML files are parsed at the boundary
into typed objects immediately — no raw dicts leak past this module.

Hierarchy (lowest to highest priority):
1. Built-in defaults  (hardcoded ``ResolvedConfig()``)
2. ``~/.config/flawed/config.yaml``
3. ``~/.config/flawed/conf.d/*.yaml``  (lexicographic order)
4. ``.flawed/config.yaml``  (if ``repo_local`` enabled in earlier layers)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from flawed._config.merge import merge_raw_into
from flawed._config.paths import flawed_config_dir, flawed_data_dir, flawed_state_dir
from flawed._config.schema import ConfigError, ResolvedConfig

try:
    import yaml

    _HAS_YAML = True
except ModuleNotFoundError:  # pragma: no cover
    _HAS_YAML = False


def load_config(
    *,
    config_path: Path | None = None,
    repo_path: Path | None = None,
) -> ResolvedConfig:
    """Load and merge configuration from all file layers.

    Args:
        config_path: If provided, load ONLY this file (skip the
            normal hierarchy).  Used by ``--config`` CLI flag.
        repo_path: The repository being analyzed.  When ``repo_local``
            is enabled, ``.flawed/config.yaml`` inside this directory
            is also loaded.  Defaults to ``Path.cwd()``.

    Returns:
        A fully merged, frozen ``ResolvedConfig``.

    Raises:
        ConfigError: If any config file contains invalid data.
    """
    cfg = _defaults()

    if config_path is not None:
        return _load_and_merge(cfg, config_path)

    config_dir = flawed_config_dir()

    # Level 2: global config
    global_cfg = config_dir / "config.yaml"
    if global_cfg.is_file():
        cfg = _load_and_merge(cfg, global_cfg)

    # Level 3: conf.d
    conf_d = config_dir / "conf.d"
    if conf_d.is_dir():
        for yaml_file in sorted(conf_d.glob("*.yaml")):
            if yaml_file.is_file():
                cfg = _load_and_merge(cfg, yaml_file)

    # Level 4: repo-local (only if enabled by earlier layers)
    if cfg.repo_local:
        target = repo_path or Path.cwd()
        local_cfg = target / ".flawed" / "config.yaml"
        if local_cfg.is_file():
            cfg = _load_and_merge(cfg, local_cfg)

    return cfg


def _defaults() -> ResolvedConfig:
    """Built-in defaults (level 1)."""
    return ResolvedConfig(
        data_dir=flawed_data_dir(),
        state_dir=flawed_state_dir(),
    )


def _load_and_merge(base: ResolvedConfig, path: Path) -> ResolvedConfig:
    """Parse a YAML file and merge into *base*."""
    raw = _read_yaml(path)
    if raw is None:
        return base
    try:
        return merge_raw_into(base, raw)
    except ConfigError:
        raise
    except Exception as exc:
        msg = f"Error merging config from {path}: {exc}"
        raise ConfigError(msg) from exc


def _read_yaml(path: Path) -> dict[str, Any] | None:
    """Read a YAML file and return the top-level mapping, or None."""
    if not _HAS_YAML:
        print(
            "Warning: PyYAML not installed — skipping config file "
            f"{path}.  Install with: pip install pyyaml",
            file=sys.stderr,
        )
        return None
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return None
    data = yaml.safe_load(text)
    if data is None:
        return None
    if not isinstance(data, dict):
        msg = f"Config file {path} must contain a YAML mapping, got {type(data).__name__}"
        raise ConfigError(msg)
    return data
