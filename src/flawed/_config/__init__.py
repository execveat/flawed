"""Configuration system for flawed.

Loads, validates, and merges YAML configuration from a 4-level hierarchy:

1. Built-in defaults (hardcoded)
2. Global config  ``~/.config/flawed/config.yaml``
3. Global conf.d  ``~/.config/flawed/conf.d/*.yaml``  (lexicographic)
4. Repo-local     ``.flawed/config.yaml``  (if ``repo_local`` is enabled)

CLI arguments and rule-author overrides are applied by the caller after
``load_config`` returns.

Public API::

    from flawed._config import load_config, ResolvedConfig, RepoIdentity

"""

from flawed._config.loader import load_config
from flawed._config.paths import RepoIdentity
from flawed._config.schema import ResolvedConfig, TypeEnrichmentConfig

__all__ = ["RepoIdentity", "ResolvedConfig", "TypeEnrichmentConfig", "load_config"]
