"""FLAW-351 regression: applying an override must not drop unrelated config fields.

``_apply_single`` previously reconstructed ``ResolvedConfig`` by hand-listing
fields, silently resetting ``cache_invalidation`` and ``timeouts`` to defaults on
any override match. The fix uses ``dataclasses.replace``, so every non-overridden
field (including the observability settings) round-trips automatically.
"""

from __future__ import annotations

from pathlib import Path

from flawed._config.match import apply_overrides
from flawed._config.merge import merge_raw_into
from flawed._config.paths import RepoIdentity
from flawed._config.schema import CacheInvalidation, ResolvedConfig, TimeoutConfig


def test_override_preserves_unrelated_resolved_config_fields(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    base = ResolvedConfig(
        cache_invalidation=CacheInvalidation.CONTENT_HASH,
        timeouts=TimeoutConfig(overall=42, per_layer=7, per_rule=3),
        observability_enabled=False,
        observability_log_path=Path("/tmp/custom-runs.jsonl"),
        observability_sampler_hz=2.5,
    )
    # An override with an empty match block applies to every repo (vacuous truth);
    # the providers change forces _apply_single to rebuild the config.
    config = merge_raw_into(
        base,
        {"overrides": [{"providers": {"flask_login": {"enable": False}}}]},
    )

    merged = apply_overrides(config, RepoIdentity.from_path(repo))

    # The override itself applied...
    assert merged.providers.entries["flask_login"].enable is False
    # ...and NONE of the unrelated sections were reset (the FLAW-351 bug).
    assert merged.cache_invalidation is CacheInvalidation.CONTENT_HASH
    assert merged.timeouts == TimeoutConfig(overall=42, per_layer=7, per_rule=3)
    assert merged.observability_enabled is False
    assert merged.observability_log_path == Path("/tmp/custom-runs.jsonl")
    assert merged.observability_sampler_hz == 2.5
