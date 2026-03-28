from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from flawed._config.match import apply_overrides
from flawed._config.merge import merge_raw_into
from flawed._config.paths import (
    RepoIdentity,
    repo_cache_name,
    repo_content_hash,
    repo_data_dir,
)
from flawed._config.schema import (
    CacheInvalidation,
    ConfigError,
    ProviderConfig,
    ProviderEntry,
    ResolvedConfig,
    TypeEnrichmentConfig,
    parse_type_enrichment_config,
)


def test_repo_data_dir_uses_readable_github_slug() -> None:
    identity = RepoIdentity(
        canonical="example-org/example-app",
        path=Path("/repos/example-org__example-app"),
        hash="abc123",
    )

    assert repo_cache_name(identity) == "example-org__example-app"
    assert repo_data_dir(Path("/cache/flawed"), identity) == Path(
        "/cache/flawed/example-org__example-app"
    )


def test_repo_identity_uses_github_slug_for_worktree_root(tmp_path: Path) -> None:
    repo = _init_git_repo(tmp_path / "repo")

    identity = RepoIdentity.from_path(repo)

    assert identity.canonical == "example/project"
    assert identity.path == repo.resolve()
    assert repo_cache_name(identity) == "example__project"


def test_repo_identity_scopes_git_subdirectory_targets_by_path(tmp_path: Path) -> None:
    repo = _init_git_repo(tmp_path / "repo")
    alpha = repo / "local" / "p9.2" / "slice_repos" / "alpha"
    beta = repo / "local" / "p9.2" / "slice_repos" / "beta"
    alpha.mkdir(parents=True)
    beta.mkdir(parents=True)

    alpha_identity = RepoIdentity.from_path(alpha)
    beta_identity = RepoIdentity.from_path(beta)

    assert alpha_identity.canonical == str(alpha.resolve())
    assert beta_identity.canonical == str(beta.resolve())
    assert alpha_identity.hash != beta_identity.hash
    assert repo_cache_name(alpha_identity).startswith("alpha--")
    assert repo_cache_name(beta_identity).startswith("beta--")
    assert repo_data_dir(Path("/cache/flawed"), alpha_identity) != repo_data_dir(
        Path("/cache/flawed"), beta_identity
    )


def test_provider_config_deep_merges_nested_dicts() -> None:
    base = ResolvedConfig(
        providers=ProviderConfig(
            entries={
                "demo": ProviderEntry(
                    config={
                        "limits": {"timeout": 5, "depth": 2},
                        "mode": "strict",
                    }
                )
            }
        )
    )

    merged = merge_raw_into(
        base,
        {
            "providers": {
                "demo": {
                    "config": {
                        "limits": {"timeout": 10},
                    }
                }
            }
        },
    )

    assert merged.providers.entries["demo"].config == {
        "limits": {"timeout": 10, "depth": 2},
        "mode": "strict",
    }


def test_type_enrichment_defaults_to_mypy_batch_disabled() -> None:
    config = ResolvedConfig().type_enrichment
    assert config.enable_mypy_batch is False
    assert config.basedpyright_max_queries == 2000
    assert config.basedpyright_max_probe_files == 500
    assert config.basedpyright_max_source_files == 5000
    assert config.basedpyright_max_workspace_bytes == 250_000_000
    assert config.mypy_batch_timeout_seconds == 120
    assert config.mypy_batch_max_files == 5000


def test_type_enrichment_config_enables_mypy_batch() -> None:
    merged = merge_raw_into(
        ResolvedConfig(),
        {"type_enrichment": {"enable_mypy_batch": True}},
    )

    assert merged.type_enrichment.enable_mypy_batch is True


def test_type_enrichment_config_parses_guardrail_fields() -> None:
    config = parse_type_enrichment_config(
        {
            "enable_mypy_batch": True,
            "basedpyright_max_queries": 100,
            "basedpyright_max_probe_files": 25,
            "basedpyright_max_source_files": 300,
            "basedpyright_max_workspace_bytes": 123456,
            "basedpyright_timeout_seconds": 240,
            "mypy_batch_timeout_seconds": 60,
            "mypy_batch_max_files": 1000,
        }
    )

    assert config.enable_mypy_batch is True
    assert config.basedpyright_max_queries == 100
    assert config.basedpyright_max_probe_files == 25
    assert config.basedpyright_max_source_files == 300
    assert config.basedpyright_max_workspace_bytes == 123456
    assert config.basedpyright_timeout_seconds == 240
    assert config.mypy_batch_timeout_seconds == 60
    assert config.mypy_batch_max_files == 1000


def test_type_enrichment_config_invalid_timeout() -> None:
    with pytest.raises(ConfigError, match="mypy_batch_timeout_seconds"):
        parse_type_enrichment_config({"mypy_batch_timeout_seconds": -1})


def test_type_enrichment_config_rejects_bool_timeout() -> None:
    with pytest.raises(ConfigError, match="mypy_batch_timeout_seconds"):
        parse_type_enrichment_config({"mypy_batch_timeout_seconds": True})


def test_type_enrichment_config_invalid_max_files() -> None:
    with pytest.raises(ConfigError, match="mypy_batch_max_files"):
        parse_type_enrichment_config({"mypy_batch_max_files": 0})


def test_type_enrichment_config_invalid_basedpyright_guardrail() -> None:
    with pytest.raises(ConfigError, match="basedpyright_max_workspace_bytes"):
        parse_type_enrichment_config({"basedpyright_max_workspace_bytes": True})


def test_type_enrichment_basedpyright_timeout_default_and_override() -> None:
    # FLAW-268: configurable basedpyright timeout; default 120s (was a hardcoded
    # 30s that dropped type facts on cold full-project checks of large repos).
    assert parse_type_enrichment_config({}).basedpyright_timeout_seconds == 120
    assert (
        parse_type_enrichment_config(
            {"basedpyright_timeout_seconds": 300}
        ).basedpyright_timeout_seconds
        == 300
    )
    with pytest.raises(ConfigError, match="basedpyright_timeout_seconds"):
        parse_type_enrichment_config({"basedpyright_timeout_seconds": 0})


def test_type_enrichment_merge_preserves_base_guardrails() -> None:
    base = ResolvedConfig(
        type_enrichment=TypeEnrichmentConfig(
            enable_mypy_batch=True,
            basedpyright_max_queries=100,
            basedpyright_max_probe_files=25,
            basedpyright_max_source_files=300,
            basedpyright_max_workspace_bytes=123456,
            mypy_batch_timeout_seconds=60,
            mypy_batch_max_files=1000,
        )
    )

    merged = merge_raw_into(base, {"type_enrichment": {"enable_mypy_batch": False}})

    assert merged.type_enrichment.enable_mypy_batch is False
    assert merged.type_enrichment.basedpyright_max_queries == 100
    assert merged.type_enrichment.basedpyright_max_probe_files == 25
    assert merged.type_enrichment.basedpyright_max_source_files == 300
    assert merged.type_enrichment.basedpyright_max_workspace_bytes == 123456
    assert merged.type_enrichment.mypy_batch_timeout_seconds == 60
    assert merged.type_enrichment.mypy_batch_max_files == 1000


def test_type_enrichment_override_preserves_unspecified_guardrails(tmp_path: Path) -> None:
    repo = _init_git_repo(tmp_path / "repo")
    base = ResolvedConfig(
        type_enrichment=TypeEnrichmentConfig(
            enable_mypy_batch=True,
            basedpyright_max_queries=100,
            basedpyright_max_probe_files=25,
            basedpyright_max_source_files=300,
            basedpyright_max_workspace_bytes=123456,
            mypy_batch_timeout_seconds=60,
            mypy_batch_max_files=1000,
        )
    )
    config = merge_raw_into(
        base,
        {
            "overrides": [
                {
                    "match": {"repo": "example/project"},
                    "type_enrichment": {
                        "basedpyright_max_source_files": 150,
                        "mypy_batch_max_files": 200,
                    },
                }
            ]
        },
    )

    merged = apply_overrides(config, RepoIdentity.from_path(repo))

    assert merged.type_enrichment.enable_mypy_batch is True
    assert merged.type_enrichment.basedpyright_max_queries == 100
    assert merged.type_enrichment.basedpyright_max_probe_files == 25
    assert merged.type_enrichment.basedpyright_max_source_files == 150
    assert merged.type_enrichment.basedpyright_max_workspace_bytes == 123456
    assert merged.type_enrichment.mypy_batch_timeout_seconds == 60
    assert merged.type_enrichment.mypy_batch_max_files == 200


def _init_git_repo(path: Path) -> Path:
    path.mkdir()
    (path / "app.py").write_text("def hello():\n    return 'hi'\n", encoding="utf-8")
    subprocess.run(["git", "init"], cwd=path, capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=path,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "test"],
        cwd=path,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/example/project.git"],
        cwd=path,
        capture_output=True,
        check=True,
    )
    subprocess.run(["git", "add", "."], cwd=path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=path,
        capture_output=True,
        check=True,
    )
    return path


# ── Cache invalidation strategy (FLAW-171 part 1) ──────────────────


class TestCacheInvalidationConfig:
    """Parsing and merge of the ``cache_invalidation`` strategy field."""

    def test_defaults_to_auto(self) -> None:
        assert ResolvedConfig().cache_invalidation is CacheInvalidation.AUTO

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("auto", CacheInvalidation.AUTO),
            ("git-hash", CacheInvalidation.GIT_HASH),
            ("mtime", CacheInvalidation.MTIME),
            ("content-hash", CacheInvalidation.CONTENT_HASH),
        ],
    )
    def test_merge_parses_valid_strategy(self, raw: str, expected: CacheInvalidation) -> None:
        merged = merge_raw_into(ResolvedConfig(), {"cache_invalidation": raw})
        assert merged.cache_invalidation is expected

    def test_merge_preserves_base_when_absent(self) -> None:
        base = ResolvedConfig(cache_invalidation=CacheInvalidation.MTIME)
        merged = merge_raw_into(base, {"repo_local": True})
        assert merged.cache_invalidation is CacheInvalidation.MTIME

    def test_rejects_unknown_strategy(self) -> None:
        with pytest.raises(ConfigError, match="cache_invalidation"):
            merge_raw_into(ResolvedConfig(), {"cache_invalidation": "sha512"})

    def test_rejects_non_string(self) -> None:
        with pytest.raises(ConfigError, match="cache_invalidation"):
            merge_raw_into(ResolvedConfig(), {"cache_invalidation": 7})


class TestCacheInvalidationStrategies:
    """``repo_content_hash`` dispatch on the chosen strategy."""

    def test_default_arg_matches_explicit_auto_non_git(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        assert repo_content_hash(tmp_path) == repo_content_hash(tmp_path, CacheInvalidation.AUTO)

    def test_auto_uses_git_head_on_git_repo(self, tmp_path: Path) -> None:
        repo = _init_git_repo(tmp_path / "repo")
        auto = repo_content_hash(repo, CacheInvalidation.AUTO)
        git = repo_content_hash(repo, CacheInvalidation.GIT_HASH)
        assert auto == git
        assert len(git) == 40  # bare HEAD commit hash

    def test_mtime_strategy_ignores_git_and_is_stable(self, tmp_path: Path) -> None:
        repo = _init_git_repo(tmp_path / "repo")
        h1 = repo_content_hash(repo, CacheInvalidation.MTIME)
        h2 = repo_content_hash(repo, CacheInvalidation.MTIME)
        assert h1 == h2
        assert len(h1) == 32  # mtime digest, not a 40-char commit hash
        assert h1 != repo_content_hash(repo, CacheInvalidation.GIT_HASH)

    def test_mtime_strategy_changes_on_touch(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        h1 = repo_content_hash(tmp_path, CacheInvalidation.MTIME)
        future = (tmp_path / "app.py").stat().st_mtime_ns + 1_000_000_000
        os.utime(tmp_path / "app.py", ns=(future, future))
        assert repo_content_hash(tmp_path, CacheInvalidation.MTIME) != h1

    def test_content_hash_stable_when_unchanged(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        h1 = repo_content_hash(tmp_path, CacheInvalidation.CONTENT_HASH)
        future = (tmp_path / "app.py").stat().st_mtime_ns + 1_000_000_000
        os.utime(tmp_path / "app.py", ns=(future, future))
        # Touching mtime must NOT change a content hash.
        assert repo_content_hash(tmp_path, CacheInvalidation.CONTENT_HASH) == h1

    def test_content_hash_detects_edit_with_mtime_pinned(self, tmp_path: Path) -> None:
        """Content hash catches a change mtime would miss (e.g. mtime-preserving checkout)."""
        py = tmp_path / "app.py"
        py.write_text("x = 1\n", encoding="utf-8")
        original_mtime = py.stat().st_mtime_ns
        h1 = repo_content_hash(tmp_path, CacheInvalidation.CONTENT_HASH)
        mtime_h1 = repo_content_hash(tmp_path, CacheInvalidation.MTIME)
        # Edit the content but restore the exact original mtime.
        py.write_text("x = 2\n", encoding="utf-8")
        os.utime(py, ns=(original_mtime, original_mtime))
        assert repo_content_hash(tmp_path, CacheInvalidation.CONTENT_HASH) != h1
        # mtime strategy is blind to this change — that is the weakness it trades for speed.
        assert repo_content_hash(tmp_path, CacheInvalidation.MTIME) == mtime_h1

    def test_git_hash_strategy_fails_closed_on_non_git(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="git-hash"):
            repo_content_hash(tmp_path, CacheInvalidation.GIT_HASH)
