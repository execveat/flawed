"""CLI cache identity coverage for target-scoped local slice scans."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

import flawed._cli.app as cli_app
import flawed._index._pipeline as index_pipeline
from flawed._cli import pipeline
from flawed._cli.app import cli
from flawed._index._type_enrichment import TypeEnrichmentIndex
from flawed._index._types import ErrorKind, ExtractionError


@pytest.mark.slow
def test_scan_profiles_use_target_scoped_artifact_dirs_for_git_subdirectories(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Two local slice targets in one checkout must not share L1 cache counts."""
    checkout = _init_git_checkout(tmp_path / "flawed")
    slice_a = checkout / "local" / "p9.2" / "slice_repos" / "alpha"
    slice_b = checkout / "local" / "p9.2" / "slice_repos" / "beta"
    slice_a.mkdir(parents=True)
    slice_b.mkdir(parents=True)
    (slice_a / "app.py").write_text("def alpha():\n    return 'a'\n", encoding="utf-8")
    (slice_b / "app.py").write_text(
        "def beta_one():\n    return 'b1'\n\ndef beta_two():\n    return 'b2'\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "-f", "."], cwd=checkout, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "add slices"],
        cwd=checkout,
        capture_output=True,
        check=True,
    )

    _patch_l1_prerequisites(monkeypatch)
    data_dir = tmp_path / "cache"
    profile_a = tmp_path / "alpha-profile.json"
    profile_b = tmp_path / "beta-profile.json"
    runner = CliRunner()

    first = runner.invoke(
        cli,
        [
            "scan",
            str(slice_a),
            "--data-dir",
            str(data_dir),
            "--profile",
            str(profile_a),
        ],
    )
    second = runner.invoke(
        cli,
        [
            "scan",
            str(slice_b),
            "--data-dir",
            str(data_dir),
            "--profile",
            str(profile_b),
        ],
    )

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    first_profile = json.loads(profile_a.read_text(encoding="utf-8"))
    second_profile = json.loads(profile_b.read_text(encoding="utf-8"))

    assert first_profile["target"]["path"] == str(slice_a.resolve())
    assert second_profile["target"]["path"] == str(slice_b.resolve())
    assert first_profile["target"]["canonical"] == str(slice_a.resolve())
    assert second_profile["target"]["canonical"] == str(slice_b.resolve())

    assert first_profile["l1"]["cache_status"] == "miss"
    assert second_profile["l1"]["cache_status"] == "miss"
    assert first_profile["l1"]["artifact_dir"] != second_profile["l1"]["artifact_dir"]
    assert Path(first_profile["l1"]["artifact_dir"]).name.startswith("alpha--")
    assert Path(second_profile["l1"]["artifact_dir"]).name.startswith("beta--")
    assert first_profile["l1"]["counts"]["functions"] == 1
    assert second_profile["l1"]["counts"]["functions"] == 2


@pytest.mark.slow
def test_scan_mypy_batch_cli_opt_in_reaches_l1_pipeline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("value = 1\n", encoding="utf-8")
    data_dir = tmp_path / "cache"
    profile_path = tmp_path / "profile.json"
    observed_flags: list[bool] = []
    observed_cache_dirs: list[Path | None] = []
    mypy_error = ExtractionError(
        file="app.py",
        pass_name="mypy_batch_type_enrichment",
        error_kind=ErrorKind.MYPY,
        message="mypy unavailable: test",
        is_fatal=False,
        location=None,
    )

    def fake_build_type_enrichment_index(
        *_args: object,
        enable_mypy_batch: bool = False,
        mypy_batch_cache_dir: Path | None = None,
        **_kwargs: object,
    ) -> TypeEnrichmentIndex:
        observed_flags.append(enable_mypy_batch)
        observed_cache_dirs.append(mypy_batch_cache_dir)
        return TypeEnrichmentIndex(errors=(mypy_error,))

    _patch_l1_prerequisites(monkeypatch)
    monkeypatch.setattr(
        index_pipeline,
        "build_type_enrichment_index",
        fake_build_type_enrichment_index,
    )

    result = CliRunner().invoke(
        cli,
        [
            "scan",
            str(repo),
            "--data-dir",
            str(data_dir),
            "--profile",
            str(profile_path),
            "--enable-mypy-batch",
        ],
    )

    assert result.exit_code == 0, result.output
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    assert observed_flags == [True]
    assert observed_cache_dirs[0] is not None
    assert observed_cache_dirs[0].parts[-2] == "mypy_batch"
    assert profile["options"]["enable_mypy_batch"] is True
    assert profile["options"]["mypy_batch_timeout_seconds"] == 120
    assert profile["options"]["mypy_batch_max_files"] == 5000
    assert profile["l1"]["counts"]["errors"] == 1


@pytest.mark.slow
def test_scan_reextracts_when_type_enrichment_signature_changes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """FLAW-344 (scheme C): an analysis-source signature change that is part of
    the L1 artifact-cache validity gate must invalidate the cache even for a
    byte-identical repo, so a warm-cache scan re-extracts instead of silently
    serving stale (false-negative-class) artifacts.  The gate is the repo
    content hash, L1 schema version, record-schema fingerprint, and the
    type-enrichment signature (see ``flawed._index._pipeline.cache_key_matches``).
    This supersedes the FLAW-207 extraction-code-signature gate, which is now
    recorded as provenance only — a behaviour-preserving ``_index`` refactor no
    longer invalidates the cache.  Exercises the full ``run_index`` wiring."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    data_dir = tmp_path / "cache"
    _patch_l1_prerequisites(monkeypatch)

    def _scan(profile_path: Path) -> dict:
        result = CliRunner().invoke(
            cli,
            [
                "scan",
                str(repo),
                "--data-dir",
                str(data_dir),
                "--profile",
                str(profile_path),
            ],
        )
        assert result.exit_code == 0, result.output
        return json.loads(profile_path.read_text(encoding="utf-8"))

    # Cold cache → miss.
    first = _scan(tmp_path / "p1.json")
    assert first["l1"]["cache_status"] == "miss"

    # Repo and engine unchanged → warm hit.
    second = _scan(tmp_path / "p2.json")
    assert second["l1"]["cache_status"] == "hit"

    # Change only the type-enrichment signature the CLI threads into the gate;
    # the repo content is byte-identical.  The cache must still MISS — this is
    # the FLAW-344 silent-FN guard (a changed analysis-source signature that is
    # part of the validity gate forces a safe re-extraction).
    monkeypatch.setattr(pipeline, "type_enrichment_signature", lambda **_kwargs: "edited-te-sig")
    third = _scan(tmp_path / "p3.json")
    assert third["l1"]["cache_status"] == "miss"


def _patch_l1_prerequisites(monkeypatch) -> None:
    class _NoopLock:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> _NoopLock:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

    monkeypatch.setattr(cli_app, "RepoLock", _NoopLock)


def _init_git_checkout(path: Path) -> Path:
    path.mkdir()
    (path / "README.md").write_text("# checkout\n", encoding="utf-8")
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
        ["git", "remote", "add", "origin", "https://github.com/execveat/flawed.git"],
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
