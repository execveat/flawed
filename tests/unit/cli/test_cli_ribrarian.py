"""CLI-level tests for the optional -r/--ribrarian integration.

Covers: the flag is absent when ribrarian is not installed (the gate env), the
shared decorator attaches it when ribrarian is available, and the scan command's
sequential multi-target loop (per-repo dispatch + worst-exit propagation + cwd
restoration, including across an erroring repo).
"""

from __future__ import annotations

from pathlib import Path

import click
import pytest
from click.testing import CliRunner

import flawed._cli.app as cli_app
from flawed._config.schema import ResolvedConfig, TimeoutConfig


class _NoopLock:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    def __enter__(self) -> _NoopLock:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


# ── Flag presence is gated on HAS_RIBRARIAN ──────────────────────


@pytest.mark.parametrize("command", ["scan", "index", ["providers", "coverage"]])
def test_ribrarian_flag_absent_without_ribrarian(command: str | list[str]) -> None:
    # The gate env has no ribrarian installed, so the option must not exist.
    assert cli_app.HAS_RIBRARIAN is False  # type: ignore[attr-defined]
    args = ([command] if isinstance(command, str) else command) + ["--help"]
    result = CliRunner().invoke(cli_app.cli, args)
    assert result.exit_code == 0
    assert "--ribrarian" not in result.output


def test_with_ribrarian_attaches_option_when_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_app, "HAS_RIBRARIAN", True)

    @click.command()
    @cli_app._with_ribrarian
    @click.argument("targets", nargs=-1)
    def dummy(targets: tuple[str, ...], ribrarian: tuple[str, ...] = ()) -> None:
        pass

    option = next((p for p in dummy.params if p.name == "ribrarian"), None)
    assert option is not None
    assert option.multiple is True
    assert "-r" in option.opts


def test_with_ribrarian_is_noop_without_ribrarian() -> None:
    assert cli_app.HAS_RIBRARIAN is False  # type: ignore[attr-defined]

    @click.command()
    @cli_app._with_ribrarian
    @click.argument("targets", nargs=-1)
    def dummy(targets: tuple[str, ...], ribrarian: tuple[str, ...] = ()) -> None:
        pass

    assert all(p.name != "ribrarian" for p in dummy.params)


# ── Multi-target scan loop ───────────────────────────────────────


def test_scan_dispatches_each_target_and_returns_worst_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_a = tmp_path / "a"
    repo_b = tmp_path / "b"
    calls: list[Path] = []

    monkeypatch.setattr(cli_app, "resolve_targets", lambda paths, sels: [repo_a, repo_b])

    def fake_do_scan(_obj: object, *, repo_path: Path, **_kw: object) -> int:
        calls.append(repo_path)
        return 1 if repo_path.name == "b" else 0

    monkeypatch.setattr(cli_app, "_do_scan", fake_do_scan)

    result = CliRunner().invoke(cli_app.cli, ["scan", str(repo_a), str(repo_b)])
    assert calls == [repo_a, repo_b]
    # Worst (highest) per-repo code wins: a finding in b is not masked by clean a.
    assert result.exit_code == 1


def test_scan_no_target_orients_instead_of_scanning(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def fake_do_scan(*_a: object, **_k: object) -> int:
        nonlocal called
        called = True
        return 0

    monkeypatch.setattr(cli_app, "_do_scan", fake_do_scan)
    result = CliRunner().invoke(cli_app.cli, ["scan"])
    assert result.exit_code == cli_app._EXIT_ERROR
    assert called is False


# ── _do_scan restores cwd (real entered_target path) ─────────────


@pytest.fixture
def stub_scan_pipeline(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Stub config/lock so _do_scan runs end-to-end, recording cwd during run_scan."""
    seen: list[Path] = []
    monkeypatch.setattr(cli_app, "RepoLock", _NoopLock)
    monkeypatch.setattr(
        cli_app,
        "load_config",
        lambda **_k: ResolvedConfig(timeouts=TimeoutConfig(overall=60)),
    )
    return seen


def _run_do_scan(repo: Path) -> int:
    obj = cli_app._Ctx()  # type: ignore[attr-defined]
    return cli_app._do_scan(
        obj,
        repo_path=repo,
        data_dir=None,
        rules_dirs=(),
        includes=(),
        include_regexes=(),
        excludes=(),
        exclude_regexes=(),
        force_providers=(),
        disable_providers=(),
        no_index=False,
        reindex=False,
        enable_mypy_batch=None,
        dry_run=False,
    )


def test_do_scan_restores_cwd_on_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stub_scan_pipeline: list[Path],
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    origin = Path.cwd()

    def fake_run_scan(**_kw: object) -> int:
        stub_scan_pipeline.append(Path.cwd())
        return 0

    monkeypatch.setattr(cli_app, "run_scan", fake_run_scan)

    code = _run_do_scan(repo)
    assert code == 0
    assert stub_scan_pipeline == [repo.resolve()]  # cwd was the repo during the scan
    assert Path.cwd() == origin  # ...and restored afterwards


def test_do_scan_restores_cwd_when_repo_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stub_scan_pipeline: list[Path],
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    origin = Path.cwd()

    def fake_run_scan(**_kw: object) -> int:
        raise cli_app.PipelineError("boom")  # type: ignore[attr-defined]

    monkeypatch.setattr(cli_app, "run_scan", fake_run_scan)

    code = _run_do_scan(repo)
    assert code == cli_app.EXIT_INTERNAL  # type: ignore[attr-defined]
    assert Path.cwd() == origin  # cwd restored even though the repo errored
