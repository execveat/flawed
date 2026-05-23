"""``flawed --version`` top-level flag (FLAW-340).

The flag must mirror the ``version`` subcommand exactly and short-circuit
``_DefaultScanGroup``'s default-scan routing (it is an eager option, so it
fires during option parsing before an unknown token is treated as a scan
target / before the bare-``flawed`` dashboard fallback).
"""

from __future__ import annotations

from click.testing import CliRunner

from flawed import __version__
from flawed._cli.app import cli


def test_version_flag_prints_version_and_exits_zero() -> None:
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"flawed {__version__}"


def test_version_flag_matches_version_subcommand() -> None:
    runner = CliRunner()
    flag = runner.invoke(cli, ["--version"])
    sub = runner.invoke(cli, ["version"])
    assert flag.exit_code == 0
    assert sub.exit_code == 0
    assert flag.output == sub.output


def test_version_flag_short_circuits_default_scan_group() -> None:
    # Eager + expose_value=False: prints the version and exits, never routing
    # to the dashboard (bare ``flawed``) or the scan fallback.
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert result.output.startswith("flawed ")
    assert "dashboard" not in result.output.lower()
