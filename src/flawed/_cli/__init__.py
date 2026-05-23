"""Command-line interface for flawed.

This package owns the user-facing CLI: argument parsing, target resolution,
per-repo locking, and orchestration of the analysis pipeline.  It is the
top-level entry point and may import from any internal package.

The ``main`` function is registered as a console_scripts entry point
(``flawed = "flawed._cli:main"``).
"""

from __future__ import annotations


def main() -> None:
    """Entry point for the ``flawed`` console script.

    Wraps Click so usage/abort errors print a single unified ``error: …`` line
    (matching ``Console.error``) instead of Click's default ``Error: …`` —
    FLAW-154 asked for one error style across the CLI. Tests invoke the ``cli``
    group directly via Click's ``CliRunner`` (not this wrapper), so this affects
    only the real console script and does not change test-observed behaviour.
    """
    import sys

    import click

    from flawed._cli.app import cli

    try:
        rv = cli.main(standalone_mode=False)
    except click.ClickException as exc:
        click.echo(f"error: {exc.format_message()}", err=True)
        sys.exit(exc.exit_code)
    except click.exceptions.Abort:
        click.echo("error: aborted", err=True)
        sys.exit(130)
    # FLAW-165: with standalone_mode=False, Click CATCHES click.exceptions.Exit
    # (raised by ctx.exit(code)) and RETURNS the code instead of exiting. Honour
    # it so every ctx.exit(N) propagates as the process status — otherwise a
    # command that does ctx.exit(2) (e.g. `flawed scan` with no target) exits 0.
    if isinstance(rv, int):
        sys.exit(rv)
