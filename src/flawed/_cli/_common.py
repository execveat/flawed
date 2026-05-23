"""Shared CLI primitives used across the command modules.

Holds the small pieces every command module needs — the help-option context
settings, the ``_Ctx`` state bag threaded through Click as ``obj``, and the
``pass_ctx`` decorator — so that ``app`` and the per-group command modules
(e.g. ``inspect_commands``) can share them without a circular import.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import click

from flawed._cli.output import Console

if TYPE_CHECKING:
    from pathlib import Path

_CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


class _Ctx:
    """Bag of state threaded through Click commands via ``obj``."""

    def __init__(self) -> None:
        self.console: Console = Console()
        self.config_path: Path | None = None
        self.root_dry_run: bool = False


pass_ctx = click.make_pass_decorator(_Ctx, ensure=True)
