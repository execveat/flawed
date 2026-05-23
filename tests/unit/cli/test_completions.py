"""Shell completion: the `completions` command + dynamic rule/provider callbacks.

FLAW-152. Covers script generation for all four shells, clean failure on an
unknown shell, and the dynamic completion callbacks (rule ids, provider ids)
which must enumerate inventory metadata *without* triggering a scan and must
never raise.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from flawed._cli.app import (
    _complete_provider,
    _complete_rule_id,
    cli,
)


@pytest.mark.parametrize(
    ("shell", "marker"),
    [
        ("bash", "flawed_completion"),
        ("zsh", "#compdef flawed"),
        ("fish", "complete"),
        ("powershell", "Register-ArgumentCompleter"),
    ],
)
def test_completions_emits_valid_script(shell: str, marker: str) -> None:
    result = CliRunner().invoke(cli, ["completions", shell])
    assert result.exit_code == 0, result.output
    assert result.output.strip(), "completion script must be non-empty"
    assert marker in result.output
    # Every shell's script drives the same Click completion env var.
    assert "_FLAWED_COMPLETE" in result.output


def test_completions_unknown_shell_errors_cleanly() -> None:
    result = CliRunner().invoke(cli, ["completions", "tcsh"])
    assert result.exit_code == 2
    # click.Choice lists the valid shells — the actionable "did you mean".
    assert "bash" in result.output and "powershell" in result.output


def test_complete_rule_id_returns_real_hyphenated_ids_without_scanning() -> None:
    # Callbacks take (ctx, param, incomplete); ours ignore ctx/param.
    items = _complete_rule_id(None, None, "route")  # type: ignore[arg-type]
    values = [item.value for item in items]
    assert values, "expected at least one rule id for the 'route' prefix"
    assert all(v.startswith("route") for v in values)
    # Canonical ids are hyphenated.
    assert any("-" in v for v in values)


def test_complete_rule_id_is_separator_insensitive() -> None:
    # Typing the underscore form still completes the hyphenated canonical ids.
    underscore = {i.value for i in _complete_rule_id(None, None, "request_")}  # type: ignore[arg-type]
    hyphen = {i.value for i in _complete_rule_id(None, None, "request-")}  # type: ignore[arg-type]
    assert underscore
    assert underscore == hyphen


def test_complete_rule_id_filters_to_the_prefix() -> None:
    all_items = {i.value for i in _complete_rule_id(None, None, "")}  # type: ignore[arg-type]
    c_items = {i.value for i in _complete_rule_id(None, None, "r")}  # type: ignore[arg-type]
    assert c_items
    assert c_items < all_items
    assert all(v.startswith("r") for v in c_items)


def test_complete_provider_returns_provider_ids() -> None:
    items = _complete_provider(None, None, "fl")  # type: ignore[arg-type]
    values = [item.value for item in items]
    assert "flask" in values
    assert all(v.startswith("fl") for v in values)
