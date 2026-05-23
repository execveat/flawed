"""CLI discoverability cluster: explain, did-you-mean, grouped help, --json.

Covers FLAW-151 (explain), FLAW-153 (grouped help), FLAW-154 (did-you-mean),
FLAW-155 (machine-readable inventory + providers show).
"""

from __future__ import annotations

import json

from click.testing import CliRunner

from flawed._cli.app import cli

# A stable rule id present in the built-in library.
_RULE_ID = "route-guards"


# ── FLAW-151: explain ────────────────────────────────────────────


def test_explain_prints_id_severity_and_suppress_hint() -> None:
    result = CliRunner().invoke(cli, ["explain", _RULE_ID])

    assert result.exit_code == 0
    assert _RULE_ID in result.output
    # Severity is rendered as a word (real severity, not "unknown").
    assert "INFO" in result.output
    # The action footer teaches the suppression syntax.
    assert f"# flawed: ignore[{_RULE_ID}]" in result.output


def test_explain_accepts_underscore_id_form() -> None:
    # Separator-insensitive (FLAW-122): the underscore stem resolves the hyphen id.
    result = CliRunner().invoke(cli, ["explain", "route_guards"])

    assert result.exit_code == 0
    assert _RULE_ID in result.output


def test_explain_prose_comes_from_module_docstring() -> None:
    # The rich body is the rule module's own docstring, not hard-coded text.
    result = CliRunner().invoke(cli, ["explain", _RULE_ID])

    assert "inventory" in result.output


def test_explain_unknown_id_suggests_and_exits_2() -> None:
    result = CliRunner().invoke(cli, ["explain", "route-guard"])

    assert result.exit_code == 2
    assert "Did you mean" in result.output
    assert _RULE_ID in result.output


def test_explain_json_is_valid_and_complete() -> None:
    result = CliRunner().invoke(cli, ["explain", _RULE_ID, "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["rule_id"] == _RULE_ID
    assert payload["severity"]
    assert payload["doc"]
    assert payload["suppress"] == f"# flawed: ignore[{_RULE_ID}]"


# ── FLAW-154: did-you-mean for subcommands ───────────────────────


def test_mistyped_subcommand_suggests_nearest() -> None:
    result = CliRunner().invoke(cli, ["scna"])

    assert result.exit_code == 2
    assert "Did you mean 'scan'" in result.output


def test_real_path_is_not_treated_as_typo(tmp_path) -> None:
    # An existing path that is not close to any command must still route to scan
    # (dry-run keeps it fast), never trigger did-you-mean.
    result = CliRunner().invoke(cli, ["--dry-run", str(tmp_path)])

    assert result.exit_code == 0
    assert "Did you mean" not in result.output


# ── FLAW-153: grouped help ───────────────────────────────────────


def test_scan_help_is_grouped_into_sections() -> None:
    result = CliRunner().invoke(cli, ["scan", "-h"])

    assert result.exit_code == 0
    for section in ("Filtering:", "Output:", "Performance:", "Suppression:"):
        assert section in result.output, f"missing help section {section!r}"


def test_engine_internal_flags_demoted_to_advanced() -> None:
    result = CliRunner().invoke(cli, ["scan", "-h"])

    assert result.exit_code == 0
    out = result.output
    assert "Advanced (engine internals):" in out
    # The engine-internal flag must appear *after* the Advanced header.
    assert out.index("--enable-mypy-batch") > out.index("Advanced (engine internals):")


def test_subcommands_have_examples_block() -> None:
    for cmd in (["scan", "-h"], ["explain", "-h"], ["rules", "-h"]):
        result = CliRunner().invoke(cli, cmd)
        assert result.exit_code == 0
        assert "Examples:" in result.output, f"{cmd} missing Examples block"


# ── FLAW-155: machine-readable inventory + providers ─────────────


def test_rules_json_is_stable_array() -> None:
    result = CliRunner().invoke(cli, ["rules", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert isinstance(payload, list)
    assert len(payload) == 5  # the built-in capability-demo core
    first = payload[0]
    assert set(first) >= {"rule_id", "severity", "description", "stem", "path"}


def test_providers_list_json_is_stable_array() -> None:
    result = CliRunner().invoke(cli, ["providers", "list", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert isinstance(payload, list)
    ids = {entry["id"] for entry in payload}
    assert "flask" in ids
    flask = next(e for e in payload if e["id"] == "flask")
    assert flask["patterns"] > 0
    assert isinstance(flask["pattern_breakdown"], dict)


def test_providers_list_table_drops_dead_version_column() -> None:
    result = CliRunner().invoke(cli, ["providers", "list"])

    assert result.exit_code == 0
    assert "Patterns" in result.output
    assert "Version" not in result.output


def test_providers_show_renders_breakdown() -> None:
    result = CliRunner().invoke(cli, ["providers", "show", "flask"])

    assert result.exit_code == 0
    assert "flask" in result.output
    assert "routes" in result.output
    assert "total" in result.output


def test_providers_show_unknown_suggests_and_exits_2() -> None:
    result = CliRunner().invoke(cli, ["providers", "show", "flsk"])

    assert result.exit_code == 2
    assert "Did you mean" in result.output
    assert "flask" in result.output
