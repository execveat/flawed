from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from click.testing import CliRunner

import flawed._cli.app as cli_app
from flawed._cli.app import cli
from flawed._cli.rules import discover_rule_files, load_configured_detectors
from flawed._config.schema import ResolvedConfig, RuleConfig, TypeEnrichmentConfig


def test_root_supports_short_help() -> None:
    result = CliRunner().invoke(cli, ["-h"])

    assert result.exit_code == 0
    assert "Usage:" in result.output


def test_index_supports_short_help() -> None:
    result = CliRunner().invoke(cli, ["index", "-h"])

    assert result.exit_code == 0
    assert "Run Layer 1 structural extraction only." in result.output


def test_bare_dry_run_routes_to_scan(tmp_path) -> None:
    result = CliRunner().invoke(cli, ["--dry-run", str(tmp_path)])

    assert result.exit_code == 0
    assert "dry run" in result.output


# ── P9.3: --semantic flag ────────────────────────────────────────


def test_scan_help_shows_semantic_flag() -> None:
    result = CliRunner().invoke(cli, ["scan", "-h"])

    assert result.exit_code == 0
    assert "--semantic" in result.output
    assert "--enable-mypy-batch" in result.output
    assert "--profile" in result.output
    assert "--profile-tracemalloc" in result.output
    assert "Layer 2 semantic analysis" in result.output
    assert "--rules-dir" in result.output
    assert "--smoke" in result.output
    # FLAW-147 exit-code contract is documented in the help.
    assert "Exit codes" in result.output
    assert "--fail-on" in result.output
    assert "--output-format" in result.output


def test_cli_mypy_batch_override_enables_type_enrichment() -> None:
    config = cli_app._apply_cli_overrides(
        ResolvedConfig(),
        force_providers=(),
        disable_providers=(),
        rules_dirs=(),
        includes=(),
        include_regexes=(),
        excludes=(),
        exclude_regexes=(),
        enable_mypy_batch=True,
    )

    assert config.type_enrichment.enable_mypy_batch is True


def test_cli_mypy_batch_absent_preserves_config() -> None:
    config = cli_app._apply_cli_overrides(
        ResolvedConfig(
            type_enrichment=TypeEnrichmentConfig(enable_mypy_batch=True),
        ),
        force_providers=(),
        disable_providers=(),
        rules_dirs=(),
        includes=(),
        include_regexes=(),
        excludes=(),
        exclude_regexes=(),
        enable_mypy_batch=None,
    )

    assert config.type_enrichment.enable_mypy_batch is True


# ── P9.3: providers list ────────────────────────────────────────


def test_providers_list_shows_real_providers() -> None:
    """providers list should output actual provider metadata, not a stub."""
    result = CliRunner().invoke(cli, ["providers", "list"])

    assert result.exit_code == 0
    output = result.output.lower()
    assert "flask" in output
    assert "django" in output
    assert "available providers" in output


def test_providers_list_counts_shows_pattern_counts() -> None:
    # FLAW-139: the per-command boolean ``-v`` was replaced by ``--counts``
    # (``-v`` is now the shared verbosity flag, see test_providers_list_*).
    result = CliRunner().invoke(cli, ["providers", "list", "--counts"])

    assert result.exit_code == 0
    assert "Patterns" in result.output


# ── P9.3: rules list ────────────────────────────────────────────


def test_rules_list_runs_without_error() -> None:
    """rules list should load config and attempt rule discovery."""
    result = CliRunner().invoke(cli, ["rules", "list"])

    assert result.exit_code == 0
    assert "endpoints" in result.output


def test_builtin_example_rules_import_as_detectors() -> None:
    """The migrated src/flawed/_rules pack should load without import errors."""
    config = ResolvedConfig()

    rule_files = discover_rule_files(config)
    detectors = load_configured_detectors(config, rule_files)

    assert {detector.rule_id for detector in detectors} >= {
        "endpoints",
        "value-flow",
    }
    assert len(detectors) == len(rule_files)


def test_default_resolves_full_rule_library() -> None:
    """The bare default resolves the built-in capability-demo core."""
    config = ResolvedConfig()

    rule_files = discover_rule_files(config)
    detectors = load_configured_detectors(config, rule_files)
    rule_ids = {d.rule_id for d in detectors}

    assert len(detectors) == 5
    assert len(detectors) == len(rule_files)
    assert "endpoints" in rule_ids
    assert "type-disagreements" in rule_ids


def test_smoke_token_resolves_curated_set() -> None:
    """FLAW-133: the fast curated set stays reachable behind the 'smoke' token / --smoke."""
    config = ResolvedConfig(rules=RuleConfig(paths=("smoke",)))

    detectors = load_configured_detectors(config, discover_rule_files(config))
    rule_ids = {d.rule_id for d in detectors}

    assert len(detectors) == 5
    assert "endpoints" in rule_ids


def _overrides(**kw) -> ResolvedConfig:
    from flawed._cli.app import _apply_cli_overrides

    base = {
        "force_providers": (),
        "disable_providers": (),
        "rules_dirs": (),
        "smoke": False,
        "includes": (),
        "include_regexes": (),
        "excludes": (),
        "exclude_regexes": (),
        "enable_mypy_batch": None,
    }
    base.update(kw)
    return _apply_cli_overrides(ResolvedConfig(), **cast("dict[str, Any]", base))


def test_smoke_flag_selects_curated_pack() -> None:
    """--smoke wires the scan to the curated smoke pack."""
    config = _overrides(smoke=True)

    assert config.rules.paths == ("smoke",)
    detectors = load_configured_detectors(config, discover_rule_files(config))
    assert len(detectors) == 5


def test_rules_dir_overrides_smoke(tmp_path) -> None:
    """An explicit --rules-dir wins over --smoke (as documented)."""
    config = _overrides(rules_dirs=(tmp_path,), smoke=True)

    assert config.rules.paths == (tmp_path,)


def test_include_filter_is_separator_insensitive() -> None:
    """FLAW-122: an include pattern using the underscore filename stem must match a
    detector whose declared id uses hyphens (and vice versa)."""
    config = ResolvedConfig(
        rules=RuleConfig(include=("route_guards",)),
    )

    detectors = load_configured_detectors(config, discover_rule_files(config))
    rule_ids = {d.rule_id for d in detectors}

    assert rule_ids == {"route-guards"}


def test_include_filter_accepts_bare_stem() -> None:
    """FLAW-178: a bare family stem (`route`) selects the rule whose id extends it at
    a separator boundary (`route-guards`), not just an exact id."""
    config = ResolvedConfig(rules=RuleConfig(include=("route",)))

    rule_ids = {d.rule_id for d in load_configured_detectors(config, discover_rule_files(config))}

    assert rule_ids == {"route-guards"}


def test_include_filter_splits_comma_separated() -> None:
    """FLAW-178: a single `-i route,value` selector is split into independent patterns."""
    config = ResolvedConfig(rules=RuleConfig(include=("route,value",)))

    rule_ids = {d.rule_id for d in load_configured_detectors(config, discover_rule_files(config))}

    assert rule_ids == {
        "route-guards",
        "value-flow",
    }


def test_include_filter_splits_whitespace_separated() -> None:
    """FLAW-178: a single space-separated `-i "route value"` selector is split too."""
    config = ResolvedConfig(rules=RuleConfig(include=("route value",)))

    rule_ids = {d.rule_id for d in load_configured_detectors(config, discover_rule_files(config))}

    assert rule_ids == {
        "route-guards",
        "value-flow",
    }


def test_exclude_filter_accepts_stem_and_splits() -> None:
    """FLAW-178: `-e` is consistent with `-i` — bare stems and comma/space lists both
    work for exclusion (default include is the full library)."""
    config = ResolvedConfig(rules=RuleConfig(exclude=("route, value",)))

    rule_ids = {d.rule_id for d in load_configured_detectors(config, discover_rule_files(config))}

    assert "route-guards" not in rule_ids
    assert "value-flow" not in rule_ids
    # The rest of the library is untouched by the exclusion.
    assert "endpoints" in rule_ids


def test_rule_id_matches_stem_respects_separator_boundary() -> None:
    """FLAW-178: stem matching is a prefix *at a separator boundary*, so `dem` must NOT
    match `demo-...` — only `demo`/`demo-presence...` do. Globs keep fnmatch semantics."""
    from flawed._cli.rules import _rule_id_matches

    target = "demo-presence-validity-divergence"

    assert _rule_id_matches(target, ResolvedConfig(rules=RuleConfig(include=("demo",))))
    assert _rule_id_matches(target, ResolvedConfig(rules=RuleConfig(include=(target,))))
    assert not _rule_id_matches(target, ResolvedConfig(rules=RuleConfig(include=("dem",))))
    # A genuine glob still matches via fnmatch.
    assert _rule_id_matches(target, ResolvedConfig(rules=RuleConfig(include=("dem*",))))


def test_builtin_rules_dir_is_packaged() -> None:
    """FLAW-136: the default library must live INSIDE the package so a wheel ships it."""
    from flawed._rules import builtin_rules_dir

    rules_dir = builtin_rules_dir()
    parts = rules_dir.parts

    assert rules_dir.name == "_rules"
    assert "flawed" in parts
    assert sum(1 for _ in rules_dir.rglob("*.py") if not _.name.startswith("_")) == 5


def test_rule_discovery_ignores_irrelevant_python_trees(tmp_path) -> None:
    (tmp_path / "real_rule.py").write_text("")
    for dirname in (".venv", "local", "cache", ".hidden", "__pycache__", "vendor"):
        noise_dir = tmp_path / dirname
        noise_dir.mkdir()
        (noise_dir / "noise_rule.py").write_text("")

    config = ResolvedConfig(rules=RuleConfig(paths=(tmp_path,)))

    entries = discover_rule_files(config)

    assert [entry.name for entry in entries] == ["real_rule"]


# ── FLAW-134: entry UX (dashboard vs silent scan) ────────────────


def test_bare_flawed_shows_dashboard_not_scan() -> None:
    """Bare `flawed` orients (dashboard) and does NOT run a scan."""
    result = CliRunner().invoke(cli, [])

    assert result.exit_code == 0
    # Dashboard markers...
    assert "built-in" in result.output
    assert "flawed ." in result.output
    # ...and it must NOT have executed a scan.
    assert "Layer 1" not in result.output
    assert "dry run" not in result.output


def test_scan_without_target_shows_help_and_exits_nonzero() -> None:
    """`flawed scan` with no TARGET prints help and exits 2 (no silent cwd scan)."""
    result = CliRunner().invoke(cli, ["scan"])

    assert result.exit_code == _exit_error()
    assert "Usage:" in result.output
    # It showed help, not a scan: no scan-phase progress markers.
    assert "L1 complete" not in result.output
    assert "Scan Summary" not in result.output


def test_explicit_dot_still_routes_to_scan(tmp_path) -> None:
    """`flawed . --dry-run` (explicit cwd) still scans."""
    result = CliRunner().invoke(cli, [str(tmp_path), "--dry-run"])

    assert result.exit_code == 0
    assert "dry run" in result.output


def _exit_error() -> int:
    from flawed._cli.app import _EXIT_ERROR

    return _EXIT_ERROR


# ── FLAW-135: rules listing collapses to a direct inventory ──────


def test_bare_rules_lists_inventory_directly() -> None:
    result = CliRunner().invoke(cli, ["rules"])

    assert result.exit_code == 0
    assert "Detection rules" in result.output
    # id + description + stem all present for a known rule.
    assert "route-guards" in result.output
    assert "route_guards" in result.output  # the filename stem


def test_rules_list_alias_still_works() -> None:
    result = CliRunner().invoke(cli, ["rules", "list"])

    assert result.exit_code == 0
    assert "Detection rules" in result.output


def test_rules_paths_flag_adds_path_column() -> None:
    # Column-presence is asserted against a wide captured Console so the
    # assertion is robust to CliRunner's narrow (80-col) truncation.
    import io

    from flawed._cli.output import Console
    from flawed._cli.rules import RuleSummary
    from flawed.severity import Severity

    summary = RuleSummary(
        rule_id="x01-demo",
        description="A demo rule.",
        severity=Severity.HIGH,
        path=Path("/tmp/x01_demo.py"),
    )

    buf = io.StringIO()
    Console(stdout=buf, color="never", width=200).show_rules([summary], paths=True)
    out_with = buf.getvalue()
    assert "Path" in out_with
    assert "x01_demo.py" in out_with

    buf2 = io.StringIO()
    Console(stdout=buf2, color="never", width=200).show_rules([summary], paths=False)
    assert "Path" not in buf2.getvalue()


# ── FLAW-139: universal -v, no boolean collisions ────────────────


def test_scan_accepts_verbose_after_subcommand() -> None:
    """`flawed scan -v` no longer errors with 'no such option'."""
    result = CliRunner().invoke(cli, ["scan", "-v", "-h"])

    assert result.exit_code == 0
    assert "no such option" not in result.output.lower()


def test_rules_verbose_is_verbosity_not_boolean_collision() -> None:
    """`flawed rules -v` is accepted (shared verbosity), not the old boolean flag."""
    result = CliRunner().invoke(cli, ["rules", "-v"])

    assert result.exit_code == 0
    assert "Detection rules" in result.output


def test_providers_list_counts_flag_replaces_verbose() -> None:
    counts = CliRunner().invoke(cli, ["providers", "list", "--counts"])
    assert counts.exit_code == 0
    assert "Patterns" in counts.output

    # -v is now shared verbosity (accepted), not a column toggle.
    verbose = CliRunner().invoke(cli, ["providers", "list", "-v"])
    assert verbose.exit_code == 0
