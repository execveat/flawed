"""Scan/machine output must never leak an absolute machine path.

Built-in rule provenance renders package-relative (``flawed/_rules/…``) and the
scanned target renders as a portable label (a GitHub slug, or the repo
directory name for a local checkout), so ``--json`` artifacts and the rule
inventory stay reproducible across machines and leak no home/install path.

Regression guard for the scan-output half of the relativize-paths initiative:
before the fix a ``flask_basic`` scan emitted 21 absolute ``/Users/...`` paths
(20 finding ``rule_path`` + 1 ``metadata.target``).
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from flawed._cli._observability import ScanMetrics
from flawed._cli.output import (
    Console,
    _display_rule_path,
    _finding_to_dict,
    _rules_package_parent,
)
from flawed._cli.rules import RuleFinding, RuleSummary
from flawed._config.paths import RepoIdentity
from flawed._rules import builtin_rules_dir
from flawed.core import Location
from flawed.evidence import Finding
from flawed.severity import Severity


def _abs_builtin_rule(rule_id: str = "g999_demo") -> Path:
    """An absolute path to a (synthetic) built-in rule module."""
    return builtin_rules_dir() / "L0_gadgets" / f"{rule_id}.py"


def _rf_abs_rule(rule_id: str = "g999_demo") -> RuleFinding:
    """A finding whose ``rule_path`` is an absolute built-in rule path."""
    return RuleFinding(
        rule_id=rule_id,
        rule_path=_abs_builtin_rule(rule_id),
        finding=Finding(
            route_endpoint="ep",
            summary="demo",
            location=Location(file="app/views.py", line=3, column=1, end_line=3, end_column=6),
            severity=Severity.HIGH,
        ),
    )


def _has_absolute_path(value: object) -> bool:
    """True if any string anywhere in *value* looks like an absolute machine path."""
    if isinstance(value, str):
        return value.startswith("/") or "/Users/" in value
    if isinstance(value, dict):
        return any(_has_absolute_path(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return any(_has_absolute_path(v) for v in value)
    return False


# ── _display_rule_path ────────────────────────────────────────────


def test_display_rule_path_builtin_is_package_relative() -> None:
    rendered = _display_rule_path(_abs_builtin_rule("g050_x"))
    assert rendered == "flawed/_rules/L0_gadgets/g050_x.py"
    assert not Path(rendered).is_absolute()


def test_display_rule_path_foreign_path_is_never_absolute(tmp_path: Path) -> None:
    # A rule outside the flawed package still renders relative (cwd-relative),
    # never an absolute machine path.
    rendered = _display_rule_path(tmp_path / "custom" / "rule.py")
    assert not Path(rendered).is_absolute()
    assert "/Users/" not in rendered


def test_rules_package_parent_contains_flawed_rules() -> None:
    assert (_rules_package_parent() / "flawed" / "_rules").is_dir()


# ── RepoIdentity.display_name ──────────────────────────────────────


def test_display_name_prefers_github_slug() -> None:
    ident = RepoIdentity(
        canonical="pallets/flask", path=Path("/abs/checkout/flask"), hash="deadbeef"
    )
    assert ident.display_name == "pallets/flask"


def test_display_name_local_repo_uses_basename() -> None:
    ident = RepoIdentity(
        canonical="/abs/checkout/flask_basic",
        path=Path("/abs/checkout/flask_basic"),
        hash="deadbeef",
    )
    assert ident.display_name == "flask_basic"
    assert not Path(ident.display_name).is_absolute()


# ── scan --json serialization ──────────────────────────────────────


def test_finding_to_dict_rule_path_is_relative() -> None:
    payload = _finding_to_dict(_rf_abs_rule())
    assert payload["rule_path"] == "flawed/_rules/L0_gadgets/g999_demo.py"
    assert not _has_absolute_path(payload)


def test_scan_json_emitter_has_no_absolute_paths() -> None:
    out, err = io.StringIO(), io.StringIO()
    console = Console(color="never", json_mode=True, stdout=out, stderr=err)
    metrics = ScanMetrics()
    metrics.target = RepoIdentity(
        canonical="/abs/checkout/flask_basic",
        path=Path("/abs/checkout/flask_basic"),
        hash="d",
    ).display_name
    console.show_findings((_rf_abs_rule(),), metrics=metrics)

    payload = json.loads(out.getvalue())
    assert payload["metadata"]["target"] == "flask_basic"
    assert payload["findings"][0]["rule_path"] == "flawed/_rules/L0_gadgets/g999_demo.py"
    assert not _has_absolute_path(payload), "scan --json must contain no absolute machine path"


# ── rules --json inventory ─────────────────────────────────────────


def test_rules_json_emitter_paths_are_relative() -> None:
    out, err = io.StringIO(), io.StringIO()
    console = Console(color="never", json_mode=True, stdout=out, stderr=err)
    summary = RuleSummary(
        rule_id="g050_x",
        description="demo",
        severity=Severity.HIGH,
        path=_abs_builtin_rule("g050_x"),
    )
    console.emit_rules_json((summary,))

    payload = json.loads(out.getvalue())
    assert payload[0]["path"] == "flawed/_rules/L0_gadgets/g050_x.py"
    assert not _has_absolute_path(payload)
