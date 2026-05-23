"""Results-exploration tooling tests (FLAW-138).

Covers the public :func:`flawed.load_findings` loader, the
:class:`flawed.findings.FindingCollection` query surface (finding-specific
filters plus the inherited ``_CollectionOps`` verbs), run-diffing by
fingerprint, and the ``flawed explore`` CLI summary surface.

Findings are loaded from a self-contained results document (the ``flawed
scan --json`` capture, or a SARIF log), so these tests build small payloads
on disk and exercise the loader/collection without running a scan.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from click.testing import CliRunner

from flawed import load_findings
from flawed._cli.app import cli
from flawed.findings import FindingCollection, FindingDiff, FindingRecord
from flawed.severity import Severity

if TYPE_CHECKING:
    from pathlib import Path


def _finding(
    rule_id: str,
    *,
    severity: str,
    fingerprint: str,
    file: str = "app/views.py",
    line: int = 10,
    route: str = "views.index",
    summary: str = "summary text",
    gaps: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "rule_path": f"/rules/{rule_id}.py",
        "fingerprint": fingerprint,
        "severity": severity,
        "route_endpoint": route,
        "summary": summary,
        "location": {
            "file": file,
            "line": line,
            "column": 1,
            "end_line": line,
            "end_column": 5,
        },
        "evidence": [{"description": "user input read", "location": {"file": file, "line": line}}],
        "gaps": gaps or [],
        "suppressed": False,
    }


def _write_json(path: Path, findings: list[dict[str, Any]]) -> Path:
    payload = {
        "finding_count": len(findings),
        "retained_finding_count": len(findings),
        "findings_truncated": False,
        "suppressed_count": 0,
        "findings": findings,
    }
    path.write_text(json.dumps(payload, indent=2))
    return path


def _sample(path: Path) -> Path:
    return _write_json(
        path,
        [
            _finding("rule-alpha", severity="high", fingerprint="aaaa1111", file="app/a.py"),
            _finding("rule-alpha", severity="low", fingerprint="bbbb2222", file="app/b.py"),
            _finding(
                "rule-beta",
                severity="critical",
                fingerprint="cccc3333",
                file="app/a.py",
                gaps=[
                    {
                        "kind": "unresolved_call",
                        "message": "could not resolve",
                        "affected_file": "app/a.py",
                        "affected_function": "load",
                    }
                ],
            ),
        ],
    )


# ── loader ────────────────────────────────────────────────────────


def test_load_findings_from_flawed_json(tmp_path: Path) -> None:
    coll = load_findings(_sample(tmp_path / "scan.json"))
    assert isinstance(coll, FindingCollection)
    assert len(coll) == 3
    rec = coll[0]
    assert isinstance(rec, FindingRecord)
    assert rec.rule_id == "rule-alpha"
    assert rec.severity is Severity.HIGH
    assert rec.fingerprint == "aaaa1111"
    assert rec.location is not None
    assert rec.location.file == "app/a.py"
    assert rec.location.line == 10


def test_load_findings_unknown_format_fails_closed(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"not": "a results document"}))
    with pytest.raises(ValueError, match="unrecognized"):
        load_findings(bad)


def test_load_findings_missing_required_field_raises(tmp_path: Path) -> None:
    path = tmp_path / "partial.json"
    path.write_text(json.dumps({"findings": [{"rule_id": "x", "summary": "no severity"}]}))
    with pytest.raises(ValueError, match="severity"):
        load_findings(path)


# ── finding-specific filters ──────────────────────────────────────


def test_by_rule(tmp_path: Path) -> None:
    coll = load_findings(_sample(tmp_path / "s.json"))
    assert len(coll.by_rule("rule-alpha")) == 2
    assert len(coll.by_rule("rule-beta")) == 1
    assert len(coll.by_rule("nope")) == 0


def test_by_severity_and_min_severity_accept_str_or_enum(tmp_path: Path) -> None:
    coll = load_findings(_sample(tmp_path / "s.json"))
    assert len(coll.by_severity("high")) == 1
    assert len(coll.by_severity(Severity.LOW)) == 1
    # min_severity is inclusive and ordered: high+critical >= high
    assert len(coll.min_severity("high")) == 2
    assert len(coll.min_severity(Severity.CRITICAL)) == 1


def test_in_file_and_in_dir(tmp_path: Path) -> None:
    coll = load_findings(_sample(tmp_path / "s.json"))
    assert len(coll.in_file("a.py")) == 2
    assert len(coll.in_dir("app/")) == 3


def test_with_gap(tmp_path: Path) -> None:
    coll = load_findings(_sample(tmp_path / "s.json"))
    gapped = coll.with_gap()
    assert len(gapped) == 1
    assert gapped.one().rule_id == "rule-beta"


def test_where_first_one(tmp_path: Path) -> None:
    coll = load_findings(_sample(tmp_path / "s.json"))
    assert coll.where(lambda r: r.severity is Severity.LOW).one().fingerprint == "bbbb2222"
    assert coll.first() is not None
    with pytest.raises(ValueError, match="exactly 1"):
        coll.by_rule("rule-alpha").one()


# ── inherited _CollectionOps verbs ────────────────────────────────


def test_group_by_and_count_by(tmp_path: Path) -> None:
    coll = load_findings(_sample(tmp_path / "s.json"))
    by_rule = coll.group_by("rule_id")
    assert set(by_rule) == {"rule-alpha", "rule-beta"}
    assert len(by_rule["rule-alpha"]) == 2
    counts = coll.count_by("severity")
    assert counts[Severity.HIGH] == 1
    assert counts[Severity.CRITICAL] == 1


def test_repr_is_concise(tmp_path: Path) -> None:
    coll = load_findings(_sample(tmp_path / "s.json"))
    text = repr(coll)
    assert text.startswith("FindingCollection(3) [")
    # the per-record repr must be one line, not a ballooned evidence dump
    assert "\n" not in repr(coll[0])


# ── run diff ──────────────────────────────────────────────────────


def test_diff_by_fingerprint(tmp_path: Path) -> None:
    new = load_findings(_sample(tmp_path / "new.json"))
    old = load_findings(
        _write_json(
            tmp_path / "old.json",
            [
                _finding("rule-alpha", severity="high", fingerprint="aaaa1111"),
                _finding("rule-gamma", severity="medium", fingerprint="dddd4444"),
            ],
        )
    )
    diff = new.diff(old)
    assert isinstance(diff, FindingDiff)
    assert {r.fingerprint for r in diff.added} == {"bbbb2222", "cccc3333"}
    assert {r.fingerprint for r in diff.removed} == {"dddd4444"}
    assert {r.fingerprint for r in diff.common} == {"aaaa1111"}


# ── SARIF source ──────────────────────────────────────────────────


def test_load_findings_from_sarif(tmp_path: Path) -> None:
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "flawed", "rules": []}},
                "results": [
                    {
                        "ruleId": "rule-alpha",
                        "level": "error",
                        "message": {"text": "divergent validation"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/a.py"},
                                    "region": {"startLine": 12, "startColumn": 3},
                                }
                            }
                        ],
                        "partialFingerprints": {"flawedFingerprint/v1": "aaaa1111"},
                        "properties": {"severity": "high"},
                    }
                ],
            }
        ],
    }
    path = tmp_path / "out.sarif"
    path.write_text(json.dumps(sarif))
    coll = load_findings(path)
    assert len(coll) == 1
    rec = coll.one()
    assert rec.rule_id == "rule-alpha"
    assert rec.severity is Severity.HIGH  # recovered from properties, not coarse level
    assert rec.fingerprint == "aaaa1111"
    assert rec.location is not None
    assert rec.location.line == 12


# ── CLI surface ───────────────────────────────────────────────────


def test_explore_group_by_rule(tmp_path: Path) -> None:
    path = _sample(tmp_path / "s.json")
    result = CliRunner().invoke(cli, ["explore", str(path), "--group-by", "rule"])
    assert result.exit_code == 0, result.output
    assert "rule-alpha" in result.output
    assert "rule-beta" in result.output


def test_explore_rule_filter_and_top(tmp_path: Path) -> None:
    path = _sample(tmp_path / "s.json")
    result = CliRunner().invoke(cli, ["explore", str(path), "--rule", "rule-alpha"])
    assert result.exit_code == 0, result.output
    assert "rule-alpha" in result.output
    assert "rule-beta" not in result.output


def test_explore_diff(tmp_path: Path) -> None:
    new = _sample(tmp_path / "new.json")
    old = _write_json(
        tmp_path / "old.json",
        [_finding("rule-alpha", severity="high", fingerprint="aaaa1111")],
    )
    result = CliRunner().invoke(cli, ["explore", str(new), "--diff", str(old)])
    assert result.exit_code == 0, result.output
    assert "added" in result.output.lower()


def test_explore_default_overview_non_interactive(tmp_path: Path) -> None:
    path = _sample(tmp_path / "s.json")
    # No projection flag + non-tty stdin: must print an overview, never hang on a REPL.
    result = CliRunner().invoke(cli, ["explore", str(path)])
    assert result.exit_code == 0, result.output
    assert "3" in result.output  # total finding count surfaced
