"""Surfaced suppression: inline directives, .flawedignore, --baseline-commit.

Covers FLAW-148 (inline ``# flawed: ignore`` — suppressed findings are excluded
from the active set but still emitted, flagged, in --json/--sarif), FLAW-150
(``.flawedignore`` path-glob + rule scoping), FLAW-149 (location-stable key that
survives line shifts), and FLAW-165 (``main()`` propagates ``ctx.exit`` codes).
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path
from typing import cast

from flawed._cli.output import Console, build_sarif_log
from flawed._cli.rules import RuleFinding
from flawed._cli.suppression import (
    IgnoreSpec,
    SuppressionRecord,
    compute_suppressions,
    location_stable_key,
    parse_inline_directives,
)
from flawed.core import Location
from flawed.evidence import Finding
from flawed.severity import Severity


def _rf(rule_id: str, *, file: str = "app.py", line: int = 10) -> RuleFinding:
    return RuleFinding(
        rule_id=rule_id,
        rule_path=Path(f"{rule_id}.py"),
        finding=Finding(
            route_endpoint="ep",
            summary=f"summary for {rule_id}",
            location=Location(file=file, line=line, column=0),
            severity=Severity.HIGH,
        ),
    )


def _write(root: Path, rel: str, lines: list[str]) -> None:
    (root / rel).write_text("\n".join(lines) + "\n", encoding="utf-8")


# ── Inline directive parsing ───────────────────────────────────────────────


def test_parse_inline_directives_variants() -> None:
    text = (
        "a = 1  # flawed: ignore\n"
        "b = 2  # flawed: ignore[rule-a]\n"
        "c = 3  # flawed: ignore[rule_a, ruleb] -- known FP, tracked in JIRA-1\n"
        "d = 4  # nothing here"
    )
    directives = parse_inline_directives(text)
    assert directives[1] == (None, None)  # all rules, no reason
    assert directives[2] == (frozenset({"rule_a"}), None)  # separator-normalised
    ids, reason = directives[3]
    assert ids == frozenset({"rule_a", "ruleb"})
    assert reason == "known FP, tracked in JIRA-1"
    assert 4 not in directives


# ── compute_suppressions: inline ───────────────────────────────────────────


def test_inline_same_line_rule_scoped(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", ["x = 0"] * 9 + ["danger()  # flawed: ignore[rule-a]"])
    findings = [_rf("rule-a", line=10), _rf("ruleb", line=10)]
    outcome = compute_suppressions(findings, root=tmp_path)
    assert [f.rule_id for f in outcome.active] == ["ruleb"]  # only rule-a suppressed
    assert len(outcome.suppressed) == 1
    rec = outcome.suppressed[0]
    assert rec.source == "inline" and rec.kind == "inSource"
    assert rec.finding.rule_id == "rule-a"


def test_inline_line_above_and_all_rules(tmp_path: Path) -> None:
    # Directive on the line *above* the finding suppresses every rule there.
    _write(tmp_path, "app.py", ["x = 0"] * 8 + ["# flawed: ignore", "danger()"])
    findings = [_rf("rule-a", line=10), _rf("ruleb", line=10)]
    outcome = compute_suppressions(findings, root=tmp_path)
    assert outcome.active == ()
    assert len(outcome.suppressed) == 2


def test_inline_separator_insensitive(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", ["x = 0"] * 9 + ["danger()  # flawed: ignore[rule_a]"])
    # Finding id uses hyphens; directive uses underscores — must still match.
    outcome = compute_suppressions([_rf("rule-a", line=10)], root=tmp_path)
    assert outcome.active == ()
    assert len(outcome.suppressed) == 1


def test_inline_strict_requires_reason(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", ["x = 0"] * 9 + ["danger()  # flawed: ignore[rule-a]"])
    warnings: list[str] = []
    # Without --strict the unreasoned directive applies.
    lax = compute_suppressions([_rf("rule-a", line=10)], root=tmp_path)
    assert len(lax.suppressed) == 1
    # Under --strict it is ignored (finding stays active) and a warning fires.
    strict = compute_suppressions(
        [_rf("rule-a", line=10)], root=tmp_path, strict=True, warn=warnings.append
    )
    assert [f.rule_id for f in strict.active] == ["rule-a"]
    assert strict.suppressed == ()
    assert warnings and "reason" in warnings[0]


def test_inline_strict_with_reason_applies(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", ["x = 0"] * 9 + ["danger()  # flawed: ignore[rule-a] -- vetted"])
    outcome = compute_suppressions([_rf("rule-a", line=10)], root=tmp_path, strict=True)
    assert outcome.active == ()
    assert outcome.suppressed[0].justification == "vetted"


# ── .flawedignore ──────────────────────────────────────────────────────────


def test_ignore_spec_all_rules_and_scoped() -> None:
    spec = IgnoreSpec.parse("# comment\nvendor/**\nmigrations/*.py  rule-c, rule-d\n")
    assert spec.matches("vendor/lib/x.py", "anything")  # all rules under vendor/
    assert spec.matches("migrations/0001.py", "rule_c")  # scoped, separator-insensitive
    assert not spec.matches("migrations/0001.py", "rule-a")  # other rule not scoped
    assert not spec.matches("app/views.py", "rule-c")  # path not matched


def test_compute_suppressions_flawedignore(tmp_path: Path) -> None:
    spec = IgnoreSpec.parse("vendor/**\n")
    findings = [_rf("rule-a", file="vendor/lib.py", line=3), _rf("rule-a", file="app.py", line=3)]
    outcome = compute_suppressions(findings, root=tmp_path, ignore_spec=spec)
    assert [str(cast("Location", f.finding.location).file) for f in outcome.active] == ["app.py"]
    assert outcome.suppressed[0].source == ".flawedignore"
    assert outcome.suppressed[0].kind == "external"


# ── location-stable key (--baseline-commit) ────────────────────────────────


def test_location_stable_key_survives_line_shift(tmp_path: Path) -> None:
    # Same source line at line 10 vs line 25 -> identical key (line-shift stable).
    _write(tmp_path, "a.py", ["pad"] * 9 + ["    do_the_risky_thing(user_input)"])
    _write(tmp_path, "b.py", ["pad"] * 24 + ["    do_the_risky_thing(user_input)"])
    key_a = location_stable_key("rule-a", tmp_path, "a.py", 10)
    key_b = location_stable_key("rule-a", tmp_path, "b.py", 25)
    assert key_a == key_b
    # A different rule id on the same line is a different key.
    assert location_stable_key("ruleb", tmp_path, "a.py", 10) != key_a


def test_compute_suppressions_baseline_commit_keys(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", ["pad"] * 9 + ["    risky(x)"])
    finding = _rf("rule-a", file="app.py", line=10)
    key = location_stable_key("rule-a", tmp_path, "app.py", 10)
    outcome = compute_suppressions([finding], root=tmp_path, baseline_commit_keys=frozenset({key}))
    assert outcome.active == ()
    assert outcome.suppressed[0].source == "--baseline-commit"


# ── Suppressed findings still surface in --json / --sarif ───────────────────


def test_json_emits_suppressed_flagged() -> None:
    out, err = io.StringIO(), io.StringIO()
    console = Console(color="never", json_mode=True, stdout=out, stderr=err)
    active = [_rf("ruleb", line=5)]
    suppressed = [
        SuppressionRecord(
            finding=_rf("rule-a", line=10),
            source="inline",
            reason="# flawed: ignore[rule-a]",
            kind="inSource",
            justification="vetted",
        )
    ]
    console.show_findings(active, suppressed=suppressed)
    payload = json.loads(out.getvalue())
    assert payload["finding_count"] == 1  # active only
    assert payload["suppressed_count"] == 1
    by_id = {f["rule_id"]: f for f in payload["findings"]}
    assert by_id["ruleb"]["suppressed"] is False
    assert by_id["rule-a"]["suppressed"] is True  # still emitted, flagged
    assert by_id["rule-a"]["suppression"]["justification"] == "vetted"


def test_sarif_marks_suppressed_results() -> None:
    active = [_rf("ruleb", line=5)]
    suppressed = [
        SuppressionRecord(
            finding=_rf("rule-a", line=10),
            source="inline",
            reason="# flawed: ignore[rule-a]",
            kind="inSource",
            justification="vetted",
        )
    ]
    log = build_sarif_log(active, suppressed)
    results = log["runs"][0]["results"]
    assert len(results) == 2  # both present (completeness)
    by_id = {r["ruleId"]: r for r in results}
    assert "suppressions" not in by_id["ruleb"]
    assert by_id["rule-a"]["suppressions"] == [{"kind": "inSource", "justification": "vetted"}]


# ── FLAW-165: main() propagates ctx.exit codes ─────────────────────────────


def test_main_propagates_no_target_exit_code() -> None:
    # `flawed scan` with no TARGET prints help and ctx.exit(2). main() runs Click
    # with standalone_mode=False; FLAW-165 ensures the returned code propagates
    # (CliRunner cannot exercise this — it must be the real main() entry).
    code = "import sys; sys.argv = ['flawed', 'scan']; from flawed._cli import main; main()"
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2, proc.stderr
