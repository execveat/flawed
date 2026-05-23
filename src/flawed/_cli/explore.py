"""``flawed explore`` — comb through a completed scan's findings.

The results analogue of ``open_repo`` + the ``inspect`` family: load a scan
document (``--json`` capture or SARIF) and either drop into a Python REPL with
the findings preloaded, or get a one-shot summary via ``--group-by`` /
``--rule`` / ``--diff``. Every flag-driven view is a one-liner over the
:class:`~flawed.findings.FindingCollection` verbs; the REPL is the primary
surface and the summaries are sugar over the same object.

Formatting lives in pure ``format_*`` functions (string in, string out) so the
behaviour is unit-testable without Click or a TTY.
"""

from __future__ import annotations

import code
from typing import TYPE_CHECKING

from flawed.findings import FindingCollection, FindingRecord, load_findings
from flawed.severity import Severity

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_GROUP_KEYS: dict[str, Callable[[FindingRecord], object]] = {
    "rule": lambda r: r.rule_id,
    "severity": lambda r: r.severity.label,
    "file": lambda r: r.location.file if r.location is not None else "(no location)",
}


def _aligned_counts(pairs: list[tuple[str, int]]) -> list[str]:
    if not pairs:
        return ["  (none)"]
    width = max(len(label) for label, _ in pairs)
    return [f"  {label.ljust(width)}  {count}" for label, count in pairs]


def format_overview(findings: FindingCollection, *, top: int = 10) -> str:
    """Default view: total, severity breakdown, and the top rules by count."""
    lines = [f"{len(findings)} findings"]

    sev_counts = findings.count_by("severity")
    sev_pairs = [(sev.label, sev_counts[sev]) for sev in Severity.ordered() if sev_counts.get(sev)]
    lines.append("")
    lines.append("by severity:")
    lines.extend(_aligned_counts(sev_pairs))

    rule_counts = findings.count_by("rule_id").most_common(top)
    lines.append("")
    lines.append(f"by rule (top {top}):")
    lines.extend(_aligned_counts([(str(rule), count) for rule, count in rule_counts]))
    return "\n".join(lines) + "\n"


def format_group(findings: FindingCollection, key: str, *, top: int | None = None) -> str:
    """Counts grouped by ``rule`` | ``severity`` | ``file``, most frequent first."""
    keyfn = _GROUP_KEYS[key]
    counts = findings.count_by(keyfn).most_common(top)
    lines = [f"by {key} ({len(findings)} findings):"]
    lines.extend(_aligned_counts([(str(value), count) for value, count in counts]))
    return "\n".join(lines) + "\n"


def format_listing(findings: FindingCollection, *, top: int) -> str:
    """One concise line per finding, capped at *top* with an elision note."""
    items = list(findings)
    shown = items[:top]
    lines = [repr(rec) for rec in shown]
    if len(items) > top:
        lines.append(f"… +{len(items) - top} more")
    if not lines:
        lines.append("(no findings)")
    return "\n".join(lines) + "\n"


def format_diff(findings: FindingCollection, baseline: FindingCollection, *, top: int) -> str:
    """Render a run-to-run diff: counts then the added/removed findings."""
    diff = findings.diff(baseline)
    lines = [diff.summary(), ""]
    for label, coll in (("added", diff.added), ("removed", diff.removed)):
        lines.append(f"{label} ({len(coll)}):")
        if coll:
            lines.append(format_listing(coll, top=top).rstrip("\n"))
        else:
            lines.append("  (none)")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def explore_results(
    results: Path,
    *,
    group_by: str | None,
    rule: str | None,
    diff: Path | None,
    top: int,
    interactive: bool,
) -> str | None:
    """Drive one ``flawed explore`` invocation.

    Returns the text to print, or ``None`` after launching an interactive REPL.
    """
    findings = load_findings(results)

    if diff is not None:
        return format_diff(findings, load_findings(diff), top=top)
    if rule is not None:
        findings = findings.by_rule(rule)
    if group_by is not None:
        return format_group(findings, group_by, top=top)
    if rule is not None:
        return format_listing(findings, top=top)
    if interactive:
        _run_repl(findings, results)
        return None
    return format_overview(findings, top=top)


def _run_repl(findings: FindingCollection, results: Path) -> None:
    banner = (
        f"flawed explore — {len(findings)} findings from {results}\n"
        "  findings : FindingCollection (try .by_rule(...), .min_severity('high'),\n"
        "             .group_by('rule_id'), .count_by('severity'), .with_gap())\n"
        "  load_findings(path) -> FindingCollection ; Severity ladder in scope\n"
        "  e.g.  findings.count_by('rule_id')   or   findings[0].detail()\n"
    )
    code.interact(
        banner=banner,
        local={
            "findings": findings,
            "load_findings": load_findings,
            "FindingCollection": FindingCollection,
            "Severity": Severity,
        },
        exitmsg="",
    )
