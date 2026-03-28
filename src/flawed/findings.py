"""Results exploration: load a completed scan and navigate its findings.

This is the *results* analogue of :func:`flawed.open_repo`. Where ``open_repo``
loads the semantic *model* of a repository for rule authoring, this module loads
the *findings* a scan already produced and lets you comb through them
interactively — filter by rule/severity/path, group and count, drill into a
finding's evidence chain, and diff two runs::

    from flawed import load_findings

    findings = load_findings("scan.json")
    findings.by_rule("value-flow").min_severity("high").tabulate("severity", "route_endpoint")
    findings.count_by("rule_id")
    findings.diff(load_findings("baseline.json")).added

It is deliberately distinct from the Rule API collections in
:mod:`flawed.collections`: those require a live Semantic Layer; a
:class:`FindingCollection` wraps inert, already-computed result records loaded
from a self-contained scan document, so it needs no analysis context.

**Source documents.** :func:`load_findings` reads a *path-addressable* results
document: the ``flawed scan --json`` capture (richest — carries severity, route,
evidence descriptions, and gaps) or a ``--output-format sarif`` log (coarser —
no route/evidence, but severity is recovered losslessly from the flawed
``properties.severity`` field). The per-detector result *cache*
(``flawed._cli.result_cache``) is intentionally **not** a source here: it is a
content-hash-keyed recompute memo, not an addressable corpus of a single run's
findings (see the FLAW-138 build note in the handover for the rationale).

**Fail closed.** A document in neither recognized shape, or a finding missing a
required identity field (``rule_id``/``severity``/``fingerprint``), raises
``ValueError`` rather than yielding a silently-empty or partial collection.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from flawed._semantic._collections import _CollectionOps
from flawed.severity import Severity

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path


@dataclass(frozen=True)
class FindingLocation:
    """A source location attached to a finding or one of its evidence items."""

    file: str
    line: int
    column: int | None = None
    end_line: int | None = None
    end_column: int | None = None

    def __str__(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass(frozen=True)
class FindingEvidence:
    """One step in a finding's evidence chain: a description and where it lives."""

    description: str
    location: FindingLocation | None


@dataclass(frozen=True)
class FindingGap:
    """An analysis gap recorded against a finding (incomplete information)."""

    kind: str
    message: str
    affected_file: str | None = None
    affected_function: str | None = None


@dataclass(frozen=True, repr=False)
class FindingRecord:
    """A single finding loaded from a results document.

    Carries the rule identity (absent from a bare ``Finding``; see FLAW-138)
    plus the finding's severity, location, evidence chain, and gaps. Frozen and
    fully hashable so collections can dedup by value and diff by fingerprint.
    """

    rule_id: str
    fingerprint: str
    severity: Severity
    route_endpoint: str
    summary: str
    location: FindingLocation | None
    evidence: tuple[FindingEvidence, ...] = ()
    gaps: tuple[FindingGap, ...] = ()
    rule_path: str = ""
    suppressed: bool = False

    def __repr__(self) -> str:
        loc = str(self.location) if self.location is not None else "?"
        return f"Finding({self.rule_id!r} {self.severity.label} {loc} +{len(self.evidence)}ev)"

    def detail(self) -> str:
        """Multi-line human dump: rule, severity, summary, evidence chain, gaps."""
        loc = str(self.location) if self.location is not None else "?"
        lines = [
            repr(self),
            f"  rule:     {self.rule_id}",
            f"  severity: {self.severity.label}",
            f"  route:    {self.route_endpoint or '?'}",
            f"  location: {loc}",
            f"  summary:  {self.summary}",
        ]
        lines.extend(
            f"  [{i}] {ev.description} @ {ev.location if ev.location is not None else '?'}"
            for i, ev in enumerate(self.evidence, start=1)
        )
        lines.extend(f"  gap: {gap.kind} — {gap.message}" for gap in self.gaps)
        if self.suppressed:
            lines.append("  (suppressed)")
        return "\n".join(lines)


@dataclass(frozen=True)
class FindingDiff:
    """The result of comparing two runs by fingerprint (see :meth:`FindingCollection.diff`).

    ``added`` are in the newer run only, ``removed`` in the baseline only, and
    ``common`` are present in both (taken from the newer run).
    """

    added: FindingCollection
    removed: FindingCollection
    common: FindingCollection

    def summary(self) -> str:
        """One-line counts, e.g. ``+2 added / -1 removed / 5 common``."""
        return (
            f"+{len(self.added)} added / -{len(self.removed)} removed / {len(self.common)} common"
        )


def _coerce_severity(value: Severity | str) -> Severity:
    return value if isinstance(value, Severity) else Severity.parse(value)


class FindingCollection(_CollectionOps[FindingRecord]):
    """An immutable, filterable collection of :class:`FindingRecord`.

    Inherits the generic verbs from ``_CollectionOps`` —
    :meth:`group_by`/:meth:`count_by`/:meth:`tabulate`, ``|`` union,
    indexing/slicing, and the concise ``Name(N) [...]`` repr — and adds
    finding-specific filters. Every filter returns a new collection; the
    original is never mutated.
    """

    __slots__ = ("_items",)

    def __init__(self, items: tuple[FindingRecord, ...] = ()) -> None:
        self._items = tuple(items)

    def __iter__(self) -> Iterator[FindingRecord]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return len(self._items) > 0

    # ── extraction ────────────────────────────────────────────────

    def where(self, predicate: Callable[[FindingRecord], bool]) -> FindingCollection:
        """Keep only findings matching *predicate*."""
        return FindingCollection(tuple(r for r in self._items if predicate(r)))

    def first(self) -> FindingRecord | None:
        """First finding, or ``None`` if empty."""
        return self._items[0] if self._items else None

    def one(self) -> FindingRecord:
        """Exactly one finding, or raise ``ValueError``."""
        if len(self._items) != 1:
            msg = f"expected exactly 1 item, got {len(self._items)}"
            raise ValueError(msg)
        return self._items[0]

    # ── finding-specific filters ──────────────────────────────────

    def by_rule(self, rule_id: str) -> FindingCollection:
        """Keep only findings produced by the rule with this exact id."""
        return self.where(lambda r: r.rule_id == rule_id)

    def by_severity(self, severity: Severity | str) -> FindingCollection:
        """Keep only findings whose severity equals *severity* exactly."""
        target = _coerce_severity(severity)
        return self.where(lambda r: r.severity is target)

    def min_severity(self, severity: Severity | str) -> FindingCollection:
        """Keep only findings at or above *severity* on the ordered ladder."""
        floor = _coerce_severity(severity)
        return self.where(lambda r: r.severity >= floor)

    def in_file(self, path: str) -> FindingCollection:
        """Keep only findings whose location file ends with *path* (suffix match)."""
        return self.where(lambda r: r.location is not None and r.location.file.endswith(path))

    def in_dir(self, path: str) -> FindingCollection:
        """Keep only findings whose location file contains *path* (substring match)."""
        return self.where(lambda r: r.location is not None and path in r.location.file)

    def with_gap(self) -> FindingCollection:
        """Keep only findings that carry at least one analysis gap."""
        return self.where(lambda r: bool(r.gaps))

    # ── run comparison ────────────────────────────────────────────

    def diff(self, other: FindingCollection) -> FindingDiff:
        """Compare this run (newer) against *other* (baseline) by fingerprint."""
        mine = {r.fingerprint: r for r in self._items}
        theirs = {r.fingerprint: r for r in other}
        added = tuple(r for fp, r in mine.items() if fp not in theirs)
        common = tuple(r for fp, r in mine.items() if fp in theirs)
        removed = tuple(r for fp, r in theirs.items() if fp not in mine)
        return FindingDiff(
            added=FindingCollection(added),
            removed=FindingCollection(removed),
            common=FindingCollection(common),
        )

    # ── full dump ─────────────────────────────────────────────────

    def detail(self) -> str:
        """Full multi-line dump of every finding's evidence chain.

        The concise repr stays the default for interactive use; call this when
        you want the whole story for the findings in hand.
        """
        return "\n\n".join(r.detail() for r in self._items)

    pretty = detail


# ── loading ───────────────────────────────────────────────────────


def load_findings(path: str | Path) -> FindingCollection:
    """Load a completed scan's findings into a navigable :class:`FindingCollection`.

    *path* is a results document written by ``flawed scan``: a ``--json``
    capture or a ``--output-format sarif`` log. The format is auto-detected by
    shape. Raises ``ValueError`` for an unrecognized document or a finding
    missing a required identity field (fail closed — never a silent empty).
    """
    from pathlib import Path as _Path

    text = _Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        msg = f"{path}: not valid JSON ({exc})"
        raise ValueError(msg) from exc
    if not isinstance(data, dict):
        # ValueError (not TypeError) is the loader's contract: this reports an
        # invalid results *document*, not a programmer passing the wrong type.
        msg = f"{path}: results document must be a JSON object, got {type(data).__name__}"
        raise ValueError(msg)  # noqa: TRY004

    if isinstance(data.get("findings"), list):
        records = tuple(_record_from_json(f, i) for i, f in enumerate(data["findings"]))
        return FindingCollection(records)
    if isinstance(data.get("runs"), list):
        return FindingCollection(_records_from_sarif(data["runs"]))

    msg = (
        f"{path}: unrecognized results document — expected a flawed --json capture "
        f"(top-level 'findings') or a SARIF log (top-level 'runs')"
    )
    raise ValueError(msg)


def _require(finding: dict[str, Any], key: str, index: int) -> str:
    value = finding.get(key)
    if not isinstance(value, str) or not value:
        msg = f"finding #{index}: missing required string field {key!r}"
        raise ValueError(msg)
    return value


def _location_from_dict(raw: object) -> FindingLocation | None:
    if not isinstance(raw, dict):
        return None
    file = raw.get("file")
    line = raw.get("line")
    if not isinstance(file, str) or not isinstance(line, int):
        return None
    return FindingLocation(
        file=file,
        line=line,
        column=raw.get("column") if isinstance(raw.get("column"), int) else None,
        end_line=raw.get("end_line") if isinstance(raw.get("end_line"), int) else None,
        end_column=raw.get("end_column") if isinstance(raw.get("end_column"), int) else None,
    )


def _record_from_json(finding: object, index: int) -> FindingRecord:
    if not isinstance(finding, dict):
        # Invalid document content -> ValueError (the loader's contract), not a
        # TypeError about a mis-typed Python argument.
        msg = f"finding #{index}: expected an object, got {type(finding).__name__}"
        raise ValueError(msg)  # noqa: TRY004
    rule_id = _require(finding, "rule_id", index)
    severity = Severity.parse(_require(finding, "severity", index))
    fingerprint = _require(finding, "fingerprint", index)

    evidence = tuple(
        FindingEvidence(
            description=str(ev.get("description", "")),
            location=_location_from_dict(ev.get("location")),
        )
        for ev in finding.get("evidence", [])
        if isinstance(ev, dict)
    )
    gaps = tuple(
        FindingGap(
            kind=str(gap.get("kind", "")),
            message=str(gap.get("message", "")),
            affected_file=gap.get("affected_file"),
            affected_function=gap.get("affected_function"),
        )
        for gap in finding.get("gaps", [])
        if isinstance(gap, dict)
    )
    return FindingRecord(
        rule_id=rule_id,
        fingerprint=fingerprint,
        severity=severity,
        route_endpoint=str(finding.get("route_endpoint", "")),
        summary=str(finding.get("summary", "")),
        location=_location_from_dict(finding.get("location")),
        evidence=evidence,
        gaps=gaps,
        rule_path=str(finding.get("rule_path", "")),
        suppressed=bool(finding.get("suppressed", False)),
    )


# SARIF level → severity when the exact flawed label is absent (foreign SARIF).
_SARIF_LEVEL_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


def _records_from_sarif(runs: list[Any]) -> tuple[FindingRecord, ...]:
    records: list[FindingRecord] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        for index, result in enumerate(run.get("results", [])):
            if isinstance(result, dict):
                records.append(_record_from_sarif(result, index))
    return tuple(records)


def _record_from_sarif(result: dict[str, Any], index: int) -> FindingRecord:
    rule_id = _require(result, "ruleId", index)
    props = result.get("properties")
    props = props if isinstance(props, dict) else {}
    raw_sev = props.get("severity")
    if isinstance(raw_sev, str):
        severity = Severity.parse(raw_sev)
    else:
        level = result.get("level")
        severity = _SARIF_LEVEL_SEVERITY.get(level if isinstance(level, str) else "", Severity.LOW)

    message = result.get("message")
    summary = str(message.get("text", "")) if isinstance(message, dict) else ""

    return FindingRecord(
        rule_id=rule_id,
        fingerprint=_sarif_fingerprint(result, rule_id, summary),
        severity=severity,
        route_endpoint="",
        summary=summary,
        location=_sarif_location(result),
        evidence=(),
        gaps=(),
        suppressed=bool(result.get("suppressions")),
    )


def _sarif_fingerprint(result: dict[str, Any], rule_id: str, summary: str) -> str:
    prints = result.get("partialFingerprints")
    if isinstance(prints, dict):
        preferred = prints.get("flawedFingerprint/v1")
        if isinstance(preferred, str) and preferred:
            return preferred
        for value in prints.values():
            if isinstance(value, str) and value:
                return value
    # Foreign SARIF without flawed fingerprints: derive a stable one so diffs work.
    loc = _sarif_location(result)
    material = f"{rule_id}\x00{summary}\x00{loc}"
    return hashlib.sha256(material.encode()).hexdigest()[:16]


def _sarif_location(result: dict[str, Any]) -> FindingLocation | None:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return None
    physical = locations[0].get("physicalLocation") if isinstance(locations[0], dict) else None
    if not isinstance(physical, dict):
        return None
    artifact = physical.get("artifactLocation")
    uri = artifact.get("uri") if isinstance(artifact, dict) else None
    if not isinstance(uri, str):
        return None
    region = physical.get("region")
    region = region if isinstance(region, dict) else {}
    line = region.get("startLine")
    return FindingLocation(
        file=uri,
        line=line if isinstance(line, int) else 0,
        column=region.get("startColumn") if isinstance(region.get("startColumn"), int) else None,
        end_line=region.get("endLine") if isinstance(region.get("endLine"), int) else None,
        end_column=region.get("endColumn") if isinstance(region.get("endColumn"), int) else None,
    )
