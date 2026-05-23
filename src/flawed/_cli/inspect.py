"""Artifact inspection tooling for L1 cache, L2/L3 profile, and findings.

Reads normalized cache JSONL files and produces deterministic counts for
empirical comparisons.  Call-edge summaries focus on resolution shape.
Extraction-error summaries focus on gap classes, fatality, messages, and
files so deferred CFG warnings are visible without ad hoc shell commands.

Profile and findings summaries read the ``--profile`` JSON and stdout
findings JSON produced by ``flawed scan``, exposing L2/L3 telemetry for
v1 triage workflows.

Used by ``flawed inspect`` commands and by unit/integration tests.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, overload

if TYPE_CHECKING:
    from pathlib import Path


# ── Summary data structures ──────────────────────────────────────────


@dataclass(frozen=True)
class CallEdgeSummary:
    """Deterministic breakdown of call edge counts from a cache directory."""

    total: int
    by_source: dict[str, int]
    by_resolution: dict[str, int]
    by_unresolved_reason: dict[str, int]
    by_dynamic_dispatch_kind: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        return {
            "total": self.total,
            "by_source": dict(sorted(self.by_source.items())),
            "by_resolution": dict(sorted(self.by_resolution.items())),
            "by_unresolved_reason": dict(sorted(self.by_unresolved_reason.items())),
            "by_dynamic_dispatch_kind": dict(sorted(self.by_dynamic_dispatch_kind.items())),
        }


@dataclass(frozen=True)
class ExtractionErrorSummary:
    """Deterministic breakdown of extraction errors from a cache directory."""

    total: int
    fatal: int
    non_fatal: int
    by_kind: dict[str, int]
    by_pass: dict[str, int]
    by_severity: dict[str, int]
    by_message: dict[str, int]
    by_file: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        return {
            "total": self.total,
            "fatal": self.fatal,
            "non_fatal": self.non_fatal,
            "by_kind": dict(sorted(self.by_kind.items())),
            "by_pass": dict(sorted(self.by_pass.items())),
            "by_severity": dict(sorted(self.by_severity.items())),
            "by_message": dict(sorted(self.by_message.items())),
            "by_file": dict(sorted(self.by_file.items())),
        }


@dataclass(frozen=True)
class DiffEntry:
    """A single row in a diff table: category, key, before, after, delta."""

    category: str
    key: str
    before: int
    after: int

    @property
    def delta(self) -> int:
        return self.after - self.before

    @property
    def delta_str(self) -> str:
        d = self.delta
        if d > 0:
            return f"+{d}"
        return str(d)


@dataclass(frozen=True)
class CallEdgeDiff:
    """Deterministic diff between two call edge summaries."""

    total_before: int
    total_after: int
    entries: tuple[DiffEntry, ...]

    @property
    def total_delta(self) -> int:
        return self.total_after - self.total_before

    def has_changes(self) -> bool:
        return self.total_before != self.total_after or any(e.delta != 0 for e in self.entries)


@dataclass(frozen=True)
class ExtractionErrorDiff:
    """Deterministic diff between two extraction error summaries."""

    total_before: int
    total_after: int
    entries: tuple[DiffEntry, ...]

    @property
    def total_delta(self) -> int:
        return self.total_after - self.total_before

    def has_changes(self) -> bool:
        return self.total_before != self.total_after or any(e.delta != 0 for e in self.entries)


@dataclass(frozen=True)
class FindingSummary:
    """Deterministic breakdown of scan findings from stdout JSON."""

    total: int
    retained: int
    truncated: bool
    by_rule: dict[str, int]
    by_severity: dict[str, int]
    by_route: dict[str, int]
    by_file: dict[str, int]
    by_gap_kind: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        return {
            "total": self.total,
            "retained": self.retained,
            "truncated": self.truncated,
            "by_rule": dict(sorted(self.by_rule.items())),
            "by_severity": dict(sorted(self.by_severity.items())),
            "by_route": dict(sorted(self.by_route.items())),
            "by_file": dict(sorted(self.by_file.items())),
            "by_gap_kind": dict(sorted(self.by_gap_kind.items())),
        }


@dataclass(frozen=True)
class ProfileSummary:
    """High-level scan profile overview."""

    status: str
    exit_code: int | None
    target_path: str
    phases: tuple[tuple[str, float], ...]
    l1_counts: dict[str, int]
    l2_counts: dict[str, int]
    l3_counts: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        return {
            "status": self.status,
            "exit_code": self.exit_code,
            "target_path": self.target_path,
            "phases": {name: round(ms, 2) for name, ms in self.phases},
            "l1_counts": dict(sorted(self.l1_counts.items())),
            "l2_counts": dict(sorted(self.l2_counts.items())),
            "l3_counts": dict(sorted(self.l3_counts.items())),
        }


@dataclass(frozen=True)
class GapSummary:
    """Analysis gap breakdown from a scan profile."""

    total: int
    by_kind: dict[str, int]
    by_phase: dict[str, int]
    by_provider: dict[str, int]
    by_file: dict[str, int]
    by_message: dict[str, int]
    finding_gap_total: int
    finding_gap_by_kind: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        return {
            "total": self.total,
            "by_kind": dict(sorted(self.by_kind.items())),
            "by_phase": dict(sorted(self.by_phase.items())),
            "by_provider": dict(sorted(self.by_provider.items())),
            "by_file": dict(sorted(self.by_file.items())),
            "by_message": dict(sorted(self.by_message.items())),
            "finding_gap_total": self.finding_gap_total,
            "finding_gap_by_kind": dict(sorted(self.finding_gap_by_kind.items())),
        }


@dataclass(frozen=True)
class ArtifactSectionSpec:
    """A deterministic count section for a normalized artifact family."""

    title: str
    path: str


@dataclass(frozen=True)
class ArtifactSpec:
    """Inspection metadata for one normalized artifact family."""

    family: str
    filename: str
    count_label: str
    sections: tuple[ArtifactSectionSpec, ...]


@dataclass(frozen=True)
class ArtifactSummary:
    """Deterministic breakdown for a normalized artifact family."""

    family: str
    filename: str
    total: int
    sections: tuple[tuple[str, dict[str, int]], ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        return {
            "family": self.family,
            "filename": self.filename,
            "total": self.total,
            "sections": {title: dict(sorted(counts.items())) for title, counts in self.sections},
        }


@dataclass(frozen=True)
class ArtifactRegistryEntry:
    """Manifest-facing artifact registry entry."""

    family: str
    path: str
    status: str
    description: str | None
    record_count: int | None
    producer: str | None
    reason: str | None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        return {
            "family": self.family,
            "path": self.path,
            "status": self.status,
            "description": self.description,
            "record_count": self.record_count,
            "producer": self.producer,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ArtifactRegistry:
    """Written/deferred artifact contract discovered from normalized metadata."""

    cache_dir: str
    summary: dict[str, Any]
    entries: tuple[ArtifactRegistryEntry, ...]
    cfg_persistence: str | None
    cfg_count: int | None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        return {
            "cache_dir": self.cache_dir,
            "summary": self.summary,
            "cfg_persistence": self.cfg_persistence,
            "cfg_count": self.cfg_count,
            "entries": [entry.to_dict() for entry in self.entries],
        }


# ── Core logic ───────────────────────────────────────────────────────


WRITTEN_ARTIFACT_SPECS: dict[str, ArtifactSpec] = {
    "functions": ArtifactSpec(
        family="functions",
        filename="functions.jsonl",
        count_label="Total functions",
        sections=(
            ArtifactSectionSpec("By file", "file"),
            ArtifactSectionSpec("By kind", "kind"),
            ArtifactSectionSpec("By async", "is_async"),
            ArtifactSectionSpec("By method", "is_method"),
            ArtifactSectionSpec("By nested", "is_nested"),
            ArtifactSectionSpec("By parent class", "parent_class"),
        ),
    ),
    "classes": ArtifactSpec(
        family="classes",
        filename="classes.jsonl",
        count_label="Total classes",
        sections=(
            ArtifactSectionSpec("By file", "file"),
            ArtifactSectionSpec("By MRO completeness", "mro_complete"),
            ArtifactSectionSpec("By abstract", "is_abstract"),
            ArtifactSectionSpec("By metaclass", "metaclass"),
        ),
    ),
    "decorators": ArtifactSpec(
        family="decorators",
        filename="decorators.jsonl",
        count_label="Total decorators",
        sections=(
            ArtifactSectionSpec("By file", "location.file"),
            ArtifactSectionSpec("By name", "name"),
            ArtifactSectionSpec("By FQN", "fqn"),
            ArtifactSectionSpec("By target", "target_fqn"),
        ),
    ),
    "imports": ArtifactSpec(
        family="imports",
        filename="imports.jsonl",
        count_label="Total imports",
        sections=(
            ArtifactSectionSpec("By file", "location.file"),
            ArtifactSectionSpec("By module", "module"),
            ArtifactSectionSpec("By from-import", "is_from_import"),
            ArtifactSectionSpec("By conditional", "is_conditional"),
        ),
    ),
    "attributes": ArtifactSpec(
        family="attributes",
        filename="attributes.jsonl",
        count_label="Total attributes",
        sections=(
            ArtifactSectionSpec("By file", "location.file"),
            ArtifactSectionSpec("By access kind", "access_kind"),
            ArtifactSectionSpec("By write", "is_write"),
            ArtifactSectionSpec("By attribute", "attr_name"),
            ArtifactSectionSpec("By function", "containing_function_fqn"),
        ),
    ),
    "valueflows": ArtifactSpec(
        family="valueflows",
        filename="value_flow_edges.jsonl",
        count_label="Total value-flow edges",
        sections=(
            ArtifactSectionSpec("By file", "source_location.file"),
            ArtifactSectionSpec("By kind", "kind"),
            ArtifactSectionSpec("By function", "containing_function_fqn"),
            ArtifactSectionSpec("By callsite callee", "callsite_callee_fqn"),
        ),
    ),
    "symbolrefs": ArtifactSpec(
        family="symbolrefs",
        filename="symbol_refs.jsonl",
        count_label="Total symbol refs",
        sections=(
            ArtifactSectionSpec("By file", "location.file"),
            ArtifactSectionSpec("By resolution", "resolution"),
            ArtifactSectionSpec("By name", "name"),
            ArtifactSectionSpec("By FQN", "fqn"),
        ),
    ),
}


class _JsonlRecords(Sequence[dict[str, Any]]):
    """Repeatable JSONL record stream with list-like compatibility on demand."""

    __hash__: ClassVar[None] = None  # type: ignore[assignment]

    def __init__(self, path: Path) -> None:
        self._path = path
        self._records: list[dict[str, Any]] | None = None

    def __iter__(self) -> Iterator[dict[str, Any]]:
        if self._records is not None:
            return iter(self._records)
        return _iter_jsonl_path(self._path)

    @overload
    def __getitem__(self, index: int) -> dict[str, Any]: ...

    @overload
    def __getitem__(self, index: slice) -> list[dict[str, Any]]: ...

    def __getitem__(self, index: int | slice) -> dict[str, Any] | list[dict[str, Any]]:
        return self._materialized()[index]

    def __len__(self) -> int:
        return len(self._materialized())

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Sequence):
            return False
        return self._materialized() == list(other)

    def _materialized(self) -> list[dict[str, Any]]:
        if self._records is None:
            self._records = list(_iter_jsonl_path(self._path))
        return self._records


def _iter_jsonl_path(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as f:
        for raw_line in f:
            stripped = raw_line.strip()
            if stripped:
                yield json.loads(stripped)


def _load_jsonl(cache_dir: Path, filename: str) -> Sequence[dict[str, Any]]:
    path = _artifact_path(cache_dir, filename)
    if not path.exists():
        return []

    return _JsonlRecords(path)


def _artifact_path(cache_dir: Path, filename: str) -> Path:
    path = cache_dir / "normalized" / filename
    if path.exists():
        return path
    # Maybe cache_dir IS the normalized directory already.
    return cache_dir / filename


def _load_json_object(cache_dir: Path, filename: str) -> dict[str, Any]:
    path = _artifact_path(cache_dir, filename)
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return {}
    return data


def load_call_edges(cache_dir: Path) -> Sequence[dict[str, Any]]:
    """Load raw call edge records from a normalized cache directory.

    Looks for ``normalized/call_edges.jsonl`` under *cache_dir*.
    Returns an empty list if the file does not exist.  Existing files are
    streamed when iterated; list-like indexing/len still materialize records
    for compatibility with direct helper callers.
    """
    return _load_jsonl(cache_dir, "call_edges.jsonl")


def load_extraction_errors(cache_dir: Path) -> Sequence[dict[str, Any]]:
    """Load raw extraction error records from a normalized cache directory.

    Looks for ``normalized/errors.jsonl`` under *cache_dir*.  Returns an
    empty list if the file does not exist.  Existing files are streamed when
    iterated; list-like indexing/len still materialize records for
    compatibility with direct helper callers.
    """
    return _load_jsonl(cache_dir, "errors.jsonl")


def load_artifact_records(cache_dir: Path, family: str) -> Sequence[dict[str, Any]]:
    """Load raw records for a written normalized artifact family."""
    spec = WRITTEN_ARTIFACT_SPECS[family]
    return _load_jsonl(cache_dir, spec.filename)


def summarize_artifact_family(
    family: str,
    records: Iterable[dict[str, Any]],
) -> ArtifactSummary:
    """Build a deterministic summary from one normalized artifact family."""
    spec = WRITTEN_ARTIFACT_SPECS[family]
    counts_by_title: dict[str, dict[str, int]] = {section.title: {} for section in spec.sections}
    total = 0

    for record in records:
        total += 1
        for section in spec.sections:
            value = _nested_field(record, section.path)
            _increment(counts_by_title[section.title], _string_value(value))

    return ArtifactSummary(
        family=family,
        filename=spec.filename,
        total=total,
        sections=tuple(
            (section.title, counts_by_title[section.title]) for section in spec.sections
        ),
    )


def load_artifact_registry(cache_dir: Path) -> ArtifactRegistry:
    """Load written/deferred artifact metadata from manifest and summary files."""
    manifest = _load_json_object(cache_dir, "manifest.json")
    summary = _load_json_object(cache_dir, "summary.json")
    entries: list[ArtifactRegistryEntry] = []

    for raw_entry in _dict_entries(manifest.get("written_artifacts")):
        path = _string_value(raw_entry.get("path"))
        entries.append(
            ArtifactRegistryEntry(
                family=_family_from_path(path),
                path=path,
                status=_string_value(raw_entry.get("status")),
                description=_optional_string(raw_entry.get("description")),
                record_count=_optional_int(raw_entry.get("record_count")),
                producer=None,
                reason=None,
            )
        )

    for raw_entry in _dict_entries(manifest.get("deferred_artifacts")):
        path = _string_value(raw_entry.get("path"))
        entries.append(
            ArtifactRegistryEntry(
                family=_family_from_path(path),
                path=path,
                status=_string_value(raw_entry.get("status")),
                description=None,
                record_count=None,
                producer=_optional_string(raw_entry.get("producer")),
                reason=_optional_string(raw_entry.get("reason")),
            )
        )

    if not entries:
        entries.extend(_fallback_registry_entries(cache_dir, summary))

    return ArtifactRegistry(
        cache_dir=str(cache_dir),
        summary=summary,
        entries=tuple(sorted(entries, key=lambda entry: (entry.status, entry.path))),
        cfg_persistence=_optional_string(manifest.get("cfg_persistence")),
        cfg_count=_optional_int(manifest.get("cfg_count")),
    )


def load_summary_counts(cache_dir: Path) -> dict[str, Any]:
    """Load aggregate normalized artifact counts from summary.json."""
    return _load_json_object(cache_dir, "summary.json")


def summarize_call_edges(records: Iterable[dict[str, Any]]) -> CallEdgeSummary:
    """Build a deterministic summary from raw call edge records."""
    by_source: dict[str, int] = {}
    by_resolution: dict[str, int] = {}
    by_unresolved_reason: dict[str, int] = {}
    by_dynamic_dispatch_kind: dict[str, int] = {}
    total = 0

    for rec in records:
        total += 1
        source = str(rec.get("source", "unknown"))
        by_source[source] = by_source.get(source, 0) + 1

        resolution = str(rec.get("resolution", "unknown"))
        by_resolution[resolution] = by_resolution.get(resolution, 0) + 1

        reason = rec.get("unresolved_reason")
        if reason is not None:
            reason = str(reason)
            by_unresolved_reason[reason] = by_unresolved_reason.get(reason, 0) + 1

        dispatch = rec.get("dynamic_dispatch_kind")
        if dispatch is not None:
            dispatch = str(dispatch)
            by_dynamic_dispatch_kind[dispatch] = by_dynamic_dispatch_kind.get(dispatch, 0) + 1

    return CallEdgeSummary(
        total=total,
        by_source=by_source,
        by_resolution=by_resolution,
        by_unresolved_reason=by_unresolved_reason,
        by_dynamic_dispatch_kind=by_dynamic_dispatch_kind,
    )


def summarize_extraction_errors(
    records: Iterable[dict[str, Any]], *, kind: str | None = None
) -> ExtractionErrorSummary:
    """Build a deterministic summary from raw extraction error records."""
    kind_filter = kind.lower() if kind is not None else None

    by_kind: dict[str, int] = {}
    by_pass: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_message: dict[str, int] = {}
    by_file: dict[str, int] = {}
    total = 0
    fatal = 0

    for rec in records:
        error_kind = _string_field(rec, "error_kind")
        if kind_filter is not None and error_kind.lower() != kind_filter:
            continue

        total += 1
        is_fatal = rec.get("is_fatal") is True
        if is_fatal:
            fatal += 1

        severity = "fatal" if is_fatal else "non_fatal"
        pass_name = _string_field(rec, "pass_name")
        message = _string_field(rec, "message")
        file_name = _string_field(rec, "file")

        _increment(by_kind, error_kind)
        _increment(by_pass, pass_name)
        _increment(by_severity, severity)
        _increment(by_message, message)
        _increment(by_file, file_name)

    return ExtractionErrorSummary(
        total=total,
        fatal=fatal,
        non_fatal=total - fatal,
        by_kind=by_kind,
        by_pass=by_pass,
        by_severity=by_severity,
        by_message=by_message,
        by_file=by_file,
    )


def diff_summaries(before: CallEdgeSummary, after: CallEdgeSummary) -> CallEdgeDiff:
    """Compare two call edge summaries and produce a deterministic diff."""
    entries: list[DiffEntry] = []

    categories = [
        ("source", before.by_source, after.by_source),
        ("resolution", before.by_resolution, after.by_resolution),
        ("unresolved_reason", before.by_unresolved_reason, after.by_unresolved_reason),
        ("dynamic_dispatch_kind", before.by_dynamic_dispatch_kind, after.by_dynamic_dispatch_kind),
    ]

    for cat_name, before_dict, after_dict in categories:
        all_keys = sorted(set(before_dict) | set(after_dict))
        for key in all_keys:
            b = before_dict.get(key, 0)
            a = after_dict.get(key, 0)
            entries.append(DiffEntry(category=cat_name, key=key, before=b, after=a))

    return CallEdgeDiff(
        total_before=before.total,
        total_after=after.total,
        entries=tuple(entries),
    )


def diff_error_summaries(
    before: ExtractionErrorSummary,
    after: ExtractionErrorSummary,
) -> ExtractionErrorDiff:
    """Compare two extraction error summaries and produce a deterministic diff."""
    entries: list[DiffEntry] = []

    categories = [
        ("kind", before.by_kind, after.by_kind),
        ("pass", before.by_pass, after.by_pass),
        ("severity", before.by_severity, after.by_severity),
        ("message", before.by_message, after.by_message),
        ("file", before.by_file, after.by_file),
    ]

    for cat_name, before_dict, after_dict in categories:
        all_keys = sorted(set(before_dict) | set(after_dict))
        for key in all_keys:
            b = before_dict.get(key, 0)
            a = after_dict.get(key, 0)
            entries.append(DiffEntry(category=cat_name, key=key, before=b, after=a))

    return ExtractionErrorDiff(
        total_before=before.total,
        total_after=after.total,
        entries=tuple(entries),
    )


def format_summary(summary: CallEdgeSummary) -> str:
    """Format a call edge summary as a human-readable table."""
    lines: list[str] = []
    lines.append(f"Total call edges: {summary.total}")
    lines.append("")

    sections = [
        ("By source", summary.by_source),
        ("By resolution", summary.by_resolution),
        ("By unresolved reason", summary.by_unresolved_reason),
        ("By dynamic dispatch kind", summary.by_dynamic_dispatch_kind),
    ]

    for title, data in sections:
        if not data:
            continue
        lines.append(f"{title}:")
        lines.extend(f"  {key}: {data[key]}" for key in sorted(data))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def format_error_summary(summary: ExtractionErrorSummary, *, top: int = 10) -> str:
    """Format an extraction error summary as human-readable text."""
    lines: list[str] = []
    lines.append(f"Total extraction errors: {summary.total}")
    lines.append(f"Fatal: {summary.fatal}")
    lines.append(f"Non-fatal: {summary.non_fatal}")
    lines.append("")

    sections = [
        ("By kind", summary.by_kind),
        ("By pass", summary.by_pass),
        ("By severity", summary.by_severity),
    ]

    for title, data in sections:
        if not data:
            continue
        lines.append(f"{title}:")
        lines.extend(f"  {key}: {data[key]}" for key in sorted(data))
        lines.append("")

    top_sections = [
        ("Top messages", summary.by_message),
        ("Top files", summary.by_file),
    ]
    for title, data in top_sections:
        if not data:
            continue
        lines.append(f"{title}:")
        lines.extend(f"  {key}: {count}" for key, count in _top_counts(data, top))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def format_artifact_summary(summary: ArtifactSummary, *, top: int = 10) -> str:
    """Format a normalized artifact-family summary as human-readable text."""
    spec = WRITTEN_ARTIFACT_SPECS[summary.family]
    lines: list[str] = []
    lines.append(f"{spec.count_label}: {summary.total}")
    lines.append("")

    for title, data in summary.sections:
        if not data:
            continue
        lines.append(f"{title}:")
        lines.extend(f"  {key}: {count}" for key, count in _top_counts(data, top))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def format_artifact_registry(registry: ArtifactRegistry) -> str:
    """Format the normalized artifact registry as human-readable text."""
    lines: list[str] = []
    lines.append("Normalized artifact families:")
    lines.append("")

    for status in ("written", "internal_only", "in_memory_only", "embedded"):
        entries = [entry for entry in registry.entries if entry.status == status]
        if not entries:
            continue
        lines.append(f"{status}:")
        for entry in entries:
            suffix = ""
            if entry.record_count is not None:
                suffix = f" ({entry.record_count} records)"
            elif entry.producer is not None:
                suffix = f" ({entry.producer})"
            lines.append(f"  {entry.family}: {entry.path}{suffix}")
            if entry.description:
                lines.append(f"    {entry.description}")
            if entry.reason:
                lines.append(f"    {entry.reason}")
        lines.append("")

    if registry.summary:
        lines.append("Summary counts:")
        lines.extend(f"  {key}: {registry.summary[key]}" for key in sorted(registry.summary))
        lines.append("")

    if registry.cfg_persistence is not None or registry.cfg_count is not None:
        lines.append(f"CFG persistence: {registry.cfg_persistence or '<missing>'}")
        if registry.cfg_count is not None:
            lines.append(f"CFG count: {registry.cfg_count}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def format_summary_counts(summary: dict[str, Any]) -> str:
    """Format aggregate normalized artifact counts as human-readable text."""
    if not summary:
        return "Summary counts: <missing>\n"
    lines = ["Summary counts:"]
    lines.extend(f"  {key}: {summary[key]}" for key in sorted(summary))
    return "\n".join(lines) + "\n"


def format_diff(diff: CallEdgeDiff) -> str:
    """Format a call edge diff as a human-readable table."""
    if not diff.has_changes():
        return "No changes.\n"

    lines: list[str] = []
    delta = diff.total_after - diff.total_before
    delta_str = f"+{delta}" if delta > 0 else str(delta)
    lines.append(f"Total: {diff.total_before} -> {diff.total_after} ({delta_str})")
    lines.append("")

    current_cat = ""
    for entry in diff.entries:
        if entry.category != current_cat:
            current_cat = entry.category
            lines.append(f"By {current_cat}:")

        if entry.delta == 0:
            lines.append(f"  {entry.key}: {entry.before} (unchanged)")
        else:
            lines.append(f"  {entry.key}: {entry.before} -> {entry.after} ({entry.delta_str})")

    lines.append("")
    return "\n".join(lines)


def format_error_diff(diff: ExtractionErrorDiff) -> str:
    """Format an extraction error diff as human-readable text."""
    if not diff.has_changes():
        return "No changes.\n"

    lines: list[str] = []
    delta = diff.total_after - diff.total_before
    delta_str = f"+{delta}" if delta > 0 else str(delta)
    lines.append(f"Total: {diff.total_before} -> {diff.total_after} ({delta_str})")
    lines.append("")

    current_cat = ""
    for entry in diff.entries:
        if entry.category != current_cat:
            current_cat = entry.category
            lines.append(f"By {current_cat}:")

        if entry.delta == 0:
            lines.append(f"  {entry.key}: {entry.before} (unchanged)")
        else:
            lines.append(f"  {entry.key}: {entry.before} -> {entry.after} ({entry.delta_str})")

    lines.append("")
    return "\n".join(lines)


def _string_field(record: dict[str, Any], key: str) -> str:
    value = record.get(key)
    if value is None or value == "":
        return "<missing>"
    return str(value)


def _string_value(value: object) -> str:
    if value is None or value == "":
        return "<missing>"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list | tuple):
        if not value:
            return "<empty>"
        return ", ".join(_string_value(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    return _string_value(value)


def _optional_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _nested_field(record: dict[str, Any], path: str) -> object:
    current: object = record
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _dict_entries(value: object) -> Iterator[dict[str, Any]]:
    if not isinstance(value, list):
        return
    for item in value:
        if isinstance(item, dict):
            yield item


def _family_from_path(path: str) -> str:
    for family, spec in WRITTEN_ARTIFACT_SPECS.items():
        if path == spec.filename:
            return family
    stem = path.removesuffix(".jsonl").removesuffix(".json")
    return {
        "call_edges": "calledges",
        "value_flow_edges": "valueflows",
        "symbol_refs": "symbolrefs",
    }.get(stem, stem.replace("_", ""))


def _fallback_registry_entries(
    cache_dir: Path,
    summary: dict[str, Any],
) -> Iterator[ArtifactRegistryEntry]:
    for family, spec in WRITTEN_ARTIFACT_SPECS.items():
        path = _artifact_path(cache_dir, spec.filename)
        summary_key = _summary_key_for_family(family)
        if not path.exists() and summary_key not in summary:
            continue
        record_count = _optional_int(summary.get(summary_key))
        if record_count is None:
            record_count = _record_count(path)
        yield ArtifactRegistryEntry(
            family=family,
            path=spec.filename,
            status="written",
            description=None,
            record_count=record_count,
            producer=None,
            reason=None,
        )


def _record_count(path: Path) -> int | None:
    if not path.exists():
        return None
    count = 0
    with path.open(encoding="utf-8") as handle:
        for raw_line in handle:
            if raw_line.strip():
                count += 1
    return count


def _increment(counts: dict[str, int], key: str) -> None:
    counts[key] = counts.get(key, 0) + 1


def _top_counts(counts: dict[str, int], top: int) -> list[tuple[str, int]]:
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:top]


def _summary_key_for_family(family: str) -> str:
    return {
        "calledges": "call_edges",
        "valueflows": "value_flow_edges",
        "symbolrefs": "symbol_refs",
    }.get(family, family)


# ── Findings / profile / gap inspection ─────────────────────────────


def _load_json_file(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return {}
    return data


def load_findings(path: Path) -> dict[str, Any]:
    """Load scan findings from stdout JSON capture."""
    if not path.exists():
        return {}
    return _load_json_file(path)


def summarize_findings(payload: dict[str, Any]) -> FindingSummary:
    """Build a deterministic summary from a findings JSON payload."""
    total = payload.get("finding_count", 0)
    if not isinstance(total, int):
        total = 0
    retained = payload.get("retained_finding_count", total)
    if not isinstance(retained, int):
        retained = total
    truncated = payload.get("findings_truncated", False) is True

    by_rule: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_route: dict[str, int] = {}
    by_file: dict[str, int] = {}
    by_gap_kind: dict[str, int] = {}

    findings = payload.get("findings")
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            _increment(by_rule, _string_value(finding.get("rule_id")))
            _increment(by_severity, _string_value(finding.get("severity")))
            _increment(by_route, _string_value(finding.get("route_endpoint")))
            location = finding.get("location")
            if isinstance(location, dict):
                _increment(by_file, _string_value(location.get("file")))
            else:
                _increment(by_file, "<missing>")
            gaps = finding.get("gaps")
            if isinstance(gaps, list):
                for gap in gaps:
                    if isinstance(gap, dict):
                        _increment(by_gap_kind, _string_value(gap.get("kind")))

    return FindingSummary(
        total=total,
        retained=retained,
        truncated=truncated,
        by_rule=by_rule,
        by_severity=by_severity,
        by_route=by_route,
        by_file=by_file,
        by_gap_kind=by_gap_kind,
    )


def load_profile(path: Path) -> dict[str, Any]:
    """Load a scan profile JSON report."""
    if not path.exists():
        return {}
    return _load_json_file(path)


def _extract_phases(payload: dict[str, Any]) -> tuple[tuple[str, float], ...]:
    raw_phases = payload.get("phases")
    if not isinstance(raw_phases, list):
        return ()
    phases: list[tuple[str, float]] = []
    for phase in raw_phases:
        if isinstance(phase, dict):
            name = _string_value(phase.get("name"))
            wall_ms = phase.get("wall_ms", 0.0)
            if not isinstance(wall_ms, int | float):
                wall_ms = 0.0
            phases.append((name, float(wall_ms)))
    return tuple(phases)


def _extract_int_keys(section: object, keys: tuple[str, ...]) -> dict[str, int]:
    if not isinstance(section, dict):
        return {}
    return {key: section[key] for key in keys if isinstance(section.get(key), int)}


_L2_KEYS = (
    "route_count",
    "function_count",
    "class_count",
    "routes_with_gaps",
    "functions_with_gaps",
    "classes_with_gaps",
)
_L3_KEYS = (
    "rule_file_count",
    "detector_count",
    "finding_count",
    "retained_finding_count",
)


def summarize_profile(payload: dict[str, Any]) -> ProfileSummary:
    """Build a high-level overview from a profile JSON payload."""
    status = _string_value(payload.get("status"))
    exit_code = payload.get("exit_code")
    if not isinstance(exit_code, int):
        exit_code = None

    target = payload.get("target")
    target_path = _string_value(target.get("path") if isinstance(target, dict) else None)

    l1_counts: dict[str, int] = {}
    l1 = payload.get("l1")
    if isinstance(l1, dict):
        counts = l1.get("counts")
        if isinstance(counts, dict):
            l1_counts = {key: value for key, value in counts.items() if isinstance(value, int)}

    l3_counts = _extract_int_keys(payload.get("l3"), _L3_KEYS)
    l3 = payload.get("l3")
    if isinstance(l3, dict) and l3.get("findings_truncated") is True:
        l3_counts["findings_truncated"] = 1

    return ProfileSummary(
        status=status,
        exit_code=exit_code,
        target_path=target_path,
        phases=_extract_phases(payload),
        l1_counts=l1_counts,
        l2_counts=_extract_int_keys(payload.get("l2"), _L2_KEYS),
        l3_counts=l3_counts,
    )


def summarize_gaps(payload: dict[str, Any]) -> GapSummary:
    """Extract gap breakdown from a profile JSON payload."""
    l2 = payload.get("l2")
    gaps: dict[str, Any] = {}
    if isinstance(l2, dict):
        raw_gaps = l2.get("gaps")
        if isinstance(raw_gaps, dict):
            gaps = raw_gaps

    total = gaps.get("total", 0)
    if not isinstance(total, int):
        total = 0

    def _int_dict(key: str) -> dict[str, int]:
        raw = gaps.get(key)
        if not isinstance(raw, dict):
            return {}
        return {str(k): v for k, v in raw.items() if isinstance(v, int)}

    finding_gaps: dict[str, Any] = {}
    l3 = payload.get("l3")
    if isinstance(l3, dict):
        raw_fg = l3.get("finding_gaps")
        if isinstance(raw_fg, dict):
            finding_gaps = raw_fg

    fg_total = finding_gaps.get("total", 0)
    if not isinstance(fg_total, int):
        fg_total = 0

    fg_by_kind: dict[str, int] = {}
    raw_fg_by_kind = finding_gaps.get("by_kind")
    if isinstance(raw_fg_by_kind, dict):
        fg_by_kind = {str(k): v for k, v in raw_fg_by_kind.items() if isinstance(v, int)}

    return GapSummary(
        total=total,
        by_kind=_int_dict("by_kind"),
        by_phase=_int_dict("by_phase"),
        by_provider=_int_dict("by_provider"),
        by_file=_int_dict("by_file"),
        by_message=_int_dict("by_message"),
        finding_gap_total=fg_total,
        finding_gap_by_kind=fg_by_kind,
    )


def format_finding_summary(summary: FindingSummary, *, top: int = 10) -> str:
    """Format a findings summary as human-readable text."""
    lines: list[str] = []
    lines.append(f"Total findings: {summary.total}")
    if summary.retained != summary.total:
        lines.append(f"Retained: {summary.retained}")
    if summary.truncated:
        lines.append("Output was truncated")
    lines.append("")

    sections: list[tuple[str, dict[str, int]]] = [
        ("By rule", summary.by_rule),
        ("By severity", summary.by_severity),
    ]
    for title, data in sections:
        if not data:
            continue
        lines.append(f"{title}:")
        lines.extend(f"  {key}: {data[key]}" for key in sorted(data))
        lines.append("")

    top_sections: list[tuple[str, dict[str, int]]] = [
        ("Top routes", summary.by_route),
        ("Top files", summary.by_file),
    ]
    for title, data in top_sections:
        if not data:
            continue
        lines.append(f"{title}:")
        lines.extend(f"  {key}: {count}" for key, count in _top_counts(data, top))
        lines.append("")

    if summary.by_gap_kind:
        lines.append("Finding gaps by kind:")
        lines.extend(f"  {key}: {summary.by_gap_kind[key]}" for key in sorted(summary.by_gap_kind))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def format_profile_summary(summary: ProfileSummary) -> str:
    """Format a profile summary as human-readable text."""
    lines: list[str] = []
    lines.append(f"Status: {summary.status}")
    if summary.exit_code is not None:
        lines.append(f"Exit code: {summary.exit_code}")
    lines.append(f"Target: {summary.target_path}")
    lines.append("")

    if summary.phases:
        lines.append("Phases:")
        total_ms = 0.0
        for name, wall_ms in summary.phases:
            lines.append(f"  {name}: {wall_ms:.0f}ms")
            total_ms += wall_ms
        lines.append(f"  total: {total_ms:.0f}ms")
        lines.append("")

    if summary.l1_counts:
        lines.append("L1 counts:")
        lines.extend(f"  {key}: {summary.l1_counts[key]}" for key in sorted(summary.l1_counts))
        lines.append("")

    if summary.l2_counts:
        lines.append("L2 counts:")
        lines.extend(f"  {key}: {summary.l2_counts[key]}" for key in sorted(summary.l2_counts))
        lines.append("")

    if summary.l3_counts:
        lines.append("L3 counts:")
        lines.extend(f"  {key}: {summary.l3_counts[key]}" for key in sorted(summary.l3_counts))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def format_gap_summary(summary: GapSummary, *, top: int = 10) -> str:
    """Format a gap summary as human-readable text."""
    lines: list[str] = []
    lines.append(f"Total L2 gaps: {summary.total}")
    lines.append("")

    sections: list[tuple[str, dict[str, int]]] = [
        ("By kind", summary.by_kind),
        ("By phase", summary.by_phase),
        ("By provider", summary.by_provider),
    ]
    for title, data in sections:
        if not data:
            continue
        lines.append(f"{title}:")
        lines.extend(f"  {key}: {data[key]}" for key in sorted(data))
        lines.append("")

    top_sections: list[tuple[str, dict[str, int]]] = [
        ("Top files", summary.by_file),
        ("Top messages", summary.by_message),
    ]
    for title, data in top_sections:
        if not data:
            continue
        lines.append(f"{title}:")
        lines.extend(f"  {key}: {count}" for key, count in _top_counts(data, top))
        lines.append("")

    if summary.finding_gap_total > 0:
        lines.append(f"L3 finding gaps: {summary.finding_gap_total}")
        if summary.finding_gap_by_kind:
            lines.append("Finding gaps by kind:")
            lines.extend(
                f"  {key}: {summary.finding_gap_by_kind[key]}"
                for key in sorted(summary.finding_gap_by_kind)
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
