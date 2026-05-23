"""Tests for artifact inspect summary, diff, findings, profile, and gap tooling."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from flawed._cli.inspect import (
    DiffEntry,
    diff_error_summaries,
    diff_summaries,
    format_artifact_registry,
    format_artifact_summary,
    format_diff,
    format_error_diff,
    format_error_summary,
    format_finding_summary,
    format_gap_summary,
    format_profile_summary,
    format_summary,
    format_summary_counts,
    load_artifact_records,
    load_artifact_registry,
    load_call_edges,
    load_extraction_errors,
    load_summary_counts,
    summarize_artifact_family,
    summarize_call_edges,
    summarize_extraction_errors,
    summarize_findings,
    summarize_gaps,
    summarize_profile,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    import pytest


class _OneShotRecords:
    """Iterable that fails if a summary path tries to iterate records twice."""

    def __init__(self, records: list[dict[str, object]]) -> None:
        self._records = records
        self._used = False

    def __iter__(self) -> Iterator[dict[str, object]]:
        if self._used:
            msg = "records were retained and re-iterated"
            raise AssertionError(msg)
        self._used = True
        return iter(self._records)


# ── Fixtures ─────────────────────────────────────────────────────────


def _make_edge(
    *,
    source: str = "ast",
    resolution: str = "resolved",
    unresolved_reason: str | None = None,
    dynamic_dispatch_kind: str | None = None,
    caller_fqn: str = "mod.caller",
    callee_fqn: str | None = "mod.callee",
) -> dict[str, object]:
    """Build a minimal call edge record as would appear in JSONL."""
    rec: dict[str, object] = {
        "caller_fqn": caller_fqn,
        "callee_fqn": callee_fqn,
        "source": source,
        "resolution": resolution,
        "arguments": [],
        "location": {
            "file": "mod.py",
            "line": 1,
            "column": 0,
            "end_line": 1,
            "end_column": 10,
        },
        "provenance": {
            "producer": "structural_entity_pass",
            "producer_version": "0.1.0",
            "artifact": "mod.py",
        },
    }
    if unresolved_reason is not None:
        rec["unresolved_reason"] = unresolved_reason
    else:
        rec["unresolved_reason"] = None
    if dynamic_dispatch_kind is not None:
        rec["dynamic_dispatch_kind"] = dynamic_dispatch_kind
    else:
        rec["dynamic_dispatch_kind"] = None
    return rec


def _make_error(
    *,
    error_kind: str = "cfg",
    pass_name: str = "cfg_builder",
    file: str = "app.py",
    message: str = "Deferred construct: yield",
    is_fatal: bool = False,
    line: int = 10,
) -> dict[str, object]:
    """Build a minimal extraction error record as would appear in JSONL."""
    return {
        "file": file,
        "pass_name": pass_name,
        "error_kind": error_kind,
        "message": message,
        "is_fatal": is_fatal,
        "location": {
            "file": file,
            "line": line,
            "column": 4,
            "end_line": line,
            "end_column": 12,
        },
    }


def _span(file: str = "app.py", *, line: int = 1) -> dict[str, object]:
    return {
        "file": file,
        "line": line,
        "column": 0,
        "end_line": line,
        "end_column": 10,
    }


def _provenance(artifact: str = "normalized/functions.jsonl") -> dict[str, object]:
    return {
        "producer": "structural_entity_pass",
        "producer_version": "0.1.0",
        "artifact": artifact,
    }


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    """Write records to a JSONL file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for rec in records:
            f.write(json.dumps(rec, sort_keys=True) + "\n")


def _write_json(path: Path, data: dict[str, object]) -> None:
    """Write a JSON object."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, sort_keys=True) + "\n", encoding="utf-8")


# ── load_call_edges ──────────────────────────────────────────────────


class TestLoadCallEdges:
    """Loading raw call edge records from cache directories."""

    def test_loads_from_normalized_subdir(self, tmp_path: Path) -> None:
        records = [_make_edge(), _make_edge(source="hierarchy")]
        _write_jsonl(tmp_path / "normalized" / "call_edges.jsonl", records)

        loaded = load_call_edges(tmp_path)
        assert loaded == records
        assert len(loaded) == 2
        assert loaded[0]["source"] == "ast"
        assert loaded[1]["source"] == "hierarchy"

    def test_loads_from_direct_dir(self, tmp_path: Path) -> None:
        """Supports pointing directly at the normalized directory."""
        records = [_make_edge(source="hierarchy")]
        _write_jsonl(tmp_path / "call_edges.jsonl", records)

        loaded = load_call_edges(tmp_path)
        assert len(loaded) == 1
        assert loaded[0]["source"] == "hierarchy"

    def test_returns_empty_for_missing_file(self, tmp_path: Path) -> None:
        assert load_call_edges(tmp_path) == []

    def test_skips_blank_lines(self, tmp_path: Path) -> None:
        path = tmp_path / "normalized" / "call_edges.jsonl"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(_make_edge()) + "\n\n" + json.dumps(_make_edge()) + "\n")
        assert len(load_call_edges(tmp_path)) == 2


# ── load_extraction_errors ───────────────────────────────────────────


class TestLoadExtractionErrors:
    """Loading raw extraction error records from cache directories."""

    def test_loads_from_normalized_subdir(self, tmp_path: Path) -> None:
        records = [_make_error(), _make_error(error_kind="resolution")]
        _write_jsonl(tmp_path / "normalized" / "errors.jsonl", records)

        loaded = load_extraction_errors(tmp_path)
        assert len(loaded) == 2
        assert loaded[0]["error_kind"] == "cfg"
        assert loaded[1]["error_kind"] == "resolution"

    def test_loads_from_direct_dir(self, tmp_path: Path) -> None:
        records = [_make_error(error_kind="resolution")]
        _write_jsonl(tmp_path / "errors.jsonl", records)

        loaded = load_extraction_errors(tmp_path)
        assert len(loaded) == 1
        assert loaded[0]["error_kind"] == "resolution"

    def test_returns_empty_for_missing_file(self, tmp_path: Path) -> None:
        assert load_extraction_errors(tmp_path) == []

    def test_skips_blank_lines(self, tmp_path: Path) -> None:
        path = tmp_path / "normalized" / "errors.jsonl"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(_make_error()) + "\n\n" + json.dumps(_make_error()) + "\n")
        assert len(load_extraction_errors(tmp_path)) == 2


# ── generic artifact summaries ───────────────────────────────────────


class TestArtifactSummaries:
    """Generic inspection for remaining normalized artifact families."""

    def test_loads_named_artifact_family(self, tmp_path: Path) -> None:
        records: list[dict[str, Any]] = [
            {
                "fqn": "app.index",
                "name": "index",
                "file": "app.py",
                "kind": "top_level",
                "is_async": False,
                "is_method": False,
                "is_nested": False,
                "parent_class": None,
            }
        ]
        _write_jsonl(tmp_path / "normalized" / "functions.jsonl", records)

        loaded = load_artifact_records(tmp_path, "functions")

        assert loaded == records

    def test_summarizes_nested_and_boolean_fields(self) -> None:
        records: list[dict[str, Any]] = [
            {
                "source_location": {"file": "app.py"},
                "kind": "assign",
                "containing_function_fqn": "app.index",
                "callsite_callee_fqn": None,
            },
            {
                "source_location": {"file": "views.py"},
                "kind": "argument",
                "containing_function_fqn": "views.show",
                "callsite_callee_fqn": "web.redirect",
            },
        ]

        summary = summarize_artifact_family("valueflows", records)
        data = summary.to_dict()

        assert data["total"] == 2
        assert data["sections"]["By file"] == {"app.py": 1, "views.py": 1}
        assert data["sections"]["By kind"] == {"argument": 1, "assign": 1}
        assert data["sections"]["By callsite callee"] == {
            "<missing>": 1,
            "web.redirect": 1,
        }

    def test_format_artifact_summary_limits_top_entries(self) -> None:
        records = [
            {"location": {"file": "b.py"}, "module": "b", "is_from_import": False},
            {"location": {"file": "a.py"}, "module": "a", "is_from_import": True},
        ]

        output = format_artifact_summary(
            summarize_artifact_family("imports", records),
            top=1,
        )

        assert "Total imports: 2" in output
        assert "By file:" in output
        assert "  a.py: 1" in output
        assert "  b.py: 1" not in output


class TestArtifactRegistry:
    """Manifest inspection for written and deferred artifact families."""

    def test_reads_manifest_and_summary(self, tmp_path: Path) -> None:
        normalized = tmp_path / "normalized"
        normalized.mkdir()
        (normalized / "summary.json").write_text(
            json.dumps({"functions": 1, "errors": 0}) + "\n",
            encoding="utf-8",
        )
        (normalized / "manifest.json").write_text(
            json.dumps(
                {
                    "cfg_persistence": "in_memory_only",
                    "cfg_count": 3,
                    "written_artifacts": [
                        {
                            "path": "functions.jsonl",
                            "status": "written",
                            "record_count": 1,
                            "description": "Function records.",
                        }
                    ],
                    "deferred_artifacts": [
                        {
                            "path": "cfgs.jsonl",
                            "status": "in_memory_only",
                            "producer": "cfg_builder",
                            "reason": "CFGs are rebuilt.",
                        }
                    ],
                }
            )
            + "\n",
            encoding="utf-8",
        )

        registry = load_artifact_registry(tmp_path)
        output = format_artifact_registry(registry)
        data = registry.to_dict()

        assert data["cfg_count"] == 3
        assert {entry["family"] for entry in data["entries"]} == {"cfgs", "functions"}
        assert "functions: functions.jsonl (1 records)" in output
        assert "cfgs: cfgs.jsonl (cfg_builder)" in output
        assert "CFG persistence: in_memory_only" in output

    def test_reads_summary_counts(self, tmp_path: Path) -> None:
        normalized = tmp_path / "normalized"
        normalized.mkdir()
        (normalized / "summary.json").write_text(
            json.dumps({"errors": 0, "functions": 2}) + "\n",
            encoding="utf-8",
        )

        summary = load_summary_counts(tmp_path)
        output = format_summary_counts(summary)

        assert summary == {"errors": 0, "functions": 2}
        assert "Summary counts:" in output
        assert "  functions: 2" in output


# ── summarize_call_edges ─────────────────────────────────────────────


class TestSummarizeCallEdges:
    """Deterministic summary of call edge counts."""

    def test_empty_records(self) -> None:
        summary = summarize_call_edges([])
        assert summary.total == 0
        assert summary.by_source == {}
        assert summary.by_resolution == {}

    def test_counts_by_source(self) -> None:
        records = [
            _make_edge(source="ast"),
            _make_edge(source="ast"),
            _make_edge(source="hierarchy"),
            _make_edge(source="hierarchy"),
        ]
        summary = summarize_call_edges(records)
        assert summary.total == 4
        assert summary.by_source == {"ast": 2, "hierarchy": 2}

    def test_counts_by_resolution(self) -> None:
        records = [
            _make_edge(resolution="resolved"),
            _make_edge(resolution="resolved"),
            _make_edge(resolution="unresolved"),
        ]
        summary = summarize_call_edges(records)
        assert summary.by_resolution == {"resolved": 2, "unresolved": 1}

    def test_counts_unresolved_reasons(self) -> None:
        records = [
            _make_edge(
                resolution="unresolved",
                unresolved_reason="dynamic_dispatch_getattr",
            ),
            _make_edge(
                resolution="unresolved",
                unresolved_reason="dynamic_dispatch_getattr",
            ),
            _make_edge(
                resolution="unresolved",
                unresolved_reason="dynamic_dispatch_computed_call",
            ),
            _make_edge(resolution="resolved"),
        ]
        summary = summarize_call_edges(records)
        assert summary.by_unresolved_reason == {
            "dynamic_dispatch_getattr": 2,
            "dynamic_dispatch_computed_call": 1,
        }

    def test_counts_dynamic_dispatch_kinds(self) -> None:
        records = [
            _make_edge(dynamic_dispatch_kind="getattr"),
            _make_edge(dynamic_dispatch_kind="getattr"),
            _make_edge(dynamic_dispatch_kind="computed_call"),
        ]
        summary = summarize_call_edges(records)
        assert summary.by_dynamic_dispatch_kind == {
            "getattr": 2,
            "computed_call": 1,
        }

    def test_null_optional_fields_excluded(self) -> None:
        """Fields with None/null are not counted in optional buckets."""
        records = [_make_edge()]  # all optional fields are None
        summary = summarize_call_edges(records)
        assert summary.by_unresolved_reason == {}
        assert summary.by_dynamic_dispatch_kind == {}

    def test_to_dict_is_sorted(self) -> None:
        records = [
            _make_edge(source="hierarchy"),
            _make_edge(source="ast"),
            _make_edge(source="unknown"),
        ]
        summary = summarize_call_edges(records)
        d = summary.to_dict()
        assert list(d["by_source"].keys()) == ["ast", "hierarchy", "unknown"]

    def test_streaming_iterable_matches_list_semantics(self) -> None:
        records = [
            _make_edge(source="ast"),
            _make_edge(source="hierarchy", resolution="unresolved"),
        ]

        assert (
            summarize_call_edges(iter(records)).to_dict()
            == summarize_call_edges(records).to_dict()
        )


# ── summarize_extraction_errors ──────────────────────────────────────


class TestSummarizeExtractionErrors:
    """Deterministic summary of extraction error counts."""

    def test_empty_records(self) -> None:
        summary = summarize_extraction_errors([])
        assert summary.total == 0
        assert summary.fatal == 0
        assert summary.non_fatal == 0
        assert summary.by_kind == {}

    def test_counts_by_kind_pass_severity_message_and_file(self) -> None:
        records = [
            _make_error(message="Deferred construct: yield", file="a.py"),
            _make_error(message="Deferred construct: yield", file="a.py"),
            _make_error(message="Deferred construct: async for", file="b.py"),
            _make_error(
                error_kind="parse",
                pass_name="structural_entity_pass",
                message="Syntax error",
                file="bad.py",
                is_fatal=True,
            ),
        ]

        summary = summarize_extraction_errors(records)
        assert summary.total == 4
        assert summary.fatal == 1
        assert summary.non_fatal == 3
        assert summary.by_kind == {"cfg": 3, "parse": 1}
        assert summary.by_pass == {"cfg_builder": 3, "structural_entity_pass": 1}
        assert summary.by_severity == {"fatal": 1, "non_fatal": 3}
        assert summary.by_message == {
            "Deferred construct: async for": 1,
            "Deferred construct: yield": 2,
            "Syntax error": 1,
        }
        assert summary.by_file == {"a.py": 2, "b.py": 1, "bad.py": 1}

    def test_kind_filter_limits_records_before_counting(self) -> None:
        records = [
            _make_error(error_kind="cfg", message="Deferred construct: yield"),
            _make_error(error_kind="resolution", message="Cannot resolve import"),
        ]
        summary = summarize_extraction_errors(records, kind="CFG")
        assert summary.total == 1
        assert summary.by_kind == {"cfg": 1}
        assert summary.by_message == {"Deferred construct: yield": 1}

    def test_to_dict_is_sorted(self) -> None:
        records = [
            _make_error(error_kind="resolution", file="z.py"),
            _make_error(error_kind="cfg", file="a.py"),
        ]
        data = summarize_extraction_errors(records).to_dict()
        assert list(data["by_kind"].keys()) == ["cfg", "resolution"]
        assert list(data["by_file"].keys()) == ["a.py", "z.py"]

    def test_streaming_iterable_matches_list_semantics_with_filter(self) -> None:
        records = [
            _make_error(error_kind="cfg", file="a.py"),
            _make_error(error_kind="resolution", file="b.py"),
            _make_error(error_kind="cfg", file="c.py", is_fatal=True),
        ]

        assert summarize_extraction_errors(iter(records), kind="cfg").to_dict() == (
            summarize_extraction_errors(records, kind="cfg").to_dict()
        )


# ── diff_summaries ───────────────────────────────────────────────────


class TestDiffSummaries:
    """Deterministic diff between two summaries."""

    def test_identical_summaries(self) -> None:
        summary = summarize_call_edges([_make_edge()])
        diff = diff_summaries(summary, summary)
        assert not diff.has_changes()
        assert diff.total_delta == 0

    def test_total_delta(self) -> None:
        before = summarize_call_edges([_make_edge()])
        after = summarize_call_edges([_make_edge(), _make_edge(source="hierarchy")])
        diff = diff_summaries(before, after)
        assert diff.has_changes()
        assert diff.total_before == 1
        assert diff.total_after == 2
        assert diff.total_delta == 1

    def test_new_category_appears(self) -> None:
        before = summarize_call_edges([_make_edge(source="ast")])
        after = summarize_call_edges([_make_edge(source="ast"), _make_edge(source="hierarchy")])
        diff = diff_summaries(before, after)
        source_entries = [e for e in diff.entries if e.category == "source"]
        hierarchy = next(e for e in source_entries if e.key == "hierarchy")
        assert hierarchy.before == 0
        assert hierarchy.after == 1
        assert hierarchy.delta == 1

    def test_category_disappears(self) -> None:
        before = summarize_call_edges([_make_edge(source="ast"), _make_edge(source="hierarchy")])
        after = summarize_call_edges([_make_edge(source="ast")])
        diff = diff_summaries(before, after)
        source_entries = [e for e in diff.entries if e.category == "source"]
        hierarchy = next(e for e in source_entries if e.key == "hierarchy")
        assert hierarchy.before == 1
        assert hierarchy.after == 0
        assert hierarchy.delta == -1

    def test_diff_entry_delta_str(self) -> None:
        entry_pos = DiffEntry(category="source", key="ast", before=5, after=8)
        assert entry_pos.delta_str == "+3"

        entry_neg = DiffEntry(category="source", key="ast", before=8, after=5)
        assert entry_neg.delta_str == "-3"

        entry_zero = DiffEntry(category="source", key="ast", before=5, after=5)
        assert entry_zero.delta_str == "0"

    def test_unresolved_reason_diff(self) -> None:
        before = summarize_call_edges(
            [
                _make_edge(
                    resolution="unresolved",
                    unresolved_reason="dynamic_dispatch_getattr",
                )
            ]
        )
        after = summarize_call_edges(
            [
                _make_edge(
                    resolution="unresolved",
                    unresolved_reason="dynamic_dispatch_getattr",
                ),
                _make_edge(
                    resolution="unresolved",
                    unresolved_reason="dynamic_dispatch_computed_call",
                ),
            ]
        )
        diff = diff_summaries(before, after)
        reason_entries = [e for e in diff.entries if e.category == "unresolved_reason"]
        assert len(reason_entries) == 2
        getattr_entry = next(e for e in reason_entries if e.key == "dynamic_dispatch_getattr")
        assert getattr_entry.delta == 0
        computed_entry = next(
            e for e in reason_entries if e.key == "dynamic_dispatch_computed_call"
        )
        assert computed_entry.delta == 1


# ── diff_error_summaries ─────────────────────────────────────────────


class TestDiffErrorSummaries:
    """Deterministic diff between extraction error summaries."""

    def test_total_delta(self) -> None:
        before = summarize_extraction_errors([_make_error(message="Deferred construct: yield")])
        after = summarize_extraction_errors(
            [
                _make_error(message="Deferred construct: yield"),
                _make_error(message="Deferred construct: try/finally exception propagation"),
            ]
        )

        diff = diff_error_summaries(before, after)
        assert diff.has_changes()
        assert diff.total_before == 1
        assert diff.total_after == 2
        assert diff.total_delta == 1

    def test_message_category_delta(self) -> None:
        before = summarize_extraction_errors([_make_error(message="Deferred construct: yield")])
        after = summarize_extraction_errors(
            [
                _make_error(message="Deferred construct: yield"),
                _make_error(message="Deferred construct: yield"),
                _make_error(message="Deferred construct: async with"),
            ]
        )

        diff = diff_error_summaries(before, after)
        message_entries = [e for e in diff.entries if e.category == "message"]
        yld = next(e for e in message_entries if e.key == "Deferred construct: yield")
        async_with = next(e for e in message_entries if e.key == "Deferred construct: async with")
        assert yld.delta == 1
        assert async_with.before == 0
        assert async_with.after == 1


# ── format_summary ───────────────────────────────────────────────────


class TestFormatSummary:
    """Human-readable summary output."""

    def test_empty_summary(self) -> None:
        summary = summarize_call_edges([])
        output = format_summary(summary)
        assert "Total call edges: 0" in output

    def test_includes_all_categories(self) -> None:
        records = [
            _make_edge(source="ast", resolution="resolved"),
            _make_edge(
                source="ast",
                resolution="unresolved",
                unresolved_reason="dynamic_dispatch_getattr",
                dynamic_dispatch_kind="getattr",
            ),
        ]
        summary = summarize_call_edges(records)
        output = format_summary(summary)
        assert "Total call edges: 2" in output
        assert "By source:" in output
        assert "ast: 2" in output
        assert "By resolution:" in output
        assert "By unresolved reason:" in output
        assert "By dynamic dispatch kind:" in output

    def test_omits_empty_categories(self) -> None:
        records = [_make_edge()]
        summary = summarize_call_edges(records)
        output = format_summary(summary)
        assert "By unresolved reason:" not in output
        assert "By dynamic dispatch kind:" not in output


# ── format_error_summary ─────────────────────────────────────────────


class TestFormatErrorSummary:
    """Human-readable extraction error summary output."""

    def test_empty_summary(self) -> None:
        output = format_error_summary(summarize_extraction_errors([]))
        assert "Total extraction errors: 0" in output

    def test_includes_top_messages_and_files(self) -> None:
        records = [
            _make_error(message="Deferred construct: yield", file="a.py"),
            _make_error(message="Deferred construct: yield", file="a.py"),
            _make_error(message="Deferred construct: async for", file="b.py"),
        ]
        output = format_error_summary(summarize_extraction_errors(records), top=1)
        assert "Total extraction errors: 3" in output
        assert "Fatal: 0" in output
        assert "Non-fatal: 3" in output
        assert "By kind:" in output
        assert "cfg: 3" in output
        assert "Top messages:" in output
        assert "Deferred construct: yield: 2" in output
        assert "Deferred construct: async for" not in output
        assert "Top files:" in output
        assert "a.py: 2" in output


# ── format_diff ──────────────────────────────────────────────────────


class TestFormatDiff:
    """Human-readable diff output."""

    def test_no_changes(self) -> None:
        summary = summarize_call_edges([_make_edge()])
        diff = diff_summaries(summary, summary)
        output = format_diff(diff)
        assert "No changes" in output

    def test_shows_deltas(self) -> None:
        before = summarize_call_edges([_make_edge(source="ast")])
        after = summarize_call_edges([_make_edge(source="ast"), _make_edge(source="hierarchy")])
        diff = diff_summaries(before, after)
        output = format_diff(diff)
        assert "1 -> 2 (+1)" in output
        assert "hierarchy: 0 -> 1 (+1)" in output


# ── format_error_diff ────────────────────────────────────────────────


class TestFormatErrorDiff:
    """Human-readable extraction error diff output."""

    def test_no_changes(self) -> None:
        summary = summarize_extraction_errors([_make_error()])
        assert "No changes" in format_error_diff(diff_error_summaries(summary, summary))

    def test_shows_message_deltas(self) -> None:
        before = summarize_extraction_errors([_make_error(message="Deferred construct: yield")])
        after = summarize_extraction_errors(
            [
                _make_error(message="Deferred construct: yield"),
                _make_error(message="Deferred construct: yield"),
            ]
        )
        output = format_error_diff(diff_error_summaries(before, after))
        assert "1 -> 2 (+1)" in output
        assert "Deferred construct: yield: 1 -> 2 (+1)" in output


# ── CLI integration (Click runner) ───────────────────────────────────


class TestInspectCLI:
    """CLI commands exercise the summary and diff logic."""

    def test_artifacts_lists_written_and_deferred_families(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        normalized = tmp_path / "normalized"
        normalized.mkdir()
        (normalized / "summary.json").write_text(
            json.dumps({"functions": 1}) + "\n",
            encoding="utf-8",
        )
        (normalized / "manifest.json").write_text(
            json.dumps(
                {
                    "written_artifacts": [
                        {
                            "path": "functions.jsonl",
                            "status": "written",
                            "record_count": 1,
                        }
                    ],
                    "deferred_artifacts": [
                        {
                            "path": "aliases.jsonl",
                            "status": "internal_only",
                            "producer": "structural_entity_pass",
                            "reason": "Deferred.",
                        }
                    ],
                }
            )
            + "\n",
            encoding="utf-8",
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["inspect", "artifacts", str(tmp_path)])

        assert result.exit_code == 0
        assert "functions: functions.jsonl (1 records)" in result.output
        assert "aliases: aliases.jsonl (structural_entity_pass)" in result.output

    def test_summary_command_text_output(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        normalized = tmp_path / "normalized"
        normalized.mkdir()
        (normalized / "summary.json").write_text(
            json.dumps({"functions": 2, "errors": 0}) + "\n",
            encoding="utf-8",
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["inspect", "summary", str(tmp_path)])

        assert result.exit_code == 0
        assert "Summary counts:" in result.output
        assert "  functions: 2" in result.output

    def test_remaining_artifact_family_command_text_output(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        _write_jsonl(
            tmp_path / "normalized" / "symbol_refs.jsonl",
            [
                {
                    "name": "redirect",
                    "fqn": "web.redirect",
                    "resolution": "resolved",
                    "location": {"file": "app.py"},
                }
            ],
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["inspect", "symbolrefs", str(tmp_path)])

        assert result.exit_code == 0
        assert "Total symbol refs: 1" in result.output
        assert "By resolution:" in result.output
        assert "  resolved: 1" in result.output

    def test_remaining_artifact_family_command_json_output(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        _write_jsonl(
            tmp_path / "normalized" / "attributes.jsonl",
            [
                {
                    "target_expr": "request",
                    "attr_name": "args",
                    "access_kind": "attr",
                    "is_write": False,
                    "containing_function_fqn": "app.index",
                    "location": {"file": "app.py"},
                }
            ],
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["inspect", "attributes", "--json", str(tmp_path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["family"] == "attributes"
        assert data["sections"]["By write"] == {"false": 1}

    def test_calledges_text_output(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        records = [_make_edge(), _make_edge(source="hierarchy")]
        _write_jsonl(tmp_path / "normalized" / "call_edges.jsonl", records)

        runner = CliRunner()
        result = runner.invoke(cli, ["inspect", "calledges", str(tmp_path)])
        assert result.exit_code == 0
        assert "Total call edges: 2" in result.output

    def test_calledges_json_output(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        records = [_make_edge(), _make_edge(source="hierarchy")]
        _write_jsonl(tmp_path / "normalized" / "call_edges.jsonl", records)

        runner = CliRunner()
        result = runner.invoke(cli, ["inspect", "calledges", "--json", str(tmp_path)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total"] == 2

    def test_calledges_diff_text(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        before_dir = tmp_path / "before"
        after_dir = tmp_path / "after"

        _write_jsonl(
            before_dir / "normalized" / "call_edges.jsonl",
            [_make_edge(source="ast")],
        )
        _write_jsonl(
            after_dir / "normalized" / "call_edges.jsonl",
            [_make_edge(source="ast"), _make_edge(source="hierarchy")],
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["inspect", "calledges-diff", str(before_dir), str(after_dir)],
        )
        assert result.exit_code == 0
        assert "1 -> 2 (+1)" in result.output

    def test_calledges_diff_json(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        before_dir = tmp_path / "before"
        after_dir = tmp_path / "after"

        _write_jsonl(
            before_dir / "normalized" / "call_edges.jsonl",
            [_make_edge(source="ast")],
        )
        _write_jsonl(
            after_dir / "normalized" / "call_edges.jsonl",
            [_make_edge(source="ast"), _make_edge(source="hierarchy")],
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "inspect",
                "calledges-diff",
                "--json",
                str(before_dir),
                str(after_dir),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_before"] == 1
        assert data["total_after"] == 2
        assert data["total_delta"] == 1

    def test_calledges_diff_accepts_one_shot_record_iterables(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        before_dir = tmp_path / "before"
        after_dir = tmp_path / "after"
        before_dir.mkdir()
        after_dir.mkdir()

        def fake_load_call_edges(cache_dir: Path) -> _OneShotRecords:
            if cache_dir == before_dir:
                return _OneShotRecords([_make_edge(source="ast")])
            if cache_dir == after_dir:
                return _OneShotRecords([_make_edge(source="ast"), _make_edge(source="hierarchy")])
            msg = f"unexpected cache dir: {cache_dir}"
            raise AssertionError(msg)

        monkeypatch.setattr("flawed._cli.inspect.load_call_edges", fake_load_call_edges)

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["inspect", "calledges-diff", str(before_dir), str(after_dir)],
        )
        assert result.exit_code == 0
        assert "1 -> 2 (+1)" in result.output

    def test_calledges_empty_dir(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        # Create an empty normalized dir so Click's exists=True check passes
        (tmp_path / "normalized").mkdir(parents=True)

        runner = CliRunner()
        result = runner.invoke(cli, ["inspect", "calledges", str(tmp_path)])
        assert result.exit_code == 0
        assert "Total call edges: 0" in result.output

    def test_errors_text_output(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        _write_jsonl(
            tmp_path / "normalized" / "errors.jsonl",
            [_make_error(), _make_error(message="Deferred construct: try/finally")],
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["inspect", "errors", str(tmp_path)])
        assert result.exit_code == 0
        assert "Total extraction errors: 2" in result.output
        assert "Deferred construct: yield: 1" in result.output

    def test_errors_json_output_with_kind_filter(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        _write_jsonl(
            tmp_path / "normalized" / "errors.jsonl",
            [
                _make_error(error_kind="cfg"),
                _make_error(error_kind="resolution", message="Cannot resolve import"),
            ],
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["inspect", "errors", "--kind", "cfg", "--json", str(tmp_path)],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total"] == 1
        assert data["by_kind"] == {"cfg": 1}

    def test_errors_diff_text(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        before_dir = tmp_path / "before"
        after_dir = tmp_path / "after"
        _write_jsonl(before_dir / "normalized" / "errors.jsonl", [_make_error()])
        _write_jsonl(
            after_dir / "normalized" / "errors.jsonl",
            [_make_error(), _make_error()],
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["inspect", "errors-diff", str(before_dir), str(after_dir)],
        )
        assert result.exit_code == 0
        assert "Deferred construct: yield: 1 -> 2 (+1)" in result.output

    def test_errors_diff_json(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        before_dir = tmp_path / "before"
        after_dir = tmp_path / "after"
        _write_jsonl(before_dir / "normalized" / "errors.jsonl", [_make_error()])
        _write_jsonl(
            after_dir / "normalized" / "errors.jsonl",
            [_make_error(), _make_error(message="Deferred construct: async for")],
        )

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "inspect",
                "errors-diff",
                "--kind",
                "cfg",
                "--json",
                str(before_dir),
                str(after_dir),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_before"] == 1
        assert data["total_after"] == 2
        assert data["total_delta"] == 1


# ── Findings inspection ─────────────────────────────────────────────


def _make_finding(
    *,
    rule_id: str = "CONF-001",
    severity: str = "HIGH",
    route_endpoint: str = "app.index",
    file: str = "app.py",
    line: int = 10,
    gaps: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "rule_id": rule_id,
        "rule_path": "rules/conf_001.py",
        "severity": severity,
        "route_endpoint": route_endpoint,
        "summary": "Test finding",
        "location": {"file": file, "line": line, "column": 0, "end_line": line, "end_column": 10},
        "evidence": [],
        "gaps": gaps or [],
    }


def _findings_payload(
    findings: list[dict[str, object]],
    *,
    truncated: bool = False,
) -> dict[str, object]:
    return {
        "finding_count": len(findings),
        "retained_finding_count": len(findings),
        "findings_truncated": truncated,
        "findings": findings,
    }


class TestSummarizeFindings:
    """Deterministic summary of scan findings."""

    def test_empty_payload(self) -> None:
        summary = summarize_findings({})
        assert summary.total == 0
        assert summary.retained == 0
        assert summary.truncated is False
        assert summary.by_rule == {}

    def test_counts_by_rule_severity_route_file(self) -> None:
        findings = [
            _make_finding(rule_id="CONF-001", severity="HIGH", file="a.py"),
            _make_finding(rule_id="CONF-001", severity="HIGH", file="a.py"),
            _make_finding(rule_id="CONF-002", severity="MEDIUM", file="b.py"),
        ]
        summary = summarize_findings(_findings_payload(findings))

        assert summary.total == 3
        assert summary.retained == 3
        assert summary.by_rule == {"CONF-001": 2, "CONF-002": 1}
        assert summary.by_severity == {"HIGH": 2, "MEDIUM": 1}
        assert summary.by_file == {"a.py": 2, "b.py": 1}

    def test_counts_gaps(self) -> None:
        findings = [
            _make_finding(gaps=[{"kind": "missing_type_info", "message": "No type for x"}]),
            _make_finding(
                gaps=[
                    {"kind": "missing_type_info", "message": "No type for y"},
                    {"kind": "unresolved_call", "message": "Cannot resolve foo"},
                ]
            ),
        ]
        summary = summarize_findings(_findings_payload(findings))

        assert summary.by_gap_kind == {"missing_type_info": 2, "unresolved_call": 1}

    def test_truncated_flag(self) -> None:
        summary = summarize_findings(_findings_payload([], truncated=True))
        assert summary.truncated is True

    def test_to_dict_is_sorted(self) -> None:
        findings = [
            _make_finding(rule_id="CONF-002"),
            _make_finding(rule_id="CONF-001"),
        ]
        data = summarize_findings(_findings_payload(findings)).to_dict()
        assert list(data["by_rule"].keys()) == ["CONF-001", "CONF-002"]


class TestFormatFindingSummary:
    """Human-readable findings summary output."""

    def test_includes_totals_and_sections(self) -> None:
        findings = [
            _make_finding(rule_id="CONF-001", file="a.py"),
            _make_finding(rule_id="CONF-002", file="b.py"),
        ]
        output = format_finding_summary(summarize_findings(_findings_payload(findings)))

        assert "Total findings: 2" in output
        assert "By rule:" in output
        assert "CONF-001: 1" in output
        assert "By severity:" in output
        assert "Top files:" in output

    def test_top_limits_entries(self) -> None:
        findings = [
            _make_finding(file="a.py"),
            _make_finding(file="a.py"),
            _make_finding(file="b.py"),
        ]
        output = format_finding_summary(
            summarize_findings(_findings_payload(findings)),
            top=1,
        )
        assert "a.py: 2" in output
        assert "b.py" not in output

    def test_shows_gap_kinds(self) -> None:
        findings = [
            _make_finding(gaps=[{"kind": "missing_type_info", "message": "x"}]),
        ]
        output = format_finding_summary(summarize_findings(_findings_payload(findings)))
        assert "Finding gaps by kind:" in output
        assert "missing_type_info: 1" in output


# ── Profile inspection ──────────────────────────────────────────────


def _make_profile(
    *,
    status: str = "completed",
    exit_code: int = 0,
    target_path: str = "/tmp/repo",
    l1_counts: dict[str, int] | None = None,
    l2_counts: dict[str, int] | None = None,
    l3_counts: dict[str, int] | None = None,
    phases: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": 1,
        "status": status,
        "exit_code": exit_code,
        "target": {"path": target_path, "canonical": target_path},
        "phases": phases or [{"name": "L1", "wall_ms": 1000.0}],
    }
    if l1_counts is not None:
        payload["l1"] = {"counts": l1_counts}
    if l2_counts is not None:
        payload["l2"] = l2_counts
    if l3_counts is not None:
        payload["l3"] = l3_counts
    return payload


class TestSummarizeProfile:
    """High-level scan profile overview."""

    def test_extracts_status_and_target(self) -> None:
        summary = summarize_profile(_make_profile())
        assert summary.status == "completed"
        assert summary.exit_code == 0
        assert summary.target_path == "/tmp/repo"

    def test_extracts_phase_timing(self) -> None:
        phases = [
            {"name": "L1", "wall_ms": 1500.5},
            {"name": "L2", "wall_ms": 800.0},
        ]
        summary = summarize_profile(_make_profile(phases=phases))
        assert summary.phases == (("L1", 1500.5), ("L2", 800.0))

    def test_extracts_l1_counts(self) -> None:
        summary = summarize_profile(
            _make_profile(l1_counts={"functions": 100, "classes": 20, "errors": 5})
        )
        assert summary.l1_counts == {"functions": 100, "classes": 20, "errors": 5}

    def test_extracts_l2_counts(self) -> None:
        summary = summarize_profile(
            _make_profile(
                l2_counts={"route_count": 10, "function_count": 50, "routes_with_gaps": 2},
            )
        )
        assert summary.l2_counts == {
            "route_count": 10,
            "function_count": 50,
            "routes_with_gaps": 2,
        }

    def test_extracts_l3_counts(self) -> None:
        summary = summarize_profile(
            _make_profile(l3_counts={"finding_count": 5, "detector_count": 3})
        )
        assert summary.l3_counts == {"finding_count": 5, "detector_count": 3}

    def test_empty_profile(self) -> None:
        summary = summarize_profile({})
        assert summary.status == "<missing>"
        assert summary.exit_code is None
        assert summary.l1_counts == {}

    def test_to_dict_is_sorted(self) -> None:
        data = summarize_profile(
            _make_profile(l1_counts={"errors": 1, "classes": 2, "functions": 3})
        ).to_dict()
        assert list(data["l1_counts"].keys()) == ["classes", "errors", "functions"]


class TestFormatProfileSummary:
    """Human-readable profile summary output."""

    def test_shows_status_and_phases(self) -> None:
        output = format_profile_summary(
            summarize_profile(_make_profile(l1_counts={"functions": 10}))
        )
        assert "Status: completed" in output
        assert "Phases:" in output
        assert "L1: 1000ms" in output
        assert "L1 counts:" in output
        assert "functions: 10" in output


# ── Gap inspection ──────────────────────────────────────────────────


def _make_profile_with_gaps(
    *,
    l2_gaps: dict[str, object] | None = None,
    l3_finding_gaps: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": 1,
        "status": "completed",
        "exit_code": 0,
    }
    if l2_gaps is not None:
        payload["l2"] = {"gaps": l2_gaps}
    if l3_finding_gaps is not None:
        l3: dict[str, object] = payload.get("l3", {})  # type: ignore[assignment]
        l3["finding_gaps"] = l3_finding_gaps
        payload["l3"] = l3
    return payload


class TestSummarizeGaps:
    """Analysis gap breakdown from profile."""

    def test_empty_profile(self) -> None:
        summary = summarize_gaps({})
        assert summary.total == 0
        assert summary.by_kind == {}
        assert summary.finding_gap_total == 0

    def test_extracts_l2_gap_breakdown(self) -> None:
        gaps = {
            "total": 5,
            "by_kind": {"missing_type_info": 3, "unresolved_call": 2},
            "by_phase": {"ROUTES": 1, "INPUTS": 4},
            "by_provider": {"flask": 5},
            "by_file": {"app.py": 3, "views.py": 2},
            "by_message": {"Cannot resolve type": 3, "Unknown call target": 2},
        }
        summary = summarize_gaps(_make_profile_with_gaps(l2_gaps=gaps))

        assert summary.total == 5
        assert summary.by_kind == {"missing_type_info": 3, "unresolved_call": 2}
        assert summary.by_phase == {"INPUTS": 4, "ROUTES": 1}
        assert summary.by_provider == {"flask": 5}

    def test_extracts_l3_finding_gaps(self) -> None:
        summary = summarize_gaps(
            _make_profile_with_gaps(
                l2_gaps={"total": 0},
                l3_finding_gaps={
                    "total": 3,
                    "by_kind": {"missing_guard": 2, "unresolved_call": 1},
                },
            )
        )
        assert summary.finding_gap_total == 3
        assert summary.finding_gap_by_kind == {"missing_guard": 2, "unresolved_call": 1}

    def test_to_dict_is_sorted(self) -> None:
        gaps = {
            "total": 2,
            "by_kind": {"z_kind": 1, "a_kind": 1},
        }
        data = summarize_gaps(_make_profile_with_gaps(l2_gaps=gaps)).to_dict()
        assert list(data["by_kind"].keys()) == ["a_kind", "z_kind"]


class TestFormatGapSummary:
    """Human-readable gap summary output."""

    def test_shows_totals_and_sections(self) -> None:
        gaps = {
            "total": 3,
            "by_kind": {"missing_type_info": 2, "unresolved_call": 1},
            "by_phase": {"ROUTES": 3},
            "by_provider": {"flask": 3},
        }
        output = format_gap_summary(summarize_gaps(_make_profile_with_gaps(l2_gaps=gaps)))

        assert "Total L2 gaps: 3" in output
        assert "By kind:" in output
        assert "missing_type_info: 2" in output
        assert "By phase:" in output
        assert "By provider:" in output

    def test_shows_finding_gaps(self) -> None:
        output = format_gap_summary(
            summarize_gaps(
                _make_profile_with_gaps(
                    l2_gaps={"total": 0},
                    l3_finding_gaps={"total": 2, "by_kind": {"missing_guard": 2}},
                )
            )
        )
        assert "L3 finding gaps: 2" in output
        assert "missing_guard: 2" in output

    def test_top_limits_messages(self) -> None:
        gaps = {
            "total": 3,
            "by_message": {"msg_a": 2, "msg_b": 1},
        }
        output = format_gap_summary(
            summarize_gaps(_make_profile_with_gaps(l2_gaps=gaps)),
            top=1,
        )
        assert "msg_a: 2" in output
        assert "msg_b" not in output


# ── CLI integration for findings/profile/gaps ───────────────────────


class TestInspectFindingsProfileGapsCLI:
    """CLI commands for findings, profile, and gaps inspection."""

    def test_findings_text_output(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        path = tmp_path / "findings.json"
        path.write_text(
            json.dumps(
                _findings_payload(
                    [
                        _make_finding(rule_id="CONF-001"),
                        _make_finding(rule_id="CONF-002"),
                    ]
                )
            )
            + "\n",
            encoding="utf-8",
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["inspect", "findings", str(path)])

        assert result.exit_code == 0
        assert "Total findings: 2" in result.output
        assert "By rule:" in result.output

    def test_findings_json_output(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        path = tmp_path / "findings.json"
        path.write_text(
            json.dumps(_findings_payload([_make_finding()])) + "\n",
            encoding="utf-8",
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["inspect", "findings", "--json", str(path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total"] == 1
        assert "CONF-001" in data["by_rule"]

    def test_profile_text_output(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        path = tmp_path / "profile.json"
        path.write_text(
            json.dumps(_make_profile(l1_counts={"functions": 42})) + "\n",
            encoding="utf-8",
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["inspect", "profile", str(path)])

        assert result.exit_code == 0
        assert "Status: completed" in result.output
        assert "functions: 42" in result.output

    def test_profile_json_output(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        path = tmp_path / "profile.json"
        path.write_text(
            json.dumps(_make_profile()) + "\n",
            encoding="utf-8",
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["inspect", "profile", "--json", str(path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "completed"

    def test_gaps_text_output(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        path = tmp_path / "profile.json"
        profile = _make_profile_with_gaps(
            l2_gaps={"total": 3, "by_kind": {"missing_type_info": 3}},
        )
        path.write_text(json.dumps(profile) + "\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(cli, ["inspect", "gaps", str(path)])

        assert result.exit_code == 0
        assert "Total L2 gaps: 3" in result.output
        assert "missing_type_info: 3" in result.output

    def test_gaps_json_output(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from flawed._cli.app import cli

        path = tmp_path / "profile.json"
        profile = _make_profile_with_gaps(
            l2_gaps={"total": 2, "by_kind": {"unresolved_call": 2}},
            l3_finding_gaps={"total": 1, "by_kind": {"missing_guard": 1}},
        )
        path.write_text(json.dumps(profile) + "\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(cli, ["inspect", "gaps", "--json", str(path)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total"] == 2
        assert data["finding_gap_total"] == 1
