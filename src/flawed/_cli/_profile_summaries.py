"""Structured summary helpers for scan profiling reports."""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from pathlib import Path

    from flawed._index import CodeIndex
    from flawed._index._type_enrichment import TypeFact
    from flawed._semantic._provider_engine import ProviderEngineResult
    from flawed.core import AnalysisGap
    from flawed.repo import RepoView


_ARTIFACT_TOP_N = 20
_PRUNED_DIR_NAMES = frozenset({".git", ".mypy_cache", ".pytest_cache", "__pycache__"})


class _FileSummary(TypedDict):
    path: str
    bytes: int


@dataclass(frozen=True)
class GapContext:
    """Known phase/provider context for a gap record."""

    gap: AnalysisGap
    phase: str
    provider: str | None = None


def index_counts(index: CodeIndex) -> dict[str, int]:
    """Return stable CodeIndex size counters."""
    return {
        "functions": len(index.functions),
        "classes": len(index.classes),
        "decorators": len(index.decorators),
        "imports": len(index.imports),
        "attributes": len(index.attributes),
        "call_edges": len(index.call_graph.edges),
        "value_flow_edges": len(index.value_flow.edges),
        "symbol_refs": len(index.symbols),
        "errors": len(index.errors),
        "fatal_errors": sum(1 for error in index.errors if error.is_fatal),
        "cfgs": sum(1 for function in index.functions if index.cfg(function.fqn) is not None),
    }


def type_enrichment_summary(index: CodeIndex) -> dict[str, object]:
    """Return concrete type-enrichment coverage counters for a CodeIndex."""
    facts = index.type_enrichment.facts
    errors = index.type_enrichment.errors
    facts_by_tool = Counter(fact.source_tool for fact in facts)
    concrete_by_tool = Counter(fact.source_tool for fact in facts if fact.is_concrete)
    imprecise_by_tool = Counter(fact.source_tool for fact in facts if not fact.is_concrete)
    errors_by_kind = Counter(error.error_kind.value for error in errors)
    errors_by_pass = Counter(error.pass_name for error in errors)

    return {
        "fact_count": len(facts),
        "concrete_fact_count": sum(1 for fact in facts if fact.is_concrete),
        "imprecise_fact_count": sum(1 for fact in facts if not fact.is_concrete),
        "facts_by_tool": counter_dict(facts_by_tool),
        "concrete_facts_by_tool": counter_dict(concrete_by_tool),
        "imprecise_facts_by_tool": counter_dict(imprecise_by_tool),
        "error_count": len(errors),
        "errors_by_kind": counter_dict(errors_by_kind),
        "errors_by_pass": counter_dict(errors_by_pass),
        "concrete_disagreement_count": _concrete_disagreement_count(facts),
    }


def artifact_summary(root: Path, *, top_n: int = _ARTIFACT_TOP_N) -> dict[str, object]:
    """Return bounded aggregate byte counts below an artifact root."""
    if not root.exists():
        return {
            "root": str(root),
            "exists": False,
            "total_bytes": 0,
            "file_count": 0,
            "by_extension": {},
            "by_category": {},
            "largest_files": [],
        }

    total = 0
    file_count = 0
    extension_counts: Counter[str] = Counter()
    extension_bytes: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    category_bytes: Counter[str] = Counter()
    largest_files: list[_FileSummary] = []

    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in _PRUNED_DIR_NAMES]
        current_path = (
            root if current_root == str(root) else root / os.path.relpath(current_root, root)
        )
        for filename in filenames:
            path = current_path / filename
            if not path.is_file():
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            relative = path.relative_to(root)
            relative_path = str(relative)
            extension = path.suffix.lower() or "<none>"
            category = _artifact_category(relative)

            total += size
            file_count += 1
            extension_counts[extension] += 1
            extension_bytes[extension] += size
            category_counts[category] += 1
            category_bytes[category] += size
            file_summary: _FileSummary = {"path": relative_path, "bytes": size}
            _record_largest_file(largest_files, file_summary, top_n=top_n)

    return {
        "root": str(root),
        "exists": True,
        "total_bytes": total,
        "file_count": file_count,
        "by_extension": _size_bucket_dict(extension_counts, extension_bytes),
        "by_category": _size_bucket_dict(category_counts, category_bytes),
        "largest_files": largest_files,
    }


def _artifact_category(relative_path: Path) -> str:
    parts = relative_path.parts
    if len(parts) <= 1:
        return "(root)"
    return parts[0]


def _record_largest_file(
    largest_files: list[_FileSummary],
    file_summary: _FileSummary,
    *,
    top_n: int,
) -> None:
    if top_n <= 0:
        return
    largest_files.append(file_summary)
    largest_files.sort(key=lambda item: (-item["bytes"], item["path"]))
    del largest_files[top_n:]


def _size_bucket_dict(
    counts: Counter[str],
    bytes_by_key: Counter[str],
) -> dict[str, dict[str, int]]:
    """Return deterministic count/byte buckets."""
    return {key: {"count": counts[key], "bytes": bytes_by_key[key]} for key in sorted(counts)}


def provider_summary(result: ProviderEngineResult) -> dict[str, object]:
    """Summarize provider activation, matching, and engine gaps."""
    by_provider = Counter(match.provider_id for match in result.matches)
    by_phase = Counter(match.phase.value for match in result.matches)
    by_provider_phase: dict[str, Counter[str]] = {}
    for match in result.matches:
        by_provider_phase.setdefault(match.provider_id, Counter())[match.phase.value] += 1

    return {
        "provider_engine": {
            "active_providers": list(result.active_provider_ids),
            "match_count": len(result.matches),
            "matches_by_provider": counter_dict(by_provider),
            "matches_by_phase": counter_dict(by_phase),
            "matches_by_provider_phase": nested_counter_dict(by_provider_phase),
            "router_group_count": len(result.router_group_info),
            "engine_gap_count": len(result.gaps),
            "engine_gaps": gap_summary(result.gaps, contexts=provider_gap_contexts(result)),
        }
    }


def provider_gap_contexts(result: ProviderEngineResult) -> tuple[GapContext, ...]:
    """Return provider/phase contexts for predicate gaps."""
    contexts: list[GapContext] = []
    for match in result.matches:
        contexts.extend(
            GapContext(gap=gap, phase=match.phase.value, provider=match.provider_id)
            for gap in match.predicate_gaps
        )
    return tuple(contexts)


def collect_repo_gaps(repo_view: RepoView) -> tuple[AnalysisGap, ...]:
    """Collect repository, route, function, and class gaps for reporting."""
    gaps = [*repo_view.gaps]
    for route in repo_view.routes:
        gaps.extend(route.gaps)
    for function in repo_view.functions:
        gaps.extend(function.gaps)
    for klass in repo_view.classes:
        gaps.extend(klass.gaps)
    return tuple(gaps)


def gap_summary(
    gaps: Iterable[AnalysisGap],
    *,
    contexts: Iterable[GapContext] = (),
) -> dict[str, object]:
    """Summarize gaps by kind, cause, location, and any known context.

    Phase and provider counts prefer native ``origin_phase``/``origin_provider``
    fields on each gap.  When those are ``None``, the function falls back to
    external ``GapContext`` records (used by the provider engine for
    predicate-level gaps).
    """
    gap_tuple = tuple(gaps)
    by_kind = Counter(gap.kind.value for gap in gap_tuple)
    by_message = Counter(gap.message for gap in gap_tuple)
    by_source_error = Counter(gap.source_error or "(none)" for gap in gap_tuple)
    by_file = Counter(gap.affected_file or "(global)" for gap in gap_tuple)
    by_function = Counter(gap.affected_function or "(global)" for gap in gap_tuple)

    # Phase/provider from native fields first.
    by_phase: Counter[str] = Counter()
    by_provider: Counter[str] = Counter()
    native_count = 0
    remaining = Counter(_gap_identity(gap) for gap in gap_tuple)
    for gap in gap_tuple:
        if gap.origin_phase is not None:
            by_phase[gap.origin_phase] += 1
            native_count += 1
            remaining[_gap_identity(gap)] -= 1
        if gap.origin_provider is not None:
            by_provider[gap.origin_provider] += 1

    # Fall back to external GapContext for gaps without native origin.
    context_count = 0
    for context in contexts:
        key = _gap_identity(context.gap)
        if remaining[key] <= 0:
            continue
        remaining[key] -= 1
        context_count += 1
        by_phase[context.phase] += 1
        if context.provider is not None:
            by_provider[context.provider] += 1

    return {
        "total": len(gap_tuple),
        "by_kind": counter_dict(by_kind),
        "by_message": counter_dict(by_message),
        "by_source_error": counter_dict(by_source_error),
        "by_file": counter_dict(by_file),
        "by_function": counter_dict(by_function),
        "known_context_count": native_count + context_count,
        "unknown_context_count": sum(remaining.values()),
        "by_phase": counter_dict(by_phase),
        "by_provider": counter_dict(by_provider),
    }


def counter_dict(counter: Counter[str]) -> dict[str, int]:
    """Return a deterministic plain dict from a counter."""
    return {key: counter[key] for key in sorted(counter)}


def nested_counter_dict(counters: Mapping[str, Counter[str]]) -> dict[str, dict[str, int]]:
    """Return deterministic nested counter dictionaries."""
    return {key: counter_dict(counters[key]) for key in sorted(counters)}


def _concrete_disagreement_count(facts: Iterable[TypeFact]) -> int:
    by_expression: dict[tuple[str, str, int, int, str | None], list[str]] = {}
    for fact in facts:
        if not fact.is_concrete:
            continue
        location = fact.location
        key = (
            fact.expression,
            location.file,
            location.line,
            location.column,
            fact.containing_function_fqn,
        )
        by_expression.setdefault(key, []).append(fact.declared_type)
    return sum(1 for declared_types in by_expression.values() if _types_disagree(declared_types))


def _types_disagree(declared_types: Iterable[str]) -> bool:
    representatives: list[str] = []
    for declared_type in declared_types:
        if not any(_type_strings_agree(declared_type, seen) for seen in representatives):
            representatives.append(declared_type)
    return len(representatives) > 1


def _type_strings_agree(left: str, right: str) -> bool:
    return left == right or left.endswith(f".{right}") or right.endswith(f".{left}")


def _gap_identity(gap: AnalysisGap) -> tuple[str, str, str | None, str | None, str | None]:
    return (
        gap.kind.value,
        gap.message,
        gap.affected_file,
        gap.affected_function,
        gap.source_error,
    )
