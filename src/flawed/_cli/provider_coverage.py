"""Provider coverage reporting for the development CLI."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from flawed._semantic._provider_engine import _PHASE_DESCRIPTOR_ATTRS as PHASE_DESCRIPTOR_ATTRS
from flawed._semantic._provider_engine import ProviderEngineResult, ProviderPhase

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from flawed._index import CodeIndex
    from flawed._index._types import ImportFact, SourceSpan
    from flawed._semantic._provider_engine import ProviderDescriptor, ProviderMatch
    from flawed._semantic.providers import Provider
    from flawed.core import AnalysisGap


@dataclass(frozen=True)
class ProviderPhaseCoverage:
    """Coverage for one provider declaration phase."""

    phase: str
    declared: int
    matched_declarations: int
    matches: int
    unmatched: tuple[str, ...]
    gaps: tuple[str, ...]
    evidence: tuple[str, ...]

    @property
    def unmatched_count(self) -> int:
        return len(self.unmatched)

    def to_dict(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "declared": self.declared,
            "matched_declarations": self.matched_declarations,
            "matches": self.matches,
            "unmatched_count": self.unmatched_count,
            "unmatched": list(self.unmatched),
            "gap_count": len(self.gaps),
            "gaps": list(self.gaps),
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class ProviderCoverage:
    """Coverage dashboard row for one provider."""

    provider_id: str
    name: str
    library: str
    active: bool
    activation_evidence: tuple[str, ...]
    phases: tuple[ProviderPhaseCoverage, ...]
    gaps: tuple[str, ...]

    @property
    def declared_count(self) -> int:
        return sum(phase.declared for phase in self.phases)

    @property
    def matched_declaration_count(self) -> int:
        return sum(phase.matched_declarations for phase in self.phases)

    @property
    def match_count(self) -> int:
        return sum(phase.matches for phase in self.phases)

    @property
    def unmatched_count(self) -> int:
        return sum(phase.unmatched_count for phase in self.phases)

    def to_dict(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "name": self.name,
            "library": self.library,
            "active": self.active,
            "activation_evidence": list(self.activation_evidence),
            "declared_count": self.declared_count,
            "matched_declaration_count": self.matched_declaration_count,
            "match_count": self.match_count,
            "unmatched_count": self.unmatched_count,
            "gap_count": len(self.gaps),
            "gaps": list(self.gaps),
            "phases": [phase.to_dict() for phase in self.phases],
        }


@dataclass(frozen=True)
class ProviderCoverageReport:
    """Provider coverage dashboard payload."""

    providers: tuple[ProviderCoverage, ...]
    inactive_hidden: int = 0

    @property
    def active_provider_ids(self) -> tuple[str, ...]:
        return tuple(provider.provider_id for provider in self.providers if provider.active)

    def to_dict(self) -> dict[str, object]:
        return {
            "active_provider_ids": list(self.active_provider_ids),
            "inactive_hidden": self.inactive_hidden,
            "providers": [provider.to_dict() for provider in self.providers],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


def build_provider_coverage_report(
    *,
    index: CodeIndex,
    result: ProviderEngineResult,
    provider_classes: Sequence[type[Provider]],
    include_inactive: bool = False,
    evidence_limit: int = 5,
) -> ProviderCoverageReport:
    """Build provider activation, declaration, match, and gap coverage."""
    active_ids = set(result.active_provider_ids)
    matches_by_provider_phase: dict[tuple[str, ProviderPhase], list[ProviderMatch]] = defaultdict(
        list
    )
    for match in result.matches:
        matches_by_provider_phase[(match.provider_id, match.phase)].append(match)

    gaps_by_provider = _gaps_by_provider(result)
    visible_provider_classes = tuple(
        provider_cls
        for provider_cls in provider_classes
        if include_inactive or provider_cls.meta.id in active_ids
    )
    inactive_hidden = len(provider_classes) - len(visible_provider_classes)

    providers = tuple(
        _provider_coverage(
            provider_cls=provider_cls,
            index=index,
            active=provider_cls.meta.id in active_ids,
            matches_by_provider_phase=matches_by_provider_phase,
            gaps=tuple(gaps_by_provider.get(provider_cls.meta.id, ())),
            evidence_limit=evidence_limit,
        )
        for provider_cls in visible_provider_classes
    )
    return ProviderCoverageReport(providers=providers, inactive_hidden=inactive_hidden)


def format_provider_coverage_report(report: ProviderCoverageReport) -> str:
    """Render a text dashboard for humans."""
    lines: list[str] = ["Provider coverage dashboard", ""]
    active = ", ".join(report.active_provider_ids) if report.active_provider_ids else "(none)"
    lines.append(f"Activated providers: {active}")
    if report.inactive_hidden:
        lines.append(f"Inactive providers hidden: {report.inactive_hidden}")
    lines.append("")

    if not report.providers:
        lines.append("No provider coverage to show.")
        return "\n".join(lines) + "\n"

    for provider in report.providers:
        status = "active" if provider.active else "inactive"
        lines.append(f"{provider.provider_id} ({provider.name}) — {status}")
        lines.append(
            "  totals: "
            f"{provider.matched_declaration_count}/{provider.declared_count} "
            "declarations matched, "
            f"{provider.match_count} match(es), "
            f"{provider.unmatched_count} unmatched declaration(s), "
            f"{len(provider.gaps)} gap(s)"
        )
        lines.append("  activation evidence:")
        if provider.activation_evidence:
            lines.extend(f"    - {item}" for item in provider.activation_evidence)
        else:
            lines.append("    - none observed")
        lines.append("  phases:")
        for phase in provider.phases:
            lines.append(
                "    - "
                f"{phase.phase}: {phase.matched_declarations}/{phase.declared} declarations, "
                f"{phase.matches} match(es), {phase.unmatched_count} unmatched, "
                f"{len(phase.gaps)} gap(s)"
            )
            if phase.evidence:
                lines.append("      matched evidence:")
                lines.extend(f"        - {item}" for item in phase.evidence)
            if phase.unmatched:
                lines.append("      unmatched declarations:")
                lines.extend(f"        - {item}" for item in phase.unmatched)
            if phase.gaps:
                lines.append("      gaps:")
                lines.extend(f"        - {item}" for item in phase.gaps)
        if provider.gaps and not any(phase.gaps for phase in provider.phases):
            lines.append("  gaps:")
            lines.extend(f"    - {item}" for item in provider.gaps)
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _provider_coverage(
    *,
    provider_cls: type[Provider],
    index: CodeIndex,
    active: bool,
    matches_by_provider_phase: Mapping[tuple[str, ProviderPhase], Sequence[ProviderMatch]],
    gaps: tuple[AnalysisGap, ...],
    evidence_limit: int,
) -> ProviderCoverage:
    provider_id = provider_cls.meta.id
    phases = tuple(
        _phase_coverage(
            provider_cls=provider_cls,
            phase=phase,
            matches=tuple(matches_by_provider_phase.get((provider_id, phase), ())),
            gaps=tuple(gap for gap in gaps if _gap_phase(gap) == phase.value),
            evidence_limit=evidence_limit,
        )
        for phase in ProviderPhase
        if _phase_has_coverage(
            provider_cls=provider_cls,
            phase=phase,
            matches_by_provider_phase=matches_by_provider_phase,
            provider_id=provider_id,
            gaps=gaps,
        )
    )
    return ProviderCoverage(
        provider_id=provider_id,
        name=provider_cls.meta.name,
        library=provider_cls.meta.library,
        active=active,
        activation_evidence=_activation_evidence(provider_cls, index, evidence_limit),
        phases=phases,
        gaps=tuple(_format_gap(gap) for gap in gaps),
    )


def _phase_has_coverage(
    *,
    provider_cls: type[Provider],
    phase: ProviderPhase,
    matches_by_provider_phase: Mapping[tuple[str, ProviderPhase], Sequence[ProviderMatch]],
    provider_id: str,
    gaps: tuple[AnalysisGap, ...],
) -> bool:
    declarations = getattr(provider_cls, PHASE_DESCRIPTOR_ATTRS[phase])
    return bool(
        declarations
        or matches_by_provider_phase.get((provider_id, phase))
        or any(_gap_phase(gap) == phase.value for gap in gaps)
    )


def _phase_coverage(
    *,
    provider_cls: type[Provider],
    phase: ProviderPhase,
    matches: tuple[ProviderMatch, ...],
    gaps: tuple[AnalysisGap, ...],
    evidence_limit: int,
) -> ProviderPhaseCoverage:
    declarations = tuple(getattr(provider_cls, PHASE_DESCRIPTOR_ATTRS[phase]))
    matched_declarations = tuple(
        descriptor for descriptor in declarations if _descriptor_matched(descriptor, matches)
    )
    unmatched = tuple(
        _descriptor_label(descriptor)
        for descriptor in declarations
        if not _descriptor_matched(descriptor, matches)
    )
    return ProviderPhaseCoverage(
        phase=phase.value,
        declared=len(declarations),
        matched_declarations=len(matched_declarations),
        matches=len(matches),
        unmatched=unmatched,
        gaps=tuple(_format_gap(gap) for gap in gaps),
        evidence=tuple(_match_evidence(match) for match in matches[:evidence_limit]),
    )


def _descriptor_matched(descriptor: ProviderDescriptor, matches: Iterable[ProviderMatch]) -> bool:
    return any(match.descriptor == descriptor for match in matches)


def _activation_evidence(
    provider_cls: type[Provider],
    index: CodeIndex,
    evidence_limit: int,
) -> tuple[str, ...]:
    library_fqn = provider_cls.meta.library_fqn
    if library_fqn == "builtins":
        return ("builtins are always available",)
    prefixes = _activation_prefixes(provider_cls)
    evidence: list[str] = []
    for import_fact in index.imports:
        if any(_module_matches_prefix(import_fact.module, prefix) for prefix in prefixes):
            evidence.append(_format_import(import_fact))
            if len(evidence) >= evidence_limit:
                break
    return tuple(evidence)


def _activation_prefixes(provider_cls: type[Provider]) -> tuple[str, ...]:
    library_fqn = provider_cls.meta.library_fqn
    if not library_fqn:
        return ()
    prefixes = [library_fqn]
    aliases: dict[str, str] = getattr(provider_cls, "fqn_aliases", {})
    for alias_from, alias_to in aliases.items():
        if alias_to == library_fqn or alias_to.startswith(f"{library_fqn}."):
            prefixes.append(alias_from)
    return tuple(dict.fromkeys(prefixes))


def _module_matches_prefix(module: str, prefix: str) -> bool:
    return module == prefix or module.startswith(f"{prefix}.")


def _gaps_by_provider(result: ProviderEngineResult) -> dict[str, list[AnalysisGap]]:
    gaps_by_provider: dict[str, list[AnalysisGap]] = defaultdict(list)
    seen: set[int] = set()
    for gap in result.gaps:
        if gap.origin_provider is not None:
            gaps_by_provider[gap.origin_provider].append(gap)
            seen.add(id(gap))
    for match in result.matches:
        for gap in match.predicate_gaps:
            if id(gap) not in seen:
                gaps_by_provider[match.provider_id].append(gap)
                seen.add(id(gap))
    return gaps_by_provider


def _format_import(import_fact: ImportFact) -> str:
    if import_fact.is_from_import and import_fact.names:
        imported = f"from {import_fact.module} import {', '.join(import_fact.names)}"
    else:
        imported = f"import {import_fact.module}"
    return f"{_span(import_fact.location)} {imported}"


def _match_evidence(match: ProviderMatch) -> str:
    observed = match.observed_fqn
    if match.canonical_fqn != match.observed_fqn:
        observed = f"{match.observed_fqn} -> {match.canonical_fqn}"
    return f"{_span(match.location)} {observed}"


def _format_gap(gap: AnalysisGap) -> str:
    location = gap.affected_file or "global"
    phase = _gap_phase(gap) or "unknown"
    return f"{phase} {location}: {gap.message}"


def _gap_phase(gap: AnalysisGap) -> str | None:
    return gap.origin_phase or gap.source_error


def _span(location: SourceSpan) -> str:
    return f"{location.file}:{location.line}"


def _descriptor_label(descriptor: ProviderDescriptor) -> str:
    descriptor_type = type(descriptor).__name__
    label = _descriptor_target(descriptor)
    if label:
        return f"{descriptor_type} {label}"
    return descriptor_type


def _descriptor_target(descriptor: ProviderDescriptor) -> str:
    for attr in (
        "fqn",
        "registration_fqn",
        "inject_fqn",
        "source_fqn",
        "entry_fqn",
        "base_class_fqn",
        "default_type_fqn",
        "receiver_fqn",
        "view_base_fqn",
    ):
        value = getattr(descriptor, attr, None)
        if value:
            target = _format_value(value)
            attribute = getattr(descriptor, "attribute", None)
            if attr == "receiver_fqn" and attribute:
                return f"{target}.{attribute}"
            return target
    names = getattr(descriptor, "names", ())
    if names:
        return ", ".join(names)
    return ""


def _format_value(value: object) -> str:
    if isinstance(value, tuple):
        return ", ".join(str(item) for item in value)
    return str(value)
