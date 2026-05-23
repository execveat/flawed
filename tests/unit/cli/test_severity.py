"""Tests for the first-class severity ladder (FLAW-140).

Covers the ordered :class:`~flawed.severity.Severity` enum, the
``@detector`` severity/description metadata, the decorator stamping every
yielded finding, the per-finding override, the concise ``Finding`` repr,
and the CLI severity-derivation reading the real severity.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest

from flawed._cli.output import _finding_severity
from flawed.detector import detector
from flawed.evidence import Finding
from flawed.severity import DEFAULT_SEVERITY, Severity

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flawed.detector import Detector


def _meta(fn: object) -> Detector:
    """View a @detector-stamped function through its public ``Detector`` protocol.

    ``Detector`` (``flawed.detector``) is the single source of truth for the
    three ``__detector_*`` attributes the decorator stamps; the tests read them
    type-checked through it rather than re-declaring a private duplicate.
    """
    return cast("Detector", fn)


class TestSeverityLadder:
    def test_ordering_is_critical_to_info(self) -> None:
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO

    def test_ordered_lists_worst_first(self) -> None:
        assert Severity.ordered() == (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        )

    def test_descending_sort_surfaces_worst_first(self) -> None:
        mixed = [Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]
        assert sorted(mixed, reverse=True)[0] is Severity.CRITICAL

    def test_label_is_lowercase_name(self) -> None:
        assert Severity.HIGH.label == "high"

    @pytest.mark.parametrize(
        ("severity", "level"),
        [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
            (Severity.INFO, "note"),
        ],
    )
    def test_sarif_level_mapping(self, severity: Severity, level: str) -> None:
        assert severity.sarif_level == level

    def test_every_member_has_style_and_glyph(self) -> None:
        for member in Severity:
            assert member.style
            assert member.glyph

    def test_parse_is_case_insensitive(self) -> None:
        assert Severity.parse("HIGH") is Severity.HIGH
        assert Severity.parse(" critical ") is Severity.CRITICAL

    def test_parse_unknown_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="unknown severity"):
            Severity.parse("catastrophic")


class TestDetectorMetadata:
    def test_stores_name_severity_and_description(self) -> None:
        @detector("my-rule", severity=Severity.HIGH, description="What it finds")
        def rule(repo: object) -> Iterator[Finding]:
            yield from ()

        assert _meta(rule).__detector_name__ == "my-rule"
        assert _meta(rule).__detector_severity__ is Severity.HIGH
        assert _meta(rule).__detector_description__ == "What it finds"

    def test_default_severity_is_the_module_default(self) -> None:
        @detector("plain")
        def rule(repo: object) -> Iterator[Finding]:
            yield from ()

        assert _meta(rule).__detector_severity__ is DEFAULT_SEVERITY

    def test_description_falls_back_to_docstring_first_line(self) -> None:
        @detector("documented")
        def rule(repo: object) -> Iterator[Finding]:
            """Detect the thing.

            Longer explanation that should not be used.
            """
            yield from ()

        assert _meta(rule).__detector_description__ == "Detect the thing."

    def test_description_is_none_without_docstring_or_arg(self) -> None:
        @detector("bare")
        def rule(repo: object) -> Iterator[Finding]:
            yield from ()

        assert _meta(rule).__detector_description__ is None


class TestDecoratorStamping:
    def test_yielded_findings_get_declared_severity(self) -> None:
        @detector("stamps", severity=Severity.CRITICAL)
        def rule(repo: object) -> Iterator[Finding]:
            yield Finding(route_endpoint="app.index", summary="boom")

        findings = list(rule(None))
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL

    def test_per_finding_override_is_not_overwritten(self) -> None:
        @detector("respects-override", severity=Severity.LOW)
        def rule(repo: object) -> Iterator[Finding]:
            yield Finding(route_endpoint="app.index", summary="boom").with_severity(
                Severity.CRITICAL
            )

        assert next(iter(rule(None))).severity is Severity.CRITICAL

    def test_with_severity_returns_new_finding(self) -> None:
        base = Finding(route_endpoint="e", summary="s")
        escalated = base.with_severity(Severity.HIGH)
        assert base.severity is None
        assert escalated.severity is Severity.HIGH
        assert escalated is not base


class TestFindingRepr:
    def test_repr_is_concise(self) -> None:
        finding = Finding(route_endpoint="app.index", summary="x" * 5000).with_severity(
            Severity.HIGH
        )
        text = repr(finding)
        assert len(text) < 200
        assert "app.index" in text
        assert "high" in text

    def test_detail_is_multiline_and_includes_summary(self) -> None:
        finding = Finding(route_endpoint="app.index", summary="the summary")
        detail = finding.detail()
        assert "the summary" in detail
        assert "\n" in detail


class TestOutputReadsRealSeverity:
    def test_finding_severity_uses_declared_severity_not_prefix(self) -> None:
        # Summary prefix would have derived "unknown" under the old heuristic.
        finding = Finding(route_endpoint="e", summary="no prefix here").with_severity(
            Severity.HIGH
        )
        assert _finding_severity(finding) == "high"

    def test_finding_severity_falls_back_to_default_when_unset(self) -> None:
        finding = Finding(route_endpoint="e", summary="s")
        assert _finding_severity(finding) == DEFAULT_SEVERITY.label
