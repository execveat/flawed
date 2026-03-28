"""Evidence building types for detection findings.

A :class:`Finding` is the output of a detection rule.  Detectors
build findings using the immutable builder pattern: each call to
:meth:`Finding.evidence` returns a **new** ``Finding`` with the
additional evidence appended.

Detectors yield findings directly as generators::

    yield (
        route.finding("Path ID guards write, body ID flows to target")
        .evidence(path_read, "Authorization uses path parameter")
        .evidence(body_read, "Write target from body parameter")
        .evidence(guard, "Guard condition uses path value")
        .evidence(effect, "Data write")
    )

Each :class:`Evidence` item records a domain object (the *fact*) and
a human-readable description of its role in the finding.  The
:data:`EvidenceFact` union type specifies which domain objects can
serve as evidence: input reads, effects, conditions, call sites,
decorators, taint sinks, and type-disagreement signals.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from flawed.calls import Argument, CallSite
    from flawed.class_ import Class
    from flawed.conditions import Condition, ExceptionGuard, Predicate, SwallowedRejection
    from flawed.core import AnalysisGap, Location
    from flawed.disagreement import TypeDisagreement
    from flawed.effects import Effect
    from flawed.function import Decorator, Function
    from flawed.inputs import InputRead
    from flawed.severity import Severity
    from flawed.sinks import TaintSink

# Union of domain objects that can serve as evidence
EvidenceFact = Union[
    "InputRead",
    "Effect",
    "Condition",
    "Predicate",
    "CallSite",
    "Argument",
    "Decorator",
    "Function",
    "Class",
    "ExceptionGuard",
    "SwallowedRejection",
    "TaintSink",
    "TypeDisagreement",
]
"""Domain objects that can serve as evidence in a finding.

Any object with a ``location`` attribute from the core domain model
is eligible (e.g. a :class:`~flawed.function.Function` anchors a finding
at a writer/handler definition).
"""


@dataclass(frozen=True)
class Evidence:
    """A single piece of evidence supporting a finding.

    Pairs a domain object (the *fact*) with a description of why
    it is relevant to the finding.  The ``location`` is extracted
    automatically from the fact.
    """

    fact: EvidenceFact
    """The domain object serving as evidence (InputRead, Effect, etc.)."""

    description: str
    """Human-readable description of this evidence's role in the finding."""

    location: Location
    """Source location of the evidence fact."""


@dataclass(frozen=True, repr=False)
class Finding:
    """A detection finding with an evidence chain.

    Findings use the immutable builder pattern: each call to
    :meth:`evidence` returns a **new** ``Finding`` with the additional
    evidence appended.  The original finding is never modified.

    Created via :meth:`Route.finding() <flawed.route.Route.finding>`,
    not directly by rule authors::

        finding = route.finding("Missing auth guard")
        finding = finding.evidence(read, "Unguarded user input")
        finding = finding.evidence(effect, "Database write")
        yield finding

    Or chained in a single expression::

        yield (
            route.finding("Missing auth guard")
            .evidence(read, "Unguarded user input")
            .evidence(effect, "Database write")
        )
    """

    route_endpoint: str
    """Endpoint name of the route this finding applies to."""

    summary: str
    """One-line summary of the detection finding."""

    evidence_items: tuple[Evidence, ...] = ()
    """Accumulated evidence chain (in order of attachment)."""

    location: Location | None = None
    """Source location of the route registration, if available."""

    gaps: tuple[AnalysisGap, ...] = ()
    """Analysis gaps that may affect the completeness of this finding.

    Auto-populated from the route's gaps when the finding is created
    via :meth:`Route.finding() <flawed.route.Route.finding>`.  Additional
    gaps from evidence facts are merged during :meth:`evidence` calls.
    Rule authors never need to set this manually.
    """

    severity: Severity | None = None
    """Resolved severity of this finding.

    Left ``None`` at construction and stamped with the producing rule's
    declared default by the :func:`~flawed.detector.detector` decorator.
    A rule may set it explicitly via :meth:`with_severity` to escalate or
    de-escalate a specific finding; the decorator then leaves it untouched.
    """

    def evidence(self, fact: EvidenceFact, description: str) -> Finding:
        """Return a new Finding with one more evidence item.

        Args:
            fact: A domain object (InputRead, Effect, Condition, etc.).
            description: Why this fact is relevant to the finding.

        Returns:
            A new ``Finding`` with the evidence appended.
        """
        new_item = Evidence(
            fact=fact,
            description=description,
            location=_extract_location(fact),
        )
        return replace(self, evidence_items=(*self.evidence_items, new_item))

    @property
    def fingerprint(self) -> str:
        """Stable content-based fingerprint for deduplication and suppression.

        The fingerprint is a SHA-256 prefix derived from the route endpoint,
        summary text, and evidence locations.  It is stable across re-scans
        of the same code: two findings with the same fingerprint describe the
        same issue.
        """
        hasher = hashlib.sha256()
        hasher.update(self.route_endpoint.encode())
        hasher.update(b"\x00")
        hasher.update(self.summary.encode())
        for item in self.evidence_items:
            loc = item.location
            hasher.update(f"\x00{loc.file}:{loc.line}".encode())
        return hasher.hexdigest()[:16]

    def with_severity(self, severity: Severity) -> Finding:
        """Return a new Finding with an explicit severity override.

        Use this when a rule wants to escalate or de-escalate a *specific*
        finding away from its declared default (e.g. raise to CRITICAL when
        evidence shows the issue is directly reachable).  The
        :func:`~flawed.detector.detector` decorator will not overwrite a
        severity set this way.
        """
        return replace(self, severity=severity)

    def __repr__(self) -> str:
        """Concise one-line repr.

        The default dataclass repr recurses through the full evidence chain
        (nested enriched functions, locations) and balloons to tens of KB,
        making findings unusable at an interactive REPL.  This keeps the
        identity legible; use :meth:`detail` for the full dump.
        """
        sev = self.severity.label if self.severity is not None else "unset"
        loc = f"{self.location.file}:{self.location.line}" if self.location else "?"
        return f"Finding({self.route_endpoint!r} {sev} {loc} +{len(self.evidence_items)}ev)"

    def detail(self) -> str:
        """Multi-line human dump: summary, severity, evidence chain, gaps."""
        sev = self.severity.label if self.severity is not None else "unset"
        lines = [
            repr(self),
            f"  severity: {sev}",
            f"  summary:  {self.summary}",
        ]
        for i, item in enumerate(self.evidence_items, start=1):
            loc = item.location
            lines.append(f"  [{i}] {item.description} @ {loc.file}:{loc.line}")
        if self.gaps:
            lines.append(f"  gaps: {len(self.gaps)}")
        return "\n".join(lines)


def _extract_location(fact: EvidenceFact) -> Location:
    """Pull the ``location`` attribute that every evidence-eligible type carries."""
    return fact.location
