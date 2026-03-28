"""First-class severity ladder for detection findings.

A Layer 3 domain type. A finding's severity is *declared by its rule* via
the :func:`~flawed.detector.detector` decorator
(``@detector("id", severity=Severity.HIGH)``) and may be escalated or
de-escalated per finding from evidence (:meth:`Finding.with_severity`).

The ordered ladder is the spine that finding color, sort order, the
``--fail-on`` gate, and SARIF ``level`` all key off. Ordering is encoded in
the member values so a descending sort surfaces the worst findings first.
"""

from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    """Ordered severity ladder: CRITICAL > HIGH > MEDIUM > LOW > INFO.

    Members compare by gravity, so ``Severity.HIGH > Severity.LOW`` and
    ``sorted(findings, key=lambda f: f.severity, reverse=True)`` lists the
    most severe first. Values are spaced to leave room for future levels.
    """

    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @property
    def label(self) -> str:
        """Lowercase display label, e.g. ``"high"``."""
        return self.name.lower()

    @property
    def sarif_level(self) -> str:
        """SARIF 2.1.0 ``level`` for this severity.

        Maps the five-level ladder onto SARIF's three result levels:
        CRITICAL/HIGH -> ``error``, MEDIUM -> ``warning``, LOW/INFO -> ``note``.
        """
        if self >= Severity.HIGH:
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        return "note"

    @property
    def style(self) -> str:
        """Rich style hint for rendering this severity (callers may override)."""
        return _STYLES[self]

    @property
    def glyph(self) -> str:
        """Single-character marker for compact, color-degraded output."""
        return _GLYPHS[self]

    @classmethod
    def parse(cls, value: str) -> Severity:
        """Parse a case-insensitive severity name (e.g. for ``--fail-on``).

        Raises:
            ValueError: if ``value`` is not a known severity name.
        """
        try:
            return cls[value.strip().upper()]
        except KeyError:
            valid = ", ".join(s.label for s in cls.ordered())
            raise ValueError(f"unknown severity {value!r}; expected one of: {valid}") from None

    @classmethod
    def ordered(cls) -> tuple[Severity, ...]:
        """Return the severities from most to least severe."""
        return tuple(sorted(cls, reverse=True))


_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_GLYPHS: dict[Severity, str] = {
    Severity.CRITICAL: "●",  # ●
    Severity.HIGH: "●",  # ●
    Severity.MEDIUM: "◐",  # ◐
    Severity.LOW: "○",  # ○
    Severity.INFO: "·",  # ·
}

DEFAULT_SEVERITY: Severity = Severity.MEDIUM
"""Severity assigned to a finding whose rule does not declare one explicitly."""
