"""Detector registration decorator.

The ``@detector`` decorator marks a function as a detection rule.
Detection rules are Python generator functions that receive a
:class:`~flawed.repo.RepoView` and yield
:class:`~flawed.evidence.Finding` objects.

A rule declares its default :class:`~flawed.severity.Severity` and a
one-line ``description`` on the decorator.  These are the single
structured source of truth: the severity is stamped onto every finding
the rule yields (unless the finding overrode it via
:meth:`~flawed.evidence.Finding.with_severity`), and the description
feeds ``flawed rules`` and ``flawed explain``.

Example::

    from collections.abc import Iterator

    from flawed import detector
    from flawed.evidence import Finding
    from flawed.repo import RepoView
    from flawed.severity import Severity


    @detector("my-rule-id", severity=Severity.HIGH, description="What it finds")
    def detect(kb: RepoView) -> Iterator[Finding]:
        for route in kb.routes:
            yield route.finding("Example finding")
"""

from __future__ import annotations

import functools
from dataclasses import replace
from typing import TYPE_CHECKING, Protocol, cast

from flawed.severity import DEFAULT_SEVERITY, Severity

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator

    from flawed.evidence import Finding


class Detector(Protocol):
    """A ``@detector``-decorated rule, viewed through its public type surface.

    The decorator returns the wrapped generator with three registration
    attributes stamped on it. Declaring them here types those attributes for
    every caller (the detection engine, ``flawed rules`` / ``flawed explain``,
    and rule tests) instead of forcing ``getattr`` or ``# type: ignore`` at
    each read site, and gives rule authors a single named type for a detector.
    """

    #: Unique rule identifier, the first positional arg to ``@detector``.
    __detector_name__: str
    #: Default severity stamped onto every finding the rule yields (unless the
    #: finding overrode it).
    __detector_severity__: Severity
    #: One-line description: the decorator's ``description`` arg, else the first
    #: non-blank docstring line, else ``None``.
    __detector_description__: str | None

    def __call__(self, repo: object) -> Iterator[Finding]: ...


def detector(
    name: str,
    *,
    severity: Severity = DEFAULT_SEVERITY,
    description: str | None = None,
) -> Callable[[Callable[..., object]], Detector]:
    """Decorator that registers a function as a detection rule.

    Stores rule metadata on the function for runtime discovery by the
    detection engine and wraps it so every yielded finding carries the
    declared severity.

    Args:
        name: Unique identifier for this detection rule
              (e.g. ``"path-guard-body-write"``).
        severity: Default severity for findings this rule produces.
              A finding may override it via
              :meth:`~flawed.evidence.Finding.with_severity`.
              Defaults to :data:`~flawed.severity.DEFAULT_SEVERITY`.
        description: One-line human description. Falls back to the first
              non-blank line of the function docstring when omitted.

    Example::

        @detector("missing-auth-on-write", severity=Severity.HIGH)
        def detect(kb: "RepoView") -> Iterator[Finding]: ...
    """

    def wrapper(fn: Callable[..., object]) -> Detector:
        resolved_description = description or _first_doc_line(fn)

        @functools.wraps(fn)
        def stamped(repo: object) -> Iterator[Finding]:
            # Local import keeps the L3 import graph acyclic at module load.
            from flawed.evidence import Finding

            for item in cast("Iterable[object]", fn(repo)):
                if isinstance(item, Finding) and item.severity is None:
                    yield replace(item, severity=severity)
                else:
                    # Non-Finding items are surfaced unchanged so the runner
                    # can raise its own clear "yielded non-Finding" error.
                    yield cast("Finding", item)

        # Registration metadata is a runtime concern; store it on the callable
        # the detection engine will actually discover. Viewing ``stamped``
        # through the ``Detector`` protocol types these assignments — no
        # ``# type: ignore`` — and is what the decorator hands back.
        rule = cast("Detector", stamped)
        rule.__detector_name__ = name
        rule.__detector_severity__ = severity
        rule.__detector_description__ = resolved_description
        return rule

    return wrapper


def _first_doc_line(fn: Callable[..., object]) -> str | None:
    """Return the first non-blank line of ``fn``'s docstring, if any."""
    doc = fn.__doc__
    if not doc:
        return None
    for line in doc.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None
