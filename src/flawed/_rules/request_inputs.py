"""Request-input inventory -- list where each endpoint reads request data.

For every route, reports which request containers (query string, form body,
JSON body, path parameters, headers, ...) the reachable handler code reads
from, and how many reads of each. A neutral capability report on the engine's
request-input modelling -- not a judgement about any read.

One of the default capability-demonstration rules shipped with the engine.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed import detector
from flawed.severity import Severity

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flawed.evidence import Finding
    from flawed.repo import RepoView

_MAX_EVIDENCE = 8


@detector(
    "request-inputs",
    severity=Severity.INFO,
    description="Per-endpoint inventory of request inputs read by handler code",
)
def detect(kb: RepoView) -> Iterator[Finding]:
    """Report, per route, which request containers its reachable code reads from."""
    for route in kb.routes:
        reads = list(route.reachable.reads())
        if not reads:
            continue
        counts: dict[str, int] = {}
        for read in reads:
            name = type(read.source).__name__
            counts[name] = counts.get(name, 0) + 1
        breakdown = ", ".join(f"{count}x {name}" for name, count in sorted(counts.items()))
        finding = route.finding(f"{route.endpoint} reads request input from: {breakdown}")
        for read in reads[:_MAX_EVIDENCE]:
            finding = finding.evidence(
                read, f"{type(read.source).__name__} read: {read.expression}"
            )
        yield finding
