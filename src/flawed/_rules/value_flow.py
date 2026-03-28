"""Value-flow trace -- show where request inputs reach operations.

For every route, reports cases where a value read from the request reaches an
operation (a write, an outbound call, ...) elsewhere in the reachable code,
following the engine's cross-procedure value-flow analysis. A neutral trace of
how data moves through the code: it does not classify any flow as unsafe.

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


@detector(
    "value-flow",
    severity=Severity.INFO,
    description="Trace request values that reach an operation in reachable code",
)
def detect(kb: RepoView) -> Iterator[Finding]:
    """Report request inputs whose value flows to an operation."""
    for route in kb.routes:
        scope = route.reachable
        for effect in scope.effects():
            target = effect.target
            if target is None:
                continue
            feeders = list(scope.reads_flowing_to(target))
            if not feeders:
                continue
            read = feeders[0]
            operation = effect.category.name.lower()
            yield (
                route.finding(f"{route.endpoint}: a request value reaches a {operation} operation")
                .evidence(read, f"request input: {read.expression}")
                .evidence(effect, f"{operation}: {effect.expression}")
            )
