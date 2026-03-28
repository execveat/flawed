"""Route-guard inventory -- list the guards present on each endpoint.

For every route, reports the provider-modelled checks (authentication,
authorization, CSRF, schema validation, rate limiting, ...) the engine
recognised on the route and its lifecycle hooks. A neutral inventory of what
is present: it does not flag absences or judge coverage.

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
    "route-guards",
    severity=Severity.INFO,
    description="Per-endpoint inventory of provider-modelled guards and checks",
)
def detect(kb: RepoView) -> Iterator[Finding]:
    """Report, per route, which provider-modelled checks are present."""
    for route in kb.routes:
        checks = list(route.full_stack.checks())
        if not checks:
            continue
        categories = ", ".join(sorted({check.category for check in checks}))
        finding = route.finding(f"{route.endpoint} guarded by: {categories}")
        for check in checks[:_MAX_EVIDENCE]:
            label = check.category
            if check.provider_id is not None:
                label += f" via {check.provider_id}"
            finding = finding.evidence(check, label)
        yield finding
