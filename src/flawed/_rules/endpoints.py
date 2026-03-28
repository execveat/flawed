"""Endpoint inventory -- reconstruct and list every HTTP route.

A neutral capability report: enumerates the HTTP endpoints the engine
reconstructed from framework registration patterns (route decorators, URL
rules, blueprints/routers), each with its accepted methods, URL rule, handler,
and route group. It reports what the analyzer sees and makes no judgement about
any route.

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
    "endpoints",
    severity=Severity.INFO,
    description="Inventory of the HTTP endpoints reconstructed from the codebase",
)
def detect(kb: RepoView) -> Iterator[Finding]:
    """Report every reconstructed route with its methods, URL rule, and handler."""
    for route in kb.routes:
        methods = ", ".join(sorted(method.value for method in route.methods)) or "(unspecified)"
        group = route.group or "(top-level)"
        yield route.finding(
            f"{route.endpoint}: {methods} {route.url_rule} -> {route.handler.fqn} [{group}]"
        ).evidence(route.handler, "handler function")
