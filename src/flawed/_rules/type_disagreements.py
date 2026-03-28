"""Type-disagreement survey -- expressions with conflicting inferred types.

Reports expressions where two independent type engines inferred materially
different concrete types for the same value. A neutral survey of the engine's
type-disagreement signal (``flawed.disagreement``): it surfaces the
inconsistency for review without classifying it as a defect.

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
    "type-disagreements",
    severity=Severity.INFO,
    description="Survey of expressions whose inferred type differs between type engines",
)
def detect(kb: RepoView) -> Iterator[Finding]:
    """Report each expression whose inferred concrete type differs between engines."""
    from flawed.evidence import Finding

    for disagreement in kb.type_disagreements:
        types = " vs ".join(
            dict.fromkeys(observation.declared_type for observation in disagreement.observations)
        )
        tools = ", ".join(disagreement.source_tools)
        location_label = disagreement.containing_function_fqn or "(module level)"
        yield (
            Finding(
                route_endpoint=location_label,
                summary=(
                    f"Expression '{disagreement.expression}' carries conflicting inferred "
                    f"types: {types} (per {tools})"
                ),
                location=disagreement.location,
            ).evidence(disagreement, f"type disagreement [{disagreement.kind.value}]")
        )
