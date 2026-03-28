"""Fire tests for the generic capability-demonstration rule core.

These rules ship as the public engine's default ruleset -- neutral capability
inventories, not vulnerability detectors. Rules 1-4 must produce findings on
real analyzed code (a committed fixture with routes, request reads, a guard,
and an input->write flow). Rule 5 (type-checker disagreements) is a hermetic
contract test in the stub style of ``test_r07a_conflicting_auth``: the
disagreement signal is derived from multi-engine type enrichment that committed
fixtures rarely carry, so a synthetic ``RepoView`` exercises the rule's contract
directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from flawed._rules.endpoints import detect as endpoints_detect
from flawed._rules.request_inputs import detect as request_inputs_detect
from flawed._rules.route_guards import detect as route_guards_detect
from flawed._rules.type_disagreements import detect as type_disagreements_detect
from flawed._rules.value_flow import detect as value_flow_detect
from flawed.core import Location
from flawed.disagreement import TypeDisagreementKind
from tests.helpers.artifact_fixtures import load_fixture

if TYPE_CHECKING:
    from flawed.repo import RepoView

_FIXTURE = "semantic/flask_self_service_writes"


def test_endpoints_inventory_fires() -> None:
    kb = load_fixture(_FIXTURE)
    findings = list(endpoints_detect(kb))
    assert findings, "endpoints rule should list the fixture's routes"
    assert all(finding.severity is not None for finding in findings)


def test_request_inputs_inventory_fires() -> None:
    kb = load_fixture(_FIXTURE)
    findings = list(request_inputs_detect(kb))
    assert findings, "request-inputs rule should report request reads"


def test_route_guards_inventory_fires() -> None:
    kb = load_fixture(_FIXTURE)
    findings = list(route_guards_detect(kb))
    assert findings, "route-guards rule should report the login_required guard"


def test_value_flow_trace_fires() -> None:
    kb = load_fixture(_FIXTURE)
    findings = list(value_flow_detect(kb))
    assert findings, "value-flow rule should trace a request value into an operation"


# --- Rule 5: hermetic contract test (stub RepoView) ---


@dataclass(frozen=True)
class _Observation:
    source_tool: str
    declared_type: str


@dataclass(frozen=True)
class _Disagreement:
    expression: str
    location: Location
    observations: tuple[_Observation, ...]
    kind: TypeDisagreementKind
    containing_function_fqn: str | None

    @property
    def source_tools(self) -> tuple[str, ...]:
        return tuple(observation.source_tool for observation in self.observations)


@dataclass(frozen=True)
class _Repo:
    type_disagreements: tuple[_Disagreement, ...]


def test_type_disagreements_survey_fires() -> None:
    disagreement = _Disagreement(
        expression="user.id",
        location=Location(file="app.py", line=12, column=4),
        observations=(
            _Observation("mypy", "int"),
            _Observation("basedpyright", "str | None"),
        ),
        kind=TypeDisagreementKind.OPTIONALITY,
        containing_function_fqn="app.views.get_user",
    )
    findings = list(type_disagreements_detect(cast("RepoView", _Repo((disagreement,)))))
    assert len(findings) == 1
    assert "conflicting inferred types" in findings[0].summary
    assert findings[0].severity is not None
