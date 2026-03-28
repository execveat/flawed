"""FLAW-281a: inferred STATE_WRITE for custom (non-provider) mutating calls.

A verb-named mutating method call on an app-defined object emits no provider
effect today, so a real persistent write is invisible to coverage reasoning
(the ``delete_report``-class false negative).  281a infers a conservative,
low-confidence SERVER ``STATE_WRITE`` for such calls; a pure read on the same
object must NOT be inferred as a mutation.

A module-local fixture loads the committed ``custom_state_write`` artifacts
(zero external tools); the per-test wall-clock guard is unaffected.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flawed.effects import EffectCategory, State, StateScope
from tests.helpers.artifact_fixtures import load_fixture

if TYPE_CHECKING:
    from flawed.repo import RepoView
    from flawed.route import Route


@pytest.fixture(scope="module")
def custom_state_write() -> RepoView:
    return load_fixture("semantic/custom_state_write")


def _route(repo: RepoView, handler_suffix: str) -> Route:
    matches = tuple(r for r in repo.routes if r.handler.fqn.endswith(handler_suffix))
    assert matches, f"route handler ending with {handler_suffix!r} was not discovered"
    return matches[0]


def test_custom_mutating_call_infers_state_write(custom_state_write: RepoView) -> None:
    """store.delete_result(...) -> an inferred SERVER STATE_WRITE the FN needs."""
    route = _route(custom_state_write, "delete_report")
    writes = [e for e in route.body.effects() if e.category is EffectCategory.STATE_WRITE]
    delete_writes = [e for e in writes if "delete_result" in e.expression]
    assert delete_writes, (
        "expected an inferred STATE_WRITE for the custom store.delete_result() call; "
        f"got effects: {[e.expression for e in route.body.effects()]}"
    )
    effect = delete_writes[0]
    assert effect.scope is StateScope.SERVER
    # Honest low-confidence marker so the write is not over-trusted.
    assert effect.provenance.confidence < 0.95
    assert effect.provenance.interpreter == "inferred_state_writes"
    # The conservative selector surfaces it as a state write.
    assert effect in route.body.effects(State.write())


def test_custom_read_call_is_not_inferred_as_mutation(custom_state_write: RepoView) -> None:
    """store.get_result(...) is a read verb -> no spurious STATE_WRITE."""
    route = _route(custom_state_write, "read_report")
    inferred = [
        e
        for e in route.body.effects()
        if e.category is EffectCategory.STATE_WRITE
        and e.provenance.interpreter == "inferred_state_writes"
    ]
    assert not inferred, (
        "a pure read (get_result) must not be inferred as a mutation; "
        f"got: {[e.expression for e in inferred]}"
    )
