"""The committed-artifact seam round-trips value-flow/taint facts.

Validates ``flawed.open_repo(path, artifact_root=...)`` by replicating a
flow-dependent spec assertion — the same one as
``tests/specs/basics/test_value_flow.py::TestValueFlowFlask::
test_input_read_derived_from_source`` — against a ``RepoView`` reconstructed
from committed L1 artifacts. No basedpyright subprocess runs.

Guards the loader seam (`tests.helpers.artifact_fixtures`) that the session
fixtures rely on to avoid live builds.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flawed.inputs import Json
from tests.helpers.artifact_fixtures import has_artifacts, load_fixture

if TYPE_CHECKING:
    from flawed.repo import RepoView

pytestmark = pytest.mark.skipif(
    not has_artifacts("flask_basic"),
    reason="committed artifacts absent; run: python -m tools.build_fixture_artifacts flask_basic",
)


@pytest.fixture(scope="module")
def flask_basic_loaded() -> RepoView:
    """flask_basic RepoView loaded from committed artifacts (no L1 execution)."""
    return load_fixture("flask_basic")


def test_routes_and_functions_present(flask_basic_loaded: RepoView) -> None:
    assert len(flask_basic_loaded.routes) >= 1
    assert flask_basic_loaded.functions.named("create_user").one() is not None


def test_input_read_derived_from_json_via_artifacts(flask_basic_loaded: RepoView) -> None:
    # Identical to the live-build spec assertion — proves value-flow / taint
    # facts survive the artifact round-trip.
    fn = flask_basic_loaded.functions.named("create_user").one()
    reads = fn.body.reads(Json())
    assert len(reads) >= 1
    read = reads.first()
    assert read is not None
    assert read.value.derived_from(Json())
