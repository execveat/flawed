"""Specs: intra-function transform provenance (FLAW-172).

A request value read into a local must keep its origin as it flows through an
intra-function transform, so the provenance primitives resolve on the
transformed local:

- ``derived_from`` traces a transformed local back to its input source.
- ``shares_origin`` correlates two transforms of the *same* logical input.
- ``preserves_whole_value`` still distinguishes a transform (not preserving)
  from a pure alias (preserving).

Fixture: tests/fixtures/apps/semantic/flask_intra_provenance/ (session-scoped).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed.inputs import Query

if TYPE_CHECKING:
    from flawed.flow import ValueHandle
    from flawed.repo import RepoView


def _sink_args(repo: RepoView) -> dict[str, ValueHandle]:
    route = repo.routes.first()
    assert route is not None
    return {
        call.arguments[0].value.expression: call.arguments[0].value
        for call in route.reachable.calls()
        if getattr(call, "target_expression", None) == "sink" and call.arguments
    }


class TestTransformProvenance:
    def test_derived_from_resolves_through_transform(
        self, flask_intra_provenance: RepoView
    ) -> None:
        args = _sink_args(flask_intra_provenance)
        # ``lowered = email.lower()`` and ``stripped = email.strip()`` both
        # derive from the ``?email=`` query read despite the transform.
        assert args["lowered"].derived_from(Query())
        assert args["stripped"].derived_from(Query())

    def test_alias_also_derives_from_source(self, flask_intra_provenance: RepoView) -> None:
        args = _sink_args(flask_intra_provenance)
        assert args["alias"].derived_from(Query())

    def test_shares_origin_correlates_two_transforms_of_same_input(
        self, flask_intra_provenance: RepoView
    ) -> None:
        route = flask_intra_provenance.routes.first()
        assert route is not None
        reads = list(route.reachable.reads())
        args = _sink_args(flask_intra_provenance)
        # The principled correlation path: two normalizations of the SAME request value
        # correlate via shares_origin instead of brittle subject-string matching.
        assert args["lowered"].shares_origin(args["stripped"], among=reads)

    def test_transform_is_not_whole_value_preserving(
        self, flask_intra_provenance: RepoView
    ) -> None:
        route = flask_intra_provenance.routes.first()
        assert route is not None
        read = next(iter(route.reachable.reads(Query()))).value
        args = _sink_args(flask_intra_provenance)
        # A pure alias preserves the whole value; a transform does not — the
        # provenance fix must not blur this distinction.
        assert read.preserves_whole_value_to(args["alias"]).preserved
        assert not read.preserves_whole_value_to(args["lowered"]).preserved
