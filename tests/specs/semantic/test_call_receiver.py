"""Specs: CallSite.receiver method-call subject provenance (FLAW-187).

A method-style transform (``email.lower()``) must expose its receiver (``email``)
as a :class:`~flawed.flow.ValueHandle`, so a rule can trace the subject's
provenance and correlate two transforms of the same input via ``shares_origin``
-- the primitive g040 (FLAW-185) consumes instead of brittle subject-string
matching.

Fixture: tests/fixtures/apps/semantic/flask_intra_provenance/ (session-scoped).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed.inputs import Query

if TYPE_CHECKING:
    from flawed.calls import CallSite
    from flawed.repo import RepoView


def _transforms(repo: RepoView) -> dict[str, CallSite]:
    """Map the method-transform call sites by their target expression."""
    route = repo.routes.first()
    assert route is not None
    return {
        call.target_expression: call
        for call in route.reachable.calls()
        if call.target_expression in {"email.lower", "email.strip"}
    }


class TestCallSiteReceiver:
    def test_receiver_exposed_for_method_call(self, flask_intra_provenance: RepoView) -> None:
        lower = _transforms(flask_intra_provenance)["email.lower"]
        assert lower.receiver is not None
        assert lower.receiver.expression == "email"

    def test_plain_function_call_has_no_receiver(self, flask_intra_provenance: RepoView) -> None:
        route = flask_intra_provenance.routes.first()
        assert route is not None
        sinks = [c for c in route.reachable.calls() if c.target_expression == "sink"]
        assert sinks  # the fixture calls sink(...) three times
        assert all(c.receiver is None for c in sinks)

    def test_receiver_derives_from_input_source(self, flask_intra_provenance: RepoView) -> None:
        calls = _transforms(flask_intra_provenance)
        lower_recv = calls["email.lower"].receiver
        strip_recv = calls["email.strip"].receiver
        assert lower_recv is not None and strip_recv is not None
        # The receiver ``email`` traces back through the ``?email=`` query read.
        assert lower_recv.derived_from(Query())
        assert strip_recv.derived_from(Query())

    def test_receivers_of_two_transforms_share_origin(
        self, flask_intra_provenance: RepoView
    ) -> None:
        route = flask_intra_provenance.routes.first()
        assert route is not None
        reads = list(route.reachable.reads())
        calls = _transforms(flask_intra_provenance)
        lower_recv = calls["email.lower"].receiver
        strip_recv = calls["email.strip"].receiver
        assert lower_recv is not None and strip_recv is not None
        # FLAW-185's correlation: two transforms of the SAME input correlate via
        # their receiver handles, not subject-string equality.
        assert lower_recv.shares_origin(strip_recv, among=reads)
