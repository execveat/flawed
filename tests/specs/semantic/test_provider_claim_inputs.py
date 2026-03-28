"""Specs: OAuth/OIDC provider-claim input reads (FLAW-202).

A federated-identity token exchange returns a claims container; reading a claim
by key (``token["userinfo"].get("email")``) is a first-class request input, so:

- ``route.reachable.reads(ProviderClaim())`` surfaces the claim reads.
- A claim read carries a keyed ``ProviderClaim`` source (so it has a
  ``LogicalInput`` identity).
- A normalized gate derivation and the raw identity derivation of the *same*
  claim correlate via ``shares_origin`` — the primitive FLAW-108 needs.

Fixture: tests/fixtures/apps/semantic/oauth_claim_inputs/ (session-scoped).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed.core import Key
from flawed.inputs import ProviderClaim

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


class TestProviderClaimReads:
    def test_email_claim_read_surfaces_with_keyed_source(
        self, oauth_claim_inputs: RepoView
    ) -> None:
        route = oauth_claim_inputs.routes.first()
        assert route is not None
        claim_reads = list(route.reachable.reads(ProviderClaim()))
        keys = {
            read.source.key
            for read in claim_reads
            if isinstance(read.source, ProviderClaim) and read.source.key is not None
        }
        # The leaf claims read by key off the userinfo container are surfaced,
        # each with its claim name as the source key.
        assert Key("email") in keys
        assert Key("sub") in keys

    def test_no_claim_reads_without_the_provider_call(self, flask_basic: RepoView) -> None:
        # A route that never touches an OAuth token exchange has no claim reads —
        # the recognizer keys off the provider claims container, not bare ``.get``.
        for route in flask_basic.routes:
            assert not list(route.reachable.reads(ProviderClaim()))


class TestProviderClaimCorrelation:
    def test_gate_and_raw_derivations_share_origin(self, oauth_claim_inputs: RepoView) -> None:
        route = oauth_claim_inputs.routes.first()
        assert route is not None
        reads = list(route.reachable.reads())
        args = _sink_args(oauth_claim_inputs)
        # ``lowered = email.lower()`` (gate-side normalization) and the raw
        # ``email`` (effect-side) are two derivations of the SAME email claim.
        assert args["lowered"].derived_from(ProviderClaim(key=Key("email")))
        assert args["raw"].derived_from(ProviderClaim(key=Key("email")))
        # The FLAW-108 keystone: they correlate as the same logical input.
        assert args["lowered"].shares_origin(args["raw"], among=reads)

    def test_distinct_claims_do_not_share_origin(self, oauth_claim_inputs: RepoView) -> None:
        route = oauth_claim_inputs.routes.first()
        assert route is not None
        reads = list(route.reachable.reads())
        args = _sink_args(oauth_claim_inputs)
        # ``subject`` reads the ``sub`` claim, a different logical input than the
        # ``email`` claim — they must NOT correlate (no name-collision blur).
        assert not args["raw"].shares_origin(args["subject"], among=reads)
