"""Specs: interprocedural OAuth/OIDC provider-claim input reads (FLAW-203).

FLAW-202 surfaced claim reads only when the claims container was bound and read
in the same function. The real federated-identity idiom is interprocedural: the
callback exchanges the token and delegates to a helper
(``create_or_update_sso_user(userinfo)``) that reads claims off its parameter.
This locks in that the claim source propagates across the call boundary:

- The helper's ``userinfo.get("email")`` / ``.get("sub")`` surface as keyed
  ``ProviderClaim`` reads even though the token exchange is in the caller.
- A normalized gate derivation and the raw identity derivation of the same claim
  correlate via ``shares_origin`` across the function boundary — the primitive
  FLAW-108 needs on the real shape.
- Distinct claims (``email`` vs ``sub``) still do NOT correlate.

Fixture: tests/fixtures/apps/semantic/oauth_claim_interproc/ (session-scoped).
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


class TestInterproceduralClaimReads:
    def test_callee_claim_reads_surface_with_keyed_source(
        self, oauth_claim_interproc: RepoView
    ) -> None:
        route = oauth_claim_interproc.routes.first()
        assert route is not None
        claim_reads = list(route.reachable.reads(ProviderClaim()))
        keys = {
            read.source.key
            for read in claim_reads
            if isinstance(read.source, ProviderClaim) and read.source.key is not None
        }
        # The helper reads ``email`` and ``sub`` off the parameter that received
        # the claims container — both must surface, keyed by claim name.
        assert Key("email") in keys
        assert Key("sub") in keys


class TestInterproceduralClaimCorrelation:
    def test_gate_and_raw_derivations_share_origin_across_boundary(
        self, oauth_claim_interproc: RepoView
    ) -> None:
        route = oauth_claim_interproc.routes.first()
        assert route is not None
        reads = list(route.reachable.reads())
        args = _sink_args(oauth_claim_interproc)
        # ``lowered = email.lower()`` (gate) and the raw ``email`` (effect) are
        # two derivations of the SAME email claim — read off a parameter the
        # helper received from the caller's token exchange.
        assert args["lowered"].derived_from(ProviderClaim(key=Key("email")))
        assert args["raw"].derived_from(ProviderClaim(key=Key("email")))
        assert args["lowered"].shares_origin(args["raw"], among=reads)

    def test_distinct_claims_do_not_share_origin(self, oauth_claim_interproc: RepoView) -> None:
        route = oauth_claim_interproc.routes.first()
        assert route is not None
        reads = list(route.reachable.reads())
        args = _sink_args(oauth_claim_interproc)
        # ``subject`` reads the ``sub`` claim — a different logical input than the
        # ``email`` claim, so they must NOT correlate.
        assert not args["raw"].shares_origin(args["subject"], among=reads)
