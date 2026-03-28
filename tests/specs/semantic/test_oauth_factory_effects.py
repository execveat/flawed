"""Specs: OAuth-client factory / registry-attribute effects (FLAW-204).

The realistic authlib idiom obtains the per-provider client by attribute access
on the OAuth registry (``oauth.<provider>``) or from an ``oauth.register(...)``
result — neither has a statically resolvable type. The security-relevant
client-method calls (``authorize_access_token`` / ``authorize_redirect``) must
therefore be recognised by their federation-specific bare method names, so the
OUTBOUND_REQUEST effect fires even though the receiver type is unknown. The
token-exchange result is still a claims container (FLAW-202).

Fixture: tests/fixtures/apps/semantic/oauth_factory_effects/ (session-scoped).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed.effects import EffectCategory
from flawed.inputs import ProviderClaim

if TYPE_CHECKING:
    from flawed.repo import RepoView


def _route(repo: RepoView, suffix: str):
    matches = [r for r in repo.routes if r.handler.fqn.endswith(suffix)]
    assert len(matches) == 1, f"expected one route ending {suffix!r}, got {len(matches)}"
    return matches[0]


class TestRegistryAttributeEffects:
    def test_authorize_access_token_fires_outbound_request(
        self, oauth_factory_effects: RepoView
    ) -> None:
        # oauth.google.authorize_access_token() — receiver type unresolvable,
        # matched by bare method name.  Configured-target (FLAW-276): the token
        # exchange hits the registered IdP, so it is an outbound but not an SSRF
        # sink.
        route = _route(oauth_factory_effects, "callback")
        outbound = [
            e
            for e in route.reachable.effects()
            if e.category is EffectCategory.OUTBOUND_REQUEST_CONFIGURED
        ]
        assert len(outbound) == 1, [e.expression for e in route.reachable.effects()]
        assert "authorize_access_token" in outbound[0].expression

    def test_authorize_redirect_fires_outbound_request(
        self, oauth_factory_effects: RepoView
    ) -> None:
        route = _route(oauth_factory_effects, "login")
        # Configured-target (FLAW-276): redirect to the registered IdP.
        outbound = [
            e
            for e in route.reachable.effects()
            if e.category is EffectCategory.OUTBOUND_REQUEST_CONFIGURED
        ]
        assert len(outbound) == 1, [e.expression for e in route.reachable.effects()]
        assert "authorize_redirect" in outbound[0].expression

    def test_no_double_fire_on_single_call(self, oauth_factory_effects: RepoView) -> None:
        # OAuth1 and OAuth2 variants share one descriptor: a single call must
        # yield exactly one effect, not one per FQN alias.
        route = _route(oauth_factory_effects, "callback")
        assert len(list(route.reachable.effects())) == 1

    def test_claim_still_surfaces_on_factory_shape(self, oauth_factory_effects: RepoView) -> None:
        # The effect fix composes with FLAW-202: the token-exchange result is a
        # claims container, so userinfo.get("email") is a ProviderClaim read.
        route = _route(oauth_factory_effects, "callback")
        keys = {
            r.source.key
            for r in route.reachable.reads(ProviderClaim())
            if isinstance(r.source, ProviderClaim) and r.source.key is not None
        }
        assert any(k == "email" for k in keys), keys
