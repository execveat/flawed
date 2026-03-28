"""Tests for ``FlowPropagatorPattern``'s ``names=`` escape hatch (FLAW-206).

A token-flow propagator declared FQN-only cannot fire on a call whose receiver
type the index cannot resolve — e.g. ``oauth.<provider>.authorize_access_token()``
where the client comes from ``oauth.register(...)`` (a registry attribute whose
return type is unknown).  ``names=`` lets the propagator match by bare method
name in that shape, closing the token-flow false negative, mirroring the
established ``names=`` escape hatch on ``EffectCallPattern`` /
``ClaimContainerPattern`` / ``ValidatedValueGuardPattern``.

These tests exercise the matching layer (``_match_call_descriptor`` →
``_descriptor_names``) against the real authlib propagator descriptors.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from flawed._index import CodeIndex
from flawed._index._type_enrichment import TypeEnrichmentIndex
from flawed._index._types import (
    CallArgument,
    CallEdge,
    EdgeSource,
    ExtractionProvenance,
    ResolutionStatus,
    SourceSpan,
)
from flawed._semantic import _matching
from flawed._semantic._matching import _match_call_descriptor
from flawed._semantic._provider_engine import ProviderPhase
from flawed._semantic.providers.authlib_ import AuthlibProvider

if TYPE_CHECKING:
    from flawed._semantic.providers._base import FlowPropagatorPattern

_PROV = ExtractionProvenance(producer="test", producer_version="0", artifact="")
_ROOT = Path("/tmp/test-repo")
_FILE = "app.py"

_PROVIDER = AuthlibProvider()
_ALIASES = dict(_PROVIDER.fqn_aliases)

_AAT_FQN = "authlib.integrations.flask_client.apps.FlaskOAuth2App.authorize_access_token"


def _span(*, line: int = 10, column: int = 0) -> SourceSpan:
    return SourceSpan(
        file=_FILE,
        line=line,
        column=column,
        end_line=line,
        end_column=column + 10,
    )


def _call_edge(
    *,
    callee_fqn: str | None,
    call_expression: str,
    resolution: ResolutionStatus,
    caller_fqn: str = "app.callback",
    arguments: tuple[CallArgument, ...] = (),
) -> CallEdge:
    return CallEdge(
        caller_fqn=caller_fqn,
        callee_fqn=callee_fqn,
        arguments=arguments,
        resolution=resolution,
        source=EdgeSource.AST,
        unresolved_reason=None,
        location=_span(),
        provenance=_PROV,
        call_expression=call_expression,
    )


def _index(*, call_edges: tuple[CallEdge, ...]) -> CodeIndex:
    _matching.clear_matching_cache()
    return CodeIndex(
        repo_root=_ROOT,
        functions=(),
        classes=(),
        decorators=(),
        imports=(),
        attributes=(),
        call_edges=call_edges,
        cfgs={},
        value_flow_edges=(),
        symbol_refs=(),
        errors=(),
        provenance=_PROV,
        type_enrichment=TypeEnrichmentIndex.empty(),
    )


def _propagator(*, fqn_suffix: str) -> FlowPropagatorPattern:
    for descriptor in _PROVIDER.propagators:
        fqns = descriptor.fqn if isinstance(descriptor.fqn, tuple) else (descriptor.fqn,)
        if any(fqn.endswith(fqn_suffix) for fqn in fqns):
            return descriptor
    msg = f"No FlowPropagatorPattern with FQN ending in {fqn_suffix!r}"
    raise ValueError(msg)


def _arg() -> tuple[CallArgument, ...]:
    return (CallArgument(position=0, keyword=None, expression="request", location=_span()),)


# -- The FLAW-206 verification: names= fires on an unresolved receiver --------


def test_authlib_propagator_names_fires_on_unresolved_receiver() -> None:
    """oauth.google.authorize_access_token() propagates even when callee_fqn is None.

    This is the registry-attribute shape (client from ``oauth.register(...)``)
    whose receiver type the index cannot resolve.  Without ``names=`` the
    FQN-only propagator silently misses it — a token-flow false negative.
    """
    descriptor = _propagator(fqn_suffix="authorize_access_token")
    assert "authorize_access_token" in descriptor.names  # the escape hatch is declared

    edge = _call_edge(
        callee_fqn=None,
        call_expression="oauth.google.authorize_access_token(request)",
        resolution=ResolutionStatus.UNRESOLVED,
        arguments=_arg(),
    )
    idx = _index(call_edges=(edge,))

    matches = _match_call_descriptor(
        _PROVIDER, ProviderPhase.PROPAGATORS, descriptor, idx, _ALIASES
    )

    assert len(matches) == 1
    assert matches[0].descriptor is descriptor


def test_propagator_names_does_not_overfire_on_unrelated_unresolved_call() -> None:
    """A different bare method name on an unresolved receiver does NOT propagate."""
    descriptor = _propagator(fqn_suffix="authorize_access_token")
    edge = _call_edge(
        callee_fqn=None,
        call_expression="oauth.google.authorize_redirect(request)",
        resolution=ResolutionStatus.UNRESOLVED,
        arguments=_arg(),
    )
    idx = _index(call_edges=(edge,))

    matches = _match_call_descriptor(
        _PROVIDER, ProviderPhase.PROPAGATORS, descriptor, idx, _ALIASES
    )

    assert len(matches) == 0


def test_fqn_only_propagator_ignores_unresolved_receiver() -> None:
    """A propagator WITHOUT names= (JWT decode) stays opt-in: no bare-name match.

    Guards against the escape hatch leaking into FQN-only descriptors and
    over-propagating on every unresolved call of the same simple name.
    """
    descriptor = _propagator(fqn_suffix="JsonWebToken.decode")
    assert descriptor.names == ()  # FQN-only, no escape hatch

    edge = _call_edge(
        callee_fqn=None,
        call_expression="something.decode(token)",
        resolution=ResolutionStatus.UNRESOLVED,
        arguments=(CallArgument(position=0, keyword=None, expression="token", location=_span()),),
    )
    idx = _index(call_edges=(edge,))

    matches = _match_call_descriptor(
        _PROVIDER, ProviderPhase.PROPAGATORS, descriptor, idx, _ALIASES
    )

    assert len(matches) == 0


def test_authlib_propagator_fqn_match_still_works() -> None:
    """Exact-FQN resolution still matches — no regression from the names= path."""
    descriptor = _propagator(fqn_suffix="authorize_access_token")
    edge = _call_edge(
        callee_fqn=_AAT_FQN,
        call_expression="client.authorize_access_token(request)",
        resolution=ResolutionStatus.RESOLVED,
        arguments=_arg(),
    )
    idx = _index(call_edges=(edge,))

    matches = _match_call_descriptor(
        _PROVIDER, ProviderPhase.PROPAGATORS, descriptor, idx, _ALIASES
    )

    assert len(matches) == 1
    assert matches[0].canonical_fqn == _AAT_FQN
