"""PyJWT provider -- JWT token verification, encoding, and claims input.

PyJWT exposes module-level ``jwt.encode`` / ``jwt.decode`` functions
that delegate to a singleton ``PyJWT`` instance.  The actual method
FQNs resolve to ``jwt.api_jwt.PyJWT.encode`` / ``.decode``.

Security-relevant patterns:

- ``jwt.decode`` is both a **security check** (signature verification)
  and an **input source** (decoded claims are attacker-controlled if
  the token came from a request).
- ``jwt.encode`` produces a signed token -- a state write when set as
  a cookie or returned in a response.
- Disabling verification (``options={"verify_signature": False}``) or
  allowing the "none" algorithm are critical misconfigurations that
  this provider flags via ``when=`` predicates where expressible.

Note: the ``options`` dict and ``algorithms`` list are runtime values
that static analysis can partially resolve (literal dicts/lists).
Full coverage of misconfiguration requires L1 constant propagation.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    EffectCallPattern,
    FlowPropagatorPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class PyJWTProvider(Provider):
    meta = ProviderMeta(
        id="pyjwt",
        name="PyJWT",
        version="0.1.0",
        library="PyJWT",
        library_fqn="jwt",
    )

    # =================================================================
    # Security checks: token verification
    # =================================================================

    checks = (
        # jwt.decode verifies signature + claims by default.
        # When called with verify_signature=False, it's still a
        # "check" syntactically but a BYPASSED one.  The engine
        # will need to inspect options kwarg for that distinction;
        # the provider declares the DEFAULT (safe) behavior.
        SecurityCheckPattern(
            fqn="jwt.api_jwt.PyJWT.decode",
            kind=CheckKind.CALL,
            category="TOKEN_VERIFY",
            description="Verify JWT signature and decode claims",
        ),
        SecurityCheckPattern(
            fqn="jwt.api_jwt.PyJWT.decode_complete",
            kind=CheckKind.CALL,
            category="TOKEN_VERIFY",
            description="Verify JWT and return complete token structure",
        ),
    )

    # =================================================================
    # Effects: token creation
    # =================================================================

    effects = (
        # jwt.encode produces a signed token string.  When this token
        # is set as a cookie or returned in a response, it's a
        # RESPONSE_WRITE.  The encode itself is the creation point.
        EffectCallPattern(
            fqn="jwt.api_jwt.PyJWT.encode",
            category="STATE_WRITE",
            scope="SESSION",
            description="Create signed JWT (becomes session state when sent to client)",
        ),
    )

    # =================================================================
    # Flow propagation: claims extraction
    # =================================================================

    propagators = (
        # The JWT token (arg 0 to decode) carries claims that flow
        # into the return value.  The returned dict is attacker-
        # controlled if the token came from a request.
        FlowPropagatorPattern(
            fqn="jwt.api_jwt.PyJWT.decode",
            input_arg=0,
            output="return",
            description="JWT token claims flow from token to decoded dict",
        ),
        FlowPropagatorPattern(
            fqn="jwt.api_jwt.PyJWT.decode_complete",
            input_arg=0,
            output="return",
            description="JWT token claims flow from token to complete result",
        ),
        # Payload data flows into the encoded token
        FlowPropagatorPattern(
            fqn="jwt.api_jwt.PyJWT.encode",
            input_arg=0,
            output="return",
            description="Payload data flows into encoded JWT string",
        ),
    )
