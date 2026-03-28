"""python-jose provider -- JWT/JWS/JWK operations.

Module-level functions for JWT encode/decode, JWS sign/verify, and
JWK key construction.  Similar role to PyJWT but different FQNs.
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


class PythonJoseProvider(Provider):
    meta = ProviderMeta(
        id="python-jose",
        name="python-jose",
        version="0.1.0",
        library="python-jose",
        library_fqn="jose",
    )

    # -- Security checks -------------------------------------------------

    checks = (
        # JWT layer
        SecurityCheckPattern(
            fqn="jose.jwt.decode",
            kind=CheckKind.CALL,
            category="TOKEN_VERIFY",
            description=(
                "Decode and verify JWT (signature + claims). "
                "Returns claims dict (attacker-controlled if token forged)."
            ),
        ),
        # JWS layer
        SecurityCheckPattern(
            fqn="jose.jws.verify",
            kind=CheckKind.CALL,
            category="TOKEN_VERIFY",
            description="Verify JWS signature and return payload bytes",
        ),
    )

    # -- Effects ---------------------------------------------------------

    effects = (
        # JWT encode produces a signed token (typically set on response)
        EffectCallPattern(
            fqn="jose.jwt.encode",
            category="STATE_WRITE",
            scope="SESSION",
            description="Create signed JWT from claims dict",
        ),
        # JWS sign produces a signed payload
        EffectCallPattern(
            fqn="jose.jws.sign",
            category="STATE_WRITE",
            scope="SESSION",
            description="Create JWS compact serialization",
        ),
    )

    # -- Flow propagation ------------------------------------------------

    propagators = (
        # Decoded claims carry taint from the token
        FlowPropagatorPattern(
            fqn="jose.jwt.decode",
            input_arg=0,
            output="return",
            description="Token taint propagates to decoded claims dict",
        ),
        # Claims flow into the encoded token
        FlowPropagatorPattern(
            fqn="jose.jwt.encode",
            input_arg=0,
            output="return",
            description="Claims flow into encoded JWT string",
        ),
        # JWS verify returns payload bytes
        FlowPropagatorPattern(
            fqn="jose.jws.verify",
            input_arg=0,
            output="return",
            description="Token taint propagates to verified payload",
        ),
        # JWS sign: payload flows to signed output
        FlowPropagatorPattern(
            fqn="jose.jws.sign",
            input_arg=0,
            output="return",
            description="Payload flows into JWS compact serialization",
        ),
        # JWK construct: key data flows to key object
        FlowPropagatorPattern(
            fqn="jose.jwk.construct",
            input_arg=0,
            output="return",
            description="Key data flows into constructed JWK",
        ),
    )
