"""itsdangerous provider -- HMAC-based token signing and verification.

Covers all four serializer classes and both signer classes.

Security model: ``.dumps()`` signs data (TOKEN_SIGN), ``.loads()``
verifies the signature and deserializes (TOKEN_VERIFY).  The low-level
``Signer.sign/unsign`` and ``TimestampSigner.sign/unsign`` provide
the same semantics without serialization.

``.loads()`` on any serializer is both a security check (signature
verification -- raises ``BadSignature``/``SignatureExpired`` on failure)
and an implicit input source (the deserialized payload is
attacker-controlled if the signing key is compromised).  The
SecurityCheckPattern captures the guard aspect; flow propagation
captures data flow through these calls.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    FlowPropagatorPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class ItsdangerousProvider(Provider):
    meta = ProviderMeta(
        id="itsdangerous",
        name="itsdangerous",
        version="0.1.0",
        library="itsdangerous",
        library_fqn="itsdangerous",
    )

    # =================================================================
    # Security checks -- signing and verification
    # =================================================================

    checks = (
        # -- Signer (low-level bytes) ---------------------------------
        SecurityCheckPattern(
            fqn="itsdangerous.signer.Signer.sign",
            kind=CheckKind.CALL,
            category="TOKEN_SIGN",
            description="HMAC-sign bytes value",
        ),
        SecurityCheckPattern(
            fqn="itsdangerous.signer.Signer.unsign",
            kind=CheckKind.CALL,
            category="TOKEN_VERIFY",
            description="Verify HMAC signature and return payload (raises BadSignature)",
        ),
        SecurityCheckPattern(
            fqn="itsdangerous.signer.Signer.validate",
            kind=CheckKind.CALL,
            category="TOKEN_VERIFY",
            description="Validate HMAC signature (returns bool, no exception)",
        ),
        SecurityCheckPattern(
            fqn="itsdangerous.signer.Signer.verify_signature",
            kind=CheckKind.CALL,
            category="TOKEN_VERIFY",
            description="Verify detached HMAC signature (returns bool)",
        ),
        # -- TimestampSigner (low-level bytes + expiry) ---------------
        SecurityCheckPattern(
            fqn="itsdangerous.timed.TimestampSigner.sign",
            kind=CheckKind.CALL,
            category="TOKEN_SIGN",
            description="HMAC-sign bytes value with embedded timestamp",
        ),
        SecurityCheckPattern(
            fqn="itsdangerous.timed.TimestampSigner.unsign",
            kind=CheckKind.CALL,
            category="TOKEN_VERIFY",
            description="Verify timestamped HMAC (raises BadSignature/SignatureExpired)",
        ),
        SecurityCheckPattern(
            fqn="itsdangerous.timed.TimestampSigner.validate",
            kind=CheckKind.CALL,
            category="TOKEN_VERIFY",
            description="Validate timestamped HMAC (returns bool)",
        ),
        # -- Serializer (sign + JSON serialize) -----------------------
        SecurityCheckPattern(
            fqn="itsdangerous.serializer.Serializer.dumps",
            kind=CheckKind.CALL,
            category="TOKEN_SIGN",
            description="Serialize and HMAC-sign object",
        ),
        SecurityCheckPattern(
            fqn="itsdangerous.serializer.Serializer.dump",
            kind=CheckKind.CALL,
            category="TOKEN_SIGN",
            description="Serialize, HMAC-sign, and write to file",
        ),
        SecurityCheckPattern(
            fqn="itsdangerous.serializer.Serializer.loads",
            kind=CheckKind.CALL,
            category="TOKEN_VERIFY",
            description="Verify HMAC and deserialize (raises BadSignature)",
        ),
        SecurityCheckPattern(
            fqn="itsdangerous.serializer.Serializer.load",
            kind=CheckKind.CALL,
            category="TOKEN_VERIFY",
            description="Read from file, verify HMAC, and deserialize",
        ),
        SecurityCheckPattern(
            fqn="itsdangerous.serializer.Serializer.loads_unsafe",
            kind=CheckKind.CALL,
            category="TOKEN_VERIFY_UNSAFE",
            description="Deserialize WITHOUT verifying signature (dangerous!)",
        ),
        # -- TimedSerializer (sign + JSON + timestamp) ----------------
        SecurityCheckPattern(
            fqn="itsdangerous.timed.TimedSerializer.loads",
            kind=CheckKind.CALL,
            category="TOKEN_VERIFY",
            description="Verify timestamped HMAC and deserialize (raises SignatureExpired)",
        ),
        SecurityCheckPattern(
            fqn="itsdangerous.timed.TimedSerializer.loads_unsafe",
            kind=CheckKind.CALL,
            category="TOKEN_VERIFY_UNSAFE",
            description="Deserialize without verifying timestamped signature (dangerous!)",
        ),
        # -- URLSafeSerializer ----------------------------------------
        SecurityCheckPattern(
            fqn="itsdangerous.url_safe.URLSafeSerializer.dumps",
            kind=CheckKind.CALL,
            category="TOKEN_SIGN",
            description="Serialize, HMAC-sign, and URL-safe encode",
        ),
        SecurityCheckPattern(
            fqn="itsdangerous.url_safe.URLSafeSerializer.loads",
            kind=CheckKind.CALL,
            category="TOKEN_VERIFY",
            description="URL-safe decode, verify HMAC, and deserialize",
        ),
        # -- URLSafeTimedSerializer -----------------------------------
        SecurityCheckPattern(
            fqn="itsdangerous.url_safe.URLSafeTimedSerializer.dumps",
            kind=CheckKind.CALL,
            category="TOKEN_SIGN",
            description="Serialize, HMAC-sign with timestamp, and URL-safe encode",
        ),
        SecurityCheckPattern(
            fqn="itsdangerous.url_safe.URLSafeTimedSerializer.loads",
            kind=CheckKind.CALL,
            category="TOKEN_VERIFY",
            description="URL-safe decode, verify timestamped HMAC, and deserialize",
        ),
        SecurityCheckPattern(
            fqn="itsdangerous.url_safe.URLSafeTimedSerializer.loads_unsafe",
            kind=CheckKind.CALL,
            category="TOKEN_VERIFY_UNSAFE",
            description="Deserialize URL-safe token without verification (dangerous!)",
        ),
    )

    # =================================================================
    # Flow propagation
    # =================================================================

    propagators = (
        # Signer: value flows through sign to signed output
        FlowPropagatorPattern(
            fqn="itsdangerous.signer.Signer.sign",
            input_arg=0,
            output="return",
            description="Value flows through HMAC signing to signed output",
        ),
        # Signer: signed value flows through unsign to original value
        FlowPropagatorPattern(
            fqn="itsdangerous.signer.Signer.unsign",
            input_arg=0,
            output="return",
            description="Signed value flows through unsign to verified payload",
        ),
        # TimestampSigner: same flow semantics
        FlowPropagatorPattern(
            fqn="itsdangerous.timed.TimestampSigner.sign",
            input_arg=0,
            output="return",
            description="Value flows through timestamped signing",
        ),
        FlowPropagatorPattern(
            fqn="itsdangerous.timed.TimestampSigner.unsign",
            input_arg=0,
            output="return",
            description="Signed value flows through timestamped unsign",
        ),
        # Serializer: object flows through dumps to signed token
        FlowPropagatorPattern(
            fqn="itsdangerous.serializer.Serializer.dumps",
            input_arg=0,
            output="return",
            description="Object flows through serialize+sign to token",
        ),
        # Serializer: signed token flows through loads to deserialized object
        FlowPropagatorPattern(
            fqn="itsdangerous.serializer.Serializer.loads",
            input_arg=0,
            output="return",
            description="Token flows through verify+deserialize to object",
        ),
        # loads_unsafe: token flows through deserialization (no verification)
        FlowPropagatorPattern(
            fqn="itsdangerous.serializer.Serializer.loads_unsafe",
            input_arg=0,
            output="return",
            description="Token flows through deserialize (NO verification -- dangerous)",
        ),
    )
