"""bcrypt provider -- password hashing and verification.

Entirely declarative.  bcrypt exposes four module-level functions:
``hashpw``, ``checkpw``, ``gensalt``, and ``kdf``.  All are
security-relevant.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    FlowPropagatorPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class BcryptProvider(Provider):
    meta = ProviderMeta(
        id="bcrypt",
        name="bcrypt",
        version="0.1.0",
        library="bcrypt",
        library_fqn="bcrypt",
    )

    # =================================================================
    # Security checks
    # =================================================================

    checks = (
        SecurityCheckPattern(
            fqn="bcrypt.hashpw",
            kind=CheckKind.CALL,
            category="PASSWORD_HASH",
            description="Hash password with bcrypt (arg 0: password, arg 1: salt)",
        ),
        SecurityCheckPattern(
            fqn="bcrypt.checkpw",
            kind=CheckKind.CALL,
            category="PASSWORD_VERIFY",
            description="Verify password against bcrypt hash (returns bool)",
        ),
        SecurityCheckPattern(
            fqn="bcrypt.gensalt",
            kind=CheckKind.CALL,
            category="KEY_GENERATION",
            description="Generate bcrypt salt (arg: rounds, default 12)",
        ),
        SecurityCheckPattern(
            fqn="bcrypt.kdf",
            kind=CheckKind.CALL,
            category="KEY_DERIVATION",
            description="bcrypt-based key derivation (password, salt, length, rounds)",
        ),
    )

    # =================================================================
    # Flow propagation
    # =================================================================

    propagators = (
        # Password flows through hashpw to produce hash
        FlowPropagatorPattern(
            fqn="bcrypt.hashpw",
            input_arg=0,
            output="return",
            description="Password flows through bcrypt hashing to hash output",
        ),
        # Password flows through kdf to produce derived key
        FlowPropagatorPattern(
            fqn="bcrypt.kdf",
            input_arg=0,
            output="return",
            description="Password flows through bcrypt KDF to derived key",
        ),
    )
