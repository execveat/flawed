"""argon2-cffi provider -- Argon2 password hashing.

Pure guard/verification library.  Entirely declarative.
"""

from __future__ import annotations


from flawed._semantic.providers._base import (
    CheckKind,
    FlowPropagatorPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class Argon2Provider(Provider):
    meta = ProviderMeta(
        id="argon2-cffi",
        name="argon2-cffi",
        version="0.1.0",
        library="argon2-cffi",
        library_fqn="argon2",
    )

    # -- Security checks -------------------------------------------------

    checks = (
        # High-level PasswordHasher API
        SecurityCheckPattern(
            fqn="argon2._password_hasher.PasswordHasher.hash",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_HASH",
            description="Hash password with Argon2 (id/i/d variants)",
        ),
        SecurityCheckPattern(
            fqn="argon2._password_hasher.PasswordHasher.verify",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_VERIFY",
            description="Verify password against Argon2 hash (raises on mismatch)",
        ),
        SecurityCheckPattern(
            fqn="argon2._password_hasher.PasswordHasher.check_needs_rehash",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_VERIFY",
            description="Check whether hash parameters are outdated",
        ),
        # Low-level API
        SecurityCheckPattern(
            fqn="argon2.low_level.hash_secret",
            kind=CheckKind.CALL,
            category="PASSWORD_HASH",
            description="Low-level Argon2 hash (returns encoded bytes)",
        ),
        SecurityCheckPattern(
            fqn="argon2.low_level.hash_secret_raw",
            kind=CheckKind.CALL,
            category="PASSWORD_HASH",
            description="Low-level Argon2 hash (returns raw bytes)",
        ),
        SecurityCheckPattern(
            fqn="argon2.low_level.verify_secret",
            kind=CheckKind.CALL,
            category="PASSWORD_VERIFY",
            description="Low-level Argon2 verify (raises on mismatch)",
        ),
    )

    # -- Flow propagation ------------------------------------------------

    propagators = (
        FlowPropagatorPattern(
            fqn="argon2._password_hasher.PasswordHasher.hash",
            input_arg=0,
            output="return",
            description="Password flows through hash to hash output",
        ),
        FlowPropagatorPattern(
            fqn="argon2.low_level.hash_secret",
            input_arg=0,
            output="return",
            description="Secret flows through low-level hash to output",
        ),
    )
