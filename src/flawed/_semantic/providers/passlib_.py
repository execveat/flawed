"""passlib provider -- password hashing and verification.

passlib provides a unified interface to 30+ password hashing schemes
via the ``PasswordHash`` protocol and the ``CryptContext`` convenience
wrapper.

Security-relevant patterns:

- Individual hashers (``passlib.hash.bcrypt``, etc.) expose ``.hash()``
  and ``.verify()`` class methods via the ``PasswordHash`` interface
  defined in ``passlib.ifc``.
- ``CryptContext`` wraps multiple hashers with automatic scheme
  selection, transparent re-hashing, and deprecation policies.
- ``CryptContext.verify_and_update()`` combines verification with
  automatic re-hash detection (important for hash-upgrade flows).

FQN note: ``passlib.hash`` is a proxy module -- actual classes live
in ``passlib.handlers.*`` but are accessed as ``passlib.hash.<name>``.
We declare both the proxy path (what users import) and the handler
path (where the class is actually defined) for each common scheme.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    FlowPropagatorPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class PasslibProvider(Provider):
    meta = ProviderMeta(
        id="passlib",
        name="passlib",
        version="0.1.0",
        library="passlib",
        library_fqn="passlib",
    )

    # =================================================================
    # Security checks: CryptContext (preferred high-level API)
    # =================================================================

    checks = (
        # -- CryptContext -------------------------------------------------
        SecurityCheckPattern(
            fqn="passlib.context.CryptContext.hash",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_HASH",
            description="Hash a password using the active scheme",
        ),
        SecurityCheckPattern(
            fqn="passlib.context.CryptContext.verify",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_VERIFY",
            description="Verify a password against a stored hash",
        ),
        SecurityCheckPattern(
            fqn="passlib.context.CryptContext.verify_and_update",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_VERIFY",
            description="Verify and return updated hash if scheme deprecated",
        ),
        SecurityCheckPattern(
            fqn="passlib.context.CryptContext.needs_update",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_VERIFY",
            description="Check if hash needs re-hashing (scheme deprecated)",
        ),
        SecurityCheckPattern(
            fqn="passlib.context.CryptContext.identify",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_VERIFY",
            description="Identify which hash scheme was used",
        ),
        # -- bcrypt -------------------------------------------------------
        SecurityCheckPattern(
            fqn="passlib.handlers.bcrypt.bcrypt.hash",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_HASH",
            description="Hash password with bcrypt",
        ),
        SecurityCheckPattern(
            fqn="passlib.handlers.bcrypt.bcrypt.verify",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_VERIFY",
            description="Verify password against bcrypt hash",
        ),
        # -- bcrypt_sha256 ------------------------------------------------
        SecurityCheckPattern(
            fqn="passlib.handlers.bcrypt.bcrypt_sha256.hash",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_HASH",
            description="Hash password with bcrypt_sha256 (avoids 72-byte limit)",
        ),
        SecurityCheckPattern(
            fqn="passlib.handlers.bcrypt.bcrypt_sha256.verify",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_VERIFY",
            description="Verify password against bcrypt_sha256 hash",
        ),
        # -- pbkdf2_sha256 ------------------------------------------------
        SecurityCheckPattern(
            fqn="passlib.handlers.pbkdf2.pbkdf2_sha256.hash",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_HASH",
            description="Hash password with PBKDF2-SHA256",
        ),
        SecurityCheckPattern(
            fqn="passlib.handlers.pbkdf2.pbkdf2_sha256.verify",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_VERIFY",
            description="Verify password against PBKDF2-SHA256 hash",
        ),
        # -- argon2 -------------------------------------------------------
        SecurityCheckPattern(
            fqn="passlib.handlers.argon2.argon2.hash",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_HASH",
            description="Hash password with Argon2",
        ),
        SecurityCheckPattern(
            fqn="passlib.handlers.argon2.argon2.verify",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_VERIFY",
            description="Verify password against Argon2 hash",
        ),
        # -- sha256_crypt -------------------------------------------------
        SecurityCheckPattern(
            fqn="passlib.handlers.sha2_crypt.sha256_crypt.hash",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_HASH",
            description="Hash password with SHA-256 crypt",
        ),
        SecurityCheckPattern(
            fqn="passlib.handlers.sha2_crypt.sha256_crypt.verify",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_VERIFY",
            description="Verify password against SHA-256 crypt hash",
        ),
        # -- sha512_crypt -------------------------------------------------
        SecurityCheckPattern(
            fqn="passlib.handlers.sha2_crypt.sha512_crypt.hash",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_HASH",
            description="Hash password with SHA-512 crypt",
        ),
        SecurityCheckPattern(
            fqn="passlib.handlers.sha2_crypt.sha512_crypt.verify",
            kind=CheckKind.METHOD_CALL,
            category="PASSWORD_VERIFY",
            description="Verify password against SHA-512 crypt hash",
        ),
    )

    # =================================================================
    # Flow propagation: data through hash/verify
    # =================================================================

    propagators = (
        FlowPropagatorPattern(
            fqn="passlib.context.CryptContext.hash",
            input_arg=0,
            output="return",
            description="Password data flows through hash to hash string",
        ),
        FlowPropagatorPattern(
            fqn="passlib.context.CryptContext.verify_and_update",
            input_arg=0,
            output="return",
            description="Password flows through verify_and_update to (ok, new_hash) tuple",
        ),
    )
