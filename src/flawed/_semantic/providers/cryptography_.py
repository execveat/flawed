"""Python cryptography library provider -- crypto ops, key mgmt, signing.

Covers the ``cryptography`` package: Fernet symmetric encryption, HMAC
message authentication, hash digests, asymmetric signing/verification
(RSA, EC, Ed25519, Ed448), key derivation (PBKDF2, Scrypt, HKDF),
symmetric ciphers, AEAD ciphers, and key serialization/loading.

All entries are declarative SecurityCheckPattern or FlowPropagatorPattern.
No extraction hooks needed -- every security-relevant API is a
straightforward FQN-to-category mapping.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    FlowPropagatorPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class CryptographyProvider(Provider):
    meta = ProviderMeta(
        id="cryptography",
        name="cryptography",
        version="0.1.0",
        library="cryptography",
        library_fqn="cryptography",
    )

    # =================================================================
    # Security checks -- crypto operations as guards / verifiers
    # =================================================================

    checks = (
        # -- Fernet symmetric encryption/decryption --------------------
        SecurityCheckPattern(
            fqn="cryptography.fernet.Fernet.encrypt",
            kind=CheckKind.CALL,
            category="ENCRYPTION",
            description="Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256)",
        ),
        SecurityCheckPattern(
            fqn="cryptography.fernet.Fernet.encrypt_at_time",
            kind=CheckKind.CALL,
            category="ENCRYPTION",
            description="Fernet encryption with explicit timestamp",
        ),
        SecurityCheckPattern(
            fqn="cryptography.fernet.Fernet.decrypt",
            kind=CheckKind.CALL,
            category="DECRYPTION",
            description="Fernet decryption with HMAC verification (raises InvalidToken)",
        ),
        SecurityCheckPattern(
            fqn="cryptography.fernet.Fernet.decrypt_at_time",
            kind=CheckKind.CALL,
            category="DECRYPTION",
            description="Fernet decryption with explicit timestamp and TTL check",
        ),
        SecurityCheckPattern(
            fqn="cryptography.fernet.MultiFernet.encrypt",
            kind=CheckKind.CALL,
            category="ENCRYPTION",
            description="MultiFernet encryption (key rotation support)",
        ),
        SecurityCheckPattern(
            fqn="cryptography.fernet.MultiFernet.encrypt_at_time",
            kind=CheckKind.CALL,
            category="ENCRYPTION",
            description="MultiFernet encryption with explicit timestamp",
        ),
        SecurityCheckPattern(
            fqn="cryptography.fernet.MultiFernet.decrypt",
            kind=CheckKind.CALL,
            category="DECRYPTION",
            description="MultiFernet decryption (tries all keys)",
        ),
        SecurityCheckPattern(
            fqn="cryptography.fernet.MultiFernet.decrypt_at_time",
            kind=CheckKind.CALL,
            category="DECRYPTION",
            description="MultiFernet decryption with explicit timestamp",
        ),
        SecurityCheckPattern(
            fqn="cryptography.fernet.MultiFernet.rotate",
            kind=CheckKind.CALL,
            category="ENCRYPTION",
            description="Re-encrypt with newest key (key rotation)",
        ),
        # -- HMAC authentication --------------------------------------
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.hmac.HMAC.verify",
            kind=CheckKind.CALL,
            category="HMAC_VERIFY",
            description="HMAC signature verification (raises InvalidSignature)",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.hmac.HMAC.finalize",
            kind=CheckKind.CALL,
            category="HMAC_FINALIZE",
            description="HMAC digest finalization",
        ),
        # -- Hash digests ---------------------------------------------
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.hashes.Hash.finalize",
            kind=CheckKind.CALL,
            category="HASH_DIGEST",
            description="Hash digest finalization",
        ),
        # -- RSA signing and verification -----------------------------
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.sign",
            kind=CheckKind.CALL,
            category="ASYMMETRIC_SIGN",
            description="RSA private key signing",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.verify",
            kind=CheckKind.CALL,
            category="ASYMMETRIC_VERIFY",
            description="RSA public key signature verification (raises InvalidSignature)",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.decrypt",
            kind=CheckKind.CALL,
            category="DECRYPTION",
            description="RSA private key decryption",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.encrypt",
            kind=CheckKind.CALL,
            category="ENCRYPTION",
            description="RSA public key encryption",
        ),
        # -- EC signing and verification ------------------------------
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.sign",
            kind=CheckKind.CALL,
            category="ASYMMETRIC_SIGN",
            description="ECDSA private key signing",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.verify",
            kind=CheckKind.CALL,
            category="ASYMMETRIC_VERIFY",
            description="ECDSA public key signature verification",
        ),
        # -- Ed25519 signing and verification -------------------------
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.sign",
            kind=CheckKind.CALL,
            category="ASYMMETRIC_SIGN",
            description="Ed25519 private key signing",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey.verify",
            kind=CheckKind.CALL,
            category="ASYMMETRIC_VERIFY",
            description="Ed25519 public key signature verification",
        ),
        # -- Ed448 signing and verification ---------------------------
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey.sign",
            kind=CheckKind.CALL,
            category="ASYMMETRIC_SIGN",
            description="Ed448 private key signing",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey.verify",
            kind=CheckKind.CALL,
            category="ASYMMETRIC_VERIFY",
            description="Ed448 public key signature verification",
        ),
        # -- DSA signing and verification -----------------------------
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey.sign",
            kind=CheckKind.CALL,
            category="ASYMMETRIC_SIGN",
            description="DSA private key signing",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey.verify",
            kind=CheckKind.CALL,
            category="ASYMMETRIC_VERIFY",
            description="DSA public key signature verification",
        ),
        # -- Key derivation functions ---------------------------------
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC.derive",
            kind=CheckKind.CALL,
            category="KEY_DERIVATION",
            description="PBKDF2-HMAC key derivation",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC.verify",
            kind=CheckKind.CALL,
            category="KEY_DERIVATION_VERIFY",
            description="PBKDF2-HMAC key verification (raises InvalidKey)",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.kdf.hkdf.HKDF.derive",
            kind=CheckKind.CALL,
            category="KEY_DERIVATION",
            description="HKDF key derivation",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.kdf.hkdf.HKDF.verify",
            kind=CheckKind.CALL,
            category="KEY_DERIVATION_VERIFY",
            description="HKDF key verification (raises InvalidKey)",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.kdf.hkdf.HKDFExpand.derive",
            kind=CheckKind.CALL,
            category="KEY_DERIVATION",
            description="HKDF-Expand key derivation",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.kdf.hkdf.HKDFExpand.verify",
            kind=CheckKind.CALL,
            category="KEY_DERIVATION_VERIFY",
            description="HKDF-Expand key verification (raises InvalidKey)",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.kdf.scrypt.Scrypt.derive",
            kind=CheckKind.CALL,
            category="KEY_DERIVATION",
            description="Scrypt key derivation",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.kdf.scrypt.Scrypt.verify",
            kind=CheckKind.CALL,
            category="KEY_DERIVATION_VERIFY",
            description="Scrypt key verification (raises InvalidKey)",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.kdf.argon2.Argon2id.derive",
            kind=CheckKind.CALL,
            category="KEY_DERIVATION",
            description="Argon2id key derivation",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.kdf.argon2.Argon2id.verify",
            kind=CheckKind.CALL,
            category="KEY_DERIVATION_VERIFY",
            description="Argon2id key verification (raises InvalidKey)",
        ),
        # -- Key loading / deserialization ----------------------------
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.serialization.load_pem_private_key",
            kind=CheckKind.CALL,
            category="KEY_LOADING",
            description="Load PEM-encoded private key",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.serialization.load_der_private_key",
            kind=CheckKind.CALL,
            category="KEY_LOADING",
            description="Load DER-encoded private key",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.serialization.load_pem_public_key",
            kind=CheckKind.CALL,
            category="KEY_LOADING",
            description="Load PEM-encoded public key",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.serialization.load_der_public_key",
            kind=CheckKind.CALL,
            category="KEY_LOADING",
            description="Load DER-encoded public key",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.serialization.load_ssh_private_key",
            kind=CheckKind.CALL,
            category="KEY_LOADING",
            description="Load OpenSSH-format private key",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.serialization.load_ssh_public_key",
            kind=CheckKind.CALL,
            category="KEY_LOADING",
            description="Load OpenSSH-format public key",
        ),
        # -- CMAC authentication --------------------------------------
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.cmac.CMAC.verify",
            kind=CheckKind.CALL,
            category="HMAC_VERIFY",
            description="CMAC signature verification (raises InvalidSignature)",
        ),
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.cmac.CMAC.finalize",
            kind=CheckKind.CALL,
            category="HMAC_FINALIZE",
            description="CMAC digest finalization",
        ),
        # -- Poly1305 -------------------------------------------------
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.poly1305.Poly1305.verify_tag",
            kind=CheckKind.CALL,
            category="HMAC_VERIFY",
            description="Poly1305 tag verification (raises InvalidSignature)",
        ),
        # -- Constant-time comparison ---------------------------------
        SecurityCheckPattern(
            fqn="cryptography.hazmat.primitives.constant_time.bytes_eq",
            kind=CheckKind.CALL,
            category="CONSTANT_TIME_COMPARE",
            description="Timing-safe byte comparison",
        ),
        # -- X.509 certificate signing --------------------------------
        SecurityCheckPattern(
            fqn="cryptography.x509.base.CertificateBuilder.sign",
            kind=CheckKind.CALL,
            category="ASYMMETRIC_SIGN",
            description="Sign X.509 certificate with private key",
        ),
        SecurityCheckPattern(
            fqn="cryptography.x509.base.CertificateSigningRequestBuilder.sign",
            kind=CheckKind.CALL,
            category="ASYMMETRIC_SIGN",
            description="Sign X.509 CSR with private key",
        ),
        # -- Fernet key generation ------------------------------------
        SecurityCheckPattern(
            fqn="cryptography.fernet.Fernet.generate_key",
            kind=CheckKind.CALL,
            category="KEY_GENERATION",
            description="Generate Fernet key (32 random bytes, base64-encoded)",
        ),
    )

    # =================================================================
    # Flow propagation
    # =================================================================

    propagators = (
        # Fernet: plaintext flows through encrypt to ciphertext
        FlowPropagatorPattern(
            fqn="cryptography.fernet.Fernet.encrypt",
            input_arg=0,
            output="return",
            description="Plaintext flows through Fernet encryption to ciphertext",
        ),
        # Fernet: ciphertext flows through decrypt to plaintext
        FlowPropagatorPattern(
            fqn="cryptography.fernet.Fernet.decrypt",
            input_arg=0,
            output="return",
            description="Ciphertext flows through Fernet decryption to plaintext",
        ),
        # HMAC: data flows through update into the MAC context
        FlowPropagatorPattern(
            fqn="cryptography.hazmat.primitives.hmac.HMAC.update",
            input_arg=0,
            output="receiver",
            description="Data flows into HMAC context via update",
        ),
        # Hash: data flows through update into the hash context
        FlowPropagatorPattern(
            fqn="cryptography.hazmat.primitives.hashes.Hash.update",
            input_arg=0,
            output="receiver",
            description="Data flows into hash context via update",
        ),
        # KDF derive: key material flows to derived key
        FlowPropagatorPattern(
            fqn="cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC.derive",
            input_arg=0,
            output="return",
            description="Key material flows through PBKDF2 derivation",
        ),
        FlowPropagatorPattern(
            fqn="cryptography.hazmat.primitives.kdf.scrypt.Scrypt.derive",
            input_arg=0,
            output="return",
            description="Key material flows through Scrypt derivation",
        ),
        FlowPropagatorPattern(
            fqn="cryptography.hazmat.primitives.kdf.hkdf.HKDF.derive",
            input_arg=0,
            output="return",
            description="Key material flows through HKDF derivation",
        ),
    )
