"""FLAW-193: instance-form credential ``.verify`` selectors fire end-to-end.

FLAW-182 added curated ``.verify`` selectors for argon2/passlib hashers, but the
instance forms were dormant: the argon2 provider declared the *internal* FQN
(``argon2._password_hasher.PasswordHasher.verify``) while a constructor binding
resolves the receiver to the *public* re-export ``argon2.PasswordHasher`` — a
public-vs-internal mismatch the canonicalization step had no alias to bridge.

This test runs the provider engine on real built indexes and asserts the
``PASSWORD_VERIFY`` security check surfaces with the public canonical FQN that
the ``Crypto.compare()`` rule vocabulary keys on.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flawed._index._pipeline import build_index
from flawed._semantic._provider_engine import ProviderEngine
from flawed._semantic.providers._base import SecurityCheckPattern

# Builds an index directly; bypass the per-test timing guard.
pytestmark = pytest.mark.slow

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "apps" / "crypto_instance_verify"


def _password_verify_fqns() -> set[str]:
    idx = build_index(_FIXTURE)
    result = ProviderEngine().run(idx)
    return {
        match.canonical_fqn
        for match in result.matches
        if isinstance(match.descriptor, SecurityCheckPattern)
        and match.descriptor.category == "PASSWORD_VERIFY"
    }


def test_argon2_instance_verify_matches() -> None:
    """``ph = PasswordHasher(); ph.verify(...)`` surfaces a PASSWORD_VERIFY check
    keyed on the public ``argon2.PasswordHasher.verify`` FQN."""
    assert "argon2.PasswordHasher.verify" in _password_verify_fqns()


def test_passlib_cryptcontext_instance_verify_matches() -> None:
    """``ctx = CryptContext(...); ctx.verify(...)`` surfaces a PASSWORD_VERIFY
    check keyed on ``passlib.context.CryptContext.verify``."""
    assert "passlib.context.CryptContext.verify" in _password_verify_fqns()
