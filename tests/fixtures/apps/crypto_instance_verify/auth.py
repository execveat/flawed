"""Fixture for FLAW-193: instance-form credential ``.verify`` recognition.

Two idioms that bind a hasher instance and then verify a credential on it:

- argon2-cffi: a *local* constructor binding ``ph = PasswordHasher()`` followed
  by ``ph.verify(hash, pw)``. L1 resolves the call as a project-local FQN
  (``login_argon2.<locals>.ph.verify``); the matching engine must recover the
  receiver class ``argon2.PasswordHasher`` and match the provider's
  ``PASSWORD_VERIFY`` check.
- passlib: a *module-level* ``CryptContext`` binding used inside a function via
  ``_pwd.verify(pw, hash)``.

Both verify calls must surface as ``PASSWORD_VERIFY`` security checks so the
``Crypto.compare()`` credential-validation vocabulary (FLAW-182) fires on them.
"""

from argon2 import PasswordHasher
from passlib.context import CryptContext

_pwd = CryptContext(schemes=["argon2"])


def login_argon2(stored_hash, given_password):
    ph = PasswordHasher()
    ph.verify(stored_hash, given_password)
    return True


def login_passlib(stored_hash, given_password):
    return _pwd.verify(given_password, stored_hash)
