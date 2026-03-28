"""Fixture for FLAW-191: receiver-type resolution from a constructor binding.

``ph`` is bound by a constructor call ``PasswordHasher()`` and then a method is
invoked on it.  L1 resolves the call as ``login.<locals>.ph.verify``; the
matching engine must recover the receiver class ``argon2.PasswordHasher`` from
the value-flow ASSIGN edge + symbol resolution, with no type-enrichment oracle.
"""

from argon2 import PasswordHasher


def login(stored_hash, given_password):
    ph = PasswordHasher()
    ph.verify(stored_hash, given_password)
    return True
