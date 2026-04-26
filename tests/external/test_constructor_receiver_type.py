"""FLAW-191: receiver-type resolution from a local constructor binding.

Locks in the behaviour that a local bound by ``x = Cls(...)`` resolves its
receiver type to ``Cls`` for a subsequent ``x.method()`` call, using only the
L1 value-flow ASSIGN edge + symbol resolution — i.e. with *no* type-enrichment
oracle present (the realistic case for a third-party class the oracle cannot
model without the package installed).

This was filed as an unticketed gap, but the constructor-inference path already
exists (``_resolve_variable_class`` over value-flow ASSIGN edges, landed with
the FLAW-187/169 receiver-plumbing cluster).  This test makes that guarantee
explicit and regression-proof.

NOTE: this resolves the *public* re-export FQN ``argon2.PasswordHasher`` (what
``from argon2 import PasswordHasher`` and symbol resolution yield). The argon2
provider formerly declared the *internal* ``argon2._password_hasher.PasswordHasher.verify``,
a public-vs-internal mismatch that kept FLAW-182's instance-form ``.verify``
selector dormant. FLAW-193 fixed it: the provider now declares the canonical
public FQN plus an internal→public ``fqn_aliases`` entry. End-to-end coverage
lives in ``test_crypto_instance_verify.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flawed._index._pipeline import build_index
from flawed._index._type_enrichment import TypeEnrichmentIndex
from flawed._semantic import _matching

# Calls build_index() directly on a fixture; bypass the per-test timing guard.
pytestmark = pytest.mark.slow

_FIXTURE = (
    Path(__file__).resolve().parent.parent / "fixtures" / "apps" / "constructor_receiver_type"
)


class _EmptyOracle:
    """Type oracle that models nothing — forces the source-level fallback."""

    def run(self, repo_root: Path, queries: object) -> TypeEnrichmentIndex:
        _ = (repo_root, queries)
        return TypeEnrichmentIndex.empty()


def test_constructor_binding_resolves_receiver_type(monkeypatch: pytest.MonkeyPatch) -> None:
    """``ph = PasswordHasher(); ph.verify(...)`` resolves ``ph`` to its class FQN."""
    idx = build_index(_FIXTURE, oracle=_EmptyOracle())

    # The constructor call itself resolves to the public re-export FQN.
    constructor_edges = [
        edge for edge in idx.call_graph.edges if edge.call_expression == "PasswordHasher"
    ]
    assert constructor_edges, "expected a constructor call edge for PasswordHasher()"
    assert constructor_edges[0].callee_fqn == "argon2.PasswordHasher"

    # The method call's receiver type is recovered from the constructor binding,
    # with no oracle fact available.
    verify_edges = [edge for edge in idx.call_graph.edges if edge.call_expression == "ph.verify"]
    assert verify_edges, "expected a ph.verify call edge"

    _matching.clear_matching_cache()
    resolved = _matching._resolve_call_receiver_type(verify_edges[0], idx)
    assert resolved == "argon2.PasswordHasher"
