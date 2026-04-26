"""FLAW-279: decorator-receiver typing — ``@recv.attr`` on a local instance.

A decorator written as an attribute call on a locally-constructed instance —
``@ns.route(...)`` where ``ns = Namespace(...)`` — previously resolved only to
the module-local binding FQN (``<module>.ns.route``), never the library FQN
(``flask_restx.Namespace.route``), so it never matched provider route
descriptors.  A real app's entire flask-restx ``api/v1`` surface (81 ``Resource``
classes / 184 routes) was invisible as a result — a corpus-wide false negative.

This shares the existing constructor-receiver-typing machinery
(``_resolve_variable_class`` over value-flow ASSIGN edges, generalised here to
the *module* scope where a top-level ``ns = Namespace(...)`` binding lives) into
the decorator path: ``@ns.route`` now resolves to ``flask_restx.Namespace.route``
as an additional observed-FQN candidate.  Purely additive — strictly FN-reducing.

Scope note: this closes the *resolution* half.  Forming the actual route from a
``@ns.route``-decorated *Resource class* (mapping its ``get``/``delete`` methods
to route handlers) is class-based route-handler modelling — a separate
L2/provider remainder (see the ``xfail`` route assertions in
``tests/specs/semantic/test_flask_restx_routes.py`` and the FLAW-272 closure
plan).  Validated end-to-end by an installed-env real-app re-scan on the sandbox.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from flawed._index._pipeline import build_index
from flawed._index._type_enrichment import TypeEnrichmentIndex
from flawed._semantic import _matching
from flawed._semantic._matching import _decorator_observed_fqns, _resolve_variable_class

if TYPE_CHECKING:
    from flawed._index import CodeIndex
    from flawed._index._types import DecoratorFact

# Calls build_index() directly on a fixture; bypass the per-test timing guard.
pytestmark = pytest.mark.slow

_FIXTURE = (
    Path(__file__).resolve().parent.parent / "fixtures" / "apps" / "semantic" / "flask_restx_api"
)


class _EmptyOracle:
    """Type oracle that models nothing — forces the source-level fallback."""

    def run(self, repo_root: Path, queries: object) -> TypeEnrichmentIndex:
        _ = (repo_root, queries)
        return TypeEnrichmentIndex.empty()


def _ns_route_fact(idx: CodeIndex) -> DecoratorFact:
    return next(f for f in idx.decorators if f.name == "ns.route")


def test_decorator_receiver_resolves_library_fqn(monkeypatch: pytest.MonkeyPatch) -> None:
    """``@ns.route`` with ``ns = Namespace(...)`` yields ``flask_restx.Namespace.route``."""
    idx = build_index(_FIXTURE, oracle=_EmptyOracle())
    _matching.clear_matching_cache()

    fact = _ns_route_fact(idx)
    observed = _decorator_observed_fqns(fact, idx)

    # The module-local binding is still present (existing behaviour) AND the
    # receiver-typed library FQN is now an additional candidate — the latter is
    # what matches the provider's ``flask_restx.Namespace.route`` descriptor.
    assert "flask_restx_api.app.ns.route" in observed
    assert "flask_restx.Namespace.route" in observed, observed


def test_module_level_constructor_receiver_resolves(monkeypatch: pytest.MonkeyPatch) -> None:
    """``_resolve_variable_class`` generalises to module scope (containing fqn ``None``)."""
    idx = build_index(_FIXTURE, oracle=_EmptyOracle())
    _matching.clear_matching_cache()

    fact = _ns_route_fact(idx)
    # ``ns = Namespace(...)`` is a top-level binding — value-flow scope ``None``.
    resolved = _resolve_variable_class("ns", None, fact.location, fact.location.file, idx)
    assert resolved == "flask_restx.Namespace"

    # An unresolvable receiver yields no fabricated type — honest, FN-safe.
    assert (
        _resolve_variable_class("nonexistent", None, fact.location, fact.location.file, idx)
        is None
    )
