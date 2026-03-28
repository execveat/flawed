"""FLAW-275: split-statement ORM chains resolve their ``<Model>.query`` opener.

``q = Model.query`` then ``q.filter_by(...).first()`` is idiomatic in real apps.
Before FLAW-275 the bare ``Model.query`` attribute access carried no
resolved type, so the bound variable's chain resolved to a namespace-local
pseudo-FQN — the SQLAlchemy ``Query`` provider never fired and the ``Db.read``
was lost (value-flow stayed connected through ``q``, but the read disappeared).
Resolution is gated to provably declarative models, so a plain ``<obj>.query`` is
never canonicalized (FP-safe).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flawed.effects import Db

if TYPE_CHECKING:
    from flawed.repo import RepoView


def _route(repo: RepoView, name: str):
    for route in repo.routes:
        if route.name == name:
            return route
    pytest.fail(f"route {name!r} not found in fixture")


@pytest.mark.parametrize("route_name", ["single_expr", "split_stmt"])
def test_orm_split_chain_produces_db_read(orm_query_split: RepoView, route_name: str) -> None:
    """Both the single-expression and split-statement forms fire a modeled read."""
    route = _route(orm_query_split, route_name)
    reads = list(route.reachable.effects(Db.read()))
    assert reads, f"{route_name}: expected a modeled Db.read() effect, got none"


def test_non_model_query_var_is_not_resolved(orm_query_split: RepoView) -> None:
    """A ``q = <non-model>.query`` chain must NOT be canonicalized to a read."""
    route = _route(orm_query_split, "non_model")
    reads = list(route.reachable.effects(Db.read()))
    assert not reads, f"non_model: expected no Db.read effect, got {len(reads)}"
