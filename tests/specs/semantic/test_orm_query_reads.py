"""FLAW-116: SQLAlchemy ORM query-chain idioms produce modeled Db.read effects.

Each canonical read idiom must resolve its chain to the library ``Query`` /
``Session`` FQN so the SQLAlchemy effect provider fires, rather than leaving the
read invisible (which forced credential rules onto a ``.query``/``.objects`` source-string
fallback). See ``flask_sqlalchemy_orm_reads`` fixture, which imports only
``flask_sqlalchemy`` (never ``sqlalchemy`` directly) — so this also exercises
FLAW-190 provider activation via the ``flask_sqlalchemy`` re-export.
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


@pytest.mark.parametrize(
    "route_name",
    [
        "by_descriptor",  # Model.query.filter_by(...).first()
        "by_session_query",  # db.session.query(Model).filter(...).first()
        "by_session_get",  # db.session.get(Model, id)
        "by_query_get",  # Model.query.get(id)
    ],
)
def test_orm_read_idiom_produces_db_read(
    flask_sqlalchemy_orm_reads: RepoView, route_name: str
) -> None:
    route = _route(flask_sqlalchemy_orm_reads, route_name)
    reads = list(route.reachable.effects(Db.read()))
    assert reads, f"{route_name}: expected a modeled Db.read() effect, got none"
