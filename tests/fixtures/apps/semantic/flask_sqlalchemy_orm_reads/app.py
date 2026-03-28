"""Flask-SQLAlchemy app exercising ORM query-chain reads (FLAW-116).

The canonical flask-sqlalchemy / SQLAlchemy read idioms must each surface a
modeled ``Db.read()`` effect, so validated-derivation rules reason over real
DB lookups instead of a source-string idiom fallback:

  - ``Model.query.filter_by(...).first()``   (legacy ``Model.query`` descriptor)
  - ``db.session.query(Model).filter(...).first()``
  - ``db.session.get(Model, id)``
  - ``Model.query.get(id)``

``Token`` and ``db`` are imported from sibling modules (the cross-file case real
apps exhibit), so the query receiver root is an imported name. The app imports
only ``flask_sqlalchemy`` (via the ``db`` singleton) and never ``sqlalchemy``
directly, yet the SQLAlchemy effect provider still activates and fires the DB
reads (FLAW-190): flask-sqlalchemy re-exposes the SQLAlchemy ORM, and the
provider declares ``flask_sqlalchemy`` as an activation import.
"""

from __future__ import annotations

from db import db
from flask import Flask
from models import Token

app = Flask(__name__)


@app.route("/by-descriptor/<raw>")
def by_descriptor(raw: str):
    """``Model.query.filter_by(...).first()`` → DB_READ."""
    return repr(Token.query.filter_by(value=raw).first())


@app.route("/by-session-query/<raw>")
def by_session_query(raw: str):
    """``db.session.query(Model).filter(...).first()`` → DB_READ."""
    return repr(db.session.query(Token).filter(Token.value == raw).first())


@app.route("/by-session-get/<int:token_id>")
def by_session_get(token_id: int):
    """``db.session.get(Model, id)`` → DB_READ (Session.get)."""
    return repr(db.session.get(Token, token_id))


@app.route("/by-query-get/<int:token_id>")
def by_query_get(token_id: int):
    """``Model.query.get(id)`` → DB_READ (Query.get)."""
    return repr(Token.query.get(token_id))
