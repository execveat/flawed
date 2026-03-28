"""SQLAlchemy models: direct ORM usage, no subclass indirection.

Level 0 complexity: calls directly on Session/Query objects.
"""

from flask import g, jsonify, request
from sqlalchemy import select
from sqlalchemy.orm import Session as SaSession

from .app import app


class FlaskBasicModel:
    """Project-local class used to verify public class collection wiring."""

    def __init__(self, name: str) -> None:
        self.name = name


@app.route("/models/create", methods=["POST"])
def model_create():
    """session.add() + session.commit() → DB_WRITE effects."""
    db: SaSession = g.db_session
    name = request.form["name"]
    # In real code this would be a mapped class instance;
    # for analysis purposes the effect is on session.add()
    db.add({"name": name})  # type: ignore[arg-type]
    db.commit()
    return jsonify({"created": True})


@app.route("/models/read")
def model_read():
    """session.execute(select(...)) → DB_READ effect."""
    db: SaSession = g.db_session
    stmt = select("*")  # type: ignore[arg-type]
    result = db.execute(stmt)
    return jsonify(list(result))


@app.route("/models/delete/<int:item_id>", methods=["DELETE"])
def model_delete(item_id):
    """session.delete() → DB_DELETE effect."""
    db: SaSession = g.db_session
    obj = db.get(object, item_id)  # type: ignore[arg-type]
    if obj:
        db.delete(obj)
        db.commit()
    return jsonify({"deleted": True})
