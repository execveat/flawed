"""Declarative model imported into the routes module (cross-file case)."""

from __future__ import annotations

from db import db


class Configs(db.Model):  # type: ignore[name-defined]
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String)
    value = db.Column(db.String)
