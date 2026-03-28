"""Declarative model defined separately from the routes that query it.

The cross-file split is deliberate: in real apps the model is
imported into the view module, so the query chain's receiver root is an
imported name — the case the FLAW-116 resolution must recover from the call
expression, not just same-file textual chains.
"""

from __future__ import annotations

from db import db


class Token(db.Model):  # type: ignore[name-defined]
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String)
