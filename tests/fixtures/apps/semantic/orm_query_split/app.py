"""ORM query forms whose ``<Model>.query`` opener must resolve (FLAW-275).

The single-expression chain already resolves (FLAW-116). The *split-statement*
form — idiomatic in real apps — binds ``<Model>.query`` to a local
variable first, then continues the chain off that variable. Before FLAW-275 the
bare ``Configs.query`` attribute access carried no resolved type, so the bound
variable had no receiver type and the later ``.filter_by(...).first()`` chain
stayed unresolved: the ``Db.read()`` effect was lost and value-flow through the
query truncated at the ``.query`` node.
"""

from __future__ import annotations

from flask import Flask, request
from models import Configs

app = Flask(__name__)


class _NotAModel:
    """A plain class with a ``query`` attribute — NOT a declarative model."""

    query = None


@app.route("/single/<raw>")
def single_expr(raw: str):
    """``Model.query.filter_by(...).first()`` (control — resolves via FLAW-116)."""
    return repr(Configs.query.filter_by(value=raw).first())


@app.route("/split/<raw>")
def split_stmt(raw: str):
    """``q = Model.query`` then ``q.filter_by(...).first()`` (the FLAW-275 gap)."""
    q = Configs.query
    return repr(q.filter_by(value=raw).first())


@app.route("/non-model/<raw>")
def non_model(raw: str):
    """``q = <non-model>.query`` must NOT canonicalize to a library read."""
    q = _NotAModel.query
    return repr(q.filter_by(value=raw).first())
