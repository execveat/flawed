"""Cross-file helpers for flask_indirect fixture.

These functions are imported by app.py and exercise cross-file
resolution (Level 4 complexity).
"""

from flask import g, request, session
from sqlalchemy import text


def get_query_param(key):
    """Read a query parameter — cross-file input source."""
    return request.args.get(key)


def get_form_field(key):
    """Read a form field — cross-file input source."""
    return request.form.get(key)


def get_json_field(key):
    """Read a JSON field — cross-file input source."""
    data = request.get_json()
    if data is None:
        return None
    return data.get(key)


def save_to_session(key, value):
    """Write to session — cross-file STATE_WRITE effect."""
    session[key] = value


def set_g_attr(key, value):
    """Write to g — cross-file STATE_WRITE effect (REQUEST scope)."""
    setattr(g, key, value)


def execute_raw(query_str):
    """Execute raw SQL — cross-file SQL_INJECTION sink."""
    db = g.db_session
    return db.execute(text(query_str))


def execute_safe(query_str, params):
    """Execute parameterized SQL — safe, no sink."""
    db = g.db_session
    return db.execute(text(query_str), params)
