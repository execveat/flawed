"""Flask auth patterns: login_required variations, fresh login, etc.

Level 0 complexity: direct decorator usage, no indirection.
"""

from flask import jsonify, request
from flask_login import fresh_login_required, login_required

from .app import app


@app.route("/auth/basic")
@login_required
def auth_basic():
    """Standard @login_required."""
    return jsonify({"ok": True})


@app.route("/auth/fresh")
@fresh_login_required
def auth_fresh():
    """@fresh_login_required — requires non-remembered session."""
    return jsonify({"ok": True})


@app.route("/auth/unprotected")
def auth_none():
    """No auth decorator — this route is unprotected."""
    return jsonify({"public": True})


@app.route("/auth/manual_check")
def auth_manual():
    """Manual auth check via call (not decorator)."""
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"ok": True})
