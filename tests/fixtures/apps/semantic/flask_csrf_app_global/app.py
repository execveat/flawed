"""Flask app: application-level CSRF via the ``CSRFProtect(app)`` constructor.

FLAW-128.  real apps register global CSRF with ``csrf = CSRFProtect(app)`` (the
constructor form).  flask-wtf implements that constructor by calling
``init_app(app)`` internally, so it protects every state-changing route exactly
like the explicit ``csrf.init_app(app)`` call does.

The engine previously modeled only the explicit ``init_app`` registration, so
the constructor form left every state-changing route looking CSRF-unprotected --
the mass false positives produced on a real corpus (~121 routes).

This fixture is intentionally minimal and framework-direct so provider FQN
matching installs the global ``CSRF`` lifecycle check from the constructor call.
"""

from flask import Flask, jsonify, session
from flask_wtf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)  # constructor form -> global before_request CSRF guard


@app.route("/settings", methods=["POST"])
def update_settings():
    """State-changing route covered by the global CSRF guard."""
    session["last_action"] = "settings"
    return jsonify(ok=True)


@app.route("/profile", methods=["POST"])
def update_profile():
    """Second state-changing route covered by the same global guard."""
    session["last_action"] = "profile"
    return jsonify(ok=True)
