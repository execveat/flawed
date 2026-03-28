"""Flask app: app-level CSRFProtect(app) with a per-route ``@csrf.exempt`` (FLAW-173).

A global ``CSRFProtect(app)`` registers a before_request CSRF guard that the
engine attributes to every route's ``full_stack`` (FLAW-128).  A route decorated
``@csrf.exempt`` is removed from that global guard, so it is NOT actually
CSRF-protected -- treating it as covered is a fail-open.  the CSRF-exemption rule must subtract the
decorator-form exemption and flag the exempted state-changing route while
leaving the genuinely-covered route alone.
"""

from flask import Flask, jsonify, session
from flask_wtf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)  # global before_request CSRF guard


@app.route("/covered", methods=["POST"])
def covered():
    """Globally covered, not exempt -> protected, no finding."""
    session["last"] = "covered"
    return jsonify(ok=True)


@app.route("/exempt-decorator", methods=["POST"])
@csrf.exempt
def exempt_decorator():
    """Exempt from the global guard -> genuinely unprotected -> the CSRF-exemption rule flags."""
    session["last"] = "exempt"
    return jsonify(ok=True)
