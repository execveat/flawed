"""Flask app: a bare ``CSRFProtect()`` that is never bound to the app.

FLAW-128 fail-open guard.  ``csrf = CSRFProtect()`` with no app argument and no
later ``csrf.init_app(app)`` does NOT install global CSRF protection -- flask-wtf
only registers the before_request guard once an app is bound.  The handle here
exists only to call ``csrf.exempt(...)`` (a common fixture/gadget pattern).

The engine must NOT treat this bare constructor as global CSRF coverage: doing so
is a fail-open that would hide a genuinely unprotected state-changing route (and
regressed an over-broad coverage rule, which counts any check as coverage).  So the CSRF-exemption rule MUST still flag the
mutating route below.
"""

from flask import Flask, jsonify, session
from flask_wtf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect()  # bare: no app, no init_app -> protects nothing


@app.route("/danger", methods=["POST"])
def danger():
    """State-changing route with NO real CSRF protection."""
    session["touched"] = True
    return jsonify(ok=True)
