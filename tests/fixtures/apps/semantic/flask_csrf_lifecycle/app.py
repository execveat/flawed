"""Flask app: lifecycle CSRF-exemption pattern.

A ``before_request`` hook gates ``csrf.exempt(view_func)`` on a
*presence-only* token helper (``is_token_authenticated()``), so a single
request-time mutation permanently disables CSRF for whichever endpoint is
being dispatched.  Because the hook runs for every route, the mutation
appears in every route's ``full_stack`` -- this is the lifecycle "flood"
case that per-route dedup must collapse to a single report with route-impact
metadata.

It also contains a *static* decorator exemption (``@csrf.exempt`` at import
time on ``webhook_receiver``).  That is a deliberate, declaration-time
config choice -- not a request-driven mutation -- so the lifecycle rules
must treat it as lower-severity / not part of the flood group.

This fixture is intentionally minimal and framework-direct so provider FQN
matching emits the ``Config.write`` (CSRF exemption) effect the rules
consume.
"""

from flask import Flask, jsonify, request
from flask_wtf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect()
csrf.init_app(app)


def extract_token_from_request():
    """Resolve a token-shaped value from several request containers.

    Presence-only: it does not hash, look up, validate expiry, or bind a
    user.  Mirrors a real-world ``extract_token_from_request`` idiom.
    """
    return (
        request.headers.get("Authorization")
        or request.headers.get("X-API-Token")
        or request.args.get("token")
    )


def is_token_authenticated():
    """Return True when *any* token-shaped value is present.

    This is the weak presence gate: it conflates "a token-shaped value
    exists" with "the request is authenticated".
    """
    return extract_token_from_request() is not None


@app.before_request
def csrf_exempt_for_api_tokens():
    """Lifecycle hook: exempt the dispatched view from CSRF on token presence.

    ``csrf.exempt(view_func)`` mutates the view function's CSRF state
    PERMANENTLY -- after one token-shaped request, all subsequent requests
    (including browser sessions from other users) skip CSRF for that
    endpoint.  Gated only on presence, not validity.
    """
    if is_token_authenticated():
        view_func = app.view_functions[request.endpoint]
        csrf.exempt(view_func)


@app.route("/settings", methods=["POST"])
def update_settings():
    """State-changing endpoint protected by CSRF in the normal case."""
    return jsonify({"ok": True})


@app.route("/profile", methods=["POST"])
def update_profile():
    """Second state-changing endpoint affected by the same lifecycle hook."""
    return jsonify({"ok": True})


@app.route("/admin/delete", methods=["POST"])
def admin_delete():
    """Third endpoint affected by the same lifecycle hook."""
    return jsonify({"ok": True})


@app.route("/webhook", methods=["POST"])
@csrf.exempt
def webhook_receiver():
    """Static, import-time CSRF exemption.

    This is a deliberate declaration-time choice (an external webhook with
    its own signature verification), NOT a request-driven mutation.  The
    lifecycle rules should treat it as lower-severity and must not fold it
    into the before_request flood group.
    """
    return jsonify({"received": True})
