"""FLAW-126 correlation false-positive regression fixtures.

Two shapes that a *name-only* correlation flags but a same-logical-input
correlation must not:

1. **Token name-collision.** A global ``before_request`` guard reads an API
   token from the QUERY STRING (``?token=``); an unrelated route reads a
   ``<token>`` segment from the URL PATH. The two share the *name* ``token`` but
   are different logical request inputs (a path segment cannot be forged into a
   query field), so the middleware/handler container-split rule must NOT fire.

2. **Unrelated transforms.** A route applies two differently-named string
   transforms to two *different* request values. With no shared-input value
   there is no normalization divergence to report.
"""

from flask import Flask, abort, g, jsonify, request

app = Flask(__name__)


@app.before_request
def api_token_query_guard():
    """Global API guard: authenticate using the ``?token=`` QUERY parameter."""
    api_token = request.args.get("token")
    if api_token is None:
        abort(401)
    g.api_token = api_token
    return None


@app.route("/verify/<token>", methods=["POST"])
def verify_email(token):
    """Email verification reads ``<token>`` from the URL PATH parameter.

    Same name as the API query token guarded above, different logical entity.
    """
    g.verified_email_token = token
    return jsonify({"verified": token})


@app.route("/normalize", methods=["GET"])
def normalize_two_inputs():
    """Two DIFFERENT request values pass through two different transforms."""
    name = request.args.get("name", "")
    city = request.args.get("city", "")
    return jsonify({"name": name.lower(), "city": city.strip()})
