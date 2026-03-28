"""Interprocedural OAuth/OIDC userinfo-claim input reads (FLAW-203).

Mirrors a real federated-identity idiom (an ``auth/sso.py`` callback): the
callback route exchanges the auth code for a token and passes the ``userinfo``
claims container into a helper, which reads the ``email``/``sub`` claims off its
*parameter*. The claim source must propagate across the call boundary so
``userinfo.get("email")`` in the helper surfaces as a
:class:`~flawed.inputs.ProviderClaim` read — and a normalized gate derivation
and the raw identity derivation of the same claim correlate via
``shares_origin`` even though the token exchange lives in a different function.

``sink(...)`` is the test's observation point for value handles.
"""

from authlib.integrations.flask_client import OAuth
from flask import Flask

app = Flask(__name__)
oauth = OAuth(app)
provider = oauth.register("provider")


def sink(value):  # noqa: ANN001, ANN201 - fixture observation point
    return value


def create_or_update_sso_user(userinfo):  # noqa: ANN001, ANN201 - fixture helper
    # ``userinfo`` is the claims container, received as a parameter from the
    # caller — each keyed read off it must be a ProviderClaim input read.
    email = userinfo.get("email")
    subject = userinfo.get("sub")

    lowered = email.lower()  # GATE-side normalized derivation of the email claim
    raw = email  # EFFECT-side raw derivation of the SAME email claim

    sink(lowered)
    sink(raw)
    sink(subject)
    return raw


@app.route("/auth/callback")
def callback():  # noqa: ANN201 - fixture handler
    token = provider.authorize_access_token()
    # The claims sub-container is passed across a call boundary; the helper's
    # reads off its parameter must still be attributed to the claim source.
    return create_or_update_sso_user(token["userinfo"])
