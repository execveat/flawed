"""OAuth/OIDC userinfo-claim input reads (FLAW-202).

An authlib callback exchanges the auth code for a token, navigates into the
``userinfo`` claims container, and reads the ``email`` claim.  The engine must
surface ``userinfo.get("email")`` as an :class:`~flawed.inputs.InputRead` whose
source is a first-class OAuth/OIDC claim, so that a normalized gate derivation
and the raw identity derivation of the *same* claim correlate via
``shares_origin`` (the primitive FLAW-108 needs).

``sink(...)`` is the test's observation point for value handles.
"""

from authlib.integrations.flask_client import OAuth
from flask import Flask

app = Flask(__name__)
oauth = OAuth(app)
provider = oauth.register("provider")


def sink(value):  # noqa: ANN001, ANN201 - fixture observation point
    return value


@app.route("/auth/callback")
def callback():  # noqa: ANN201 - fixture handler
    token = provider.authorize_access_token()
    userinfo = token["userinfo"]
    email = userinfo.get("email")
    subject = userinfo.get("sub")

    lowered = email.lower()  # GATE-side normalized derivation of the email claim
    raw = email  # EFFECT-side raw derivation of the SAME email claim

    sink(lowered)
    sink(raw)
    sink(subject)
    return "ok"
