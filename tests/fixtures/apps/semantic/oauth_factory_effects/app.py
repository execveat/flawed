"""OAuth-client factory shape: registry-attribute client calls (FLAW-204).

The realistic authlib idiom obtains the per-provider client by *attribute
access on the OAuth registry* — ``oauth.google`` — whose type the index cannot
resolve (it is produced by ``OAuth.__getattr__`` / ``register``). So the
security-relevant client-method calls must be recognised by their
federation-specific method names, not by a resolved receiver FQN:

- ``oauth.google.authorize_access_token()`` -> OUTBOUND_REQUEST effect
- ``oauth.google.authorize_redirect(...)`` -> OUTBOUND_REQUEST effect
- the token-exchange result is a claims container (FLAW-202), so
  ``userinfo.get("email")`` is a ProviderClaim read.
"""

from authlib.integrations.flask_client import OAuth
from flask import Flask

app = Flask(__name__)
oauth = OAuth(app)
oauth.register(name="google")


@app.route("/login")
def login():  # noqa: ANN201 - fixture handler
    return oauth.google.authorize_redirect("https://example.test/callback")


@app.route("/auth/callback")
def callback():  # noqa: ANN201 - fixture handler
    token = oauth.google.authorize_access_token()
    userinfo = token["userinfo"]
    email = userinfo.get("email")
    return email
