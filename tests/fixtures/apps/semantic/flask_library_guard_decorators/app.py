"""Routes guarded by LIBRARY auth decorators on module-global instances.

flask-allows (``@allows.requires`` on a module-global ``Allows()``) and
Flask-HTTPAuth (``@basic_auth.login_required`` / ``@token_auth.login_required``
on ``HTTPBasicAuth()`` / ``HTTPTokenAuth()`` instances) are authorization /
authentication guards whose wrapper bodies live in the third-party library, not
in the repo -- so the call-graph auth-inference pass cannot trace their
``abort()`` / redirect the way it does project-local ``@admins_only``.
Recognition must instead come from the provider ``SecurityCheckPattern`` matched
through the decorator's *receiver type* (``allows`` -> ``flask_allows.Allows``,
``basic_auth`` -> ``flask_httpauth.HTTPBasicAuth``).

A genuinely unguarded route and an unproven look-alike decorator (a project
``login_required`` method on a non-HTTPAuth object) must NOT be recognized --
recognising either would silently suppress a real missing-auth finding (a false
negative, the cardinal sin).
"""

from flask import Flask, session
from flask_allows import Allows, Requirement
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth

app = Flask(__name__)
allows = Allows(app)
basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth()


class IsAdmin(Requirement):
    def fulfill(self, user):
        return bool(getattr(user, "is_admin", False))


@app.route("/allows/config", methods=["POST"])
@allows.requires(IsAdmin())
def allows_guarded():
    # @allows.requires(...) authorizes -> AUTHORIZATION via the flask_allows
    # provider, resolved through allows: flask_allows.Allows.
    session["last_action"] = "config"
    return "ok"


@app.route("/basic/config", methods=["POST"])
@basic_auth.login_required
def basic_guarded():
    # @basic_auth.login_required authenticates -> AUTHENTICATION via the new
    # flask_httpauth provider, resolved through basic_auth: HTTPBasicAuth.
    session["last_action"] = "config"
    return "ok"


@app.route("/token/config", methods=["POST"])
@token_auth.login_required
def token_guarded():
    # @token_auth.login_required -> AUTHENTICATION via HTTPTokenAuth.
    session["last_action"] = "config"
    return "ok"


@app.route("/unguarded", methods=["POST"])
def unguarded():
    # No guard decorator -> a genuine coverage gap; coverage rules MUST still
    # fire here (the false-negative guard for this whole feature).
    session["last_action"] = "config"
    return "ok"


class _NotAuth:
    """A project object that merely happens to expose a ``login_required`` name."""

    def login_required(self, view):
        return view


notauth = _NotAuth()


@app.route("/lookalike", methods=["POST"])
@notauth.login_required
def lookalike_guarded():
    # @notauth.login_required is a local no-op, NOT flask_httpauth: its receiver
    # types to _NotAuth, so the provider check must NOT match -> this route stays
    # unguarded and a coverage rule MUST still fire (no over-recognition = no FN).
    session["last_action"] = "config"
    return "ok"
