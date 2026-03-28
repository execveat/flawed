"""Routes guarded by custom decorators imported cross-module, plus an
unguarded control route.

Mirrors a real app: ``@admins_only`` (abort 403 + login redirect -> AUTHORIZATION
*and* AUTHENTICATION) and ``@authed_only`` (login redirect only ->
AUTHENTICATION).  ``scope.checks()`` on the guarded routes must expose the
inferred guard so authorization-coverage rules stop firing on them,
while the unguarded route must still be flagged (no false negative).
"""

from flask import Flask, session

from .decorators import admins_only, authed_only

app = Flask(__name__)


@app.route("/admin/config", methods=["POST"])
@admins_only
def admin_set_config():
    # SESSION write -> a principal-write authorization rule needs AUTHENTICATION coverage. @admins_only both
    # aborts(403) (authz) AND redirects to login (authn); it must expose BOTH
    # categories.  Under the mono-category bug it exposed only AUTHORIZATION,
    # so a principal-write authorization rule false-flagged this route for "missing AUTHENTICATION".
    session["last_admin_action"] = "config"
    return "ok"


@app.route("/me/settings", methods=["POST"])
@authed_only
def update_settings():
    # @authed_only only redirects to login -> AUTHENTICATION only (correct).
    # The fix must NOT over-broaden it to AUTHORIZATION.
    session["pref"] = "changed"
    return "ok"


@app.route("/admin/danger", methods=["POST"])
def admin_unguarded():
    # No guard decorator -> genuine coverage gap; coverage rules MUST still
    # fire (false-negative guard).
    session["danger"] = "changed"
    return "ok"
