"""Flask app: user-scoped self-service writes (FLAW-168).

After FLAW-127 recognized in-body authorization guards, c02a's largest
residual false-positive class on a real corpus is *self-service* routes:
a logged-in user mutating only resources scoped to their own identity
(``ApiToken(user_id=current_user.id)``, ``...filter_by(user_id=current_user.id)``).
Such a write needs only AUTHENTICATION — ownership scoping makes authorization
implicit, so demanding an explicit AUTHORIZATION check is a false positive.

The discriminator is a *positive ownership binding to the principal*: an owner
field (``user_id``/``owner_id``/...) bound to the request principal
(``current_user``/``g.user``/``request.user``).  A write whose target is a
request-supplied id (IDOR) or a global record carries no such binding and must
still be flagged — those are the false-negative guards below.
"""

from flask import Flask, g, jsonify, request
from flask_login import current_user, login_required
from sqlalchemy.orm import Session as SaSession

app = Flask(__name__)


class ApiToken:  # noqa: D101 - fixture model, analyzed statically (never imported)
    pass


class User:  # noqa: D101
    pass


class SiteConfig:  # noqa: D101
    pass


@app.route("/tokens/create", methods=["POST"])
@login_required
def create_token():
    """Self-service: constructs a row owned by the principal, then writes it.

    Ownership binding ``user_id=current_user.id`` is in the constructor call.
    AUTHENTICATION (``@login_required``) + principal-owned write → a principal-write authorization rule must
    NOT fire.
    """
    db_session = g.db_session  # type: SaSession
    token = ApiToken(user_id=current_user.id, name=request.form["name"])
    db_session.add(token)
    db_session.commit()
    return jsonify({"ok": True})


@app.route("/tokens/revoke", methods=["POST"])
@login_required
def revoke_my_token():
    """Self-service delete scoped by owner — even though a request id is present.

    ``filter_by(user_id=current_user.id, id=...)`` binds the owner to the
    principal, so the request-supplied ``id`` can only ever match the user's
    OWN row.  Ownership scoping defeats IDOR; a principal-write authorization rule must NOT fire despite the
    request-derived id.
    """
    db_session = g.db_session  # type: SaSession
    token = (
        db_session.query(ApiToken)
        .filter_by(user_id=current_user.id, id=request.form["tid"])
        .first()
    )
    db_session.delete(token)
    db_session.commit()
    return jsonify({"ok": True})


@app.route("/users/promote", methods=["POST"])
@login_required
def promote_user():
    """IDOR / privilege write: target chosen by a request id, no owner binding.

    Only AUTHENTICATION, and the write targets an arbitrary user's row keyed by
    request input — a principal-write authorization rule MUST still fire (false-negative guard).
    """
    db_session = g.db_session  # type: SaSession
    target = db_session.query(User).filter_by(id=request.form["uid"]).first()
    target.is_admin = True
    db_session.add(target)
    db_session.commit()
    return jsonify({"ok": True})


@app.route("/admin/site-config", methods=["POST"])
@login_required
def set_site_config():
    """Global config write: no principal ownership binding at all.

    A logged-in user mutating a global record needs AUTHORIZATION — a principal-write authorization rule MUST
    still fire (false-negative guard for global/server state).
    """
    db_session = g.db_session  # type: SaSession
    setting = db_session.query(SiteConfig).filter_by(key="registration_open").first()
    setting.value = request.form["value"]
    db_session.add(setting)
    db_session.commit()
    return jsonify({"ok": True})
