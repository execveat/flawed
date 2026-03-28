"""Fixture app: presence-vs-validity credential derivation divergence.

A GENERIC internal-API app (not a copy of any real repo) exhibiting the
presence-vs-validity divergence pattern:

- the same logical credential is resolved across multiple request containers,
- one helper authenticates by *presence* (predicate produced as a return value),
- the authoritative loader authenticates by *validation + principal binding*,
- a lifecycle hook performs a control-plane mutation (``csrf.exempt``) gated on
  the weak presence derivation,
- a state-changing route is reachable from both derivations.

These are the four gadgets G1–G4 plus the lifecycle effect.  No identifiers are
borrowed from any specific application; the shapes are intentionally typical of
token-authenticated Flask apps.
"""

from __future__ import annotations

import hashlib

from flask import Flask, jsonify, request
from flask_wtf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect()
csrf.init_app(app)


class ApiToken:
    """Stand-in ORM model for a stored API token."""

    query: object  # SQLAlchemy-style query attribute (provider-modeled)

    def is_valid(self) -> bool:
        """Whether the token is unexpired and unrevoked."""
        return True

    account: object


class Settings:
    """Stand-in ORM model for per-account settings."""

    query: object
    theme: str


class _Session:
    def commit(self) -> None: ...


class _Db:
    session = _Session()


db = _Db()


def extract_credential() -> str | None:
    """Resolve an API token across several request containers (G1).

    Source precedence: Authorization Bearer, then X-Api-Token header, then a
    ``token`` query parameter.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]

    header_token = request.headers.get("X-Api-Token")
    if header_token:
        return header_token

    return request.args.get("token")


def credential_present() -> bool:
    """Presence-only derivation (G2).

    The security-relevant predicate is produced as a RETURN VALUE, not an
    ``if`` test, so the current ``conditions()`` lifter never sees it.  Any
    token-shaped value satisfies this; no value is validated.
    """
    token = extract_credential()
    return token is not None


def load_principal() -> object | None:
    """Validated, principal-binding derivation (G4).

    Extract -> hash -> database lookup -> ``is_valid()`` -> bound account.
    This is the authoritative authentication that ``credential_present`` does
    not perform.
    """
    token = extract_credential()
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    record = ApiToken.query.filter_by(token_hash=token_hash).first()
    if record is None or not record.is_valid():
        return None
    return record.account


@app.before_request
def exempt_when_credential_present() -> None:
    """Lifecycle control-plane mutation gated on the weak derivation (G3).

    When a token-shaped value is merely present, the current endpoint's CSRF
    protection is disabled for ALL subsequent requests -- a per-request
    decision mutating a global control.
    """
    if credential_present():
        view_func = app.view_functions[request.endpoint]
        csrf.exempt(view_func)


@app.route("/settings", methods=["POST"])
def update_settings() -> object:
    """State-changing route reachable from both derivations."""
    account = load_principal()
    if account is None:
        return jsonify({"error": "unauthorized"}), 401
    new_theme = request.form.get("theme")
    settings = Settings.query.filter_by(account_id=account.id).first()
    settings.theme = new_theme
    db.session.commit()
    return jsonify({"ok": True})
