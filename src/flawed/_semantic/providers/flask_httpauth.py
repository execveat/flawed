"""Flask-HTTPAuth provider -- authentication guard decorators.

Covers the ``@<auth>.login_required`` decorator exposed by every Flask-HTTPAuth
authenticator.  ``login_required`` is defined on the ``HTTPAuth`` base and
inherited by ``HTTPBasicAuth`` / ``HTTPTokenAuth`` / ``HTTPDigestAuth`` /
``HTTPMultiAuth``; real apps instantiate one of those concrete classes at module
scope (``auth = HTTPBasicAuth()``) and decorate handlers with
``@auth.login_required``.

Recognition is by the decorator's **receiver type**: the engine resolves
``auth`` to its constructed class and matches the decorator FQN
``flask_httpauth.HTTPBasicAuth.login_required``.  This is an AUTHENTICATION guard
-- the wrapper authenticates the request and invokes the 401 ``auth_error``
callback when verification fails -- so coverage rules must stop flagging
the routes it decorates as 'missing auth'.

The wrapper body lives in the third-party library, not in the analyzed repo, so
the call-graph auth-inference pass cannot trace its ``abort``/``401`` the way it
does a project-local ``@admins_only``; provider recognition through the receiver
type is the only sound signal.  Because a ``SecurityCheckPattern`` matches by
resolved FQN only (no bare-name escape hatch), a ``login_required`` method on a
non-HTTPAuth object resolves to a different receiver FQN and is never matched --
no over-recognition, hence no false negative on a look-alike decorator.

FQNs verified against Flask-HTTPAuth 4.8.0 source (``login_required`` on the
``HTTPAuth`` base in ``flask_httpauth/__init__.py``).
"""

from __future__ import annotations

from typing import ClassVar

from flawed._semantic.providers._base import (
    CheckKind,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class FlaskHttpAuthProvider(Provider):
    meta = ProviderMeta(
        id="flask-httpauth",
        name="Flask-HTTPAuth",
        version="0.1.0",
        library="Flask-HTTPAuth",
        library_fqn="flask_httpauth",
    )

    # ``login_required`` lives on the ``HTTPAuth`` base; canonicalize every
    # concrete authenticator's inherited reference onto it so a single set of
    # patterns covers all of them regardless of which class is constructed.
    fqn_aliases: ClassVar[dict[str, str]] = {
        "flask_httpauth.HTTPBasicAuth.login_required": "flask_httpauth.HTTPAuth.login_required",
        "flask_httpauth.HTTPTokenAuth.login_required": "flask_httpauth.HTTPAuth.login_required",
        "flask_httpauth.HTTPDigestAuth.login_required": "flask_httpauth.HTTPAuth.login_required",
        "flask_httpauth.HTTPMultiAuth.login_required": "flask_httpauth.HTTPAuth.login_required",
    }

    # =================================================================
    # Security guard decorators
    # =================================================================

    checks = (
        SecurityCheckPattern(
            fqn="flask_httpauth.HTTPAuth.login_required",
            kind=CheckKind.DECORATOR,
            category="AUTHENTICATION",
            description="@<auth>.login_required requires a verified identity (Flask-HTTPAuth)",
        ),
    )
