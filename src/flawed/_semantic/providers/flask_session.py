"""Flask-Session provider -- server-side session backends.

Flask-Session replaces Flask's default client-side cookie session
with a server-side backend (Redis, filesystem, MongoDB, SQLAlchemy,
DynamoDB, memcached).  The ``flask.session`` proxy still works
identically -- reads/writes are handled by the Flask core provider.

This provider declares:
- ``Session.init_app`` lifecycle registration (replaces session interface)
- ``ServerSideSessionInterface.regenerate`` as a security-relevant
  state write (session ID regeneration for fixation prevention)
- The before_request cleanup hook installed by non-TTL backends

FQNs verified against Flask-Session 0.8.0 source.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    EffectCallPattern,
    HookType,
    LifecycleRegistrationPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class FlaskSessionProvider(Provider):
    meta = ProviderMeta(
        id="flask-session",
        name="Flask-Session",
        version="0.1.0",
        library="Flask-Session",
        library_fqn="flask_session",
    )

    # =================================================================
    # Lifecycle hooks
    # =================================================================

    lifecycle = (
        # Session.init_app replaces Flask's session_interface with a
        # server-side backend.  This is a critical lifecycle registration
        # that changes how session state is stored and retrieved.
        LifecycleRegistrationPattern(
            registration_fqn="flask_session.Session.init_app",
            hook_type=HookType.BEFORE_HANDLER,
            description="Replaces Flask session interface with server-side backend",
        ),
    )

    # =================================================================
    # Effects: session ID regeneration
    # =================================================================

    effects = (
        # ServerSideSessionInterface.regenerate() generates a new
        # session ID, deletes the old session from storage, and marks
        # the session as modified.  This is the primary defense against
        # session fixation attacks.
        EffectCallPattern(
            fqn="flask_session.base.ServerSideSessionInterface.regenerate",
            category="STATE_WRITE",
            scope="SESSION",
            description="Regenerates session ID (session fixation prevention)",
        ),
    )

    # =================================================================
    # Security checks
    # =================================================================

    checks = (
        # regenerate() also functions as a security check -- calling it
        # indicates the developer is actively defending against session
        # fixation.  Model it as both an effect (STATE_WRITE) and a
        # check (SESSION_FIXATION_PREVENTION).
        SecurityCheckPattern(
            fqn="flask_session.base.ServerSideSessionInterface.regenerate",
            kind=CheckKind.METHOD_CALL,
            category="SESSION_FIXATION_PREVENTION",
            description="Session ID regeneration (anti-fixation measure)",
        ),
    )
