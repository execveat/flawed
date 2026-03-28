"""Flask-Login provider -- authentication state and guards.

Covers:
- ``@login_required`` and ``@fresh_login_required`` guard decorators
- ``login_user`` / ``logout_user`` / ``confirm_login`` session state
- ``current_user`` proxy resolution to ``g._login_user``
- ``LoginManager.init_app`` lifecycle hook (installs after_request)
- ``LoginManager.user_loader`` / ``request_loader`` dispatch hooks
- ``LoginManager.unauthorized_handler`` dispatch override
- ``set_login_view`` config write (redirect target for unauthenticated)

FQNs verified against Flask-Login 0.6.3 source.  Public API is
re-exported from ``flask_login.utils`` and ``flask_login.login_manager``
via ``fqn_aliases``.
"""

from __future__ import annotations

from typing import ClassVar

from flawed._semantic.providers._base import (
    CheckKind,
    DispatchPattern,
    EffectCallPattern,
    HookType,
    LifecycleRegistrationPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
    StateProxyPattern,
)


class FlaskLoginProvider(Provider):
    meta = ProviderMeta(
        id="flask-login",
        name="Flask-Login",
        version="0.1.0",
        library="Flask-Login",
        library_fqn="flask_login",
    )

    fqn_aliases: ClassVar[dict[str, str]] = {
        "flask_login.utils": "flask_login",
        "flask_login.login_manager": "flask_login",
    }

    # =================================================================
    # Security guard decorators
    # =================================================================

    checks = (
        SecurityCheckPattern(
            fqn="flask_login.login_required",
            kind=CheckKind.DECORATOR,
            category="AUTHENTICATION",
            description="Requires authenticated user (is_authenticated=True)",
        ),
        SecurityCheckPattern(
            fqn="flask_login.fresh_login_required",
            kind=CheckKind.DECORATOR,
            category="AUTHENTICATION_FRESH",
            description="Requires fresh session (not remembered login)",
        ),
    )

    # =================================================================
    # State-writing function calls
    # =================================================================

    effects = (
        EffectCallPattern(
            fqn="flask_login.login_user",
            category="STATE_WRITE",
            scope="SESSION",
            keys=("_user_id", "_fresh", "_id", "_remember"),
            description="Logs user in -- writes auth state to session",
        ),
        EffectCallPattern(
            fqn="flask_login.logout_user",
            category="STATE_WRITE",
            scope="SESSION",
            keys=("_user_id", "_fresh", "_id", "_remember"),
            description="Logs user out -- clears auth state from session",
        ),
        EffectCallPattern(
            fqn="flask_login.confirm_login",
            category="STATE_WRITE",
            scope="SESSION",
            keys=("_fresh", "_id"),
            description="Marks session as freshly authenticated",
        ),
        EffectCallPattern(
            fqn="flask_login.set_login_view",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Sets login view for unauthenticated redirects",
        ),
    )

    # =================================================================
    # State proxies
    # =================================================================

    proxies = (
        StateProxyPattern(
            fqn="flask_login.current_user",
            resolves_to="flask.g._login_user",
            scope="REQUEST",
            description="LocalProxy to g._login_user, loaded from session/cookie",
        ),
    )

    # =================================================================
    # Implicit lifecycle hooks
    # =================================================================

    lifecycle = (
        LifecycleRegistrationPattern(
            registration_fqn="flask_login.LoginManager.init_app",
            hook_type=HookType.AFTER_HANDLER,
            description="Updates remember-me cookie on response",
        ),
    )

    # =================================================================
    # Dispatch patterns
    # =================================================================

    dispatches = (
        DispatchPattern(
            source_fqn="flask_login.LoginManager.user_loader",
            target_method_names=("_user_callback",),
            dispatch_type="callback_registration",
            callback_arg=0,
            invocation_scope="framework_lifecycle",
            hook_type=HookType.BEFORE_HANDLER,
            description="Registers user loader callback invoked per-request",
        ),
        DispatchPattern(
            source_fqn="flask_login.LoginManager.request_loader",
            target_method_names=("_request_callback",),
            dispatch_type="callback_registration",
            callback_arg=0,
            invocation_scope="framework_lifecycle",
            hook_type=HookType.BEFORE_HANDLER,
            description="Registers request-based user loader callback",
        ),
        DispatchPattern(
            source_fqn="flask_login.LoginManager.unauthorized_handler",
            target_method_names=("unauthorized_callback",),
            dispatch_type="callback_registration",
            callback_arg=0,
            invocation_scope="framework_lifecycle",
            hook_type=HookType.ON_ERROR,
            description="Registers custom unauthorized handler callback",
        ),
        DispatchPattern(
            source_fqn="flask_login.LoginManager.needs_refresh_handler",
            target_method_names=("needs_refresh_callback",),
            dispatch_type="callback_registration",
            callback_arg=0,
            invocation_scope="framework_lifecycle",
            hook_type=HookType.ON_ERROR,
            description="Registers custom needs-refresh handler callback",
        ),
    )
