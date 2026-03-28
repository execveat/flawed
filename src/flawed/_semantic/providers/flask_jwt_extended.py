"""flask-jwt-extended provider -- JWT authentication for Flask.

Provides decorator-based route protection, token creation, claims
access, and cookie-based token transport.

Security-relevant patterns:

- ``@jwt_required()`` decorator is the primary security guard.
  Variants: ``fresh=True`` (requires fresh auth), ``optional=True``
  (allows unauthenticated access).
- ``get_jwt_identity()`` / ``get_jwt()`` return attacker-controlled
  claims from the decoded JWT.  These are input sources.
- ``create_access_token()`` / ``create_refresh_token()`` produce
  signed tokens (state writes).
- ``set_access_cookies()`` / ``unset_jwt_cookies()`` manipulate
  response cookies (response writes).

FQNs: The public API re-exports from submodules.  Users import from
``flask_jwt_extended`` but actual definitions live in:
- ``flask_jwt_extended.view_decorators`` (``jwt_required``, ``verify_jwt_in_request``)
- ``flask_jwt_extended.utils`` (``get_jwt``, ``create_access_token``, etc.)
- ``flask_jwt_extended.jwt_manager`` (``JWTManager``)
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    EffectCallPattern,
    FlowPropagatorPattern,
    HookType,
    InputMethodPattern,
    LifecycleRegistrationPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
    StateProxyPattern,
)


class FlaskJWTExtendedProvider(Provider):
    meta = ProviderMeta(
        id="flask-jwt-extended",
        name="Flask-JWT-Extended",
        version="0.1.0",
        library="Flask-JWT-Extended",
        library_fqn="flask_jwt_extended",
    )

    # =================================================================
    # Lifecycle: JWTManager initialization
    # =================================================================

    lifecycle = (
        LifecycleRegistrationPattern(
            registration_fqn="flask_jwt_extended.jwt_manager.JWTManager.init_app",
            hook_type=HookType.BEFORE_HANDLER,
            description="Register JWT error handlers and request hooks",
        ),
    )

    # =================================================================
    # Security checks: JWT verification decorators
    # =================================================================

    checks = (
        # @jwt_required() -- primary authentication guard
        SecurityCheckPattern(
            fqn="flask_jwt_extended.view_decorators.jwt_required",
            kind=CheckKind.DECORATOR,
            category="AUTHENTICATION",
            description="Require valid JWT in request (cookie, header, query, or JSON)",
        ),
        # verify_jwt_in_request() -- imperative equivalent
        SecurityCheckPattern(
            fqn="flask_jwt_extended.view_decorators.verify_jwt_in_request",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="Imperatively verify JWT (called by jwt_required)",
        ),
    )

    # =================================================================
    # Input sources: JWT claims access
    # =================================================================

    inputs = (
        # get_jwt() returns the full decoded claims dict
        InputMethodPattern(
            fqn="flask_jwt_extended.utils.get_jwt",
            source_type="Header",
            cardinality="SINGLE",
            description="Full decoded JWT claims dict (attacker-controlled)",
        ),
        # get_jwt_identity() returns the 'sub' claim
        InputMethodPattern(
            fqn="flask_jwt_extended.utils.get_jwt_identity",
            source_type="Header",
            cardinality="SINGLE",
            description="JWT identity claim (attacker-controlled 'sub' field)",
        ),
        # get_jwt_header() returns the token header
        InputMethodPattern(
            fqn="flask_jwt_extended.utils.get_jwt_header",
            source_type="Header",
            cardinality="SINGLE",
            description="JWT header dict (alg, typ, kid -- partially attacker-controlled)",
        ),
    )

    # =================================================================
    # Effects: token creation and cookie management
    # =================================================================

    effects = (
        # Token creation
        EffectCallPattern(
            fqn="flask_jwt_extended.utils.create_access_token",
            category="STATE_WRITE",
            scope="SESSION",
            description="Create signed JWT access token",
        ),
        EffectCallPattern(
            fqn="flask_jwt_extended.utils.create_refresh_token",
            category="STATE_WRITE",
            scope="SESSION",
            description="Create signed JWT refresh token",
        ),
        # Cookie-based token transport
        EffectCallPattern(
            fqn="flask_jwt_extended.utils.set_access_cookies",
            category="RESPONSE_WRITE",
            description="Set access token cookie on response",
        ),
        EffectCallPattern(
            fqn="flask_jwt_extended.utils.set_refresh_cookies",
            category="RESPONSE_WRITE",
            description="Set refresh token cookie on response",
        ),
        EffectCallPattern(
            fqn="flask_jwt_extended.utils.unset_jwt_cookies",
            category="RESPONSE_WRITE",
            description="Remove all JWT cookies from response",
        ),
        EffectCallPattern(
            fqn="flask_jwt_extended.utils.unset_access_cookies",
            category="RESPONSE_WRITE",
            description="Remove access token cookie from response",
        ),
        EffectCallPattern(
            fqn="flask_jwt_extended.utils.unset_refresh_cookies",
            category="RESPONSE_WRITE",
            description="Remove refresh token cookie from response",
        ),
    )

    # =================================================================
    # State proxies
    # =================================================================

    proxies = (
        StateProxyPattern(
            fqn="flask_jwt_extended.utils.get_current_user",
            resolves_to="flask.g._jwt_extended_jwt_user",
            scope="REQUEST",
            description="Current user loaded from JWT identity via user_lookup_loader",
        ),
    )

    # =================================================================
    # Flow propagation
    # =================================================================

    propagators = (
        # Identity flows into access token
        FlowPropagatorPattern(
            fqn="flask_jwt_extended.utils.create_access_token",
            input_arg=0,
            output="return",
            description="Identity and claims flow into signed access token",
        ),
        # Identity flows into refresh token
        FlowPropagatorPattern(
            fqn="flask_jwt_extended.utils.create_refresh_token",
            input_arg=0,
            output="return",
            description="Identity flows into signed refresh token",
        ),
    )
