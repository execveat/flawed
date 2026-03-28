"""Flask-Limiter provider -- rate limiting guards and exemptions.

Covers:
- ``@limiter.limit("100/hour")`` rate-limiting decorator on views
- ``@limiter.shared_limit(...)`` shared rate limit across views
- ``@limiter.exempt`` exempts a view/blueprint from all rate limits
- ``Limiter.init_app(app)`` lifecycle registration
- ``limiter.request_filter`` callback registration for request filtering

FQNs verified against Flask-Limiter 3.x source.  The ``Limiter`` class
lives at ``flask_limiter.Limiter`` and is re-exported as
``flask_limiter.Limiter``.
"""

from __future__ import annotations

from typing import ClassVar

from flawed._semantic.providers._base import (
    CheckKind,
    CheckRegistrationPattern,
    DispatchPattern,
    EffectCallPattern,
    HookType,
    LifecycleRegistrationPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class FlaskLimiterProvider(Provider):
    meta = ProviderMeta(
        id="flask-limiter",
        name="Flask-Limiter",
        version="0.1.0",
        library="Flask-Limiter",
        library_fqn="flask_limiter",
    )

    fqn_aliases: ClassVar[dict[str, str]] = {
        "flask_limiter._extension": "flask_limiter",
    }

    # =================================================================
    # Security check decorators (rate limiting guards)
    # =================================================================

    checks = (
        # @limiter.limit("100/hour") — enforces per-route rate limit
        SecurityCheckPattern(
            fqn="flask_limiter.Limiter.limit",
            kind=CheckKind.DECORATOR,
            category="RATE_LIMITING",
            description="Per-route rate limit decorator",
        ),
        # @limiter.shared_limit("100/hour", scope="group")
        SecurityCheckPattern(
            fqn="flask_limiter.Limiter.shared_limit",
            kind=CheckKind.DECORATOR,
            category="RATE_LIMITING",
            description="Shared rate limit across multiple views",
        ),
    )

    # =================================================================
    # Effects: rate limit exemption (CONFIG_WRITE)
    # =================================================================

    effects = (
        # @limiter.exempt — disables rate limiting for a view/blueprint
        EffectCallPattern(
            fqn="flask_limiter.Limiter.exempt",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Exempts view or blueprint from all rate limits",
        ),
    )

    # =================================================================
    # Lifecycle registration
    # =================================================================

    lifecycle = (
        # Limiter.init_app registers before_request + after_request hooks:
        # - before_request: _check_request_limit
        # - after_request: __inject_headers
        LifecycleRegistrationPattern(
            registration_fqn="flask_limiter.Limiter.init_app",
            hook_type=HookType.BEFORE_HANDLER,
            check_category="RATE_LIMITING",
            description=(
                "Installs rate-limit checking on before_request "
                "and header injection on after_request"
            ),
        ),
        # Blueprint-level rate limiting: ``limiter.limit("5/min")(blueprint)``
        #
        # This is a two-stage call: ``limit("5/min")`` returns a decorator,
        # which is then called with the blueprint. L1 records both call sites;
        # the outer call keeps the blueprint as argument 0 and provider
        # matching resolves the registration FQN through the inner decorator
        # factory. Scope the implicit check to that router group instead of
        # falling back to application-global.
        CheckRegistrationPattern(
            registration_fqn=(
                "flask_limiter.Limiter.limit",
                "flask_limiter.Limiter.shared_limit",
            ),
            hook_type=HookType.BEFORE_HANDLER,
            check_category="RATE_LIMITING",
            target_arg=0,
            target_kind="router_group",
            require_call_result_invocation=True,
            description="Blueprint-level rate limit registration",
        ),
    )

    # =================================================================
    # Dispatch patterns
    # =================================================================

    dispatches = (
        # limiter.request_filter registers a callback that is called
        # before evaluating rate limits to decide whether to skip.
        DispatchPattern(
            source_fqn="flask_limiter.Limiter.request_filter",
            target_method_names=("_request_filters",),
            dispatch_type="callback_registration",
            callback_arg=0,
            invocation_scope="framework_lifecycle",
            hook_type=HookType.BEFORE_HANDLER,
            description="Registers a request filter callback for rate limit bypass",
        ),
    )
