"""Flask-Talisman provider -- HTTP security headers enforcement.

Covers:
- ``Talisman(app)`` / ``Talisman.init_app(app)`` — lifecycle (installs
  before_request + after_request hooks)
- ``init_app`` configures: CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options, X-XSS-Protection, Referrer-Policy,
  Permissions-Policy, session cookie security
- ``@talisman(frame_options=..., content_security_policy=...)`` —
  per-view security header overrides (decorator)

FQNs verified against Flask-Talisman 0.8.x source.  The ``Talisman``
class lives at ``flask_talisman.Talisman`` and is re-exported
as ``flask_talisman.Talisman``.

Security significance: Talisman is a **hardening** extension.  Its
presence is a positive security signal.  Detection rules should flag:
1. Apps that import Flask but NOT Talisman (missing headers)
2. Per-view overrides that weaken CSP or disable frame protection
3. ``content_security_policy=False`` disabling CSP entirely
"""

from __future__ import annotations

from typing import ClassVar

from flawed._semantic.providers._base import (
    CheckKind,
    EffectCallPattern,
    HookType,
    LifecycleRegistrationPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class FlaskTalismanProvider(Provider):
    meta = ProviderMeta(
        id="flask-talisman",
        name="Flask-Talisman",
        version="0.1.0",
        library="flask-talisman",
        library_fqn="flask_talisman",
    )

    fqn_aliases: ClassVar[dict[str, str]] = {
        "flask_talisman.talisman": "flask_talisman",
    }

    # =================================================================
    # Security checks
    # =================================================================

    checks = (
        # Talisman.__call__(**kwargs) acts as a per-view decorator that
        # can override security headers for a specific view.
        SecurityCheckPattern(
            fqn="flask_talisman.Talisman.__call__",
            kind=CheckKind.DECORATOR,
            category="SECURITY_HEADERS",
            description=(
                "Per-view security header override; may weaken CSP or "
                "frame protection for this view"
            ),
        ),
        SecurityCheckPattern(
            fqn="flask_talisman.Talisman.__call__",
            kind=CheckKind.DECORATOR,
            category="SECURITY_HEADERS",
            description="Per-view security header override (internal path)",
        ),
    )

    # =================================================================
    # Effects: security configuration (CONFIG_WRITE)
    # =================================================================

    effects = (
        # Talisman.init_app configures CSP, HSTS, frame options,
        # session cookie security, etc. at the SERVER scope.
        EffectCallPattern(
            fqn="flask_talisman.Talisman.init_app",
            category="CONFIG_WRITE",
            scope="SERVER",
            description=(
                "Configures HTTP security headers: CSP, HSTS, "
                "X-Frame-Options, X-Content-Type-Options, "
                "Referrer-Policy, session cookie security"
            ),
        ),
        EffectCallPattern(
            fqn="flask_talisman.Talisman.init_app",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Security header configuration (internal path)",
        ),
    )

    # =================================================================
    # Lifecycle registration
    # =================================================================

    lifecycle = (
        # init_app registers both before_request (HTTPS redirect, nonce
        # generation) and after_request (header injection) hooks.
        LifecycleRegistrationPattern(
            registration_fqn="flask_talisman.Talisman.init_app",
            hook_type=HookType.BEFORE_HANDLER,
            description=(
                "Installs HTTPS redirect on before_request and "
                "security header injection on after_request"
            ),
        ),
        LifecycleRegistrationPattern(
            registration_fqn="flask_talisman.Talisman.init_app",
            hook_type=HookType.BEFORE_HANDLER,
            description="Security header lifecycle registration (internal path)",
        ),
    )
