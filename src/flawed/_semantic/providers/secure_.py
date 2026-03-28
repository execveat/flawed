"""secure.py provider -- Security headers for Python web frameworks.

The ``Secure`` class sets security headers (CSP, HSTS, X-Frame-Options,
etc.) on HTTP responses.  Framework-agnostic -- works via WSGI/ASGI
middleware or explicit ``set_headers()`` calls.
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


class SecurePyProvider(Provider):
    meta = ProviderMeta(
        id="secure-py",
        name="secure.py",
        version="0.1.0",
        library="secure",
        library_fqn="secure",
    )

    # -- Security checks -------------------------------------------------

    checks = (
        SecurityCheckPattern(
            fqn="secure.secure.Secure.__init__",
            kind=CheckKind.CALL,
            category="SECURITY_HEADERS",
            description="Configure security headers (CSP, HSTS, X-Frame-Options, etc.)",
        ),
    )

    # -- Effects ---------------------------------------------------------

    effects = (
        # set_headers applies configured headers to a response object
        EffectCallPattern(
            fqn="secure.secure.Secure.set_headers",
            category="RESPONSE_WRITE",
            description="Apply security headers to response",
        ),
        EffectCallPattern(
            fqn="secure.secure.Secure.set_headers_async",
            category="RESPONSE_WRITE",
            description="Apply security headers to response (async)",
        ),
        # Individual header constructors are CONFIG_WRITE (server-wide policy)
        EffectCallPattern(
            fqn="secure.headers.content_security_policy.ContentSecurityPolicy.__init__",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Define Content-Security-Policy header value",
        ),
        EffectCallPattern(
            fqn="secure.headers.strict_transport_security.StrictTransportSecurity.__init__",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Define Strict-Transport-Security header value",
        ),
        EffectCallPattern(
            fqn="secure.headers.x_frame_options.XFrameOptions.__init__",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Define X-Frame-Options header value",
        ),
        EffectCallPattern(
            fqn="secure.headers.referrer_policy.ReferrerPolicy.__init__",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Define Referrer-Policy header value",
        ),
        EffectCallPattern(
            fqn="secure.headers.permissions_policy.PermissionsPolicy.__init__",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Define Permissions-Policy header value",
        ),
        EffectCallPattern(
            fqn="secure.headers.cache_control.CacheControl.__init__",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Define Cache-Control header value",
        ),
        EffectCallPattern(
            fqn="secure.headers.cross_origin_opener_policy.CrossOriginOpenerPolicy.__init__",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Define Cross-Origin-Opener-Policy header value",
        ),
        EffectCallPattern(
            fqn="secure.headers.cross_origin_resource_policy.CrossOriginResourcePolicy.__init__",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Define Cross-Origin-Resource-Policy header value",
        ),
        EffectCallPattern(
            fqn="secure.headers.cross_origin_embedder_policy.CrossOriginEmbedderPolicy.__init__",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Define Cross-Origin-Embedder-Policy header value",
        ),
    )

    # -- Lifecycle: WSGI/ASGI middleware ---------------------------------

    lifecycle = (
        LifecycleRegistrationPattern(
            registration_fqn="secure.middleware.wsgi.SecureWSGIMiddleware.__init__",
            hook_type=HookType.AFTER_HANDLER,
            description="WSGI middleware applying security headers to every response",
        ),
        LifecycleRegistrationPattern(
            registration_fqn="secure.middleware.asgi.SecureASGIMiddleware.__init__",
            hook_type=HookType.AFTER_HANDLER,
            description="ASGI middleware applying security headers to every response",
        ),
    )
