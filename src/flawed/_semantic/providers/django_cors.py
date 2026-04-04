"""django-cors-headers provider -- CORS middleware for Django.

Installs as Django middleware to add Access-Control-* headers.
Security-relevant because it relaxes same-origin policy.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    EffectCallPattern,
    HookType,
    MiddlewareClassPattern,
    Provider,
    ProviderMeta,
)


class DjangoCorsProvider(Provider):
    meta = ProviderMeta(
        id="django-cors-headers",
        name="django-cors-headers",
        version="0.1.0",
        library="django-cors-headers",
        library_fqn="corsheaders",
    )

    # =================================================================
    # EP-3: Effects -- CORS configuration
    # =================================================================

    effects = (
        EffectCallPattern(
            fqn="corsheaders.middleware.CorsMiddleware.__init__",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Install CORS middleware (relaxes same-origin policy)",
        ),
    )

    # =================================================================
    # EP-6: Lifecycle -- middleware class
    # =================================================================

    lifecycle = (
        MiddlewareClassPattern(
            base_class_fqn="corsheaders.middleware.CorsMiddleware",
            method_hooks={
                "process_request": HookType.BEFORE_HANDLER,
                "process_response": HookType.AFTER_HANDLER,
            },
            description="CORS middleware: preflight handling + response headers",
        ),
    )
