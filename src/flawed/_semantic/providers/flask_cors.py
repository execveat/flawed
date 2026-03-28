"""flask-cors provider -- CORS middleware configuration.

Covers the ``Flask-CORS`` extension: app-wide CORS via ``CORS(app)``
or ``CORS.init_app(app)``, and per-route CORS via the
``@cross_origin()`` decorator.

Both patterns relax the browser same-origin policy, which is a
``CONFIG_WRITE`` at ``SERVER`` scope -- it changes security posture
for all clients.

FQN note: ``CORS`` lives in ``flask_cors.extension``.
``cross_origin`` lives in ``flask_cors.decorator``.
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


class FlaskCorsProvider(Provider):
    meta = ProviderMeta(
        id="flask-cors",
        name="Flask-CORS",
        version="0.1.0",
        library="Flask-CORS",
        library_fqn="flask_cors",
    )

    # =================================================================
    # Lifecycle: CORS registers an after_request hook
    # =================================================================

    lifecycle = (
        LifecycleRegistrationPattern(
            registration_fqn="flask_cors.extension.CORS.init_app",
            hook_type=HookType.AFTER_HANDLER,
            description="Registers CORS after_request hook to inject Access-Control headers",
        ),
    )

    # =================================================================
    # Effects: CORS configuration relaxes same-origin policy
    # =================================================================

    effects = (
        # App-wide: CORS(app, ...) constructor
        EffectCallPattern(
            fqn="flask_cors.extension.CORS.__init__",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="App-wide CORS -- relaxes same-origin policy for all routes",
        ),
        # App-wide: CORS.init_app(app, ...)
        EffectCallPattern(
            fqn="flask_cors.extension.CORS.init_app",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="App-wide CORS via init_app -- relaxes same-origin policy",
        ),
    )

    # =================================================================
    # Security checks: @cross_origin() as a per-route guard modifier
    # =================================================================

    checks = (
        SecurityCheckPattern(
            fqn="flask_cors.decorator.cross_origin",
            kind=CheckKind.DECORATOR,
            category="CORS",
            description="Per-route CORS decorator -- relaxes same-origin for this endpoint",
        ),
    )
