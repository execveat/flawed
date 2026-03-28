"""Flask-Allows provider -- authorization guards.

Covers:
- ``@allows.requires(...)`` authorization decorator (method on ``Allows``)
- ``@requires(...)`` standalone authorization decorator

FQNs verified against flask-allows 0.7.1 source.  Public API is
re-exported from ``flask_allows.allows`` via ``fqn_aliases``.
"""

from __future__ import annotations

from typing import ClassVar

from flawed._semantic.providers._base import (
    CheckKind,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class FlaskAllowsProvider(Provider):
    meta = ProviderMeta(
        id="flask-allows",
        name="Flask-Allows",
        version="0.1.0",
        library="flask-allows",
        library_fqn="flask_allows",
    )

    fqn_aliases: ClassVar[dict[str, str]] = {
        "flask_allows.allows": "flask_allows",
        # flask-allows2 is a common fork (seen in real-world Flask apps) with identical API
        "flask_allows2": "flask_allows",
        "flask_allows2.allows": "flask_allows",
    }

    # =================================================================
    # Security guard decorators
    # =================================================================

    checks = (
        SecurityCheckPattern(
            fqn="flask_allows.Allows.requires",
            kind=CheckKind.DECORATOR,
            category="AUTHORIZATION",
            description="Requires identity to fulfill authorization requirements",
        ),
        SecurityCheckPattern(
            fqn="flask_allows.requires",
            kind=CheckKind.DECORATOR,
            category="AUTHORIZATION",
            description="Standalone decorator requiring authorization requirements",
        ),
    )
