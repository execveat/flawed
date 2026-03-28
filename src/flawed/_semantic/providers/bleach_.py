"""Bleach provider -- HTML sanitization guards and flow propagation.

Bleach is a security-focused HTML sanitizer.  Its primary function,
``bleach.clean()``, strips disallowed tags, attributes, and protocols
from HTML fragments to prevent XSS.  ``bleach.linkify()`` safely
converts URL-like strings to links.

Both the module-level convenience functions and the class-based
``Cleaner``/``Linker`` APIs are covered.

Note: bleach is deprecated in favor of ``nh3``, but remains widely
used in existing codebases.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    FlowPropagatorPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class BleachProvider(Provider):
    meta = ProviderMeta(
        id="bleach",
        name="Bleach",
        version="0.1.0",
        library="bleach",
        library_fqn="bleach",
    )

    # =================================================================
    # Security checks: XSS sanitization
    # =================================================================

    checks = (
        # -- Module-level convenience functions --------------------------
        SecurityCheckPattern(
            fqn="bleach.clean",
            kind=CheckKind.CALL,
            category="XSS_SANITIZATION",
            description="Strips disallowed HTML tags/attributes/protocols",
        ),
        SecurityCheckPattern(
            fqn="bleach.linkify",
            kind=CheckKind.CALL,
            category="XSS_SANITIZATION",
            description="Safely converts URL-like strings to anchor tags",
        ),
        # -- Class-based API ---------------------------------------------
        SecurityCheckPattern(
            fqn="bleach.sanitizer.Cleaner.clean",
            kind=CheckKind.METHOD_CALL,
            category="XSS_SANITIZATION",
            description="Instance-based HTML sanitization (reusable config)",
        ),
        SecurityCheckPattern(
            fqn="bleach.linkifier.Linker.linkify",
            kind=CheckKind.METHOD_CALL,
            category="XSS_SANITIZATION",
            description="Instance-based URL linkification (reusable config)",
        ),
    )

    # =================================================================
    # Flow propagation: taint survives sanitization (attenuated)
    # =================================================================

    propagators = (
        # User input flows through clean() to sanitized output.
        # The output is safer but still user-derived -- taint propagates
        # so downstream rules can see the data origin.
        FlowPropagatorPattern(
            fqn="bleach.clean",
            input_arg=0,
            output="return",
            description="Input HTML flows through sanitizer to cleaned output",
        ),
        FlowPropagatorPattern(
            fqn="bleach.linkify",
            input_arg=0,
            output="return",
            description="Input text flows through linkifier to linked output",
        ),
        FlowPropagatorPattern(
            fqn="bleach.sanitizer.Cleaner.clean",
            input_arg=0,
            output="return",
            description="Input HTML flows through Cleaner to cleaned output",
        ),
        FlowPropagatorPattern(
            fqn="bleach.linkifier.Linker.linkify",
            input_arg=0,
            output="return",
            description="Input text flows through Linker to linked output",
        ),
    )
