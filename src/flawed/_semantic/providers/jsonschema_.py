"""jsonschema provider -- JSON Schema validation guards.

``jsonschema`` validates Python objects against JSON Schema documents.
The convenience function ``jsonschema.validate()`` and the per-draft
validator classes (``Draft7Validator``, ``Draft202012Validator``, etc.)
all act as schema validation security checks.

When a schema is enforced, it constrains the shape and types of input
data, reducing the attack surface for injection and type-mismatch
vulnerabilities.

Key FQN note: the validator classes are dynamically created by
``jsonschema.validators.create()`` and assigned to module-level names
in ``jsonschema.validators``.  The convenience ``validate()`` function
lives at ``jsonschema.validators.validate`` but is re-exported from
``jsonschema.__init__``.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class JsonSchemaProvider(Provider):
    meta = ProviderMeta(
        id="jsonschema",
        name="jsonschema",
        version="0.1.0",
        library="jsonschema",
        library_fqn="jsonschema",
    )

    # =================================================================
    # Security checks: schema validation
    # =================================================================

    checks = (
        # -- Module-level convenience function ---------------------------
        SecurityCheckPattern(
            fqn="jsonschema.validators.validate",
            kind=CheckKind.CALL,
            category="SCHEMA_VALIDATION",
            description="Validate instance against JSON Schema (raises on failure)",
        ),
        # -- Draft202012Validator (latest, recommended) ------------------
        SecurityCheckPattern(
            fqn="jsonschema.validators.Draft202012Validator.validate",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Draft 2020-12 schema validation (raises on failure)",
        ),
        SecurityCheckPattern(
            fqn="jsonschema.validators.Draft202012Validator.is_valid",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Draft 2020-12 schema validation (returns bool)",
        ),
        # -- Draft201909Validator ----------------------------------------
        SecurityCheckPattern(
            fqn="jsonschema.validators.Draft201909Validator.validate",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Draft 2019-09 schema validation (raises on failure)",
        ),
        SecurityCheckPattern(
            fqn="jsonschema.validators.Draft201909Validator.is_valid",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Draft 2019-09 schema validation (returns bool)",
        ),
        # -- Draft7Validator (most widely used) --------------------------
        SecurityCheckPattern(
            fqn="jsonschema.validators.Draft7Validator.validate",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Draft 7 schema validation (raises on failure)",
        ),
        SecurityCheckPattern(
            fqn="jsonschema.validators.Draft7Validator.is_valid",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Draft 7 schema validation (returns bool)",
        ),
        # -- Draft6Validator ---------------------------------------------
        SecurityCheckPattern(
            fqn="jsonschema.validators.Draft6Validator.validate",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Draft 6 schema validation (raises on failure)",
        ),
        SecurityCheckPattern(
            fqn="jsonschema.validators.Draft6Validator.is_valid",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Draft 6 schema validation (returns bool)",
        ),
        # -- Draft4Validator (legacy, still common) ----------------------
        SecurityCheckPattern(
            fqn="jsonschema.validators.Draft4Validator.validate",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Draft 4 schema validation (raises on failure)",
        ),
        SecurityCheckPattern(
            fqn="jsonschema.validators.Draft4Validator.is_valid",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Draft 4 schema validation (returns bool)",
        ),
        # -- Draft3Validator (very legacy) -------------------------------
        SecurityCheckPattern(
            fqn="jsonschema.validators.Draft3Validator.validate",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Draft 3 schema validation (raises on failure)",
        ),
        SecurityCheckPattern(
            fqn="jsonschema.validators.Draft3Validator.is_valid",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Draft 3 schema validation (returns bool)",
        ),
        # -- FormatChecker -----------------------------------------------
        SecurityCheckPattern(
            fqn="jsonschema._format.FormatChecker.check",
            kind=CheckKind.METHOD_CALL,
            category="FORMAT_VALIDATION",
            description="Validate instance conforms to a declared format",
        ),
        SecurityCheckPattern(
            fqn="jsonschema._format.FormatChecker.conforms",
            kind=CheckKind.METHOD_CALL,
            category="FORMAT_VALIDATION",
            description="Check format conformance (returns bool)",
        ),
    )

    # =================================================================
    # Flow propagation
    # =================================================================
    #
    # jsonschema.validate() does NOT return the validated data -- it
    # returns None on success and raises ValidationError on failure.
    # Therefore there is no meaningful flow propagation through the
    # validate() call itself.
    #
    # However, the *pattern* matters: if validate(data, schema)
    # succeeds, subsequent use of `data` is implicitly validated.
    # This is a "gate" pattern (pass/raise), not a transform.
    # The engine handles gate patterns via SecurityCheckPattern --
    # no FlowPropagatorPattern needed here.
