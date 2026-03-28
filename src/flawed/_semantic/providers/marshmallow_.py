"""Marshmallow provider -- object serialization and validation.

Marshmallow provides ``Schema``-based serialization (``dump``) and
deserialization with validation (``load``).  It is widely used as the
validation layer for Flask APIs (via flask-marshmallow, webargs, or
direct usage).

Key patterns:
- ``Schema.load`` -- deserializes + validates input (security check + input source)
- ``Schema.loads`` -- JSON string deserialization + validation
- ``Schema.dump`` -- serializes output (flow propagation)
- ``Schema.validate`` -- validation only (security check, no deserialization)
- ``@validates`` / ``@validates_schema`` -- custom field/schema validators
- ``@pre_load`` / ``@post_load`` -- deserialization hooks (flow propagation)

DSL fitness: Fully declarative.  SecurityCheckPattern for validation,
FlowPropagatorPattern for data flow through serialization/deserialization.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    FlowPropagatorPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class MarshmallowProvider(Provider):
    meta = ProviderMeta(
        id="marshmallow",
        name="Marshmallow",
        version="0.1.0",
        library="marshmallow",
        library_fqn="marshmallow",
    )

    # =================================================================
    # EP-4: Security checks -- validation
    # =================================================================

    checks = (
        # Schema.load: deserialize + validate.  Acts as both a security
        # check (validation) and an input transformer.  If validation
        # fails it raises ValidationError, blocking further processing.
        SecurityCheckPattern(
            fqn="marshmallow.schema.Schema.load",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Deserialize + validate input data against schema fields",
        ),
        # Schema.loads: JSON string → deserialized + validated object
        SecurityCheckPattern(
            fqn="marshmallow.schema.Schema.loads",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Parse JSON string, deserialize, and validate against schema",
        ),
        # Schema.validate: validation only (returns errors dict, no deserialization)
        SecurityCheckPattern(
            fqn="marshmallow.schema.Schema.validate",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Validate data against schema without deserializing",
        ),
        # @validates("field_name") -- custom field-level validator
        SecurityCheckPattern(
            fqn="marshmallow.decorators.validates",
            kind=CheckKind.DECORATOR,
            category="FIELD_VALIDATION",
            description="Custom validator for a specific field",
        ),
        # @validates_schema -- whole-schema cross-field validator
        SecurityCheckPattern(
            fqn="marshmallow.decorators.validates_schema",
            kind=CheckKind.DECORATOR,
            category="SCHEMA_VALIDATION",
            description="Custom cross-field schema-level validator",
        ),
    )

    # =================================================================
    # EP-8: Flow propagation
    # =================================================================

    propagators = (
        # Schema.load: input data flows through validation → deserialized output
        FlowPropagatorPattern(
            fqn="marshmallow.schema.Schema.load",
            input_arg=0,
            output="return",
            description="Input data flows through load() to deserialized object",
        ),
        # Schema.loads: JSON string flows through parsing + validation → output
        FlowPropagatorPattern(
            fqn="marshmallow.schema.Schema.loads",
            input_arg=0,
            output="return",
            description="JSON string flows through loads() to deserialized object",
        ),
        # Schema.dump: object flows through serialization → dict/JSON-ready output
        FlowPropagatorPattern(
            fqn="marshmallow.schema.Schema.dump",
            input_arg=0,
            output="return",
            description="Object data flows through dump() to serialized dict",
        ),
        # Schema.dumps: object flows through serialization → JSON string
        FlowPropagatorPattern(
            fqn="marshmallow.schema.Schema.dumps",
            input_arg=0,
            output="return",
            description="Object data flows through dumps() to JSON string",
        ),
    )
