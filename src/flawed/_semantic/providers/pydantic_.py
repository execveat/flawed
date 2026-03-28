"""Pydantic provider -- schema validation guards and flow propagation.

Pydantic models enforce structural and type constraints on input data.
From a security perspective:

- ``BaseModel.__init__`` and ``model_validate`` act as schema
  validation guards: if data passes, it conforms to the declared schema.
- ``model_dump`` / ``model_dump_json`` propagate validated data into
  serialized forms (flow propagation, not new input).
- ``validate_call`` wraps function arguments in Pydantic validation,
  acting as an implicit guard on the function's inputs.
- ``TypeAdapter`` provides the same validation without requiring a
  model class.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    FlowPropagatorPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class PydanticProvider(Provider):
    meta = ProviderMeta(
        id="pydantic",
        name="Pydantic",
        version="0.1.0",
        library="pydantic",
        library_fqn="pydantic",
    )

    # =================================================================
    # Security checks: schema validation
    # =================================================================

    checks = (
        # -- BaseModel construction (validates on __init__) --
        SecurityCheckPattern(
            fqn="pydantic.main.BaseModel.__init__",
            kind=CheckKind.CALL,
            category="SCHEMA_VALIDATION",
            description="Pydantic model construction validates all fields",
        ),
        # -- Explicit validation classmethods --
        SecurityCheckPattern(
            fqn="pydantic.main.BaseModel.model_validate",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Validate dict/object against model schema",
        ),
        SecurityCheckPattern(
            fqn="pydantic.main.BaseModel.model_validate_json",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Parse JSON string and validate against model schema",
        ),
        # -- TypeAdapter validation (no model class required) --
        SecurityCheckPattern(
            fqn="pydantic.type_adapter.TypeAdapter.validate_python",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Validate Python object against type annotation",
        ),
        SecurityCheckPattern(
            fqn="pydantic.type_adapter.TypeAdapter.validate_json",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Parse JSON and validate against type annotation",
        ),
        SecurityCheckPattern(
            fqn="pydantic.type_adapter.TypeAdapter.validate_strings",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Validate string-keyed data against type annotation",
        ),
        # -- validate_call decorator --
        SecurityCheckPattern(
            fqn="pydantic.validate_call_decorator.validate_call",
            kind=CheckKind.DECORATOR,
            category="SCHEMA_VALIDATION",
            description="Decorator that validates function arguments via Pydantic",
        ),
    )

    # =================================================================
    # Flow propagation: validated data flows
    # =================================================================

    propagators = (
        # Input data flows through model_validate to the validated model
        FlowPropagatorPattern(
            fqn="pydantic.main.BaseModel.model_validate",
            input_arg=0,
            output="return",
            description="Input data flows through validation to model instance",
        ),
        FlowPropagatorPattern(
            fqn="pydantic.main.BaseModel.model_validate_json",
            input_arg=0,
            output="return",
            description="JSON string flows through validation to model instance",
        ),
        # Model data flows to serialized output
        FlowPropagatorPattern(
            fqn="pydantic.main.BaseModel.model_dump",
            input_arg=0,
            output="return",
            description="Model data flows to dict representation",
        ),
        FlowPropagatorPattern(
            fqn="pydantic.main.BaseModel.model_dump_json",
            input_arg=0,
            output="return",
            description="Model data flows to JSON string representation",
        ),
        # TypeAdapter validation propagation
        FlowPropagatorPattern(
            fqn="pydantic.type_adapter.TypeAdapter.validate_python",
            input_arg=0,
            output="return",
            description="Input flows through TypeAdapter validation to result",
        ),
        FlowPropagatorPattern(
            fqn="pydantic.type_adapter.TypeAdapter.validate_json",
            input_arg=0,
            output="return",
            description="JSON flows through TypeAdapter validation to result",
        ),
    )
