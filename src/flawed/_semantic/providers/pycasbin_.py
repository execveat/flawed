"""PyCasbin provider -- ABAC/RBAC authorization enforcement.

PyCasbin is a model-driven authorization library supporting ACL, RBAC,
ABAC, and other access control models.  The central ``Enforcer`` class
loads a policy model and enforces access decisions via
``enforce(sub, obj, act)``.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    EffectCallPattern,
    FlowPropagatorPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class PyCasbinProvider(Provider):
    meta = ProviderMeta(
        id="pycasbin",
        name="PyCasbin",
        version="0.1.0",
        library="casbin",
        library_fqn="casbin",
    )

    # =================================================================
    # EP-4: Security checks
    # =================================================================

    checks = (
        SecurityCheckPattern(
            fqn="casbin.enforcer.Enforcer.enforce",
            kind=CheckKind.METHOD_CALL,
            category="AUTHORIZATION",
            description="Check if (sub, obj, act) satisfies policy model",
        ),
        SecurityCheckPattern(
            fqn="casbin.enforcer.Enforcer.enforce_ex",
            kind=CheckKind.METHOD_CALL,
            category="AUTHORIZATION",
            description="Enforce with explanation of matched rule",
        ),
        SecurityCheckPattern(
            fqn="casbin.enforcer.Enforcer.batch_enforce",
            kind=CheckKind.METHOD_CALL,
            category="AUTHORIZATION",
            description="Batch enforce multiple (sub, obj, act) tuples",
        ),
    )

    # =================================================================
    # EP-3: Effects -- policy management
    # =================================================================

    effects = (
        # Policy CRUD
        EffectCallPattern(
            fqn="casbin.enforcer.Enforcer.add_policy",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Add a policy rule to the enforcer",
        ),
        EffectCallPattern(
            fqn="casbin.enforcer.Enforcer.add_policies",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Add multiple policy rules",
        ),
        EffectCallPattern(
            fqn="casbin.enforcer.Enforcer.remove_policy",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Remove a policy rule from the enforcer",
        ),
        EffectCallPattern(
            fqn="casbin.enforcer.Enforcer.remove_policies",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Remove multiple policy rules",
        ),
        EffectCallPattern(
            fqn="casbin.enforcer.Enforcer.remove_filtered_policy",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Remove policy rules matching filter",
        ),
        # Role management
        EffectCallPattern(
            fqn="casbin.enforcer.Enforcer.add_role_for_user",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Assign a role to a user",
        ),
        EffectCallPattern(
            fqn="casbin.enforcer.Enforcer.delete_role_for_user",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Remove a role from a user",
        ),
        EffectCallPattern(
            fqn="casbin.enforcer.Enforcer.delete_roles_for_user",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Remove all roles from a user",
        ),
        EffectCallPattern(
            fqn="casbin.enforcer.Enforcer.delete_user",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Delete a user from all roles and policies",
        ),
        EffectCallPattern(
            fqn="casbin.enforcer.Enforcer.delete_role",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Delete a role and all its assignments",
        ),
        # Policy persistence
        EffectCallPattern(
            fqn="casbin.enforcer.Enforcer.load_policy",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Load policy from adapter (file or DB)",
        ),
        EffectCallPattern(
            fqn="casbin.enforcer.Enforcer.save_policy",
            category="FILE_WRITE",
            description="Save current policy to adapter",
        ),
    )

    # =================================================================
    # EP-8: Flow propagation
    # =================================================================

    propagators = (
        FlowPropagatorPattern(
            fqn="casbin.enforcer.Enforcer.enforce_ex",
            input_arg=0,
            output="return",
            description="Subject/object/action flows through to explanation",
        ),
    )
