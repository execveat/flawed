"""SQLModel provider -- SQLAlchemy + Pydantic hybrid ORM.

SQLModel is a thin layer over SQLAlchemy and Pydantic.  Most database
effects delegate to the sqlalchemy provider (same FQNs).  This
provider covers SQLModel-specific patterns: its own Session subclass,
model validation, and select() helper.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    EffectCallPattern,
    FlowPropagatorPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
    arg,
)


class SQLModelProvider(Provider):
    meta = ProviderMeta(
        id="sqlmodel",
        name="SQLModel",
        version="0.1.0",
        library="sqlmodel",
        library_fqn="sqlmodel",
    )

    # =================================================================
    # EP-4: Security checks -- Pydantic validation inherited
    # =================================================================

    checks = (
        SecurityCheckPattern(
            fqn="sqlmodel.main.SQLModel.model_validate",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Validate data against SQLModel schema (Pydantic)",
        ),
        SecurityCheckPattern(
            fqn="sqlmodel.main.SQLModel.model_validate_json",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Parse JSON and validate against SQLModel schema",
        ),
    )

    # =================================================================
    # EP-3: Effects -- SQLModel Session (thin wrapper over SA Session)
    # =================================================================

    effects = (
        EffectCallPattern(
            fqn="sqlmodel.session.Session.add",
            category="DB_WRITE",
            description="Stage SQLModel instance for INSERT",
        ),
        EffectCallPattern(
            fqn="sqlmodel.session.Session.commit",
            category="DB_WRITE",
            description="Flush pending changes to database",
        ),
        EffectCallPattern(
            fqn="sqlmodel.session.Session.flush",
            category="DB_WRITE",
            description="Write pending changes within transaction",
        ),
        EffectCallPattern(
            fqn="sqlmodel.session.Session.delete",
            category="DB_DELETE",
            description="Stage SQLModel instance for DELETE",
        ),
        EffectCallPattern(
            fqn="sqlmodel.session.Session.rollback",
            category="STATE_WRITE",
            description="Rollback current transaction",
        ),
        EffectCallPattern(
            fqn="sqlmodel.session.Session.refresh",
            category="DB_READ",
            description="Refresh instance from database",
        ),
        # Session.get retrieves by primary key
        EffectCallPattern(
            fqn="sqlmodel.session.Session.get",
            category="DB_READ",
            description="Primary key lookup",
        ),
        # Session.exec runs a select statement
        EffectCallPattern(
            fqn="sqlmodel.session.Session.exec",
            category="DB_READ",
            description="Execute a select statement and return results",
        ),
        # Session.execute with DML type discrimination (same as SQLAlchemy)
        EffectCallPattern(
            fqn="sqlmodel.session.Session.execute",
            category="DB_WRITE",
            when=arg(0).type_in(
                "sqlalchemy.sql.dml.Insert",
                "sqlalchemy.sql.dml.Update",
            ),
            description="Execute DML statement (INSERT/UPDATE)",
        ),
        EffectCallPattern(
            fqn="sqlmodel.session.Session.execute",
            category="DB_DELETE",
            when=arg(0).type_is("sqlalchemy.sql.dml.Delete"),
            description="Execute DML statement (DELETE)",
        ),
        EffectCallPattern(
            fqn="sqlmodel.session.Session.execute",
            category="DB_READ",
            when=arg(0).type_is("sqlalchemy.sql.selectable.Select"),
            description="Execute SELECT statement",
        ),
    )

    # =================================================================
    # EP-8: Flow propagation
    # =================================================================

    propagators = (
        FlowPropagatorPattern(
            fqn="sqlmodel.session.Session.get",
            input_arg=0,
            output="return",
            description="Model class + PK flows through to loaded instance",
        ),
        FlowPropagatorPattern(
            fqn="sqlmodel.session.Session.exec",
            input_arg=0,
            output="return",
            description="Select statement flows through to result set",
        ),
        FlowPropagatorPattern(
            fqn="sqlmodel.main.SQLModel.model_validate",
            input_arg=0,
            output="return",
            description="Input data flows through validation to model instance",
        ),
    )
