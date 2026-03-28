"""SQLAlchemy ORM provider -- database effects, injection sinks, flow rules.

Covers both the 2.0 style (Session.execute + select/insert/update/delete
constructors) and legacy 1.x Query interface.  Uses ``when=`` predicates
for argument-type-dependent semantics on Session.execute and
Connection.execute.

FQNs verified against SQLAlchemy 2.0.49 source.
"""

from __future__ import annotations

from typing import ClassVar

from flawed._semantic.providers._base import (
    EffectCallPattern,
    FlowPropagatorPattern,
    HookType,
    LifecycleDecoratorPattern,
    Provider,
    ProviderMeta,
    TaintSinkPattern,
    arg,
)


class SQLAlchemyProvider(Provider):
    meta = ProviderMeta(
        id="sqlalchemy",
        name="SQLAlchemy ORM",
        version="0.1.0",
        library="SQLAlchemy",
        library_fqn="sqlalchemy",
        # Flask-SQLAlchemy re-exposes the SQLAlchemy ORM: a pure
        # flask-sqlalchemy app imports only ``flask_sqlalchemy`` yet its
        # ``Model.query`` chains canonicalize to ``sqlalchemy.orm`` FQNs that
        # this provider models. Activate here too so DB effects fire without a
        # direct ``import sqlalchemy`` (FLAW-190).
        activation_imports=("flask_sqlalchemy",),
    )

    fqn_aliases: ClassVar[dict[str, str]] = {
        "sqlalchemy.orm.Query": "sqlalchemy.orm.query.Query",
        "sqlalchemy.orm.Session": "sqlalchemy.orm.session.Session",
        "sqlalchemy.text": "sqlalchemy.sql._elements_constructors.text",
    }

    # =================================================================
    # Effects: Session operations
    # =================================================================

    effects = (
        # -- Session: staging writes ------------------------------------
        EffectCallPattern(
            fqn="sqlalchemy.orm.session.Session.add",
            category="DB_WRITE",
            description="Stage object for INSERT on next flush",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.orm.session.Session.add_all",
            category="DB_WRITE",
            description="Stage multiple objects for INSERT",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.orm.session.Session.merge",
            category="DB_WRITE",
            description="INSERT-or-UPDATE (upsert semantics)",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.orm.session.Session.delete",
            category="DB_DELETE",
            description="Stage object for DELETE on next flush",
        ),
        # -- Session: flush ----------------------------------------------
        EffectCallPattern(
            fqn="sqlalchemy.orm.session.Session.flush",
            category="DB_WRITE",
            description="Write pending to DB within transaction (no commit)",
        ),
        # -- Session/Connection.execute with DML type discrimination ------
        EffectCallPattern(
            fqn=(
                "sqlalchemy.orm.session.Session.execute",
                "sqlalchemy.engine.base.Connection.execute",
            ),
            category="DB_WRITE",
            when=arg(0).type_in(
                "sqlalchemy.sql.dml.Insert",
                "sqlalchemy.sql.dml.Update",
            ),
            description="Direct DML execution (INSERT/UPDATE)",
        ),
        EffectCallPattern(
            fqn=(
                "sqlalchemy.orm.session.Session.execute",
                "sqlalchemy.engine.base.Connection.execute",
            ),
            category="DB_DELETE",
            when=arg(0).type_is("sqlalchemy.sql.dml.Delete"),
            description="Direct DML execution (DELETE)",
        ),
        EffectCallPattern(
            fqn=(
                "sqlalchemy.orm.session.Session.execute",
                "sqlalchemy.engine.base.Connection.execute",
            ),
            category="DB_READ",
            when=arg(0).type_is("sqlalchemy.sql.selectable.Select"),
            description="Query execution (SELECT)",
        ),
        # -- Session: read operations ------------------------------------
        EffectCallPattern(
            fqn="sqlalchemy.orm.session.Session.get",
            category="DB_READ",
            description="Primary key lookup (may hit identity map)",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.orm.session.Session.get_one",
            category="DB_READ",
            description="Primary key lookup (raises if not found)",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.orm.session.Session.scalar",
            category="DB_READ",
            description="Execute and return single scalar value",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.orm.session.Session.scalars",
            category="DB_READ",
            description="Execute and return iterable of scalar values",
        ),
        # -- Session: identity map / object state operations -------------
        EffectCallPattern(
            fqn="sqlalchemy.orm.session.Session.refresh",
            category="DB_READ",
            description="Reload object attributes from database",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.orm.session.Session.expire",
            category="STATE_WRITE",
            scope="SERVER",
            description="Mark attributes as stale (triggers re-read on access)",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.orm.session.Session.expunge",
            category="STATE_WRITE",
            scope="SERVER",
            description="Remove object from session identity map",
        ),
        # -- Transaction control (Session + Connection) ------------------
        EffectCallPattern(
            fqn=(
                "sqlalchemy.orm.session.Session.commit",
                "sqlalchemy.engine.base.Connection.commit",
            ),
            category="DB_WRITE",
            description="Commit current transaction",
        ),
        EffectCallPattern(
            fqn=(
                "sqlalchemy.orm.session.Session.rollback",
                "sqlalchemy.engine.base.Connection.rollback",
            ),
            category="STATE_WRITE",
            scope="SERVER",
            description="Rollback current transaction",
        ),
        # -- Query-level operations (1.x style, still common) -----------
        EffectCallPattern(
            fqn="sqlalchemy.orm.query.Query.update",
            category="DB_WRITE",
            description="Bulk UPDATE with WHERE clause",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.orm.query.Query.delete",
            category="DB_DELETE",
            description="Bulk DELETE with WHERE clause",
        ),
        # -- Query: terminal read methods (1.x) -------------------------
        EffectCallPattern(
            fqn="sqlalchemy.orm.query.Query.first",
            category="DB_READ",
            description="Execute query, return first result or None",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.orm.query.Query.all",
            category="DB_READ",
            description="Execute query, return all results",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.orm.query.Query.one",
            category="DB_READ",
            description="Execute query, return exactly one (raises otherwise)",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.orm.query.Query.one_or_none",
            category="DB_READ",
            description="Execute query, return one or None (raises if >1)",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.orm.query.Query.get",
            category="DB_READ",
            description="Primary key lookup (1.x legacy)",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.orm.query.Query.count",
            category="DB_READ",
            description="Execute COUNT query",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.orm.query.Query.exists",
            category="DB_READ",
            description="Execute EXISTS subquery",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.orm.query.Query.scalar",
            category="DB_READ",
            description="Execute query, return first column of first row",
        ),
        # -- Legacy bulk operations (deprecated in 2.0) -----------------
        EffectCallPattern(
            fqn="sqlalchemy.orm.session.Session.bulk_save_objects",
            category="DB_WRITE",
            description="Legacy bulk save (deprecated in 2.0)",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.orm.session.Session.bulk_insert_mappings",
            category="DB_WRITE",
            description="Legacy bulk insert from dicts",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.orm.session.Session.bulk_update_mappings",
            category="DB_WRITE",
            description="Legacy bulk update from dicts",
        ),
        # -- Engine / pool management ------------------------------------
        EffectCallPattern(
            fqn="sqlalchemy.engine.create.create_engine",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Create database engine (connection configuration)",
        ),
        EffectCallPattern(
            fqn="sqlalchemy.engine.base.Engine.dispose",
            category="STATE_WRITE",
            scope="SERVER",
            description="Dispose connection pool (close all connections)",
        ),
    )

    # =================================================================
    # Injection sinks: SQL injection vectors
    # =================================================================

    sinks = (
        # text() -- the primary SQL injection vector.
        # Public import path: sqlalchemy.text
        # Actual FQN: sqlalchemy.sql._elements_constructors.text
        TaintSinkPattern(
            fqn="sqlalchemy.sql._elements_constructors.text",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Raw SQL string -- injection if user input flows here",
        ),
        # literal_column() -- ALWAYS dangerous with user input
        TaintSinkPattern(
            fqn="sqlalchemy.sql.elements.literal_column",
            arg=0,
            sink_kind="SQL_INJECTION",
            description="Raw column expression rendered verbatim in SQL",
        ),
        # column() -- renders column name verbatim (injection if user-controlled)
        TaintSinkPattern(
            fqn="sqlalchemy.sql._elements_constructors.column",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Column name rendered in SQL (injection if not literal)",
        ),
    )

    # =================================================================
    # Flow propagation: how taint flows through ORM operations
    # =================================================================

    propagators = (
        # Taint flows from object to session when added
        FlowPropagatorPattern(
            fqn="sqlalchemy.orm.session.Session.add",
            input_arg=0,
            output="receiver",
            description="Object taint propagates to session state",
        ),
        # Taint flows from criteria through filter to query result
        FlowPropagatorPattern(
            fqn="sqlalchemy.orm.query.Query.filter",
            input_arg=0,
            output="return",
            description="Filter criteria taint propagates to query result",
        ),
        FlowPropagatorPattern(
            # ``filter_by(**criteria)`` is keyword-only, so a positional
            # ``input_arg=0`` never matched its tainted argument. Every criterion
            # value flows into the query result, so propagate all of them.
            fqn="sqlalchemy.orm.query.Query.filter_by",
            input_arg=None,
            input_variadic=True,
            output="return",
            description="Filter-by kwargs taint propagates to query result",
        ),
        # Result access: taint from execute() result flows through
        # row-fetching methods
        FlowPropagatorPattern(
            fqn="sqlalchemy.engine.result.Result.fetchone",
            input_arg=0,
            output="return",
            description="Taint from result set flows through fetchone()",
        ),
        FlowPropagatorPattern(
            fqn="sqlalchemy.engine.result.Result.fetchall",
            input_arg=0,
            output="return",
            description="Taint from result set flows through fetchall()",
        ),
        FlowPropagatorPattern(
            fqn="sqlalchemy.engine.result.Result.fetchmany",
            input_arg=0,
            output="return",
            description="Taint from result set flows through fetchmany()",
        ),
        FlowPropagatorPattern(
            fqn="sqlalchemy.engine.result.Result.first",
            input_arg=0,
            output="return",
            description="Taint from result set flows through first()",
        ),
        FlowPropagatorPattern(
            fqn="sqlalchemy.engine.result.Result.one",
            input_arg=0,
            output="return",
            description="Taint from result set flows through one()",
        ),
        FlowPropagatorPattern(
            fqn="sqlalchemy.engine.result.Result.scalar",
            input_arg=0,
            output="return",
            description="Taint from result set flows through scalar()",
        ),
        FlowPropagatorPattern(
            fqn="sqlalchemy.engine.result.Result.scalar_one",
            input_arg=0,
            output="return",
            description="Taint from result set flows through scalar_one()",
        ),
        FlowPropagatorPattern(
            fqn="sqlalchemy.engine.result.Result.scalars",
            input_arg=0,
            output="return",
            description="Taint from result set flows through scalars()",
        ),
        FlowPropagatorPattern(
            fqn="sqlalchemy.engine.result.Result.mappings",
            input_arg=0,
            output="return",
            description="Taint from result set flows through mappings()",
        ),
        FlowPropagatorPattern(
            fqn="sqlalchemy.engine.result.Result.all",
            input_arg=0,
            output="return",
            description="Taint from result set flows through all()",
        ),
    )

    # =================================================================
    # Lifecycle: event system
    # =================================================================

    lifecycle = (
        # sqlalchemy.event.listens_for is a decorator that registers
        # event listeners (e.g. @event.listens_for(Session, "before_flush"))
        LifecycleDecoratorPattern(
            fqn="sqlalchemy.event.api.listens_for",
            hook_type=HookType.SIGNAL,
            description="SQLAlchemy event listener decorator (before_flush, etc.)",
        ),
    )
