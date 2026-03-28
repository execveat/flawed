"""Peewee ORM provider -- lightweight Python ORM.

Peewee uses an ActiveRecord pattern where Model subclasses provide
class-level query methods (select, insert, update, delete) and
instance methods (save, delete_instance).  SQL injection vectors
exist via ``fn.SQL()``, ``Model.raw()``, and ``SQL()`` expressions.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    EffectCallPattern,
    FlowPropagatorPattern,
    Provider,
    ProviderMeta,
    TaintSinkPattern,
    arg,
)


class PeeweeProvider(Provider):
    meta = ProviderMeta(
        id="peewee",
        name="Peewee",
        version="0.1.0",
        library="peewee",
        library_fqn="peewee",
    )

    # =================================================================
    # EP-3: Effects -- database operations
    # =================================================================

    effects = (
        # -- Instance-level writes --
        EffectCallPattern(
            fqn="peewee.Model.save",
            category="DB_WRITE",
            description="INSERT or UPDATE the model instance",
        ),
        EffectCallPattern(
            fqn="peewee.Model.delete_instance",
            category="DB_DELETE",
            description="DELETE this model instance from DB",
        ),
        # -- Class-level writes (return queries that execute) --
        EffectCallPattern(
            fqn="peewee.Model.create",
            category="DB_WRITE",
            description="INSERT a new row and return model instance",
        ),
        EffectCallPattern(
            fqn="peewee.Model.bulk_create",
            category="DB_WRITE",
            description="Bulk INSERT multiple model instances",
        ),
        EffectCallPattern(
            fqn="peewee.Model.bulk_update",
            category="DB_WRITE",
            description="Bulk UPDATE multiple model instances",
        ),
        EffectCallPattern(
            fqn="peewee.Model.get_or_create",
            category="DB_WRITE",
            description="Get existing or INSERT new row (read+write)",
        ),
        EffectCallPattern(
            fqn="peewee.Model.replace",
            category="DB_WRITE",
            description="INSERT or REPLACE (upsert)",
        ),
        EffectCallPattern(
            fqn="peewee.Model.replace_many",
            category="DB_WRITE",
            description="Bulk INSERT or REPLACE",
        ),
        # -- Insert queries --
        EffectCallPattern(
            fqn="peewee.Model.insert",
            category="DB_WRITE",
            description="Create INSERT query for single row",
        ),
        EffectCallPattern(
            fqn="peewee.Model.insert_many",
            category="DB_WRITE",
            description="Create bulk INSERT query",
        ),
        EffectCallPattern(
            fqn="peewee.Model.insert_from",
            category="DB_WRITE",
            description="INSERT from SELECT subquery",
        ),
        # -- Update queries --
        EffectCallPattern(
            fqn="peewee.Model.update",
            category="DB_WRITE",
            description="Create UPDATE query",
        ),
        # -- Delete queries --
        EffectCallPattern(
            fqn="peewee.Model.delete",
            category="DB_DELETE",
            description="Create DELETE query",
        ),
        # -- Class-level reads --
        EffectCallPattern(
            fqn="peewee.Model.get",
            category="DB_READ",
            description="Get single row matching criteria (raises DoesNotExist)",
        ),
        EffectCallPattern(
            fqn="peewee.Model.get_or_none",
            category="DB_READ",
            description="Get single row or None",
        ),
        EffectCallPattern(
            fqn="peewee.Model.get_by_id",
            category="DB_READ",
            description="Get by primary key",
        ),
        EffectCallPattern(
            fqn="peewee.Model.select",
            category="DB_READ",
            description="Create SELECT query",
        ),
        # -- Query terminal methods (ModelSelect) --
        EffectCallPattern(
            fqn="peewee.ModelSelect.get",
            category="DB_READ",
            description="Execute query, return single result",
        ),
        EffectCallPattern(
            fqn="peewee.ModelSelect.first",
            category="DB_READ",
            description="Execute query, return first result or None",
        ),
        EffectCallPattern(
            fqn="peewee.ModelSelect.count",
            category="DB_READ",
            description="Execute COUNT query",
        ),
        EffectCallPattern(
            fqn="peewee.ModelSelect.exists",
            category="DB_READ",
            description="Execute EXISTS check",
        ),
        EffectCallPattern(
            fqn="peewee.ModelSelect.scalar",
            category="DB_READ",
            description="Execute query, return scalar value",
        ),
        EffectCallPattern(
            fqn="peewee.ModelSelect.iterator",
            category="DB_READ",
            description="Execute query, iterate without caching",
        ),
        EffectCallPattern(
            fqn="peewee.ModelSelect.peek",
            category="DB_READ",
            description="Execute query, return first N rows",
        ),
        # -- SelectQuery legacy (same as ModelSelect) --
        EffectCallPattern(
            fqn="peewee.SelectQuery.get",
            category="DB_READ",
            description="Legacy: execute query, return single result",
        ),
        # -- Raw SQL execution --
        EffectCallPattern(
            fqn="peewee.Model.raw",
            category="DB_READ",
            description="Execute raw SQL query (injection risk)",
        ),
        # -- Transaction management --
        EffectCallPattern(
            fqn="peewee.Database.atomic",
            category="DB_WRITE",
            description="Transaction/savepoint context manager",
        ),
        EffectCallPattern(
            fqn="peewee.Database.execute_sql",
            category="DB_WRITE",
            description="Execute raw SQL on database connection",
        ),
        # -- Schema operations --
        EffectCallPattern(
            fqn="peewee.Model.create_table",
            category="DB_WRITE",
            description="CREATE TABLE for this model",
        ),
        EffectCallPattern(
            fqn="peewee.Model.drop_table",
            category="DB_DELETE",
            description="DROP TABLE for this model",
        ),
        EffectCallPattern(
            fqn="peewee.Database.create_tables",
            category="DB_WRITE",
            description="CREATE TABLES for multiple models",
        ),
        EffectCallPattern(
            fqn="peewee.Database.drop_tables",
            category="DB_DELETE",
            description="DROP TABLES for multiple models",
        ),
    )

    # =================================================================
    # EP-8b: Taint sinks -- SQL injection vectors
    # =================================================================

    sinks = (
        TaintSinkPattern(
            fqn="peewee.Model.raw",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Raw SQL query -- injection if user input flows here",
        ),
        TaintSinkPattern(
            fqn="peewee.Database.execute_sql",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Raw SQL execution -- injection risk",
        ),
        TaintSinkPattern(
            fqn="peewee.SQL",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Raw SQL expression node -- rendered verbatim",
        ),
        TaintSinkPattern(
            fqn="peewee.fn.SQL",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Raw SQL via fn namespace -- rendered verbatim",
        ),
    )

    # =================================================================
    # EP-8: Flow propagation
    # =================================================================

    propagators = (
        FlowPropagatorPattern(
            fqn="peewee.Model.create",
            input_arg=0,
            output="return",
            description="Constructor kwargs flow to created model instance",
        ),
        FlowPropagatorPattern(
            fqn="peewee.Model.get",
            input_arg=0,
            output="return",
            description="Query criteria flow to retrieved model instance",
        ),
        FlowPropagatorPattern(
            fqn="peewee.Model.get_or_none",
            input_arg=0,
            output="return",
            description="Query criteria flow to retrieved model instance",
        ),
        FlowPropagatorPattern(
            fqn="peewee.Model.get_or_create",
            input_arg=0,
            output="return",
            description="Defaults flow to created-or-fetched instance",
        ),
        FlowPropagatorPattern(
            fqn="peewee.ModelSelect.first",
            input_arg=0,
            output="return",
            description="Query flows to first result",
        ),
    )
