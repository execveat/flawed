"""psycopg2 provider -- PostgreSQL database driver (DB-API 2.0).

Covers cursor execution (SQL injection sinks), fetch operations,
transaction control, and COPY bulk data commands.

psycopg2 is a C extension module.  The actual classes live in
``psycopg2._psycopg`` but are re-exported via ``psycopg2.extensions``
and ``psycopg2.extras``.  Users import ``psycopg2.connect()`` and
work with the returned connection/cursor objects.

FQNs use ``psycopg2.extensions`` where the public API lives, falling
back to ``psycopg2._psycopg`` for the C-level implementation classes.
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


class Psycopg2Provider(Provider):
    meta = ProviderMeta(
        id="psycopg2",
        name="psycopg2",
        version="0.1.0",
        library="psycopg2",
        library_fqn="psycopg2",
    )

    # =================================================================
    # Effects: cursor execution and transaction control
    # =================================================================

    effects = (
        # -- Connection establishment -----------------------------------
        EffectCallPattern(
            fqn="psycopg2.connect",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Open PostgreSQL connection (DSN may contain credentials)",
        ),
        # -- Cursor: write operations -----------------------------------
        # cursor.execute() can be SELECT or DML; statically we can't
        # always distinguish.  We declare it as DB_WRITE by default --
        # the taint sink is what matters for security.
        EffectCallPattern(
            fqn="psycopg2.extensions.cursor.execute",
            category="DB_WRITE",
            description="Execute SQL statement (may be SELECT or DML)",
        ),
        EffectCallPattern(
            fqn="psycopg2.extensions.cursor.executemany",
            category="DB_WRITE",
            description="Execute SQL with multiple parameter sets (batch DML)",
        ),
        EffectCallPattern(
            fqn="psycopg2.extensions.cursor.callproc",
            category="DB_WRITE",
            description="Call stored procedure (may produce side effects)",
        ),
        # -- Cursor: COPY commands (bulk data transfer) -----------------
        EffectCallPattern(
            fqn="psycopg2.extensions.cursor.copy_from",
            category="DB_WRITE",
            description="COPY FROM: bulk insert from file-like object",
        ),
        EffectCallPattern(
            fqn="psycopg2.extensions.cursor.copy_to",
            category="DB_READ",
            description="COPY TO: bulk export to file-like object",
        ),
        EffectCallPattern(
            fqn="psycopg2.extensions.cursor.copy_expert",
            category="DB_WRITE",
            description="COPY with custom SQL (may be COPY FROM or COPY TO)",
        ),
        # -- Cursor: read operations ------------------------------------
        EffectCallPattern(
            fqn="psycopg2.extensions.cursor.fetchone",
            category="DB_READ",
            description="Fetch one row from cursor result set",
        ),
        EffectCallPattern(
            fqn="psycopg2.extensions.cursor.fetchall",
            category="DB_READ",
            description="Fetch all remaining rows from cursor result set",
        ),
        EffectCallPattern(
            fqn="psycopg2.extensions.cursor.fetchmany",
            category="DB_READ",
            description="Fetch N rows from cursor result set",
        ),
        # -- Transaction control ----------------------------------------
        EffectCallPattern(
            fqn="psycopg2.extensions.connection.commit",
            category="DB_WRITE",
            description="Commit current transaction",
        ),
        EffectCallPattern(
            fqn="psycopg2.extensions.connection.rollback",
            category="STATE_WRITE",
            scope="SERVER",
            description="Rollback current transaction",
        ),
        # -- Extras: execute_values/execute_batch -----------------------
        EffectCallPattern(
            fqn="psycopg2.extras.execute_values",
            category="DB_WRITE",
            description="Optimised multi-row INSERT via VALUES list",
        ),
        EffectCallPattern(
            fqn="psycopg2.extras.execute_batch",
            category="DB_WRITE",
            description="Optimised batch execute with server-side grouping",
        ),
    )

    # =================================================================
    # Injection sinks: SQL injection vectors
    # =================================================================

    sinks = (
        # cursor.execute(query) -- the primary SQL injection vector.
        # Safe when using parameterised queries: cursor.execute(sql, params).
        # Dangerous when query string is constructed from user input.
        TaintSinkPattern(
            fqn="psycopg2.extensions.cursor.execute",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
            description="SQL query string -- injection if user input flows here",
        ),
        TaintSinkPattern(
            fqn="psycopg2.extensions.cursor.executemany",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
            description="SQL template for batch execution -- injection risk",
        ),
        TaintSinkPattern(
            fqn="psycopg2.extensions.cursor.copy_expert",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
            description="COPY SQL command string -- injection if not literal",
        ),
        TaintSinkPattern(
            fqn="psycopg2.extras.execute_values",
            arg=1,
            sink_kind="SQL_INJECTION",
            when=~arg(1).is_literal_string(),
            description="SQL template for execute_values -- injection risk",
        ),
        TaintSinkPattern(
            fqn="psycopg2.extras.execute_batch",
            arg=1,
            sink_kind="SQL_INJECTION",
            when=~arg(1).is_literal_string(),
            description="SQL template for execute_batch -- injection risk",
        ),
    )

    # =================================================================
    # Flow propagation: data flows through fetch operations
    # =================================================================

    propagators = (
        FlowPropagatorPattern(
            fqn="psycopg2.extensions.cursor.fetchone",
            input_arg=0,
            output="return",
            description="DB data flows from cursor through fetchone()",
        ),
        FlowPropagatorPattern(
            fqn="psycopg2.extensions.cursor.fetchall",
            input_arg=0,
            output="return",
            description="DB data flows from cursor through fetchall()",
        ),
        FlowPropagatorPattern(
            fqn="psycopg2.extensions.cursor.fetchmany",
            input_arg=0,
            output="return",
            description="DB data flows from cursor through fetchmany()",
        ),
    )
