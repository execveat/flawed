"""PyMySQL provider -- pure-Python MySQL/MariaDB driver (DB-API 2.0).

Covers cursor execution (SQL injection sinks), fetch operations,
and transaction control.  PyMySQL follows the DB-API 2.0 interface
closely so patterns are structurally identical to psycopg2.

FQNs: ``pymysql.connections.Connection`` and ``pymysql.cursors.Cursor``
are the concrete implementation classes.
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


class PyMySQLProvider(Provider):
    meta = ProviderMeta(
        id="pymysql",
        name="PyMySQL",
        version="0.1.0",
        library="PyMySQL",
        library_fqn="pymysql",
    )

    # =================================================================
    # Effects: cursor execution and transaction control
    # =================================================================

    effects = (
        # -- Connection establishment -----------------------------------
        EffectCallPattern(
            fqn="pymysql.connections.Connection.__init__",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Open MySQL/MariaDB connection",
        ),
        EffectCallPattern(
            fqn="pymysql.connect",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Open MySQL/MariaDB connection (module-level alias)",
        ),
        # -- Cursor: write operations -----------------------------------
        EffectCallPattern(
            fqn="pymysql.cursors.Cursor.execute",
            category="DB_WRITE",
            description="Execute SQL statement (may be SELECT or DML)",
        ),
        EffectCallPattern(
            fqn="pymysql.cursors.Cursor.executemany",
            category="DB_WRITE",
            description="Execute SQL with multiple parameter sets",
        ),
        EffectCallPattern(
            fqn="pymysql.cursors.Cursor.callproc",
            category="DB_WRITE",
            description="Call stored procedure",
        ),
        # -- DictCursor variants (same methods, different result type) --
        EffectCallPattern(
            fqn="pymysql.cursors.DictCursor.execute",
            category="DB_WRITE",
            description="Execute SQL (returns dicts instead of tuples)",
        ),
        EffectCallPattern(
            fqn="pymysql.cursors.DictCursor.executemany",
            category="DB_WRITE",
            description="Batch execute (DictCursor variant)",
        ),
        EffectCallPattern(
            fqn="pymysql.cursors.SSCursor.execute",
            category="DB_WRITE",
            description="Execute SQL (server-side cursor, unbuffered)",
        ),
        EffectCallPattern(
            fqn="pymysql.cursors.SSDictCursor.execute",
            category="DB_WRITE",
            description="Execute SQL (server-side dict cursor)",
        ),
        # -- Cursor: read operations ------------------------------------
        EffectCallPattern(
            fqn="pymysql.cursors.Cursor.fetchone",
            category="DB_READ",
            description="Fetch one row from result set",
        ),
        EffectCallPattern(
            fqn="pymysql.cursors.Cursor.fetchall",
            category="DB_READ",
            description="Fetch all remaining rows from result set",
        ),
        EffectCallPattern(
            fqn="pymysql.cursors.Cursor.fetchmany",
            category="DB_READ",
            description="Fetch N rows from result set",
        ),
        EffectCallPattern(
            fqn="pymysql.cursors.DictCursor.fetchone",
            category="DB_READ",
            description="Fetch one row as dict",
        ),
        EffectCallPattern(
            fqn="pymysql.cursors.DictCursor.fetchall",
            category="DB_READ",
            description="Fetch all rows as dicts",
        ),
        # -- Transaction control ----------------------------------------
        EffectCallPattern(
            fqn="pymysql.connections.Connection.commit",
            category="DB_WRITE",
            description="Commit current transaction",
        ),
        EffectCallPattern(
            fqn="pymysql.connections.Connection.rollback",
            category="STATE_WRITE",
            scope="SERVER",
            description="Rollback current transaction",
        ),
        EffectCallPattern(
            fqn="pymysql.connections.Connection.begin",
            category="STATE_WRITE",
            scope="SERVER",
            description="Begin explicit transaction",
        ),
    )

    # =================================================================
    # Injection sinks: SQL injection vectors
    # =================================================================

    sinks = (
        TaintSinkPattern(
            fqn="pymysql.cursors.Cursor.execute",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
            description="SQL query string -- injection if user input flows here",
        ),
        TaintSinkPattern(
            fqn="pymysql.cursors.Cursor.executemany",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
            description="SQL template for batch execution -- injection risk",
        ),
        TaintSinkPattern(
            fqn="pymysql.cursors.DictCursor.execute",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
            description="SQL query string (DictCursor) -- injection risk",
        ),
        TaintSinkPattern(
            fqn="pymysql.cursors.SSCursor.execute",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
            description="SQL query string (SSCursor) -- injection risk",
        ),
        TaintSinkPattern(
            fqn="pymysql.cursors.SSDictCursor.execute",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
            description="SQL query string (SSDictCursor) -- injection risk",
        ),
    )

    # =================================================================
    # Flow propagation: data flows through fetch operations
    # =================================================================

    propagators = (
        FlowPropagatorPattern(
            fqn="pymysql.cursors.Cursor.fetchone",
            input_arg=0,
            output="return",
            description="DB data flows from cursor through fetchone()",
        ),
        FlowPropagatorPattern(
            fqn="pymysql.cursors.Cursor.fetchall",
            input_arg=0,
            output="return",
            description="DB data flows from cursor through fetchall()",
        ),
        FlowPropagatorPattern(
            fqn="pymysql.cursors.Cursor.fetchmany",
            input_arg=0,
            output="return",
            description="DB data flows from cursor through fetchmany()",
        ),
        FlowPropagatorPattern(
            fqn="pymysql.cursors.DictCursor.fetchone",
            input_arg=0,
            output="return",
            description="DB data flows from DictCursor through fetchone()",
        ),
        FlowPropagatorPattern(
            fqn="pymysql.cursors.DictCursor.fetchall",
            input_arg=0,
            output="return",
            description="DB data flows from DictCursor through fetchall()",
        ),
    )
