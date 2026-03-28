"""Flask-SQLAlchemy provider -- Flask/SQLAlchemy integration glue.

Thin provider for the Flask-SQLAlchemy extension (v3.x).  Most
database-level effects are handled by the ``sqlalchemy`` provider;
this provider covers:

- ``db.session`` as a scoped session proxy
- ``Model.query`` legacy query interface
- ``SQLAlchemy.init_app()`` lifecycle registration
- ``db.create_all()`` / ``db.drop_all()`` schema management
- ``db.get_or_404()`` / ``db.first_or_404()`` / ``db.one_or_404()``
  convenience query-with-abort methods
- ``Model.query.get()`` / ``.first()`` / ``.all()`` / ``.one()`` and the other
  terminal reads on the ``flask_sqlalchemy.query.Query`` subclass

FQNs verified against Flask-SQLAlchemy 3.1.1 source.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    EffectCallPattern,
    FlowPropagatorPattern,
    HookType,
    LifecycleRegistrationPattern,
    Provider,
    ProviderMeta,
    StateProxyPattern,
)


class FlaskSQLAlchemyProvider(Provider):
    meta = ProviderMeta(
        id="flask-sqlalchemy",
        name="Flask-SQLAlchemy",
        version="0.1.0",
        library="Flask-SQLAlchemy",
        library_fqn="flask_sqlalchemy",
    )

    # =================================================================
    # Effects: schema management + convenience queries
    # =================================================================

    effects = (
        # -- Schema management -------------------------------------------
        EffectCallPattern(
            fqn="flask_sqlalchemy.extension.SQLAlchemy.create_all",
            category="DB_WRITE",
            description="Create all tables (DDL -- metadata.create_all)",
        ),
        EffectCallPattern(
            fqn="flask_sqlalchemy.extension.SQLAlchemy.drop_all",
            category="DB_DELETE",
            description="Drop all tables (DDL -- metadata.drop_all)",
        ),
        EffectCallPattern(
            fqn="flask_sqlalchemy.extension.SQLAlchemy.reflect",
            category="DB_READ",
            description="Reflect table definitions from database",
        ),
        # -- Convenience query + abort methods ---------------------------
        #
        # These combine a DB_READ with a potential abort(404).
        # The primary security concern is the DB_READ.
        EffectCallPattern(
            fqn="flask_sqlalchemy.extension.SQLAlchemy.get_or_404",
            category="DB_READ",
            description="Session.get() with 404 abort on None",
        ),
        EffectCallPattern(
            fqn="flask_sqlalchemy.extension.SQLAlchemy.first_or_404",
            category="DB_READ",
            description="Execute + scalar() with 404 abort on None",
        ),
        EffectCallPattern(
            fqn="flask_sqlalchemy.extension.SQLAlchemy.one_or_404",
            category="DB_READ",
            description="Execute + scalar_one() with 404 abort on failure",
        ),
        EffectCallPattern(
            fqn="flask_sqlalchemy.extension.SQLAlchemy.paginate",
            category="DB_READ",
            description="Paginated query execution",
        ),
        # -- Flask-SQLAlchemy Query subclass terminal reads ---------------
        #
        # ``Model.query`` returns a ``flask_sqlalchemy.query.Query`` (a
        # subclass of ``sqlalchemy.orm.query.Query``).  The base class's
        # terminal reads ARE modelled in the ``sqlalchemy_orm`` provider, but
        # receiver-type resolution lands on the *subclass* FQN, so a plain
        # ``Note.query.get(id)`` / ``.first()`` / ``.all()`` was invisible as a
        # DB_READ -- a silent false negative (FLAW-232).  Model them here on the
        # subclass FQN, mirroring ``sqlalchemy_orm.query.Query.*``.
        EffectCallPattern(
            fqn="flask_sqlalchemy.query.Query.get",
            category="DB_READ",
            description="Primary key lookup (legacy Model.query.get)",
        ),
        EffectCallPattern(
            fqn="flask_sqlalchemy.query.Query.first",
            category="DB_READ",
            description="Execute query, return first result or None",
        ),
        EffectCallPattern(
            fqn="flask_sqlalchemy.query.Query.all",
            category="DB_READ",
            description="Execute query, return all results",
        ),
        EffectCallPattern(
            fqn="flask_sqlalchemy.query.Query.one",
            category="DB_READ",
            description="Execute query, return exactly one (raises otherwise)",
        ),
        EffectCallPattern(
            fqn="flask_sqlalchemy.query.Query.one_or_none",
            category="DB_READ",
            description="Execute query, return one or None (raises if >1)",
        ),
        EffectCallPattern(
            fqn="flask_sqlalchemy.query.Query.scalar",
            category="DB_READ",
            description="Execute query, return first column of first row",
        ),
        EffectCallPattern(
            fqn="flask_sqlalchemy.query.Query.count",
            category="DB_READ",
            description="Execute COUNT query",
        ),
        # -- Flask-SQLAlchemy Query subclass convenience methods ----------
        EffectCallPattern(
            fqn="flask_sqlalchemy.query.Query.get_or_404",
            category="DB_READ",
            description="Query.get() with 404 abort on None",
        ),
        EffectCallPattern(
            fqn="flask_sqlalchemy.query.Query.first_or_404",
            category="DB_READ",
            description="Query.first() with 404 abort on None",
        ),
        EffectCallPattern(
            fqn="flask_sqlalchemy.query.Query.one_or_404",
            category="DB_READ",
            description="Query.one() with 404 abort on failure",
        ),
        EffectCallPattern(
            fqn="flask_sqlalchemy.query.Query.paginate",
            category="DB_READ",
            description="Paginated legacy query execution",
        ),
    )

    # =================================================================
    # Flow propagation
    # =================================================================

    propagators = (
        # get_or_404 returns the same object as session.get() -- taint
        # from the primary key arg flows to the return value.
        FlowPropagatorPattern(
            fqn="flask_sqlalchemy.extension.SQLAlchemy.get_or_404",
            input_arg=0,
            output="return",
            description="PK lookup result flows through get_or_404",
        ),
        FlowPropagatorPattern(
            fqn="flask_sqlalchemy.query.Query.get_or_404",
            input_arg=0,
            output="return",
            description="PK lookup result flows through Query.get_or_404",
        ),
    )

    # =================================================================
    # Lifecycle: init_app registers teardown hook
    # =================================================================

    lifecycle = (
        LifecycleRegistrationPattern(
            registration_fqn="flask_sqlalchemy.extension.SQLAlchemy.init_app",
            hook_type=HookType.TEARDOWN,
            description="Registers session cleanup on app context teardown",
        ),
    )

    # =================================================================
    # State proxy: db.session is a scoped_session proxy
    # =================================================================

    proxies = (
        StateProxyPattern(
            fqn="flask_sqlalchemy.extension.SQLAlchemy.session",
            resolves_to="flask_sqlalchemy.session.Session",
            scope="REQUEST",
            description="Scoped session proxy -- one Session per app context",
        ),
    )
