"""PyMongo provider -- MongoDB driver.

Covers Collection CRUD operations, aggregation pipeline, index
management, Database-level commands, and NoSQL injection sinks.

PyMongo's security surface differs from SQL drivers: the primary
injection vector is not string interpolation but rather operator
injection in query filter dicts (``{"$where": user_input}``).

FQNs: ``pymongo.collection.Collection`` and ``pymongo.database.Database``
are the main classes.  ``pymongo.MongoClient`` handles connections.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    EffectCallPattern,
    FlowPropagatorPattern,
    Provider,
    ProviderMeta,
    TaintSinkPattern,
)


class PyMongoProvider(Provider):
    meta = ProviderMeta(
        id="pymongo",
        name="PyMongo",
        version="0.1.0",
        library="pymongo",
        library_fqn="pymongo",
    )

    # =================================================================
    # Effects: Collection CRUD, aggregation, index management
    # =================================================================

    effects = (
        # -- Connection -------------------------------------------------
        EffectCallPattern(
            fqn="pymongo.mongo_client.MongoClient.__init__",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Open MongoDB connection (URI may contain credentials)",
        ),
        # -- Collection: write operations -------------------------------
        EffectCallPattern(
            fqn="pymongo.collection.Collection.insert_one",
            category="DB_WRITE",
            description="Insert single document",
        ),
        EffectCallPattern(
            fqn="pymongo.collection.Collection.insert_many",
            category="DB_WRITE",
            description="Insert multiple documents",
        ),
        EffectCallPattern(
            fqn="pymongo.collection.Collection.update_one",
            category="DB_WRITE",
            description="Update first matching document",
        ),
        EffectCallPattern(
            fqn="pymongo.collection.Collection.update_many",
            category="DB_WRITE",
            description="Update all matching documents",
        ),
        EffectCallPattern(
            fqn="pymongo.collection.Collection.replace_one",
            category="DB_WRITE",
            description="Replace first matching document entirely",
        ),
        EffectCallPattern(
            fqn="pymongo.collection.Collection.bulk_write",
            category="DB_WRITE",
            description="Execute batch of write operations",
        ),
        # -- Collection: delete operations ------------------------------
        EffectCallPattern(
            fqn="pymongo.collection.Collection.delete_one",
            category="DB_DELETE",
            description="Delete first matching document",
        ),
        EffectCallPattern(
            fqn="pymongo.collection.Collection.delete_many",
            category="DB_DELETE",
            description="Delete all matching documents",
        ),
        EffectCallPattern(
            fqn="pymongo.collection.Collection.drop",
            category="DB_DELETE",
            description="Drop entire collection",
        ),
        # -- Collection: read+modify operations -------------------------
        EffectCallPattern(
            fqn="pymongo.collection.Collection.find_one_and_update",
            category="DB_WRITE",
            description="Atomically find and update one document",
        ),
        EffectCallPattern(
            fqn="pymongo.collection.Collection.find_one_and_replace",
            category="DB_WRITE",
            description="Atomically find and replace one document",
        ),
        EffectCallPattern(
            fqn="pymongo.collection.Collection.find_one_and_delete",
            category="DB_DELETE",
            description="Atomically find and delete one document",
        ),
        # -- Collection: read operations --------------------------------
        EffectCallPattern(
            fqn="pymongo.collection.Collection.find",
            category="DB_READ",
            description="Query documents (returns Cursor)",
        ),
        EffectCallPattern(
            fqn="pymongo.collection.Collection.find_one",
            category="DB_READ",
            description="Query single document",
        ),
        EffectCallPattern(
            fqn="pymongo.collection.Collection.aggregate",
            category="DB_READ",
            description="Run aggregation pipeline",
        ),
        EffectCallPattern(
            fqn="pymongo.collection.Collection.distinct",
            category="DB_READ",
            description="Get distinct values for a field",
        ),
        EffectCallPattern(
            fqn="pymongo.collection.Collection.count_documents",
            category="DB_READ",
            description="Count documents matching filter",
        ),
        EffectCallPattern(
            fqn="pymongo.collection.Collection.estimated_document_count",
            category="DB_READ",
            description="Estimated document count (metadata-based)",
        ),
        # -- Collection: index management (schema effects) --------------
        EffectCallPattern(
            fqn="pymongo.collection.Collection.create_index",
            category="DB_WRITE",
            description="Create index on collection",
        ),
        EffectCallPattern(
            fqn="pymongo.collection.Collection.create_indexes",
            category="DB_WRITE",
            description="Create multiple indexes on collection",
        ),
        EffectCallPattern(
            fqn="pymongo.collection.Collection.drop_index",
            category="DB_WRITE",
            description="Drop index from collection",
        ),
        EffectCallPattern(
            fqn="pymongo.collection.Collection.drop_indexes",
            category="DB_WRITE",
            description="Drop all indexes from collection",
        ),
        EffectCallPattern(
            fqn="pymongo.collection.Collection.list_indexes",
            category="DB_READ",
            description="List indexes on collection",
        ),
        # -- Collection: rename -----------------------------------------
        EffectCallPattern(
            fqn="pymongo.collection.Collection.rename",
            category="DB_WRITE",
            description="Rename collection",
        ),
        # -- Database-level operations ----------------------------------
        EffectCallPattern(
            fqn="pymongo.database.Database.command",
            category="DB_WRITE",
            description="Execute raw database command (admin-level)",
        ),
        EffectCallPattern(
            fqn="pymongo.database.Database.create_collection",
            category="DB_WRITE",
            description="Create new collection with options",
        ),
        EffectCallPattern(
            fqn="pymongo.database.Database.drop_collection",
            category="DB_DELETE",
            description="Drop entire collection by name",
        ),
        EffectCallPattern(
            fqn="pymongo.database.Database.list_collection_names",
            category="DB_READ",
            description="List collection names in database",
        ),
        EffectCallPattern(
            fqn="pymongo.database.Database.list_collections",
            category="DB_READ",
            description="List collections with metadata",
        ),
        # -- Client-level operations ------------------------------------
        EffectCallPattern(
            fqn="pymongo.mongo_client.MongoClient.drop_database",
            category="DB_DELETE",
            description="Drop entire database",
        ),
        EffectCallPattern(
            fqn="pymongo.mongo_client.MongoClient.list_database_names",
            category="DB_READ",
            description="List database names",
        ),
    )

    # =================================================================
    # Injection sinks: NoSQL injection vectors
    # =================================================================

    sinks = (
        # The filter dict (arg 0) on find/find_one is the primary NoSQL
        # injection vector: if user input flows into the filter dict,
        # an attacker can inject MongoDB operators like $gt, $where, $regex.
        TaintSinkPattern(
            fqn="pymongo.collection.Collection.find",
            arg=0,
            sink_kind="NOSQL_INJECTION",
            description="Query filter dict -- operator injection if user-controlled",
        ),
        TaintSinkPattern(
            fqn="pymongo.collection.Collection.find_one",
            arg=0,
            sink_kind="NOSQL_INJECTION",
            description="Query filter dict -- operator injection if user-controlled",
        ),
        TaintSinkPattern(
            fqn="pymongo.collection.Collection.update_one",
            arg=0,
            sink_kind="NOSQL_INJECTION",
            description="Update filter dict -- operator injection risk",
        ),
        TaintSinkPattern(
            fqn="pymongo.collection.Collection.update_many",
            arg=0,
            sink_kind="NOSQL_INJECTION",
            description="Update filter dict -- operator injection risk",
        ),
        TaintSinkPattern(
            fqn="pymongo.collection.Collection.delete_one",
            arg=0,
            sink_kind="NOSQL_INJECTION",
            description="Delete filter dict -- operator injection risk",
        ),
        TaintSinkPattern(
            fqn="pymongo.collection.Collection.delete_many",
            arg=0,
            sink_kind="NOSQL_INJECTION",
            description="Delete filter dict -- operator injection risk",
        ),
        TaintSinkPattern(
            fqn="pymongo.collection.Collection.count_documents",
            arg=0,
            sink_kind="NOSQL_INJECTION",
            description="Count filter dict -- operator injection risk",
        ),
        TaintSinkPattern(
            fqn="pymongo.collection.Collection.distinct",
            arg=1,
            sink_kind="NOSQL_INJECTION",
            description="Distinct filter dict (arg 1) -- operator injection risk",
        ),
        # aggregate pipeline: if user input flows into pipeline stages,
        # it can control $match, $group, $lookup, etc.
        TaintSinkPattern(
            fqn="pymongo.collection.Collection.aggregate",
            arg=0,
            sink_kind="NOSQL_INJECTION",
            description="Aggregation pipeline -- injection if user-controlled stages",
        ),
        # Database.command: raw command execution
        TaintSinkPattern(
            fqn="pymongo.database.Database.command",
            arg=0,
            sink_kind="NOSQL_INJECTION",
            description="Raw database command -- injection if user-controlled",
        ),
    )

    # =================================================================
    # Flow propagation: query results carry tainted data
    # =================================================================

    propagators = (
        # find() returns a Cursor; iteration over it yields documents
        FlowPropagatorPattern(
            fqn="pymongo.collection.Collection.find",
            input_arg=0,
            output="return",
            description="Query filter taint propagates to result cursor",
        ),
        FlowPropagatorPattern(
            fqn="pymongo.collection.Collection.find_one",
            input_arg=0,
            output="return",
            description="Query result carries taint from filter context",
        ),
        FlowPropagatorPattern(
            fqn="pymongo.collection.Collection.aggregate",
            input_arg=0,
            output="return",
            description="Aggregation result carries taint from pipeline",
        ),
        FlowPropagatorPattern(
            fqn="pymongo.collection.Collection.find_one_and_update",
            input_arg=0,
            output="return",
            description="Returned document carries taint from filter context",
        ),
        FlowPropagatorPattern(
            fqn="pymongo.collection.Collection.find_one_and_replace",
            input_arg=0,
            output="return",
            description="Returned document carries taint from filter context",
        ),
        FlowPropagatorPattern(
            fqn="pymongo.collection.Collection.find_one_and_delete",
            input_arg=0,
            output="return",
            description="Returned document carries taint from filter context",
        ),
    )
