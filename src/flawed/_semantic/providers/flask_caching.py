"""Flask-Caching provider -- cache read/write effects and view caching.

Covers:
- ``cache.get(key)`` / ``cache.set(key, value)`` — explicit cache ops
- ``cache.delete(key)`` / ``cache.clear()`` — cache invalidation
- ``cache.get_many()`` / ``cache.set_many()`` — batch cache ops
- ``@cache.cached(timeout)`` — view/function response caching decorator
- ``@cache.memoize(timeout)`` — argument-aware result caching decorator
- ``cache.delete_memoized(func)`` — memoization invalidation
- ``Cache(app)`` / ``Cache.init_app(app)`` — lifecycle registration

FQNs verified against Flask-Caching 2.3.x source.  The ``Cache`` class
lives at ``flask_caching.Cache`` (directly in ``__init__.py``).
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    EffectCallPattern,
    HookType,
    LifecycleRegistrationPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class FlaskCachingProvider(Provider):
    meta = ProviderMeta(
        id="flask-caching",
        name="Flask-Caching",
        version="0.1.0",
        library="Flask-Caching",
        library_fqn="flask_caching",
    )

    # =================================================================
    # Effects: cache operations
    # =================================================================

    effects = (
        # -- Cache reads -------------------------------------------------
        EffectCallPattern(
            fqn="flask_caching.Cache.get",
            category="CACHE_READ",
            description="Read a single value from the cache by key",
        ),
        EffectCallPattern(
            fqn="flask_caching.Cache.has",
            category="CACHE_READ",
            description="Check whether a key exists in the cache",
        ),
        EffectCallPattern(
            fqn="flask_caching.Cache.get_many",
            category="CACHE_READ",
            description="Read multiple values from the cache",
        ),
        EffectCallPattern(
            fqn="flask_caching.Cache.get_dict",
            category="CACHE_READ",
            description="Read multiple values as a dict from the cache",
        ),
        # -- Cache writes ------------------------------------------------
        EffectCallPattern(
            fqn="flask_caching.Cache.set",
            category="CACHE_WRITE",
            description="Write a single value to the cache",
        ),
        EffectCallPattern(
            fqn="flask_caching.Cache.add",
            category="CACHE_WRITE",
            description="Add a value to the cache (only if key absent)",
        ),
        EffectCallPattern(
            fqn="flask_caching.Cache.set_many",
            category="CACHE_WRITE",
            description="Write multiple values to the cache",
        ),
        # -- Cache deletes (still CACHE_WRITE: mutation) -----------------
        EffectCallPattern(
            fqn="flask_caching.Cache.delete",
            category="CACHE_WRITE",
            description="Delete a single key from the cache",
        ),
        EffectCallPattern(
            fqn="flask_caching.Cache.delete_many",
            category="CACHE_WRITE",
            description="Delete multiple keys from the cache",
        ),
        EffectCallPattern(
            fqn="flask_caching.Cache.unlink",
            category="CACHE_WRITE",
            description="Redis unlink (async delete) or fallback to delete_many",
        ),
        EffectCallPattern(
            fqn="flask_caching.Cache.clear",
            category="CACHE_WRITE",
            description="Clear all keys from the cache",
        ),
        # -- Memoization invalidation ------------------------------------
        EffectCallPattern(
            fqn="flask_caching.Cache.delete_memoized",
            category="CACHE_WRITE",
            description="Invalidate memoized function cache entries",
        ),
        EffectCallPattern(
            fqn="flask_caching.Cache.delete_memoized_verhash",
            category="CACHE_WRITE",
            description="Delete memoized function version hash",
        ),
    )

    # =================================================================
    # Security checks: caching decorators
    #
    # @cache.cached and @cache.memoize are noteworthy from a security
    # perspective because they bypass request processing for cached
    # responses -- potentially serving stale auth state.
    # =================================================================

    checks = (
        SecurityCheckPattern(
            fqn="flask_caching.Cache.cached",
            kind=CheckKind.DECORATOR,
            category="RESPONSE_CACHING",
            description=(
                "Caches decorated view response; may serve stale data "
                "bypassing auth checks on subsequent requests"
            ),
        ),
        SecurityCheckPattern(
            fqn="flask_caching.Cache.memoize",
            kind=CheckKind.DECORATOR,
            category="RESPONSE_CACHING",
            description=(
                "Caches function result by arguments; may serve stale data bypassing auth checks"
            ),
        ),
    )

    # =================================================================
    # Lifecycle registration
    # =================================================================

    lifecycle = (
        LifecycleRegistrationPattern(
            registration_fqn="flask_caching.Cache.init_app",
            hook_type=HookType.TEARDOWN,
            description="Initializes cache backend and registers with app",
        ),
    )
