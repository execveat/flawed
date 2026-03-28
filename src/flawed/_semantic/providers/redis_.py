"""redis-py provider -- cache effects, pub/sub, scripting sinks.

Covers the synchronous ``redis.client.Redis`` API surface.  Methods
are defined on mixin classes in ``redis.commands.core`` but called on
``Redis`` / ``Pipeline`` instances.

Taxonomy note: ``Redis.eval`` / ``evalsha`` execute server-side Lua
scripts.  There is no CODE_INJECTION category in the current effect
taxonomy.  These are declared as taint sinks with sink_kind
``SCRIPT_INJECTION`` so the rule API can surface them.  See
``taxonomy-gaps.md`` for discussion.
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


def _redis_method(owner: str, method: str) -> tuple[str, ...]:
    """Public Redis class FQNs plus the redis-py implementation owner."""
    return tuple(
        dict.fromkeys(
            (f"redis.Redis.{method}", f"redis.client.Redis.{method}", f"{owner}.{method}")
        )
    )


class RedisProvider(Provider):
    meta = ProviderMeta(
        id="redis",
        name="Redis",
        version="0.1.0",
        library="redis",
        library_fqn="redis",
    )

    # =================================================================
    # Effects: cache writes
    # =================================================================

    effects = (
        # -- String key/value writes --
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "set"),
            category="CACHE_WRITE",
            description="Set key to value",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "setex"),
            category="CACHE_WRITE",
            description="Set key with expiration (seconds)",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "setnx"),
            category="CACHE_WRITE",
            description="Set key only if it does not exist",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "mset"),
            category="CACHE_WRITE",
            description="Set multiple key-value pairs atomically",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "append"),
            category="CACHE_WRITE",
            description="Append value to existing key",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "getset"),
            category="CACHE_WRITE",
            description="Set key and return previous value (atomic swap)",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "getdel"),
            category="CACHE_WRITE",
            description="Get value and delete key atomically",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "incrby"),
            category="CACHE_WRITE",
            description="Increment integer value of key",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "decrby"),
            category="CACHE_WRITE",
            description="Decrement integer value of key",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "expire"),
            category="CACHE_WRITE",
            description="Set key expiration (changes key lifetime)",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "persist"),
            category="CACHE_WRITE",
            description="Remove expiration from key",
        ),
        # -- Key deletion --
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "delete"),
            category="CACHE_WRITE",
            description="Delete one or more keys",
        ),
        # -- Hash writes --
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.HashCommands", "hset"),
            category="CACHE_WRITE",
            description="Set hash field value",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.HashCommands", "hdel"),
            category="CACHE_WRITE",
            description="Delete hash field(s)",
        ),
        # -- List writes --
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.ListCommands", "lpush"),
            category="CACHE_WRITE",
            description="Prepend value(s) to list",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.ListCommands", "rpush"),
            category="CACHE_WRITE",
            description="Append value(s) to list",
        ),
        # -- Set writes --
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.SetCommands", "sadd"),
            category="CACHE_WRITE",
            description="Add member(s) to set",
        ),
        # -- Sorted set writes --
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.SortedSetCommands", "zadd"),
            category="CACHE_WRITE",
            description="Add member(s) to sorted set with scores",
        ),
        # -- Cache reads --
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "get"),
            category="CACHE_READ",
            description="Get value by key",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "mget"),
            category="CACHE_READ",
            description="Get values for multiple keys",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "exists"),
            category="CACHE_READ",
            description="Check if key(s) exist",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "keys"),
            category="CACHE_READ",
            description="Find keys matching pattern",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "type"),
            category="CACHE_READ",
            description="Get key type",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "ttl"),
            category="CACHE_READ",
            description="Get key time-to-live in seconds",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.HashCommands", "hget"),
            category="CACHE_READ",
            description="Get hash field value",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.HashCommands", "hgetall"),
            category="CACHE_READ",
            description="Get all hash fields and values",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.HashCommands", "hkeys"),
            category="CACHE_READ",
            description="Get all hash field names",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.HashCommands", "hvals"),
            category="CACHE_READ",
            description="Get all hash field values",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.ListCommands", "lrange"),
            category="CACHE_READ",
            description="Get list elements in range",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.ListCommands", "llen"),
            category="CACHE_READ",
            description="Get list length",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.ListCommands", "lindex"),
            category="CACHE_READ",
            description="Get list element by index",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.SetCommands", "smembers"),
            category="CACHE_READ",
            description="Get all set members",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.SetCommands", "sismember"),
            category="CACHE_READ",
            description="Check set membership",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.SortedSetCommands", "zrange"),
            category="CACHE_READ",
            description="Get sorted set members in score range",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.ScanCommands", "scan"),
            category="CACHE_READ",
            description="Incrementally iterate keys",
        ),
        # -- Pipeline execution (flushes buffered commands) --
        EffectCallPattern(
            fqn="redis.client.Pipeline.execute",
            category="CACHE_WRITE",
            description="Execute all buffered pipeline commands",
        ),
        # -- Pub/Sub (notification semantics) --
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.PubSubCommands", "publish"),
            category="NOTIFICATION",
            description="Publish message to channel",
        ),
        # -- Lua scripting (server-side code execution) --
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.ScriptCommands", "eval"),
            category="CACHE_WRITE",
            description="Execute Lua script on server (may read or write)",
        ),
        EffectCallPattern(
            fqn=_redis_method("redis.commands.core.ScriptCommands", "evalsha"),
            category="CACHE_WRITE",
            description="Execute cached Lua script by SHA on server",
        ),
        # -- Generic command execution --
        EffectCallPattern(
            fqn=_redis_method("redis.client.Redis", "execute_command"),
            category="CACHE_WRITE",
            description="Execute arbitrary Redis command (conservative: assume write)",
        ),
    )

    # =================================================================
    # Taint sinks: injection vectors
    # =================================================================

    sinks = (
        # Lua script injection: user input in the script body is
        # server-side code injection.
        TaintSinkPattern(
            fqn=_redis_method("redis.commands.core.ScriptCommands", "eval"),
            arg=0,
            sink_kind="SCRIPT_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Lua script body -- injection if user input flows here",
        ),
        # Key names: attacker-controlled key names enable data
        # exfiltration, key enumeration, and cache poisoning.
        TaintSinkPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "get"),
            arg=0,
            sink_kind="KEY_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Redis key name -- attacker-controlled keys enable cache poisoning",
        ),
        TaintSinkPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "set"),
            arg=0,
            sink_kind="KEY_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Redis key name -- attacker-controlled keys enable cache poisoning",
        ),
        TaintSinkPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "delete"),
            arg=0,
            sink_kind="KEY_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Redis key name -- attacker-controlled keys enable cache destruction",
        ),
    )

    # =================================================================
    # Flow propagation
    # =================================================================

    propagators = (
        # Data written to Redis flows from arg 1 (value) into the store
        FlowPropagatorPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "set"),
            input_arg=1,
            output="receiver",
            description="Value taint propagates into Redis store",
        ),
        # Data read from Redis flows from store into return value
        FlowPropagatorPattern(
            fqn=_redis_method("redis.commands.core.BasicKeyCommands", "get"),
            input_arg=0,
            output="return",
            description="Stored value taint propagates to caller",
        ),
    )
