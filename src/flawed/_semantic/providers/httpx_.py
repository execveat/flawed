"""httpx provider -- sync and async outbound HTTP requests, SSRF sinks.

Covers the ``httpx`` library: module-level convenience functions,
``Client`` (sync) methods, ``AsyncClient`` (async) methods, SSRF
taint sinks on URL arguments, and flow propagation from response.

FQN note: module-level functions live in ``httpx._api``.
``Client`` and ``AsyncClient`` live in ``httpx._client``.
``Response`` lives in ``httpx._models``.
Auth classes live in ``httpx._auth``.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    EffectCallPattern,
    FlowPropagatorPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
    TaintSinkPattern,
)

_HTTP_METHODS = ("get", "post", "put", "delete", "patch", "head", "options")


def _module_effects() -> tuple[EffectCallPattern, ...]:
    """Module-level convenience functions: httpx.get(), etc."""
    return (
        *[
            EffectCallPattern(
                fqn=f"httpx._api.{method}",
                category="OUTBOUND_REQUEST",
                description=f"HTTP {method.upper()} via httpx.{method}()",
            )
            for method in _HTTP_METHODS
        ],
        EffectCallPattern(
            fqn="httpx._api.request",
            category="OUTBOUND_REQUEST",
            description="Generic HTTP request via httpx.request(method, url)",
        ),
        EffectCallPattern(
            fqn="httpx._api.stream",
            category="OUTBOUND_REQUEST",
            description="Streaming HTTP request via httpx.stream()",
        ),
    )


def _client_effects() -> tuple[EffectCallPattern, ...]:
    """Client + AsyncClient methods (merged via tuple FQNs)."""
    return (
        *[
            EffectCallPattern(
                fqn=(f"httpx._client.Client.{method}", f"httpx._client.AsyncClient.{method}"),
                category="OUTBOUND_REQUEST",
                description=f"HTTP {method.upper()} via Client/AsyncClient.{method}()",
            )
            for method in _HTTP_METHODS
        ],
        EffectCallPattern(
            fqn=("httpx._client.Client.request", "httpx._client.AsyncClient.request"),
            category="OUTBOUND_REQUEST",
            description="Generic HTTP request via Client/AsyncClient.request()",
        ),
        EffectCallPattern(
            fqn=("httpx._client.Client.stream", "httpx._client.AsyncClient.stream"),
            category="OUTBOUND_REQUEST",
            description="Streaming HTTP request via Client/AsyncClient.stream()",
        ),
        EffectCallPattern(
            fqn=("httpx._client.Client.send", "httpx._client.AsyncClient.send"),
            category="OUTBOUND_REQUEST",
            description="Send prepared Request via Client/AsyncClient.send()",
        ),
    )


def _module_sinks() -> tuple[TaintSinkPattern, ...]:
    """SSRF sinks on module-level functions."""
    return (
        *[
            TaintSinkPattern(
                fqn=f"httpx._api.{method}",
                arg=0,
                sink_kind="SSRF",
                description=f"URL argument to httpx.{method}() -- SSRF if user-controlled",
            )
            for method in _HTTP_METHODS
        ],
        # httpx.request(method, url) -- url is arg 1
        TaintSinkPattern(
            fqn="httpx._api.request",
            arg=1,
            sink_kind="SSRF",
            description="URL argument to httpx.request() -- SSRF if user-controlled",
        ),
        TaintSinkPattern(
            fqn="httpx._api.stream",
            arg=1,
            sink_kind="SSRF",
            description="URL argument to httpx.stream() -- SSRF if user-controlled",
        ),
    )


def _client_sinks() -> tuple[TaintSinkPattern, ...]:
    """SSRF sinks on Client + AsyncClient methods."""
    results: list[TaintSinkPattern] = []
    for cls in ("Client", "AsyncClient"):
        results.extend(
            TaintSinkPattern(
                fqn=f"httpx._client.{cls}.{method}",
                arg=0,
                sink_kind="SSRF",
                description=f"URL argument to {cls}.{method}() -- SSRF if user-controlled",
            )
            for method in _HTTP_METHODS
        )
        # .request(method, url) -- url is arg 1
        results.append(
            TaintSinkPattern(
                fqn=f"httpx._client.{cls}.request",
                arg=1,
                sink_kind="SSRF",
                description=f"URL argument to {cls}.request() -- SSRF if user-controlled",
            ),
        )
        results.append(
            TaintSinkPattern(
                fqn=f"httpx._client.{cls}.stream",
                arg=1,
                sink_kind="SSRF",
                description=f"URL argument to {cls}.stream() -- SSRF if user-controlled",
            ),
        )
    return tuple(results)


class HttpxProvider(Provider):
    meta = ProviderMeta(
        id="httpx",
        name="HTTPX",
        version="0.1.0",
        library="httpx",
        library_fqn="httpx",
    )

    # =================================================================
    # Effects: all HTTP methods produce OUTBOUND_REQUEST
    # =================================================================

    effects = _module_effects() + _client_effects()

    # =================================================================
    # Taint sinks: URL arguments are SSRF vectors
    # =================================================================

    sinks = _module_sinks() + _client_sinks()

    # =================================================================
    # Security checks: auth handlers
    # =================================================================

    checks = (
        SecurityCheckPattern(
            fqn="httpx._auth.BasicAuth",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="HTTP Basic authentication via httpx",
        ),
        SecurityCheckPattern(
            fqn="httpx._auth.DigestAuth",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="HTTP Digest authentication via httpx",
        ),
    )

    # =================================================================
    # Flow propagation: taint flows from request to response
    # =================================================================

    propagators = (
        FlowPropagatorPattern(
            fqn="httpx._models.Response.json",
            input_arg=0,
            output="return",
            description="Parsed JSON from HTTP response body",
        ),
    )
