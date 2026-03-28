"""requests provider -- outbound HTTP requests and SSRF sinks.

Covers the ``requests`` library: module-level convenience functions,
``Session`` methods, SSRF taint sinks on URL arguments, and flow
propagation from request to response.

FQN note: ``requests.get`` etc. are defined in ``requests.api`` and
re-exported from ``requests.__init__``.  ``Session`` lives in
``requests.sessions``.  Module-level and Session methods are merged
via tuple FQNs since they have identical semantics.
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
    arg,
)

_HTTP_METHODS = ("get", "post", "put", "delete", "patch", "head", "options")


def _effects() -> tuple[EffectCallPattern, ...]:
    """Module-level + Session HTTP verb methods (merged via tuple FQNs)."""
    return (
        *[
            EffectCallPattern(
                fqn=(f"requests.{m}", f"requests.api.{m}", f"requests.sessions.Session.{m}"),
                category="OUTBOUND_REQUEST",
                description=f"HTTP {m.upper()} via requests.{m}() or Session.{m}()",
            )
            for m in _HTTP_METHODS
        ],
        EffectCallPattern(
            fqn=("requests.request", "requests.api.request", "requests.sessions.Session.request"),
            category="OUTBOUND_REQUEST",
            description="Generic HTTP request via requests.request() or Session.request()",
        ),
        EffectCallPattern(
            fqn="requests.sessions.Session.send",
            category="OUTBOUND_REQUEST",
            description="Send a PreparedRequest via Session.send()",
        ),
    )


def _sinks() -> tuple[TaintSinkPattern, ...]:
    """SSRF sinks on URL arguments (module-level + Session, merged)."""
    return (
        *[
            TaintSinkPattern(
                fqn=(f"requests.{m}", f"requests.api.{m}", f"requests.sessions.Session.{m}"),
                arg=0,
                sink_kind="SSRF",
                when=~arg(0).is_literal_string(),
                description=f"URL argument to requests.{m}() -- SSRF if user-controlled",
            )
            for m in _HTTP_METHODS
        ],
        # request(method, url) -- url is arg 1
        TaintSinkPattern(
            fqn=("requests.request", "requests.api.request", "requests.sessions.Session.request"),
            arg=1,
            sink_kind="SSRF",
            when=~arg(1).is_literal_string(),
            description="URL argument to requests.request() -- SSRF if user-controlled",
        ),
    )


class RequestsProvider(Provider):
    meta = ProviderMeta(
        id="requests",
        name="Requests",
        version="0.1.0",
        library="requests",
        library_fqn="requests",
    )

    effects = _effects()

    sinks = _sinks()

    checks = (
        SecurityCheckPattern(
            fqn="requests.auth.HTTPBasicAuth",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="HTTP Basic authentication (credentials in header)",
        ),
        SecurityCheckPattern(
            fqn="requests.auth.HTTPDigestAuth",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="HTTP Digest authentication",
        ),
    )

    propagators = (
        FlowPropagatorPattern(
            fqn="requests.models.Response.json",
            input_arg=0,
            output="return",
            description="Parsed JSON from HTTP response body",
        ),
    )
