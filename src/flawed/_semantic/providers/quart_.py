"""Quart provider -- async Flask-compatible web framework.

Quart is an async reimplementation of Flask.  Its ``Quart`` class
extends ``flask.sansio.app.App``, so it inherits Flask's routing
infrastructure.  Route patterns mirror Flask exactly but with
``quart.*`` FQNs.  Request properties are async (``await request.json``
instead of ``request.json``).

The Flask core provider handles ``flask.*`` FQNs.  This provider covers
the ``quart.*`` FQN namespace for code that imports directly from
``quart`` rather than relying on Flask compatibility.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    EffectCallPattern,
    HookType,
    InputAttributePattern,
    InputMethodPattern,
    LifecycleDecoratorPattern,
    Provider,
    ProviderMeta,
    RouteCallPattern,
    RouteDecorator,
    StateProxyPattern,
    TaintSinkPattern,
)


class QuartProvider(Provider):
    meta = ProviderMeta(
        id="quart",
        name="Quart",
        version="0.1.0",
        library="quart",
        library_fqn="quart",
    )

    # =================================================================
    # EP-1: Route registration
    # =================================================================

    routes = (
        # -- Decorator routing (Quart + Blueprint, mirrors Flask) --------
        RouteDecorator(
            fqn=("quart.app.Quart.route", "quart.blueprints.Blueprint.route"),
            rule_arg=0,
            methods_kwarg="methods",
            default_methods=("GET",),
        ),
        RouteDecorator(
            fqn=("quart.app.Quart.get", "quart.blueprints.Blueprint.get"), implied_method="GET"
        ),
        RouteDecorator(
            fqn=("quart.app.Quart.post", "quart.blueprints.Blueprint.post"), implied_method="POST"
        ),
        RouteDecorator(
            fqn=("quart.app.Quart.put", "quart.blueprints.Blueprint.put"), implied_method="PUT"
        ),
        RouteDecorator(
            fqn=("quart.app.Quart.delete", "quart.blueprints.Blueprint.delete"),
            implied_method="DELETE",
        ),
        RouteDecorator(
            fqn=("quart.app.Quart.patch", "quart.blueprints.Blueprint.patch"),
            implied_method="PATCH",
        ),
        # -- Imperative route registration --
        RouteCallPattern(
            fqn=("quart.app.Quart.add_url_rule", "quart.blueprints.Blueprint.add_url_rule"),
            rule_arg=0,
            view_func_kwarg="view_func",
            methods_kwarg="methods",
        ),
    )

    # =================================================================
    # EP-2: Request input sources
    # =================================================================

    inputs = (
        # -- Sync attribute access (same as Flask) --
        InputAttributePattern(
            receiver_fqn="quart.globals.request",
            attribute="args",
            source_type="Query",
            description="URL query parameters",
        ),
        InputAttributePattern(
            receiver_fqn="quart.globals.request",
            attribute="headers",
            source_type="Header",
            cardinality="MULTI",
            description="HTTP request headers",
        ),
        InputAttributePattern(
            receiver_fqn="quart.globals.request",
            attribute="cookies",
            source_type="Cookie",
            cardinality="MULTI",
            description="HTTP cookies",
        ),
        InputAttributePattern(
            receiver_fqn="quart.globals.request",
            attribute="view_args",
            source_type="PathParam",
            cardinality="MULTI",
            description="URL path parameters",
        ),
        InputAttributePattern(
            receiver_fqn="quart.globals.request",
            attribute="path",
            source_type="PathParam",
            description="URL path",
        ),
        InputAttributePattern(
            receiver_fqn="quart.globals.request",
            attribute="url",
            source_type="PathParam",
            description="Full request URL",
        ),
        InputAttributePattern(
            receiver_fqn="quart.globals.request",
            attribute="method",
            source_type="Header",
            description="HTTP method",
        ),
        InputAttributePattern(
            receiver_fqn="quart.globals.request",
            attribute="host",
            source_type="Header",
            description="Host header",
        ),
        InputAttributePattern(
            receiver_fqn="quart.globals.request",
            attribute="content_type",
            source_type="Header",
            description="Content-Type header",
        ),
        InputAttributePattern(
            receiver_fqn="quart.globals.request",
            attribute="authorization",
            source_type="Header",
            description="Parsed Authorization header",
        ),
        # -- Async property inputs (Quart-specific) --
        # These are awaited: data = await request.data
        InputAttributePattern(
            receiver_fqn="quart.wrappers.request.Request",
            attribute="data",
            source_type="RawBody",
            description="Raw request body bytes (async property)",
        ),
        InputAttributePattern(
            receiver_fqn="quart.wrappers.request.Request",
            attribute="json",
            source_type="Json",
            description="Parsed JSON body (async property)",
        ),
        InputAttributePattern(
            receiver_fqn="quart.wrappers.request.Request",
            attribute="form",
            source_type="Form",
            cardinality="MULTI",
            description="POST form data (async property)",
        ),
        InputAttributePattern(
            receiver_fqn="quart.wrappers.request.Request",
            attribute="files",
            source_type="FileUpload",
            cardinality="MULTI",
            description="Uploaded files (async property)",
        ),
        # -- Async method inputs --
        InputMethodPattern(
            fqn="quart.wrappers.request.Request.get_json",
            source_type="Json",
            description="Parsed JSON body via method (async)",
        ),
    )

    # =================================================================
    # EP-3: Effects
    # =================================================================

    effects = (
        # -- Quart-specific helper functions --
        EffectCallPattern(
            fqn="quart.helpers.redirect",
            category="RESPONSE_WRITE",
            description="HTTP redirect",
        ),
        EffectCallPattern(
            fqn="quart.helpers.abort",
            category="RESPONSE_WRITE",
            description="Abort request with error status",
        ),
        EffectCallPattern(
            fqn="quart.helpers.flash",
            category="RESPONSE_WRITE",
            description="Flash message (XSS risk if unescaped)",
        ),
        EffectCallPattern(
            fqn="quart.helpers.send_file",
            category="FILE_READ",
            description="Serve a file (path traversal risk)",
        ),
        EffectCallPattern(
            fqn="quart.helpers.send_from_directory",
            category="FILE_READ",
            description="Serve file from directory (safer)",
        ),
        EffectCallPattern(
            fqn="quart.helpers.make_response",
            category="RESPONSE_WRITE",
            description="Construct response object",
        ),
        # -- Session writes (via quart.globals.session proxy) --
        # Session subscript writes are handled by the Flask core provider
        # since quart.globals.session delegates to the same mechanism.
    )

    # =================================================================
    # EP-6: Lifecycle hooks
    # =================================================================

    lifecycle = (
        LifecycleDecoratorPattern(
            fqn="quart.app.Quart.before_request",
            hook_type=HookType.BEFORE_HANDLER,
            scope="global",
        ),
        LifecycleDecoratorPattern(
            fqn="quart.app.Quart.after_request",
            hook_type=HookType.AFTER_HANDLER,
            scope="global",
        ),
        LifecycleDecoratorPattern(
            fqn="quart.app.Quart.teardown_request",
            hook_type=HookType.TEARDOWN,
            scope="global",
        ),
        LifecycleDecoratorPattern(
            fqn="quart.app.Quart.errorhandler",
            hook_type=HookType.ON_ERROR,
            scope="global",
        ),
        # Blueprint-scoped hooks
        LifecycleDecoratorPattern(
            fqn="quart.blueprints.Blueprint.before_request",
            hook_type=HookType.BEFORE_HANDLER,
            scope="group",
        ),
        LifecycleDecoratorPattern(
            fqn="quart.blueprints.Blueprint.after_request",
            hook_type=HookType.AFTER_HANDLER,
            scope="group",
        ),
        LifecycleDecoratorPattern(
            fqn="quart.blueprints.Blueprint.teardown_request",
            hook_type=HookType.TEARDOWN,
            scope="group",
        ),
        LifecycleDecoratorPattern(
            fqn="quart.blueprints.Blueprint.errorhandler",
            hook_type=HookType.ON_ERROR,
            scope="group",
        ),
    )

    # =================================================================
    # EP-10: State proxies
    # =================================================================

    proxies = (
        StateProxyPattern(
            fqn="quart.globals.g",
            resolves_to="quart.ctx._AppCtxGlobals",
            scope="REQUEST",
            description="Request-scoped namespace (like Flask g)",
        ),
        StateProxyPattern(
            fqn="quart.globals.session",
            resolves_to="quart.sessions.SessionMixin",
            scope="SESSION",
            description="Server-side session",
        ),
        StateProxyPattern(
            fqn="quart.globals.request",
            resolves_to="quart.wrappers.request.Request",
            scope="REQUEST",
            description="Current request proxy",
        ),
    )

    # =================================================================
    # EP-8b: Taint sinks
    # =================================================================

    sinks = (
        TaintSinkPattern(
            fqn="quart.helpers.redirect",
            arg=0,
            sink_kind="OPEN_REDIRECT",
            description="Open redirect if location is user-controlled",
        ),
        TaintSinkPattern(
            fqn="quart.helpers.send_file",
            arg=0,
            sink_kind="PATH_TRAVERSAL",
            description="Path traversal if filename is user-controlled",
        ),
    )
