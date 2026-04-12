"""Sanic provider -- async Python web framework.

Sanic uses Flask-like decorator routing (``@app.get``, ``@app.route``),
class-based views via ``HTTPMethodView``, and function-based middleware
via ``@app.middleware("request")``.  Mostly maps to existing DSL types.
"""

from __future__ import annotations

from typing import ClassVar

from flawed._semantic.providers._base import (
    ClassViewPattern,
    EffectCallPattern,
    EffectSubscriptPattern,
    HookType,
    InputAttributePattern,
    InputMethodPattern,
    LifecycleDecoratorPattern,
    Provider,
    ProviderMeta,
    RouteCallPattern,
    RouteDecorator,
    TaintSinkPattern,
)


class SanicProvider(Provider):
    meta = ProviderMeta(
        id="sanic",
        name="Sanic",
        version="0.1.0",
        library="sanic",
        library_fqn="sanic",
    )

    # Sanic.* methods are inherited from sanic.mixins.routes.RouteMixin
    fqn_aliases: ClassVar[dict[str, str]] = {
        "sanic.mixins.routes.RouteMixin": "sanic.app.Sanic",
        "sanic.mixins.listeners.ListenerMixin": "sanic.app.Sanic",
        "sanic.mixins.middleware.MiddlewareMixin": "sanic.app.Sanic",
    }

    # =================================================================
    # EP-1: Route registration
    # =================================================================

    routes = (
        # -- Decorator-based routing --
        RouteDecorator(
            fqn="sanic.app.Sanic.route",
            rule_arg=0,
            methods_kwarg="methods",
            default_methods=("GET",),
        ),
        RouteDecorator(
            fqn="sanic.app.Sanic.get",
            rule_arg=0,
            implied_method="GET",
        ),
        RouteDecorator(
            fqn="sanic.app.Sanic.post",
            rule_arg=0,
            implied_method="POST",
        ),
        RouteDecorator(
            fqn="sanic.app.Sanic.put",
            rule_arg=0,
            implied_method="PUT",
        ),
        RouteDecorator(
            fqn="sanic.app.Sanic.delete",
            rule_arg=0,
            implied_method="DELETE",
        ),
        RouteDecorator(
            fqn="sanic.app.Sanic.patch",
            rule_arg=0,
            implied_method="PATCH",
        ),
        RouteDecorator(
            fqn="sanic.app.Sanic.head",
            rule_arg=0,
            implied_method="HEAD",
        ),
        RouteDecorator(
            fqn="sanic.app.Sanic.options",
            rule_arg=0,
            implied_method="OPTIONS",
        ),
        # (RouteMixin duplicates eliminated via fqn_aliases)
        # -- Imperative add_route --
        RouteCallPattern(
            fqn="sanic.app.Sanic.add_route",
            rule_arg=1,
            view_func_kwarg="handler",
            methods_kwarg="methods",
        ),
        # -- Class-based views: HTTPMethodView --
        ClassViewPattern(
            base_class_fqn="sanic.views.HTTPMethodView",
            method_map={
                "get": "GET",
                "post": "POST",
                "put": "PUT",
                "delete": "DELETE",
                "patch": "PATCH",
                "head": "HEAD",
                "options": "OPTIONS",
            },
            as_view_method="as_view",
        ),
    )

    # =================================================================
    # EP-2: Request input sources
    # =================================================================

    inputs = (
        # -- Query parameters (request.args) --
        InputAttributePattern(
            receiver_fqn="sanic.request.types.Request",
            attribute="args",
            source_type="Query",
            cardinality="MULTI",
            description="URL query parameters (RequestParameters)",
        ),
        InputMethodPattern(
            fqn="sanic.request.types.Request.get_args",
            source_type="Query",
            cardinality="MULTI",
            description="URL query parameters via method call",
        ),
        # -- Form data --
        InputAttributePattern(
            receiver_fqn="sanic.request.types.Request",
            attribute="form",
            source_type="Form",
            cardinality="MULTI",
            description="POST form data (RequestParameters)",
        ),
        # -- JSON body --
        InputAttributePattern(
            receiver_fqn="sanic.request.types.Request",
            attribute="json",
            source_type="Json",
            description="Parsed JSON request body (property, not method)",
        ),
        # -- Raw body --
        InputAttributePattern(
            receiver_fqn="sanic.request.types.Request",
            attribute="body",
            source_type="RawBody",
            description="Raw request body bytes",
        ),
        # -- File uploads --
        InputAttributePattern(
            receiver_fqn="sanic.request.types.Request",
            attribute="files",
            source_type="FileUpload",
            cardinality="MULTI",
            description="Uploaded files (RequestParameters)",
        ),
        # -- Headers --
        InputAttributePattern(
            receiver_fqn="sanic.request.types.Request",
            attribute="headers",
            source_type="Header",
            cardinality="MULTI",
            description="HTTP request headers",
        ),
        # -- Cookies --
        InputAttributePattern(
            receiver_fqn="sanic.request.types.Request",
            attribute="cookies",
            source_type="Cookie",
            cardinality="MULTI",
            description="HTTP cookies",
        ),
        # -- Token (Authorization header value) --
        InputAttributePattern(
            receiver_fqn="sanic.request.types.Request",
            attribute="token",
            source_type="Header",
            description="Bearer/Token from Authorization header",
        ),
        # -- Client IP (may be spoofable via proxies) --
        InputAttributePattern(
            receiver_fqn="sanic.request.types.Request",
            attribute="ip",
            source_type="Header",
            description="Client IP address (spoofable via proxies)",
        ),
        # -- Host header --
        InputAttributePattern(
            receiver_fqn="sanic.request.types.Request",
            attribute="host",
            source_type="Header",
            description="Host header value",
        ),
        # -- URL path --
        InputAttributePattern(
            receiver_fqn="sanic.request.types.Request",
            attribute="path",
            source_type="PathParam",
            description="URL path",
        ),
        # -- Content type --
        InputAttributePattern(
            receiver_fqn="sanic.request.types.Request",
            attribute="content_type",
            source_type="Header",
            description="Content-Type header value",
        ),
        # -- Match info (path params) --
        InputAttributePattern(
            receiver_fqn="sanic.request.types.Request",
            attribute="match_info",
            source_type="PathParam",
            cardinality="MULTI",
            description="URL path parameters from route matching",
        ),
    )

    # =================================================================
    # EP-3: Effects -- response functions
    # =================================================================

    effects = (
        # -- Response convenience functions --
        EffectCallPattern(
            fqn="sanic.response.convenience.json",
            category="RESPONSE_WRITE",
            description="JSON response",
        ),
        EffectCallPattern(
            fqn="sanic.response.convenience.text",
            category="RESPONSE_WRITE",
            description="Plain text response",
        ),
        EffectCallPattern(
            fqn="sanic.response.convenience.html",
            category="RESPONSE_WRITE",
            description="HTML response",
        ),
        EffectCallPattern(
            fqn="sanic.response.convenience.raw",
            category="RESPONSE_WRITE",
            description="Raw bytes response",
        ),
        EffectCallPattern(
            fqn="sanic.response.convenience.redirect",
            category="RESPONSE_WRITE",
            description="HTTP redirect (open-redirect risk)",
        ),
        EffectCallPattern(
            fqn="sanic.response.convenience.file",
            category="FILE_READ",
            description="File response (path traversal risk)",
        ),
        EffectCallPattern(
            fqn="sanic.response.convenience.file_stream",
            category="FILE_READ",
            description="Streaming file response",
        ),
        EffectCallPattern(
            fqn="sanic.response.convenience.empty",
            category="RESPONSE_WRITE",
            description="Empty response",
        ),
        # -- Cookie manipulation via response --
        EffectSubscriptPattern(
            receiver_fqn="sanic.cookies.response.CookieJar",
            category="RESPONSE_WRITE",
            description="Set cookie on response (response.cookies[key] = value)",
        ),
    )

    # =================================================================
    # EP-6: Lifecycle hooks
    # =================================================================

    lifecycle = (
        # -- Middleware decorators --
        LifecycleDecoratorPattern(
            fqn="sanic.app.Sanic.middleware",
            hook_type=HookType.BEFORE_HANDLER,
            description="Register request or response middleware",
        ),
        LifecycleDecoratorPattern(
            fqn="sanic.app.Sanic.on_request",
            hook_type=HookType.BEFORE_HANDLER,
            description="Register request middleware (before handler)",
        ),
        LifecycleDecoratorPattern(
            fqn="sanic.app.Sanic.on_response",
            hook_type=HookType.AFTER_HANDLER,
            description="Register response middleware (after handler)",
        ),
        # (Mixin duplicates eliminated via fqn_aliases)
        # -- Listener decorators (server lifecycle) --
        LifecycleDecoratorPattern(
            fqn="sanic.app.Sanic.listener",
            hook_type=HookType.STARTUP,
            description="Server lifecycle listener (before_server_start, etc.)",
        ),
    )

    # =================================================================
    # EP-8b: Taint sinks
    # =================================================================

    sinks = (
        # -- Redirect with user-controlled destination --
        TaintSinkPattern(
            fqn="sanic.response.convenience.redirect",
            arg=0,
            sink_kind="OPEN_REDIRECT",
            description="Open redirect if destination is user-controlled",
        ),
        # -- File response with user-controlled path --
        TaintSinkPattern(
            fqn="sanic.response.convenience.file",
            arg=0,
            sink_kind="PATH_TRAVERSAL",
            description="Path traversal if file path is user-controlled",
        ),
        TaintSinkPattern(
            fqn="sanic.response.convenience.file_stream",
            arg=0,
            sink_kind="PATH_TRAVERSAL",
            description="Path traversal in streaming file response",
        ),
    )
