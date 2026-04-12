"""Starlette provider -- async web framework with ASGI foundation.

Starlette uses a mix of imperative route lists (``Route(...)``) and
optional decorator routing, class-based endpoints via ``HTTPEndpoint``,
and class-based middleware via ``BaseHTTPMiddleware``.  This provider
exercises three new DSL types: ``ImperativeRoutePattern``,
``MiddlewareClassPattern``, and ``ClassViewPattern``.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    ClassViewPattern,
    EffectCallPattern,
    HookType,
    ImperativeRoutePattern,
    InputAttributePattern,
    InputMethodPattern,
    LifecycleRegistrationPattern,
    MiddlewareClassPattern,
    Provider,
    ProviderMeta,
    RouteCallPattern,
    SecurityCheckPattern,
    TaintSinkPattern,
)


class StarletteProvider(Provider):
    meta = ProviderMeta(
        id="starlette",
        name="Starlette",
        version="0.1.0",
        library="starlette",
        library_fqn="starlette",
    )

    # =================================================================
    # EP-1: Route registration
    # =================================================================

    routes = (
        # -- Imperative route list: Route("/path", endpoint=handler) --
        ImperativeRoutePattern(
            entry_fqn="starlette.routing.Route",
            rule_arg=0,
            view_arg=1,
            view_kwarg="endpoint",
            methods_kwarg="methods",
            list_variable=None,
            nested_fqn="starlette.routing.Mount",
        ),
        # -- WebSocket routes --
        ImperativeRoutePattern(
            entry_fqn="starlette.routing.WebSocketRoute",
            rule_arg=0,
            view_arg=1,
            view_kwarg="endpoint",
            methods_kwarg=None,
            list_variable=None,
        ),
        # -- Imperative add_route on Starlette app --
        RouteCallPattern(
            fqn="starlette.applications.Starlette.add_route",
            rule_arg=0,
            view_func_kwarg="route",
            methods_kwarg="methods",
        ),
        # -- add_route on Router --
        RouteCallPattern(
            fqn="starlette.routing.Router.add_route",
            rule_arg=0,
            view_func_kwarg="route",
            methods_kwarg="methods",
        ),
        # -- Class-based endpoints: HTTPEndpoint --
        ClassViewPattern(
            base_class_fqn="starlette.endpoints.HTTPEndpoint",
            method_map={
                "get": "GET",
                "post": "POST",
                "put": "PUT",
                "delete": "DELETE",
                "patch": "PATCH",
                "head": "HEAD",
                "options": "OPTIONS",
            },
        ),
    )

    # =================================================================
    # EP-2: Request input sources
    # =================================================================

    inputs = (
        # -- Query parameters --
        InputAttributePattern(
            receiver_fqn="starlette.requests.Request",
            attribute="query_params",
            source_type="Query",
            cardinality="MULTI",
            description="URL query parameters (QueryParams mapping)",
        ),
        # -- Path parameters --
        InputAttributePattern(
            receiver_fqn="starlette.requests.Request",
            attribute="path_params",
            source_type="PathParam",
            cardinality="MULTI",
            description="URL path parameters extracted from route",
        ),
        # -- Headers --
        InputAttributePattern(
            receiver_fqn="starlette.requests.Request",
            attribute="headers",
            source_type="Header",
            cardinality="MULTI",
            description="HTTP request headers",
        ),
        # Also accessible via HTTPConnection base class
        InputAttributePattern(
            receiver_fqn="starlette.requests.HTTPConnection",
            attribute="headers",
            source_type="Header",
            cardinality="MULTI",
            description="HTTP request headers (via base class)",
        ),
        InputAttributePattern(
            receiver_fqn="starlette.requests.HTTPConnection",
            attribute="query_params",
            source_type="Query",
            cardinality="MULTI",
            description="URL query parameters (via base class)",
        ),
        InputAttributePattern(
            receiver_fqn="starlette.requests.HTTPConnection",
            attribute="path_params",
            source_type="PathParam",
            cardinality="MULTI",
            description="URL path parameters (via base class)",
        ),
        InputAttributePattern(
            receiver_fqn="starlette.requests.HTTPConnection",
            attribute="cookies",
            source_type="Cookie",
            cardinality="MULTI",
            description="HTTP cookies",
        ),
        # -- Cookies --
        InputAttributePattern(
            receiver_fqn="starlette.requests.Request",
            attribute="cookies",
            source_type="Cookie",
            cardinality="MULTI",
            description="HTTP cookies",
        ),
        # -- URL (attacker-controlled) --
        InputAttributePattern(
            receiver_fqn="starlette.requests.HTTPConnection",
            attribute="url",
            source_type="PathParam",
            description="Full request URL (attacker-controlled)",
        ),
        # -- Client address --
        InputAttributePattern(
            receiver_fqn="starlette.requests.HTTPConnection",
            attribute="client",
            source_type="Header",
            description="Client address (may be spoofable via proxies)",
        ),
        # -- Async method-call inputs --
        InputMethodPattern(
            fqn="starlette.requests.Request.json",
            source_type="Json",
            description="Parsed JSON request body (async)",
        ),
        InputMethodPattern(
            fqn="starlette.requests.Request.body",
            source_type="RawBody",
            description="Raw request body bytes (async)",
        ),
        InputMethodPattern(
            fqn="starlette.requests.Request.form",
            source_type="Form",
            cardinality="MULTI",
            description="Parsed form data / multipart (async)",
        ),
        # -- Session (requires SessionMiddleware) --
        InputAttributePattern(
            receiver_fqn="starlette.requests.HTTPConnection",
            attribute="session",
            source_type="Cookie",
            cardinality="MULTI",
            description="Server-side session data (requires SessionMiddleware)",
        ),
        # -- Auth data (requires AuthenticationMiddleware) --
        InputAttributePattern(
            receiver_fqn="starlette.requests.HTTPConnection",
            attribute="auth",
            source_type="Header",
            description="Authentication credentials (via AuthenticationMiddleware)",
        ),
        InputAttributePattern(
            receiver_fqn="starlette.requests.HTTPConnection",
            attribute="user",
            source_type="Header",
            description="Authenticated user object (via AuthenticationMiddleware)",
        ),
    )

    # =================================================================
    # EP-3: Effects -- response construction
    # =================================================================

    effects = (
        # -- Response classes --
        EffectCallPattern(
            fqn="starlette.responses.Response.__init__",
            category="RESPONSE_WRITE",
            description="Base HTTP response",
        ),
        EffectCallPattern(
            fqn="starlette.responses.JSONResponse.__init__",
            category="RESPONSE_WRITE",
            description="JSON response",
        ),
        EffectCallPattern(
            fqn="starlette.responses.HTMLResponse.__init__",
            category="RESPONSE_WRITE",
            description="HTML response",
        ),
        EffectCallPattern(
            fqn="starlette.responses.PlainTextResponse.__init__",
            category="RESPONSE_WRITE",
            description="Plain text response",
        ),
        EffectCallPattern(
            fqn="starlette.responses.RedirectResponse.__init__",
            category="RESPONSE_WRITE",
            description="HTTP redirect response (open-redirect risk)",
        ),
        EffectCallPattern(
            fqn="starlette.responses.StreamingResponse.__init__",
            category="RESPONSE_WRITE",
            description="Streaming response",
        ),
        EffectCallPattern(
            fqn="starlette.responses.FileResponse.__init__",
            category="FILE_READ",
            description="File response (path traversal risk)",
        ),
        # -- Cookie manipulation on Response --
        EffectCallPattern(
            fqn="starlette.responses.Response.set_cookie",
            category="RESPONSE_WRITE",
            description="Set cookie on response",
        ),
        EffectCallPattern(
            fqn="starlette.responses.Response.delete_cookie",
            category="RESPONSE_WRITE",
            description="Delete cookie from response",
        ),
        # -- Middleware registration --
        EffectCallPattern(
            fqn="starlette.applications.Starlette.add_middleware",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Register middleware (modifies app pipeline)",
        ),
    )

    # =================================================================
    # EP-4: Security checks
    # =================================================================

    checks = (
        # -- @requires(["authenticated"]) scope-based auth --
        SecurityCheckPattern(
            fqn="starlette.authentication.requires",
            kind=CheckKind.DECORATOR,
            category="AUTHORIZATION",
            description="Scope-based authorization decorator",
        ),
    )

    # =================================================================
    # EP-6: Lifecycle -- middleware
    # =================================================================

    lifecycle = (
        # -- Class-based middleware (BaseHTTPMiddleware) --
        MiddlewareClassPattern(
            base_class_fqn="starlette.middleware.base.BaseHTTPMiddleware",
            method_hooks={"dispatch": HookType.BEFORE_HANDLER},
            description="ASGI middleware with dispatch(request, call_next)",
        ),
        # -- AuthenticationMiddleware --
        LifecycleRegistrationPattern(
            registration_fqn="starlette.middleware.authentication.AuthenticationMiddleware.__init__",
            hook_type=HookType.BEFORE_HANDLER,
            description="Populates request.user and request.auth",
        ),
        # -- SessionMiddleware --
        LifecycleRegistrationPattern(
            registration_fqn="starlette.middleware.sessions.SessionMiddleware.__init__",
            hook_type=HookType.BEFORE_HANDLER,
            description="Cookie-based session middleware",
        ),
        # -- CORSMiddleware --
        LifecycleRegistrationPattern(
            registration_fqn="starlette.middleware.cors.CORSMiddleware.__init__",
            hook_type=HookType.AFTER_HANDLER,
            description="CORS header middleware",
        ),
        # -- TrustedHostMiddleware --
        LifecycleRegistrationPattern(
            registration_fqn="starlette.middleware.trustedhost.TrustedHostMiddleware.__init__",
            hook_type=HookType.BEFORE_HANDLER,
            description="Host header validation middleware",
        ),
        # -- HTTPSRedirectMiddleware --
        LifecycleRegistrationPattern(
            registration_fqn="starlette.middleware.httpsredirect.HTTPSRedirectMiddleware.__init__",
            hook_type=HookType.BEFORE_HANDLER,
            description="HTTPS redirect middleware",
        ),
        # -- GZipMiddleware --
        LifecycleRegistrationPattern(
            registration_fqn="starlette.middleware.gzip.GZipMiddleware.__init__",
            hook_type=HookType.AFTER_HANDLER,
            description="Response compression middleware",
        ),
    )

    # =================================================================
    # EP-8b: Taint sinks
    # =================================================================

    sinks = (
        # -- RedirectResponse with user-controlled URL --
        TaintSinkPattern(
            fqn="starlette.responses.RedirectResponse.__init__",
            arg=0,
            sink_kind="OPEN_REDIRECT",
            description="Open redirect if URL is user-controlled",
        ),
        # -- FileResponse with user-controlled path --
        TaintSinkPattern(
            fqn="starlette.responses.FileResponse.__init__",
            arg=0,
            sink_kind="PATH_TRAVERSAL",
            description="Path traversal if path is user-controlled",
        ),
    )
