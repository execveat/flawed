"""FastAPI provider -- routes, parameter-based inputs, DI, middleware, security.

FastAPI is the most important non-Flask framework.  It exercises three of
the five new DSL types added for framework support:

- ``InputParameterPattern`` -- parameter default types as input sources
- ``DependencyPattern`` -- ``Depends()`` as compound lifecycle/input/guard
- ``MiddlewareClassPattern`` -- ``BaseHTTPMiddleware`` subclass hooks

FastAPI re-exports almost everything from Starlette.  FQNs here use the
public ``fastapi.*`` import path where users write ``from fastapi import X``,
and the underlying ``starlette.*`` path for types only accessed through
Starlette's API.

FQN verification notes:

- Route decorators: ``fastapi.applications.FastAPI.get`` etc. are defined
  on ``FastAPI(Starlette)``; ``fastapi.routing.APIRouter.get`` etc. are
  defined directly on ``APIRouter``.
- Param markers: ``fastapi.Query`` re-exports ``fastapi.param_functions.Query``
  which returns a ``fastapi.params.Query`` instance.  Static analysis sees
  the call to ``fastapi.param_functions.Query``.
- ``Depends`` / ``Security``: similarly re-exported through param_functions,
  returns ``fastapi.params.Depends`` / ``fastapi.params.Security`` instances.
- Security schemes: ``fastapi.security.OAuth2PasswordBearer`` etc. live in
  ``fastapi.security.oauth2`` but are re-exported via ``fastapi.security``.
- Response classes: re-exported from ``starlette.responses``.
- Request class: ``starlette.requests.Request``, re-exported as ``fastapi.Request``.
"""

from __future__ import annotations

from typing import ClassVar

from flawed._semantic.providers._base import (
    CheckKind,
    DependencyPattern,
    DispatchPattern,
    EffectCallPattern,
    FlowPropagatorPattern,
    HookType,
    InputAttributePattern,
    InputMethodPattern,
    InputParameterPattern,
    LifecycleDecoratorPattern,
    MiddlewareClassPattern,
    Provider,
    ProviderMeta,
    RouteDecorator,
    SecurityCheckPattern,
    TaintSinkPattern,
)


class FastAPIProvider(Provider):
    meta = ProviderMeta(
        id="fastapi",
        name="FastAPI",
        version="0.1.0",
        library="fastapi",
        library_fqn="fastapi",
    )
    fqn_aliases: ClassVar[dict[str, str]] = {
        "fastapi.FastAPI": "fastapi.applications.FastAPI",
        "fastapi.APIRouter": "fastapi.routing.APIRouter",
        "fastapi.Query": "fastapi.param_functions.Query",
        "fastapi.Path": "fastapi.param_functions.Path",
        "fastapi.Body": "fastapi.param_functions.Body",
        "fastapi.Form": "fastapi.param_functions.Form",
        "fastapi.Header": "fastapi.param_functions.Header",
        "fastapi.Cookie": "fastapi.param_functions.Cookie",
        "fastapi.File": "fastapi.param_functions.File",
        "fastapi.Depends": "fastapi.param_functions.Depends",
        "fastapi.Security": "fastapi.param_functions.Security",
        "fastapi.security.OAuth2PasswordBearer": ("fastapi.security.oauth2.OAuth2PasswordBearer"),
    }

    # =================================================================
    # EP-1: Route registration (decorator-based, like Flask)
    # =================================================================

    routes = (
        # -- FastAPI + APIRouter decorators (both inherit from APIRouter) --
        RouteDecorator(
            fqn=("fastapi.applications.FastAPI.get", "fastapi.routing.APIRouter.get"),
            implied_method="GET",
        ),
        RouteDecorator(
            fqn=("fastapi.applications.FastAPI.post", "fastapi.routing.APIRouter.post"),
            implied_method="POST",
        ),
        RouteDecorator(
            fqn=("fastapi.applications.FastAPI.put", "fastapi.routing.APIRouter.put"),
            implied_method="PUT",
        ),
        RouteDecorator(
            fqn=("fastapi.applications.FastAPI.delete", "fastapi.routing.APIRouter.delete"),
            implied_method="DELETE",
        ),
        RouteDecorator(
            fqn=("fastapi.applications.FastAPI.patch", "fastapi.routing.APIRouter.patch"),
            implied_method="PATCH",
        ),
        RouteDecorator(
            fqn=("fastapi.applications.FastAPI.options", "fastapi.routing.APIRouter.options"),
            implied_method="OPTIONS",
        ),
        RouteDecorator(
            fqn=("fastapi.applications.FastAPI.head", "fastapi.routing.APIRouter.head"),
            implied_method="HEAD",
        ),
        RouteDecorator(
            fqn=("fastapi.applications.FastAPI.trace", "fastapi.routing.APIRouter.trace"),
            implied_method="TRACE",
        ),
        RouteDecorator(
            fqn=("fastapi.applications.FastAPI.api_route", "fastapi.routing.APIRouter.api_route"),
            rule_arg=0,
            methods_kwarg="methods",
            default_methods=("GET",),
        ),
    )

    # =================================================================
    # EP-2: Input sources
    # =================================================================
    #
    # FastAPI has TWO input mechanisms:
    # 1. Parameter annotations with marker defaults (InputParameterPattern)
    # 2. Direct Starlette Request access (InputAttributePattern/InputMethodPattern)

    inputs = (
        # -- Parameter annotation markers (NEW DSL type) -----------------
        #
        # Static analysis sees calls to fastapi.param_functions.Query etc.
        # but users write ``from fastapi import Query`` (re-exported).
        # We declare both the public and internal FQNs.
        InputParameterPattern(
            default_type_fqn="fastapi.param_functions.Query",
            source_type="Query",
            key_from="param_name",
            description="URL query parameter via Query() default",
        ),
        InputParameterPattern(
            default_type_fqn="fastapi.param_functions.Path",
            source_type="PathParam",
            key_from="param_name",
            description="URL path parameter via Path() default",
        ),
        InputParameterPattern(
            default_type_fqn="fastapi.param_functions.Body",
            source_type="Json",
            key_from="param_name",
            description="JSON body field via Body() default",
        ),
        InputParameterPattern(
            default_type_fqn="fastapi.param_functions.Form",
            source_type="Form",
            key_from="param_name",
            description="Form field via Form() default",
        ),
        InputParameterPattern(
            default_type_fqn="fastapi.param_functions.Header",
            source_type="Header",
            key_from="param_name",
            description="HTTP header via Header() default",
        ),
        InputParameterPattern(
            default_type_fqn="fastapi.param_functions.Cookie",
            source_type="Cookie",
            key_from="param_name",
            description="Cookie value via Cookie() default",
        ),
        InputParameterPattern(
            default_type_fqn="fastapi.param_functions.File",
            source_type="FileUpload",
            key_from="param_name",
            description="Uploaded file via File() default",
        ),
        # -- Direct Starlette Request attribute access -------------------
        InputAttributePattern(
            receiver_fqn="starlette.requests.Request",
            attribute="query_params",
            source_type="Query",
            cardinality="MULTI",
            description="URL query parameters (QueryParams mapping)",
        ),
        InputAttributePattern(
            receiver_fqn="starlette.requests.Request",
            attribute="path_params",
            source_type="PathParam",
            cardinality="MULTI",
            description="URL path parameters dict",
        ),
        InputAttributePattern(
            receiver_fqn="starlette.requests.Request",
            attribute="headers",
            source_type="Header",
            cardinality="MULTI",
            description="HTTP request headers",
        ),
        InputAttributePattern(
            receiver_fqn="starlette.requests.Request",
            attribute="cookies",
            source_type="Cookie",
            cardinality="MULTI",
            description="HTTP cookies dict",
        ),
        InputAttributePattern(
            receiver_fqn="starlette.requests.Request",
            attribute="url",
            source_type="PathParam",
            description="Full request URL object",
        ),
        InputAttributePattern(
            receiver_fqn="starlette.requests.Request",
            attribute="method",
            source_type="Header",
            description="HTTP method string",
        ),
        InputAttributePattern(
            receiver_fqn="starlette.requests.Request",
            attribute="client",
            source_type="Header",
            description="Client address (may be spoofable behind proxy)",
        ),
        # -- Direct Request method-call inputs ---------------------------
        InputMethodPattern(
            fqn="starlette.requests.Request.json",
            source_type="Json",
            description="Parsed JSON request body",
        ),
        InputMethodPattern(
            fqn="starlette.requests.Request.form",
            source_type="Form",
            cardinality="MULTI",
            description="Parsed form data",
        ),
        InputMethodPattern(
            fqn="starlette.requests.Request.body",
            source_type="RawBody",
            description="Raw request body bytes",
        ),
        InputMethodPattern(
            fqn="starlette.requests.Request.stream",
            source_type="RawBody",
            description="Streaming request body",
        ),
    )

    # =================================================================
    # Dependency injection (NEW DSL type)
    # =================================================================

    dependencies = (
        DependencyPattern(
            inject_fqn="fastapi.param_functions.Depends",
            callable_arg=0,
            scope="lifecycle_and_input",
            description="General DI -- callable runs before handler, return injected",
        ),
        DependencyPattern(
            inject_fqn="fastapi.param_functions.Security",
            callable_arg=0,
            scope="guard",
            description="Security DI -- callable acts as auth/permission guard",
        ),
    )

    # =================================================================
    # EP-4: Security checks
    # =================================================================

    checks = (
        # -- OAuth2 security schemes (used as Depends/Security callables) -
        SecurityCheckPattern(
            fqn="fastapi.security.oauth2.OAuth2PasswordBearer",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="OAuth2 password bearer token extraction + validation",
        ),
        SecurityCheckPattern(
            fqn="fastapi.security.oauth2.OAuth2AuthorizationCodeBearer",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="OAuth2 authorization code bearer token extraction",
        ),
        # -- API key schemes -------------------------------------------
        SecurityCheckPattern(
            fqn="fastapi.security.api_key.APIKeyQuery",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="API key from query parameter",
        ),
        SecurityCheckPattern(
            fqn="fastapi.security.api_key.APIKeyHeader",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="API key from HTTP header",
        ),
        SecurityCheckPattern(
            fqn="fastapi.security.api_key.APIKeyCookie",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="API key from cookie",
        ),
        # -- HTTP auth schemes -----------------------------------------
        SecurityCheckPattern(
            fqn="fastapi.security.http.HTTPBasic",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="HTTP Basic authentication",
        ),
        SecurityCheckPattern(
            fqn="fastapi.security.http.HTTPBearer",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="HTTP Bearer token authentication",
        ),
        SecurityCheckPattern(
            fqn="fastapi.security.http.HTTPDigest",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="HTTP Digest authentication",
        ),
        # -- OpenID Connect -------------------------------------------
        SecurityCheckPattern(
            fqn="fastapi.security.open_id_connect_url.OpenIdConnect",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="OpenID Connect authentication",
        ),
    )

    # =================================================================
    # EP-3/EP-5: Effects
    # =================================================================

    effects = (
        # -- Response cookie manipulation --------------------------------
        EffectCallPattern(
            fqn="starlette.responses.Response.set_cookie",
            category="RESPONSE_WRITE",
            description="Set a cookie on the HTTP response",
        ),
        EffectCallPattern(
            fqn="starlette.responses.Response.delete_cookie",
            category="RESPONSE_WRITE",
            description="Delete a cookie from the response",
        ),
        # -- Response construction (may carry user-controlled data) ------
        EffectCallPattern(
            fqn="starlette.responses.RedirectResponse",
            category="RESPONSE_WRITE",
            description="HTTP redirect (open-redirect risk if URL is user-controlled)",
        ),
        EffectCallPattern(
            fqn="starlette.responses.HTMLResponse",
            category="RESPONSE_WRITE",
            description="HTML response (XSS risk if content is user-controlled)",
        ),
        EffectCallPattern(
            fqn="starlette.responses.JSONResponse",
            category="RESPONSE_WRITE",
            description="JSON response",
        ),
        EffectCallPattern(
            fqn="starlette.responses.PlainTextResponse",
            category="RESPONSE_WRITE",
            description="Plain text response",
        ),
        EffectCallPattern(
            fqn="starlette.responses.FileResponse",
            category="FILE_READ",
            description="Serve a file (path traversal risk)",
        ),
        EffectCallPattern(
            fqn="starlette.responses.StreamingResponse",
            category="RESPONSE_WRITE",
            description="Streaming response",
        ),
        # -- FastAPI-specific response types ----------------------------
        EffectCallPattern(
            fqn="fastapi.responses.UJSONResponse",
            category="RESPONSE_WRITE",
            description="UJSON-serialized response",
        ),
        EffectCallPattern(
            fqn="fastapi.responses.ORJSONResponse",
            category="RESPONSE_WRITE",
            description="ORJSON-serialized response",
        ),
    )

    # =================================================================
    # EP-6: Lifecycle hooks and middleware
    # =================================================================

    lifecycle = (
        # -- Decorator-based middleware ----------------------------------
        LifecycleDecoratorPattern(
            fqn="fastapi.applications.FastAPI.middleware",
            hook_type=HookType.BEFORE_HANDLER,
            scope="global",
            description="@app.middleware('http') decorator",
        ),
        # -- Exception handlers -----------------------------------------
        LifecycleDecoratorPattern(
            fqn="fastapi.applications.FastAPI.exception_handler",
            hook_type=HookType.ON_ERROR,
            scope="global",
            description="Custom exception handler registration",
        ),
        LifecycleDecoratorPattern(
            fqn="fastapi.routing.APIRouter.exception_handler",
            hook_type=HookType.ON_ERROR,
            scope="group",
            description="Router-scoped exception handler",
        ),
        # -- Event handlers (startup/shutdown) ---------------------------
        LifecycleDecoratorPattern(
            fqn="fastapi.applications.FastAPI.on_event",
            hook_type=HookType.STARTUP,
            scope="global",
            description="Startup/shutdown event handler (deprecated in favor of lifespan)",
        ),
        # -- Class-based middleware (Starlette) --------------------------
        MiddlewareClassPattern(
            base_class_fqn="starlette.middleware.base.BaseHTTPMiddleware",
            method_hooks={
                "dispatch": HookType.BEFORE_HANDLER,
            },
            description="Starlette BaseHTTPMiddleware subclass",
        ),
    )

    # =================================================================
    # EP-7: Dispatch resolution
    # =================================================================

    dispatches = (
        DispatchPattern(
            source_fqn="starlette.background.BackgroundTasks.add_task",
            target_method_names=("add_task",),
            dispatch_type="background_task",
            callback_arg=0,
            description="Background task scheduled after response is sent",
        ),
    )

    # =================================================================
    # EP-8: Taint sinks
    # =================================================================

    sinks = (
        # -- Open redirect risk -----------------------------------------
        TaintSinkPattern(
            fqn="starlette.responses.RedirectResponse",
            arg=0,
            sink_kind="OPEN_REDIRECT",
            description="Redirect URL -- open redirect if user-controlled",
        ),
        # -- Path traversal risk ----------------------------------------
        TaintSinkPattern(
            fqn="starlette.responses.FileResponse",
            arg=0,
            sink_kind="PATH_TRAVERSAL",
            description="File path in FileResponse -- path traversal risk",
        ),
        # -- XSS risk ---------------------------------------------------
        TaintSinkPattern(
            fqn="starlette.responses.HTMLResponse",
            arg=0,
            sink_kind="XSS",
            description="HTML content -- XSS if user input flows here unescaped",
        ),
    )

    # =================================================================
    # EP-8: Flow propagation
    # =================================================================

    propagators = (
        FlowPropagatorPattern(
            fqn="starlette.requests.Request.json",
            input_arg=0,
            output="return",
            description="Request body taint flows to parsed JSON",
        ),
        FlowPropagatorPattern(
            fqn="starlette.requests.Request.form",
            input_arg=0,
            output="return",
            description="Request body taint flows to parsed form data",
        ),
    )
