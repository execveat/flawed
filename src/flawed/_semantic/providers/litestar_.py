"""Litestar provider -- routes, parameter inputs, DI, guards, middleware.

Litestar (formerly Starlite) is an ASGI framework with patterns similar
to FastAPI but with its own guard/middleware system.  It exercises four
of the five new DSL types:

- ``InputParameterPattern`` -- parameter marker defaults for inputs
- ``DependencyPattern`` -- ``Provide()`` DI mechanism
- ``ClassAttributeGuardPattern`` -- ``guards=[...]`` on controllers/routes
- ``MiddlewareClassPattern`` -- ``AbstractMiddleware`` subclass hooks

Litestar was not available locally for FQN verification.  FQNs are
based on the public API documentation (litestar 2.x series).  All
public exports are re-exported from the top-level ``litestar`` package.

FQN conventions:
- Route decorators: ``litestar.handlers.get``, ``litestar.handlers.post``, etc.
  Re-exported as ``litestar.get``, ``litestar.post``.
- Parameter markers: ``litestar.params.Body``, ``litestar.params.Parameter``, etc.
- DI: ``litestar.di.Provide``.
- Guards: ``litestar.connection.base.ASGIConnection`` (guard callable signature).
- Controllers: ``litestar.controller.Controller``.
- Middleware: ``litestar.middleware.base.AbstractMiddleware``.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    ClassAttributeGuardPattern,
    ClassViewPattern,
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


class LitestarProvider(Provider):
    meta = ProviderMeta(
        id="litestar",
        name="Litestar",
        version="0.1.0",
        library="litestar",
        library_fqn="litestar",
    )

    # =================================================================
    # EP-1: Route registration
    # =================================================================
    #
    # Litestar uses top-level decorator functions: @get("/"), @post("/")
    # These are re-exported from litestar.handlers.http_handlers.

    routes = (
        # -- Function-level route decorators -----------------------------
        RouteDecorator(
            fqn="litestar.handlers.http_handlers.get",
            implied_method="GET",
        ),
        RouteDecorator(
            fqn="litestar.handlers.http_handlers.post",
            implied_method="POST",
        ),
        RouteDecorator(
            fqn="litestar.handlers.http_handlers.put",
            implied_method="PUT",
        ),
        RouteDecorator(
            fqn="litestar.handlers.http_handlers.delete",
            implied_method="DELETE",
        ),
        RouteDecorator(
            fqn="litestar.handlers.http_handlers.patch",
            implied_method="PATCH",
        ),
        RouteDecorator(
            fqn="litestar.handlers.http_handlers.head",
            implied_method="HEAD",
        ),
        # -- Generic @route with explicit method list --------------------
        RouteDecorator(
            fqn="litestar.handlers.http_handlers.route",
            rule_arg=0,
            methods_kwarg="http_method",
            default_methods=("GET",),
        ),
        # -- Controller (class-based views) ------------------------------
        #
        # Litestar controllers are classes that contain @get/@post methods.
        # The controller itself is registered with Router or app via
        # route_handlers=[MyController].  HTTP method dispatch is handled
        # by the decorators on the methods, not by method names.
        ClassViewPattern(
            base_class_fqn="litestar.controller.Controller",
            method_map={
                "get": "GET",
                "post": "POST",
                "put": "PUT",
                "delete": "DELETE",
                "patch": "PATCH",
                "head": "HEAD",
            },
        ),
    )

    # =================================================================
    # EP-2: Input sources (parameter annotation markers)
    # =================================================================

    inputs = (
        # -- Parameter marker defaults (InputParameterPattern) -----------
        InputParameterPattern(
            default_type_fqn="litestar.params.Parameter",
            source_type="Query",
            key_from="param_name",
            description="Generic parameter marker (defaults to query)",
        ),
        InputParameterPattern(
            default_type_fqn="litestar.params.Body",
            source_type="Json",
            key_from="param_name",
            description="Request body parameter",
        ),
        InputParameterPattern(
            default_type_fqn="litestar.params.Header",
            source_type="Header",
            key_from="param_name",
            description="HTTP header parameter",
        ),
        InputParameterPattern(
            default_type_fqn="litestar.params.Cookie",
            source_type="Cookie",
            key_from="param_name",
            description="Cookie value parameter",
        ),
        # -- Direct Request attribute access -----------------------------
        InputAttributePattern(
            receiver_fqn="litestar.connection.request.Request",
            attribute="query_params",
            source_type="Query",
            cardinality="MULTI",
            description="URL query parameters",
        ),
        InputAttributePattern(
            receiver_fqn="litestar.connection.request.Request",
            attribute="headers",
            source_type="Header",
            cardinality="MULTI",
            description="HTTP request headers",
        ),
        InputAttributePattern(
            receiver_fqn="litestar.connection.request.Request",
            attribute="cookies",
            source_type="Cookie",
            cardinality="MULTI",
            description="HTTP cookies",
        ),
        InputAttributePattern(
            receiver_fqn="litestar.connection.request.Request",
            attribute="path_params",
            source_type="PathParam",
            cardinality="MULTI",
            description="URL path parameters",
        ),
        InputAttributePattern(
            receiver_fqn="litestar.connection.request.Request",
            attribute="url",
            source_type="PathParam",
            description="Full request URL",
        ),
        InputAttributePattern(
            receiver_fqn="litestar.connection.request.Request",
            attribute="method",
            source_type="Header",
            description="HTTP method string",
        ),
        InputAttributePattern(
            receiver_fqn="litestar.connection.request.Request",
            attribute="client",
            source_type="Header",
            description="Client address",
        ),
        # -- Request method-call inputs ----------------------------------
        InputMethodPattern(
            fqn="litestar.connection.request.Request.json",
            source_type="Json",
            description="Parsed JSON body",
        ),
        InputMethodPattern(
            fqn="litestar.connection.request.Request.form",
            source_type="Form",
            cardinality="MULTI",
            description="Parsed form data",
        ),
        InputMethodPattern(
            fqn="litestar.connection.request.Request.body",
            source_type="RawBody",
            description="Raw request body bytes",
        ),
        InputMethodPattern(
            fqn="litestar.connection.request.Request.stream",
            source_type="RawBody",
            description="Streaming request body",
        ),
    )

    # =================================================================
    # Dependency injection
    # =================================================================

    dependencies = (
        DependencyPattern(
            inject_fqn="litestar.di.Provide",
            callable_arg=0,
            scope="lifecycle_and_input",
            description="Litestar DI -- Provide(callable) runs before handler",
        ),
    )

    # =================================================================
    # EP-4: Security checks (class-attribute guards)
    # =================================================================
    #
    # Litestar guards are declared as ``guards=[guard_fn]`` on controllers,
    # handlers, or the app itself.  Guard functions receive
    # ``(connection, handler)`` and raise to deny access.

    checks = (
        ClassAttributeGuardPattern(
            view_base_fqn="litestar.controller.Controller",
            attribute_name="guards",
            guard_base_fqn="litestar.types.Guard",
            category="AUTHORIZATION",
            empty_means_unprotected=True,
            description="Controller-level guard list",
        ),
        # -- Built-in session auth guard ---------------------------------
        SecurityCheckPattern(
            fqn="litestar.security.session_auth.auth.SessionAuth",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="Session-based authentication middleware",
        ),
        SecurityCheckPattern(
            fqn="litestar.security.jwt.auth.JWTAuth",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="JWT authentication middleware",
        ),
        SecurityCheckPattern(
            fqn="litestar.security.jwt.auth.JWTCookieAuth",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="JWT cookie-based authentication",
        ),
        SecurityCheckPattern(
            fqn="litestar.security.jwt.auth.OAuth2Login",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="OAuth2 login flow",
        ),
        SecurityCheckPattern(
            fqn="litestar.security.jwt.auth.OAuth2PasswordBearerAuth",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="OAuth2 password bearer authentication",
        ),
    )

    # =================================================================
    # EP-3/EP-5: Effects
    # =================================================================

    effects = (
        # -- Response cookie manipulation --------------------------------
        EffectCallPattern(
            fqn="litestar.response.base.Response.set_cookie",
            category="RESPONSE_WRITE",
            description="Set cookie on response",
        ),
        EffectCallPattern(
            fqn="litestar.response.base.Response.delete_cookie",
            category="RESPONSE_WRITE",
            description="Delete cookie from response",
        ),
        # -- Response types ----------------------------------------------
        EffectCallPattern(
            fqn="litestar.response.redirect.Redirect",
            category="RESPONSE_WRITE",
            description="HTTP redirect response",
        ),
        EffectCallPattern(
            fqn="litestar.response.file.File",
            category="FILE_READ",
            description="File response (path traversal risk)",
        ),
        EffectCallPattern(
            fqn="litestar.response.streaming.Stream",
            category="RESPONSE_WRITE",
            description="Streaming response",
        ),
        EffectCallPattern(
            fqn="litestar.response.template.Template",
            category="RESPONSE_WRITE",
            description="Template response",
        ),
    )

    # =================================================================
    # EP-6: Lifecycle and middleware
    # =================================================================

    lifecycle = (
        # -- Event hooks (decorator-based) -------------------------------
        LifecycleDecoratorPattern(
            fqn="litestar.app.Litestar.on_startup",
            hook_type=HookType.STARTUP,
            scope="global",
            description="Application startup hook",
        ),
        LifecycleDecoratorPattern(
            fqn="litestar.app.Litestar.on_shutdown",
            hook_type=HookType.SHUTDOWN,
            scope="global",
            description="Application shutdown hook",
        ),
        # -- Class-based middleware (MiddlewareClassPattern) --------------
        MiddlewareClassPattern(
            base_class_fqn="litestar.middleware.base.AbstractMiddleware",
            method_hooks={
                "__call__": HookType.BEFORE_HANDLER,
            },
            description="Litestar AbstractMiddleware subclass",
        ),
    )

    # =================================================================
    # EP-7: Dispatch patterns
    # =================================================================

    dispatches = (
        DispatchPattern(
            source_fqn="litestar.background_tasks.BackgroundTask",
            target_method_names=("fn",),
            dispatch_type="background_task",
            callback_arg=0,
            callback_kwarg="fn",
            description="Background task scheduled after response",
        ),
    )

    # =================================================================
    # EP-8: Taint sinks
    # =================================================================

    sinks = (
        TaintSinkPattern(
            fqn="litestar.response.redirect.Redirect",
            arg=0,
            sink_kind="OPEN_REDIRECT",
            description="Redirect URL -- open redirect risk",
        ),
        TaintSinkPattern(
            fqn="litestar.response.file.File",
            arg=0,
            sink_kind="PATH_TRAVERSAL",
            description="File path -- path traversal risk",
        ),
        TaintSinkPattern(
            fqn="litestar.response.template.Template",
            arg=0,
            sink_kind="SSTI",
            description="Template name/string -- SSTI if user-controlled",
        ),
    )

    # =================================================================
    # EP-8: Flow propagation
    # =================================================================

    propagators = (
        FlowPropagatorPattern(
            fqn="litestar.connection.request.Request.json",
            input_arg=0,
            output="return",
            description="Request body taint flows to parsed JSON",
        ),
        FlowPropagatorPattern(
            fqn="litestar.connection.request.Request.form",
            input_arg=0,
            output="return",
            description="Request body taint flows to parsed form",
        ),
    )
