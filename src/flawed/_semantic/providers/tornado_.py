"""Tornado provider -- handler-based routing, request/response, XSRF, auth.

Tornado uses class-based ``RequestHandler`` subclasses with HTTP-verb
methods (``get``, ``post``, etc.).  Routes are defined either as
constructor arguments to ``Application`` (imperative tuple list) or
via ``add_handlers``.

FQNs verified against Tornado 6.5.5 source.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    ClassViewPattern,
    EffectCallPattern,
    FlowPropagatorPattern,
    HookType,
    ImperativeRoutePattern,
    InputAttributePattern,
    InputMethodPattern,
    MiddlewareClassPattern,
    Provider,
    ProviderMeta,
    RouteCallPattern,
    SecurityCheckPattern,
    TaintSinkPattern,
)


class TornadoProvider(Provider):
    meta = ProviderMeta(
        id="tornado",
        name="Tornado",
        version="0.1.0",
        library="tornado",
        library_fqn="tornado",
    )

    # =================================================================
    # EP-1: Route registration
    # =================================================================

    routes = (
        # Imperative route list: Application([(r"/", Handler), ...])
        # Tornado uses tuples or URLSpec objects in a list passed to
        # the Application constructor.
        ImperativeRoutePattern(
            entry_fqn="tornado.routing.URLSpec",
            rule_arg=0,
            view_arg=1,
            view_kwarg="handler_class",
            list_variable=None,  # passed as constructor arg, not module variable
        ),
        # Application.add_handlers(".*", handler_list)
        RouteCallPattern(
            fqn="tornado.web.Application.add_handlers",
            rule_arg=0,
            view_func_kwarg="",  # handlers are in a list, not a kwarg
            methods_kwarg="",
        ),
        # RequestHandler subclasses dispatch by method name
        ClassViewPattern(
            base_class_fqn="tornado.web.RequestHandler",
            method_map={
                "get": "GET",
                "post": "POST",
                "put": "PUT",
                "delete": "DELETE",
                "patch": "PATCH",
                "head": "HEAD",
                "options": "OPTIONS",
            },
            as_view_method="",  # no as_view in Tornado
        ),
    )

    # =================================================================
    # EP-2: Request input sources
    # =================================================================

    inputs = (
        # -- Method-call inputs on RequestHandler --
        InputMethodPattern(
            fqn="tornado.web.RequestHandler.get_argument",
            source_type="Query",
            key_arg=0,
            description="Combined query + body argument by name",
        ),
        InputMethodPattern(
            fqn="tornado.web.RequestHandler.get_arguments",
            source_type="Query",
            key_arg=0,
            cardinality="MULTI",
            description="All values for combined query + body argument",
        ),
        InputMethodPattern(
            fqn="tornado.web.RequestHandler.get_query_argument",
            source_type="Query",
            key_arg=0,
            description="Query string argument by name",
        ),
        InputMethodPattern(
            fqn="tornado.web.RequestHandler.get_query_arguments",
            source_type="Query",
            key_arg=0,
            cardinality="MULTI",
            description="All values for query string argument",
        ),
        InputMethodPattern(
            fqn="tornado.web.RequestHandler.get_body_argument",
            source_type="Form",
            key_arg=0,
            description="POST body argument by name",
        ),
        InputMethodPattern(
            fqn="tornado.web.RequestHandler.get_body_arguments",
            source_type="Form",
            key_arg=0,
            cardinality="MULTI",
            description="All values for POST body argument",
        ),
        # -- Attribute-access inputs on HTTPServerRequest --
        # (accessed as self.request.* inside handlers)
        InputAttributePattern(
            receiver_fqn="tornado.httputil.HTTPServerRequest",
            attribute="body",
            source_type="RawBody",
            description="Raw request body bytes",
        ),
        InputAttributePattern(
            receiver_fqn="tornado.httputil.HTTPServerRequest",
            attribute="headers",
            source_type="Header",
            cardinality="MULTI",
            description="HTTP request headers (HTTPHeaders)",
        ),
        InputAttributePattern(
            receiver_fqn="tornado.httputil.HTTPServerRequest",
            attribute="cookies",
            source_type="Cookie",
            cardinality="MULTI",
            description="HTTP cookies (dict of Morsel objects)",
        ),
        InputAttributePattern(
            receiver_fqn="tornado.httputil.HTTPServerRequest",
            attribute="files",
            source_type="FileUpload",
            cardinality="MULTI",
            description="Uploaded files (dict of lists of HTTPFile)",
        ),
        InputAttributePattern(
            receiver_fqn="tornado.httputil.HTTPServerRequest",
            attribute="arguments",
            source_type="Query",
            cardinality="MULTI",
            description="Combined query + body arguments (dict of lists)",
        ),
        InputAttributePattern(
            receiver_fqn="tornado.httputil.HTTPServerRequest",
            attribute="query_arguments",
            source_type="Query",
            cardinality="MULTI",
            description="Query string arguments only",
        ),
        InputAttributePattern(
            receiver_fqn="tornado.httputil.HTTPServerRequest",
            attribute="body_arguments",
            source_type="Form",
            cardinality="MULTI",
            description="POST body arguments only",
        ),
        InputAttributePattern(
            receiver_fqn="tornado.httputil.HTTPServerRequest",
            attribute="path",
            source_type="PathParam",
            description="URL path component",
        ),
        InputAttributePattern(
            receiver_fqn="tornado.httputil.HTTPServerRequest",
            attribute="uri",
            source_type="PathParam",
            description="Full request URI",
        ),
        InputAttributePattern(
            receiver_fqn="tornado.httputil.HTTPServerRequest",
            attribute="full_url",
            source_type="PathParam",
            description="Full URL including scheme and host",
        ),
        InputAttributePattern(
            receiver_fqn="tornado.httputil.HTTPServerRequest",
            attribute="query",
            source_type="Query",
            description="Raw query string",
        ),
        InputAttributePattern(
            receiver_fqn="tornado.httputil.HTTPServerRequest",
            attribute="remote_ip",
            source_type="Header",
            description="Client IP (may be from X-Real-IP/X-Forwarded-For)",
        ),
        InputAttributePattern(
            receiver_fqn="tornado.httputil.HTTPServerRequest",
            attribute="host",
            source_type="Header",
            description="Host header value",
        ),
        # -- Cookie access via handler --
        InputMethodPattern(
            fqn="tornado.web.RequestHandler.get_cookie",
            source_type="Cookie",
            key_arg=0,
            description="Cookie value by name",
        ),
        InputMethodPattern(
            fqn="tornado.web.RequestHandler.get_signed_cookie",
            source_type="Cookie",
            key_arg=0,
            description="Signed cookie value (integrity-verified)",
        ),
    )

    # =================================================================
    # EP-3: Effects
    # =================================================================

    effects = (
        # -- Response output --
        EffectCallPattern(
            fqn="tornado.web.RequestHandler.write",
            category="RESPONSE_WRITE",
            description="Write data to response body",
        ),
        EffectCallPattern(
            fqn="tornado.web.RequestHandler.finish",
            category="RESPONSE_WRITE",
            description="Finish response (optional final chunk)",
        ),
        EffectCallPattern(
            fqn="tornado.web.RequestHandler.render",
            category="RESPONSE_WRITE",
            description="Render template and write to response",
        ),
        EffectCallPattern(
            fqn="tornado.web.RequestHandler.render_string",
            category="RESPONSE_WRITE",
            description="Render template to string",
        ),
        # -- Redirect --
        EffectCallPattern(
            fqn="tornado.web.RequestHandler.redirect",
            category="RESPONSE_WRITE",
            description="HTTP redirect (open-redirect risk if user-controlled)",
        ),
        # -- Cookie manipulation --
        EffectCallPattern(
            fqn="tornado.web.RequestHandler.set_cookie",
            category="RESPONSE_WRITE",
            description="Set a cookie on the response",
        ),
        EffectCallPattern(
            fqn="tornado.web.RequestHandler.set_signed_cookie",
            category="RESPONSE_WRITE",
            description="Set a signed (HMAC) cookie",
        ),
        EffectCallPattern(
            fqn="tornado.web.RequestHandler.clear_cookie",
            category="RESPONSE_WRITE",
            description="Clear a cookie",
        ),
        EffectCallPattern(
            fqn="tornado.web.RequestHandler.clear_all_cookies",
            category="RESPONSE_WRITE",
            description="Clear all cookies",
        ),
        # -- Header manipulation --
        EffectCallPattern(
            fqn="tornado.web.RequestHandler.set_header",
            category="RESPONSE_WRITE",
            description="Set a response header (overwrites)",
        ),
        EffectCallPattern(
            fqn="tornado.web.RequestHandler.add_header",
            category="RESPONSE_WRITE",
            description="Add a response header (appends)",
        ),
        EffectCallPattern(
            fqn="tornado.web.RequestHandler.set_status",
            category="RESPONSE_WRITE",
            description="Set HTTP response status code",
        ),
        # -- Error responses --
        EffectCallPattern(
            fqn="tornado.web.RequestHandler.send_error",
            category="RESPONSE_WRITE",
            description="Send error response",
        ),
    )

    # =================================================================
    # EP-4: Security checks
    # =================================================================

    checks = (
        # @tornado.web.authenticated decorator
        SecurityCheckPattern(
            fqn="tornado.web.authenticated",
            kind=CheckKind.DECORATOR,
            category="AUTHENTICATION",
            description="Requires get_current_user() to return truthy value",
        ),
        # XSRF protection
        SecurityCheckPattern(
            fqn="tornado.web.RequestHandler.check_xsrf_cookie",
            kind=CheckKind.METHOD_CALL,
            category="CSRF",
            description="Verify XSRF token (auto-called on POST/PUT/DELETE)",
        ),
    )

    lifecycle = (
        # Tornado lifecycle is via method overrides on RequestHandler, not
        # decorators.  Class-based lifecycle matching carries HookType so the
        # L2 core can attach these methods without Tornado-specific branches.
        MiddlewareClassPattern(
            base_class_fqn="tornado.web.RequestHandler",
            method_hooks={
                "prepare": HookType.BEFORE_HANDLER,
                "on_finish": HookType.AFTER_HANDLER,
                "get_current_user": HookType.BEFORE_HANDLER,
            },
            description="RequestHandler lifecycle method overrides",
        ),
    )

    # =================================================================
    # EP-8: Flow propagation
    # =================================================================

    propagators = (
        FlowPropagatorPattern(
            fqn="tornado.web.RequestHandler.render_string",
            input_arg=0,
            output="return",
            description="Template name flows to rendered output",
        ),
    )

    # =================================================================
    # EP-8b: Taint sinks
    # =================================================================

    sinks = (
        # redirect with user-controlled URL
        TaintSinkPattern(
            fqn="tornado.web.RequestHandler.redirect",
            arg=0,
            sink_kind="OPEN_REDIRECT",
            description="Redirect URL (open redirect if user-controlled)",
        ),
        # write with user-controlled data (XSS in non-JSON responses)
        TaintSinkPattern(
            fqn="tornado.web.RequestHandler.write",
            arg=0,
            sink_kind="XSS",
            description="Response body (XSS risk if HTML with user data)",
        ),
    )
