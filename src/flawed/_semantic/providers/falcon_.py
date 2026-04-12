"""Falcon provider -- resource-based routing, request/response, middleware.

Falcon uses class-based resources with ``on_get``/``on_post`` methods
registered via ``app.add_route()``.  Middleware is duck-typed (no base
class required), so the ``MiddlewareClassPattern`` uses a sentinel FQN.

FQNs verified against Falcon 4.2.0 source.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    ClassViewPattern,
    EffectAttributePattern,
    EffectCallPattern,
    InputAttributePattern,
    InputMethodPattern,
    Provider,
    ProviderMeta,
    RouteCallPattern,
    TaintSinkPattern,
)


class FalconProvider(Provider):
    meta = ProviderMeta(
        id="falcon",
        name="Falcon",
        version="0.1.0",
        library="falcon",
        library_fqn="falcon",
    )

    # =================================================================
    # EP-1: Route registration
    # =================================================================

    routes = (
        # app.add_route("/users", UserResource())
        RouteCallPattern(
            fqn="falcon.app.App.add_route",
            rule_arg=0,
            view_func_kwarg="resource",
            methods_kwarg="",  # Falcon doesn't take methods here
        ),
        # ASGI variant
        RouteCallPattern(
            fqn="falcon.asgi.app.App.add_route",
            rule_arg=0,
            view_func_kwarg="resource",
            methods_kwarg="",
        ),
        # Resources dispatch by on_get / on_post / etc.
        # Falcon doesn't require a base class (duck typing), but
        # static analysis needs an anchor.  We use the abstract
        # concept -- the engine matches any class passed to add_route.
        ClassViewPattern(
            base_class_fqn="falcon.app.App",  # sentinel: matched via add_route
            method_map={
                "on_get": "GET",
                "on_post": "POST",
                "on_put": "PUT",
                "on_delete": "DELETE",
                "on_patch": "PATCH",
                "on_head": "HEAD",
                "on_options": "OPTIONS",
            },
            as_view_method="",  # no as_view in Falcon
        ),
    )

    # =================================================================
    # EP-2: Request input sources
    # =================================================================

    inputs = (
        # -- Method-call inputs (typed param accessors) --
        InputMethodPattern(
            fqn="falcon.request.Request.get_param",
            source_type="Query",
            key_arg=0,
            description="Query parameter by name",
        ),
        InputMethodPattern(
            fqn="falcon.request.Request.get_param_as_int",
            source_type="Query",
            key_arg=0,
            description="Query parameter coerced to int",
        ),
        InputMethodPattern(
            fqn="falcon.request.Request.get_param_as_float",
            source_type="Query",
            key_arg=0,
            description="Query parameter coerced to float",
        ),
        InputMethodPattern(
            fqn="falcon.request.Request.get_param_as_bool",
            source_type="Query",
            key_arg=0,
            description="Query parameter coerced to bool",
        ),
        InputMethodPattern(
            fqn="falcon.request.Request.get_param_as_uuid",
            source_type="Query",
            key_arg=0,
            description="Query parameter coerced to UUID",
        ),
        InputMethodPattern(
            fqn="falcon.request.Request.get_param_as_list",
            source_type="Query",
            key_arg=0,
            cardinality="MULTI",
            description="Query parameter as list of values",
        ),
        InputMethodPattern(
            fqn="falcon.request.Request.get_param_as_datetime",
            source_type="Query",
            key_arg=0,
            description="Query parameter coerced to datetime",
        ),
        InputMethodPattern(
            fqn="falcon.request.Request.get_param_as_date",
            source_type="Query",
            key_arg=0,
            description="Query parameter coerced to date",
        ),
        InputMethodPattern(
            fqn="falcon.request.Request.get_header",
            source_type="Header",
            key_arg=0,
            description="HTTP header by name",
        ),
        InputMethodPattern(
            fqn="falcon.request.Request.get_header_as_int",
            source_type="Header",
            key_arg=0,
            description="HTTP header coerced to int",
        ),
        InputMethodPattern(
            fqn="falcon.request.Request.get_cookie_values",
            source_type="Cookie",
            key_arg=0,
            cardinality="MULTI",
            description="Cookie values by name",
        ),
        InputMethodPattern(
            fqn="falcon.request.Request.get_media",
            source_type="Json",
            description="Deserialized request body (JSON/msgpack/etc.)",
        ),
        # -- Attribute-access inputs --
        InputAttributePattern(
            receiver_fqn="falcon.request.Request",
            attribute="media",
            source_type="Json",
            description="Deserialized request body (property form of get_media)",
        ),
        InputAttributePattern(
            receiver_fqn="falcon.request.Request",
            attribute="params",
            source_type="Query",
            cardinality="MULTI",
            description="Dict of all query string parameters",
        ),
        InputAttributePattern(
            receiver_fqn="falcon.request.Request",
            attribute="cookies",
            source_type="Cookie",
            cardinality="MULTI",
            description="Dict of all cookies",
        ),
        InputAttributePattern(
            receiver_fqn="falcon.request.Request",
            attribute="bounded_stream",
            source_type="RawBody",
            description="Length-bounded request body stream",
        ),
        InputAttributePattern(
            receiver_fqn="falcon.request.Request",
            attribute="path",
            source_type="PathParam",
            description="URL path component",
        ),
        InputAttributePattern(
            receiver_fqn="falcon.request.Request",
            attribute="uri",
            source_type="PathParam",
            description="Full request URI",
        ),
        InputAttributePattern(
            receiver_fqn="falcon.request.Request",
            attribute="query_string",
            source_type="Query",
            description="Raw query string",
        ),
        InputAttributePattern(
            receiver_fqn="falcon.request.Request",
            attribute="content_type",
            source_type="Header",
            description="Content-Type header value",
        ),
        InputAttributePattern(
            receiver_fqn="falcon.request.Request",
            attribute="host",
            source_type="Header",
            description="Host header (may be spoofable)",
        ),
        InputAttributePattern(
            receiver_fqn="falcon.request.Request",
            attribute="user_agent",
            source_type="Header",
            description="User-Agent header",
        ),
        InputAttributePattern(
            receiver_fqn="falcon.request.Request",
            attribute="access_route",
            source_type="Header",
            cardinality="MULTI",
            description="X-Forwarded-For IP chain (spoofable)",
        ),
    )

    # =================================================================
    # EP-3: Effects -- response manipulation and state
    # =================================================================

    effects = (
        # -- Response attribute writes --
        EffectAttributePattern(
            receiver_fqn="falcon.response.Response",
            category="RESPONSE_WRITE",
            description="Write to Falcon response (text/body/media/data/status)",
        ),
        # -- Response method calls --
        EffectCallPattern(
            fqn="falcon.response.Response.set_cookie",
            category="RESPONSE_WRITE",
            description="Set a cookie on the response",
        ),
        EffectCallPattern(
            fqn="falcon.response.Response.unset_cookie",
            category="RESPONSE_WRITE",
            description="Unset/delete a cookie",
        ),
        EffectCallPattern(
            fqn="falcon.response.Response.set_header",
            category="RESPONSE_WRITE",
            description="Set a response header",
        ),
        EffectCallPattern(
            fqn="falcon.response.Response.append_header",
            category="RESPONSE_WRITE",
            description="Append a value to a response header",
        ),
        EffectCallPattern(
            fqn="falcon.response.Response.set_headers",
            category="RESPONSE_WRITE",
            description="Set multiple response headers at once",
        ),
        # -- Request context (request-scoped state) --
        EffectAttributePattern(
            receiver_fqn="falcon.request.Request",
            category="STATE_WRITE",
            scope="REQUEST",
            description="Write to req.context (request-scoped state namespace)",
        ),
    )

    # =================================================================
    # EP-4: Security checks
    # =================================================================

    # Falcon has no built-in auth decorators.  Auth is typically
    # implemented via middleware.  Specific auth libraries (falcon-auth,
    # falcon-auth2) would get their own providers.

    # =================================================================
    # EP-6: Lifecycle -- middleware
    # =================================================================

    # Falcon middleware is duck-typed: any class with process_request /
    # process_response / process_resource methods.  There's no base
    # class to anchor on.  We declare the pattern anyway -- the engine
    # must scan classes passed to App(middleware=[...]) and check for
    # these method names.
    #
    # NOTE: This is a DSL limitation -- MiddlewareClassPattern requires
    # base_class_fqn, but Falcon middleware has none.  We use a
    # convention: the engine should also check middleware= kwarg on
    # App.__init__ to discover middleware classes.

    # =================================================================
    # EP-8b: Taint sinks
    # =================================================================

    sinks = (
        # falcon.HTTPError with user-controlled description
        TaintSinkPattern(
            fqn="falcon.HTTPError",
            arg=1,
            sink_kind="XSS",
            description="Error description reflected in response (XSS if HTML)",
        ),
    )
