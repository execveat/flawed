"""Bottle provider -- single-file micro-framework routing, inputs, effects.

Bottle is a single-module framework (``bottle.py``).  All FQNs live
under the ``bottle`` namespace.  The ``Bottle`` class provides routing
decorators; ``BaseRequest`` and ``BaseResponse`` provide input/output.

FQNs verified against Bottle 0.13.4 source.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    EffectCallPattern,
    FlowPropagatorPattern,
    HookType,
    InputAttributePattern,
    InputMethodPattern,
    LifecycleDecoratorPattern,
    Provider,
    ProviderMeta,
    RouteDecorator,
    TaintSinkPattern,
)


class BottleProvider(Provider):
    meta = ProviderMeta(
        id="bottle",
        name="Bottle",
        version="0.1.0",
        library="bottle",
        library_fqn="bottle",
    )

    # =================================================================
    # EP-1: Route registration
    # =================================================================

    routes = (
        # @app.route("/path", method="GET")
        RouteDecorator(
            fqn="bottle.Bottle.route",
            rule_arg=0,
            methods_kwarg="method",
            default_methods=("GET",),
        ),
        # Shorthand decorators
        RouteDecorator(fqn="bottle.Bottle.get", implied_method="GET"),
        RouteDecorator(fqn="bottle.Bottle.post", implied_method="POST"),
        RouteDecorator(fqn="bottle.Bottle.put", implied_method="PUT"),
        RouteDecorator(fqn="bottle.Bottle.delete", implied_method="DELETE"),
        RouteDecorator(fqn="bottle.Bottle.patch", implied_method="PATCH"),
        # Module-level decorators (use default app)
        RouteDecorator(
            fqn="bottle.route",
            rule_arg=0,
            methods_kwarg="method",
            default_methods=("GET",),
        ),
        RouteDecorator(fqn="bottle.get", implied_method="GET"),
        RouteDecorator(fqn="bottle.post", implied_method="POST"),
        RouteDecorator(fqn="bottle.put", implied_method="PUT"),
        RouteDecorator(fqn="bottle.delete", implied_method="DELETE"),
    )

    # =================================================================
    # EP-2: Request input sources
    # =================================================================

    inputs = (
        # -- Attribute-access on BaseRequest --
        InputAttributePattern(
            receiver_fqn="bottle.BaseRequest",
            attribute="query",
            source_type="Query",
            cardinality="MULTI",
            description="URL query string parameters (FormsDict)",
        ),
        InputAttributePattern(
            receiver_fqn="bottle.BaseRequest",
            attribute="forms",
            source_type="Form",
            cardinality="MULTI",
            description="POST form-encoded body fields (FormsDict)",
        ),
        InputAttributePattern(
            receiver_fqn="bottle.BaseRequest",
            attribute="params",
            source_type="Form",
            cardinality="MULTI",
            description="Combined query + form parameters (FormsDict)",
        ),
        InputAttributePattern(
            receiver_fqn="bottle.BaseRequest",
            attribute="json",
            source_type="Json",
            description="Parsed JSON body (None if not JSON)",
        ),
        InputAttributePattern(
            receiver_fqn="bottle.BaseRequest",
            attribute="files",
            source_type="FileUpload",
            cardinality="MULTI",
            description="Uploaded files (FormsDict of FileUpload)",
        ),
        InputAttributePattern(
            receiver_fqn="bottle.BaseRequest",
            attribute="headers",
            source_type="Header",
            cardinality="MULTI",
            description="HTTP request headers (HeaderDict)",
        ),
        InputAttributePattern(
            receiver_fqn="bottle.BaseRequest",
            attribute="cookies",
            source_type="Cookie",
            cardinality="MULTI",
            description="HTTP cookies (dict)",
        ),
        InputAttributePattern(
            receiver_fqn="bottle.BaseRequest",
            attribute="body",
            source_type="RawBody",
            description="Raw request body (BytesIO stream)",
        ),
        InputAttributePattern(
            receiver_fqn="bottle.BaseRequest",
            attribute="url",
            source_type="PathParam",
            description="Full request URL",
        ),
        InputAttributePattern(
            receiver_fqn="bottle.BaseRequest",
            attribute="path",
            source_type="PathParam",
            description="URL path component",
        ),
        InputAttributePattern(
            receiver_fqn="bottle.BaseRequest",
            attribute="query_string",
            source_type="Query",
            description="Raw query string",
        ),
        InputAttributePattern(
            receiver_fqn="bottle.BaseRequest",
            attribute="content_type",
            source_type="Header",
            description="Content-Type header value",
        ),
        InputAttributePattern(
            receiver_fqn="bottle.BaseRequest",
            attribute="remote_addr",
            source_type="Header",
            description="Client IP address (may be spoofable behind proxy)",
        ),
        InputAttributePattern(
            receiver_fqn="bottle.BaseRequest",
            attribute="url_args",
            source_type="PathParam",
            cardinality="MULTI",
            description="URL path parameters matched from route",
        ),
        # -- Method-call inputs --
        InputMethodPattern(
            fqn="bottle.BaseRequest.get_header",
            source_type="Header",
            key_arg=0,
            description="HTTP header by name",
        ),
        InputMethodPattern(
            fqn="bottle.BaseRequest.get_cookie",
            source_type="Cookie",
            key_arg=0,
            description="Cookie value by key (with optional signing)",
        ),
    )

    # =================================================================
    # EP-3: Effects
    # =================================================================

    effects = (
        # -- Module-level response functions --
        EffectCallPattern(
            fqn="bottle.redirect",
            category="RESPONSE_WRITE",
            description="HTTP redirect (open-redirect risk if user-controlled)",
        ),
        EffectCallPattern(
            fqn="bottle.abort",
            category="RESPONSE_WRITE",
            description="Abort request with error status",
        ),
        EffectCallPattern(
            fqn="bottle.template",
            category="RESPONSE_WRITE",
            description="Render template (SimpleTemplate by default)",
        ),
        EffectCallPattern(
            fqn="bottle.jinja2_template",
            category="RESPONSE_WRITE",
            description="Render Jinja2 template",
        ),
        # -- BaseResponse methods --
        EffectCallPattern(
            fqn="bottle.BaseResponse.set_cookie",
            category="RESPONSE_WRITE",
            description="Set a cookie on the response",
        ),
        EffectCallPattern(
            fqn="bottle.BaseResponse.delete_cookie",
            category="RESPONSE_WRITE",
            description="Delete a cookie",
        ),
        EffectCallPattern(
            fqn="bottle.BaseResponse.set_header",
            category="RESPONSE_WRITE",
            description="Set a response header (overwrites existing)",
        ),
        EffectCallPattern(
            fqn="bottle.BaseResponse.add_header",
            category="RESPONSE_WRITE",
            description="Add a response header (appends)",
        ),
    )

    # =================================================================
    # EP-6: Lifecycle hooks
    # =================================================================

    lifecycle = (
        # @app.hook("before_request") / @app.hook("after_request")
        LifecycleDecoratorPattern(
            fqn="bottle.Bottle.hook",
            hook_type=HookType.BEFORE_HANDLER,
            description="Lifecycle hook decorator (before_request or after_request)",
        ),
        # Error handler
        LifecycleDecoratorPattern(
            fqn="bottle.Bottle.error",
            hook_type=HookType.ON_ERROR,
            description="Error handler for specific HTTP status codes",
        ),
    )

    # =================================================================
    # EP-8: Flow propagation
    # =================================================================

    propagators = (
        FlowPropagatorPattern(
            fqn="bottle.template",
            input_arg=0,
            output="return",
            description="Template name/string flows to rendered output",
        ),
    )

    # =================================================================
    # EP-8b: Taint sinks
    # =================================================================

    sinks = (
        # bottle.redirect with user-controlled URL
        TaintSinkPattern(
            fqn="bottle.redirect",
            arg=0,
            sink_kind="OPEN_REDIRECT",
            description="Redirect URL (open redirect if user-controlled)",
        ),
        # SimpleTemplate with user input (SSTI)
        TaintSinkPattern(
            fqn="bottle.template",
            arg=0,
            sink_kind="SSTI",
            description="Template string (SSTI risk if user-controlled)",
        ),
    )
