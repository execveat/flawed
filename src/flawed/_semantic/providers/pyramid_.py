"""Pyramid provider -- two-step route config, ACL security, tweens.

Pyramid has a unique two-step route+view configuration pattern:
``config.add_route("name", "/pattern")`` registers a named route,
then ``config.add_view(fn, route_name="name")`` or ``@view_config``
binds a view callable to it.  The correlation of add_route to
add_view requires an extraction hook.

Lifecycle is handled via subscriber events and tweens (middleware
equivalent).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed._semantic.providers._base import (
    CheckKind,
    EffectCallPattern,
    EffectSubscriptPattern,
    HookType,
    InputAttributePattern,
    LifecycleRegistrationPattern,
    Provider,
    ProviderMeta,
    RouteCallPattern,
    RouteDecorator,
    SecurityCheckPattern,
    TaintSinkPattern,
)

if TYPE_CHECKING:
    from collections.abc import Sequence


class PyramidProvider(Provider):
    meta = ProviderMeta(
        id="pyramid",
        name="Pyramid",
        version="0.1.0",
        library="pyramid",
        library_fqn="pyramid",
    )

    # =================================================================
    # EP-1: Routes
    # =================================================================

    routes = (
        # Imperative: config.add_route("home", "/") + config.add_view(...)
        # add_route registers a named route; add_view binds a view to it.
        # The actual correlation requires extract_routes, but we declare
        # both calls so the engine knows they exist.
        RouteCallPattern(
            fqn="pyramid.config.Configurator.add_route",
            rule_arg=1,  # pattern is 2nd arg: add_route(name, pattern)
            view_func_kwarg="view",  # not used for add_route; correlation in hook
            methods_kwarg="request_method",
        ),
        RouteCallPattern(
            fqn="pyramid.config.Configurator.add_view",
            rule_arg=-1,  # no rule arg; bound via route_name kwarg
            view_func_kwarg="view",
            methods_kwarg="request_method",
        ),
        # Decorator: @view_config(route_name="home", renderer="json")
        RouteDecorator(
            fqn="pyramid.view.view_config",
            rule_arg=-1,  # no positional rule; route binding via route_name kwarg
            methods_kwarg="request_method",
            default_methods=("GET",),
        ),
        # Class-level defaults: @view_defaults(route_name="home")
        RouteDecorator(
            fqn="pyramid.view.view_defaults",
            rule_arg=-1,
            methods_kwarg="request_method",
            default_methods=("GET",),
        ),
    )

    # =================================================================
    # EP-2: Input sources
    # =================================================================

    inputs = (
        # Combined query + form
        InputAttributePattern(
            receiver_fqn="pyramid.request.Request",
            attribute="params",
            source_type="Form",
            cardinality="MULTI",
            description="Combined query + POST parameters (MultiDict)",
        ),
        InputAttributePattern(
            receiver_fqn="pyramid.request.Request",
            attribute="GET",
            source_type="Query",
            cardinality="MULTI",
            description="URL query string parameters",
        ),
        InputAttributePattern(
            receiver_fqn="pyramid.request.Request",
            attribute="POST",
            source_type="Form",
            cardinality="MULTI",
            description="POST form-encoded body parameters",
        ),
        InputAttributePattern(
            receiver_fqn="pyramid.request.Request",
            attribute="json_body",
            source_type="Json",
            description="Parsed JSON request body",
        ),
        InputAttributePattern(
            receiver_fqn="pyramid.request.Request",
            attribute="json",
            source_type="Json",
            description="Alias for json_body (parsed JSON)",
        ),
        InputAttributePattern(
            receiver_fqn="pyramid.request.Request",
            attribute="body",
            source_type="RawBody",
            description="Raw request body bytes",
        ),
        InputAttributePattern(
            receiver_fqn="pyramid.request.Request",
            attribute="text",
            source_type="RawBody",
            description="Request body decoded as text",
        ),
        InputAttributePattern(
            receiver_fqn="pyramid.request.Request",
            attribute="headers",
            source_type="Header",
            cardinality="MULTI",
            description="HTTP request headers",
        ),
        InputAttributePattern(
            receiver_fqn="pyramid.request.Request",
            attribute="cookies",
            source_type="Cookie",
            cardinality="MULTI",
            description="HTTP cookies",
        ),
        InputAttributePattern(
            receiver_fqn="pyramid.request.Request",
            attribute="matchdict",
            source_type="PathParam",
            cardinality="MULTI",
            description="URL path parameters from route pattern",
        ),
        InputAttributePattern(
            receiver_fqn="pyramid.request.Request",
            attribute="path",
            source_type="PathParam",
            description="URL path string",
        ),
        InputAttributePattern(
            receiver_fqn="pyramid.request.Request",
            attribute="url",
            source_type="PathParam",
            description="Full request URL",
        ),
        InputAttributePattern(
            receiver_fqn="pyramid.request.Request",
            attribute="host",
            source_type="Header",
            description="Host header value",
        ),
        InputAttributePattern(
            receiver_fqn="pyramid.request.Request",
            attribute="content_type",
            source_type="Header",
            description="Content-Type header value",
        ),
        InputAttributePattern(
            receiver_fqn="pyramid.request.Request",
            attribute="method",
            source_type="Header",
            description="HTTP method (GET, POST, etc.)",
        ),
        InputAttributePattern(
            receiver_fqn="pyramid.request.Request",
            attribute="authorization",
            source_type="Header",
            description="Parsed Authorization header",
        ),
    )

    # =================================================================
    # EP-3: Effects
    # =================================================================

    effects = (
        # Response redirects
        EffectCallPattern(
            fqn="pyramid.httpexceptions.HTTPFound",
            category="RESPONSE_WRITE",
            description="HTTP 302 redirect (open-redirect risk if user-controlled)",
        ),
        EffectCallPattern(
            fqn="pyramid.httpexceptions.HTTPMovedPermanently",
            category="RESPONSE_WRITE",
            description="HTTP 301 permanent redirect",
        ),
        EffectCallPattern(
            fqn="pyramid.httpexceptions.HTTPForbidden",
            category="RESPONSE_WRITE",
            description="HTTP 403 Forbidden response",
        ),
        EffectCallPattern(
            fqn="pyramid.httpexceptions.HTTPUnauthorized",
            category="RESPONSE_WRITE",
            description="HTTP 401 Unauthorized response",
        ),
        EffectCallPattern(
            fqn="pyramid.httpexceptions.HTTPNotFound",
            category="RESPONSE_WRITE",
            description="HTTP 404 Not Found response",
        ),
        # Response construction
        EffectCallPattern(
            fqn="pyramid.response.Response",
            category="RESPONSE_WRITE",
            description="Construct HTTP response object",
        ),
        # Session state
        EffectSubscriptPattern(
            receiver_fqn="pyramid.session.BaseCookieSessionFactory",
            category="STATE_WRITE",
            scope="SESSION",
            description="Write to Pyramid session via subscript",
        ),
        # Authentication state management
        EffectCallPattern(
            fqn="pyramid.security.remember",
            category="STATE_WRITE",
            scope="SESSION",
            description="Set authentication headers (remember user)",
        ),
        EffectCallPattern(
            fqn="pyramid.security.forget",
            category="STATE_WRITE",
            scope="SESSION",
            description="Clear authentication headers (forget user)",
        ),
        # Config mutations
        EffectCallPattern(
            fqn="pyramid.config.Configurator.add_tween",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Register a tween (middleware) in the pipeline",
        ),
        EffectCallPattern(
            fqn="pyramid.config.Configurator.set_default_permission",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Set default permission for all views",
        ),
        EffectCallPattern(
            fqn="pyramid.config.Configurator.set_authentication_policy",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Set authentication policy",
        ),
        EffectCallPattern(
            fqn="pyramid.config.Configurator.set_authorization_policy",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Set authorization policy",
        ),
    )

    # =================================================================
    # EP-4: Security checks
    # =================================================================

    checks = (
        # Permission check via has_permission
        SecurityCheckPattern(
            fqn="pyramid.security.has_permission",
            kind=CheckKind.CALL,
            category="AUTHORIZATION",
            description="Check if principal has permission on context",
        ),
        # view_config permission kwarg acts as authorization gate
        # (handled via extract_routes; noted here for documentation)
        # Authenticated user check
        SecurityCheckPattern(
            fqn="pyramid.security.Authenticated",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="Special principal for authenticated users",
        ),
    )

    # =================================================================
    # EP-6: Lifecycle
    # =================================================================

    lifecycle = (
        # Subscriber-based lifecycle
        LifecycleRegistrationPattern(
            registration_fqn="pyramid.config.Configurator.add_subscriber",
            hook_type=HookType.SIGNAL,
            description="Register event subscriber (NewRequest, etc.)",
        ),
    )

    # =================================================================
    # EP-8b: Taint sinks
    # =================================================================

    sinks = (
        TaintSinkPattern(
            fqn="pyramid.httpexceptions.HTTPFound",
            arg=0,
            sink_kind="OPEN_REDIRECT",
            description="Redirect location — open redirect if user-controlled",
        ),
    )

    # =================================================================
    # Extraction hooks
    # =================================================================

    def extract_routes(self, idx: object) -> Sequence[object]:  # noqa: ARG002
        """Correlate add_route(name, pattern) with add_view(fn, route_name=name).

        Pyramid's two-step route configuration requires imperative
        extraction:
        1. Find all config.add_route(name, pattern) calls.
        2. Find all config.add_view(view, route_name=name) calls.
        3. Match on the route name to correlate pattern with view.
        4. Also find @view_config(route_name=name) decorators.
        5. Combine into Route objects.
        """
        return []
