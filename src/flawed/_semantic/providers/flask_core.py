"""Flask core provider -- routes, lifecycle, inputs, state, effects, sinks.

Covers Flask, Werkzeug, Jinja2, and MarkupSafe -- the full Flask stack.
Declarative descriptors for common cases.  Complex structural patterns
(class-based view dispatch, router-group URL-prefix resolution) are
handled by generic DSL primitives declared here.

FQN resolution notes:

- ``flask.Flask`` and ``flask.Blueprint`` both inherit route/lifecycle
  methods from ``flask.sansio.scaffold.Scaffold``.  Users write
  ``app.route()`` and ``bp.route()`` so we declare both concrete FQNs.
- ``flask.globals.request`` is a ``LocalProxy`` to
  ``flask.wrappers.Request`` (which extends
  ``werkzeug.wrappers.request.Request``).  Request attribute/method
  FQNs use the proxy object FQN for static matching.
- ``flask.helpers.redirect`` wraps ``werkzeug.utils.redirect``.  We
  declare the Flask re-export FQN since users write ``flask.redirect()``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from collections.abc import Sequence

from flawed._semantic.providers._base import (
    CheckKind,
    ClassViewPattern,
    DispatchPattern,
    EffectAttributePattern,
    EffectCallPattern,
    EffectSubscriptPattern,
    FlowPropagatorPattern,
    HookType,
    InputAttributePattern,
    InputContainerPattern,
    InputMethodPattern,
    LifecycleDecoratorPattern,
    Provider,
    ProviderMeta,
    RouteCallPattern,
    RouteDecorator,
    RouterGroupMountPattern,
    RouterGroupPattern,
    SafeGeneratedURLPattern,
    SecurityCheckPattern,
    StateProxyPattern,
    TaintSinkPattern,
    ValidatedValueGuardPattern,
    arg,
    kwarg,
)


class FlaskProvider(Provider):
    meta = ProviderMeta(
        id="flask",
        name="Flask",
        version="0.1.0",
        library="Flask",
        library_fqn="flask",
    )
    fqn_aliases: ClassVar[dict[str, str]] = {
        "flask.g": "flask.globals.g",
        "flask.request": "flask.globals.request",
        "flask.session": "flask.globals.session",
        "flask.flash": "flask.helpers.flash",
        "flask.redirect": "flask.helpers.redirect",
        "flask.make_response": "flask.helpers.make_response",
        "flask.jsonify": "flask.json.jsonify",
        "flask.send_file": "flask.helpers.send_file",
        "flask.send_from_directory": "flask.helpers.send_from_directory",
        "flask.url_for": "flask.helpers.url_for",
        "flask.render_template": "flask.templating.render_template",
        "flask.render_template_string": "flask.templating.render_template_string",
    }

    # =================================================================
    # EP-1: Route registration
    # =================================================================

    routes = (
        # -- @app.route / @bp.route (both inherit from Scaffold) -------
        RouteDecorator(
            fqn=("flask.Flask.route", "flask.Blueprint.route"),
            rule_arg=0,
            methods_kwarg="methods",
            default_methods=("GET",),
        ),
        # -- HTTP-method shorthands: @app.get(), @bp.get(), etc. -------
        RouteDecorator(fqn=("flask.Flask.get", "flask.Blueprint.get"), implied_method="GET"),
        RouteDecorator(fqn=("flask.Flask.post", "flask.Blueprint.post"), implied_method="POST"),
        RouteDecorator(fqn=("flask.Flask.put", "flask.Blueprint.put"), implied_method="PUT"),
        RouteDecorator(
            fqn=("flask.Flask.delete", "flask.Blueprint.delete"), implied_method="DELETE"
        ),
        RouteDecorator(fqn=("flask.Flask.patch", "flask.Blueprint.patch"), implied_method="PATCH"),
        # -- Imperative: app.add_url_rule() ----------------------------
        RouteCallPattern(
            fqn=("flask.Flask.add_url_rule", "flask.Blueprint.add_url_rule"),
            rule_arg=0,
            view_func_kwarg="view_func",
            methods_kwarg="methods",
        ),
        # -- Class-based: MethodView with HTTP-verb dispatch -----------
        ClassViewPattern(
            base_class_fqn="flask.views.MethodView",
            method_map={
                "get": "GET",
                "post": "POST",
                "put": "PUT",
                "delete": "DELETE",
                "patch": "PATCH",
            },
            as_view_method="as_view",
        ),
    )

    # =================================================================
    # EP-1b: Router group namespacing (Blueprint)
    # =================================================================

    router_groups = (
        RouterGroupPattern(
            constructor_fqn="flask.Blueprint",
            name_arg=0,
            prefix_kwarg="url_prefix",
            description="Flask Blueprint route group constructor",
        ),
    )

    router_group_mounts = (
        RouterGroupMountPattern(
            app_fqn="flask.Flask",
            mount_method="register_blueprint",
            group_arg=0,
            prefix_kwarg="url_prefix",
            description="Flask app.register_blueprint() mount",
        ),
    )

    # =================================================================
    # EP-2: Request input sources
    # =================================================================

    inputs = (
        # -- Werkzeug Request attributes via flask.globals.request -----
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="args",
            source_type="Query",
            description="URL query string parameters (?key=value)",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="form",
            source_type="Form",
            description="POST form-encoded body fields",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="json",
            source_type="Json",
            description="Parsed JSON request body",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="data",
            source_type="RawBody",
            description="Raw request body bytes",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="files",
            source_type="FileUpload",
            cardinality="MULTI",
            description="Uploaded files (ImmutableMultiDict of FileStorage)",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="headers",
            source_type="Header",
            cardinality="MULTI",
            description="HTTP request headers",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="cookies",
            source_type="Cookie",
            cardinality="MULTI",
            description="HTTP cookies (ImmutableMultiDict)",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="values",
            source_type="Form",
            cardinality="MULTI",
            description="Combined args + form (CombinedMultiDict)",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="view_args",
            source_type="PathParam",
            cardinality="MULTI",
            description="URL path parameters matched from route rule",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="authorization",
            source_type="Header",
            description="Parsed Authorization header (may be None)",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="access_route",
            source_type="Header",
            cardinality="MULTI",
            description="X-Forwarded-For IP chain (spoofable)",
        ),
        # -- Path components (attacker-controlled URL) -----------------
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="path",
            source_type="PathParam",
            description="URL path (e.g. /users/42)",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="full_path",
            source_type="PathParam",
            description="URL path with query string",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="url",
            source_type="PathParam",
            description="Full request URL",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="base_url",
            source_type="PathParam",
            description="URL without query string",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="method",
            source_type="Header",
            description="HTTP method (GET, POST, etc.)",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="content_type",
            source_type="Header",
            description="Content-Type header value",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="host",
            source_type="Header",
            description="Host header (spoofable without TRUSTED_HOSTS)",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="referrer",
            source_type="Header",
            description="Referer header (spoofable)",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="user_agent",
            source_type="Header",
            description="User-Agent header",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="remote_addr",
            source_type="Header",
            description="Client IP (spoofable behind proxy without TRUSTED_HOSTS)",
        ),
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="stream",
            source_type="RawBody",
            description="Raw input stream (unbuffered body bytes)",
        ),
        # -- Method-call inputs ----------------------------------------
        InputMethodPattern(
            fqn=("flask.globals.request.get_json", "flask.wrappers.Request.get_json"),
            source_type="Json",
            description="Parsed JSON body via method call",
        ),
        InputMethodPattern(
            fqn=("flask.globals.request.get_data", "werkzeug.wrappers.request.Request.get_data"),
            source_type="RawBody",
            description="Raw request body bytes via method call",
        ),
        # -- Identity sources: session / g (FLAW-240) ------------------
        # Server-managed/request-scoped identifier containers. Emitted as
        # *identity* sources (is_identity_source=True) so subject/object and
        # presence-vs-validity rules can pair a session/g-sourced identifier
        # against a request-sourced one -- while FP-containment keeps them out
        # of the wildcard reads() stream. Reads only; writes are State effects.
        InputContainerPattern(
            receiver_fqn="flask.globals.session",
            source_type="SessionValue",
            access=("subscript", "method", "membership"),
            key_methods=("get", "pop"),
            description="Flask session value read by key (session[k] / .get / .pop)",
        ),
        InputContainerPattern(
            receiver_fqn="flask.globals.g",
            source_type="FrameworkGlobal",
            access=("attribute", "method", "membership"),
            key_methods=("get", "pop"),
            description="Flask g request-global value read by attribute/key (g.x / g.get)",
        ),
    )

    # =================================================================
    # EP-3/EP-5: Effects -- state, response, config, templates
    # =================================================================

    effects = (
        # -- State: Flask g (REQUEST scope) ----------------------------
        EffectAttributePattern(
            receiver_fqn="flask.globals.g",
            category="STATE_READ",
            scope="REQUEST",
            description="Read from Flask g (request-scoped namespace)",
        ),
        EffectAttributePattern(
            receiver_fqn="flask.globals.g",
            category="STATE_WRITE",
            scope="REQUEST",
            description="Write to Flask g (request-scoped namespace)",
        ),
        # -- State: session (SESSION scope) ----------------------------
        EffectSubscriptPattern(
            receiver_fqn="flask.globals.session",
            category="STATE_READ",
            scope="SESSION",
            description="Read from Flask server-side session",
        ),
        EffectSubscriptPattern(
            receiver_fqn="flask.globals.session",
            category="STATE_WRITE",
            scope="SESSION",
            description="Write to Flask server-side session",
        ),
        # -- Response: cookie manipulation -----------------------------
        EffectCallPattern(
            fqn="werkzeug.sansio.response.Response.set_cookie",
            category="RESPONSE_WRITE",
            description="Set a cookie on the HTTP response",
        ),
        EffectCallPattern(
            fqn="werkzeug.sansio.response.Response.delete_cookie",
            category="RESPONSE_WRITE",
            description="Delete a cookie from the HTTP response",
        ),
        # -- Response: redirects and aborts ----------------------------
        EffectCallPattern(
            fqn=("flask.helpers.redirect", "werkzeug.utils.redirect"),
            category="RESPONSE_WRITE",
            description="HTTP redirect (open-redirect risk if user-controlled)",
        ),
        EffectCallPattern(
            fqn="flask.helpers.abort",
            category="RESPONSE_WRITE",
            description="Abort request with HTTP error status",
        ),
        # -- Response: flash messages ----------------------------------
        EffectCallPattern(
            fqn="flask.helpers.flash",
            category="RESPONSE_WRITE",
            description="Flash message (XSS risk if unescaped in template)",
        ),
        # -- Response: make_response / jsonify -------------------------
        EffectCallPattern(
            fqn="flask.helpers.make_response",
            category="RESPONSE_WRITE",
            description="Construct explicit Response object",
        ),
        EffectCallPattern(
            fqn="flask.json.jsonify",
            category="RESPONSE_WRITE",
            description="Serialize data as JSON response",
        ),
        # -- File serving (path traversal risk) ------------------------
        EffectCallPattern(
            fqn=("flask.helpers.send_file", "werkzeug.utils.send_file"),
            category="FILE_READ",
            description="Serve a file (path traversal risk if user-controlled)",
        ),
        EffectCallPattern(
            fqn=("flask.helpers.send_from_directory", "werkzeug.utils.send_from_directory"),
            category="FILE_READ",
            description="Serve file from directory (safer than send_file)",
        ),
        # -- Templates -------------------------------------------------
        EffectCallPattern(
            fqn="flask.templating.render_template",
            category="RESPONSE_WRITE",
            description="Render Jinja2 template to string",
        ),
        EffectCallPattern(
            fqn="flask.templating.render_template_string",
            category="RESPONSE_WRITE",
            description="Render string as Jinja2 template (SSTI risk)",
        ),
        EffectCallPattern(
            fqn="jinja2.environment.Template.render",
            category="RESPONSE_WRITE",
            description="Direct Jinja2 template render",
        ),
        EffectCallPattern(
            fqn="jinja2.environment.Environment.from_string",
            category="RESPONSE_WRITE",
            description="Create template from string (SSTI if user-controlled)",
        ),
        # -- Config mutation -------------------------------------------
        EffectCallPattern(
            fqn="flask.config.Config.from_object",
            category="CONFIG_WRITE",
            description="Load config from Python object/module",
        ),
        EffectCallPattern(
            fqn="flask.config.Config.from_pyfile",
            category="CONFIG_WRITE",
            description="Load config from Python file",
        ),
        EffectCallPattern(
            fqn="flask.config.Config.from_envvar",
            category="CONFIG_WRITE",
            description="Load config from environment variable path",
        ),
        EffectCallPattern(
            fqn="flask.config.Config.from_mapping",
            category="CONFIG_WRITE",
            description="Load config from mapping/kwargs",
        ),
        EffectCallPattern(
            fqn="flask.config.Config.from_file",
            category="CONFIG_WRITE",
            description="Load config from file (JSON/TOML/etc.)",
        ),
        EffectSubscriptPattern(
            receiver_fqn=("flask.config.Config", "flask.Flask.config"),
            category="CONFIG_WRITE",
            description="Direct config key mutation (app.config['KEY'] = val)",
        ),
    )

    # =================================================================
    # EP-4: Security checks
    # =================================================================

    checks = (
        SecurityCheckPattern(
            fqn="werkzeug.security.check_password_hash",
            kind=CheckKind.CALL,
            category="PASSWORD_VERIFY",
            description="Verify password against hash (Werkzeug pbkdf2)",
        ),
        SecurityCheckPattern(
            fqn="werkzeug.security.generate_password_hash",
            kind=CheckKind.CALL,
            category="PASSWORD_HASH",
            description="Generate password hash (Werkzeug pbkdf2/scrypt)",
        ),
    )

    # =================================================================
    # EP-6: Lifecycle hooks
    # =================================================================

    lifecycle = (
        # -- App-level hooks (from Scaffold) ---------------------------
        LifecycleDecoratorPattern(
            fqn="flask.Flask.before_request",
            hook_type=HookType.BEFORE_HANDLER,
            scope="global",
        ),
        LifecycleDecoratorPattern(
            fqn="flask.Flask.after_request",
            hook_type=HookType.AFTER_HANDLER,
            scope="global",
        ),
        LifecycleDecoratorPattern(
            fqn="flask.Flask.teardown_request",
            hook_type=HookType.TEARDOWN,
            scope="global",
        ),
        LifecycleDecoratorPattern(
            fqn="flask.Flask.teardown_appcontext",
            hook_type=HookType.TEARDOWN,
            scope="global",
        ),
        LifecycleDecoratorPattern(
            fqn="flask.Flask.errorhandler",
            hook_type=HookType.ON_ERROR,
            scope="global",
        ),
        # -- Blueprint-scoped hooks ------------------------------------
        LifecycleDecoratorPattern(
            fqn="flask.Blueprint.before_request",
            hook_type=HookType.BEFORE_HANDLER,
            scope="group",
        ),
        LifecycleDecoratorPattern(
            fqn="flask.Blueprint.after_request",
            hook_type=HookType.AFTER_HANDLER,
            scope="group",
        ),
        LifecycleDecoratorPattern(
            fqn="flask.Blueprint.teardown_request",
            hook_type=HookType.TEARDOWN,
            scope="group",
        ),
        LifecycleDecoratorPattern(
            fqn="flask.Blueprint.errorhandler",
            hook_type=HookType.ON_ERROR,
            scope="group",
        ),
        # -- Blueprint hooks registered at app scope -------------------
        LifecycleDecoratorPattern(
            fqn="flask.Blueprint.before_app_request",
            hook_type=HookType.BEFORE_HANDLER,
            scope="global",
        ),
        LifecycleDecoratorPattern(
            fqn="flask.Blueprint.after_app_request",
            hook_type=HookType.AFTER_HANDLER,
            scope="global",
        ),
        # -- Per-request hook (not a decorator on the class) -----------
        LifecycleDecoratorPattern(
            fqn="flask.ctx.after_this_request",
            hook_type=HookType.AFTER_HANDLER,
            scope="global",
            description="Register callback for current request only",
        ),
    )

    # =================================================================
    # EP-7: Dispatch patterns
    # =================================================================

    dispatches = (
        # Flask signals — blinker-based event dispatch that the L1
        # call graph cannot follow.
        DispatchPattern(
            source_fqn="flask.signals.request_started",
            target_method_names=("connect", "connect_via"),
            dispatch_type="signal",
            description="Blinker signal dispatched at request start",
        ),
        DispatchPattern(
            source_fqn="flask.signals.request_finished",
            target_method_names=("connect", "connect_via"),
            dispatch_type="signal",
            description="Blinker signal dispatched at request end",
        ),
        DispatchPattern(
            source_fqn="flask.signals.got_request_exception",
            target_method_names=("connect", "connect_via"),
            dispatch_type="signal",
            description="Blinker signal dispatched on unhandled exception",
        ),
        DispatchPattern(
            source_fqn="flask.signals.request_tearing_down",
            target_method_names=("connect", "connect_via"),
            dispatch_type="signal",
            description="Blinker signal dispatched during request teardown",
        ),
        DispatchPattern(
            source_fqn="flask.signals.template_rendered",
            target_method_names=("connect", "connect_via"),
            dispatch_type="signal",
            description="Blinker signal dispatched after template render",
        ),
        DispatchPattern(
            source_fqn="flask.signals.before_render_template",
            target_method_names=("connect", "connect_via"),
            dispatch_type="signal",
            description="Blinker signal dispatched before template render",
        ),
        DispatchPattern(
            source_fqn="flask.signals.appcontext_tearing_down",
            target_method_names=("connect", "connect_via"),
            dispatch_type="signal",
            description="Blinker signal dispatched during app context teardown",
        ),
        DispatchPattern(
            source_fqn="flask.signals.message_flashed",
            target_method_names=("connect", "connect_via"),
            dispatch_type="signal",
            description="Blinker signal dispatched when flash() is called",
        ),
    )

    # =================================================================
    # EP-8: Taint sinks (injection vectors)
    # =================================================================

    sinks = (
        # render_template_string: SSTI when first arg is user-controlled
        TaintSinkPattern(
            fqn=("flask.render_template_string", "flask.templating.render_template_string"),
            arg=0,
            sink_kind="SSTI",
            when=~arg(0).is_literal_string(),
            description="Template string injection if user input flows here",
        ),
        # Jinja2 Environment.from_string: SSTI vector
        TaintSinkPattern(
            fqn="jinja2.environment.Environment.from_string",
            arg=0,
            sink_kind="SSTI",
            when=~arg(0).is_literal_string(),
            description="Jinja2 template from string -- SSTI if user-controlled",
        ),
        # redirect: open redirect when location is user-controlled
        TaintSinkPattern(
            fqn=("flask.helpers.redirect", "werkzeug.utils.redirect"),
            arg=0,
            keyword="location",
            sink_kind="OPEN_REDIRECT",
            description="Redirect target may be user-controlled",
        ),
        # send_file: path traversal when path is user-controlled
        TaintSinkPattern(
            fqn=("flask.helpers.send_file", "werkzeug.utils.send_file"),
            arg=0,
            sink_kind="PATH_TRAVERSAL",
            when=~arg(0).is_literal_string(),
            description="File path may be user-controlled (path traversal)",
        ),
        # Uploaded FileStorage.save(): path traversal when destination is user-controlled
        TaintSinkPattern(
            fqn=(
                "werkzeug.datastructures.FileStorage.save",
                "werkzeug.datastructures.file_storage.FileStorage.save",
                "flask.FileStorage.save",
            ),
            arg=0,
            keyword="dst",
            sink_kind="PATH_TRAVERSAL",
            when=~(arg(0).is_literal_string() | kwarg("dst").is_literal_string()),
            description="Uploaded file destination may be user-controlled (path traversal)",
        ),
        # Markup() wrapping bypasses Jinja2 autoescaping
        TaintSinkPattern(
            fqn="markupsafe.Markup",
            arg=0,
            sink_kind="XSS",
            description="Markup() marks string as safe -- XSS if user-controlled",
        ),
    )

    # =================================================================
    # EP-8a: Provider-generated safe URLs
    # =================================================================

    safe_generated_urls = (
        SafeGeneratedURLPattern(
            fqn="flask.helpers.url_for",
            safe_for_sink_kinds=("OPEN_REDIRECT",),
            external_kwarg="_external",
            external_safe=False,
            description=(
                "Flask url_for() builds application-local redirect targets "
                "when _external is absent or false"
            ),
        ),
    )

    # =================================================================
    # EP-8b: Project-local URL validation guards
    # =================================================================

    validation_guards = (
        # Name-based matching is intentional here: these helpers are
        # project-local functions (not from a known library) so they have
        # unpredictable FQNs.  The convention ``is_safe_url`` / ``is_valid_url``
        # is well-established across real-world Flask apps.
        # FQN matching would miss every project-local validator (false negatives).
        ValidatedValueGuardPattern(
            names=("is_safe_url", "is_valid_url", "is_safe_redirect_url"),
            arg=0,
            safe_for_sink_kinds=("OPEN_REDIRECT",),
            category="URL_VALIDATION",
            description=(
                "Project-local URL validator guarding redirect targets -- "
                "name-based matching for project-local helpers with "
                "unpredictable FQNs (a widespread Flask-app convention)"
            ),
        ),
    )

    # =================================================================
    # EP-8c: Flow propagation
    # =================================================================

    propagators = (
        # Data flows through url_for into the redirect target
        FlowPropagatorPattern(
            fqn="flask.helpers.url_for",
            input_arg=0,
            input_keyword="endpoint",
            input_variadic=True,
            output="return",
            description="Endpoint name + args flow into generated URL",
        ),
        # Data flows through make_response into Response body
        FlowPropagatorPattern(
            fqn="flask.helpers.make_response",
            input_arg=None,
            input_required=False,
            input_variadic=True,
            output="return",
            description="Response body flows through make_response",
        ),
        # Data flows through jsonify into Response body
        FlowPropagatorPattern(
            fqn="flask.json.jsonify",
            input_arg=None,
            input_required=False,
            input_variadic=True,
            output="return",
            description="Data flows through jsonify into JSON response",
        ),
        # Data flows through render_template into rendered output
        FlowPropagatorPattern(
            fqn="flask.templating.render_template",
            input_arg=None,
            input_required=False,
            input_variadic=True,
            excluded_input_args=(0,),
            excluded_input_keywords=("template_name",),
            output="return",
            description="Template context flows into rendered HTML",
        ),
        # Markup() propagates taint (marks safe but data flows through)
        FlowPropagatorPattern(
            fqn="markupsafe.Markup",
            input_arg=0,
            output="return",
            description="Input flows through Markup() unchanged",
        ),
        # markupsafe.escape() propagates (with HTML-encoding)
        FlowPropagatorPattern(
            fqn="markupsafe.escape",
            input_arg=0,
            output="return",
            description="Input flows through escape() with HTML encoding",
        ),
    )

    # =================================================================
    # EP-10: State proxies
    # =================================================================

    proxies = (
        StateProxyPattern(
            fqn="flask.globals.g",
            resolves_to="flask.ctx._AppCtxGlobals",
            scope="REQUEST",
            description="Request-scoped namespace for arbitrary attributes",
        ),
        StateProxyPattern(
            fqn="flask.globals.session",
            resolves_to="flask.sessions.SecureCookieSession",
            scope="SESSION",
            description="Server-side session (signed cookie by default)",
        ),
        StateProxyPattern(
            fqn="flask.globals.request",
            resolves_to="flask.wrappers.Request",
            scope="REQUEST",
            description="Proxy to current request object",
        ),
    )

    # =================================================================
    # Extraction hooks -- complex patterns requiring imperative code
    # =================================================================

    def extract_routes(self, idx: object) -> Sequence[object]:  # noqa: ARG002
        """No imperative route patterns needed for Flask.

        Flask routes are fully covered by declarative DSL descriptors:

        - ``RouteDecorator`` handles ``@app.route`` / ``@app.get`` etc.
        - ``RouteCallPattern`` handles ``app.add_url_rule()``
        - ``ClassViewPattern`` handles ``MethodView`` subclasses

        Unlike Django (which uses ``urlpatterns = [path(...)]`` list
        assignment), Flask has no data-structure-based route registration
        pattern requiring ``ImperativeRoutePattern``.
        """
        return []
