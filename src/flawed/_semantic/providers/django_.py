"""Django core provider -- routes, inputs, ORM effects, middleware, signals.

Comprehensive provider for the Django web framework covering:
- URL configuration (imperative ``urlpatterns`` list)
- Class-based generic views (View, ListView, CreateView, etc.)
- HttpRequest input sources (GET, POST, FILES, body, etc.)
- ORM effects (Model.save, QuerySet.create/update/delete, etc.)
- Middleware class patterns (MiddlewareMixin hooks)
- Auth decorators (login_required, permission_required, csrf_*)
- Template rendering (SSTI sinks)
- Django signals as dispatch patterns
- Cache framework effects
- Email sending (NOTIFICATION)

Uses three NEW DSL types introduced for Gap 3 and Gap 4:
- ``ImperativeRoutePattern`` for urlpatterns-based routing
- ``MiddlewareClassPattern`` for class-based middleware hooks
- ``ClassViewPattern`` for Django's generic CBVs
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed._semantic.providers._base import (
    CheckKind,
    ClassViewPattern,
    DispatchPattern,
    EffectCallPattern,
    EffectSubscriptPattern,
    FlowPropagatorPattern,
    HookType,
    ImperativeRoutePattern,
    InputAttributePattern,
    InputMethodPattern,
    MiddlewareClassPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
    StateProxyPattern,
    TaintSinkPattern,
    arg,
)

if TYPE_CHECKING:
    from collections.abc import Sequence


class DjangoProvider(Provider):
    meta = ProviderMeta(
        id="django",
        name="Django",
        version="0.1.0",
        library="Django",
        library_fqn="django",
    )

    # =================================================================
    # EP-1: Route registration
    # =================================================================

    routes = (
        # -- Imperative URL configuration (Gap 3) ----------------------
        #
        # urlpatterns = [
        #     path("users/", views.user_list),
        #     path("users/<int:pk>/", views.user_detail),
        #     path("api/", include("api.urls")),
        # ]
        ImperativeRoutePattern(
            entry_fqn="django.urls.path",
            rule_arg=0,
            view_arg=1,
            view_kwarg="view",
            list_variable="urlpatterns",
            nested_fqn="django.urls.conf.include",
        ),
        ImperativeRoutePattern(
            entry_fqn="django.urls.re_path",
            rule_arg=0,
            view_arg=1,
            view_kwarg="view",
            list_variable="urlpatterns",
            nested_fqn="django.urls.conf.include",
        ),
        # -- Class-based generic views ---------------------------------
        #
        # Django CBVs dispatch by HTTP method via View.dispatch().
        # The base View class maps get/post/put/patch/delete/head/options
        # to handler methods.
        ClassViewPattern(
            base_class_fqn=(
                "django.views.View",
                "django.views.generic.View",
                "django.views.generic.base.View",
                "django.views.generic.base.TemplateView",
                "django.views.generic.base.RedirectView",
                "django.views.generic.detail.DetailView",
                "django.views.generic.DetailView",
                "django.views.generic.edit.FormView",
                "django.views.generic.FormView",
                "django.views.generic.edit.CreateView",
                "django.views.generic.CreateView",
                "django.views.generic.edit.UpdateView",
                "django.views.generic.UpdateView",
                "django.views.generic.edit.DeleteView",
                "django.views.generic.DeleteView",
                "django.views.generic.list.ListView",
                "django.views.generic.ListView",
            ),
            method_map={
                "get": "GET",
                "post": "POST",
                "put": "PUT",
                "patch": "PATCH",
                "delete": "DELETE",
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
        # -- HttpRequest attributes ------------------------------------
        InputAttributePattern(
            receiver_fqn="django.http.request.HttpRequest",
            attribute="GET",
            source_type="Query",
            cardinality="MULTI",
            description="URL query string parameters (QueryDict)",
        ),
        InputAttributePattern(
            receiver_fqn="django.http.request.HttpRequest",
            attribute="POST",
            source_type="Form",
            cardinality="MULTI",
            description="POST form-encoded body fields (QueryDict)",
        ),
        InputAttributePattern(
            receiver_fqn="django.http.request.HttpRequest",
            attribute="FILES",
            source_type="FileUpload",
            cardinality="MULTI",
            description="Uploaded files (MultiValueDict)",
        ),
        InputAttributePattern(
            receiver_fqn="django.http.request.HttpRequest",
            attribute="body",
            source_type="RawBody",
            description="Raw request body as bytes",
        ),
        InputAttributePattern(
            receiver_fqn="django.http.request.HttpRequest",
            attribute="META",
            source_type="Header",
            cardinality="MULTI",
            description="Server variables including HTTP headers (CONTENT_TYPE, HTTP_*)",
        ),
        InputAttributePattern(
            receiver_fqn="django.http.request.HttpRequest",
            attribute="COOKIES",
            source_type="Cookie",
            cardinality="MULTI",
            description="HTTP cookies dict",
        ),
        InputAttributePattern(
            receiver_fqn="django.http.request.HttpRequest",
            attribute="headers",
            source_type="Header",
            cardinality="MULTI",
            description="HTTP headers (case-insensitive dict, Django 2.2+)",
        ),
        InputAttributePattern(
            receiver_fqn="django.http.request.HttpRequest",
            attribute="content_type",
            source_type="Header",
            description="Content-Type header value",
        ),
        InputAttributePattern(
            receiver_fqn="django.http.request.HttpRequest",
            attribute="path",
            source_type="PathParam",
            description="URL path (e.g. /users/42/)",
        ),
        InputAttributePattern(
            receiver_fqn="django.http.request.HttpRequest",
            attribute="path_info",
            source_type="PathParam",
            description="URL path info (path under the WSGI script prefix)",
        ),
        InputAttributePattern(
            receiver_fqn="django.http.request.HttpRequest",
            attribute="method",
            source_type="Header",
            description="HTTP method string (GET, POST, etc.)",
        ),
        InputAttributePattern(
            receiver_fqn="django.http.request.HttpRequest",
            attribute="resolver_match",
            source_type="PathParam",
            description="Resolved URL match (contains captured kwargs)",
        ),
        # -- QueryDict methods ----------------------------------------
        InputMethodPattern(
            fqn="django.http.request.QueryDict.get",
            source_type="Query",
            key_arg=0,
            cardinality="SINGLE",
            description="Single value from QueryDict by key",
        ),
        InputMethodPattern(
            fqn="django.http.request.QueryDict.getlist",
            source_type="Query",
            key_arg=0,
            cardinality="MULTI",
            description="All values for a key from QueryDict",
        ),
        InputMethodPattern(
            fqn="django.http.request.QueryDict.__getitem__",
            source_type="Query",
            key_arg=0,
            cardinality="SINGLE",
            description="Subscript access on QueryDict (raises KeyError if missing)",
        ),
    )

    # =================================================================
    # EP-3/EP-5: Effects
    # =================================================================

    effects = (
        # -- ORM: Model instance operations ----------------------------
        EffectCallPattern(
            fqn="django.db.models.base.Model.save",
            category="DB_WRITE",
            description="Save model instance (INSERT or UPDATE)",
        ),
        EffectCallPattern(
            fqn="django.db.models.base.Model.delete",
            category="DB_DELETE",
            description="Delete model instance",
        ),
        EffectCallPattern(
            fqn="django.db.models.base.Model.refresh_from_db",
            category="DB_READ",
            description="Reload model instance fields from database",
        ),
        # -- ORM: QuerySet write operations ----------------------------
        EffectCallPattern(
            fqn="django.db.models.query.QuerySet.create",
            category="DB_WRITE",
            description="INSERT and return new model instance",
        ),
        EffectCallPattern(
            fqn="django.db.models.query.QuerySet.bulk_create",
            category="DB_WRITE",
            description="Bulk INSERT multiple model instances",
        ),
        EffectCallPattern(
            fqn="django.db.models.query.QuerySet.bulk_update",
            category="DB_WRITE",
            description="Bulk UPDATE multiple model instances",
        ),
        EffectCallPattern(
            fqn="django.db.models.query.QuerySet.update",
            category="DB_WRITE",
            description="UPDATE matching rows (returns affected count)",
        ),
        EffectCallPattern(
            fqn="django.db.models.query.QuerySet.get_or_create",
            category="DB_WRITE",
            description="Get existing or INSERT new instance",
        ),
        EffectCallPattern(
            fqn="django.db.models.query.QuerySet.update_or_create",
            category="DB_WRITE",
            description="UPDATE existing or INSERT new instance",
        ),
        # -- ORM: QuerySet delete --------------------------------------
        EffectCallPattern(
            fqn="django.db.models.query.QuerySet.delete",
            category="DB_DELETE",
            description="DELETE matching rows (cascades per ForeignKey on_delete)",
        ),
        # -- ORM: QuerySet read operations -----------------------------
        EffectCallPattern(
            fqn="django.db.models.query.QuerySet.get",
            category="DB_READ",
            description="SELECT single object (raises DoesNotExist / MultipleObjectsReturned)",
        ),
        EffectCallPattern(
            fqn="django.db.models.query.QuerySet.first",
            category="DB_READ",
            description="SELECT first object or None",
        ),
        EffectCallPattern(
            fqn="django.db.models.query.QuerySet.last",
            category="DB_READ",
            description="SELECT last object or None",
        ),
        EffectCallPattern(
            fqn="django.db.models.query.QuerySet.count",
            category="DB_READ",
            description="SELECT COUNT(*)",
        ),
        EffectCallPattern(
            fqn="django.db.models.query.QuerySet.exists",
            category="DB_READ",
            description="SELECT EXISTS (efficient existence check)",
        ),
        EffectCallPattern(
            fqn="django.db.models.query.QuerySet.aggregate",
            category="DB_READ",
            description="Aggregate query (SUM, AVG, COUNT, etc.)",
        ),
        EffectCallPattern(
            fqn="django.db.models.query.QuerySet.values",
            category="DB_READ",
            description="SELECT specific columns as dicts",
        ),
        EffectCallPattern(
            fqn="django.db.models.query.QuerySet.values_list",
            category="DB_READ",
            description="SELECT specific columns as tuples",
        ),
        # -- ORM: Raw SQL (injection surface) --------------------------
        EffectCallPattern(
            fqn="django.db.models.query.QuerySet.raw",
            category="DB_READ",
            description="Execute raw SQL query (SQL injection risk)",
        ),
        EffectCallPattern(
            fqn="django.db.models.query.QuerySet.extra",
            category="DB_READ",
            description="Extra SQL clauses (deprecated, injection risk)",
        ),
        # -- Cursor: direct SQL execution ------------------------------
        EffectCallPattern(
            fqn="django.db.backends.utils.CursorWrapper.execute",
            category="DB_WRITE",
            description="Execute raw SQL via cursor (default DB_WRITE, may be read)",
        ),
        EffectCallPattern(
            fqn="django.db.backends.utils.CursorWrapper.executemany",
            category="DB_WRITE",
            description="Execute parameterized SQL for multiple rows",
        ),
        EffectCallPattern(
            fqn="django.db.backends.utils.CursorDebugWrapper.execute",
            category="DB_WRITE",
            description="Execute raw SQL via debug cursor",
        ),
        EffectCallPattern(
            fqn="django.db.backends.utils.CursorDebugWrapper.executemany",
            category="DB_WRITE",
            description="Execute SQL for multiple rows via debug cursor",
        ),
        # -- Response construction -------------------------------------
        EffectCallPattern(
            fqn="django.http.response.HttpResponse.__init__",
            category="RESPONSE_WRITE",
            description="Construct HTTP response",
        ),
        EffectCallPattern(
            fqn="django.http.response.JsonResponse.__init__",
            category="RESPONSE_WRITE",
            description="Construct JSON response",
        ),
        EffectCallPattern(
            fqn="django.http.response.HttpResponseRedirect.__init__",
            category="RESPONSE_WRITE",
            description="Construct redirect response (open redirect risk)",
        ),
        EffectCallPattern(
            fqn="django.shortcuts.redirect",
            category="RESPONSE_WRITE",
            description="Redirect shortcut (open redirect if user-controlled)",
        ),
        # -- Cookie manipulation ---------------------------------------
        EffectCallPattern(
            fqn="django.http.response.HttpResponseBase.set_cookie",
            category="RESPONSE_WRITE",
            description="Set a cookie on the HTTP response",
        ),
        EffectCallPattern(
            fqn="django.http.response.HttpResponseBase.delete_cookie",
            category="RESPONSE_WRITE",
            description="Delete a cookie from the HTTP response",
        ),
        EffectCallPattern(
            fqn="django.http.response.HttpResponseBase.set_signed_cookie",
            category="RESPONSE_WRITE",
            description="Set a signed cookie (tamper-resistant)",
        ),
        # -- Django messages framework ---------------------------------
        EffectCallPattern(
            fqn="django.contrib.messages.api.add_message",
            category="RESPONSE_WRITE",
            description="Add a message to the messages framework",
        ),
        EffectCallPattern(
            fqn="django.contrib.messages.api.info",
            category="RESPONSE_WRITE",
            description="Add info-level message",
        ),
        EffectCallPattern(
            fqn="django.contrib.messages.api.success",
            category="RESPONSE_WRITE",
            description="Add success-level message",
        ),
        EffectCallPattern(
            fqn="django.contrib.messages.api.warning",
            category="RESPONSE_WRITE",
            description="Add warning-level message",
        ),
        EffectCallPattern(
            fqn="django.contrib.messages.api.error",
            category="RESPONSE_WRITE",
            description="Add error-level message",
        ),
        # -- Email (NOTIFICATION) --------------------------------------
        EffectCallPattern(
            fqn="django.core.mail.send_mail",
            category="NOTIFICATION",
            description="Send a single email message",
        ),
        EffectCallPattern(
            fqn="django.core.mail.send_mass_mail",
            category="NOTIFICATION",
            description="Send multiple email messages in one connection",
        ),
        EffectCallPattern(
            fqn="django.core.mail.message.EmailMessage.send",
            category="NOTIFICATION",
            description="Send EmailMessage instance",
        ),
        # -- Cache framework -------------------------------------------
        EffectCallPattern(
            fqn="django.core.cache.backends.base.BaseCache.get",
            category="CACHE_READ",
            description="Read value from cache",
        ),
        EffectCallPattern(
            fqn="django.core.cache.backends.base.BaseCache.get_many",
            category="CACHE_READ",
            description="Read multiple values from cache",
        ),
        EffectCallPattern(
            fqn="django.core.cache.backends.base.BaseCache.set",
            category="CACHE_WRITE",
            description="Write value to cache",
        ),
        EffectCallPattern(
            fqn="django.core.cache.backends.base.BaseCache.set_many",
            category="CACHE_WRITE",
            description="Write multiple values to cache",
        ),
        EffectCallPattern(
            fqn="django.core.cache.backends.base.BaseCache.delete",
            category="CACHE_WRITE",
            description="Delete key from cache",
        ),
        EffectCallPattern(
            fqn="django.core.cache.backends.base.BaseCache.delete_many",
            category="CACHE_WRITE",
            description="Delete multiple keys from cache",
        ),
        EffectCallPattern(
            fqn="django.core.cache.backends.base.BaseCache.clear",
            category="CACHE_WRITE",
            description="Clear entire cache",
        ),
        # -- Session state (via request.session) -----------------------
        EffectSubscriptPattern(
            receiver_fqn="django.contrib.sessions.backends.base.SessionBase",
            category="STATE_WRITE",
            scope="SESSION",
            description="Write to Django session via subscript",
        ),
        # -- Config: CSRF exemption ------------------------------------
        EffectCallPattern(
            fqn="django.views.decorators.csrf.csrf_exempt",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Mark view as CSRF-exempt (weakens protection)",
        ),
    )

    # =================================================================
    # EP-4: Security checks
    # =================================================================

    checks = (
        # -- Auth decorators -------------------------------------------
        SecurityCheckPattern(
            fqn="django.contrib.auth.decorators.login_required",
            kind=CheckKind.DECORATOR,
            category="AUTHENTICATION",
            description="Requires authenticated user (redirects to login_url)",
        ),
        SecurityCheckPattern(
            fqn="django.contrib.auth.decorators.permission_required",
            kind=CheckKind.DECORATOR,
            category="AUTHORIZATION",
            description="Requires specific permission(s)",
        ),
        SecurityCheckPattern(
            fqn="django.contrib.auth.decorators.user_passes_test",
            kind=CheckKind.DECORATOR,
            category="AUTHORIZATION",
            description="Requires user passes custom test callable",
        ),
        # -- Auth functions --------------------------------------------
        SecurityCheckPattern(
            fqn="django.contrib.auth.authenticate",
            kind=CheckKind.CALL,
            category="AUTHENTICATION",
            description="Authenticate credentials against backends",
        ),
        SecurityCheckPattern(
            fqn="django.contrib.auth.hashers.check_password",
            kind=CheckKind.CALL,
            category="PASSWORD_VERIFY",
            description="Verify password against hash",
        ),
        SecurityCheckPattern(
            fqn="django.contrib.auth.hashers.make_password",
            kind=CheckKind.CALL,
            category="PASSWORD_HASH",
            description="Hash a password using configured hasher",
        ),
        # -- CSRF decorators -------------------------------------------
        SecurityCheckPattern(
            fqn="django.views.decorators.csrf.csrf_protect",
            kind=CheckKind.DECORATOR,
            category="CSRF",
            description="Enforce CSRF check on this view",
        ),
        # -- HTTP method restriction -----------------------------------
        SecurityCheckPattern(
            fqn="django.views.decorators.http.require_http_methods",
            kind=CheckKind.DECORATOR,
            category="METHOD_RESTRICTION",
            description="Restrict allowed HTTP methods",
        ),
        SecurityCheckPattern(
            fqn="django.views.decorators.http.require_GET",
            kind=CheckKind.DECORATOR,
            category="METHOD_RESTRICTION",
            description="Restrict to GET only",
        ),
        SecurityCheckPattern(
            fqn="django.views.decorators.http.require_POST",
            kind=CheckKind.DECORATOR,
            category="METHOD_RESTRICTION",
            description="Restrict to POST only",
        ),
        SecurityCheckPattern(
            fqn="django.views.decorators.http.require_safe",
            kind=CheckKind.DECORATOR,
            category="METHOD_RESTRICTION",
            description="Restrict to GET and HEAD only",
        ),
    )

    # =================================================================
    # EP-6: Lifecycle -- middleware classes (Gap 4)
    # =================================================================

    lifecycle = (
        # -- MiddlewareMixin-based middleware ---------------------------
        #
        # Django middleware classes inherit MiddlewareMixin and define
        # process_request, process_view, process_response, and
        # process_exception hooks.  The engine discovers subclasses and
        # maps methods to hook types.
        MiddlewareClassPattern(
            base_class_fqn="django.utils.deprecation.MiddlewareMixin",
            method_hooks={
                "process_request": HookType.BEFORE_HANDLER,
                "process_view": HookType.BEFORE_HANDLER,
                "process_response": HookType.AFTER_HANDLER,
                "process_exception": HookType.ON_ERROR,
            },
            description="Django middleware using MiddlewareMixin with hook methods",
        ),
    )

    # =================================================================
    # EP-7: Dispatch -- Django signals
    # =================================================================

    dispatches = (
        # -- Signal receiver decorator ---------------------------------
        DispatchPattern(
            source_fqn="django.dispatch.dispatcher.receiver",
            target_method_names=(),
            dispatch_type="signal",
            description="@receiver(signal) decorator registers signal handler",
        ),
        # -- ORM signals -----------------------------------------------
        DispatchPattern(
            source_fqn="django.db.models.signals.pre_save",
            target_method_names=("send",),
            dispatch_type="signal",
            description="Fires before Model.save()",
        ),
        DispatchPattern(
            source_fqn="django.db.models.signals.post_save",
            target_method_names=("send",),
            dispatch_type="signal",
            description="Fires after Model.save()",
        ),
        DispatchPattern(
            source_fqn="django.db.models.signals.pre_delete",
            target_method_names=("send",),
            dispatch_type="signal",
            description="Fires before Model.delete()",
        ),
        DispatchPattern(
            source_fqn="django.db.models.signals.post_delete",
            target_method_names=("send",),
            dispatch_type="signal",
            description="Fires after Model.delete()",
        ),
        # -- Request lifecycle signals ---------------------------------
        DispatchPattern(
            source_fqn="django.core.signals.request_started",
            target_method_names=("send",),
            dispatch_type="signal",
            description="Fires at start of HTTP request handling",
        ),
        DispatchPattern(
            source_fqn="django.core.signals.request_finished",
            target_method_names=("send",),
            dispatch_type="signal",
            description="Fires at end of HTTP request handling",
        ),
    )

    # =================================================================
    # EP-8: Taint sinks (injection vectors)
    # =================================================================

    sinks = (
        # -- SQL injection ---------------------------------------------
        TaintSinkPattern(
            fqn="django.db.backends.utils.CursorWrapper.execute",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Raw SQL via cursor.execute() -- injection if not parameterized",
        ),
        TaintSinkPattern(
            fqn="django.db.backends.utils.CursorDebugWrapper.execute",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Raw SQL via debug cursor.execute()",
        ),
        TaintSinkPattern(
            fqn="django.db.models.query.QuerySet.raw",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Raw SQL query -- injection if query string is user-controlled",
        ),
        TaintSinkPattern(
            fqn="django.db.models.query.QuerySet.extra",
            arg=0,
            sink_kind="SQL_INJECTION",
            description="Extra SQL clauses (deprecated, high injection risk)",
        ),
        TaintSinkPattern(
            fqn="django.db.models.expressions.RawSQL",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
            description="Raw SQL expression -- injection if sql is user-controlled",
        ),
        # -- XSS: mark_safe bypasses auto-escaping ---------------------
        TaintSinkPattern(
            fqn="django.utils.safestring.mark_safe",
            arg=0,
            sink_kind="XSS",
            description="Marks string as safe HTML -- XSS if user-controlled",
        ),
        # -- Open redirect ---------------------------------------------
        TaintSinkPattern(
            fqn="django.shortcuts.redirect",
            arg=0,
            sink_kind="OPEN_REDIRECT",
            description="Redirect destination -- open redirect if user-controlled",
        ),
        TaintSinkPattern(
            fqn="django.http.response.HttpResponseRedirect.__init__",
            arg=0,
            sink_kind="OPEN_REDIRECT",
            description="Redirect URL -- open redirect if user-controlled",
        ),
        # -- Template rendering (SSTI) ---------------------------------
        TaintSinkPattern(
            fqn="django.template.base.Template.__init__",
            arg=0,
            sink_kind="SSTI",
            when=~arg(0).is_literal_string(),
            description="Dynamic template string -- SSTI if user-controlled",
        ),
    )

    # =================================================================
    # EP-8: Flow propagation
    # =================================================================

    propagators = (
        # -- QuerySet filter chains ------------------------------------
        FlowPropagatorPattern(
            fqn="django.db.models.query.QuerySet.filter",
            input_arg=0,
            output="return",
            description="Filter criteria taint propagates to filtered QuerySet",
        ),
        FlowPropagatorPattern(
            fqn="django.db.models.query.QuerySet.exclude",
            input_arg=0,
            output="return",
            description="Exclude criteria taint propagates to filtered QuerySet",
        ),
        FlowPropagatorPattern(
            fqn="django.db.models.query.QuerySet.get",
            input_arg=0,
            output="return",
            description="Get criteria taint propagates to returned object",
        ),
        # -- Response construction -------------------------------------
        FlowPropagatorPattern(
            fqn="django.shortcuts.redirect",
            input_arg=0,
            output="return",
            description="Redirect target flows to response location",
        ),
        FlowPropagatorPattern(
            fqn="django.http.response.JsonResponse.__init__",
            input_arg=0,
            output="receiver",
            description="Data flows into JSON response body",
        ),
    )

    # =================================================================
    # EP-10: State proxies
    # =================================================================

    proxies = (
        StateProxyPattern(
            fqn="django.contrib.auth.get_user",
            resolves_to="django.contrib.auth.models.User",
            scope="REQUEST",
            description="request.user -- current authenticated user",
        ),
    )

    # =================================================================
    # Extraction hooks
    # =================================================================

    def extract_routes(self, _idx: object) -> Sequence[object]:
        """Resolve Django URL configuration.

        The declarative ImperativeRoutePattern handles the common case
        of ``path()`` / ``re_path()`` calls inside ``urlpatterns``.
        This hook handles advanced patterns:

        1. ``include()`` resolution -- follow include() calls to find
           the target URL conf module and recursively extract routes.
        2. URL namespace resolution -- Django supports URL namespaces
           via the ``app_name`` module attribute and ``namespace``
           argument to include().
        3. Nested prefix accumulation -- each include() adds its
           pattern as a prefix to all child routes.
        """
        return []
