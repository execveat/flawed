"""Django REST Framework provider -- ViewSets, serializers, permissions.

Extends the base Django provider with DRF-specific patterns:
- ViewSet/ModelViewSet class-based routing with action dispatch
- Router-based URL registration
- @api_view decorator for function-based views
- ClassAttributeGuardPattern for permission_classes,
  authentication_classes, and throttle_classes (Gap 5)
- Serializer validation as security checks
- DRF Request wrapper input sources (request.data, request.query_params)
- @action decorator for extra ViewSet routes
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    ClassAttributeGuardPattern,
    ClassViewPattern,
    EffectCallPattern,
    FlowPropagatorPattern,
    InputAttributePattern,
    InputMethodPattern,
    Provider,
    ProviderMeta,
    RouteCallPattern,
    RouteDecorator,
    SecurityCheckPattern,
)


class DjangoRestFrameworkProvider(Provider):
    meta = ProviderMeta(
        id="djangorestframework",
        name="Django REST Framework",
        version="0.1.0",
        library="djangorestframework",
        library_fqn="rest_framework",
    )

    # =================================================================
    # EP-1: Route registration
    # =================================================================

    routes = (
        # -- Router registration ---------------------------------------
        #
        # router = DefaultRouter()
        # router.register("users", UserViewSet)
        RouteCallPattern(
            fqn="rest_framework.routers.SimpleRouter.register",
            rule_arg=0,
            view_func_kwarg="viewset",
            methods_kwarg="",
        ),
        RouteCallPattern(
            fqn="rest_framework.routers.DefaultRouter.register",
            rule_arg=0,
            view_func_kwarg="viewset",
            methods_kwarg="",
        ),
        # -- @api_view decorator for function-based views ---------------
        #
        # @api_view(["GET", "POST"])
        # def user_list(request): ...
        RouteDecorator(
            fqn="rest_framework.decorators.api_view",
            rule_arg=0,
            methods_kwarg="http_method_names",
        ),
        # -- ViewSet class-based routing --------------------------------
        #
        # ModelViewSet maps standard CRUD actions to HTTP methods:
        #   list   -> GET /resources/
        #   create -> POST /resources/
        #   retrieve -> GET /resources/{pk}/
        #   update -> PUT /resources/{pk}/
        #   partial_update -> PATCH /resources/{pk}/
        #   destroy -> DELETE /resources/{pk}/
        ClassViewPattern(
            base_class_fqn="rest_framework.viewsets.ViewSetMixin",
            method_map={
                "list": "GET",
                "create": "POST",
                "retrieve": "GET",
                "update": "PUT",
                "partial_update": "PATCH",
                "destroy": "DELETE",
            },
            as_view_method="as_view",
        ),
        # -- Generic API views dispatch by HTTP method ------------------
        ClassViewPattern(
            base_class_fqn="rest_framework.views.APIView",
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
        # -- DRF Request wrapper attributes ----------------------------
        #
        # DRF wraps Django's HttpRequest with its own Request class
        # that provides parsed body access.
        InputAttributePattern(
            receiver_fqn="rest_framework.request.Request",
            attribute="data",
            source_type="Json",
            cardinality="MULTI",
            description="Parsed request body (JSON, form, or multipart)",
        ),
        InputAttributePattern(
            receiver_fqn="rest_framework.request.Request",
            attribute="query_params",
            source_type="Query",
            cardinality="MULTI",
            description="URL query parameters (alias for request.GET)",
        ),
        InputAttributePattern(
            receiver_fqn="rest_framework.request.Request",
            attribute="FILES",
            source_type="FileUpload",
            cardinality="MULTI",
            description="Uploaded files",
        ),
        InputAttributePattern(
            receiver_fqn="rest_framework.request.Request",
            attribute="auth",
            source_type="Header",
            description="Authentication credentials (parsed from Authorization header)",
        ),
        InputAttributePattern(
            receiver_fqn="rest_framework.request.Request",
            attribute="user",
            source_type="Header",
            description="Authenticated user (set by authentication class)",
        ),
        # -- Serializer validated_data as input source -------------------
        InputAttributePattern(
            receiver_fqn="rest_framework.serializers.BaseSerializer",
            attribute="validated_data",
            source_type="Json",
            cardinality="MULTI",
            description="Validated and deserialized request data",
        ),
        InputMethodPattern(
            fqn="rest_framework.serializers.BaseSerializer.validated_data",
            source_type="Json",
            cardinality="MULTI",
            description="Validated data property (dict for Serializer, list for ListSerializer)",
        ),
    )

    # =================================================================
    # EP-3: Effects
    # =================================================================

    effects = (
        # -- Response construction -------------------------------------
        EffectCallPattern(
            fqn="rest_framework.response.Response.__init__",
            category="RESPONSE_WRITE",
            description="Construct DRF Response",
        ),
    )

    # =================================================================
    # EP-4/EP-9: Security checks (including Gap 5)
    # =================================================================

    checks = (
        # -- Class-attribute guard patterns (Gap 5) --------------------
        #
        # class UserViewSet(ModelViewSet):
        #     permission_classes = [IsAuthenticated, IsAdminUser]
        #     authentication_classes = [TokenAuthentication]
        #     throttle_classes = [UserRateThrottle]
        ClassAttributeGuardPattern(
            view_base_fqn="rest_framework.views.APIView",
            attribute_name="permission_classes",
            guard_base_fqn="rest_framework.permissions.BasePermission",
            category="AUTHORIZATION",
            empty_means_unprotected=True,
            description="View-level permission classes list (empty = AllowAny)",
        ),
        ClassAttributeGuardPattern(
            view_base_fqn="rest_framework.views.APIView",
            attribute_name="authentication_classes",
            guard_base_fqn="rest_framework.authentication.BaseAuthentication",
            category="AUTHENTICATION",
            empty_means_unprotected=True,
            description="View-level authentication classes list",
        ),
        ClassAttributeGuardPattern(
            view_base_fqn="rest_framework.views.APIView",
            attribute_name="throttle_classes",
            guard_base_fqn="rest_framework.throttling.BaseThrottle",
            category="RATE_LIMITING",
            description="View-level throttle classes list",
        ),
        # -- Individual permission classes (for resolution) -------------
        SecurityCheckPattern(
            fqn="rest_framework.permissions.IsAuthenticated.has_permission",
            kind=CheckKind.METHOD_CALL,
            category="AUTHENTICATION",
            description="Requires authenticated user",
        ),
        SecurityCheckPattern(
            fqn="rest_framework.permissions.IsAdminUser.has_permission",
            kind=CheckKind.METHOD_CALL,
            category="AUTHORIZATION",
            description="Requires staff user",
        ),
        SecurityCheckPattern(
            fqn="rest_framework.permissions.AllowAny.has_permission",
            kind=CheckKind.METHOD_CALL,
            category="AUTHORIZATION",
            description="Allows any access (no restriction)",
        ),
        SecurityCheckPattern(
            fqn="rest_framework.permissions.IsAuthenticatedOrReadOnly.has_permission",
            kind=CheckKind.METHOD_CALL,
            category="AUTHENTICATION",
            description="Auth required for writes, reads open",
        ),
        SecurityCheckPattern(
            fqn="rest_framework.permissions.DjangoModelPermissions.has_permission",
            kind=CheckKind.METHOD_CALL,
            category="AUTHORIZATION",
            description="Django model-level permissions (add/change/delete/view)",
        ),
        SecurityCheckPattern(
            fqn="rest_framework.permissions.DjangoObjectPermissions.has_object_permission",
            kind=CheckKind.METHOD_CALL,
            category="AUTHORIZATION",
            description="Object-level permissions via Django backends",
        ),
        # -- Individual authentication classes --------------------------
        SecurityCheckPattern(
            fqn="rest_framework.authentication.TokenAuthentication.authenticate",
            kind=CheckKind.METHOD_CALL,
            category="TOKEN_VERIFY",
            description="Token-based authentication (Authorization: Token xxx)",
        ),
        SecurityCheckPattern(
            fqn="rest_framework.authentication.SessionAuthentication.authenticate",
            kind=CheckKind.METHOD_CALL,
            category="AUTHENTICATION",
            description="Session-based authentication (CSRF enforced)",
        ),
        SecurityCheckPattern(
            fqn="rest_framework.authentication.BasicAuthentication.authenticate",
            kind=CheckKind.METHOD_CALL,
            category="AUTHENTICATION",
            description="HTTP Basic authentication",
        ),
        # -- Serializer validation as security check --------------------
        SecurityCheckPattern(
            fqn="rest_framework.serializers.BaseSerializer.is_valid",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Validate serializer data against field definitions",
        ),
        SecurityCheckPattern(
            fqn="rest_framework.serializers.Serializer.is_valid",
            kind=CheckKind.METHOD_CALL,
            category="SCHEMA_VALIDATION",
            description="Validate serializer data (with field-level validators)",
        ),
        # -- @action decorator as route modifier -----------------------
        SecurityCheckPattern(
            fqn="rest_framework.decorators.action",
            kind=CheckKind.DECORATOR,
            category="METHOD_RESTRICTION",
            description="Defines extra ViewSet action (methods kwarg restricts HTTP verbs)",
        ),
    )

    # =================================================================
    # EP-8: Flow propagation
    # =================================================================

    propagators = (
        FlowPropagatorPattern(
            fqn="rest_framework.serializers.BaseSerializer.is_valid",
            input_arg=0,
            output="receiver",
            description="Validation: input data flows to serializer.validated_data",
        ),
        FlowPropagatorPattern(
            fqn="rest_framework.response.Response.__init__",
            input_arg=0,
            output="receiver",
            description="Response data flows into response body",
        ),
    )
