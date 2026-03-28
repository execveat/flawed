"""Flask-RESTX provider -- Swagger-documented REST API framework.

Flask-RESTX provides namespaced routing, request parsing, response
marshalling, and built-in Swagger documentation on top of Flask.
Resources are class-based views inheriting from ``flask_restx.Resource``
(itself a ``MethodView`` subclass), decorated with ``@ns.route()``.

Key patterns:
- ``Namespace.route`` registers Resource subclasses (class-based views)
- ``Namespace.expect`` declares input model validation
- ``Namespace.marshal_with`` declares output serialization
- ``RequestParser.parse_args`` returns parsed user input as a dict
- ``Api.init_app`` registers the API with a Flask app

DSL fitness: Fully declarative.  Uses ``ClassViewPattern`` for Resource
dispatch, ``RouteDecorator`` for namespace routing, ``InputMethodPattern``
for ``parse_args()``, and ``SecurityCheckPattern`` for ``expect()``.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    ClassViewPattern,
    EffectCallPattern,
    FlowPropagatorPattern,
    HookType,
    InputMethodPattern,
    LifecycleRegistrationPattern,
    Provider,
    ProviderMeta,
    RouteCallPattern,
    RouteDecorator,
    SecurityCheckPattern,
)


class FlaskRestxProvider(Provider):
    meta = ProviderMeta(
        id="flask-restx",
        name="Flask-RESTX",
        version="0.1.0",
        library="flask-restx",
        library_fqn="flask_restx",
    )

    # =================================================================
    # EP-1: Route registration
    # =================================================================

    # Each FQN is declared as a (submodule, package-root) alias pair: apps import
    # these names from either the defining submodule
    # (``flask_restx.namespace.Namespace``) or — far more commonly — the package
    # root (``from flask_restx import Namespace``), and the engine resolves a
    # symbol to the FQN of the import path the app actually used. Declaring only
    # the submodule form makes the whole API invisible to root-import apps (e.g. a
    # large flask-restx ``api/v1`` surface), a corpus-wide false negative. Mirrors how
    # ``flask_core`` declares both ``flask.Flask.route`` and ``flask.Blueprint.route``.
    routes = (
        # @ns.route("/path") decorates a Resource class
        # Namespace.route internally calls Namespace.add_resource
        RouteDecorator(
            fqn=("flask_restx.namespace.Namespace.route", "flask_restx.Namespace.route"),
            rule_arg=0,
            methods_kwarg="methods",
            default_methods=("GET",),
        ),
        # Api-level route (less common but supported)
        RouteDecorator(
            fqn=("flask_restx.api.Api.route", "flask_restx.Api.route"),
            rule_arg=0,
            methods_kwarg="methods",
            default_methods=("GET",),
        ),
        # Imperative: ns.add_resource(MyResource, "/path")
        RouteCallPattern(
            fqn=(
                "flask_restx.namespace.Namespace.add_resource",
                "flask_restx.Namespace.add_resource",
            ),
            rule_arg=1,  # resource is arg 0, urls start at arg 1
            view_func_kwarg="resource",
            methods_kwarg="methods",
        ),
        # Class-based views: Resource subclasses dispatch by HTTP method
        ClassViewPattern(
            base_class_fqn=("flask_restx.resource.Resource", "flask_restx.Resource"),
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
    # EP-2: Input sources
    # =================================================================

    inputs = (
        # RequestParser.parse_args() returns a dict of parsed input
        # sourced from query/form/json/headers based on location= kwarg
        InputMethodPattern(
            fqn="flask_restx.reqparse.RequestParser.parse_args",
            source_type="Form",  # conservative: mixed sources
            cardinality="MULTI",
            description="Parsed request arguments from declared parser fields",
        ),
    )

    # =================================================================
    # EP-3: Effects
    # =================================================================

    effects = (
        # abort() terminates request with error status
        EffectCallPattern(
            fqn=("flask_restx.errors.abort", "flask_restx.abort"),
            category="RESPONSE_WRITE",
            description="Abort request with HTTP error status",
        ),
        EffectCallPattern(
            fqn=("flask_restx.namespace.Namespace.abort", "flask_restx.Namespace.abort"),
            category="RESPONSE_WRITE",
            description="Namespace-scoped abort (delegates to errors.abort)",
        ),
    )

    # =================================================================
    # EP-4: Security checks
    # =================================================================

    checks = (
        # @ns.expect(model) validates request body against a model
        SecurityCheckPattern(
            fqn=("flask_restx.namespace.Namespace.expect", "flask_restx.Namespace.expect"),
            kind=CheckKind.DECORATOR,
            category="SCHEMA_VALIDATION",
            description="Validates request payload against declared API model",
        ),
    )

    # =================================================================
    # EP-6: Lifecycle hooks
    # =================================================================

    lifecycle = (
        # Api.init_app registers error handlers, url rules, teardown
        LifecycleRegistrationPattern(
            registration_fqn=("flask_restx.api.Api.init_app", "flask_restx.Api.init_app"),
            hook_type=HookType.TEARDOWN,
            description="Registers API routes, error handlers, and Swagger UI",
        ),
    )

    # =================================================================
    # EP-8: Flow propagation
    # =================================================================

    propagators = (
        # marshal_with serializes output through the model
        FlowPropagatorPattern(
            fqn=("flask_restx.marshalling.marshal", "flask_restx.marshal"),
            input_arg=0,
            output="return",
            description="Data flows through marshal() to serialized output",
        ),
    )
