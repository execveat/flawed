"""Flask-RESTful provider -- class-based REST API resources.

Flask-RESTful provides class-based Resource views, request parsing via
``RequestParser``, and output marshalling.  Resources are registered
imperatively with ``api.add_resource(MyResource, "/path")`` or via
class inheritance from ``flask_restful.Resource`` (a ``MethodView``
subclass dispatching by HTTP verb).

Key patterns:
- ``Api.add_resource`` registers Resource subclasses with URL rules
- ``Resource`` subclasses dispatch HTTP verbs to methods (get, post, ...)
- ``RequestParser.parse_args`` returns parsed user input
- ``marshal()`` serializes output through field definitions
- ``Api.init_app`` registers the API with a Flask app

DSL fitness: Fully declarative.  ClassViewPattern for Resource,
RouteCallPattern for add_resource, InputMethodPattern for parse_args.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    ClassViewPattern,
    EffectCallPattern,
    FlowPropagatorPattern,
    HookType,
    InputMethodPattern,
    LifecycleRegistrationPattern,
    Provider,
    ProviderMeta,
    RouteCallPattern,
)


class FlaskRestfulProvider(Provider):
    meta = ProviderMeta(
        id="flask-restful",
        name="Flask-RESTful",
        version="0.1.0",
        library="flask-restful",
        library_fqn="flask_restful",
    )

    # =================================================================
    # EP-1: Route registration
    # =================================================================

    routes = (
        # Imperative: api.add_resource(UserResource, "/users", "/users/<int:id>")
        # resource is arg 0, urls are *args starting at 1
        RouteCallPattern(
            fqn="flask_restful.Api.add_resource",
            rule_arg=1,  # first URL is positional arg 1
            view_func_kwarg="resource",
            methods_kwarg="methods",
        ),
        # Class-based views: Resource subclasses dispatch by HTTP method
        ClassViewPattern(
            base_class_fqn="flask_restful.Resource",
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
        # RequestParser.parse_args() returns Namespace of parsed values
        # Input comes from query/form/json based on location= in add_argument
        InputMethodPattern(
            fqn="flask_restful.reqparse.RequestParser.parse_args",
            source_type="Form",  # conservative: mixed sources
            cardinality="MULTI",
            description="Parsed request arguments from declared parser fields",
        ),
    )

    # =================================================================
    # EP-3: Effects
    # =================================================================

    effects = (
        # abort() from flask-restful (re-export of flask.abort with JSON body)
        EffectCallPattern(
            fqn="flask_restful.abort",
            category="RESPONSE_WRITE",
            description="Abort request with HTTP error status and JSON body",
        ),
    )

    # =================================================================
    # EP-6: Lifecycle hooks
    # =================================================================

    lifecycle = (
        # Api.init_app registers error handlers, representations, url rules
        LifecycleRegistrationPattern(
            registration_fqn="flask_restful.Api.init_app",
            hook_type=HookType.TEARDOWN,
            description="Registers API routes and error handlers with Flask app",
        ),
    )

    # =================================================================
    # EP-8: Flow propagation
    # =================================================================

    propagators = (
        # marshal() serializes data through field definitions
        FlowPropagatorPattern(
            fqn="flask_restful.marshal",
            input_arg=0,
            output="return",
            description="Data flows through marshal() to serialized output dict",
        ),
    )
