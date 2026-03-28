"""Astroid brain plugin for Flask-RESTX namespaced REST resources."""

from __future__ import annotations

from typing import TYPE_CHECKING

from astroid import MANAGER, nodes
from astroid.brain.helpers import register_module_extender
from astroid.builder import parse
from astroid.exceptions import AstroidBuildingError

if TYPE_CHECKING:
    from collections.abc import Callable

    from astroid.manager import AstroidManager

_RESTX_RESOURCE_STUB = """
class Resource:
    method_decorators = []

    def dispatch_request(self, *args, **kwargs):
        return None

    def get(self, *args, **kwargs):
        return None

    def post(self, *args, **kwargs):
        return None

    def put(self, *args, **kwargs):
        return None

    def delete(self, *args, **kwargs):
        return None

    def patch(self, *args, **kwargs):
        return None

    def head(self, *args, **kwargs):
        return None

    def options(self, *args, **kwargs):
        return None
"""

_RESTX_NAMESPACE_STUB = """
def _identity_decorator(func):
    return func


class Namespace:
    def __init__(self, name=None, description=None, *args, **kwargs):
        self.name = name or ""

    def route(self, *urls, **kwargs):
        return _identity_decorator

    def doc(self, *args, **kwargs):
        return _identity_decorator

    def expect(self, *inputs, **kwargs):
        return _identity_decorator

    def marshal_with(self, fields, *args, **kwargs):
        return _identity_decorator

    def marshal_list_with(self, fields, *args, **kwargs):
        return _identity_decorator

    def param(self, name, description=None, _in="query", **kwargs):
        return _identity_decorator

    def response(self, code, description, model=None, **kwargs):
        return _identity_decorator

    def header(self, name, description=None, **kwargs):
        return _identity_decorator

    def produces(self, *mimetypes):
        return _identity_decorator

    def add_resource(self, resource, *urls, **kwargs):
        return None

    def abort(self, code, message=None, **kwargs):
        return None
"""

_RESTX_API_STUB = """
def _identity_decorator(func):
    return func


class Api:
    def __init__(self, app=None, *args, **kwargs):
        pass

    def init_app(self, app, **kwargs):
        return None

    def add_namespace(self, ns, path=None):
        return None

    def namespace(self, *args, **kwargs):
        from flask_restx.namespace import Namespace
        return Namespace(*args, **kwargs)

    def route(self, *urls, **kwargs):
        return _identity_decorator

    def add_resource(self, resource, *urls, **kwargs):
        return None
"""

_RESTX_FIELDS_STUB = """
class Raw:
    def __init__(self, default=None, attribute=None, **kwargs):
        pass

    def format(self, value):
        return value

    def output(self, key, obj, **kwargs):
        return None


class String(Raw):
    pass


class Integer(Raw):
    pass


class Float(Raw):
    pass


class Boolean(Raw):
    pass


class DateTime(Raw):
    pass


class Url(Raw):
    pass


class List(Raw):
    def __init__(self, cls_or_instance, **kwargs):
        pass


class Nested(Raw):
    def __init__(self, model, **kwargs):
        pass


class Wildcard(Raw):
    pass
"""

_RESTX_REQPARSE_STUB = """
class RequestParser:
    def __init__(self, *args, **kwargs):
        pass

    def add_argument(self, name, *args, **kwargs):
        return self

    def copy(self):
        return RequestParser()

    def replace_argument(self, name, *args, **kwargs):
        return self

    def remove_argument(self, name):
        return self

    def parse_args(self, req=None, strict=False):
        return {}
"""

_RESTX_MARSHALLING_STUB = """
def marshal(data, fields, envelope=None, skip_none=False, mask=None, ordered=False):
    return {}
"""

_RESTX_ERRORS_STUB = """
def abort(code, message=None, **kwargs):
    return None
"""

_RESTX_MAIN_STUB = (
    _RESTX_RESOURCE_STUB
    + _RESTX_NAMESPACE_STUB
    + _RESTX_API_STUB.replace(
        "from flask_restx.namespace import Namespace\n        return Namespace(*args, **kwargs)",
        "return Namespace(*args, **kwargs)",
    )
    + _RESTX_REQPARSE_STUB
)

_MODULE_STUBS: dict[str, str] = {
    "flask_restx": _RESTX_MAIN_STUB,
    "flask_restx.resource": _RESTX_RESOURCE_STUB,
    "flask_restx.namespace": _RESTX_NAMESPACE_STUB,
    "flask_restx.api": _RESTX_API_STUB,
    "flask_restx.fields": _RESTX_FIELDS_STUB,
    "flask_restx.reqparse": _RESTX_REQPARSE_STUB,
    "flask_restx.marshalling": _RESTX_MARSHALLING_STUB,
    "flask_restx.errors": _RESTX_ERRORS_STUB,
}


def _module_from_stub(module_name: str, source: str) -> nodes.Module:
    return parse(source, module_name=module_name, apply_transforms=False)


def _make_extender(module_name: str) -> Callable[[], nodes.Module]:
    def extender() -> nodes.Module:
        return _module_from_stub(module_name, _MODULE_STUBS[module_name])

    return extender


def _failed_import_hook(module_name: str) -> nodes.Module:
    try:
        source = _MODULE_STUBS[module_name]
    except KeyError as exc:
        raise AstroidBuildingError(f"no Flask-RESTX brain stub for {module_name!r}") from exc
    return _module_from_stub(module_name, source)


def register(manager: AstroidManager = MANAGER) -> None:
    """Register Flask-RESTX module extenders and missing-dependency stubs."""
    for module_name in _MODULE_STUBS:
        register_module_extender(manager, module_name, _make_extender(module_name))
    manager.register_failed_import_hook(_failed_import_hook)


register()
