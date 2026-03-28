"""Astroid brain plugin for Flask-RESTful class-based REST resources."""

from __future__ import annotations

from typing import TYPE_CHECKING

from astroid import MANAGER, nodes
from astroid.brain.helpers import register_module_extender
from astroid.builder import parse
from astroid.exceptions import AstroidBuildingError

if TYPE_CHECKING:
    from collections.abc import Callable

    from astroid.manager import AstroidManager

_FLASK_RESTFUL_STUB = """
def _identity_decorator(func):
    return func


class Namespace:
    def __init__(self, *args, **kwargs):
        self.urls = {}


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


class Api:
    def __init__(self, app=None, *args, **kwargs):
        pass

    def add_resource(self, resource, *urls, **kwargs):
        return None

    def resource(self, *urls, **kwargs):
        return _identity_decorator

    def init_app(self, app, **kwargs):
        return None

    def representation(self, mediatype):
        return _identity_decorator


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

    def parse_args(self, req=None, strict=False, http_error_code=400):
        return {}


def marshal(data, fields, envelope=None):
    return {}


def abort(http_status_code, **kwargs):
    return None
"""

_FLASK_RESTFUL_FIELDS_STUB = """
class Raw:
    def __init__(self, default=None, attribute=None):
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
    def __init__(self, nested, **kwargs):
        pass
"""

_MODULE_STUBS: dict[str, str] = {
    "flask_restful": _FLASK_RESTFUL_STUB,
    "flask_restful.reqparse": _FLASK_RESTFUL_STUB,
    "flask_restful.fields": _FLASK_RESTFUL_FIELDS_STUB,
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
        raise AstroidBuildingError(f"no Flask-RESTful brain stub for {module_name!r}") from exc
    return _module_from_stub(module_name, source)


def register(manager: AstroidManager = MANAGER) -> None:
    """Register Flask-RESTful module extenders and missing-dependency stubs."""
    for module_name in _MODULE_STUBS:
        register_module_extender(manager, module_name, _make_extender(module_name))
    manager.register_failed_import_hook(_failed_import_hook)


register()
