"""Astroid brain plugin for Flask and Werkzeug structural objects."""

from __future__ import annotations

from typing import TYPE_CHECKING

from astroid import MANAGER, nodes
from astroid.brain.helpers import register_module_extender
from astroid.builder import parse
from astroid.exceptions import AstroidBuildingError

if TYPE_CHECKING:
    from collections.abc import Callable

    from astroid.manager import AstroidManager

_FLASK_STUB = """
class ImmutableMultiDict(dict):
    def get(self, key, default=None, type=None):
        return ""

    def getlist(self, key):
        return [""]


class FileStorage:
    def __init__(self):
        self.filename = ""

    def read(self):
        return b""

    def save(self, dst, buffer_size=16384):
        return None


class EnvironHeaders(dict):
    pass


class SecureCookieSession(dict):
    pass


class _AppGlobals:
    pass


class Request:
    def __init__(self):
        self.form = ImmutableMultiDict()
        self.args = ImmutableMultiDict()
        self.json = None
        self.json = {}
        self.files = ImmutableMultiDict()
        self.headers = EnvironHeaders()
        self.method = "GET"
        self.path = "/"
        self.cookies = ImmutableMultiDict()
        self.data = b""


def _identity_decorator(func):
    return func


class Flask:
    def __init__(self, *args, **kwargs):
        pass

    def route(self, *args, **kwargs):
        return _identity_decorator

    def before_request(self, func=None):
        if func is None:
            return _identity_decorator
        return func

    def after_request(self, func=None):
        if func is None:
            return _identity_decorator
        return func

    def errorhandler(self, *args, **kwargs):
        return _identity_decorator

    def context_processor(self, func=None):
        if func is None:
            return _identity_decorator
        return func

    def register_blueprint(self, blueprint, **kwargs):
        return None


class Blueprint(Flask):
    def add_url_rule(self, *args, **kwargs):
        return None


request = Request()
g = _AppGlobals()
session = SecureCookieSession()


def jsonify(*args, **kwargs):
    return {}


def redirect(location, code=302):
    return ""


def url_for(endpoint, **values):
    return ""
"""

_WERKZEUG_DATASTRUCTURES_STUB = """
class ImmutableMultiDict(dict):
    def get(self, key, default=None, type=None):
        return ""

    def getlist(self, key):
        return [""]


class EnvironHeaders(dict):
    pass


class FileStorage:
    def __init__(self):
        self.filename = ""

    def read(self):
        return b""

    def save(self, dst, buffer_size=16384):
        return None
"""

_WERKZEUG_FILE_STORAGE_STUB = """
class FileStorage:
    def __init__(self):
        self.filename = ""

    def read(self):
        return b""

    def save(self, dst, buffer_size=16384):
        return None
"""

_FLASK_SESSIONS_STUB = """
class SecureCookieSession(dict):
    pass
"""

_MODULE_STUBS: dict[str, str] = {
    "flask": _FLASK_STUB,
    "flask.blueprints": _FLASK_STUB,
    "flask.globals": _FLASK_STUB,
    "flask.sessions": _FLASK_SESSIONS_STUB,
    "werkzeug.datastructures": _WERKZEUG_DATASTRUCTURES_STUB,
    "werkzeug.datastructures.file_storage": _WERKZEUG_FILE_STORAGE_STUB,
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
        raise AstroidBuildingError(f"no Flask brain stub for {module_name!r}") from exc
    return _module_from_stub(module_name, source)


def register(manager: AstroidManager = MANAGER) -> None:
    """Register Flask module extenders and missing-dependency stubs."""
    for module_name in _MODULE_STUBS:
        register_module_extender(manager, module_name, _make_extender(module_name))
    manager.register_failed_import_hook(_failed_import_hook)


register()
