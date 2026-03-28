"""Astroid brain plugin for flask-login authentication helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from astroid import MANAGER, nodes
from astroid.brain.helpers import register_module_extender
from astroid.builder import parse
from astroid.exceptions import AstroidBuildingError

if TYPE_CHECKING:
    from collections.abc import Callable

    from astroid.manager import AstroidManager

_FLASK_LOGIN_STUB = """
def _identity_decorator(func):
    return func


def login_required(func):
    return func


def roles_required(*roles):
    return _identity_decorator


class UserMixin:
    def __init__(self):
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False

    def get_id(self):
        return ""


class AnonymousUserMixin(UserMixin):
    def __init__(self):
        self.is_authenticated = False
        self.is_active = False
        self.is_anonymous = True


class LoginManager:
    def user_loader(self, callback):
        return callback

    def request_loader(self, callback):
        return callback


current_user = UserMixin()


def login_user(user, remember=False, duration=None, force=False, fresh=True):
    return True


def logout_user():
    return True
"""

_MODULE_STUBS: dict[str, str] = {
    "flask_login": _FLASK_LOGIN_STUB,
    "flask.ext.login": _FLASK_LOGIN_STUB,
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
        raise AstroidBuildingError(f"no flask-login brain stub for {module_name!r}") from exc
    return _module_from_stub(module_name, source)


def _inherits_user_mixin(model: nodes.ClassDef) -> bool:
    for base in model.bases:
        if isinstance(base, nodes.Name) and base.name == "UserMixin":
            return True
        if isinstance(base, nodes.Attribute) and base.attrname == "UserMixin":
            return True
    return False


def _user_mixin_subclasses(module: nodes.Module) -> list[nodes.ClassDef]:
    return [
        statement
        for statement in module.body
        if isinstance(statement, nodes.ClassDef) and _inherits_user_mixin(statement)
    ]


def _has_current_user_import_and_single_model(module: nodes.Module) -> bool:
    return "current_user" in module.locals and len(_user_mixin_subclasses(module)) == 1


def _transform_current_user(module: nodes.Module) -> None:
    models = _user_mixin_subclasses(module)
    if len(models) != 1:
        return
    module.locals["current_user"] = [models[0].instantiate_class()]


def register(manager: AstroidManager = MANAGER) -> None:
    """Register flask-login stubs and current_user model refinement."""
    for module_name in _MODULE_STUBS:
        register_module_extender(manager, module_name, _make_extender(module_name))
    manager.register_failed_import_hook(_failed_import_hook)
    manager.register_transform(
        nodes.Module,
        _transform_current_user,
        _has_current_user_import_and_single_model,
    )


register()
