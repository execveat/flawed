"""Astroid brain plugin for WTForms field and form objects."""

from __future__ import annotations

from typing import TYPE_CHECKING

from astroid import MANAGER, nodes
from astroid.brain.helpers import register_module_extender
from astroid.builder import parse
from astroid.exceptions import AstroidBuildingError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from astroid.manager import AstroidManager

_WTFORMS_STUB = """
class Form:
    def __init__(self, *args, **kwargs):
        self.errors = {}
        self.data = {}

    def validate(self, *args, **kwargs):
        return True

    def validate_on_submit(self, *args, **kwargs):
        return True


class FlaskForm(Form):
    pass


class _Field:
    def __init__(self, *args, **kwargs):
        self.data = None


class StringField(_Field):
    def __init__(self, *args, **kwargs):
        self.data = ""


class TextAreaField(StringField):
    pass


class PasswordField(StringField):
    pass


class HiddenField(StringField):
    pass


class SelectField(StringField):
    pass


class IntegerField(_Field):
    def __init__(self, *args, **kwargs):
        self.data = 0


class BooleanField(_Field):
    def __init__(self, *args, **kwargs):
        self.data = True


class FloatField(_Field):
    def __init__(self, *args, **kwargs):
        self.data = 0.0


class SubmitField(BooleanField):
    pass
"""

_MODULE_STUBS: dict[str, str] = {
    "wtforms": _WTFORMS_STUB,
    "wtforms.fields": _WTFORMS_STUB,
    "flask_wtf": _WTFORMS_STUB,
    "flask_wtf.form": _WTFORMS_STUB,
}
_FIELD_DATA_VALUES = {
    "BooleanField": "True",
    "FloatField": "0.0",
    "IntegerField": "0",
    "PasswordField": '""',
    "SelectField": '""',
    "StringField": '""',
    "TextAreaField": '""',
    "HiddenField": '""',
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
        raise AstroidBuildingError(f"no WTForms brain stub for {module_name!r}") from exc
    return _module_from_stub(module_name, source)


def _call_name(node: nodes.NodeNG) -> str | None:
    if not isinstance(node, nodes.Call):
        return None
    if isinstance(node.func, nodes.Name):
        return str(node.func.name)
    if isinstance(node.func, nodes.Attribute):
        return str(node.func.attrname)
    return None


def _field_instance(call: nodes.Call, field_name: str) -> nodes.NodeNG:
    data_value = _field_data_value(call, field_name)
    module = parse(
        "class _BrainField:\n"
        "    def __init__(self):\n"
        f"        self.data = {data_value}\n"
        "field = _BrainField()",
    )
    return module.body[1].value


def _field_data_value(call: nodes.Call, field_name: str) -> str:
    if field_name != "SelectField":
        return _FIELD_DATA_VALUES[field_name]
    for keyword in call.keywords:
        if keyword.arg != "coerce":
            continue
        if isinstance(keyword.value, nodes.Name):
            return {"bool": "True", "float": "0.0", "int": "0", "str": '""'}.get(
                keyword.value.name,
                '""',
            )
    return _FIELD_DATA_VALUES[field_name]


def _assign_targets(statement: nodes.Assign | nodes.AnnAssign) -> Iterator[nodes.AssignName]:
    raw_targets = statement.targets if isinstance(statement, nodes.Assign) else [statement.target]
    for target in raw_targets:
        if isinstance(target, nodes.AssignName):
            yield target


def _has_wtforms_field_assignment(model: nodes.ClassDef) -> bool:
    for statement in model.body:
        if not isinstance(statement, (nodes.Assign, nodes.AnnAssign)):
            continue
        if _call_name(statement.value) in _FIELD_DATA_VALUES:
            return True
    return False


def _transform_wtforms_fields(model: nodes.ClassDef) -> None:
    for statement in model.body:
        if not isinstance(statement, (nodes.Assign, nodes.AnnAssign)):
            continue
        if not isinstance(statement.value, nodes.Call):
            continue
        field_name = _call_name(statement.value)
        if field_name not in _FIELD_DATA_VALUES:
            continue
        field = _field_instance(statement.value, field_name)
        for target in _assign_targets(statement):
            model.instance_attrs[target.name] = [field]


def register(manager: AstroidManager = MANAGER) -> None:
    """Register WTForms module stubs and field transforms."""
    for module_name in _MODULE_STUBS:
        register_module_extender(manager, module_name, _make_extender(module_name))
    manager.register_failed_import_hook(_failed_import_hook)
    manager.register_transform(
        nodes.ClassDef,
        _transform_wtforms_fields,
        _has_wtforms_field_assignment,
    )


register()
