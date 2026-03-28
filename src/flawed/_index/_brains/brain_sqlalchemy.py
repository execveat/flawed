"""Astroid brain plugin for SQLAlchemy ORM structural inference."""

from __future__ import annotations

from typing import TYPE_CHECKING

from astroid import MANAGER, nodes
from astroid.brain.helpers import register_module_extender
from astroid.builder import extract_node, parse
from astroid.exceptions import AstroidBuildingError, UseInferenceDefault
from astroid.inference_tip import inference_tip
from astroid.util import safe_infer

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from astroid.context import InferenceContext
    from astroid.manager import AstroidManager
    from astroid.typing import InferenceResult

_SQLALCHEMY_STUB = """
class Integer:
    pass


class String:
    def __init__(self, *args, **kwargs):
        pass


class Text:
    pass


class Boolean:
    pass


class DateTime:
    pass


class Float:
    pass


class Column:
    def __init__(self, *args, **kwargs):
        pass


def relationship(*args, **kwargs):
    return None


class Query:
    def filter(self, *args, **kwargs):
        return self

    def filter_by(self, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def join(self, *args, **kwargs):
        return self

    def all(self):
        return []

    def first(self):
        return None

    def one(self):
        return None

    def get(self, ident):
        return None


class Session:
    def query(self, model):
        return Query()


class sessionmaker:
    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, **kwargs):
        return Session()


def declarative_base(*args, **kwargs):
    class Base:
        pass

    return Base
"""

_MODULE_STUBS: dict[str, str] = {
    "sqlalchemy": _SQLALCHEMY_STUB,
    "sqlalchemy.orm": _SQLALCHEMY_STUB,
    "sqlalchemy.orm.session": _SQLALCHEMY_STUB,
    "flask_sqlalchemy": _SQLALCHEMY_STUB
    + """
class SQLAlchemy:
    Column = Column
    Integer = Integer
    String = String
    Text = Text
    Boolean = Boolean
    DateTime = DateTime
    Float = Float
    Model = declarative_base()

    def __init__(self, *args, **kwargs):
        self.session = Session()

    def relationship(self, *args, **kwargs):
        return relationship(*args, **kwargs)
""",
}
_COLUMN_TYPES = {
    "BigInteger": "0",
    "Boolean": "True",
    "Float": "0.0",
    "Integer": "0",
    "SmallInteger": "0",
    "String": '""',
    "Text": '""',
    "Unicode": '""',
    "UnicodeText": '""',
}
_QUERY_CHAIN_METHODS = frozenset({"filter", "filter_by", "join", "limit", "offset", "order_by"})
_QUERY_TERMINAL_METHODS = frozenset({"all", "first", "get", "one"})


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
        raise AstroidBuildingError(f"no SQLAlchemy brain stub for {module_name!r}") from exc
    return _module_from_stub(module_name, source)


def _call_name(node: nodes.NodeNG) -> str | None:
    if not isinstance(node, nodes.Call):
        return None
    if isinstance(node.func, nodes.Name):
        return str(node.func.name)
    if isinstance(node.func, nodes.Attribute):
        return str(node.func.attrname)
    return None


def _type_name(node: nodes.NodeNG) -> str | None:
    if isinstance(node, nodes.Call):
        return _type_name(node.func)
    if isinstance(node, nodes.Name):
        return str(node.name)
    if isinstance(node, nodes.Attribute):
        return str(node.attrname)
    return None


def _keyword_is_true(call: nodes.Call, keyword_name: str) -> bool:
    for keyword in call.keywords:
        if keyword.arg != keyword_name:
            continue
        return isinstance(keyword.value, nodes.Const) and keyword.value.value is True
    return False


def _column_nodes(call: nodes.Call) -> list[nodes.NodeNG]:
    type_name = _column_type_name(call)
    if type_name is None:
        return []

    nodes_for_type = [_value_node(type_name)]
    if _keyword_is_true(call, "nullable"):
        nodes_for_type.append(extract_node("None"))
    return nodes_for_type


def _column_type_name(call: nodes.Call) -> str | None:
    for arg in call.args:
        name = _type_name(arg)
        if name in _COLUMN_TYPES or name == "DateTime":
            return name
    for keyword in call.keywords:
        if keyword.arg in {"type_", "type"}:
            name = _type_name(keyword.value)
            if name in _COLUMN_TYPES or name == "DateTime":
                return name
    return None


def _value_node(type_name: str) -> nodes.NodeNG:
    if type_name == "DateTime":
        module = parse("import datetime\nvalue = datetime.datetime(2000, 1, 1)")
        return module.body[1].value
    module = parse(f"value = {_COLUMN_TYPES[type_name]}", apply_transforms=False)
    return module.body[0].value


def _relationship_nodes(model: nodes.ClassDef, call: nodes.Call) -> list[InferenceResult]:
    target_name = _relationship_target_name(call)
    if target_name is None:
        return []

    target = _class_in_module(model.root(), target_name)
    if target is None:
        return []

    if _keyword_is_true(call, "uselist"):
        return [extract_node("[]")]
    return [target.instantiate_class()]


def _relationship_target_name(call: nodes.Call) -> str | None:
    if not call.args:
        return None
    first = call.args[0]
    if isinstance(first, nodes.Const) and isinstance(first.value, str):
        return first.value
    return _type_name(first)


def _class_in_module(module: nodes.Module, name: str) -> nodes.ClassDef | None:
    values = module.locals.get(name, ())
    for value in values:
        if isinstance(value, nodes.ClassDef):
            return value
    return None


def _assign_targets(statement: nodes.Assign | nodes.AnnAssign) -> Iterator[nodes.AssignName]:
    raw_targets = statement.targets if isinstance(statement, nodes.Assign) else [statement.target]
    for target in raw_targets:
        if isinstance(target, nodes.AssignName):
            yield target


def _orm_attribute_nodes(model: nodes.ClassDef, value: nodes.NodeNG) -> list[InferenceResult]:
    if not isinstance(value, nodes.Call):
        return []
    call_name = _call_name(value)
    if call_name == "Column":
        return _column_nodes(value)
    if call_name == "relationship":
        return _relationship_nodes(model, value)
    return []


def _has_sqlalchemy_orm_assignment(model: nodes.ClassDef) -> bool:
    for statement in model.body:
        if not isinstance(statement, (nodes.Assign, nodes.AnnAssign)):
            continue
        if _orm_attribute_nodes(model, statement.value):
            return True
    return False


def _transform_sqlalchemy_model(model: nodes.ClassDef) -> None:
    for statement in model.body:
        if not isinstance(statement, (nodes.Assign, nodes.AnnAssign)):
            continue
        inferred_nodes = _orm_attribute_nodes(model, statement.value)
        if not inferred_nodes:
            continue
        for target in _assign_targets(statement):
            model.instance_attrs[target.name] = list(inferred_nodes)


def _query_model(expr: nodes.NodeNG) -> nodes.ClassDef | None:
    if not isinstance(expr, nodes.Call) or not isinstance(expr.func, nodes.Attribute):
        return None

    method_name = expr.func.attrname
    if method_name == "query" and expr.args:
        inferred = safe_infer(expr.args[0])
        if isinstance(inferred, nodes.ClassDef):
            return inferred
        return None

    if method_name in _QUERY_CHAIN_METHODS:
        return _query_model(expr.func.expr)
    return None


def _query_instance() -> nodes.NodeNG:
    module = parse("class Query:\n    pass\nquery = Query()", apply_transforms=False)
    return module.body[1].value


def _is_query_object_call(node: nodes.Call) -> bool:
    if not isinstance(node.func, nodes.Attribute):
        return False
    if node.func.attrname == "query" and node.args:
        return isinstance(safe_infer(node.args[0]), nodes.ClassDef)
    if node.func.attrname in _QUERY_CHAIN_METHODS:
        return _query_model(node.func.expr) is not None
    return False


def _infer_query_object(
    node: nodes.Call,
    context: InferenceContext | None = None,
) -> Iterator[InferenceResult]:
    _ = context
    if not _is_query_object_call(node):
        raise UseInferenceDefault("SQLAlchemy query object target model is unknown")
    yield from _query_instance().infer()


def _is_query_terminal_call(node: nodes.Call) -> bool:
    if not isinstance(node.func, nodes.Attribute):
        return False
    if node.func.attrname not in _QUERY_TERMINAL_METHODS:
        return False
    return _query_model(node.func.expr) is not None


def _infer_query_terminal(
    node: nodes.Call,
    context: InferenceContext | None = None,
) -> Iterator[InferenceResult]:
    _ = context
    if not isinstance(node.func, nodes.Attribute):
        raise UseInferenceDefault("SQLAlchemy query terminal must be an attribute call")

    model = _query_model(node.func.expr)
    if model is None:
        raise UseInferenceDefault("SQLAlchemy query target model is unknown")

    method_name = node.func.attrname
    if method_name == "all":
        yield extract_node("[]")
    elif method_name in {"first", "get"}:
        yield model.instantiate_class()
        yield extract_node("None")
    elif method_name == "one":
        yield model.instantiate_class()
    else:
        raise UseInferenceDefault(f"unsupported SQLAlchemy query terminal {method_name!r}")


def register(manager: AstroidManager = MANAGER) -> None:
    """Register SQLAlchemy module stubs and ORM inference transforms."""
    for module_name in _MODULE_STUBS:
        register_module_extender(manager, module_name, _make_extender(module_name))
    manager.register_failed_import_hook(_failed_import_hook)
    manager.register_transform(
        nodes.ClassDef,
        _transform_sqlalchemy_model,
        _has_sqlalchemy_orm_assignment,
    )
    manager.register_transform(
        nodes.Call,
        inference_tip(_infer_query_object),
        _is_query_object_call,
    )
    manager.register_transform(
        nodes.Call,
        inference_tip(_infer_query_terminal),
        _is_query_terminal_call,
    )


register()
