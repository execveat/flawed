"""Verify frozen dataclasses can be instantiated with valid data."""

from __future__ import annotations

import pytest

from flawed.core import (
    AnalysisGap,
    ExtractionProvenance,
    GapKind,
    Location,
    Provenance,
)
from flawed.function import (
    Decorator,
    Function,
    FunctionKind,
    Parameter,
)


def make_location(
    *,
    file: str = "app/views.py",
    line: int = 10,
    column: int = 0,
) -> Location:
    return Location(file=file, line=line, column=column)


def make_provenance() -> Provenance:
    return Provenance(
        source_layer="L2",
        interpreter="FlaskRouteInterpreter",
        confidence=0.95,
    )


def make_provenance_with_facts() -> Provenance:
    return Provenance(
        source_layer="L2",
        interpreter="FlaskRouteInterpreter",
        confidence=0.95,
        supporting_facts=("route_decorator_found",),
    )


def make_parameter() -> Parameter:
    return Parameter(
        name="user_id",
        annotation="int",
        default=None,
        kind="positional_or_keyword",
    )


def make_function() -> Function:
    return Function(
        fqn="app.views.get_user",
        name="get_user",
        params=(make_parameter(),),
        kind=FunctionKind.TOP_LEVEL,
        parent_class=None,
        parent_function=None,
        location=make_location(),
        provenance=make_provenance(),
    )


class TestLocation:
    def test_basic(self) -> None:
        loc = make_location()
        assert loc.file == "app/views.py"
        assert loc.line == 10
        assert loc.column == 0
        assert loc.end_line is None
        assert loc.end_column is None

    def test_with_end(self) -> None:
        loc = Location(file="a.py", line=1, column=0, end_line=5, end_column=20)
        assert loc.end_line == 5
        assert loc.end_column == 20

    def test_frozen(self) -> None:
        loc = make_location()
        with pytest.raises(AttributeError):
            loc.line = 99  # type: ignore[misc]


class TestProvenance:
    def test_basic(self) -> None:
        p = make_provenance()
        assert p.source_layer == "L2"
        assert p.confidence == 0.95

    def test_provenance_with_facts(self) -> None:
        p = make_provenance_with_facts()
        assert p.supporting_facts == ("route_decorator_found",)

    def test_default_supporting_facts(self) -> None:
        p = make_provenance()
        assert p.supporting_facts == ()

    def test_frozen(self) -> None:
        p = make_provenance()
        with pytest.raises(AttributeError):
            p.confidence = 0.5  # type: ignore[misc]

    def test_extraction_provenance(self) -> None:
        ep = ExtractionProvenance(
            producer="structural_entity_pass",
            producer_version="1.0",
            artifact="normalized/functions.jsonl",
        )
        assert ep.producer == "structural_entity_pass"
        assert ep.producer_version == "1.0"
        assert ep.artifact == "normalized/functions.jsonl"

    def test_extraction_provenance_frozen(self) -> None:
        ep = ExtractionProvenance(
            producer="structural_entity_pass",
            producer_version="1.0",
            artifact="normalized/functions.jsonl",
        )
        with pytest.raises(AttributeError):
            ep.producer = "other"  # type: ignore[misc]

    def test_extraction_provenance_is_slotted(self) -> None:
        ep = ExtractionProvenance(
            producer="structural_entity_pass",
            producer_version="1.0",
            artifact="normalized/functions.jsonl",
        )
        assert not hasattr(ep, "__dict__")


class TestAnalysisGap:
    def test_basic(self) -> None:
        gap = AnalysisGap(
            kind=GapKind.CFG_UNAVAILABLE,
            message="CFG construction failed for function app.views.index",
            affected_file="app/views.py",
            affected_function="app.views.index",
        )
        assert gap.kind == GapKind.CFG_UNAVAILABLE
        assert gap.affected_file == "app/views.py"
        assert gap.affected_function == "app.views.index"
        assert gap.source_error is None

    def test_defaults(self) -> None:
        gap = AnalysisGap(kind=GapKind.PARSE_FAILURE, message="syntax error")
        assert gap.affected_file is None
        assert gap.affected_function is None
        assert gap.source_error is None

    def test_frozen(self) -> None:
        gap = AnalysisGap(kind=GapKind.PARSE_FAILURE, message="err")
        with pytest.raises(AttributeError):
            gap.message = "other"  # type: ignore[misc]


class TestClass:
    def test_basic(self) -> None:
        from flawed.class_ import Class, InheritedMethod

        cls = Class(
            fqn="app.models.User",
            name="User",
            bases=("app.models.Timestamped", "app.models.Base"),
            mro=("app.models.User", "app.models.Timestamped", "app.models.Base"),
            method_names=("__init__", "greet"),
            inherited_methods=(
                InheritedMethod(name="save", defining_class="app.models.Base"),
                InheritedMethod(name="touch", defining_class="app.models.Timestamped"),
            ),
            location=make_location(file="app/models.py", line=10),
            provenance=make_provenance(),
        )
        assert cls.fqn == "app.models.User"
        assert cls.name == "User"
        assert len(cls.bases) == 2
        assert cls.method_names == ("__init__", "greet")
        assert len(cls.inherited_methods) == 2
        assert cls.inherited_methods[0].name == "save"
        assert cls.inherited_methods[0].defining_class == "app.models.Base"

    def test_superclasses(self) -> None:
        from flawed.class_ import Class

        cls = Class(
            fqn="app.models.User",
            name="User",
            bases=("app.models.Base",),
            mro=("app.models.User", "app.models.Base", "builtins.object"),
            method_names=(),
            inherited_methods=(),
            location=make_location(),
            provenance=make_provenance(),
        )
        assert cls.superclasses == ("app.models.Base", "builtins.object")

    def test_superclasses_empty_mro(self) -> None:
        from flawed.class_ import Class

        cls = Class(
            fqn="app.models.Base",
            name="Base",
            bases=(),
            mro=("app.models.Base",),
            method_names=(),
            inherited_methods=(),
            location=make_location(),
            provenance=make_provenance(),
        )
        assert cls.superclasses == ()

    def test_frozen(self) -> None:
        from flawed.class_ import Class

        cls = Class(
            fqn="app.X",
            name="X",
            bases=(),
            mro=("app.X",),
            method_names=(),
            inherited_methods=(),
            location=make_location(),
            provenance=make_provenance(),
        )
        with pytest.raises(AttributeError):
            cls.name = "Y"  # type: ignore[misc]


class TestParameter:
    def test_basic(self) -> None:
        p = make_parameter()
        assert p.name == "user_id"
        assert p.annotation == "int"
        assert p.default is None

    def test_no_annotation(self) -> None:
        p = Parameter(name="x", annotation=None, default="42", kind="positional_or_keyword")
        assert p.annotation is None
        assert p.default == "42"


class TestDecorator:
    def test_basic(self) -> None:
        d = Decorator(
            name="login_required",
            fqn="flask_login.login_required",
            arguments=(),
            location=make_location(),
        )
        assert d.name == "login_required"
        assert d.fqn == "flask_login.login_required"


class TestFunction:
    def test_basic(self) -> None:
        fn = make_function()
        assert fn.fqn == "app.views.get_user"
        assert fn.kind == FunctionKind.TOP_LEVEL
        assert fn.parent_class is None
        assert fn.parent_function is None
        assert len(fn.params) == 1

    def test_method_kind(self) -> None:
        fn = Function(
            fqn="app.models.User.save",
            name="save",
            params=(),
            kind=FunctionKind.METHOD,
            parent_class="app.models.User",
            parent_function=None,
            location=make_location(file="app/models.py", line=20),
            provenance=make_provenance(),
        )
        assert fn.kind == FunctionKind.METHOD
        assert fn.parent_class == "app.models.User"

    def test_nested_kind(self) -> None:
        fn = Function(
            fqn="app.views.outer.<locals>.inner",
            name="inner",
            params=(),
            kind=FunctionKind.NESTED,
            parent_class=None,
            parent_function="app.views.outer",
            location=make_location(line=15),
            provenance=make_provenance(),
        )
        assert fn.kind == FunctionKind.NESTED
        assert fn.parent_function == "app.views.outer"

    def test_frozen(self) -> None:
        fn = make_function()
        with pytest.raises(AttributeError):
            fn.name = "other"  # type: ignore[misc]
