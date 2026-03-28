"""Tests: WebApp runtime skeleton and L1-to-L3 domain conversion.

Covers GATE-001 + L2-001: verify that L2 can consume L1 facts through a clean
public API and produce Rule API domain objects without leaking L1 types.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flawed._index import CodeIndex
from flawed._index._types import (
    ClassRecord,
    DecoratorFact,
    ErrorKind,
    ExtractionError,
    ExtractionProvenance,
    FunctionRecord,
    ParameterKind,
    SourceSpan,
)
from flawed._index._types import (
    FunctionKind as L1FunctionKind,
)
from flawed._index._types import (
    Parameter as L1Parameter,
)
from flawed._semantic import WebApp
from flawed.function import FunctionKind

# =====================================================================
# Helpers
# =====================================================================

_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="")
_SPAN = SourceSpan(file="app.py", line=1, column=0, end_line=5, end_column=0)
_ROOT = Path("/tmp/test-repo")


def _make_function_record(
    *,
    fqn: str = "app.hello",
    name: str = "hello",
    kind: L1FunctionKind = L1FunctionKind.TOP_LEVEL,
    params: tuple[L1Parameter, ...] = (),
    parent_class: str | None = None,
    parent_function: str | None = None,
) -> FunctionRecord:
    return FunctionRecord(
        fqn=fqn,
        name=name,
        file="app.py",
        line=1,
        params=params,
        decorator_names=(),
        decorator_fqns=(),
        kind=kind,
        is_method=kind == L1FunctionKind.METHOD,
        is_nested=kind == L1FunctionKind.NESTED,
        is_async=False,
        parent_class=parent_class,
        location=_SPAN,
        provenance=_PROV,
        parent_function=parent_function,
    )


def _make_class_record(
    *,
    fqn: str = "app.MyClass",
    name: str = "MyClass",
    bases: tuple[str, ...] = (),
    mro_chain: tuple[str, ...] | None = None,
    method_names: tuple[str, ...] = (),
) -> ClassRecord:
    return ClassRecord(
        fqn=fqn,
        name=name,
        file="app.py",
        bases=bases,
        mro_chain=mro_chain if mro_chain is not None else (fqn,),
        mro_complete=True,
        method_names=method_names,
        class_var_names=(),
        is_abstract=False,
        metaclass=None,
        subclasses=(),
        all_subclasses=(),
        inherited_methods=(),
        hierarchy_gaps=(),
        location=_SPAN,
        provenance=_PROV,
    )


def _make_index(
    *,
    functions: tuple[FunctionRecord, ...] = (),
    classes: tuple[ClassRecord, ...] = (),
    decorators: tuple[DecoratorFact, ...] = (),
    errors: tuple[ExtractionError, ...] = (),
) -> CodeIndex:
    return CodeIndex(
        repo_root=_ROOT,
        functions=functions,
        classes=classes,
        decorators=decorators,
        imports=(),
        attributes=(),
        call_edges=(),
        cfgs={},
        value_flow_edges=(),
        symbol_refs=(),
        errors=errors,
        provenance=_PROV,
    )


# =====================================================================
# WebApp.from_index
# =====================================================================


class TestWebAppFromIndex:
    """WebApp.from_index creates a valid runtime shell from a CodeIndex."""

    def test_from_empty_index(self) -> None:
        idx = CodeIndex.empty(_ROOT)
        webapp = WebApp.from_index(idx)
        assert webapp is not None

    def test_from_index_with_functions(self) -> None:
        fn_rec = _make_function_record()
        idx = _make_index(functions=(fn_rec,))
        webapp = WebApp.from_index(idx)
        assert webapp is not None

    def test_from_index_preserves_repo_root(self) -> None:
        idx = CodeIndex.empty(_ROOT)
        webapp = WebApp.from_index(idx)
        rv = webapp.repo_view()
        assert rv.path == str(_ROOT)


# =====================================================================
# FunctionRecord → Function conversion
# =====================================================================


class TestFunctionConversion:
    """L1 FunctionRecord → L3 Function domain conversion."""

    def test_basic_fields(self) -> None:
        fn_rec = _make_function_record(fqn="app.hello", name="hello")
        idx = _make_index(functions=(fn_rec,))
        webapp = WebApp.from_index(idx)
        rv = webapp.repo_view()

        fn = rv.functions.named("hello").one()
        assert fn.fqn == "app.hello"
        assert fn.name == "hello"

    def test_kind_mapped(self) -> None:
        fn_rec = _make_function_record(kind=L1FunctionKind.METHOD, parent_class="app.Cls")
        idx = _make_index(functions=(fn_rec,))
        rv = WebApp.from_index(idx).repo_view()

        fn = rv.functions.one()
        assert fn.kind == FunctionKind.METHOD
        assert fn.parent_class == "app.Cls"

    def test_location_converted(self) -> None:
        fn_rec = _make_function_record()
        idx = _make_index(functions=(fn_rec,))
        rv = WebApp.from_index(idx).repo_view()

        fn = rv.functions.one()
        assert fn.location.file == "app.py"
        assert fn.location.line == 1
        assert fn.location.column == 0
        assert fn.location.end_line == 5
        assert fn.location.end_column == 0

    def test_provenance_set(self) -> None:
        fn_rec = _make_function_record()
        idx = _make_index(functions=(fn_rec,))
        rv = WebApp.from_index(idx).repo_view()

        fn = rv.functions.one()
        assert fn.provenance.source_layer == "L2"
        assert fn.provenance.confidence >= 0.9

    def test_parameters_converted(self) -> None:
        l1_param = L1Parameter(
            name="x",
            annotation="int",
            default="0",
            kind=ParameterKind.POSITIONAL_OR_KEYWORD,
            position=0,
            location=_SPAN,
        )
        fn_rec = _make_function_record(params=(l1_param,))
        idx = _make_index(functions=(fn_rec,))
        rv = WebApp.from_index(idx).repo_view()

        fn = rv.functions.one()
        assert len(fn.params) == 1
        assert fn.params[0].name == "x"
        assert fn.params[0].annotation == "int"
        assert fn.params[0].default == "0"
        assert fn.params[0].kind == "positional_or_keyword"

    def test_parent_function_none_for_top_level(self) -> None:
        fn_rec = _make_function_record(kind=L1FunctionKind.TOP_LEVEL)
        idx = _make_index(functions=(fn_rec,))
        rv = WebApp.from_index(idx).repo_view()

        fn = rv.functions.one()
        assert fn.parent_function is None

    def test_parent_function_converted_for_nested(self) -> None:
        fn_rec = _make_function_record(
            fqn="app.outer.<locals>.inner",
            name="inner",
            kind=L1FunctionKind.NESTED,
            parent_function="app.outer",
        )
        idx = _make_index(functions=(fn_rec,))
        rv = WebApp.from_index(idx).repo_view()

        fn = rv.functions.one()
        assert fn.parent_function == "app.outer"


# =====================================================================
# ClassRecord → Class conversion
# =====================================================================


class TestClassConversion:
    """L1 ClassRecord → L3 Class domain conversion."""

    def test_basic_fields(self) -> None:
        cr = _make_class_record(fqn="app.MyClass", name="MyClass")
        idx = _make_index(classes=(cr,))
        rv = WebApp.from_index(idx).repo_view()

        cls = rv.classes.named("MyClass").one()
        assert cls.fqn == "app.MyClass"
        assert cls.name == "MyClass"

    def test_bases_and_mro(self) -> None:
        cr = _make_class_record(
            fqn="app.Child",
            name="Child",
            bases=("app.Parent",),
            mro_chain=("app.Child", "app.Parent"),
        )
        idx = _make_index(classes=(cr,))
        rv = WebApp.from_index(idx).repo_view()

        cls = rv.classes.one()
        assert cls.bases == ("app.Parent",)
        assert cls.mro == ("app.Child", "app.Parent")

    def test_method_names_preserved(self) -> None:
        cr = _make_class_record(method_names=("__init__", "save"))
        idx = _make_index(classes=(cr,))
        rv = WebApp.from_index(idx).repo_view()

        cls = rv.classes.one()
        assert cls.method_names == ("__init__", "save")

    def test_location_and_provenance(self) -> None:
        cr = _make_class_record()
        idx = _make_index(classes=(cr,))
        rv = WebApp.from_index(idx).repo_view()

        cls = rv.classes.one()
        assert cls.location.file == "app.py"
        assert cls.provenance.source_layer == "L2"


# =====================================================================
# RepoView collection queries
# =====================================================================


class TestRepoViewCollections:
    """RepoView exposes typed collections with query methods."""

    def test_functions_where(self) -> None:
        fns = (
            _make_function_record(fqn="app.a", name="a"),
            _make_function_record(fqn="app.b", name="b"),
        )
        idx = _make_index(functions=fns)
        rv = WebApp.from_index(idx).repo_view()

        result = rv.functions.where(lambda f: f.name == "a")
        assert len(result) == 1
        assert result.one().name == "a"

    def test_functions_named(self) -> None:
        fns = (
            _make_function_record(fqn="app.a", name="a"),
            _make_function_record(fqn="app.b", name="b"),
        )
        idx = _make_index(functions=fns)
        rv = WebApp.from_index(idx).repo_view()

        result = rv.functions.named("b")
        assert len(result) == 1

    def test_classes_named(self) -> None:
        classes = (
            _make_class_record(fqn="app.X", name="X"),
            _make_class_record(fqn="app.Y", name="Y"),
        )
        idx = _make_index(classes=classes)
        rv = WebApp.from_index(idx).repo_view()

        result = rv.classes.named("Y")
        assert len(result) == 1
        assert result.one().name == "Y"

    def test_routes_empty_without_providers(self) -> None:
        idx = CodeIndex.empty(_ROOT)
        rv = WebApp.from_index(idx).repo_view()

        routes = rv.routes
        assert len(routes) == 0

    def test_functions_iter_and_len(self) -> None:
        fns = (
            _make_function_record(fqn="app.a", name="a"),
            _make_function_record(fqn="app.b", name="b"),
            _make_function_record(fqn="app.c", name="c"),
        )
        idx = _make_index(functions=fns)
        rv = WebApp.from_index(idx).repo_view()

        assert len(rv.functions) == 3
        names = {f.name for f in rv.functions}
        assert names == {"a", "b", "c"}

    def test_empty_collections_are_falsy(self) -> None:
        idx = CodeIndex.empty(_ROOT)
        rv = WebApp.from_index(idx).repo_view()

        assert not rv.functions
        assert not rv.classes
        assert not rv.routes

    def test_one_raises_on_empty(self) -> None:
        idx = CodeIndex.empty(_ROOT)
        rv = WebApp.from_index(idx).repo_view()

        with pytest.raises(ValueError, match="expected exactly 1"):
            rv.functions.one()


# =====================================================================
# DecoratorFact → Decorator conversion
# =====================================================================


class TestDecoratorConversion:
    """L1 DecoratorFact → L3 Decorator domain conversion and wiring."""

    def test_decorator_basic_fields(self) -> None:
        dec = DecoratorFact(
            name="app.route",
            fqn="flask.app.Flask.route",
            args=('"/users"',),
            kwargs=(("methods", '["POST"]'),),
            target_fqn="app.hello",
            application_order=0,
            location=_SPAN,
            provenance=_PROV,
        )
        fn_rec = _make_function_record(fqn="app.hello", name="hello")
        idx = _make_index(functions=(fn_rec,), decorators=(dec,))
        rv = WebApp.from_index(idx).repo_view()

        fn = rv.functions.named("hello").one()
        assert len(fn.decorators) == 1
        d = fn.decorators.first()
        assert d is not None
        assert d.name == "app.route"
        assert d.fqn == "flask.app.Flask.route"
        assert d.arguments == ('"/users"',)
        assert d.location.file == "app.py"

    def test_function_multiple_decorators(self) -> None:
        decs = (
            DecoratorFact(
                name="app.route",
                fqn="flask.app.Flask.route",
                args=('"/users"',),
                kwargs=(),
                target_fqn="app.hello",
                application_order=1,
                location=_SPAN,
                provenance=_PROV,
            ),
            DecoratorFact(
                name="login_required",
                fqn="flask_login.login_required",
                args=(),
                kwargs=(),
                target_fqn="app.hello",
                application_order=0,
                location=_SPAN,
                provenance=_PROV,
            ),
        )
        fn_rec = _make_function_record(fqn="app.hello", name="hello")
        idx = _make_index(functions=(fn_rec,), decorators=decs)
        rv = WebApp.from_index(idx).repo_view()

        fn = rv.functions.named("hello").one()
        assert len(fn.decorators) == 2

    def test_decorated_with_by_name(self) -> None:
        dec = DecoratorFact(
            name="app.route",
            fqn="flask.app.Flask.route",
            args=(),
            kwargs=(),
            target_fqn="app.hello",
            application_order=0,
            location=_SPAN,
            provenance=_PROV,
        )
        fn_rec = _make_function_record(fqn="app.hello", name="hello")
        fn_other = _make_function_record(fqn="app.other", name="other")
        idx = _make_index(functions=(fn_rec, fn_other), decorators=(dec,))
        rv = WebApp.from_index(idx).repo_view()

        result = rv.functions.decorated_with("app.route")
        assert len(result) == 1
        assert result.one().name == "hello"

    def test_decorated_with_by_fqn(self) -> None:
        dec = DecoratorFact(
            name="app.route",
            fqn="flask.app.Flask.route",
            args=(),
            kwargs=(),
            target_fqn="app.hello",
            application_order=0,
            location=_SPAN,
            provenance=_PROV,
        )
        fn_rec = _make_function_record(fqn="app.hello", name="hello")
        idx = _make_index(functions=(fn_rec,), decorators=(dec,))
        rv = WebApp.from_index(idx).repo_view()

        result = rv.functions.decorated_with("flask.app.Flask.route")
        assert len(result) == 1

    def test_class_decorated_with_by_name(self) -> None:
        dec = DecoratorFact(
            name="model_marker",
            fqn="app.decorators.model_marker",
            args=(),
            kwargs=(),
            target_fqn="app.User",
            application_order=0,
            location=_SPAN,
            provenance=_PROV,
        )
        cls_rec = _make_class_record(fqn="app.User", name="User")
        other_cls = _make_class_record(fqn="app.Other", name="Other")
        fn_rec = _make_function_record(fqn="app.helper", name="helper")
        fn_dec = DecoratorFact(
            name="model_marker",
            fqn="app.decorators.model_marker",
            args=(),
            kwargs=(),
            target_fqn="app.helper",
            application_order=0,
            location=_SPAN,
            provenance=_PROV,
        )
        idx = _make_index(
            functions=(fn_rec,),
            classes=(cls_rec, other_cls),
            decorators=(dec, fn_dec),
        )
        rv = WebApp.from_index(idx).repo_view()

        result = rv.classes.decorated_with("model_marker")

        assert [klass.name for klass in result] == ["User"]
        assert result.one().decorators.one().fqn == "app.decorators.model_marker"

    def test_class_decorated_with_by_fqn(self) -> None:
        dec = DecoratorFact(
            name="model_marker",
            fqn="app.decorators.model_marker",
            args=(),
            kwargs=(),
            target_fqn="app.User",
            application_order=0,
            location=_SPAN,
            provenance=_PROV,
        )
        cls_rec = _make_class_record(fqn="app.User", name="User")
        idx = _make_index(classes=(cls_rec,), decorators=(dec,))
        rv = WebApp.from_index(idx).repo_view()

        result = rv.classes.decorated_with("app.decorators.model_marker")

        assert result.one().name == "User"

    def test_decorator_collection_named_filter(self) -> None:
        decs = (
            DecoratorFact(
                name="app.route",
                fqn=None,
                args=(),
                kwargs=(),
                target_fqn="app.hello",
                application_order=0,
                location=_SPAN,
                provenance=_PROV,
            ),
            DecoratorFact(
                name="login_required",
                fqn=None,
                args=(),
                kwargs=(),
                target_fqn="app.hello",
                application_order=1,
                location=_SPAN,
                provenance=_PROV,
            ),
        )
        fn_rec = _make_function_record(fqn="app.hello", name="hello")
        idx = _make_index(functions=(fn_rec,), decorators=decs)
        rv = WebApp.from_index(idx).repo_view()

        fn = rv.functions.named("hello").one()
        routes = fn.decorators.named("app.route")
        assert len(routes) == 1
        logins = fn.decorators.named("login_required")
        assert len(logins) == 1


# =====================================================================
# Analysis gap propagation
# =====================================================================


class TestAnalysisGapPropagation:
    """L1 ExtractionError → L3 AnalysisGap propagation."""

    def test_extraction_errors_become_function_gaps(self) -> None:
        fn_rec = _make_function_record(fqn="app.hello", name="hello")
        err = ExtractionError(
            file="app.py",
            pass_name="cfg_builder",
            error_kind=ErrorKind.CFG,
            message="yield in function body",
            is_fatal=False,
            location=_SPAN,
        )
        idx = _make_index(functions=(fn_rec,), errors=(err,))
        rv = WebApp.from_index(idx).repo_view()

        fn = rv.functions.named("hello").one()
        assert len(fn.gaps) == 1
        gap = fn.gaps[0]
        assert gap.kind.value == "cfg_unavailable"
        assert "yield" in gap.message

    def test_function_gaps_empty_when_no_errors(self) -> None:
        fn_rec = _make_function_record()
        idx = _make_index(functions=(fn_rec,))
        rv = WebApp.from_index(idx).repo_view()

        fn = rv.functions.one()
        assert fn.gaps == ()

    def test_class_gaps_empty_when_no_errors(self) -> None:
        cr = _make_class_record()
        idx = _make_index(classes=(cr,))
        rv = WebApp.from_index(idx).repo_view()

        cls = rv.classes.one()
        assert cls.gaps == ()

    def test_error_for_different_file_not_attached(self) -> None:
        fn_rec = _make_function_record(fqn="app.hello", name="hello")
        err = ExtractionError(
            file="other.py",
            pass_name="cfg_builder",
            error_kind=ErrorKind.CFG,
            message="some error in other file",
            is_fatal=False,
            location=SourceSpan(file="other.py", line=1, column=0, end_line=1, end_column=0),
        )
        idx = _make_index(functions=(fn_rec,), errors=(err,))
        rv = WebApp.from_index(idx).repo_view()

        fn = rv.functions.named("hello").one()
        assert fn.gaps == ()


# =====================================================================
# Function navigation properties
# =====================================================================


class TestFunctionNavigation:
    """Function navigation properties work instead of raising NotImplementedError."""

    def test_parameter_named(self) -> None:
        l1_param = L1Parameter(
            name="user_id",
            annotation="int",
            default=None,
            kind=ParameterKind.POSITIONAL_OR_KEYWORD,
            position=0,
            location=_SPAN,
        )
        fn_rec = _make_function_record(params=(l1_param,))
        idx = _make_index(functions=(fn_rec,))
        rv = WebApp.from_index(idx).repo_view()

        fn = rv.functions.one()
        p = fn.parameter_named("user_id")
        assert p.name == "user_id"

    def test_parameter_named_missing(self) -> None:
        fn_rec = _make_function_record()
        idx = _make_index(functions=(fn_rec,))
        rv = WebApp.from_index(idx).repo_view()

        fn = rv.functions.one()
        with pytest.raises(KeyError, match="nonexistent"):
            fn.parameter_named("nonexistent")

    def test_calls_returns_empty_collection(self) -> None:
        fn_rec = _make_function_record()
        idx = _make_index(functions=(fn_rec,))
        rv = WebApp.from_index(idx).repo_view()

        fn = rv.functions.one()
        assert len(fn.calls) == 0

    def test_called_by_returns_empty_collection(self) -> None:
        fn_rec = _make_function_record()
        idx = _make_index(functions=(fn_rec,))
        rv = WebApp.from_index(idx).repo_view()

        fn = rv.functions.one()
        assert len(fn.called_by) == 0

    def test_class_methods_returns_matching_functions(self) -> None:
        cr = _make_class_record(
            fqn="app.MyClass",
            name="MyClass",
            method_names=("__init__", "save"),
        )
        fn_init = _make_function_record(
            fqn="app.MyClass.__init__",
            name="__init__",
            kind=L1FunctionKind.METHOD,
            parent_class="app.MyClass",
        )
        fn_save = _make_function_record(
            fqn="app.MyClass.save",
            name="save",
            kind=L1FunctionKind.METHOD,
            parent_class="app.MyClass",
        )
        fn_other = _make_function_record(fqn="app.other", name="other")
        idx = _make_index(
            functions=(fn_init, fn_save, fn_other),
            classes=(cr,),
        )
        rv = WebApp.from_index(idx).repo_view()

        cls = rv.classes.named("MyClass").one()
        methods = cls.methods
        assert len(methods) == 2
        names = {f.name for f in methods}
        assert names == {"__init__", "save"}

    def test_class_is_abstract_false(self) -> None:
        cr = _make_class_record()
        idx = _make_index(classes=(cr,))
        rv = WebApp.from_index(idx).repo_view()

        cls = rv.classes.one()
        assert cls.is_abstract is False
