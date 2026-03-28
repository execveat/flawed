"""InputFieldAccessPattern resolution tests.

Tests form-field subclass attribute access patterns like ``form.username.data``
where ``form`` is an instance of a class that extends a provider-declared base
(e.g. ``flask_wtf.FlaskForm``).
"""

from __future__ import annotations

from pathlib import Path

from flawed._index import CodeIndex
from flawed._index._types import (
    AccessKind,
    AttributeAccess,
    CallEdge,
    ClassRecord,
    DecoratorFact,
    ExtractionProvenance,
    FlowKind,
    FunctionRecord,
    ImportFact,
    ResolutionStatus,
    SourceSpan,
    SymbolRef,
    ValueFlowEdge,
)
from flawed._index._types import FunctionKind as L1FunctionKind
from flawed._index._types import Parameter as L1Parameter
from flawed._semantic import WebApp
from flawed.core import Key
from flawed.inputs import (
    AccessPattern,
    Cardinality,
    FileUpload,
    Form,
)

_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="")
_ROOT = Path("/tmp/test-repo")


def _span(line: int, *, file: str = "app.py") -> SourceSpan:
    return SourceSpan(file=file, line=line, column=0, end_line=line, end_column=10)


def _function(
    fqn: str,
    *,
    params: tuple[L1Parameter, ...] = (),
    line: int = 20,
) -> FunctionRecord:
    return FunctionRecord(
        fqn=fqn,
        name=fqn.rsplit(".", 1)[-1],
        file="app.py",
        line=line,
        params=params,
        decorator_names=(),
        decorator_fqns=(),
        kind=L1FunctionKind.TOP_LEVEL,
        is_method=False,
        is_nested=False,
        is_async=False,
        parent_class=None,
        location=_span(line),
        provenance=_PROV,
    )


def _decorator(
    fqn: str,
    *,
    target_fqn: str,
    args: tuple[str, ...],
    line: int,
) -> DecoratorFact:
    return DecoratorFact(
        name=fqn,
        fqn=fqn,
        args=args,
        kwargs=(),
        target_fqn=target_fqn,
        application_order=0,
        location=_span(line),
        provenance=_PROV,
    )


def _class_record(
    fqn: str,
    *,
    bases: tuple[str, ...] = (),
    mro_chain: tuple[str, ...] | None = None,
    file: str = "forms.py",
    line: int = 1,
) -> ClassRecord:
    return ClassRecord(
        fqn=fqn,
        name=fqn.rsplit(".", 1)[-1],
        file=file,
        bases=bases,
        mro_chain=mro_chain or (fqn,),
        mro_complete=True,
        method_names=(),
        class_var_names=(),
        is_abstract=False,
        metaclass=None,
        subclasses=(),
        all_subclasses=(),
        inherited_methods=(),
        hierarchy_gaps=(),
        location=_span(line, file=file),
        provenance=_PROV,
    )


def _vf(
    source_expr: str,
    target_expr: str,
    *,
    containing_function_fqn: str | None,
    line: int,
    file: str = "app.py",
) -> ValueFlowEdge:
    return ValueFlowEdge(
        source_expr=source_expr,
        source_location=_span(line, file=file),
        target_expr=target_expr,
        target_location=_span(line, file=file),
        kind=FlowKind.ASSIGN,
        containing_function_fqn=containing_function_fqn,
        provenance=_PROV,
    )


def _symbol(name: str, fqn: str, *, line: int) -> SymbolRef:
    return SymbolRef(
        name=name,
        fqn=fqn,
        resolution=ResolutionStatus.RESOLVED,
        location=_span(line),
        provenance=_PROV,
    )


def _make_index(
    *,
    functions: tuple[FunctionRecord, ...],
    classes: tuple[ClassRecord, ...] = (),
    decorators: tuple[DecoratorFact, ...],
    attributes: tuple[AttributeAccess, ...],
    call_edges: tuple[CallEdge, ...] = (),
    symbols: tuple[SymbolRef, ...],
    value_flow_edges: tuple[ValueFlowEdge, ...],
    imports: tuple[ImportFact, ...] | None = None,
) -> CodeIndex:
    default_imports = (
        ImportFact(
            module="flask",
            names=("Flask", "request"),
            aliases=(),
            is_from_import=True,
            location=_span(1),
            provenance=_PROV,
        ),
        ImportFact(
            module="flask_wtf",
            names=("FlaskForm",),
            aliases=(),
            is_from_import=True,
            location=_span(2),
            provenance=_PROV,
        ),
    )
    return CodeIndex(
        repo_root=_ROOT,
        functions=functions,
        classes=classes,
        decorators=decorators,
        imports=imports if imports is not None else default_imports,
        attributes=attributes,
        call_edges=call_edges,
        cfgs={},
        value_flow_edges=value_flow_edges,
        symbol_refs=symbols,
        errors=(),
        provenance=_PROV,
    )


class TestFieldAccessFormRead:
    """InputFieldAccessPattern produces InputRead for form.field.data accesses."""

    def test_form_field_data_produces_form_read(self) -> None:
        """form.username.data where form is FlaskForm subclass → Form(key=username)."""
        idx = _make_index(
            functions=(_function("app.register"),),
            classes=(
                _class_record(
                    "app.RegistrationForm",
                    bases=("FlaskForm",),
                    file="app.py",
                    line=5,
                ),
            ),
            decorators=(
                _decorator(
                    "app.route",
                    target_fqn="app.register",
                    args=('"/register"',),
                    line=10,
                ),
            ),
            attributes=(
                AttributeAccess(
                    target_expr="form.username",
                    attr_name="data",
                    is_write=False,
                    access_kind=AccessKind.ATTR,
                    value_expr=None,
                    containing_function_fqn="app.register",
                    location=_span(23),
                    provenance=_PROV,
                ),
            ),
            symbols=(
                _symbol("Flask", "flask.Flask", line=1),
                _symbol("FlaskForm", "flask_wtf.FlaskForm", line=2),
                _symbol("app.route", "app.app.route", line=10),
                _symbol("RegistrationForm", "app.RegistrationForm", line=5),
            ),
            value_flow_edges=(
                _vf("Flask(__name__)", "app", containing_function_fqn=None, line=4),
                _vf(
                    "RegistrationForm()",
                    "form",
                    containing_function_fqn="app.register",
                    line=22,
                ),
            ),
        )

        repo = WebApp.from_index(idx).repo_view()
        route = repo.routes.one()
        read = route.body.reads(Form()).one()

        assert read.source == Form(key=Key("username"))
        assert read.access_pattern is AccessPattern.ATTRIBUTE
        assert read.cardinality is Cardinality.SINGLE
        assert read.expression == "form.username.data"

    def test_multiple_field_accesses_produce_multiple_reads(self) -> None:
        """form.username.data + form.email.data → two Form InputReads."""
        idx = _make_index(
            functions=(_function("app.register"),),
            classes=(
                _class_record(
                    "app.RegistrationForm",
                    bases=("FlaskForm",),
                    file="app.py",
                    line=5,
                ),
            ),
            decorators=(
                _decorator(
                    "app.route",
                    target_fqn="app.register",
                    args=('"/register"',),
                    line=10,
                ),
            ),
            attributes=(
                AttributeAccess(
                    target_expr="form.username",
                    attr_name="data",
                    is_write=False,
                    access_kind=AccessKind.ATTR,
                    value_expr=None,
                    containing_function_fqn="app.register",
                    location=_span(23),
                    provenance=_PROV,
                ),
                AttributeAccess(
                    target_expr="form.email",
                    attr_name="data",
                    is_write=False,
                    access_kind=AccessKind.ATTR,
                    value_expr=None,
                    containing_function_fqn="app.register",
                    location=_span(24),
                    provenance=_PROV,
                ),
            ),
            symbols=(
                _symbol("Flask", "flask.Flask", line=1),
                _symbol("FlaskForm", "flask_wtf.FlaskForm", line=2),
                _symbol("app.route", "app.app.route", line=10),
                _symbol("RegistrationForm", "app.RegistrationForm", line=5),
            ),
            value_flow_edges=(
                _vf("Flask(__name__)", "app", containing_function_fqn=None, line=4),
                _vf(
                    "RegistrationForm()",
                    "form",
                    containing_function_fqn="app.register",
                    line=22,
                ),
            ),
        )

        repo = WebApp.from_index(idx).repo_view()
        reads = tuple(repo.routes.one().body.reads(Form()))

        assert len(reads) == 2
        sources = {read.source for read in reads}
        assert Form(key=Key("username")) in sources
        assert Form(key=Key("email")) in sources
        assert all(read.access_pattern is AccessPattern.ATTRIBUTE for read in reads)

    def test_project_local_mro_chain_matches_base_class(self) -> None:
        """Subclasses through a project-local base still match provider base FQNs."""
        idx = _make_index(
            functions=(_function("app.register"),),
            classes=(
                _class_record(
                    "app.BaseRegistrationForm",
                    bases=("FlaskForm",),
                    mro_chain=("app.BaseRegistrationForm",),
                    file="app.py",
                    line=5,
                ),
                _class_record(
                    "app.RegistrationForm",
                    bases=("BaseRegistrationForm",),
                    mro_chain=("app.RegistrationForm", "app.BaseRegistrationForm"),
                    file="app.py",
                    line=8,
                ),
            ),
            decorators=(
                _decorator(
                    "app.route",
                    target_fqn="app.register",
                    args=('"/register"',),
                    line=10,
                ),
            ),
            attributes=(
                AttributeAccess(
                    target_expr="form.username",
                    attr_name="data",
                    is_write=False,
                    access_kind=AccessKind.ATTR,
                    value_expr=None,
                    containing_function_fqn="app.register",
                    location=_span(23),
                    provenance=_PROV,
                ),
            ),
            symbols=(
                _symbol("Flask", "flask.Flask", line=1),
                _symbol("FlaskForm", "flask_wtf.FlaskForm", line=2),
                _symbol("app.route", "app.app.route", line=10),
                _symbol("BaseRegistrationForm", "app.BaseRegistrationForm", line=8),
                _symbol("RegistrationForm", "app.RegistrationForm", line=22),
            ),
            value_flow_edges=(
                _vf("Flask(__name__)", "app", containing_function_fqn=None, line=4),
                _vf(
                    "RegistrationForm()",
                    "form",
                    containing_function_fqn="app.register",
                    line=22,
                ),
            ),
        )

        repo = WebApp.from_index(idx).repo_view()
        read = repo.routes.one().body.reads(Form()).one()

        assert read.source == Form(key=Key("username"))

    def test_non_subclass_field_access_not_matched(self) -> None:
        """obj.field.data where obj is NOT a FlaskForm subclass → no InputRead."""
        idx = _make_index(
            functions=(_function("app.handler"),),
            classes=(
                _class_record(
                    "app.SomeObject",
                    bases=("object",),
                    file="app.py",
                    line=5,
                ),
            ),
            decorators=(
                _decorator(
                    "app.route",
                    target_fqn="app.handler",
                    args=('"/handler"',),
                    line=10,
                ),
            ),
            attributes=(
                AttributeAccess(
                    target_expr="obj.field",
                    attr_name="data",
                    is_write=False,
                    access_kind=AccessKind.ATTR,
                    value_expr=None,
                    containing_function_fqn="app.handler",
                    location=_span(23),
                    provenance=_PROV,
                ),
            ),
            symbols=(
                _symbol("Flask", "flask.Flask", line=1),
                _symbol("FlaskForm", "flask_wtf.FlaskForm", line=2),
                _symbol("app.route", "app.app.route", line=10),
                _symbol("SomeObject", "app.SomeObject", line=5),
            ),
            value_flow_edges=(
                _vf("Flask(__name__)", "app", containing_function_fqn=None, line=4),
                _vf(
                    "SomeObject()",
                    "obj",
                    containing_function_fqn="app.handler",
                    line=22,
                ),
            ),
        )

        repo = WebApp.from_index(idx).repo_view()
        reads = tuple(repo.routes.one().body.reads(Form()))

        assert len(reads) == 0

    def test_write_access_not_matched(self) -> None:
        """form.field.data = value (write) → no InputRead."""
        idx = _make_index(
            functions=(_function("app.register"),),
            classes=(
                _class_record(
                    "app.RegistrationForm",
                    bases=("FlaskForm",),
                    file="app.py",
                    line=5,
                ),
            ),
            decorators=(
                _decorator(
                    "app.route",
                    target_fqn="app.register",
                    args=('"/register"',),
                    line=10,
                ),
            ),
            attributes=(
                AttributeAccess(
                    target_expr="form.username",
                    attr_name="data",
                    is_write=True,
                    access_kind=AccessKind.ATTR,
                    value_expr="new_value",
                    containing_function_fqn="app.register",
                    location=_span(23),
                    provenance=_PROV,
                ),
            ),
            symbols=(
                _symbol("Flask", "flask.Flask", line=1),
                _symbol("FlaskForm", "flask_wtf.FlaskForm", line=2),
                _symbol("app.route", "app.app.route", line=10),
                _symbol("RegistrationForm", "app.RegistrationForm", line=5),
            ),
            value_flow_edges=(
                _vf("Flask(__name__)", "app", containing_function_fqn=None, line=4),
                _vf(
                    "RegistrationForm()",
                    "form",
                    containing_function_fqn="app.register",
                    line=22,
                ),
            ),
        )

        repo = WebApp.from_index(idx).repo_view()
        reads = tuple(repo.routes.one().body.reads(Form()))

        assert len(reads) == 0

    def test_wrong_attribute_not_matched(self) -> None:
        """form.field.value (not .data) → no InputRead."""
        idx = _make_index(
            functions=(_function("app.register"),),
            classes=(
                _class_record(
                    "app.RegistrationForm",
                    bases=("FlaskForm",),
                    file="app.py",
                    line=5,
                ),
            ),
            decorators=(
                _decorator(
                    "app.route",
                    target_fqn="app.register",
                    args=('"/register"',),
                    line=10,
                ),
            ),
            attributes=(
                AttributeAccess(
                    target_expr="form.username",
                    attr_name="value",
                    is_write=False,
                    access_kind=AccessKind.ATTR,
                    value_expr=None,
                    containing_function_fqn="app.register",
                    location=_span(23),
                    provenance=_PROV,
                ),
            ),
            symbols=(
                _symbol("Flask", "flask.Flask", line=1),
                _symbol("FlaskForm", "flask_wtf.FlaskForm", line=2),
                _symbol("app.route", "app.app.route", line=10),
                _symbol("RegistrationForm", "app.RegistrationForm", line=5),
            ),
            value_flow_edges=(
                _vf("Flask(__name__)", "app", containing_function_fqn=None, line=4),
                _vf(
                    "RegistrationForm()",
                    "form",
                    containing_function_fqn="app.register",
                    line=22,
                ),
            ),
        )

        repo = WebApp.from_index(idx).repo_view()
        reads = tuple(repo.routes.one().body.reads(Form()))

        assert len(reads) == 0

    def test_file_upload_field_produces_file_upload_read(self) -> None:
        """FileField subclass .data → FileUpload(field=Key("photo"))."""
        idx = _make_index(
            functions=(_function("app.upload"),),
            classes=(
                _class_record(
                    "app.UploadForm",
                    bases=("FlaskForm",),
                    file="app.py",
                    line=5,
                ),
                _class_record(
                    "app.PhotoField",
                    bases=("FileField",),
                    file="app.py",
                    line=7,
                ),
            ),
            decorators=(
                _decorator(
                    "app.route",
                    target_fqn="app.upload",
                    args=('"/upload"',),
                    line=10,
                ),
            ),
            attributes=(
                AttributeAccess(
                    target_expr="form.photo",
                    attr_name="data",
                    is_write=False,
                    access_kind=AccessKind.ATTR,
                    value_expr=None,
                    containing_function_fqn="app.upload",
                    location=_span(23),
                    provenance=_PROV,
                ),
            ),
            symbols=(
                _symbol("Flask", "flask.Flask", line=1),
                _symbol("FlaskForm", "flask_wtf.FlaskForm", line=2),
                _symbol("FileField", "flask_wtf.file.FileField", line=3),
                _symbol("app.route", "app.app.route", line=10),
                _symbol("UploadForm", "app.UploadForm", line=5),
                _symbol("PhotoField", "app.PhotoField", line=7),
            ),
            value_flow_edges=(
                _vf("Flask(__name__)", "app", containing_function_fqn=None, line=4),
                _vf("PhotoField()", "app.UploadForm.photo", containing_function_fqn=None, line=8),
                _vf(
                    "UploadForm()",
                    "form",
                    containing_function_fqn="app.upload",
                    line=22,
                ),
            ),
        )

        repo = WebApp.from_index(idx).repo_view()

        form_reads = tuple(repo.routes.one().body.reads(Form()))
        assert len(form_reads) == 1
        assert form_reads[0].source == Form(key=Key("photo"))
        assert form_reads[0].access_pattern is AccessPattern.ATTRIBUTE

        file_reads = tuple(repo.routes.one().body.reads(FileUpload()))
        assert len(file_reads) == 1
        assert file_reads[0].source == FileUpload(field=Key("photo"))
        assert file_reads[0].access_pattern is AccessPattern.ATTRIBUTE
