"""Flask request input-resolution tests."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from flawed._index import CodeIndex
from flawed._index._types import (
    AccessKind,
    AttributeAccess,
    CallArgument,
    CallEdge,
    DecoratorFact,
    EdgeSource,
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
from flawed._index._types import ParameterKind as L1ParameterKind
from flawed._semantic import WebApp
from flawed.core import Key
from flawed.inputs import (
    AccessPattern,
    Cardinality,
    Cookie,
    FileUpload,
    Form,
    Header,
    Json,
    PathParam,
    Query,
    RawBody,
)

if TYPE_CHECKING:
    from flawed.repo import RepoView
    from flawed.route import Route

_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="")
_ROOT = Path("/tmp/test-repo")


def _route(repo: RepoView, endpoint: str) -> Route:
    return repo.routes.where(lambda route: route.endpoint == endpoint).one()


class TestFlaskDirectInputReads:
    """Direct Flask request reads produce InputRead domain objects."""

    def test_request_args_get_produces_query_read_with_key(self, flask_basic: RepoView) -> None:
        route = _route(flask_basic, "input_query")

        read = route.body.reads(Query()).one()

        assert read.source == Query(key=Key("user_id"))
        assert read.access_pattern is AccessPattern.GET
        assert read.cardinality is Cardinality.SINGLE
        assert read.function.fqn == "flask_basic.app.input_query"
        assert read.expression == 'request.args.get("user_id")'

    def test_request_form_subscript_and_get_produce_form_reads(
        self, flask_basic: RepoView
    ) -> None:
        route = _route(flask_basic, "input_form")

        reads = tuple(route.body.reads(Form()))

        assert [(read.source, read.access_pattern) for read in reads] == [
            (Form(key=Key("name")), AccessPattern.SUBSCRIPT),
            (Form(key=Key("email")), AccessPattern.GET),
        ]
        assert all(read.cardinality is Cardinality.SINGLE for read in reads)

    def test_request_json_attribute_and_get_json_method_produce_json_reads(
        self, flask_basic: RepoView
    ) -> None:
        attr_read = _route(flask_basic, "input_json_attr").body.reads(Json()).one()
        method_read = _route(flask_basic, "input_json_method").body.reads(Json()).one()

        assert attr_read.source == Json()
        assert attr_read.access_pattern is AccessPattern.ATTRIBUTE
        assert attr_read.expression == "request.json"
        assert method_read.source == Json()
        assert method_read.access_pattern is AccessPattern.ATTRIBUTE
        assert method_read.expression == "request.get_json()"

    def test_request_headers_and_cookies_get_extract_names(self, flask_basic: RepoView) -> None:
        header = _route(flask_basic, "input_headers").body.reads(Header()).one()
        cookie = _route(flask_basic, "input_cookies").body.reads(Cookie()).one()

        assert header.source == Header(name=Key("Authorization"))
        assert header.access_pattern is AccessPattern.GET
        assert cookie.source == Cookie(name=Key("session_token"))
        assert cookie.access_pattern is AccessPattern.GET

    def test_request_files_subscript_and_data_attribute_produce_file_and_raw_reads(
        self, flask_basic: RepoView
    ) -> None:
        upload = _route(flask_basic, "input_files").body.reads(FileUpload()).one()
        raw = _route(flask_basic, "input_raw").body.reads(RawBody()).one()

        assert upload.source == FileUpload(field=Key("document"))
        assert upload.access_pattern is AccessPattern.SUBSCRIPT
        assert upload.cardinality is Cardinality.SINGLE
        assert raw.source == RawBody()
        assert raw.access_pattern is AccessPattern.ATTRIBUTE

    def test_route_path_parameter_produces_path_param_read(self, flask_basic: RepoView) -> None:
        route = _route(flask_basic, "input_path")

        read = route.body.reads(PathParam()).one()

        assert read.source == PathParam(name=Key("item_id"))
        assert read.access_pattern is AccessPattern.UNKNOWN
        assert read.cardinality is Cardinality.SINGLE
        assert read.expression == "item_id"


class TestFlaskAliasedInputReads:
    """Flask request import aliases resolve for direct input reads."""

    def test_aliased_request_args_get_produces_query_read(self, flask_aliased: RepoView) -> None:
        route = _route(flask_aliased, "input_query")

        read = route.body.reads(Query()).one()

        assert read.source == Query(key=Key("user_id"))
        assert read.access_pattern is AccessPattern.GET
        assert read.expression == 'req.args.get("user_id")'

    def test_aliased_request_form_json_header_and_cookie_reads(
        self, flask_aliased: RepoView
    ) -> None:
        form = _route(flask_aliased, "input_form").body.reads(Form()).one()
        json_read = _route(flask_aliased, "input_json").body.reads(Json()).one()
        header = _route(flask_aliased, "input_headers").body.reads(Header()).one()
        cookie = _route(flask_aliased, "input_cookies").body.reads(Cookie()).one()

        assert form.source == Form(key=Key("name"))
        assert form.access_pattern is AccessPattern.SUBSCRIPT
        assert json_read.source == Json()
        assert json_read.access_pattern is AccessPattern.ATTRIBUTE
        assert header.source == Header(name=Key("Authorization"))
        assert cookie.source == Cookie(name=Key("session_token"))


class TestFlaskLocalInputAliasReads:
    """Handler-local aliases resolve through generic L1 value-flow facts."""

    def test_local_request_object_alias_produces_query_read(self) -> None:
        idx = _make_index(
            functions=(_function("app.handler"),),
            decorators=(
                _decorator(
                    "app.route",
                    target_fqn="app.handler",
                    args=('"/alias-object"',),
                    line=10,
                ),
            ),
            attributes=(
                AttributeAccess(
                    target_expr="local_request",
                    attr_name="args",
                    is_write=False,
                    access_kind=AccessKind.ATTR,
                    value_expr=None,
                    containing_function_fqn="app.handler",
                    location=_span(22),
                    provenance=_PROV,
                ),
            ),
            call_edges=(
                _call(
                    "local_request.args.get",
                    expression='local_request.args.get("user_id")',
                    args=(_arg(0, '"user_id"', line=22),),
                    line=22,
                ),
            ),
            symbols=(
                _symbol("Flask", "flask.Flask", line=1),
                _symbol("app.route", "app.app.route", line=10),
                _symbol("request", "flask.request", line=21),
            ),
            value_flow_edges=(
                _vf("Flask(__name__)", "app", containing_function_fqn=None, line=2),
                _vf("request", "local_request", containing_function_fqn="app.handler", line=21),
            ),
        )

        read = WebApp.from_index(idx).repo_view().routes.one().body.reads(Query()).one()

        assert read.source == Query(key=Key("user_id"))
        assert read.access_pattern is AccessPattern.GET
        assert read.expression == 'local_request.args.get("user_id")'

    def test_local_input_container_alias_get_produces_query_read(self) -> None:
        idx = _make_index(
            functions=(_function("app.handler"),),
            decorators=(
                _decorator(
                    "app.route",
                    target_fqn="app.handler",
                    args=('"/alias-container"',),
                    line=10,
                ),
            ),
            attributes=(
                AttributeAccess(
                    target_expr="request",
                    attr_name="args",
                    is_write=False,
                    access_kind=AccessKind.ATTR,
                    value_expr=None,
                    containing_function_fqn="app.handler",
                    location=_span(21),
                    provenance=_PROV,
                ),
            ),
            call_edges=(
                _call(
                    "params.get",
                    expression='params.get("user_id")',
                    args=(_arg(0, '"user_id"', line=22),),
                    line=22,
                ),
            ),
            symbols=(
                _symbol("Flask", "flask.Flask", line=1),
                _symbol("app.route", "app.app.route", line=10),
                _symbol("request", "flask.request", line=21),
            ),
            value_flow_edges=(
                _vf("Flask(__name__)", "app", containing_function_fqn=None, line=2),
                _vf("request.args", "params", containing_function_fqn="app.handler", line=21),
            ),
        )

        read = WebApp.from_index(idx).repo_view().routes.one().body.reads(Query()).one()

        assert read.source == Query(key=Key("user_id"))
        assert read.access_pattern is AccessPattern.GET
        assert read.expression == 'params.get("user_id")'

    def test_local_input_container_alias_subscript_produces_form_read(self) -> None:
        idx = _make_index(
            functions=(_function("app.handler"),),
            decorators=(
                _decorator(
                    "app.route",
                    target_fqn="app.handler",
                    args=('"/alias-form"',),
                    line=10,
                ),
            ),
            attributes=(
                AttributeAccess(
                    target_expr="request",
                    attr_name="form",
                    is_write=False,
                    access_kind=AccessKind.ATTR,
                    value_expr=None,
                    containing_function_fqn="app.handler",
                    location=_span(21),
                    provenance=_PROV,
                ),
                AttributeAccess(
                    target_expr="form_data",
                    attr_name='"name"',
                    is_write=False,
                    access_kind=AccessKind.SUBSCRIPT,
                    value_expr=None,
                    containing_function_fqn="app.handler",
                    location=_span(22),
                    provenance=_PROV,
                ),
            ),
            call_edges=(),
            symbols=(
                _symbol("Flask", "flask.Flask", line=1),
                _symbol("app.route", "app.app.route", line=10),
                _symbol("request", "flask.request", line=21),
            ),
            value_flow_edges=(
                _vf("Flask(__name__)", "app", containing_function_fqn=None, line=2),
                _vf("request.form", "form_data", containing_function_fqn="app.handler", line=21),
            ),
        )

        read = WebApp.from_index(idx).repo_view().routes.one().body.reads(Form()).one()

        assert read.source == Form(key=Key("name"))
        assert read.access_pattern is AccessPattern.SUBSCRIPT
        assert read.expression == 'form_data["name"]'

    def test_request_container_argument_produces_helper_keyed_reads(self) -> None:
        helper = _function(
            "app.helper",
            params=(
                L1Parameter(
                    name="data",
                    annotation=None,
                    default=None,
                    kind=L1ParameterKind.POSITIONAL_OR_KEYWORD,
                    position=0,
                    location=_span(30),
                ),
            ),
            line=30,
        )
        idx = _make_index(
            functions=(_function("app.handler"), helper),
            decorators=(
                _decorator(
                    "app.route",
                    target_fqn="app.handler",
                    args=('"/helper-form"',),
                    line=10,
                ),
            ),
            attributes=(
                AttributeAccess(
                    target_expr="request",
                    attr_name="form",
                    is_write=False,
                    access_kind=AccessKind.ATTR,
                    value_expr=None,
                    containing_function_fqn="app.handler",
                    location=_span(21),
                    provenance=_PROV,
                ),
            ),
            call_edges=(
                _call(
                    "app.helper",
                    expression="helper(request.form)",
                    args=(_arg(0, "request.form", line=21),),
                    line=21,
                ),
                _call(
                    "data.get",
                    expression='data.get("item")',
                    args=(_arg(0, '"item"', line=31),),
                    line=31,
                    caller_fqn="app.helper",
                ),
                _call(
                    "data.getlist",
                    expression='data.getlist("items")',
                    args=(_arg(0, '"items"', line=32),),
                    line=32,
                    caller_fqn="app.helper",
                ),
            ),
            symbols=(
                _symbol("Flask", "flask.Flask", line=1),
                _symbol("app.route", "app.app.route", line=10),
                _symbol("request", "flask.request", line=21),
            ),
            value_flow_edges=(
                _vf("Flask(__name__)", "app", containing_function_fqn=None, line=2),
            ),
        )

        reads = tuple(WebApp.from_index(idx).repo_view().routes.one().reachable.reads(Form()))

        observed = {(read.source, read.access_pattern, read.cardinality) for read in reads}
        assert {
            (Form(key=Key("item")), AccessPattern.GET, Cardinality.SINGLE),
            (Form(key=Key("items")), AccessPattern.GETLIST, Cardinality.MULTI),
        } <= observed
        keyed_reads = [read for read in reads if getattr(read.source, "key", None) is not None]
        assert {read.function.fqn for read in keyed_reads} == {"app.helper"}


class TestFlaskInputFalsePositives:
    """Local names shadowing Flask globals do not become Flask input reads."""

    def test_local_request_parameter_does_not_match_flask_request_proxy(self) -> None:
        handler = _function(
            "app.handler",
            params=(
                L1Parameter(
                    name="request",
                    annotation=None,
                    default=None,
                    kind=L1ParameterKind.POSITIONAL_OR_KEYWORD,
                    position=0,
                    location=_span(20),
                ),
            ),
        )
        idx = _make_index(
            functions=(handler,),
            decorators=(
                _decorator(
                    "app.route",
                    target_fqn="app.handler",
                    args=('"/shadow"',),
                    line=10,
                ),
            ),
            attributes=(
                AttributeAccess(
                    target_expr="request",
                    attr_name="args",
                    is_write=False,
                    access_kind=AccessKind.ATTR,
                    value_expr=None,
                    containing_function_fqn="app.handler",
                    location=_span(21),
                    provenance=_PROV,
                ),
            ),
            call_edges=(),
            symbols=(
                _symbol("Flask", "flask.Flask", line=1),
                _symbol("app.route", "app.app.route", line=10),
                _symbol("request", "flask.request", line=21),
            ),
            value_flow_edges=(
                ValueFlowEdge(
                    source_expr="Flask(__name__)",
                    source_location=_span(2),
                    target_expr="app",
                    target_location=_span(2),
                    kind=FlowKind.ASSIGN,
                    containing_function_fqn=None,
                    provenance=_PROV,
                ),
            ),
        )

        route = WebApp.from_index(idx).repo_view().routes.one()

        assert tuple(route.body.reads(Query())) == ()


class TestCrossFunctionInputReads:
    """Input reads in callee functions surface on the caller route's body scope."""

    def test_callee_input_read_surfaces_on_handler_route(self) -> None:
        """A handler calls a helper; the helper's input read appears on the route."""
        idx = _make_index(
            functions=(
                _function("app.handler"),
                _function("app._helper", line=30),
            ),
            decorators=(
                _decorator(
                    "app.route",
                    target_fqn="app.handler",
                    args=('"/test"',),
                    line=10,
                ),
            ),
            attributes=(
                AttributeAccess(
                    target_expr="request",
                    attr_name="args",
                    is_write=False,
                    access_kind=AccessKind.ATTR,
                    value_expr=None,
                    containing_function_fqn="app._helper",
                    location=_span(31),
                    provenance=_PROV,
                ),
            ),
            call_edges=(
                _call(
                    "request.args.get",
                    expression='request.args.get("user_id")',
                    args=(_arg(0, '"user_id"', line=31),),
                    line=31,
                    caller_fqn="app._helper",
                ),
                _call(
                    "app._helper",
                    expression="_helper()",
                    args=(),
                    line=22,
                    caller_fqn="app.handler",
                ),
            ),
            symbols=(
                _symbol("Flask", "flask.Flask", line=1),
                _symbol("app.route", "app.app.route", line=10),
                _symbol("request", "flask.request", line=31),
            ),
            value_flow_edges=(
                _vf("Flask(__name__)", "app", containing_function_fqn=None, line=2),
            ),
        )

        route = WebApp.from_index(idx).repo_view().routes.one()
        reads = tuple(route.body.reads(Query()))

        assert len(reads) == 1
        assert reads[0].source == Query(key=Key("user_id"))
        assert reads[0].function.fqn == "app._helper"

    def test_transitive_callee_input_read_at_depth_two(self) -> None:
        """Handler → helper → helper2; input read in helper2 surfaces."""
        idx = _make_index(
            functions=(
                _function("app.handler"),
                _function("app._helper", line=30),
                _function("app._helper2", line=40),
            ),
            decorators=(
                _decorator(
                    "app.route",
                    target_fqn="app.handler",
                    args=('"/test"',),
                    line=10,
                ),
            ),
            attributes=(
                AttributeAccess(
                    target_expr="request",
                    attr_name="args",
                    is_write=False,
                    access_kind=AccessKind.ATTR,
                    value_expr=None,
                    containing_function_fqn="app._helper2",
                    location=_span(41),
                    provenance=_PROV,
                ),
            ),
            call_edges=(
                _call(
                    "request.args.get",
                    expression='request.args.get("key")',
                    args=(_arg(0, '"key"', line=41),),
                    line=41,
                    caller_fqn="app._helper2",
                ),
                _call(
                    "app._helper2",
                    expression="_helper2()",
                    args=(),
                    line=31,
                    caller_fqn="app._helper",
                ),
                _call(
                    "app._helper",
                    expression="_helper()",
                    args=(),
                    line=22,
                    caller_fqn="app.handler",
                ),
            ),
            symbols=(
                _symbol("Flask", "flask.Flask", line=1),
                _symbol("app.route", "app.app.route", line=10),
                _symbol("request", "flask.request", line=41),
            ),
            value_flow_edges=(
                _vf("Flask(__name__)", "app", containing_function_fqn=None, line=2),
            ),
        )

        route = WebApp.from_index(idx).repo_view().routes.one()
        reads = tuple(route.body.reads(Query()))

        assert len(reads) == 1
        assert reads[0].source == Query(key=Key("key"))
        assert reads[0].function.fqn == "app._helper2"

    def test_unrelated_function_input_read_does_not_leak_to_route(self) -> None:
        """An input read in a function NOT called by the handler does not appear."""
        idx = _make_index(
            functions=(
                _function("app.handler"),
                _function("app.unrelated", line=40),
            ),
            decorators=(
                _decorator(
                    "app.route",
                    target_fqn="app.handler",
                    args=('"/test"',),
                    line=10,
                ),
            ),
            attributes=(
                AttributeAccess(
                    target_expr="request",
                    attr_name="args",
                    is_write=False,
                    access_kind=AccessKind.ATTR,
                    value_expr=None,
                    containing_function_fqn="app.unrelated",
                    location=_span(41),
                    provenance=_PROV,
                ),
            ),
            call_edges=(
                _call(
                    "request.args.get",
                    expression='request.args.get("user_id")',
                    args=(_arg(0, '"user_id"', line=41),),
                    line=41,
                    caller_fqn="app.unrelated",
                ),
            ),
            symbols=(
                _symbol("Flask", "flask.Flask", line=1),
                _symbol("app.route", "app.app.route", line=10),
                _symbol("request", "flask.request", line=41),
            ),
            value_flow_edges=(
                _vf("Flask(__name__)", "app", containing_function_fqn=None, line=2),
            ),
        )

        route = WebApp.from_index(idx).repo_view().routes.one()
        reads = tuple(route.body.reads(Query()))

        assert reads == ()


class TestFlaskIndirectFixtureInputReads:
    """Flask indirect fixture: cross-function and cross-file input reads."""

    def test_l3_cross_function_same_file_helper_read(self, flask_indirect: RepoView) -> None:
        """_get_user_id() reads request.args → surfaces on /l3/input route."""
        route = _route(flask_indirect, "l3_cross_function_input")

        reads = tuple(route.body.reads(Query()))

        assert len(reads) >= 1
        query_reads = [r for r in reads if r.source == Query(key=Key("user_id"))]
        assert len(query_reads) == 1
        assert query_reads[0].function.fqn == "flask_indirect.app._get_user_id"

    def test_l4_cross_file_imported_helper_read(self, flask_indirect: RepoView) -> None:
        """helpers.get_query_param() reads request.args → surfaces on /l4/input."""
        route = _route(flask_indirect, "l4_cross_file_input")

        reads = tuple(route.body.reads(Query()))

        assert len(reads) >= 1
        query_reads = [
            r for r in reads if r.function.fqn == "flask_indirect.helpers.get_query_param"
        ]
        assert len(query_reads) == 1

    def test_l6_multi_hop_cross_file_read(self, flask_indirect: RepoView) -> None:
        """utils.process_input() → helpers.get_query_param() → request.args."""
        route = _route(flask_indirect, "l6_nested_call")

        reads = tuple(route.body.reads(Query()))

        assert len(reads) >= 1
        query_reads = [
            r for r in reads if r.function.fqn == "flask_indirect.helpers.get_query_param"
        ]
        assert len(query_reads) == 1

    def test_l7_getattr_dynamic_not_detected(self, flask_indirect: RepoView) -> None:
        """getattr(request, 'args') is dynamic — no input read expected."""
        route = _route(flask_indirect, "l7_getattr")

        reads = tuple(route.body.reads(Query()))

        assert reads == ()


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


def _call(
    callee_fqn: str,
    *,
    expression: str,
    args: tuple[CallArgument, ...],
    line: int,
    caller_fqn: str = "app.handler",
) -> CallEdge:
    return CallEdge(
        caller_fqn=caller_fqn,
        callee_fqn=callee_fqn,
        arguments=args,
        resolution=ResolutionStatus.RESOLVED,
        source=EdgeSource.AST,
        unresolved_reason=None,
        location=_span(line),
        provenance=_PROV,
        call_expression=expression,
    )


def _arg(position: int, expression: str, *, line: int) -> CallArgument:
    return CallArgument(
        position=position,
        keyword=None,
        expression=expression,
        location=_span(line),
    )


def _vf(
    source_expr: str,
    target_expr: str,
    *,
    containing_function_fqn: str | None,
    line: int,
) -> ValueFlowEdge:
    return ValueFlowEdge(
        source_expr=source_expr,
        source_location=_span(line),
        target_expr=target_expr,
        target_location=_span(line),
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
    decorators: tuple[DecoratorFact, ...],
    attributes: tuple[AttributeAccess, ...],
    call_edges: tuple[CallEdge, ...],
    symbols: tuple[SymbolRef, ...],
    value_flow_edges: tuple[ValueFlowEdge, ...],
) -> CodeIndex:
    return CodeIndex(
        repo_root=_ROOT,
        functions=functions,
        classes=(),
        decorators=decorators,
        imports=(
            ImportFact(
                module="flask",
                names=("Flask", "request"),
                aliases=(),
                is_from_import=True,
                location=_span(1),
                provenance=_PROV,
            ),
        ),
        attributes=attributes,
        call_edges=call_edges,
        cfgs={},
        value_flow_edges=value_flow_edges,
        symbol_refs=symbols,
        errors=(),
        provenance=_PROV,
    )
