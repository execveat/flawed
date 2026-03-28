"""InputParameterPattern resolution tests — FastAPI-style parameter defaults."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from flawed._index import CodeIndex
from flawed._index._types import (
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
from flawed._index._types import ParameterKind as L1ParameterKind
from flawed._semantic import WebApp
from flawed._semantic._conversion import convert_function
from flawed._semantic._input_conversion import convert_input_match
from flawed._semantic._provider_engine import ProviderEngine
from flawed._semantic.providers import (
    InputParameterPattern,
    Provider,
    ProviderMeta,
    RouteDecorator,
)
from flawed.core import JsonPath, Key
from flawed.inputs import (
    AccessPattern,
    Cardinality,
    Cookie,
    Header,
    Json,
    Query,
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
        is_async=True,
        parent_class=None,
        location=_span(line),
        provenance=_PROV,
    )


def _param(
    name: str,
    *,
    default: str | None = None,
    position: int = 0,
    line: int = 21,
    annotation: str | None = None,
) -> L1Parameter:
    return L1Parameter(
        name=name,
        annotation=annotation,
        default=default,
        kind=L1ParameterKind.KEYWORD_ONLY,
        position=position,
        location=_span(line),
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


def _symbol(name: str, fqn: str, *, line: int) -> SymbolRef:
    return SymbolRef(
        name=name,
        fqn=fqn,
        resolution=ResolutionStatus.RESOLVED,
        location=_span(line),
        provenance=_PROV,
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


def _make_index(
    *,
    functions: tuple[FunctionRecord, ...],
    decorators: tuple[DecoratorFact, ...] = (),
    symbols: tuple[SymbolRef, ...] = (),
    value_flow_edges: tuple[ValueFlowEdge, ...] = (),
    imports: tuple[ImportFact, ...] | None = None,
) -> CodeIndex:
    return CodeIndex(
        repo_root=_ROOT,
        functions=functions,
        classes=(),
        decorators=decorators,
        imports=imports
        or (
            ImportFact(
                module="fastapi",
                names=("FastAPI", "Query", "Header", "Cookie", "Body"),
                aliases=(),
                is_from_import=True,
                location=_span(1),
                provenance=_PROV,
            ),
        ),
        attributes=(),
        call_edges=(),
        cfgs={},
        value_flow_edges=value_flow_edges,
        symbol_refs=symbols,
        errors=(),
        provenance=_PROV,
    )


class CustomParameterProvider(Provider):
    """Provider used to exercise non-default key derivation strategies."""

    meta = ProviderMeta(
        id="custom-parameters",
        name="Custom Parameters",
        version="0.1.0",
        library="custom",
        library_fqn="custom",
    )
    routes = (
        RouteDecorator(
            fqn="custom.App.get",
            rule_arg=0,
            default_methods=("GET",),
        ),
    )
    inputs = (
        InputParameterPattern(
            default_type_fqn="custom.ParamAlias",
            source_type="Query",
            key_from="alias",
        ),
        InputParameterPattern(
            default_type_fqn="custom.ParamFirst",
            source_type="Header",
            key_from="first_arg",
        ),
    )


def _custom_imports() -> tuple[ImportFact, ...]:
    return (
        ImportFact(
            module="custom",
            names=("App", "ParamAlias", "ParamFirst"),
            aliases=(),
            is_from_import=True,
            location=_span(1),
            provenance=_PROV,
        ),
    )


class TestParameterInputResolution:
    """InputParameterPattern: function parameter defaults as input sources."""

    def test_query_default_produces_query_read(self) -> None:
        """Parameter with Query(None) default → InputRead(source=Query)."""
        idx = _make_index(
            functions=(
                _function(
                    "app.search",
                    params=(_param("q", default="Query(None)", position=0, line=21),),
                ),
            ),
            decorators=(
                _decorator(
                    "app.get",
                    target_fqn="app.search",
                    args=('"/search"',),
                    line=19,
                ),
            ),
            symbols=(
                _symbol("FastAPI", "fastapi.applications.FastAPI", line=1),
                _symbol("Query", "fastapi.param_functions.Query", line=1),
                _symbol("app.get", "app.app.get", line=19),
            ),
            value_flow_edges=(_vf("FastAPI()", "app", containing_function_fqn=None, line=2),),
        )

        repo = WebApp.from_index(idx).repo_view()
        route = repo.routes.one()
        read = route.body.reads(Query()).one()

        assert read.source == Query(key=Key("q"))
        assert read.access_pattern is AccessPattern.ATTRIBUTE
        assert read.cardinality is Cardinality.SINGLE
        assert read.function.fqn == "app.search"

    def test_header_default_produces_header_read(self) -> None:
        """Parameter with Header(...) default → InputRead(source=Header)."""
        idx = _make_index(
            functions=(
                _function(
                    "app.with_header",
                    params=(_param("x_token", default="Header(...)", position=0, line=21),),
                ),
            ),
            decorators=(
                _decorator(
                    "app.get",
                    target_fqn="app.with_header",
                    args=('"/with_header"',),
                    line=19,
                ),
            ),
            symbols=(
                _symbol("FastAPI", "fastapi.applications.FastAPI", line=1),
                _symbol("Header", "fastapi.param_functions.Header", line=1),
                _symbol("app.get", "app.app.get", line=19),
            ),
            value_flow_edges=(_vf("FastAPI()", "app", containing_function_fqn=None, line=2),),
        )

        repo = WebApp.from_index(idx).repo_view()
        route = repo.routes.one()
        read = route.body.reads(Header()).one()

        assert read.source == Header(name=Key("x_token"))
        assert read.access_pattern is AccessPattern.ATTRIBUTE
        assert read.cardinality is Cardinality.SINGLE
        assert read.function.fqn == "app.with_header"

    def test_cookie_default_produces_cookie_read(self) -> None:
        """Parameter with Cookie(None) default → InputRead(source=Cookie)."""
        idx = _make_index(
            functions=(
                _function(
                    "app.with_cookie",
                    params=(_param("session_id", default="Cookie(None)", position=0, line=21),),
                ),
            ),
            decorators=(
                _decorator(
                    "app.get",
                    target_fqn="app.with_cookie",
                    args=('"/with_cookie"',),
                    line=19,
                ),
            ),
            symbols=(
                _symbol("FastAPI", "fastapi.applications.FastAPI", line=1),
                _symbol("Cookie", "fastapi.param_functions.Cookie", line=1),
                _symbol("app.get", "app.app.get", line=19),
            ),
            value_flow_edges=(_vf("FastAPI()", "app", containing_function_fqn=None, line=2),),
        )

        repo = WebApp.from_index(idx).repo_view()
        route = repo.routes.one()
        read = route.body.reads(Cookie()).one()

        assert read.source == Cookie(name=Key("session_id"))
        assert read.access_pattern is AccessPattern.ATTRIBUTE
        assert read.cardinality is Cardinality.SINGLE
        assert read.function.fqn == "app.with_cookie"

    def test_body_default_produces_json_read(self) -> None:
        """Parameter with Body(...) default → InputRead(source=Json)."""
        idx = _make_index(
            functions=(
                _function(
                    "app.create_item",
                    params=(_param("payload", default="Body(...)", position=0, line=21),),
                ),
            ),
            decorators=(
                _decorator(
                    "app.post",
                    target_fqn="app.create_item",
                    args=('"/items"',),
                    line=19,
                ),
            ),
            symbols=(
                _symbol("FastAPI", "fastapi.applications.FastAPI", line=1),
                _symbol("Body", "fastapi.param_functions.Body", line=1),
                _symbol("app.post", "app.app.post", line=19),
            ),
            value_flow_edges=(_vf("FastAPI()", "app", containing_function_fqn=None, line=2),),
        )

        repo = WebApp.from_index(idx).repo_view()
        route = repo.routes.one()
        read = route.body.reads(Json()).one()

        assert read.source == Json(path=JsonPath("$.payload"))
        assert read.access_pattern is AccessPattern.ATTRIBUTE
        assert read.cardinality is Cardinality.SINGLE
        assert read.function.fqn == "app.create_item"

    def test_multiple_query_params_produce_multiple_reads(self) -> None:
        """Multiple Query() params on the same function each produce a read."""
        idx = _make_index(
            functions=(
                _function(
                    "app.search",
                    params=(
                        _param("q", default="Query(None)", position=0, line=21),
                        _param("limit", default="Query(10)", position=1, line=22),
                        _param("offset", default="Query(0)", position=2, line=23),
                    ),
                ),
            ),
            decorators=(
                _decorator(
                    "app.get",
                    target_fqn="app.search",
                    args=('"/search"',),
                    line=19,
                ),
            ),
            symbols=(
                _symbol("FastAPI", "fastapi.applications.FastAPI", line=1),
                _symbol("Query", "fastapi.param_functions.Query", line=1),
                _symbol("app.get", "app.app.get", line=19),
            ),
            value_flow_edges=(_vf("FastAPI()", "app", containing_function_fqn=None, line=2),),
        )

        repo = WebApp.from_index(idx).repo_view()
        route = repo.routes.one()
        reads = tuple(route.body.reads(Query()))

        assert len(reads) == 3
        keys = {cast("Query", read.source).key for read in reads}
        assert keys == {Key("q"), Key("limit"), Key("offset")}
        assert all(read.cardinality is Cardinality.SINGLE for read in reads)

    def test_alias_key_strategy_uses_literal_alias_kwarg(self) -> None:
        """key_from=alias derives the key from the default constructor kwarg."""
        idx = _make_index(
            functions=(
                _function(
                    "app.search",
                    params=(
                        _param(
                            "q",
                            default='ParamAlias(None, alias="external_q")',
                            position=0,
                            line=21,
                        ),
                    ),
                ),
            ),
            decorators=(
                _decorator(
                    "app.get",
                    target_fqn="app.search",
                    args=('"/search"',),
                    line=19,
                ),
            ),
            imports=_custom_imports(),
            symbols=(
                _symbol("App", "custom.App", line=1),
                _symbol("ParamAlias", "custom.ParamAlias", line=1),
                _symbol("app.get", "app.app.get", line=19),
            ),
            value_flow_edges=(_vf("App()", "app", containing_function_fqn=None, line=2),),
        )

        repo = WebApp.from_index(
            idx,
            provider_engine=ProviderEngine(providers=(CustomParameterProvider,)),
        ).repo_view()
        read = repo.routes.one().body.reads(Query()).one()

        assert read.source == Query(key=Key("external_q"))

    def test_first_arg_key_strategy_uses_literal_positional_arg(self) -> None:
        """key_from=first_arg derives the key from the first constructor arg."""
        idx = _make_index(
            functions=(
                _function(
                    "app.with_header",
                    params=(
                        _param(
                            "token",
                            default='ParamFirst("X-Token")',
                            position=0,
                            line=21,
                        ),
                    ),
                ),
            ),
            decorators=(
                _decorator(
                    "app.get",
                    target_fqn="app.with_header",
                    args=('"/headers"',),
                    line=19,
                ),
            ),
            imports=_custom_imports(),
            symbols=(
                _symbol("App", "custom.App", line=1),
                _symbol("ParamFirst", "custom.ParamFirst", line=1),
                _symbol("app.get", "app.app.get", line=19),
            ),
            value_flow_edges=(_vf("App()", "app", containing_function_fqn=None, line=2),),
        )

        repo = WebApp.from_index(
            idx,
            provider_engine=ProviderEngine(providers=(CustomParameterProvider,)),
        ).repo_view()
        read = repo.routes.one().body.reads(Header()).one()

        assert read.source == Header(name=Key("X-Token"))

    def test_dynamic_alias_records_gap_and_uses_wildcard_source(self) -> None:
        """Dynamic alias expressions preserve the input read and report a gap."""
        idx = _make_index(
            functions=(
                _function(
                    "app.search",
                    params=(
                        _param(
                            "q",
                            default="ParamAlias(None, alias=alias_name)",
                            position=0,
                            line=21,
                        ),
                    ),
                ),
            ),
            imports=_custom_imports(),
            symbols=(_symbol("ParamAlias", "custom.ParamAlias", line=1),),
        )
        engine_result = ProviderEngine(providers=(CustomParameterProvider,)).run(idx)
        match = next(match for match in engine_result.matches if match.phase.value == "inputs")
        functions_by_fqn = {function.fqn: convert_function(function) for function in idx.functions}

        result = convert_input_match(match, idx, functions_by_fqn)

        assert len(result.reads) == 1
        assert result.reads[0].source == Query()
        assert len(result.gaps) == 1
        assert result.gaps[0].affected_function == "app.search"

    def test_no_default_does_not_produce_read(self) -> None:
        """Parameter without default → no InputRead produced."""
        idx = _make_index(
            functions=(
                _function(
                    "app.handler",
                    params=(_param("item_id", default=None, position=0, line=21),),
                ),
            ),
            decorators=(
                _decorator(
                    "app.get",
                    target_fqn="app.handler",
                    args=('"/items"',),
                    line=19,
                ),
            ),
            symbols=(
                _symbol("FastAPI", "fastapi.applications.FastAPI", line=1),
                _symbol("Query", "fastapi.param_functions.Query", line=1),
                _symbol("app.get", "app.app.get", line=19),
            ),
            value_flow_edges=(_vf("FastAPI()", "app", containing_function_fqn=None, line=2),),
        )

        repo = WebApp.from_index(idx).repo_view()
        route = repo.routes.one()
        reads = tuple(route.body.reads(Query()))

        assert len(reads) == 0

    def test_plain_default_does_not_produce_read(self) -> None:
        """Parameter with plain default (not a call) → no InputRead."""
        idx = _make_index(
            functions=(
                _function(
                    "app.handler",
                    params=(_param("limit", default="10", position=0, line=21),),
                ),
            ),
            decorators=(
                _decorator(
                    "app.get",
                    target_fqn="app.handler",
                    args=('"/items"',),
                    line=19,
                ),
            ),
            symbols=(
                _symbol("FastAPI", "fastapi.applications.FastAPI", line=1),
                _symbol("Query", "fastapi.param_functions.Query", line=1),
                _symbol("app.get", "app.app.get", line=19),
            ),
            value_flow_edges=(_vf("FastAPI()", "app", containing_function_fqn=None, line=2),),
        )

        repo = WebApp.from_index(idx).repo_view()
        route = repo.routes.one()
        reads = tuple(route.body.reads(Query()))

        assert len(reads) == 0

    def test_unresolved_call_default_does_not_match(self) -> None:
        """Parameter with unknown function call default → no match."""
        idx = _make_index(
            functions=(
                _function(
                    "app.handler",
                    params=(_param("x", default="unknown_func(42)", position=0, line=21),),
                ),
            ),
            decorators=(
                _decorator(
                    "app.get",
                    target_fqn="app.handler",
                    args=('"/items"',),
                    line=19,
                ),
            ),
            symbols=(
                _symbol("FastAPI", "fastapi.applications.FastAPI", line=1),
                _symbol("Query", "fastapi.param_functions.Query", line=1),
                _symbol("app.get", "app.app.get", line=19),
            ),
            value_flow_edges=(_vf("FastAPI()", "app", containing_function_fqn=None, line=2),),
        )

        repo = WebApp.from_index(idx).repo_view()
        route = repo.routes.one()
        reads = tuple(route.body.reads(Query()))

        assert len(reads) == 0
