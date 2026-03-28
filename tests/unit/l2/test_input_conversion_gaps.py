"""No-fail-open coverage for provider input conversion gaps."""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar, cast

from flawed._index import CodeIndex
from flawed._index._types import (
    AccessKind,
    AttributeAccess,
    CallEdge,
    DecoratorFact,
    EdgeSource,
    ExtractionProvenance,
    FunctionRecord,
    ImportFact,
    ResolutionStatus,
    SourceSpan,
    SymbolRef,
)
from flawed._index._types import FunctionKind as L1FunctionKind
from flawed._index._types import (
    Parameter as L1Parameter,
)
from flawed._index._types import (
    ParameterKind as L1ParameterKind,
)
from flawed._semantic import WebApp
from flawed._semantic._conversion import convert_function
from flawed._semantic._input_conversion import convert_input_match, path_param_reads_for_route
from flawed._semantic._provider_engine import (
    ParameterFact,
    ProviderEngine,
    ProviderMatch,
    ProviderPhase,
)
from flawed._semantic._scope import ConcreteCodeScope
from flawed._semantic.providers import (
    EffectCallPattern,
    InputAttributePattern,
    InputFieldAccessPattern,
    InputMethodPattern,
    InputParameterPattern,
    Provider,
    ProviderMeta,
    RouteDecorator,
)
from flawed.core import AnalysisGap, GapKind, Key, Location, Provenance
from flawed.inputs import AccessPattern, Cardinality, InputRead, InputValueType, PathParam, Query
from flawed.route import HttpMethod, Route
from flawed.sinks import TaintSink

_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="")
_ROOT = Path("/tmp/test-repo")


class _InputGapProvider(Provider):
    meta = ProviderMeta(
        id="input-gap",
        name="Input Gap",
        version="0.1.0",
        library="input_gap",
        library_fqn="input_gap",
    )

    fqn_aliases: ClassVar[dict[str, str]] = {"input_gap.local": "input_gap"}
    routes = (RouteDecorator(fqn="input_gap.App.get"),)
    inputs = (
        InputParameterPattern(
            default_type_fqn="input_gap.Param",
            source_type="Query",
            key_from="alias",
        ),
    )


def test_unsupported_input_descriptor_records_actionable_gap() -> None:
    result = convert_input_match(
        _input_match(cast("Any", EffectCallPattern(fqn="input_gap.read", category="DB_READ"))),
        _make_index(functions=(_function("app.handler"),)),
        {"app.handler": convert_function(_function("app.handler"))},
    )

    assert result.reads == ()
    _assert_gap(
        result.gaps,
        source_error="input_conversion: unsupported descriptor",
        message="Unsupported input descriptor: EffectCallPattern",
    )


def test_unknown_attribute_source_type_records_actionable_gap() -> None:
    fact = _attribute("request", "args")
    result = convert_input_match(
        _input_match(
            InputAttributePattern(
                receiver_fqn="input_gap.Request",
                attribute="args",
                source_type="NotAnInputSource",
            ),
            source_fact=fact,
        ),
        _make_index(functions=(_function("app.handler"),), attributes=(fact,)),
        {"app.handler": convert_function(_function("app.handler"))},
    )

    assert result.reads == ()
    _assert_gap(
        result.gaps,
        source_error="input_conversion: unknown source type",
        message="Unknown input source type: NotAnInputSource",
    )


def test_unknown_method_source_type_records_actionable_gap() -> None:
    result = convert_input_match(
        _input_match(
            InputMethodPattern(
                fqn="input_gap.Request.json",
                source_type="NotAnInputSource",
            )
        ),
        _make_index(functions=(_function("app.handler"),)),
        {"app.handler": convert_function(_function("app.handler"))},
    )

    assert result.reads == ()
    _assert_gap(
        result.gaps,
        source_error="input_conversion: unknown source type",
        message="Unknown input source type: NotAnInputSource",
    )


def test_unknown_field_access_source_type_records_actionable_gap() -> None:
    result = convert_input_match(
        _input_match(
            InputFieldAccessPattern(
                base_class_fqn="input_gap.Form",
                field_attribute="data",
                source_type="NotAnInputSource",
            ),
            source_fact=_attribute("form.username", "data"),
        ),
        _make_index(functions=(_function("app.handler"),)),
        {"app.handler": convert_function(_function("app.handler"))},
    )

    assert result.reads == ()
    _assert_gap(
        result.gaps,
        source_error="input_conversion: unknown source type",
        message="Unknown input source type: NotAnInputSource",
    )


def test_unknown_parameter_source_type_records_actionable_gap() -> None:
    result = convert_input_match(
        _input_match(
            InputParameterPattern(
                default_type_fqn="input_gap.Param",
                source_type="NotAnInputSource",
            ),
            source_fact=_parameter_fact(_param("q", default="Param()")),
        ),
        _make_index(functions=(_function("app.handler"),)),
        {"app.handler": convert_function(_function("app.handler"))},
    )

    assert result.reads == ()
    _assert_gap(
        result.gaps,
        source_error="input_conversion: unknown source type",
        message="Unknown input source type: NotAnInputSource",
    )


def test_unsupported_parameter_key_strategy_preserves_read_and_records_gap() -> None:
    result = convert_input_match(
        _input_match(
            InputParameterPattern(
                default_type_fqn="input_gap.Param",
                source_type="Query",
                key_from="unsupported",
            ),
            source_fact=_parameter_fact(_param("q", default="Param()")),
        ),
        _make_index(functions=(_function("app.handler"),)),
        {"app.handler": convert_function(_function("app.handler"))},
    )

    assert len(result.reads) == 1
    assert result.reads[0].source == Query(key=Key("q"))
    _assert_gap(
        result.gaps,
        source_error="input_conversion: unsupported parameter key strategy",
        message="Unsupported input parameter key strategy: unsupported",
    )


def test_dynamic_parameter_alias_preserves_wildcard_read_and_records_gap() -> None:
    result = convert_input_match(
        _input_match(
            InputParameterPattern(
                default_type_fqn="input_gap.Param",
                source_type="Query",
                key_from="alias",
            ),
            source_fact=_parameter_fact(_param("q", default="Param(alias=alias_name)")),
        ),
        _make_index(functions=(_function("app.handler"),)),
        {"app.handler": convert_function(_function("app.handler"))},
    )

    assert len(result.reads) == 1
    assert result.reads[0].source == Query()
    _assert_gap(
        result.gaps,
        kind=GapKind.INFERENCE_FAILURE,
        source_error="input_conversion: non-literal parameter key",
        message="Could not derive input key from alias for parameter app.handler.q",
    )


def test_parameter_key_gap_survives_unknown_source_type() -> None:
    result = convert_input_match(
        _input_match(
            InputParameterPattern(
                default_type_fqn="input_gap.Param",
                source_type="NotAnInputSource",
                key_from="alias",
            ),
            source_fact=_parameter_fact(_param("q", default="Param(alias=alias_name)")),
        ),
        _make_index(functions=(_function("app.handler"),)),
        {"app.handler": convert_function(_function("app.handler"))},
    )

    assert result.reads == ()
    assert {gap.source_error for gap in result.gaps} == {
        "input_conversion: non-literal parameter key",
        "input_conversion: unknown source type",
    }


def test_invalid_input_cardinality_preserves_read_and_records_gap() -> None:
    result = convert_input_match(
        _input_match(
            InputMethodPattern(
                fqn="input_gap.Request.args",
                source_type="Query",
                cardinality="MANY",
            )
        ),
        _make_index(functions=(_function("app.handler"),)),
        {"app.handler": convert_function(_function("app.handler"))},
    )

    assert len(result.reads) == 1
    assert result.reads[0].cardinality is Cardinality.SINGLE
    _assert_gap(
        result.gaps,
        source_error="input_conversion: unknown cardinality",
        message="Unknown input cardinality: MANY",
    )


def test_missing_input_method_function_records_actionable_gap() -> None:
    result = convert_input_match(
        _input_match(InputMethodPattern(fqn="input_gap.Request.args", source_type="Query")),
        _make_index(functions=()),
        {},
    )

    assert result.reads == ()
    _assert_gap(
        result.gaps,
        source_error="input_conversion: missing function",
        message="No converted Function found for app.handler",
    )


def test_missing_route_handler_record_records_actionable_gap() -> None:
    handler_record = _function(
        "app.handler",
        params=(_route_param("item_id"),),
    )

    result = path_param_reads_for_route(
        _route("/items/<int:item_id>", handler_record),
        {},
    )

    assert result.reads == ()
    _assert_gap(
        result.gaps,
        source_error="input_conversion: missing route handler record",
        message="No L1 handler record found for route /items/<int:item_id>",
    )


def test_input_conversion_gap_reaches_repo_route_and_function_scopes() -> None:
    repo = WebApp.from_index(
        _index_with_dynamic_alias_parameter(),
        provider_engine=ProviderEngine(providers=(_InputGapProvider,)),
    ).repo_view()

    route = repo.routes.one()
    handler = repo.functions.named("handler").one()
    read = route.body.reads(Query()).one()
    gap = _assert_gap(
        repo.gaps,
        kind=GapKind.INFERENCE_FAILURE,
        source_error="input_conversion: non-literal parameter key",
        message="Could not derive input key from alias for parameter app.handler.q",
    )

    assert read.source == Query()
    assert gap in route.body.gaps
    assert gap in route.full_stack.gaps
    assert gap in route.gaps
    assert gap in handler.reachable.gaps


def test_route_int_converter_sets_generic_integer_input_type() -> None:
    handler_record = _function(
        "app.handler",
        params=(_route_param("item_id"),),
    )

    result = path_param_reads_for_route(
        _route("/items/<int:item_id>", handler_record),
        {handler_record.fqn: handler_record},
    )

    assert result.gaps == ()
    assert len(result.reads) == 1
    assert result.reads[0].source == PathParam(name=Key("item_id"))
    assert result.reads[0].value_type is InputValueType.INTEGER


def test_unknown_route_converter_records_gap_without_dropping_read() -> None:
    handler_record = _function(
        "app.handler",
        params=(_route_param("item_id"),),
    )

    result = path_param_reads_for_route(
        _route("/items/<slug:item_id>", handler_record),
        {handler_record.fqn: handler_record},
    )

    assert len(result.reads) == 1
    assert result.reads[0].source == PathParam(name=Key("item_id"))
    assert result.reads[0].value_type is None
    _assert_gap(
        result.gaps,
        source_error="input_conversion: unknown route parameter converter",
        message="Unknown route parameter converter 'slug'",
        kind=GapKind.INFERENCE_FAILURE,
    )


def test_route_converter_gap_reaches_repo_route_and_scopes() -> None:
    repo = WebApp.from_index(
        _index_with_unknown_route_converter(),
        provider_engine=ProviderEngine(providers=(_InputGapProvider,)),
    ).repo_view()

    route = repo.routes.one()
    read = route.body.reads(PathParam()).one()
    gap = _assert_gap(
        tuple(
            gap
            for gap in repo.gaps
            if gap.source_error == "input_conversion: unknown route parameter converter"
        ),
        source_error="input_conversion: unknown route parameter converter",
        message="Unknown route parameter converter 'slug'",
        kind=GapKind.INFERENCE_FAILURE,
    )

    assert read.source == PathParam(name=Key("item_id"))
    assert read.value_type is None
    assert gap in route.body.gaps
    assert gap in route.full_stack.gaps
    assert gap in route.gaps


def test_predicate_validated_string_sink_ignores_non_string_constrained_reads() -> None:
    handler = convert_function(_function("app.handler"))
    read = _input_read(handler, value_type=InputValueType.INTEGER)
    sink = _taint_sink(handler)
    object.__setattr__(sink, "_predicate_validated", True)
    scope = ConcreteCodeScope(input_reads=(read,), sinks=(sink,))

    assert list(scope.sinks(kind="PATH_TRAVERSAL")) == []


def test_predicate_validated_string_sink_keeps_unconstrained_reads_conservative() -> None:
    handler = convert_function(_function("app.handler"))
    read = _input_read(handler, value_type=None)
    sink = _taint_sink(handler)
    object.__setattr__(sink, "_predicate_validated", True)
    scope = ConcreteCodeScope(input_reads=(read,), sinks=(sink,))

    assert list(scope.sinks(kind="PATH_TRAVERSAL")) == [sink]


def _assert_gap(
    gaps: tuple[AnalysisGap, ...],
    *,
    source_error: str,
    message: str,
    kind: GapKind = GapKind.INTERPRETER_ERROR,
) -> AnalysisGap:
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap.kind is kind
    assert gap.affected_file == "app.py"
    assert gap.affected_function == "app.handler"
    assert gap.source_error == source_error
    assert gap.origin_phase == "input_conversion"
    assert gap.origin_provider == "input-gap"
    assert message in gap.message
    return gap


def _input_match(descriptor: Any, *, source_fact: object | None = None) -> ProviderMatch:
    fact = source_fact or _call("input_gap.Request.args")
    return ProviderMatch(
        provider_id="input-gap",
        phase=ProviderPhase.INPUTS,
        descriptor=descriptor,
        source_fact=cast("Any", fact),
        observed_fqn="input_gap.Request.args",
        canonical_fqn="input_gap.Request.args",
        location=cast("Any", fact).location,
    )


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


def _param(name: str, *, default: str, line: int = 21) -> L1Parameter:
    return L1Parameter(
        name=name,
        annotation=None,
        default=default,
        kind=L1ParameterKind.KEYWORD_ONLY,
        position=0,
        location=_span(line),
    )


def _route_param(name: str, *, line: int = 21) -> L1Parameter:
    return L1Parameter(
        name=name,
        annotation=None,
        default=None,
        kind=L1ParameterKind.POSITIONAL_OR_KEYWORD,
        position=0,
        location=_span(line),
    )


def _route(url_rule: str, handler_record: FunctionRecord) -> Route:
    route = Route(
        endpoint=handler_record.name,
        url_rule=url_rule,
        methods=frozenset({HttpMethod.GET}),
        handler=convert_function(handler_record),
        group=None,
        location=Location(file="app.py", line=10, column=0),
        provenance=Provenance(source_layer="L2", interpreter="test", confidence=1.0),
    )
    object.__setattr__(route, "_provider_id", "input-gap")
    return route


def _input_read(
    handler: object,
    *,
    value_type: InputValueType | None,
) -> InputRead:
    return InputRead(
        source=PathParam(name=Key("item_id")),
        access_pattern=AccessPattern.UNKNOWN,
        cardinality=Cardinality.SINGLE,
        function=cast("Any", handler),
        location=Location(file="app.py", line=21, column=0),
        expression="item_id",
        provenance=Provenance(source_layer="L2", interpreter="test", confidence=1.0),
        value_type=value_type,
    )


def _taint_sink(handler: object) -> TaintSink:
    return TaintSink(
        kind="PATH_TRAVERSAL",
        function=cast("Any", handler),
        location=Location(file="app.py", line=22, column=0),
        expression="send_file(path)",
        argument_location=Location(file="app.py", line=22, column=10),
        argument_expression="path",
        provenance=Provenance(source_layer="L2", interpreter="test", confidence=1.0),
    )


def _parameter_fact(param: L1Parameter) -> ParameterFact:
    return ParameterFact(param=param, function_fqn="app.handler", location=param.location)


def _attribute(target_expr: str, attr_name: str, *, line: int = 21) -> AttributeAccess:
    return AttributeAccess(
        target_expr=target_expr,
        attr_name=attr_name,
        is_write=False,
        access_kind=AccessKind.ATTR,
        value_expr=None,
        containing_function_fqn="app.handler",
        location=_span(line),
        provenance=_PROV,
    )


def _call(callee_fqn: str, *, line: int = 21) -> CallEdge:
    return CallEdge(
        caller_fqn="app.handler",
        callee_fqn=callee_fqn,
        arguments=(),
        resolution=ResolutionStatus.RESOLVED,
        source=EdgeSource.AST,
        unresolved_reason=None,
        location=_span(line),
        provenance=_PROV,
        call_expression=f"{callee_fqn}()",
    )


def _decorator(url_rule: str = "/input") -> DecoratorFact:
    return DecoratorFact(
        name="get",
        fqn="input_gap.App.get",
        args=(repr(url_rule),),
        kwargs=(),
        target_fqn="app.handler",
        application_order=0,
        location=_span(10),
        provenance=_PROV,
    )


def _import() -> ImportFact:
    return ImportFact(
        module="input_gap",
        names=("App", "Param"),
        aliases=(),
        is_from_import=True,
        location=_span(1),
        provenance=_PROV,
    )


def _symbol(name: str, fqn: str, *, line: int = 1) -> SymbolRef:
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
    attributes: tuple[AttributeAccess, ...] = (),
    call_edges: tuple[CallEdge, ...] = (),
    decorators: tuple[DecoratorFact, ...] = (),
    imports: tuple[ImportFact, ...] = (),
    symbols: tuple[SymbolRef, ...] = (),
) -> CodeIndex:
    return CodeIndex(
        repo_root=_ROOT,
        functions=functions,
        classes=(),
        decorators=decorators,
        imports=imports,
        attributes=attributes,
        call_edges=call_edges,
        cfgs={},
        value_flow_edges=(),
        symbol_refs=symbols,
        errors=(),
        provenance=_PROV,
    )


def _index_with_dynamic_alias_parameter() -> CodeIndex:
    return _make_index(
        functions=(
            _function(
                "app.handler",
                params=(_param("q", default="Param(alias=alias_name)"),),
            ),
        ),
        decorators=(_decorator(),),
        imports=(_import(),),
        symbols=(
            _symbol("Param", "input_gap.Param"),
            _symbol("input_gap.App.get", "input_gap.App.get", line=10),
        ),
    )


def _index_with_unknown_route_converter() -> CodeIndex:
    return _make_index(
        functions=(
            _function(
                "app.handler",
                params=(_route_param("item_id"),),
            ),
        ),
        decorators=(_decorator("/items/<slug:item_id>"),),
        imports=(_import(),),
        symbols=(_symbol("input_gap.App.get", "input_gap.App.get", line=10),),
    )
