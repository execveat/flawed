"""Tests for generic FlowPropagatorPattern conversion."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, cast

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
    FunctionKind,
    FunctionRecord,
    ImportFact,
    ResolutionStatus,
    SourceSpan,
    SymbolRef,
    ValueFlowEdge,
)
from flawed._semantic import WebApp
from flawed._semantic._flow_propagation import convert_flow_propagator_matches
from flawed._semantic._provider_engine import (
    ProviderDescriptor,
    ProviderEngine,
    ProviderMatch,
    ProviderPhase,
)
from flawed._semantic._proxy_flow import convert_proxy_flow_matches
from flawed._semantic.providers import (
    EffectCallPattern,
    FlowPropagatorPattern,
    Provider,
    ProviderMeta,
)
from flawed._semantic.providers.flask_core import FlaskProvider
from flawed._semantic.providers.flask_login import FlaskLoginProvider
from flawed.core import GapKind
from flawed.effects import EffectCategory
from flawed.inputs import Query

_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="")
_SPAN = SourceSpan(file="app.py", line=10, column=4, end_line=10, end_column=28)
_ARG0 = SourceSpan(file="app.py", line=10, column=16, end_line=10, end_column=23)
_ARG1 = SourceSpan(file="app.py", line=10, column=25, end_line=10, end_column=31)
_ROOT = Path("/tmp/test-repo")
_DEFAULT_CALL_EXPRESSION = object()


class GenericFlowProvider(Provider):
    meta = ProviderMeta(
        id="generic",
        name="Generic",
        version="0.1.0",
        library="Generic",
        library_fqn="generic",
    )

    fqn_aliases: ClassVar[dict[str, str]] = {
        "generic.public_decode": "generic.decode",
    }
    propagators = (FlowPropagatorPattern(fqn="generic.decode", input_arg=0, output="return"),)


class MissingInputArgFlowProvider(Provider):
    meta = ProviderMeta(
        id="missing-arg",
        name="Missing Arg",
        version="0.1.0",
        library="Generic",
        library_fqn="generic",
    )

    propagators = (FlowPropagatorPattern(fqn="generic.decode", input_arg=1, output="return"),)


def test_provider_engine_matches_feed_flow_propagator_conversion() -> None:
    idx = _index(
        imports=(_import("generic"),),
        call_edges=(
            _call(
                "generic.public_decode",
                _arg(0, "payload", _ARG0),
                call_expression="public_decode(payload)",
            ),
        ),
    )

    engine_result = ProviderEngine(providers=(GenericFlowProvider,)).run(idx)
    result = convert_flow_propagator_matches(engine_result.matches)

    assert engine_result.active_provider_ids == ("generic",)
    assert len(result.propagators) == 1
    assert result.propagators[0].observed_fqn == "generic.public_decode"
    assert result.propagators[0].canonical_fqn == "generic.decode"
    assert result.propagators[0].source_expression == "payload"


def test_provider_engine_prefers_ast_call_match_over_argumentless_hierarchy_duplicate() -> None:
    idx = _index(
        imports=(_import("generic"),),
        call_edges=(
            _call(
                "generic.decode",
                source=EdgeSource.HIERARCHY,
                call_expression=None,
            ),
            _call(
                "generic.decode",
                _arg(0, "payload", _ARG0),
                source=EdgeSource.AST,
                call_expression="decode(payload)",
            ),
        ),
    )

    engine_result = ProviderEngine(providers=(GenericFlowProvider,)).run(idx)
    result = convert_flow_propagator_matches(engine_result.matches)

    assert len(engine_result.matches) == 1
    assert result.gaps == ()
    assert len(result.propagators) == 1
    assert result.propagators[0].source_expression == "payload"


def test_webapp_stores_converted_flow_propagators_for_tracer() -> None:
    idx = _index(
        imports=(_import("generic"),),
        call_edges=(
            _call(
                "generic.decode",
                _arg(0, "payload", _ARG0),
                call_expression="decode(payload)",
            ),
        ),
    )

    webapp = WebApp.from_index(
        idx,
        provider_engine=ProviderEngine(providers=(GenericFlowProvider,)),
    )
    repo = webapp.repo_view()

    propagators = repo._flow_propagators
    assert len(propagators) == 1
    assert propagators[0].source_expression == "payload"
    assert propagators[0].target_expression == "decode(payload)"


def test_provider_flow_propagator_enables_call_argument_to_return_flow() -> None:
    idx = _index(
        functions=(_function(),),
        imports=(_import("generic"),),
        call_edges=(
            _call(
                "generic.decode",
                _arg(0, "payload", _ARG0),
                call_expression="decode(payload)",
            ),
        ),
    )

    webapp = WebApp.from_index(
        idx,
        provider_engine=ProviderEngine(providers=(GenericFlowProvider,)),
    )
    repo = webapp.repo_view()
    fn = repo.functions.with_fqn("app.handler").one()
    call = fn.body.calls().one()

    assert call.arguments[0].value.flows_to(call.return_value)


def test_webapp_exposes_flow_propagator_conversion_gaps_on_repo_view() -> None:
    idx = _index(
        imports=(_import("generic"),),
        call_edges=(
            _call(
                "generic.decode",
                _arg(0, "payload", _ARG0),
                call_expression="decode(payload)",
            ),
        ),
    )

    webapp = WebApp.from_index(
        idx,
        provider_engine=ProviderEngine(providers=(MissingInputArgFlowProvider,)),
    )
    repo = webapp.repo_view()

    assert len(repo.gaps) == 1
    assert repo.gaps[0].kind == GapKind.VALUE_FLOW_INCOMPLETE
    assert "input arg 1" in repo.gaps[0].message


def test_proxy_flow_converter_resolves_backing_state_to_attribute_access() -> None:
    idx = _index(
        imports=(_import("flask_login"),),
        attributes=(_attribute("current_user", "id", line=30),),
        symbols=(_symbol("current_user", "flask_login.current_user", line=30),),
    )

    engine_result = ProviderEngine(providers=(FlaskLoginProvider,)).run(idx)
    result = convert_proxy_flow_matches(engine_result.matches)

    assert result.gaps == ()
    assert len(result.propagators) == 4
    expressions = {edge.source_expression for edge in result.propagators}
    assert "flask.g._login_user" in expressions
    assert "g._login_user" in expressions
    assert "flask.g._login_user.id" in expressions
    assert "g._login_user.id" in expressions
    assert {edge.target_expression for edge in result.propagators} == {"current_user.id"}


def test_proxy_flow_converter_resolves_bare_symbol_with_function_context() -> None:
    idx = _index(
        functions=(_function(),),
        imports=(_import("flask_login"),),
        symbols=(_symbol("current_user", "flask_login.current_user", line=5),),
    )

    engine_result = ProviderEngine(providers=(FlaskLoginProvider,)).run(idx)
    result = convert_proxy_flow_matches(engine_result.matches, idx=idx)

    assert result.gaps == ()
    assert len(result.propagators) == 2
    assert {edge.source_expression for edge in result.propagators} == {
        "flask.g._login_user",
        "g._login_user",
    }
    assert {edge.target_expression for edge in result.propagators} == {"current_user"}
    assert {edge.containing_function_fqn for edge in result.propagators} == {"app.handler"}


def test_proxy_flow_converter_records_gap_for_attribute_without_function_context() -> None:
    fact = _attribute("current_user", "id", line=30, containing_function_fqn=None)
    match = _proxy_match(fact)

    result = convert_proxy_flow_matches((match,))

    assert result.propagators == ()
    assert len(result.gaps) == 1
    gap = result.gaps[0]
    assert gap.kind == GapKind.VALUE_FLOW_INCOMPLETE
    assert gap.affected_file == "app.py"
    assert gap.affected_function is None
    assert gap.origin_phase == "proxy_flow_conversion"
    assert gap.origin_provider == "flask-login"
    assert "missing containing function context" in gap.message


def test_proxy_flow_converter_records_gap_for_bare_symbol_without_function_context() -> None:
    idx = _index(
        functions=(),
        imports=(_import("flask_login"),),
        symbols=(_symbol("current_user", "flask_login.current_user", line=5),),
    )

    engine_result = ProviderEngine(providers=(FlaskLoginProvider,)).run(idx)
    result = convert_proxy_flow_matches(engine_result.matches, idx=idx)

    assert result.propagators == ()
    assert len(result.gaps) == 1
    gap = result.gaps[0]
    assert gap.kind == GapKind.VALUE_FLOW_INCOMPLETE
    assert gap.affected_file == "app.py"
    assert gap.affected_function is None
    assert gap.origin_phase == "proxy_flow_conversion"
    assert "outside any known containing function" in gap.message


def test_proxy_flow_converter_records_gap_when_symbol_conversion_lacks_index() -> None:
    result = convert_proxy_flow_matches(
        (_proxy_match(_symbol("current_user", "flask_login.current_user", line=5)),)
    )

    assert result.propagators == ()
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == GapKind.VALUE_FLOW_INCOMPLETE
    assert "requires index context" in result.gaps[0].message


def test_webapp_exposes_proxy_flow_conversion_gaps_on_repo_view() -> None:
    idx = _index(
        functions=(),
        imports=(_import("flask_login"),),
        symbols=(_symbol("current_user", "flask_login.current_user", line=5),),
    )

    repo = WebApp.from_index(
        idx,
        provider_engine=ProviderEngine(providers=(FlaskLoginProvider,)),
    ).repo_view()

    assert len(repo.gaps) == 1
    assert repo.gaps[0].kind == GapKind.VALUE_FLOW_INCOMPLETE
    assert repo.gaps[0].origin_phase == "proxy_flow_conversion"
    assert repo.gaps[0].affected_file == "app.py"


def test_proxy_flow_connects_request_input_to_current_user_attribute() -> None:
    idx = _index(
        functions=(_function(),),
        imports=(_import("flask"), _import("flask_login")),
        decorators=(_decorator("app.route", target_fqn="app.handler", args=('"/proxy"',)),),
        attributes=(
            _attribute("request", "args", line=20),
            _attribute(
                "g",
                "_login_user",
                is_write=True,
                value_expr='request.args.get("name")',
                line=21,
            ),
            _attribute("current_user", "name", line=22),
        ),
        call_edges=(
            _call(
                "request.args.get",
                _arg(0, '"name"', _span(20)),
                call_expression='request.args.get("name")',
            ),
        ),
        value_flow_edges=(
            _vf(
                "Flask(__name__)",
                "app",
                source_line=2,
                target_line=2,
                containing_function_fqn=None,
            ),
            _vf(
                'request.args.get("name")',
                "g._login_user",
                source_line=20,
                target_line=21,
            ),
        ),
        symbols=(
            _symbol("Flask", "flask.Flask", line=1),
            _symbol("app.route", "app.app.route", line=10),
            _symbol("request", "flask.request", line=20),
            _symbol("g", "flask.g", line=21),
            _symbol("current_user", "flask_login.current_user", line=22),
        ),
    )

    route = WebApp.from_index(idx).repo_view().routes.one()
    read = route.body.reads(Query()).one()
    proxy_read = next(
        effect
        for effect in route.body.effects()
        if (
            effect.category is EffectCategory.STATE_READ
            and effect.expression == "current_user.name"
        )
    )

    assert proxy_read.target is not None
    assert read.value.flows_to(proxy_read.target)


def test_return_output_converts_input_argument_to_call_result() -> None:
    pattern = FlowPropagatorPattern(fqn="generic.decode", input_arg=0, output="return")
    match = _match(pattern, _call("generic.decode", _arg(0, "payload", _ARG0)))

    result = convert_flow_propagator_matches((match,))

    assert result.gaps == ()
    assert len(result.propagators) == 1
    edge = result.propagators[0]
    assert edge.source_expression == "payload"
    assert edge.source_location == _ARG0
    assert edge.target_expression == "generic.decode(payload)"
    assert edge.target_location == _SPAN
    assert edge.containing_function_fqn == "app.handler"


def test_keyword_input_converts_to_call_result() -> None:
    pattern = FlowPropagatorPattern(
        fqn="generic.url_for",
        input_arg=0,
        input_keyword="endpoint",
        output="return",
    )
    match = _match(
        pattern,
        _call(
            "generic.url_for",
            _kwarg("endpoint", "endpoint_name", _ARG0),
            call_expression="url_for(endpoint=endpoint_name)",
        ),
    )

    result = convert_flow_propagator_matches((match,))

    assert result.gaps == ()
    assert len(result.propagators) == 1
    assert result.propagators[0].source_expression == "endpoint_name"
    assert result.propagators[0].target_expression == "url_for(endpoint=endpoint_name)"


def test_keyword_input_falls_back_to_positional_argument() -> None:
    pattern = FlowPropagatorPattern(
        fqn="generic.url_for",
        input_arg=0,
        input_keyword="endpoint",
        output="return",
    )
    match = _match(
        pattern,
        _call(
            "generic.url_for",
            _arg(0, "endpoint_name", _ARG0),
            call_expression="url_for(endpoint_name)",
        ),
    )

    result = convert_flow_propagator_matches((match,))

    assert result.gaps == ()
    assert len(result.propagators) == 1
    assert result.propagators[0].source_expression == "endpoint_name"


def test_optional_missing_input_is_skipped_without_gap() -> None:
    pattern = FlowPropagatorPattern(
        fqn="generic.jsonify",
        input_arg=0,
        input_required=False,
        output="return",
    )
    match = _match(pattern, _call("generic.jsonify", call_expression="jsonify()"))

    result = convert_flow_propagator_matches((match,))

    assert result.propagators == ()
    assert result.gaps == ()


def test_receiver_output_converts_input_argument_to_method_receiver() -> None:
    pattern = FlowPropagatorPattern(
        fqn="generic.Builder.merge",
        input_arg=0,
        output="receiver",
    )
    match = _match(
        pattern,
        _call(
            "generic.Builder.merge",
            _arg(0, "payload", _ARG0),
            call_expression="builder.merge(payload)",
        ),
    )

    result = convert_flow_propagator_matches((match,))

    assert result.gaps == ()
    assert result.propagators[0].source_expression == "payload"
    assert result.propagators[0].target_expression == "builder"
    assert result.propagators[0].target_location == _SPAN


def test_arg_output_converts_input_argument_to_mutated_argument() -> None:
    pattern = FlowPropagatorPattern(fqn="generic.copy_into", input_arg=0, output="arg:1")
    match = _match(
        pattern,
        _call(
            "generic.copy_into",
            _arg(0, "payload", _ARG0),
            _arg(1, "target", _ARG1),
        ),
    )

    result = convert_flow_propagator_matches((match,))

    assert result.gaps == ()
    assert result.propagators[0].source_expression == "payload"
    assert result.propagators[0].target_expression == "target"
    assert result.propagators[0].target_location == _ARG1


def test_keyword_output_converts_input_argument_to_mutated_keyword_argument() -> None:
    pattern = FlowPropagatorPattern(fqn="generic.copy_into", input_arg=0, output="kwarg:target")
    match = _match(
        pattern,
        _call(
            "generic.copy_into",
            _arg(0, "payload", _ARG0),
            _kwarg("target", "target_buffer", _ARG1),
        ),
    )

    result = convert_flow_propagator_matches((match,))

    assert result.gaps == ()
    assert result.propagators[0].source_expression == "payload"
    assert result.propagators[0].target_expression == "target_buffer"
    assert result.propagators[0].target_location == _ARG1


def test_variadic_input_converts_each_call_argument_to_return_flow() -> None:
    pattern = FlowPropagatorPattern(
        fqn="generic.join",
        input_arg=None,
        input_variadic=True,
        output="return",
    )
    match = _match(
        pattern,
        _call(
            "generic.join",
            _arg(0, "left", _ARG0),
            _kwarg("right", "right", _ARG1),
            call_expression="join(left, right=right)",
        ),
    )

    result = convert_flow_propagator_matches((match,))

    assert result.gaps == ()
    assert [edge.source_expression for edge in result.propagators] == ["left", "right"]
    assert {edge.target_expression for edge in result.propagators} == {"join(left, right=right)"}


def test_variadic_input_can_exclude_signature_arguments() -> None:
    pattern = FlowPropagatorPattern(
        fqn="generic.render_template",
        input_arg=None,
        input_variadic=True,
        excluded_input_args=(0,),
        excluded_input_keywords=("template_name",),
        input_required=False,
        output="return",
    )
    match = _match(
        pattern,
        _call(
            "generic.render_template",
            _arg(0, '"page.html"', _ARG0),
            _kwarg("context", "payload", _ARG1),
            call_expression='render_template("page.html", context=payload)',
        ),
    )

    result = convert_flow_propagator_matches((match,))

    assert result.gaps == ()
    assert [edge.source_expression for edge in result.propagators] == ["payload"]


def test_missing_input_argument_records_value_flow_gap() -> None:
    pattern = FlowPropagatorPattern(fqn="generic.decode", input_arg=1, output="return")
    match = _match(pattern, _call("generic.decode", _arg(0, "payload", _ARG0)))

    result = convert_flow_propagator_matches((match,))

    assert result.propagators == ()
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == GapKind.VALUE_FLOW_INCOMPLETE
    assert result.gaps[0].affected_file == "app.py"
    assert result.gaps[0].affected_function == "app.handler"
    assert "input arg 1" in result.gaps[0].message
    assert result.gaps[0].source_error == (
        "flow_propagator_conversion: propagator input arg 1 is missing"
    )


def test_missing_keyword_input_records_named_value_flow_gap() -> None:
    pattern = FlowPropagatorPattern(
        fqn="generic.url_for",
        input_arg=0,
        input_keyword="endpoint",
        output="return",
    )
    match = _match(pattern, _call("generic.url_for", _kwarg("anchor", "section", _ARG0)))

    result = convert_flow_propagator_matches((match,))

    assert result.propagators == ()
    assert len(result.gaps) == 1
    assert "input arg 'endpoint'/position 0 is missing" in result.gaps[0].message
    assert (
        result.gaps[0].source_error
        == "flow_propagator_conversion: propagator input arg 'endpoint'/position 0 is missing"
    )


def test_flask_url_for_keyword_endpoint_converts_to_return_flow() -> None:
    idx = _index(
        imports=(_import("flask"),),
        call_edges=(
            _call(
                "flask.url_for",
                _kwarg("endpoint", "endpoint_name", _ARG0),
                call_expression="url_for(endpoint=endpoint_name)",
            ),
        ),
    )

    engine_result = ProviderEngine(providers=(FlaskProvider,)).run(idx)
    result = convert_flow_propagator_matches(engine_result.matches)

    assert result.gaps == ()
    assert len(result.propagators) == 1
    assert result.propagators[0].canonical_fqn == "flask.helpers.url_for"
    assert result.propagators[0].source_expression == "endpoint_name"


def test_flask_jsonify_without_args_is_ignored_without_conversion_gap() -> None:
    idx = _index(
        imports=(_import("flask"),),
        call_edges=(
            _call(
                "flask.jsonify",
                call_expression="jsonify()",
            ),
        ),
    )

    engine_result = ProviderEngine(providers=(FlaskProvider,)).run(idx)
    result = convert_flow_propagator_matches(engine_result.matches)

    assert any(match.canonical_fqn == "flask.json.jsonify" for match in engine_result.matches)
    assert result.propagators == ()
    assert result.gaps == ()


def test_flask_jsonify_keyword_argument_converts_to_return_flow() -> None:
    idx = _index(
        imports=(_import("flask"),),
        call_edges=(
            _call(
                "flask.jsonify",
                _kwarg("message", "message", _ARG0),
                call_expression="jsonify(message=message)",
            ),
        ),
    )

    engine_result = ProviderEngine(providers=(FlaskProvider,)).run(idx)
    result = convert_flow_propagator_matches(engine_result.matches)

    assert result.gaps == ()
    assert len(result.propagators) == 1
    assert result.propagators[0].canonical_fqn == "flask.json.jsonify"
    assert result.propagators[0].source_expression == "message"


def test_flask_render_template_keyword_context_converts_without_template_name_source() -> None:
    idx = _index(
        imports=(_import("flask"),),
        call_edges=(
            _call(
                "flask.render_template",
                _kwarg("template_name", '"page.html"', _ARG0),
                _kwarg("content", "content", _ARG1),
                call_expression='render_template(template_name="page.html", content=content)',
            ),
        ),
    )

    engine_result = ProviderEngine(providers=(FlaskProvider,)).run(idx)
    result = convert_flow_propagator_matches(engine_result.matches)

    assert result.gaps == ()
    assert len(result.propagators) == 1
    assert result.propagators[0].canonical_fqn == "flask.templating.render_template"
    assert result.propagators[0].source_expression == "content"


def test_receiver_output_without_receiver_records_value_flow_gap() -> None:
    pattern = FlowPropagatorPattern(fqn="generic.decode", input_arg=0, output="receiver")
    match = _match(
        pattern,
        _call(
            "generic.decode",
            _arg(0, "payload", _ARG0),
            call_expression="decode(payload)",
        ),
    )

    result = convert_flow_propagator_matches((match,))

    assert result.propagators == ()
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == GapKind.VALUE_FLOW_INCOMPLETE
    assert "receiver" in result.gaps[0].message


def test_unsupported_output_value_records_value_flow_gap() -> None:
    pattern = FlowPropagatorPattern(fqn="generic.decode", input_arg=0, output="body")
    match = _match(pattern, _call("generic.decode", _arg(0, "payload", _ARG0)))

    result = convert_flow_propagator_matches((match,))

    assert result.propagators == ()
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == GapKind.VALUE_FLOW_INCOMPLETE
    assert "unsupported propagator output 'body'" in result.gaps[0].message


def test_non_flow_propagator_descriptor_records_value_flow_gap() -> None:
    descriptor = EffectCallPattern(fqn="generic.decode", category="NETWORK")
    match = _match(descriptor, _call("generic.decode", _arg(0, "payload", _ARG0)))

    result = convert_flow_propagator_matches((match,))

    assert result.propagators == ()
    assert len(result.gaps) == 1
    assert result.gaps[0].kind == GapKind.VALUE_FLOW_INCOMPLETE
    assert "FlowPropagatorPattern" in result.gaps[0].message


def _match(pattern: object, edge: CallEdge) -> ProviderMatch:
    return ProviderMatch(
        provider_id="generic",
        phase=ProviderPhase.PROPAGATORS,
        descriptor=cast("ProviderDescriptor", pattern),
        source_fact=edge,
        observed_fqn=edge.callee_fqn or "",
        canonical_fqn="generic.canonical",
        location=edge.location,
    )


def _proxy_match(fact: AttributeAccess | SymbolRef) -> ProviderMatch:
    return ProviderMatch(
        provider_id="flask-login",
        phase=ProviderPhase.PROXIES,
        descriptor=FlaskLoginProvider.proxies[0],
        source_fact=fact,
        observed_fqn="flask_login.current_user",
        canonical_fqn="flask_login.current_user",
        location=fact.location,
    )


def _index(
    *,
    functions: tuple[FunctionRecord, ...] = (),
    decorators: tuple[DecoratorFact, ...] = (),
    imports: tuple[ImportFact, ...] = (),
    attributes: tuple[AttributeAccess, ...] = (),
    call_edges: tuple[CallEdge, ...] = (),
    value_flow_edges: tuple[ValueFlowEdge, ...] = (),
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
        value_flow_edges=value_flow_edges,
        symbol_refs=symbols,
        errors=(),
        provenance=_PROV,
    )


def _import(module: str) -> ImportFact:
    return ImportFact(
        module=module,
        names=(),
        aliases=(),
        is_from_import=False,
        location=_SPAN,
        provenance=_PROV,
    )


def _decorator(
    name: str,
    *,
    target_fqn: str,
    args: tuple[str, ...] = (),
    line: int = 10,
) -> DecoratorFact:
    return DecoratorFact(
        name=name,
        fqn=name,
        args=args,
        kwargs=(),
        target_fqn=target_fqn,
        application_order=0,
        location=_span(line),
        provenance=_PROV,
    )


def _attribute(
    target_expr: str,
    attr_name: str,
    *,
    is_write: bool = False,
    value_expr: str | None = None,
    line: int = 20,
    containing_function_fqn: str | None = "app.handler",
) -> AttributeAccess:
    return AttributeAccess(
        target_expr=target_expr,
        attr_name=attr_name,
        is_write=is_write,
        access_kind=AccessKind.ATTR,
        value_expr=value_expr,
        containing_function_fqn=containing_function_fqn,
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


def _call(
    fqn: str,
    *args: CallArgument,
    call_expression: str | None | object = _DEFAULT_CALL_EXPRESSION,
    source: EdgeSource = EdgeSource.AST,
) -> CallEdge:
    if call_expression is _DEFAULT_CALL_EXPRESSION:
        expression: str | None = f"{fqn}({', '.join(a.expression for a in args)})"
    else:
        expression = cast("str | None", call_expression)
    return CallEdge(
        caller_fqn="app.handler",
        callee_fqn=fqn,
        arguments=args,
        resolution=ResolutionStatus.RESOLVED,
        source=source,
        unresolved_reason=None,
        location=_SPAN,
        provenance=_PROV,
        call_expression=expression,
    )


def _vf(
    source: str,
    target: str,
    *,
    source_line: int,
    target_line: int,
    containing_function_fqn: str | None = "app.handler",
) -> ValueFlowEdge:
    return ValueFlowEdge(
        source_expr=source,
        source_location=_span(source_line),
        target_expr=target,
        target_location=_span(target_line),
        kind=FlowKind.ASSIGN,
        containing_function_fqn=containing_function_fqn,
        provenance=_PROV,
    )


def _arg(position: int, expression: str, location: SourceSpan) -> CallArgument:
    return CallArgument(
        position=position,
        keyword=None,
        expression=expression,
        location=location,
    )


def _kwarg(keyword: str, expression: str, location: SourceSpan) -> CallArgument:
    return CallArgument(
        position=None,
        keyword=keyword,
        expression=expression,
        location=location,
    )


def _span(line: int) -> SourceSpan:
    return SourceSpan(file="app.py", line=line, column=0, end_line=line, end_column=20)


def _function() -> FunctionRecord:
    return FunctionRecord(
        fqn="app.handler",
        name="handler",
        file="app.py",
        line=1,
        params=(),
        decorator_names=(),
        decorator_fqns=(),
        kind=FunctionKind.TOP_LEVEL,
        is_method=False,
        is_nested=False,
        is_async=False,
        parent_class=None,
        location=SourceSpan(file="app.py", line=1, column=0, end_line=11, end_column=0),
        provenance=_PROV,
    )
