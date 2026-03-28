"""Tests for Layer 1 data types in flawed._index._types.

Verifies:
- All types are constructable with valid args
- All dataclasses are frozen (reject attribute assignment)
- All enums have the expected members
"""

from __future__ import annotations

import dataclasses

import pytest

from flawed._index._types import (
    AccessKind,
    AliasFact,
    AliasMechanism,
    AssignmentFact,
    AssignmentKind,
    AttributeAccess,
    BranchCondition,
    CallArgument,
    CallEdge,
    CFGBlock,
    CFGEdge,
    CFGPath,
    ClassRecord,
    ComprehensionBindingFact,
    DecoratorFact,
    EdgeSource,
    ErrorKind,
    ExtractionError,
    ExtractionProvenance,
    FlowKind,
    FunctionKind,
    FunctionRecord,
    ImportFact,
    InheritedMethod,
    LocationFact,
    Parameter,
    ParameterKind,
    ResolutionProvenance,
    ResolutionStatus,
    SourceSpan,
    SymbolRef,
    ValueFlowEdge,
    YieldFact,
)

# ── Fixture helpers ────────────────────────────────────────────────────


def _span() -> SourceSpan:
    return SourceSpan(file="app.py", line=1, column=0, end_line=1, end_column=10)


def _prov() -> ExtractionProvenance:
    return ExtractionProvenance(
        producer="structural_entity_pass",
        producer_version="1.0",
        artifact="normalized/functions.jsonl",
    )


# ── Enum completeness ─────────────────────────────────────────────────


class TestEnumMembers:
    def test_access_kind(self):
        assert {m.value for m in AccessKind} == {
            "attr",
            "subscript",
            "del",
            "augmented",
            "call_mutator",
        }

    def test_alias_mechanism(self):
        assert {m.value for m in AliasMechanism} == {
            "import_alias",
            "assignment_alias",
            "wildcard_import",
        }

    def test_assignment_kind(self):
        assert {m.value for m in AssignmentKind} == {
            "simple",
            "augmented",
            "unpacking",
            "annotated",
        }

    def test_edge_source(self):
        assert {m.value for m in EdgeSource} == {"ast", "hierarchy"}

    def test_error_kind(self):
        assert {m.value for m in ErrorKind} == {
            "parse",
            "astroid",
            "basedpyright",
            "mypy",
            "cfg",
            "resolution",
            "value_flow",
        }

    def test_flow_kind(self):
        assert {m.value for m in FlowKind} == {
            "assign",
            "argument",
            "return",
            "alias",
            "unpack",
            "augmented_assign",
            "annotated_assign",
            "chain",
            "comprehension_binding",
            "attribute_write",
            "yield",
            "transform_input",
        }

    def test_function_kind(self):
        assert {m.value for m in FunctionKind} == {
            "top_level",
            "method",
            "nested",
            "lambda",
        }

    def test_parameter_kind(self):
        assert {m.value for m in ParameterKind} == {
            "positional_only",
            "positional_or_keyword",
            "keyword_only",
            "var_positional",
            "var_keyword",
        }

    def test_resolution_status(self):
        assert {m.value for m in ResolutionStatus} == {
            "resolved",
            "unresolved",
            "partial",
        }


# ── Foundation type construction ──────────────────────────────────────


class TestFoundationTypes:
    def test_source_span(self):
        s = _span()
        assert s.file == "app.py"
        assert s.line == 1
        assert s.column == 0
        assert s.end_line == 1
        assert s.end_column == 10
        assert not hasattr(s, "__dict__")

    def test_extraction_provenance(self):
        p = _prov()
        assert p.producer == "structural_entity_pass"

    def test_resolution_provenance(self):
        rp = ResolutionProvenance(
            selected_source="consensus",
            contributing_sources=("basedpyright", "libcst"),
            alternatives=None,
            verification_method=None,
            confidence=1.0,
        )
        assert rp.confidence == 1.0
        assert rp.alternatives is None

    def test_resolution_provenance_with_alternatives(self):
        rp = ResolutionProvenance(
            selected_source="basedpyright",
            contributing_sources=("basedpyright", "libcst", "astroid"),
            alternatives=("flask.globals.request",),
            verification_method="import_chain",
            confidence=0.85,
        )
        assert rp.alternatives == ("flask.globals.request",)


# ── Record type construction ──────────────────────────────────────────


class TestRecordTypes:
    def test_parameter(self):
        p = Parameter(
            name="user_id",
            annotation="int",
            default=None,
            kind=ParameterKind.POSITIONAL_OR_KEYWORD,
            position=0,
            location=_span(),
        )
        assert p.name == "user_id"
        assert p.annotation == "int"
        assert p.default is None

    def test_call_argument(self):
        ca = CallArgument(
            position=0,
            keyword=None,
            expression="user_id",
            location=_span(),
        )
        assert ca.position == 0
        assert ca.keyword is None

    def test_call_argument_keyword_only(self):
        ca = CallArgument(
            position=None,
            keyword="timeout",
            expression="30",
            location=_span(),
        )
        assert ca.position is None
        assert ca.keyword == "timeout"

    def test_inherited_method(self):
        im = InheritedMethod(
            name="save",
            defining_class_fqn="django.db.models.Model",
            resolution="mro",
        )
        assert im.name == "save"

    def test_function_record(self):
        fn = FunctionRecord(
            fqn="app.views.index",
            name="index",
            file="app/views.py",
            line=10,
            params=(),
            decorator_names=("route",),
            decorator_fqns=("flask.Flask.route",),
            kind=FunctionKind.TOP_LEVEL,
            is_method=False,
            is_nested=False,
            is_async=False,
            parent_class=None,
            location=_span(),
            provenance=_prov(),
        )
        assert fn.fqn == "app.views.index"
        assert fn.kind == FunctionKind.TOP_LEVEL
        assert fn.is_async is False

    def test_class_record(self):
        cr = ClassRecord(
            fqn="app.models.User",
            name="User",
            file="app/models.py",
            bases=("flask_sqlalchemy.Model",),
            mro_chain=("app.models.User", "flask_sqlalchemy.Model", "builtins.object"),
            mro_complete=True,
            method_names=("__repr__",),
            class_var_names=("__tablename__",),
            is_abstract=False,
            metaclass=None,
            subclasses=(),
            all_subclasses=(),
            inherited_methods=(
                InheritedMethod(
                    name="query",
                    defining_class_fqn="flask_sqlalchemy.Model",
                    resolution="mro",
                ),
            ),
            hierarchy_gaps=(),
            location=_span(),
            provenance=_prov(),
        )
        assert cr.fqn == "app.models.User"
        assert len(cr.mro_chain) == 3
        assert len(cr.inherited_methods) == 1

    def test_call_edge(self):
        ce = CallEdge(
            caller_fqn="app.views.index",
            callee_fqn="app.models.get_user",
            arguments=(
                CallArgument(position=0, keyword=None, expression="user_id", location=_span()),
            ),
            resolution=ResolutionStatus.RESOLVED,
            source=EdgeSource.AST,
            unresolved_reason=None,
            location=_span(),
            provenance=_prov(),
        )
        assert ce.resolution == ResolutionStatus.RESOLVED
        assert len(ce.arguments) == 1

    def test_call_edge_unresolved(self):
        ce = CallEdge(
            caller_fqn="app.views.index",
            callee_fqn=None,
            arguments=(),
            resolution=ResolutionStatus.UNRESOLVED,
            source=EdgeSource.AST,
            unresolved_reason="dynamic dispatch",
            location=_span(),
            provenance=_prov(),
        )
        assert ce.callee_fqn is None

    def test_decorator_fact(self):
        df = DecoratorFact(
            name="route",
            fqn="flask.Flask.route",
            args=("/users",),
            kwargs=(("methods", '["GET", "POST"]'),),
            target_fqn="app.views.users",
            application_order=0,
            location=_span(),
            provenance=_prov(),
        )
        assert df.fqn == "flask.Flask.route"
        assert df.application_order == 0

    def test_attribute_access_read(self):
        aa = AttributeAccess(
            target_expr="request",
            attr_name="args",
            is_write=False,
            access_kind=AccessKind.ATTR,
            value_expr=None,
            containing_function_fqn="app.views.index",
            location=_span(),
            provenance=_prov(),
        )
        assert aa.is_write is False
        assert aa.value_expr is None

    def test_attribute_access_write(self):
        aa = AttributeAccess(
            target_expr="g",
            attr_name="user",
            is_write=True,
            access_kind=AccessKind.ATTR,
            value_expr="current_user",
            containing_function_fqn="app.views.before_request",
            location=_span(),
            provenance=_prov(),
        )
        assert aa.is_write is True
        assert aa.value_expr == "current_user"

    def test_value_flow_edge(self):
        vfe = ValueFlowEdge(
            source_expr="request.args.get('id')",
            source_location=_span(),
            target_expr="user_id",
            target_location=_span(),
            kind=FlowKind.ASSIGN,
            containing_function_fqn="app.views.index",
            provenance=_prov(),
        )
        assert vfe.kind == FlowKind.ASSIGN

    def test_assignment_fact(self):
        af = AssignmentFact(
            target="user_id",
            target_location=_span(),
            value_expression="request.args.get('id')",
            value_location=_span(),
            kind=AssignmentKind.SIMPLE,
            containing_function_fqn="app.views.index",
        )
        assert af.kind == AssignmentKind.SIMPLE

    def test_alias_fact(self):
        af = AliasFact(
            original_fqn="flask.request",
            alias_name="req",
            mechanism=AliasMechanism.IMPORT_ALIAS,
            location=_span(),
        )
        assert af.mechanism == AliasMechanism.IMPORT_ALIAS

    def test_import_fact(self):
        imf = ImportFact(
            module="flask",
            names=("Flask", "request"),
            aliases=(("Flask", "Flask"), ("request", "req")),
            is_from_import=True,
            location=_span(),
            provenance=_prov(),
        )
        assert imf.is_from_import is True
        assert len(imf.names) == 2

    def test_symbol_ref(self):
        sr = SymbolRef(
            name="request",
            fqn="flask.globals.request",
            resolution=ResolutionStatus.RESOLVED,
            location=_span(),
            provenance=_prov(),
        )
        assert sr.fqn == "flask.globals.request"

    def test_extraction_error(self):
        ee = ExtractionError(
            file="app/views.py",
            pass_name="cfg",
            error_kind=ErrorKind.CFG,
            message="Unsupported: async for",
            is_fatal=False,
            location=_span(),
        )
        assert ee.is_fatal is False

    def test_extraction_error_no_location(self):
        ee = ExtractionError(
            file="app/views.py",
            pass_name="parse",
            error_kind=ErrorKind.PARSE,
            message="SyntaxError",
            is_fatal=True,
            location=None,
        )
        assert ee.location is None

    def test_location_fact(self):
        lf = LocationFact(
            entity_fqn="app.views.index",
            span=_span(),
        )
        assert lf.entity_fqn == "app.views.index"

    def test_branch_condition(self):
        bc = BranchCondition(
            condition_expr="user is not None",
            direction=True,
            location=_span(),
        )
        assert bc.direction is True

    def test_cfg_block(self):
        condition_location = _span()
        b = CFGBlock(
            id=0,
            statements=(_span(),),
            successors=(1, 2),
            predecessors=(),
            condition_expr="x > 0",
            condition_location=condition_location,
        )
        assert b.id == 0
        assert len(b.successors) == 2
        assert b.condition_location == condition_location

    def test_cfg_edge(self):
        e = CFGEdge(
            source_id=0,
            target_id=1,
            label="true",
            is_exceptional=False,
        )
        assert e.label == "true"

    def test_cfg_path(self):
        b0 = CFGBlock(id=0, statements=(), successors=(1,), predecessors=(), condition_expr=None)
        b1 = CFGBlock(id=1, statements=(), successors=(), predecessors=(0,), condition_expr=None)
        branch = BranchCondition(
            condition_expr="x",
            direction=True,
            location=_span(),
        )
        p = CFGPath(blocks=(b0, b1), conditions=(branch,))
        assert len(p.blocks) == 2
        assert p.conditions == (branch,)

    def test_yield_fact(self):
        yf = YieldFact(
            expression="value",
            expression_location=_span(),
            statement_location=_span(),
            is_from=False,
            containing_function_fqn="mod.gen",
            provenance=_prov(),
        )
        assert yf.expression == "value"
        assert yf.is_from is False
        assert yf.containing_function_fqn == "mod.gen"

    def test_yield_fact_bare(self):
        yf = YieldFact(
            expression=None,
            expression_location=None,
            statement_location=_span(),
            is_from=False,
            containing_function_fqn="mod.gen",
            provenance=_prov(),
        )
        assert yf.expression is None
        assert yf.expression_location is None

    def test_yield_fact_from(self):
        yf = YieldFact(
            expression="sub_gen()",
            expression_location=_span(),
            statement_location=_span(),
            is_from=True,
            containing_function_fqn="mod.delegator",
            provenance=_prov(),
        )
        assert yf.is_from is True


# ── Frozenness ────────────────────────────────────────────────────────


_ALL_DATACLASSES = [
    AliasFact,
    AssignmentFact,
    AttributeAccess,
    BranchCondition,
    CFGBlock,
    CFGEdge,
    CFGPath,
    CallArgument,
    CallEdge,
    ClassRecord,
    ComprehensionBindingFact,
    DecoratorFact,
    ExtractionError,
    ExtractionProvenance,
    FunctionRecord,
    ImportFact,
    InheritedMethod,
    LocationFact,
    Parameter,
    ResolutionProvenance,
    SourceSpan,
    SymbolRef,
    ValueFlowEdge,
    YieldFact,
]


class TestFrozenness:
    @pytest.mark.parametrize("cls", _ALL_DATACLASSES, ids=lambda c: c.__name__)
    def test_is_frozen_dataclass(self, cls: type) -> None:
        assert dataclasses.is_dataclass(cls), f"{cls.__name__} is not a dataclass"
        # frozen=True sets __dataclass_params__.frozen
        params = getattr(cls, "__dataclass_params__", None)
        assert params is not None, f"{cls.__name__} missing __dataclass_params__"
        assert params.frozen, f"{cls.__name__} is not frozen"

    def test_extraction_provenance_is_slotted(self):
        assert not hasattr(_prov(), "__dict__")
