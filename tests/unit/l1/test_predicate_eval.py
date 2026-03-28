"""Comprehensive tests for provider predicate evaluation.

The ``_predicate_eval`` module evaluates ``when`` predicates attached to
provider descriptors.  It supports literal-string checks, type-check
predicates, and boolean combinators (``And``, ``Or``, ``Not``).

This file covers every predicate type, combinator, and edge case:
- ``_descriptor_when`` routing
- ``LiteralStringPredicate`` evaluation
- ``TypeCheckPredicate`` evaluation (delegated to ``_evaluate_type_check``)
- ``AndPredicate``, ``OrPredicate``, ``NotPredicate`` combinators
- ``_find_argument`` positional and keyword lookup
- ``_is_literal_string_expression`` / ``_is_literal_string_value`` helpers
- ``_concrete_facts_disagree`` / ``_type_strings_agree`` helpers
- Gap propagation through combinators

TypeCheckPredicate resolution against the TypeEnrichmentIndex is covered
in ``test_type_predicate_resolution.py``; this file focuses on the
predicate evaluation dispatch logic and combinators.
"""

from __future__ import annotations

import pytest

from flawed._index._type_enrichment import TypeEnrichmentIndex
from flawed._index._types import (
    CallArgument,
    CallEdge,
    EdgeSource,
    ExtractionProvenance,
    ResolutionStatus,
    SourceSpan,
)
from flawed._semantic._predicate_eval import (
    _concrete_facts_disagree,
    _descriptor_when,
    _evaluate_when_predicate,
    _find_argument,
    _is_literal_string_expression,
    _is_literal_string_value,
    _type_strings_agree,
)
from flawed._semantic._provider_engine import PredicateStatus
from flawed._semantic.providers import (
    CheckKind,
    EffectCallPattern,
    InputMethodPattern,
    RouteCallPattern,
    SecurityCheckPattern,
    TaintSinkPattern,
)
from flawed._semantic.providers._base import (
    AndPredicate,
    LiteralStringPredicate,
    NotPredicate,
    OrPredicate,
    TypeCheckPredicate,
    WhenPredicate,
)

_PROV = ExtractionProvenance(producer="test", producer_version="0", artifact="")
_SPAN = SourceSpan(file="app.py", line=10, column=0, end_line=10, end_column=10)


def _arg(
    position: int,
    expression: str,
    *,
    keyword: str | None = None,
) -> CallArgument:
    return CallArgument(
        position=position,
        keyword=keyword,
        expression=expression,
        location=_SPAN,
    )


def _edge(*arguments: CallArgument) -> CallEdge:
    return CallEdge(
        caller_fqn="app.handler",
        callee_fqn="lib.func",
        arguments=arguments,
        resolution=ResolutionStatus.RESOLVED,
        source=EdgeSource.AST,
        unresolved_reason=None,
        location=_SPAN,
        provenance=_PROV,
        call_expression="lib.func()",
    )


def _status_operand(status: PredicateStatus, position: int) -> WhenPredicate:
    if status is PredicateStatus.UNKNOWN:
        return TypeCheckPredicate(arg_pos=position, type_fqn="expected.Type")
    return LiteralStringPredicate(arg_pos=position)


def _status_arg(status: PredicateStatus, position: int) -> CallArgument:
    expression = f"unknown_{position}" if status is PredicateStatus.UNKNOWN else "name"
    if status is PredicateStatus.PASSED:
        expression = f"'literal_{position}'"
    return _arg(position, expression)


def _expected_type_gap_sources(*statuses: PredicateStatus) -> list[str]:
    return [
        f"no type enrichment for: unknown_{position}"
        for position, status in enumerate(statuses)
        if status is PredicateStatus.UNKNOWN
    ]


# =====================================================================
# _descriptor_when: routing predicate extraction from descriptors
# =====================================================================


class TestDescriptorWhen:
    def test_effect_call_returns_when(self) -> None:
        pred = LiteralStringPredicate(arg_pos=0)
        desc = EffectCallPattern(fqn="db.exec", category="DB_READ", when=pred)
        assert _descriptor_when(desc) is pred

    def test_taint_sink_returns_when(self) -> None:
        pred = TypeCheckPredicate(arg_pos=0, type_fqn="str")
        desc = TaintSinkPattern(fqn="os.system", arg=0, sink_kind="CMD", when=pred)
        assert _descriptor_when(desc) is pred

    def test_effect_call_no_when_returns_none(self) -> None:
        desc = EffectCallPattern(fqn="db.exec", category="DB_READ")
        assert _descriptor_when(desc) is None

    def test_route_call_always_returns_none(self) -> None:
        desc = RouteCallPattern(fqn="app.route")
        assert _descriptor_when(desc) is None

    def test_input_method_always_returns_none(self) -> None:
        desc = InputMethodPattern(fqn="req.json", source_type="Json")
        assert _descriptor_when(desc) is None

    def test_security_check_always_returns_none(self) -> None:
        desc = SecurityCheckPattern(fqn="check_perm", kind=CheckKind.DECORATOR, category="AUTH")
        assert _descriptor_when(desc) is None


# =====================================================================
# _find_argument: positional and keyword lookup
# =====================================================================


class TestFindArgument:
    def test_positional_match(self) -> None:
        arg = _arg(0, "hello")
        result = _find_argument((arg,), position=0, keyword=None)
        assert result is arg

    def test_positional_no_match(self) -> None:
        arg = _arg(0, "hello")
        result = _find_argument((arg,), position=1, keyword=None)
        assert result is None

    def test_keyword_match(self) -> None:
        arg = _arg(0, "hello", keyword="name")
        result = _find_argument((arg,), position=None, keyword="name")
        assert result is arg

    def test_keyword_takes_priority_over_position(self) -> None:
        a0 = _arg(0, "wrong")
        a1 = _arg(1, "right", keyword="target")
        result = _find_argument((a0, a1), position=None, keyword="target")
        assert result is a1

    def test_empty_arguments(self) -> None:
        result = _find_argument((), position=0, keyword=None)
        assert result is None

    def test_keyword_no_match(self) -> None:
        arg = _arg(0, "hello", keyword="other")
        result = _find_argument((arg,), position=None, keyword="name")
        assert result is None


# =====================================================================
# _is_literal_string_expression / _is_literal_string_value
# =====================================================================


class TestIsLiteralString:
    def test_simple_string(self) -> None:
        assert _is_literal_string_expression("'hello'") is True

    def test_double_quoted_string(self) -> None:
        assert _is_literal_string_expression('"hello"') is True

    def test_integer(self) -> None:
        assert _is_literal_string_expression("42") is False

    def test_variable_reference(self) -> None:
        assert _is_literal_string_expression("my_var") is False

    def test_function_call(self) -> None:
        assert _is_literal_string_expression("foo()") is False

    def test_tuple_of_strings(self) -> None:
        assert _is_literal_string_expression("('a', 'b')") is True

    def test_list_of_strings(self) -> None:
        assert _is_literal_string_expression("['a', 'b']") is True

    def test_mixed_tuple(self) -> None:
        assert _is_literal_string_expression("('a', 1)") is False

    def test_dict_of_strings(self) -> None:
        assert _is_literal_string_expression("{'a': 'b'}") is True

    def test_dict_with_non_string_value(self) -> None:
        assert _is_literal_string_expression("{'a': 1}") is False

    def test_empty_string(self) -> None:
        assert _is_literal_string_expression("''") is True

    def test_syntax_error(self) -> None:
        assert _is_literal_string_expression("not valid python!!") is False

    def test_nested_collections(self) -> None:
        assert _is_literal_string_expression("('a', ('b', 'c'))") is True

    # _is_literal_string_value directly
    def test_value_string(self) -> None:
        assert _is_literal_string_value("hello") is True

    def test_value_int(self) -> None:
        assert _is_literal_string_value(42) is False

    def test_value_none(self) -> None:
        assert _is_literal_string_value(None) is False

    def test_value_empty_tuple(self) -> None:
        assert _is_literal_string_value(()) is True

    def test_value_frozenset_of_strings(self) -> None:
        assert _is_literal_string_value(frozenset({"a", "b"})) is True

    def test_value_set_with_int(self) -> None:
        assert _is_literal_string_value({1}) is False

    def test_value_dict_non_string_key(self) -> None:
        assert _is_literal_string_value({1: "v"}) is False


# =====================================================================
# _type_strings_agree / _concrete_facts_disagree
# =====================================================================


class TestTypeStringAgreement:
    def test_exact_match(self) -> None:
        assert _type_strings_agree("a.B", "a.B") is True

    def test_left_suffix_of_right(self) -> None:
        assert _type_strings_agree("B", "a.B") is True

    def test_right_suffix_of_left(self) -> None:
        assert _type_strings_agree("a.B", "B") is True

    def test_no_match(self) -> None:
        assert _type_strings_agree("a.B", "c.D") is False

    def test_partial_name_no_match(self) -> None:
        """'elete' should not match '.Delete' without a dot boundary."""
        assert _type_strings_agree("elete", "a.Delete") is False


class TestConcreteFactsDisagree:
    def test_single_fact_does_not_disagree(self) -> None:
        from flawed._index._type_enrichment import TypeFact

        fact = TypeFact(
            expression="x",
            declared_type="a.B",
            location=_SPAN,
            source_tool="mypy",
            is_concrete=True,
            provenance=_PROV,
        )
        assert _concrete_facts_disagree((fact,)) is False

    def test_two_agreeing_facts(self) -> None:
        from flawed._index._type_enrichment import TypeFact

        f1 = TypeFact(
            expression="x",
            declared_type="a.B",
            location=_SPAN,
            source_tool="mypy",
            is_concrete=True,
            provenance=_PROV,
        )
        f2 = TypeFact(
            expression="x",
            declared_type="B",
            location=_SPAN,
            source_tool="pyright",
            is_concrete=True,
            provenance=_PROV,
        )
        assert _concrete_facts_disagree((f1, f2)) is False

    def test_two_disagreeing_facts(self) -> None:
        from flawed._index._type_enrichment import TypeFact

        f1 = TypeFact(
            expression="x",
            declared_type="a.B",
            location=_SPAN,
            source_tool="mypy",
            is_concrete=True,
            provenance=_PROV,
        )
        f2 = TypeFact(
            expression="x",
            declared_type="c.D",
            location=_SPAN,
            source_tool="pyright",
            is_concrete=True,
            provenance=_PROV,
        )
        assert _concrete_facts_disagree((f1, f2)) is True


# =====================================================================
# LiteralStringPredicate evaluation
# =====================================================================


class TestLiteralStringPredicate:
    def test_passes_with_string_literal(self) -> None:
        pred = LiteralStringPredicate(arg_pos=0)
        edge = _edge(_arg(0, "'hello'"))
        result = _evaluate_when_predicate(pred, edge)
        assert result.status is PredicateStatus.PASSED

    def test_fails_with_variable(self) -> None:
        pred = LiteralStringPredicate(arg_pos=0)
        edge = _edge(_arg(0, "my_var"))
        result = _evaluate_when_predicate(pred, edge)
        assert result.status is PredicateStatus.FAILED

    def test_fails_when_argument_missing(self) -> None:
        pred = LiteralStringPredicate(arg_pos=1)
        edge = _edge(_arg(0, "'hello'"))
        result = _evaluate_when_predicate(pred, edge)
        assert result.status is PredicateStatus.FAILED

    def test_keyword_match(self) -> None:
        pred = LiteralStringPredicate(arg_kw="name")
        edge = _edge(_arg(0, "'hello'", keyword="name"))
        result = _evaluate_when_predicate(pred, edge)
        assert result.status is PredicateStatus.PASSED


# =====================================================================
# None predicate (passthrough)
# =====================================================================


class TestNonePredicate:
    def test_none_predicate_passes(self) -> None:
        result = _evaluate_when_predicate(None, _edge())
        assert result.status is PredicateStatus.PASSED
        assert result.gaps == ()


# =====================================================================
# NotPredicate combinator
# =====================================================================


class TestNotPredicate:
    @pytest.mark.parametrize(
        ("inner_status", "expected_status"),
        [
            (PredicateStatus.PASSED, PredicateStatus.FAILED),
            (PredicateStatus.FAILED, PredicateStatus.PASSED),
            (PredicateStatus.UNKNOWN, PredicateStatus.UNKNOWN),
        ],
    )
    def test_truth_table_and_gap_propagation(
        self,
        inner_status: PredicateStatus,
        expected_status: PredicateStatus,
    ) -> None:
        pred = NotPredicate(inner=_status_operand(inner_status, 0))
        edge = _edge(_status_arg(inner_status, 0))

        result = _evaluate_when_predicate(
            pred,
            edge,
            type_enrichment=TypeEnrichmentIndex.empty(),
        )

        assert result.status is expected_status
        assert [gap.source_error for gap in result.gaps] == _expected_type_gap_sources(
            inner_status,
        )

    def test_not_inverts_passed_to_failed(self) -> None:
        inner = LiteralStringPredicate(arg_pos=0)
        pred = NotPredicate(inner=inner)
        edge = _edge(_arg(0, "'hello'"))
        result = _evaluate_when_predicate(pred, edge)
        assert result.status is PredicateStatus.FAILED

    def test_not_inverts_failed_to_passed(self) -> None:
        inner = LiteralStringPredicate(arg_pos=0)
        pred = NotPredicate(inner=inner)
        edge = _edge(_arg(0, "my_var"))
        result = _evaluate_when_predicate(pred, edge)
        assert result.status is PredicateStatus.PASSED

    def test_not_preserves_unknown(self) -> None:
        # TypeCheckPredicate with no enrichment produces UNKNOWN
        inner = TypeCheckPredicate(arg_pos=0, type_fqn="a.B")
        pred = NotPredicate(inner=inner)
        edge = _edge(_arg(0, "x"))
        result = _evaluate_when_predicate(pred, edge, type_enrichment=None)
        assert result.status is PredicateStatus.UNKNOWN
        assert len(result.gaps) == 1

    def test_not_propagates_gap_operand(self) -> None:
        inner = TypeCheckPredicate(arg_pos=0, type_fqn="a.B")
        pred = NotPredicate(inner=inner)
        edge = _edge(_arg(0, "value"))

        result = _evaluate_when_predicate(pred, edge, type_enrichment=None)

        assert result.status is PredicateStatus.UNKNOWN
        assert len(result.gaps) == 1
        assert result.gaps[0].affected_function == "app.handler"


# =====================================================================
# AndPredicate combinator
# =====================================================================


class TestAndPredicate:
    @pytest.mark.parametrize(
        ("left_status", "right_status", "expected_status"),
        [
            (PredicateStatus.PASSED, PredicateStatus.PASSED, PredicateStatus.PASSED),
            (PredicateStatus.PASSED, PredicateStatus.FAILED, PredicateStatus.FAILED),
            (PredicateStatus.PASSED, PredicateStatus.UNKNOWN, PredicateStatus.UNKNOWN),
            (PredicateStatus.FAILED, PredicateStatus.PASSED, PredicateStatus.FAILED),
            (PredicateStatus.FAILED, PredicateStatus.FAILED, PredicateStatus.FAILED),
            (PredicateStatus.FAILED, PredicateStatus.UNKNOWN, PredicateStatus.FAILED),
            (PredicateStatus.UNKNOWN, PredicateStatus.PASSED, PredicateStatus.UNKNOWN),
            (PredicateStatus.UNKNOWN, PredicateStatus.FAILED, PredicateStatus.FAILED),
            (PredicateStatus.UNKNOWN, PredicateStatus.UNKNOWN, PredicateStatus.UNKNOWN),
        ],
    )
    def test_truth_table_and_gap_propagation(
        self,
        left_status: PredicateStatus,
        right_status: PredicateStatus,
        expected_status: PredicateStatus,
    ) -> None:
        pred = AndPredicate(
            left=_status_operand(left_status, 0),
            right=_status_operand(right_status, 1),
        )
        edge = _edge(_status_arg(left_status, 0), _status_arg(right_status, 1))

        result = _evaluate_when_predicate(
            pred,
            edge,
            type_enrichment=TypeEnrichmentIndex.empty(),
        )

        assert result.status is expected_status
        assert [gap.source_error for gap in result.gaps] == _expected_type_gap_sources(
            left_status,
            right_status,
        )

    def test_both_passed(self) -> None:
        left = LiteralStringPredicate(arg_pos=0)
        right = LiteralStringPredicate(arg_pos=1)
        pred = AndPredicate(left=left, right=right)
        edge = _edge(_arg(0, "'a'"), _arg(1, "'b'"))
        result = _evaluate_when_predicate(pred, edge)
        assert result.status is PredicateStatus.PASSED

    def test_left_failed(self) -> None:
        left = LiteralStringPredicate(arg_pos=0)
        right = LiteralStringPredicate(arg_pos=1)
        pred = AndPredicate(left=left, right=right)
        edge = _edge(_arg(0, "var"), _arg(1, "'b'"))
        result = _evaluate_when_predicate(pred, edge)
        assert result.status is PredicateStatus.FAILED

    def test_right_failed(self) -> None:
        left = LiteralStringPredicate(arg_pos=0)
        right = LiteralStringPredicate(arg_pos=1)
        pred = AndPredicate(left=left, right=right)
        edge = _edge(_arg(0, "'a'"), _arg(1, "var"))
        result = _evaluate_when_predicate(pred, edge)
        assert result.status is PredicateStatus.FAILED

    def test_both_failed(self) -> None:
        left = LiteralStringPredicate(arg_pos=0)
        right = LiteralStringPredicate(arg_pos=1)
        pred = AndPredicate(left=left, right=right)
        edge = _edge(_arg(0, "var1"), _arg(1, "var2"))
        result = _evaluate_when_predicate(pred, edge)
        assert result.status is PredicateStatus.FAILED

    def test_and_with_one_unknown_and_one_passed(self) -> None:
        """Passed AND Unknown -> Unknown (can't determine truth)."""
        passed = LiteralStringPredicate(arg_pos=0)
        unknown = TypeCheckPredicate(arg_pos=1, type_fqn="a.B")
        pred = AndPredicate(left=passed, right=unknown)
        edge = _edge(_arg(0, "'a'"), _arg(1, "x"))
        result = _evaluate_when_predicate(pred, edge, type_enrichment=None)
        assert result.status is PredicateStatus.UNKNOWN
        assert len(result.gaps) == 1

    def test_and_with_one_failed_and_one_unknown(self) -> None:
        """Failed AND Unknown -> Failed (short-circuit)."""
        failed = LiteralStringPredicate(arg_pos=0)
        unknown = TypeCheckPredicate(arg_pos=1, type_fqn="a.B")
        pred = AndPredicate(left=failed, right=unknown)
        edge = _edge(_arg(0, "var"), _arg(1, "x"))
        result = _evaluate_when_predicate(pred, edge, type_enrichment=None)
        assert result.status is PredicateStatus.FAILED
        assert len(result.gaps) == 1

    def test_and_propagates_gaps_from_both_sides(self) -> None:
        left = TypeCheckPredicate(arg_pos=0, type_fqn="a.B")
        right = TypeCheckPredicate(arg_pos=1, type_fqn="c.D")
        pred = AndPredicate(left=left, right=right)
        edge = _edge(_arg(0, "x"), _arg(1, "y"))
        result = _evaluate_when_predicate(pred, edge, type_enrichment=None)
        assert result.status is PredicateStatus.UNKNOWN
        assert len(result.gaps) == 2


# =====================================================================
# OrPredicate combinator
# =====================================================================


class TestOrPredicate:
    @pytest.mark.parametrize(
        ("left_status", "right_status", "expected_status"),
        [
            (PredicateStatus.PASSED, PredicateStatus.PASSED, PredicateStatus.PASSED),
            (PredicateStatus.PASSED, PredicateStatus.FAILED, PredicateStatus.PASSED),
            (PredicateStatus.PASSED, PredicateStatus.UNKNOWN, PredicateStatus.PASSED),
            (PredicateStatus.FAILED, PredicateStatus.PASSED, PredicateStatus.PASSED),
            (PredicateStatus.FAILED, PredicateStatus.FAILED, PredicateStatus.FAILED),
            (PredicateStatus.FAILED, PredicateStatus.UNKNOWN, PredicateStatus.UNKNOWN),
            (PredicateStatus.UNKNOWN, PredicateStatus.PASSED, PredicateStatus.PASSED),
            (PredicateStatus.UNKNOWN, PredicateStatus.FAILED, PredicateStatus.UNKNOWN),
            (PredicateStatus.UNKNOWN, PredicateStatus.UNKNOWN, PredicateStatus.UNKNOWN),
        ],
    )
    def test_truth_table_and_gap_propagation(
        self,
        left_status: PredicateStatus,
        right_status: PredicateStatus,
        expected_status: PredicateStatus,
    ) -> None:
        pred = OrPredicate(
            left=_status_operand(left_status, 0),
            right=_status_operand(right_status, 1),
        )
        edge = _edge(_status_arg(left_status, 0), _status_arg(right_status, 1))

        result = _evaluate_when_predicate(
            pred,
            edge,
            type_enrichment=TypeEnrichmentIndex.empty(),
        )

        assert result.status is expected_status
        assert [gap.source_error for gap in result.gaps] == _expected_type_gap_sources(
            left_status,
            right_status,
        )

    def test_both_passed(self) -> None:
        left = LiteralStringPredicate(arg_pos=0)
        right = LiteralStringPredicate(arg_pos=1)
        pred = OrPredicate(left=left, right=right)
        edge = _edge(_arg(0, "'a'"), _arg(1, "'b'"))
        result = _evaluate_when_predicate(pred, edge)
        assert result.status is PredicateStatus.PASSED

    def test_left_passed_right_failed(self) -> None:
        left = LiteralStringPredicate(arg_pos=0)
        right = LiteralStringPredicate(arg_pos=1)
        pred = OrPredicate(left=left, right=right)
        edge = _edge(_arg(0, "'a'"), _arg(1, "var"))
        result = _evaluate_when_predicate(pred, edge)
        assert result.status is PredicateStatus.PASSED

    def test_left_failed_right_passed(self) -> None:
        left = LiteralStringPredicate(arg_pos=0)
        right = LiteralStringPredicate(arg_pos=1)
        pred = OrPredicate(left=left, right=right)
        edge = _edge(_arg(0, "var"), _arg(1, "'b'"))
        result = _evaluate_when_predicate(pred, edge)
        assert result.status is PredicateStatus.PASSED

    def test_both_failed(self) -> None:
        left = LiteralStringPredicate(arg_pos=0)
        right = LiteralStringPredicate(arg_pos=1)
        pred = OrPredicate(left=left, right=right)
        edge = _edge(_arg(0, "var1"), _arg(1, "var2"))
        result = _evaluate_when_predicate(pred, edge)
        assert result.status is PredicateStatus.FAILED

    def test_or_with_one_passed_and_one_unknown(self) -> None:
        """Passed OR Unknown -> Passed (short-circuit)."""
        passed = LiteralStringPredicate(arg_pos=0)
        unknown = TypeCheckPredicate(arg_pos=1, type_fqn="a.B")
        pred = OrPredicate(left=passed, right=unknown)
        edge = _edge(_arg(0, "'a'"), _arg(1, "x"))
        result = _evaluate_when_predicate(pred, edge, type_enrichment=None)
        assert result.status is PredicateStatus.PASSED
        assert len(result.gaps) == 1

    def test_or_with_both_unknown(self) -> None:
        left = TypeCheckPredicate(arg_pos=0, type_fqn="a.B")
        right = TypeCheckPredicate(arg_pos=1, type_fqn="c.D")
        pred = OrPredicate(left=left, right=right)
        edge = _edge(_arg(0, "x"), _arg(1, "y"))
        result = _evaluate_when_predicate(pred, edge, type_enrichment=None)
        assert result.status is PredicateStatus.UNKNOWN
        assert len(result.gaps) == 2

    def test_or_with_one_failed_and_one_unknown(self) -> None:
        """Failed OR Unknown -> Unknown (can't rule out truth)."""
        failed = LiteralStringPredicate(arg_pos=0)
        unknown = TypeCheckPredicate(arg_pos=1, type_fqn="a.B")
        pred = OrPredicate(left=failed, right=unknown)
        edge = _edge(_arg(0, "var"), _arg(1, "x"))
        result = _evaluate_when_predicate(pred, edge, type_enrichment=None)
        assert result.status is PredicateStatus.UNKNOWN
        assert len(result.gaps) == 1


# =====================================================================
# Operator composition via __and__, __or__, __invert__
# =====================================================================


class TestPredicateOperators:
    def test_and_operator_creates_and_predicate(self) -> None:
        left = LiteralStringPredicate(arg_pos=0)
        right = LiteralStringPredicate(arg_pos=1)
        combined = left & right
        assert isinstance(combined, AndPredicate)
        assert combined.left is left
        assert combined.right is right

    def test_or_operator_creates_or_predicate(self) -> None:
        left = LiteralStringPredicate(arg_pos=0)
        right = LiteralStringPredicate(arg_pos=1)
        combined = left | right
        assert isinstance(combined, OrPredicate)
        assert combined.left is left
        assert combined.right is right

    def test_invert_operator_creates_not_predicate(self) -> None:
        inner = LiteralStringPredicate(arg_pos=0)
        inverted = ~inner
        assert isinstance(inverted, NotPredicate)
        assert inverted.inner is inner

    def test_composed_expression_evaluates_correctly(self) -> None:
        """Test: arg(0) is literal AND NOT arg(1) is literal."""
        pred = LiteralStringPredicate(arg_pos=0) & ~LiteralStringPredicate(arg_pos=1)
        edge = _edge(_arg(0, "'hello'"), _arg(1, "var"))
        result = _evaluate_when_predicate(pred, edge)
        assert result.status is PredicateStatus.PASSED


# =====================================================================
# Unknown predicate type falls through to UNKNOWN
# =====================================================================


class TestUnknownPredicateType:
    def test_base_when_predicate_returns_unknown(self) -> None:
        """A bare WhenPredicate (not a known subclass) returns UNKNOWN."""
        pred = WhenPredicate()
        result = _evaluate_when_predicate(pred, _edge())
        assert result.status is PredicateStatus.UNKNOWN
