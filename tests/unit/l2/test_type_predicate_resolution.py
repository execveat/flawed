"""Tests for TypeCheckPredicate resolution against type-enrichment facts."""

from __future__ import annotations

from flawed._index._type_enrichment import TypeEnrichmentIndex, TypeFact
from flawed._index._types import (
    CallArgument,
    CallEdge,
    EdgeSource,
    ExtractionProvenance,
    ResolutionStatus,
    SourceSpan,
)
from flawed._semantic._predicate_eval import _evaluate_when_predicate, _type_matches
from flawed._semantic._provider_engine import PredicateStatus
from flawed._semantic.providers._base import TypeCheckPredicate

_PROV = ExtractionProvenance(producer="test", producer_version="0", artifact="")
_SPAN = SourceSpan(file="app.py", line=10, column=0, end_line=10, end_column=10)
_ASSIGN_SPAN = SourceSpan(file="app.py", line=5, column=4, end_line=5, end_column=8)


def _edge(*, arg_expr: str = "stmt", caller_fqn: str = "app.handler") -> CallEdge:
    return CallEdge(
        caller_fqn=caller_fqn,
        callee_fqn="db.session.execute",
        arguments=(
            CallArgument(
                position=0,
                keyword=None,
                expression=arg_expr,
                location=_SPAN,
            ),
        ),
        resolution=ResolutionStatus.RESOLVED,
        source=EdgeSource.AST,
        unresolved_reason=None,
        location=_SPAN,
        provenance=_PROV,
        call_expression=f"db.session.execute({arg_expr})",
    )


def _fact(
    *,
    expression: str = "stmt",
    declared_type: str = "sqlalchemy.sql.dml.Delete",
    is_concrete: bool = True,
    source_tool: str = "basedpyright",
    containing_function_fqn: str | None = None,
) -> TypeFact:
    return TypeFact(
        expression=expression,
        declared_type=declared_type,
        location=_ASSIGN_SPAN,
        source_tool=source_tool,
        is_concrete=is_concrete,
        provenance=_PROV,
        containing_function_fqn=containing_function_fqn,
    )


def _predicate(
    *,
    type_fqn: str = "sqlalchemy.sql.dml.Delete",
    alt_fqns: tuple[str, ...] = (),
) -> TypeCheckPredicate:
    return TypeCheckPredicate(arg_pos=0, type_fqn=type_fqn, alt_fqns=alt_fqns)


# -- concrete match ----------------------------------------------------------


def test_type_predicate_passes_with_concrete_match() -> None:
    enrichment = TypeEnrichmentIndex(facts=(_fact(),))
    result = _evaluate_when_predicate(_predicate(), _edge(), enrichment)
    assert result.status is PredicateStatus.PASSED
    assert result.gaps == ()


def test_type_predicate_fails_with_concrete_mismatch() -> None:
    enrichment = TypeEnrichmentIndex(facts=(_fact(declared_type="sqlalchemy.sql.dml.Update"),))
    result = _evaluate_when_predicate(_predicate(), _edge(), enrichment)
    assert result.status is PredicateStatus.FAILED
    assert result.gaps == ()


# -- unknown / gap cases -----------------------------------------------------


def test_type_predicate_unknown_when_no_fact() -> None:
    enrichment = TypeEnrichmentIndex.empty()
    result = _evaluate_when_predicate(_predicate(), _edge(), enrichment)
    assert result.status is PredicateStatus.UNKNOWN
    assert len(result.gaps) == 1
    assert result.gaps[0].kind.value == "inference_failure"
    assert "No type fact" in result.gaps[0].message


def test_type_predicate_unknown_when_imprecise() -> None:
    enrichment = TypeEnrichmentIndex(facts=(_fact(declared_type="Any", is_concrete=False),))
    result = _evaluate_when_predicate(_predicate(), _edge(), enrichment)
    assert result.status is PredicateStatus.UNKNOWN
    assert len(result.gaps) == 1
    assert "imprecise" in result.gaps[0].message


def test_type_predicate_unknown_with_concrete_tool_disagreement() -> None:
    enrichment = TypeEnrichmentIndex(
        facts=(
            _fact(
                declared_type="sqlalchemy.sql.dml.Delete",
                source_tool="mypy",
            ),
            _fact(
                declared_type="sqlalchemy.sql.dml.Update",
                source_tool="basedpyright",
            ),
        )
    )

    result = _evaluate_when_predicate(_predicate(), _edge(), enrichment)

    assert result.status is PredicateStatus.UNKNOWN
    assert len(result.gaps) == 1
    assert "Conflicting concrete type facts" in result.gaps[0].message
    source_error = result.gaps[0].source_error
    assert source_error is not None
    assert "mypy=sqlalchemy.sql.dml.Delete" in source_error
    assert "basedpyright=sqlalchemy.sql.dml.Update" in source_error


def test_type_predicate_prefers_concrete_when_other_tool_is_imprecise() -> None:
    enrichment = TypeEnrichmentIndex(
        facts=(
            _fact(declared_type="Any", source_tool="mypy", is_concrete=False),
            _fact(
                declared_type="sqlalchemy.sql.dml.Delete",
                source_tool="basedpyright",
            ),
        )
    )

    result = _evaluate_when_predicate(_predicate(), _edge(), enrichment)

    assert result.status is PredicateStatus.PASSED
    assert result.gaps == ()


def test_type_predicate_unknown_when_all_tool_facts_are_imprecise() -> None:
    enrichment = TypeEnrichmentIndex(
        facts=(
            _fact(declared_type="Any", source_tool="mypy", is_concrete=False),
            _fact(declared_type="Unknown", source_tool="basedpyright", is_concrete=False),
        )
    )

    result = _evaluate_when_predicate(_predicate(), _edge(), enrichment)

    assert result.status is PredicateStatus.UNKNOWN
    assert len(result.gaps) == 1
    assert "No concrete type fact" in result.gaps[0].message
    source_error = result.gaps[0].source_error
    assert source_error is not None
    assert "mypy=Any" in source_error
    assert "basedpyright=Unknown" in source_error


def test_type_predicate_uses_function_scoped_type_facts() -> None:
    enrichment = TypeEnrichmentIndex(
        facts=(
            _fact(
                declared_type="sqlalchemy.sql.dml.Update",
                containing_function_fqn="app.sibling",
            ),
            _fact(
                declared_type="sqlalchemy.sql.dml.Delete",
                containing_function_fqn="app.handler",
            ),
        )
    )

    result = _evaluate_when_predicate(_predicate(), _edge(caller_fqn="app.handler"), enrichment)

    assert result.status is PredicateStatus.PASSED
    assert result.gaps == ()


def test_type_predicate_unknown_when_no_enrichment() -> None:
    result = _evaluate_when_predicate(_predicate(), _edge(), type_enrichment=None)
    assert result.status is PredicateStatus.UNKNOWN
    assert len(result.gaps) == 1
    assert "requires type enrichment" in result.gaps[0].message


def test_type_predicate_failed_when_arg_missing() -> None:
    """Predicate asking for arg(1) when only arg(0) exists."""
    pred = TypeCheckPredicate(arg_pos=1, type_fqn="some.Type")
    enrichment = TypeEnrichmentIndex(facts=(_fact(),))
    result = _evaluate_when_predicate(pred, _edge(), enrichment)
    assert result.status is PredicateStatus.FAILED


# -- suffix matching ----------------------------------------------------------


def test_type_predicate_suffix_match_short_declared() -> None:
    enrichment = TypeEnrichmentIndex(facts=(_fact(declared_type="Delete"),))
    result = _evaluate_when_predicate(_predicate(), _edge(), enrichment)
    assert result.status is PredicateStatus.PASSED


def test_type_predicate_suffix_match_short_fqn() -> None:
    enrichment = TypeEnrichmentIndex(facts=(_fact(declared_type="sqlalchemy.sql.dml.Delete"),))
    pred = _predicate(type_fqn="Delete")
    result = _evaluate_when_predicate(pred, _edge(), enrichment)
    assert result.status is PredicateStatus.PASSED


# -- alt_fqns -----------------------------------------------------------------


def test_type_predicate_alt_fqns_match() -> None:
    enrichment = TypeEnrichmentIndex(facts=(_fact(declared_type="c.D"),))
    pred = _predicate(type_fqn="a.B", alt_fqns=("c.D",))
    result = _evaluate_when_predicate(pred, _edge(), enrichment)
    assert result.status is PredicateStatus.PASSED


def test_type_predicate_alt_fqns_no_match() -> None:
    enrichment = TypeEnrichmentIndex(facts=(_fact(declared_type="x.Y"),))
    pred = _predicate(type_fqn="a.B", alt_fqns=("c.D",))
    result = _evaluate_when_predicate(pred, _edge(), enrichment)
    assert result.status is PredicateStatus.FAILED


# -- _type_matches unit tests -------------------------------------------------


def test_type_matches_exact() -> None:
    assert _type_matches("sqlalchemy.sql.dml.Delete", {"sqlalchemy.sql.dml.Delete"})


def test_type_matches_suffix_declared_shorter() -> None:
    assert _type_matches("Delete", {"sqlalchemy.sql.dml.Delete"})


def test_type_matches_suffix_fqn_shorter() -> None:
    assert _type_matches("sqlalchemy.sql.dml.Delete", {"Delete"})


def test_type_matches_no_match() -> None:
    assert not _type_matches("Update", {"sqlalchemy.sql.dml.Delete"})


def test_type_matches_no_partial_name_match() -> None:
    """'elete' should not match 'Delete' — suffix requires a dot boundary."""
    assert not _type_matches("elete", {"sqlalchemy.sql.dml.Delete"})
