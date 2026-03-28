"""Tests for the canonical ``dedupe_gaps`` function in ``_scope.py``.

Verifies deduplication by identity key, insertion-order preservation,
and correct handling of None fields and empty inputs.
"""

from __future__ import annotations

from flawed._semantic._scope import ConcreteCodeScope, dedupe_gaps
from flawed.core import AnalysisGap, GapKind


def _gap(
    kind: GapKind = GapKind.SYMBOL_UNRESOLVED,
    message: str = "test gap",
    *,
    affected_file: str | None = "test.py",
    affected_function: str | None = None,
    source_error: str | None = None,
) -> AnalysisGap:
    return AnalysisGap(
        kind=kind,
        message=message,
        affected_file=affected_file,
        affected_function=affected_function,
        source_error=source_error,
    )


class TestDedupeGapsEmpty:
    def test_empty_input(self) -> None:
        assert dedupe_gaps(()) == ()


class TestDedupeGapsSingleElement:
    def test_single_gap_passes_through(self) -> None:
        g = _gap()
        result = dedupe_gaps((g,))
        assert result == (g,)


class TestDedupeGapsDuplicateRemoval:
    def test_exact_duplicates_reduced_to_one(self) -> None:
        g1 = _gap(message="same")
        g2 = _gap(message="same")
        result = dedupe_gaps((g1, g2))
        assert len(result) == 1
        assert result[0] is g1

    def test_three_identical_gaps_reduced_to_one(self) -> None:
        g = _gap(message="dup")
        result = dedupe_gaps((g, g, g))
        assert len(result) == 1


class TestDedupeGapsDistinctFields:
    def test_different_kind_kept(self) -> None:
        g1 = _gap(kind=GapKind.SYMBOL_UNRESOLVED, message="x")
        g2 = _gap(kind=GapKind.PARSE_FAILURE, message="x")
        result = dedupe_gaps((g1, g2))
        assert len(result) == 2

    def test_different_message_kept(self) -> None:
        g1 = _gap(message="alpha")
        g2 = _gap(message="beta")
        result = dedupe_gaps((g1, g2))
        assert len(result) == 2

    def test_different_affected_file_kept(self) -> None:
        g1 = _gap(affected_file="a.py")
        g2 = _gap(affected_file="b.py")
        result = dedupe_gaps((g1, g2))
        assert len(result) == 2

    def test_different_affected_function_kept(self) -> None:
        g1 = _gap(affected_function="app.foo")
        g2 = _gap(affected_function="app.bar")
        result = dedupe_gaps((g1, g2))
        assert len(result) == 2

    def test_different_source_error_kept(self) -> None:
        g1 = _gap(source_error="err1")
        g2 = _gap(source_error="err2")
        result = dedupe_gaps((g1, g2))
        assert len(result) == 2


class TestDedupeGapsInsertionOrder:
    def test_first_occurrence_wins(self) -> None:
        g1 = _gap(message="same", affected_file="a.py")
        g2 = _gap(message="same", affected_file="a.py")
        g3 = _gap(message="other")
        result = dedupe_gaps((g1, g2, g3))
        assert result == (g1, g3)
        assert result[0] is g1

    def test_interleaved_duplicates_preserve_first(self) -> None:
        a = _gap(message="a")
        b = _gap(message="b")
        result = dedupe_gaps((a, b, a, b, a))
        assert result == (a, b)


class TestDedupeGapsNoneFields:
    def test_none_affected_file_handled(self) -> None:
        g1 = _gap(affected_file=None, message="x")
        g2 = _gap(affected_file=None, message="x")
        result = dedupe_gaps((g1, g2))
        assert len(result) == 1

    def test_none_vs_value_treated_as_distinct(self) -> None:
        g1 = _gap(affected_file=None, message="x")
        g2 = _gap(affected_file="f.py", message="x")
        result = dedupe_gaps((g1, g2))
        assert len(result) == 2

    def test_all_none_optional_fields(self) -> None:
        g = _gap(affected_file=None, affected_function=None, source_error=None)
        result = dedupe_gaps((g, g))
        assert len(result) == 1


class TestScopeGapPropagation:
    """Gaps survive deduplication and are accessible via ConcreteCodeScope.gaps."""

    def test_scope_exposes_gap_tuple(self) -> None:
        g = _gap()
        scope = ConcreteCodeScope(gaps=(g,))
        assert scope.gaps == (g,)

    def test_scope_with_deduped_gaps(self) -> None:
        g1 = _gap(message="alpha")
        g2 = _gap(message="alpha")
        g3 = _gap(message="beta")
        deduped = dedupe_gaps((g1, g2, g3))
        scope = ConcreteCodeScope(gaps=deduped)
        assert len(scope.gaps) == 2
        assert scope.gaps[0] is g1
        assert scope.gaps[1] is g3

    def test_empty_scope_has_empty_gaps(self) -> None:
        scope = ConcreteCodeScope()
        assert scope.gaps == ()
