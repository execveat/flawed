"""Tests for scope construction with shared per-function observations.

Verifies that ``_scope_parts_for_functions`` correctly gathers and
combines observations from multiple functions, including gap propagation
for functions with gaps and empty/missing entries.
"""

from __future__ import annotations

from flawed._semantic import _scope_parts_for_functions
from flawed._semantic._collections import ConcreteFunctionCollection
from flawed._semantic._enriched import EnrichedFunction
from flawed._semantic._scope import ConcreteCodeScope, dedupe_gaps
from flawed.core import AnalysisGap, GapKind, Location, Provenance
from flawed.effects import Effect, EffectCategory
from flawed.function import Function, FunctionKind
from flawed.inputs import AccessPattern, Cardinality, InputRead, Query

_EMPTY_FN_COLLECTION = ConcreteFunctionCollection(())


def _loc(file: str = "test.py", line: int = 1) -> Location:
    return Location(file=file, line=line, column=0)


def _prov() -> Provenance:
    return Provenance(source_layer="L2", interpreter="test", confidence=1.0)


def _function(
    fqn: str,
    *,
    gaps: tuple[AnalysisGap, ...] = (),
) -> EnrichedFunction:
    """Create an EnrichedFunction with decorators/gaps/calls wired up."""
    name = fqn.rsplit(".", 1)[-1]
    from flawed._semantic._collections import ConcreteDecoratorCollection

    base = Function(
        fqn=fqn,
        name=name,
        params=(),
        kind=FunctionKind.TOP_LEVEL,
        parent_class=None,
        parent_function=None,
        location=_loc(),
        provenance=_prov(),
    )
    return EnrichedFunction.from_base(
        base,
        decorators=ConcreteDecoratorCollection(()),
        gaps=gaps,
        calls=_EMPTY_FN_COLLECTION,
        called_by=_EMPTY_FN_COLLECTION,
    )


def _input_read(fn: Function) -> InputRead:
    return InputRead(
        source=Query(),
        access_pattern=AccessPattern.GET,
        cardinality=Cardinality.SINGLE,
        function=fn,
        location=fn.location,
        expression='request.args.get("x")',
        provenance=_prov(),
    )


def _effect(fn: Function) -> Effect:
    return Effect(
        category=EffectCategory.STATE_WRITE,
        function=fn,
        location=fn.location,
        expression='session["k"] = v',
        provenance=_prov(),
    )


def _gap(
    message: str = "test gap",
    affected_file: str | None = "test.py",
) -> AnalysisGap:
    return AnalysisGap(
        kind=GapKind.SYMBOL_UNRESOLVED,
        message=message,
        affected_file=affected_file,
    )


class TestScopePartsForFunctions:
    """Tests for _scope_parts_for_functions gathering logic."""

    def test_single_function_observations_collected(self) -> None:
        fn_a = _function("app.a")
        read_a = _input_read(fn_a)
        effect_a = _effect(fn_a)

        reads, effects, _sinks, _sites, _conds, _decs, gaps = _scope_parts_for_functions(
            ("app.a",),
            input_reads_by_function={"app.a": [read_a]},
            effects_by_function={"app.a": [effect_a]},
            sinks_by_function={},
            conditions_by_function={},
            call_sites_by_caller={},
            functions_by_fqn={"app.a": fn_a},
        )

        assert read_a in reads
        assert effect_a in effects
        assert len(gaps) == 0

    def test_two_functions_observations_combined(self) -> None:
        fn_a = _function("app.a")
        fn_b = _function("app.b")
        read_a = _input_read(fn_a)
        effect_b = _effect(fn_b)

        reads, effects, *_rest = _scope_parts_for_functions(
            ("app.a", "app.b"),
            input_reads_by_function={"app.a": [read_a]},
            effects_by_function={"app.b": [effect_b]},
            sinks_by_function={},
            conditions_by_function={},
            call_sites_by_caller={},
            functions_by_fqn={"app.a": fn_a, "app.b": fn_b},
        )

        assert read_a in reads
        assert effect_b in effects

    def test_shared_helper_observations_included(self) -> None:
        fn_route = _function("app.route_handler")
        fn_helper = _function("app.helper")
        read_helper = _input_read(fn_helper)

        reads, *_rest = _scope_parts_for_functions(
            ("app.route_handler", "app.helper"),
            input_reads_by_function={"app.helper": [read_helper]},
            effects_by_function={},
            sinks_by_function={},
            conditions_by_function={},
            call_sites_by_caller={},
            functions_by_fqn={
                "app.route_handler": fn_route,
                "app.helper": fn_helper,
            },
        )

        assert read_helper in reads

    def test_gap_bearing_function_gaps_included(self) -> None:
        g = _gap(message="fn has gap")
        fn = _function("app.fn", gaps=(g,))

        _, _, _, _, _, _, gaps = _scope_parts_for_functions(
            ("app.fn",),
            input_reads_by_function={},
            effects_by_function={},
            sinks_by_function={},
            conditions_by_function={},
            call_sites_by_caller={},
            functions_by_fqn={"app.fn": fn},
        )

        assert g in gaps

    def test_empty_fqn_list_produces_empty_results(self) -> None:
        result = _scope_parts_for_functions(
            (),
            input_reads_by_function={},
            effects_by_function={},
            sinks_by_function={},
            conditions_by_function={},
            call_sites_by_caller={},
            functions_by_fqn={},
        )

        assert all(part == [] for part in result)

    def test_unknown_fqn_produces_no_observations(self) -> None:
        result = _scope_parts_for_functions(
            ("app.missing",),
            input_reads_by_function={},
            effects_by_function={},
            sinks_by_function={},
            conditions_by_function={},
            call_sites_by_caller={},
            functions_by_fqn={},
        )

        assert all(part == [] for part in result)


class TestScopeWithDeduplicatedGaps:
    """ConcreteCodeScope constructed with deduped gap tuples."""

    def test_scope_from_deduped_gaps_preserves_unique(self) -> None:
        g1 = _gap(message="alpha")
        g2 = _gap(message="alpha")
        g3 = _gap(message="beta")
        scope = ConcreteCodeScope(gaps=dedupe_gaps((g1, g2, g3)))
        assert len(scope.gaps) == 2
        assert scope.gaps[0].message == "alpha"
        assert scope.gaps[1].message == "beta"

    def test_scope_with_multiple_function_gaps(self) -> None:
        gap_a = _gap(message="gap_a", affected_file="a.py")
        gap_b = _gap(message="gap_b", affected_file="b.py")
        fn_a = _function("app.a", gaps=(gap_a,))
        fn_b = _function("app.b", gaps=(gap_b,))

        _, _, _, _, _, _, gaps = _scope_parts_for_functions(
            ("app.a", "app.b"),
            input_reads_by_function={},
            effects_by_function={},
            sinks_by_function={},
            conditions_by_function={},
            call_sites_by_caller={},
            functions_by_fqn={"app.a": fn_a, "app.b": fn_b},
        )

        scope = ConcreteCodeScope(gaps=dedupe_gaps(tuple(gaps)))
        assert len(scope.gaps) == 2
        messages = {g.message for g in scope.gaps}
        assert messages == {"gap_a", "gap_b"}
