"""Tests for no-argument reads() and effects() on ConcreteCodeScope.

P1.4: Make source/selector optional — when called with no arguments,
return all items unfiltered.
"""

from __future__ import annotations

from flawed._semantic._scope import ConcreteCodeScope
from flawed.core import Location, Provenance
from flawed.effects import Effect, EffectCategory, State, StateScope
from flawed.function import Function, FunctionKind
from flawed.inputs import AccessPattern, Cardinality, Form, InputRead, Json, Query

_LOC = Location(file="app.py", line=1, column=0)
_PROV = Provenance(source_layer="L2", interpreter="test", confidence=1.0)
_FN = Function(
    fqn="app.handler",
    name="handler",
    params=(),
    kind=FunctionKind.TOP_LEVEL,
    parent_class=None,
    parent_function=None,
    location=_LOC,
    provenance=_PROV,
)


def _read(source: object) -> InputRead:
    """Build a minimal InputRead for testing."""
    return InputRead(
        source=source,  # type: ignore[arg-type]
        access_pattern=AccessPattern.ATTRIBUTE,
        cardinality=Cardinality.SINGLE,
        function=_FN,
        location=_LOC,
        expression="request.x",
        provenance=_PROV,
    )


def _effect(category: EffectCategory, scope: StateScope | None = None) -> Effect:
    """Build a minimal Effect for testing."""
    return Effect(
        category=category,
        function=_FN,
        location=_LOC,
        expression="db.commit()",
        provenance=_PROV,
        scope=scope,
    )


class TestReadsNoArg:
    """reads() with no arguments returns all input reads."""

    def test_reads_no_arg_returns_all(self) -> None:
        json_read = _read(Json())
        query_read = _read(Query())
        form_read = _read(Form())
        scope = ConcreteCodeScope(input_reads=(json_read, query_read, form_read))
        result = list(scope.reads())
        assert len(result) == 3

    def test_reads_with_arg_still_filters(self) -> None:
        json_read = _read(Json())
        query_read = _read(Query())
        scope = ConcreteCodeScope(input_reads=(json_read, query_read))
        result = list(scope.reads(Json()))
        assert len(result) == 1
        assert result[0].source == Json()

    def test_reads_no_arg_empty_scope(self) -> None:
        scope = ConcreteCodeScope()
        result = list(scope.reads())
        assert len(result) == 0


class TestEffectsNoArg:
    """effects() with no arguments returns all effects."""

    def test_effects_no_arg_returns_all(self) -> None:
        state_w = _effect(EffectCategory.STATE_WRITE, StateScope.SESSION)
        state_r = _effect(EffectCategory.STATE_READ, StateScope.REQUEST)
        db_w = _effect(EffectCategory.DB_WRITE)
        scope = ConcreteCodeScope(effects=(state_w, state_r, db_w))
        result = list(scope.effects())
        assert len(result) == 3

    def test_effects_with_arg_still_filters(self) -> None:
        state_w = _effect(EffectCategory.STATE_WRITE, StateScope.SESSION)
        db_w = _effect(EffectCategory.DB_WRITE)
        scope = ConcreteCodeScope(effects=(state_w, db_w))
        result = list(scope.effects(State.write()))
        assert len(result) == 1
        assert result[0].category == EffectCategory.STATE_WRITE

    def test_effects_no_arg_empty_scope(self) -> None:
        scope = ConcreteCodeScope()
        result = list(scope.effects())
        assert len(result) == 0

    def test_effects_no_arg_bypasses_category_gate(self) -> None:
        """No-arg effects() must return DB_WRITE without NotImplementedError."""
        db_w = _effect(EffectCategory.DB_WRITE)
        resp_w = _effect(EffectCategory.RESPONSE_WRITE)
        scope = ConcreteCodeScope(effects=(db_w, resp_w))
        # Currently raises NotImplementedError for non-state categories
        result = list(scope.effects())
        assert len(result) == 2
