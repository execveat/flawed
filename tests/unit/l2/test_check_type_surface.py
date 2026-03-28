"""FLAW-257: ``.checks()`` yields a typed ``Check`` view.

The nullability crash class (`'<' not supported between NoneType and str`) was
possible because rules reached ``provider_id`` via ``getattr(...) -> Any``: the
``Condition`` they were handed had no typed ``provider_id`` and a ``str | None``
``category``, so the checker was blind to the nullability. ``.checks()`` now
yields :class:`~flawed.conditions.Check`, which surfaces both as typed members.

These tests pin the *structural* guarantees that make the typed surface
truthful. The *behavioural* proof (the rules run and produce findings without
the ``TypeError``) lives in ``test_r07a_conflicting_auth.py`` /
``test_r07c_dual_validation.py``, which now exercise ``check.provider_id``
typed access end to end.
"""

from __future__ import annotations

from flawed._semantic._check_conversion import ConcreteCondition
from flawed.conditions import Check, Condition


def test_check_is_a_condition() -> None:
    # A Check IS a Condition: rules/collections typed on Condition still accept
    # checks, so narrowing .checks() to Check is non-breaking.
    assert issubclass(Check, Condition)


def test_runtime_check_object_is_a_check() -> None:
    # The object .checks() yields at runtime must BE a Check, so the typed
    # surface rules see (check.provider_id, a str category) is truthful by
    # construction rather than an unchecked promise.
    assert issubclass(ConcreteCondition, Check)


def test_check_exposes_nullable_provider_id() -> None:
    # provider_id is a first-class typed str | None on Check -> the checker sees
    # the nullability and forces rules to handle None (the nullability fix).
    field = Check.__dataclass_fields__["provider_id"]
    assert "None" in str(field.type)


def test_check_narrows_category_to_str() -> None:
    # A recognised check always carries a category, so Check narrows it from
    # Condition.category (str | None) to a required str.
    field = Check.__dataclass_fields__["category"]
    assert "None" not in str(field.type)


def test_condition_category_remains_optional() -> None:
    # The generic Condition is unchanged: structural conditions still carry an
    # optional category.
    field = Condition.__dataclass_fields__["category"]
    assert "None" in str(field.type)


def test_concrete_condition_inherits_check_fields() -> None:
    fields = ConcreteCondition.__dataclass_fields__
    assert "provider_id" in fields
    assert "category" in fields
