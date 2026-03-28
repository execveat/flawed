"""Compound-category security checks are credited to each component.

flask_wtf ``validate_on_submit`` emits the compound category ``"CSRF|FORM_VALIDATION"``;
single-category coverage queries (``CSRF``, ``FORM_VALIDATION``) must recognise
it, otherwise a recognised CSRF+validation guard is never credited and the missing-coverage
finding fires as a false positive (FLAW-274). FN-safe: a check only declares a component it
genuinely provides.
"""

from dataclasses import dataclass

from flawed._semantic._scope import _is_security_check


@dataclass(frozen=True)
class _FakeCheck:
    category: str


def test_exact_single_category_still_matches() -> None:
    check = _FakeCheck(category="CSRF")
    assert _is_security_check(check, "CSRF")
    assert not _is_security_check(check, "FORM_VALIDATION")


def test_none_category_matches_any_check() -> None:
    assert _is_security_check(_FakeCheck(category="CSRF"), None)
    assert _is_security_check(_FakeCheck(category="CSRF|FORM_VALIDATION"), None)


def test_compound_category_credited_to_each_component() -> None:
    check = _FakeCheck(category="CSRF|FORM_VALIDATION")
    assert _is_security_check(check, "CSRF")
    assert _is_security_check(check, "FORM_VALIDATION")


def test_compound_category_does_not_match_an_unlisted_component() -> None:
    check = _FakeCheck(category="CSRF|FORM_VALIDATION")
    assert not _is_security_check(check, "SCHEMA_VALIDATION")


def test_object_without_a_string_category_is_not_a_check() -> None:
    assert not _is_security_check(object(), "CSRF")
