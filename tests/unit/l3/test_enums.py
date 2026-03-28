"""Verify enum values and completeness."""

from __future__ import annotations


def test_http_method_values() -> None:
    from flawed.route import HttpMethod

    expected = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
    actual = {m.value for m in HttpMethod}
    assert actual == expected


def test_http_method_aliases() -> None:
    from flawed.route import (
        DELETE,
        GET,
        HEAD,
        OPTIONS,
        PATCH,
        POST,
        PUT,
        HttpMethod,
    )

    assert GET == HttpMethod.GET
    assert POST == HttpMethod.POST
    assert PUT == HttpMethod.PUT
    assert PATCH == HttpMethod.PATCH
    assert DELETE == HttpMethod.DELETE
    assert OPTIONS == HttpMethod.OPTIONS
    assert HEAD == HttpMethod.HEAD


def test_function_kind_values() -> None:
    from flawed.function import FunctionKind

    expected = {"top_level", "method", "nested", "lambda", "closure"}
    actual = {k.value for k in FunctionKind}
    assert actual == expected


def test_access_pattern_values() -> None:
    from flawed.inputs import AccessPattern

    expected = {"get", "subscript", "getlist", "attribute", "iteration", "membership", "unknown"}
    actual = {p.value for p in AccessPattern}
    assert actual == expected


def test_cardinality_values() -> None:
    from flawed.inputs import Cardinality

    expected = {"single", "multi", "unknown"}
    actual = {c.value for c in Cardinality}
    assert actual == expected


def test_effect_category_values() -> None:
    from flawed.effects import EffectCategory

    expected = {
        "db_write",
        "db_delete",
        "db_read",
        "file_write",
        "file_read",
        "cache_write",
        "cache_read",
        "state_write",
        "state_read",
        "config_write",
        "response_write",
        "outbound_request",
        "outbound_request_configured",
        "notification",
        "principal_attr_write",
    }
    actual = {c.value for c in EffectCategory}
    assert actual == expected


def test_condition_kind_values() -> None:
    from flawed.conditions import ConditionKind

    expected = {
        "comparison",
        "membership",
        "identity",
        "truthiness",
        "call_result",
        "compound",
        "unknown",
    }
    actual = {k.value for k in ConditionKind}
    assert actual == expected


def test_denial_kind_values() -> None:
    from flawed.conditions import DenialKind

    expected = {
        "abort",
        "return_error",
        "raise_",
        "redirect",
        "early_return",
        "unknown",
    }
    actual = {k.value for k in DenialKind}
    assert actual == expected


def test_gap_kind_values() -> None:
    from flawed.core import GapKind

    expected = {
        "parse_failure",
        "cfg_unavailable",
        "cfg_reconstruction_failure",
        "symbol_unresolved",
        "inference_failure",
        "call_graph_incomplete",
        "interpreter_error",
        "value_flow_incomplete",
    }
    actual = {k.value for k in GapKind}
    assert actual == expected
