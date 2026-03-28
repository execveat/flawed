"""Structural (shape-based, name-independent) URL-safety-guard recognition.

Named URL-safety guards (``is_safe_url`` / ``is_valid_url`` / ...) are recognised
declaratively via a provider :class:`ValidatedValueGuardPattern` ``names=`` list
(see ``providers/flask_core.py``).  That covers the common idiom because the
canonical snippet is copied verbatim across projects — but it has a
false-negative cliff: an *arbitrarily-named* project-local guard (a renamed
helper, or a minified ``n``) matches no name list, so its guarded redirect is
flagged as an open-redirect false positive (the class FLAW-186 / FLAW-037
identified, shared with CodeQL).

This module closes that gap by recognising a guard from the **shape** of its
body rather than its name, and emitting the *same* :class:`ValidatedValue` fact
the named path produces.  All downstream consumption — crucially
``_collections._sink_target_is_validated`` — is therefore unchanged: a
structurally-recognised guard suppresses exactly the sinks a same-shaped named
guard would.

The recognised shape is the stable invariant behind the canonical
``url_has_allowed_host_and_scheme`` / ``is_safe_url`` allow-list helpers that
web ecosystems copy verbatim:

* the function takes the candidate URL as its first parameter, and
* its body parses that URL (``urlparse`` / ``urlsplit`` / ``url_parse``), and
* it inspects a host/scheme component (``.netloc`` / ``.scheme`` / ``.hostname``), and
* the safety verdict **depends on** that component — i.e. the component appears
  in a branch test (``if netloc not in allowed: return False``) or in a
  value-position boolean expression (``return scheme in (...) and
  netloc == ...``).

The verdict-dependence requirement is what keeps the recogniser sound: a
function that merely *touches* ``.netloc`` (e.g. logs it) but returns a constant
is **not** recognised, so it does not over-suppress.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from flawed._semantic._conversion_utils import find_argument as _argument
from flawed._semantic._validation_guard_conversion import (
    ValidationGuardConversionResult,
    build_validated_value_from_call,
)
from flawed.core import Provenance

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flawed._index import CodeIndex
    from flawed._index._types import CallEdge
    from flawed.function import Function
    from flawed.validation import ValidatedValue

# urllib.parse.urlparse / urlsplit and werkzeug's url_parse.
_URL_PARSER_NAMES = frozenset({"urlparse", "urlsplit", "url_parse"})

# Host/scheme components whose inspection characterises a URL-safety guard.
_URL_PART_ATTRS = ("netloc", "scheme", "hostname")

# Matches a URL-part component as a whole word inside a condition / predicate
# expression, so a variable like ``schemexyz`` does not spuriously match.
_URL_PART_RE = re.compile(r"\b(?:netloc|scheme|hostname)\b")

_STRUCTURAL_GUARD_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="structural_url_guards",
    confidence=0.85,
    supporting_facts=(
        "function body parses arg 0 as a URL and gates its boolean verdict on a "
        "host/scheme component (shape-recognised URL-safety guard)",
    ),
)

_STRUCTURAL_GUARD_DESCRIPTION = (
    "Shape-recognised URL-safety guard: validates the redirect target against a "
    "host/scheme allow-list (name-independent; see FLAW-186)."
)

_SAFE_SINK_KINDS = ("OPEN_REDIRECT",)


def _call_short_name(edge: CallEdge) -> str | None:
    """Best-effort callee short name for an edge (resolved FQN or call text)."""
    if edge.callee_fqn:
        return edge.callee_fqn.rsplit(".", 1)[-1]
    expr = edge.call_expression
    if expr:
        head = expr.split("(", 1)[0].strip()
        if head:
            return head.rsplit(".", 1)[-1]
    return None


def _parses_a_url(idx: CodeIndex, fqn: str) -> bool:
    return any(
        _call_short_name(edge) in _URL_PARSER_NAMES for edge in idx.call_graph.edges_from(fqn)
    )


def _reads_url_part(idx: CodeIndex, fqn: str) -> bool:
    return any(idx.attributes.named(attr).in_function(fqn).exists() for attr in _URL_PART_ATTRS)


def _verdict_depends_on_url_part(idx: CodeIndex, fqn: str) -> bool:
    """True when a branch test or value-position predicate references a URL part.

    This is the soundness gate: it distinguishes a real guard (whose boolean
    result is decided by the host/scheme check) from a function that merely
    inspects ``.netloc`` without letting it determine the return value.
    """
    cfg = idx.cfg(fqn)
    if cfg is None:
        return False
    for block in cfg.blocks:
        if block.condition_expr is not None and _URL_PART_RE.search(block.condition_expr):
            return True
        for predicate in block.value_predicates:
            if _URL_PART_RE.search(predicate.expression):
                return True
    return False


def recognize_structural_url_guards(idx: CodeIndex) -> frozenset[str]:
    """Return FQNs of project-local functions shaped like URL-safety guards."""
    guards: set[str] = set()
    for function in idx.functions.all():
        if not function.params:
            continue
        fqn = function.fqn
        if not _parses_a_url(idx, fqn):
            continue
        if not _reads_url_part(idx, fqn):
            continue
        if not _verdict_depends_on_url_part(idx, fqn):
            continue
        guards.add(fqn)
    return frozenset(guards)


def convert_structural_url_guards(
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> ValidationGuardConversionResult:
    """Emit :class:`ValidatedValue` facts for calls to shape-recognised guards.

    Mirrors :func:`_validation_guard_conversion.convert_validation_guard_matches`
    for the structural case: each call ``guard(target)`` validates ``target``
    (arg 0) for ``OPEN_REDIRECT``.  Returns no synthetic conditions — sink
    suppression is driven by the validated values alone — and only the facts
    whose caller has a converted L3 function (others are silently skipped, never
    fabricated, preserving fail-closed semantics: an unmodelled caller yields no
    suppression rather than a spurious one).
    """
    guard_fqns = recognize_structural_url_guards(idx)
    values_by_function: dict[str, list[ValidatedValue]] = {}
    if not guard_fqns:
        return ValidationGuardConversionResult(
            validated_values_by_function=values_by_function,
            conditions_by_function={},
        )

    for edge in idx.call_graph.edges:
        if edge.callee_fqn not in guard_fqns:
            continue
        function = functions_by_fqn.get(edge.caller_fqn)
        if function is None:
            continue
        argument = _argument(edge, position=0, keyword=None)
        if argument is None:
            continue
        value = build_validated_value_from_call(
            edge,
            function,
            argument=argument,
            safe_for_sink_kinds=_SAFE_SINK_KINDS,
            validated_when=True,
            description=_STRUCTURAL_GUARD_DESCRIPTION,
            provenance=_STRUCTURAL_GUARD_PROVENANCE,
            idx=idx,
        )
        values_by_function.setdefault(function.fqn, []).append(value)

    return ValidationGuardConversionResult(
        validated_values_by_function=values_by_function,
        conditions_by_function={},
    )
