"""Convert L1 type facts into first-class disagreement signals."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from flawed.core import Location, Provenance
from flawed.disagreement import (
    TypeCheckerObservation,
    TypeDisagreement,
    TypeDisagreementKind,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from flawed._index._type_enrichment import TypeEnrichmentIndex, TypeFact

_PROVENANCE = Provenance(
    source_layer="L2",
    interpreter="type_checker_disagreement",
    confidence=0.85,
    supporting_facts=("multiple concrete type-enrichment facts disagreed",),
)

_SCALAR_FAMILIES = {
    "str": "text",
    "builtins.str": "text",
    "bytes": "bytes",
    "builtins.bytes": "bytes",
    "int": "number",
    "builtins.int": "number",
    "float": "number",
    "builtins.float": "number",
    "decimal.Decimal": "number",
    "Decimal": "number",
    "bool": "boolean",
    "builtins.bool": "boolean",
}
_CONTAINER_MARKERS = (
    "dict",
    "mapping",
    "mutablemapping",
    "list",
    "sequence",
    "tuple",
    "set",
    "frozenset",
    "multidict",
)
_IDENTITY_MARKERS = (
    "account",
    "anonymous",
    "identity",
    "principal",
    "subject",
    "token",
    "user",
)


@dataclass(frozen=True)
class _FactGroup:
    expression: str
    file: str
    line: int
    column: int
    containing_function_fqn: str | None
    facts: tuple[TypeFact, ...]


def convert_type_disagreements(index: TypeEnrichmentIndex) -> tuple[TypeDisagreement, ...]:
    """Return concrete type-checker disagreement signals from an enrichment index."""
    groups = _group_concrete_facts(index.facts)
    disagreements: list[TypeDisagreement] = []
    for group in groups:
        representative_types = _representative_types(group.facts)
        if len(representative_types) < 2:
            continue
        first_fact = group.facts[0]
        kind = _classify(representative_types)
        disagreements.append(
            TypeDisagreement(
                expression=group.expression,
                location=Location(
                    file=first_fact.location.file,
                    line=first_fact.location.line,
                    column=first_fact.location.column,
                    end_line=first_fact.location.end_line,
                    end_column=first_fact.location.end_column,
                ),
                observations=tuple(
                    TypeCheckerObservation(
                        source_tool=fact.source_tool,
                        declared_type=fact.declared_type,
                    )
                    for fact in group.facts
                ),
                kind=kind,
                security_relevance=_security_relevance(kind),
                containing_function_fqn=group.containing_function_fqn,
                provenance=_PROVENANCE,
            )
        )
    return tuple(sorted(disagreements, key=_sort_key))


def _group_concrete_facts(facts: Iterable[TypeFact]) -> tuple[_FactGroup, ...]:
    grouped: dict[tuple[str, str, int, int, str | None], list[TypeFact]] = defaultdict(list)
    for fact in facts:
        if not fact.is_concrete:
            continue
        key = (
            fact.expression,
            fact.location.file,
            fact.location.line,
            fact.location.column,
            fact.containing_function_fqn,
        )
        grouped[key].append(fact)

    groups: list[_FactGroup] = []
    for (expression, file, line, column, containing_function_fqn), group_facts in grouped.items():
        if len(group_facts) < 2:
            continue
        groups.append(
            _FactGroup(
                expression=expression,
                file=file,
                line=line,
                column=column,
                containing_function_fqn=containing_function_fqn,
                facts=tuple(group_facts),
            )
        )
    return tuple(groups)


def _representative_types(facts: Iterable[TypeFact]) -> tuple[str, ...]:
    representatives: list[str] = []
    for fact in facts:
        if not any(_type_strings_agree(fact.declared_type, seen) for seen in representatives):
            representatives.append(fact.declared_type)
    return tuple(representatives)


def _classify(types: tuple[str, ...]) -> TypeDisagreementKind:
    lowered = tuple(type_text.lower() for type_text in types)
    if _has_optional_disagreement(lowered):
        return TypeDisagreementKind.OPTIONALITY
    if _has_container_shape_disagreement(lowered):
        return TypeDisagreementKind.CONTAINER_SHAPE
    if _has_scalar_kind_disagreement(types):
        return TypeDisagreementKind.SCALAR_KIND
    if _has_callable_disagreement(lowered):
        return TypeDisagreementKind.CALLABLE_SHAPE
    if _has_identity_disagreement(lowered):
        return TypeDisagreementKind.OBJECT_IDENTITY
    return TypeDisagreementKind.UNKNOWN


def _has_optional_disagreement(types: tuple[str, ...]) -> bool:
    nullable_flags = tuple(_type_allows_none(type_text) for type_text in types)
    return any(nullable_flags) and not all(nullable_flags)


def _type_allows_none(type_text: str) -> bool:
    tokens = {token.lower() for token in re.findall(r"[A-Za-z_][\w.]*", type_text)}
    return any(_is_none_token(token) or _is_optional_token(token) for token in tokens)


def _is_none_token(token: str) -> bool:
    stripped = token.removeprefix("typing.").removeprefix("builtins.")
    return stripped in {"none", "nonetype"} or stripped.endswith(".nonetype")


def _is_optional_token(token: str) -> bool:
    stripped = token.removeprefix("typing.").removeprefix("builtins.")
    return stripped == "optional"


def _has_container_shape_disagreement(types: tuple[str, ...]) -> bool:
    container_kinds = {
        marker for type_text in types for marker in _CONTAINER_MARKERS if marker in type_text
    }
    if len(container_kinds) > 1:
        return True
    if len(container_kinds) == 1:
        return len({_strip_qualifiers(type_text) for type_text in types}) > 1
    return False


def _has_scalar_kind_disagreement(types: tuple[str, ...]) -> bool:
    families = {
        family
        for type_text in types
        for spelling, family in _SCALAR_FAMILIES.items()
        if _type_mentions(type_text, spelling)
    }
    return len(families) > 1


def _has_callable_disagreement(types: tuple[str, ...]) -> bool:
    return any("callable" in type_text for type_text in types) and any(
        "callable" not in type_text for type_text in types
    )


def _has_identity_disagreement(types: tuple[str, ...]) -> bool:
    matching = {
        marker for type_text in types for marker in _IDENTITY_MARKERS if marker in type_text
    }
    return bool(matching) and len({_strip_qualifiers(type_text) for type_text in types}) > 1


def _security_relevance(kind: TypeDisagreementKind) -> str:
    if kind is TypeDisagreementKind.OPTIONALITY:
        return "nullable-vs-non-null disagreement can hide missing validation or guard bypasses"
    if kind is TypeDisagreementKind.CONTAINER_SHAPE:
        return "container-shape disagreement can hide single-vs-multi value input ambiguity"
    if kind is TypeDisagreementKind.SCALAR_KIND:
        return "scalar-family disagreement can hide string/number/bytes comparison ambiguity"
    if kind is TypeDisagreementKind.CALLABLE_SHAPE:
        return "callable-vs-value disagreement can hide dynamic dispatch ambiguity"
    if kind is TypeDisagreementKind.OBJECT_IDENTITY:
        return "identity-object disagreement can hide subject/principal ambiguity"
    return "concrete type-checker disagreement requires manual security review"


def _type_mentions(type_text: str, spelling: str) -> bool:
    lowered = type_text.lower()
    spelling = spelling.lower()
    return lowered == spelling or lowered.endswith(f".{spelling}") or spelling in lowered


def _strip_qualifiers(type_text: str) -> str:
    return type_text.replace("typing.", "").replace("builtins.", "")


def _type_strings_agree(left: str, right: str) -> bool:
    return left == right or left.endswith(f".{right}") or right.endswith(f".{left}")


def _sort_key(disagreement: TypeDisagreement) -> tuple[str, int, int, str]:
    return (
        disagreement.location.file,
        disagreement.location.line,
        disagreement.location.column,
        disagreement.expression,
    )
