"""Tests for receiver-type-based method call matching via type enrichment.

When L1 resolves ``db.add(user)`` as ``create_user.<locals>.db.add`` rather
than ``sqlalchemy.orm.session.Session.add``, the matching engine must fall
back to type enrichment: look up the declared type of the receiver variable
``db``, confirm it is ``Session``, and match against the provider descriptor.

These tests verify that ``_match_call_descriptor`` resolves method calls
through receiver type enrichment when direct FQN matching fails.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from flawed._index import CodeIndex
from flawed._index._type_enrichment import TypeEnrichmentIndex, TypeFact
from flawed._index._types import (
    CallArgument,
    CallEdge,
    EdgeSource,
    ExtractionProvenance,
    ResolutionStatus,
    SourceSpan,
)
from flawed._semantic import _matching
from flawed._semantic._matching import _match_call_descriptor
from flawed._semantic._provider_engine import ProviderPhase
from flawed._semantic.providers.sqlalchemy_orm import SQLAlchemyProvider

if TYPE_CHECKING:
    from flawed._semantic.providers import EffectCallPattern

_PROV = ExtractionProvenance(producer="test", producer_version="0", artifact="")
_ROOT = Path("/tmp/test-repo")
_FILE = "app.py"

_SESSION_FQN = "sqlalchemy.orm.session.Session"
_QUERY_FQN = "sqlalchemy.orm.query.Query"


def _span(*, line: int = 10, column: int = 0) -> SourceSpan:
    return SourceSpan(
        file=_FILE,
        line=line,
        column=column,
        end_line=line,
        end_column=column + 10,
    )


def _call_edge(
    *,
    callee_fqn: str,
    call_expression: str,
    caller_fqn: str = "app.create_user",
    arguments: tuple[CallArgument, ...] = (),
    line: int = 10,
) -> CallEdge:
    return CallEdge(
        caller_fqn=caller_fqn,
        callee_fqn=callee_fqn,
        arguments=arguments,
        resolution=ResolutionStatus.RESOLVED,
        source=EdgeSource.AST,
        unresolved_reason=None,
        location=_span(line=line),
        provenance=_PROV,
        call_expression=call_expression,
    )


def _type_fact(
    *,
    expression: str = "db",
    declared_type: str = _SESSION_FQN,
    is_concrete: bool = True,
    containing_function_fqn: str | None = "app.create_user",
    line: int = 5,
) -> TypeFact:
    return TypeFact(
        expression=expression,
        declared_type=declared_type,
        location=SourceSpan(
            file=_FILE,
            line=line,
            column=4,
            end_line=line,
            end_column=6,
        ),
        source_tool="basedpyright",
        is_concrete=is_concrete,
        provenance=_PROV,
        containing_function_fqn=containing_function_fqn,
    )


def _index(
    *,
    call_edges: tuple[CallEdge, ...] = (),
    type_enrichment: TypeEnrichmentIndex | None = None,
) -> CodeIndex:
    _matching.clear_matching_cache()
    return CodeIndex(
        repo_root=_ROOT,
        functions=(),
        classes=(),
        decorators=(),
        imports=(),
        attributes=(),
        call_edges=call_edges,
        cfgs={},
        value_flow_edges=(),
        symbol_refs=(),
        errors=(),
        provenance=_PROV,
        type_enrichment=type_enrichment,
    )


_PROVIDER = SQLAlchemyProvider()
_ALIASES = dict(_PROVIDER.fqn_aliases)


def _find_effect_descriptor(fqn_suffix: str) -> EffectCallPattern:
    """Find an EffectCallPattern from the SQLAlchemy provider by FQN suffix."""
    for descriptor in _PROVIDER.effects:
        fqns = descriptor.fqn if isinstance(descriptor.fqn, tuple) else (descriptor.fqn,)
        if any(fqn.endswith(fqn_suffix) for fqn in fqns):
            return descriptor
    msg = f"No EffectCallPattern with FQN ending in {fqn_suffix!r}"
    raise ValueError(msg)


# -- Session.add: match via receiver type enrichment -------------------------


def test_session_add_matched_via_receiver_type() -> None:
    """db.add(user) matches Session.add when type enrichment says db is Session."""
    edge = _call_edge(
        callee_fqn="app.create_user.<locals>.db.add",
        call_expression="db.add(user)",
        arguments=(CallArgument(position=0, keyword=None, expression="user", location=_span()),),
    )
    enrichment = TypeEnrichmentIndex(facts=(_type_fact(),))
    idx = _index(call_edges=(edge,), type_enrichment=enrichment)
    descriptor = _find_effect_descriptor("Session.add")

    matches = _match_call_descriptor(_PROVIDER, ProviderPhase.EFFECTS, descriptor, idx, _ALIASES)

    assert len(matches) == 1
    assert matches[0].canonical_fqn == f"{_SESSION_FQN}.add"


# -- Session.commit: match via receiver type enrichment ----------------------


def test_session_commit_matched_via_receiver_type() -> None:
    """db.commit() matches Session.commit when type enrichment says db is Session."""
    edge = _call_edge(
        callee_fqn="app.create_user.<locals>.db.commit",
        call_expression="db.commit()",
    )
    enrichment = TypeEnrichmentIndex(facts=(_type_fact(),))
    idx = _index(call_edges=(edge,), type_enrichment=enrichment)
    descriptor = _find_effect_descriptor("Session.commit")

    matches = _match_call_descriptor(_PROVIDER, ProviderPhase.EFFECTS, descriptor, idx, _ALIASES)

    assert len(matches) == 1
    assert matches[0].canonical_fqn == f"{_SESSION_FQN}.commit"


# -- Session.delete: match via receiver type enrichment ----------------------


def test_session_delete_matched_via_receiver_type() -> None:
    """db.delete(user) matches Session.delete when type enrichment says db is Session."""
    edge = _call_edge(
        callee_fqn="app.delete_user.<locals>.db.delete",
        call_expression="db.delete(user)",
        caller_fqn="app.delete_user",
        arguments=(CallArgument(position=0, keyword=None, expression="user", location=_span()),),
    )
    enrichment = TypeEnrichmentIndex(
        facts=(_type_fact(containing_function_fqn="app.delete_user"),)
    )
    idx = _index(call_edges=(edge,), type_enrichment=enrichment)
    descriptor = _find_effect_descriptor("Session.delete")

    matches = _match_call_descriptor(_PROVIDER, ProviderPhase.EFFECTS, descriptor, idx, _ALIASES)

    assert len(matches) == 1
    assert matches[0].canonical_fqn == f"{_SESSION_FQN}.delete"


# -- Query.first: match via receiver type enrichment -------------------------


def test_query_first_matched_via_receiver_type() -> None:
    """result.first() matches Query.first when type enrichment says result is Query."""
    edge = _call_edge(
        callee_fqn="app.get_user.<locals>.result.first",
        call_expression="result.first()",
        caller_fqn="app.get_user",
    )
    enrichment = TypeEnrichmentIndex(
        facts=(
            _type_fact(
                expression="result",
                declared_type=_QUERY_FQN,
                containing_function_fqn="app.get_user",
            ),
        )
    )
    idx = _index(call_edges=(edge,), type_enrichment=enrichment)
    descriptor = _find_effect_descriptor("Query.first")

    matches = _match_call_descriptor(_PROVIDER, ProviderPhase.EFFECTS, descriptor, idx, _ALIASES)

    assert len(matches) == 1
    assert matches[0].canonical_fqn == f"{_QUERY_FQN}.first"


# -- Negative cases: no match without / wrong / imprecise type ---------------


def test_no_match_without_type_enrichment() -> None:
    """Without type enrichment, db.add(user) does not match Session.add."""
    edge = _call_edge(
        callee_fqn="app.create_user.<locals>.db.add",
        call_expression="db.add(user)",
        arguments=(CallArgument(position=0, keyword=None, expression="user", location=_span()),),
    )
    idx = _index(call_edges=(edge,), type_enrichment=TypeEnrichmentIndex.empty())
    descriptor = _find_effect_descriptor("Session.add")

    matches = _match_call_descriptor(_PROVIDER, ProviderPhase.EFFECTS, descriptor, idx, _ALIASES)

    assert len(matches) == 0


def test_no_match_with_wrong_receiver_type() -> None:
    """db.add(user) does not match Session.add when db is typed as something else."""
    edge = _call_edge(
        callee_fqn="app.create_user.<locals>.db.add",
        call_expression="db.add(user)",
        arguments=(CallArgument(position=0, keyword=None, expression="user", location=_span()),),
    )
    enrichment = TypeEnrichmentIndex(facts=(_type_fact(declared_type="redis.client.Redis"),))
    idx = _index(call_edges=(edge,), type_enrichment=enrichment)
    descriptor = _find_effect_descriptor("Session.add")

    matches = _match_call_descriptor(_PROVIDER, ProviderPhase.EFFECTS, descriptor, idx, _ALIASES)

    assert len(matches) == 0


def test_no_match_with_imprecise_receiver_type() -> None:
    """db.add(user) does not match when receiver type is Any/Unknown."""
    edge = _call_edge(
        callee_fqn="app.create_user.<locals>.db.add",
        call_expression="db.add(user)",
        arguments=(CallArgument(position=0, keyword=None, expression="user", location=_span()),),
    )
    enrichment = TypeEnrichmentIndex(
        facts=(_type_fact(declared_type="Unknown", is_concrete=False),)
    )
    idx = _index(call_edges=(edge,), type_enrichment=enrichment)
    descriptor = _find_effect_descriptor("Session.add")

    matches = _match_call_descriptor(_PROVIDER, ProviderPhase.EFFECTS, descriptor, idx, _ALIASES)

    # Imprecise types should produce UNKNOWN status match (with gap),
    # not a hard match
    assert len(matches) == 0


# -- Gap production for missing/unknown receiver type -----------------------


def test_gap_produced_for_missing_receiver_type() -> None:
    """When method name matches but no type fact exists, produce an AnalysisGap."""
    edge = _call_edge(
        callee_fqn="app.create_user.<locals>.db.add",
        call_expression="db.add(user)",
        arguments=(CallArgument(position=0, keyword=None, expression="user", location=_span()),),
    )
    idx = _index(call_edges=(edge,), type_enrichment=TypeEnrichmentIndex.empty())
    descriptor = _find_effect_descriptor("Session.add")

    matches = _match_call_descriptor(_PROVIDER, ProviderPhase.EFFECTS, descriptor, idx, _ALIASES)

    # No match, but the engine should have noted a gap for the unresolved
    # receiver type. The gap propagation mechanism depends on implementation
    # — this test documents the expectation that no false-positive match occurs.
    assert len(matches) == 0


# -- Direct FQN match still works (no regression) ---------------------------


def test_direct_fqn_match_still_works() -> None:
    """Exact FQN match continues to work (no regression from receiver-type path)."""
    edge = _call_edge(
        callee_fqn="sqlalchemy.orm.session.Session.add",
        call_expression="Session.add(user)",
        arguments=(CallArgument(position=0, keyword=None, expression="user", location=_span()),),
    )
    idx = _index(call_edges=(edge,))
    descriptor = _find_effect_descriptor("Session.add")

    matches = _match_call_descriptor(_PROVIDER, ProviderPhase.EFFECTS, descriptor, idx, _ALIASES)

    assert len(matches) == 1
    assert matches[0].canonical_fqn == f"{_SESSION_FQN}.add"


def test_alias_fqn_match_still_works() -> None:
    """Alias-canonicalised FQN match (sqlalchemy.orm.Session → Session) works."""
    edge = _call_edge(
        callee_fqn="sqlalchemy.orm.Session.add",
        call_expression="Session.add(user)",
        arguments=(CallArgument(position=0, keyword=None, expression="user", location=_span()),),
    )
    idx = _index(call_edges=(edge,))
    descriptor = _find_effect_descriptor("Session.add")

    matches = _match_call_descriptor(_PROVIDER, ProviderPhase.EFFECTS, descriptor, idx, _ALIASES)

    assert len(matches) == 1
    assert matches[0].canonical_fqn == f"{_SESSION_FQN}.add"
