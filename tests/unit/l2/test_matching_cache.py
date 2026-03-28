"""Focused tests for provider matching cache indexes."""

from __future__ import annotations

from pathlib import Path

from flawed._index import CodeIndex
from flawed._index._types import (
    CallEdge,
    ClassRecord,
    DecoratorFact,
    EdgeSource,
    ExtractionProvenance,
    ResolutionStatus,
    SourceSpan,
    SymbolRef,
)
from flawed._semantic import _matching
from flawed._semantic._matching import (
    _class_record_for_fqn,
    _decorator_observed_fqns,
    _fqn_extends_any,
    _get_cache,
)
from flawed._semantic._provider_engine import ProviderMatch, ProviderPhase
from flawed._semantic.providers import RouteCallPattern

_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="")
_ROOT = Path("/tmp/test-repo")


def _span(*, file: str = "app.py", line: int = 1, column: int = 0) -> SourceSpan:
    return SourceSpan(
        file=file,
        line=line,
        column=column,
        end_line=line,
        end_column=column + 10,
    )


def _index(
    *,
    decorators: tuple[DecoratorFact, ...] = (),
    symbol_refs: tuple[SymbolRef, ...] = (),
    classes: tuple[ClassRecord, ...] = (),
    call_edges: tuple[CallEdge, ...] = (),
) -> CodeIndex:
    return CodeIndex(
        repo_root=_ROOT,
        functions=(),
        classes=classes,
        decorators=decorators,
        imports=(),
        attributes=(),
        call_edges=call_edges,
        cfgs={},
        value_flow_edges=(),
        symbol_refs=symbol_refs,
        errors=(),
        provenance=_PROV,
    )


def _decorator(fqn: str | None, *, line: int = 10) -> DecoratorFact:
    return DecoratorFact(
        name="route",
        fqn=fqn,
        args=(),
        kwargs=(),
        target_fqn="app.handler",
        application_order=0,
        location=_span(line=line),
        provenance=_PROV,
    )


def _symbol(name: str, fqn: str | None, *, file: str = "app.py", line: int = 1) -> SymbolRef:
    return SymbolRef(
        name=name,
        fqn=fqn,
        resolution=ResolutionStatus.RESOLVED if fqn is not None else ResolutionStatus.UNRESOLVED,
        location=_span(file=file, line=line),
        provenance=_PROV,
    )


def _class(fqn: str, *, bases: tuple[str, ...] = ()) -> ClassRecord:
    return ClassRecord(
        fqn=fqn,
        name=fqn.rsplit(".", maxsplit=1)[-1],
        file="app.py",
        bases=bases,
        mro_chain=(),
        mro_complete=False,
        method_names=(),
        class_var_names=(),
        is_abstract=False,
        metaclass=None,
        subclasses=(),
        all_subclasses=(),
        inherited_methods=(),
        hierarchy_gaps=(),
        location=_span(),
        provenance=_PROV,
    )


def _call(fqn: str, *, source: EdgeSource, line: int = 1, column: int = 0) -> CallEdge:
    return CallEdge(
        caller_fqn="app.handler",
        callee_fqn=fqn,
        arguments=(),
        resolution=ResolutionStatus.RESOLVED,
        source=source,
        unresolved_reason=None,
        location=_span(line=line, column=column),
        provenance=_PROV,
        call_expression=f"{fqn}()",
    )


def _match(edge: CallEdge, descriptor: RouteCallPattern) -> ProviderMatch:
    return ProviderMatch(
        provider_id="test",
        phase=ProviderPhase.ROUTES,
        descriptor=descriptor,
        source_fact=edge,
        observed_fqn=edge.callee_fqn or "",
        canonical_fqn=edge.callee_fqn or "",
        location=edge.location,
    )


def test_decorator_observed_fqns_uses_symbol_refs_location_index() -> None:
    _matching.clear_matching_cache()
    decorator = _decorator(None, line=10)
    unrelated = tuple(
        _symbol(f"unrelated_{line}", f"pkg.unrelated_{line}", line=line)
        for line in range(100, 600)
    )
    idx = _index(
        decorators=(decorator,),
        symbol_refs=(
            *unrelated,
            _symbol("route", "framework.route", line=10),
        ),
    )

    observed = _decorator_observed_fqns(decorator, idx)
    idx.symbols._refs = ()

    assert observed == ("framework.route",)
    assert _decorator_observed_fqns(decorator, idx) == ("framework.route",)


def test_decorator_receiver_typing_skips_unresolvable_receiver() -> None:
    """FLAW-279: ``@recv.attr`` with no local constructor binding fabricates nothing.

    The decorator-receiver typing is purely additive — when ``recv``'s class
    cannot be resolved (no value-flow ASSIGN edge here), no extra observed-FQN
    candidate is emitted and behaviour is unchanged (FN-safe, honest)."""
    _matching.clear_matching_cache()
    decorator = DecoratorFact(
        name="ns.route",
        fqn="app.ns.route",
        args=(),
        kwargs=(),
        target_fqn="app.Handler",
        application_order=0,
        location=_span(line=10),
        provenance=_PROV,
    )
    idx = _index(decorators=(decorator,))

    # Only the module-local FQN survives; no fabricated ``<Class>.route`` candidate.
    assert _decorator_observed_fqns(decorator, idx) == ("app.ns.route",)


def test_class_fqn_and_inheritance_lookups_use_class_index() -> None:
    _matching.clear_matching_cache()
    idx = _index(
        classes=(
            *(_class(f"app.Unrelated{number}") for number in range(500)),
            _class("app.Base"),
            _class("app.Child", bases=("app.Base",)),
            _class("app.GrandChild", bases=("app.Child",)),
        )
    )
    assert "app.GrandChild" in _get_cache(idx).class_by_fqn
    idx.classes._items = ()

    record = _class_record_for_fqn("app.Child", idx)
    assert record is not None
    assert record.fqn == "app.Child"
    assert _fqn_extends_any("app.GrandChild", frozenset({"app.Base"}), idx, {})


def test_precise_call_match_dedupe_uses_keyed_lookup(monkeypatch) -> None:
    descriptor = RouteCallPattern(fqn="framework.add_route")
    precise = _match(_call("framework.add_route", source=EdgeSource.AST, line=10), descriptor)
    lossy = _match(_call("framework.add_route", source=EdgeSource.HIERARCHY, line=10), descriptor)
    unrelated_precise = tuple(
        _match(_call("framework.add_route", source=EdgeSource.AST, line=line), descriptor)
        for line in range(100, 600)
    )

    def fail_fallback(left: ProviderMatch, right: ProviderMatch) -> bool:
        raise AssertionError("exact call-site dedupe should not need fallback comparison")

    monkeypatch.setattr(_matching, "_same_provider_call_site", fail_fallback)

    assert _matching._prefer_precise_call_matches((*unrelated_precise, precise, lossy)) == (
        *unrelated_precise,
        precise,
    )


def test_precise_call_match_dedupe_merges_declared_alias_divergence() -> None:
    # One logical outbound call: the AST edge resolves it to `requests.get`, the
    # HIERARCHY-source edge to `requests.api.get` — both declared aliases on ONE
    # descriptor — and they report different columns. The lossy (arg-less
    # HIERARCHY) match must be dropped so the call surfaces as a single effect.
    descriptor = RouteCallPattern(fqn=("requests.get", "requests.api.get"))
    precise = _match(_call("requests.get", source=EdgeSource.AST, line=10, column=4), descriptor)
    lossy = _match(
        _call("requests.api.get", source=EdgeSource.HIERARCHY, line=10, column=11), descriptor
    )

    assert _matching._prefer_precise_call_matches((precise, lossy)) == (precise,)


def test_precise_call_match_dedupe_keeps_lossy_without_precise_sibling() -> None:
    # No precise (AST) match exists, so neither lossy match may be dropped —
    # dropping a HIERARCHY edge with no AST sibling would be a false negative.
    descriptor = RouteCallPattern(fqn=("requests.get", "requests.api.get"))
    lossy_a = _match(_call("requests.get", source=EdgeSource.HIERARCHY, line=10), descriptor)
    lossy_b = _match(_call("requests.api.get", source=EdgeSource.HIERARCHY, line=11), descriptor)

    assert _matching._prefer_precise_call_matches((lossy_a, lossy_b)) == (lossy_a, lossy_b)


def test_precise_call_match_dedupe_keeps_lossy_on_different_line() -> None:
    # The locus bucket is keyed by (descriptor, line): a lossy match on a
    # different line than the precise one is a distinct call site and stays.
    descriptor = RouteCallPattern(fqn=("requests.get", "requests.api.get"))
    precise = _match(_call("requests.get", source=EdgeSource.AST, line=10), descriptor)
    lossy = _match(_call("requests.api.get", source=EdgeSource.HIERARCHY, line=20), descriptor)

    assert _matching._prefer_precise_call_matches((precise, lossy)) == (precise, lossy)


def test_precise_call_match_dedupe_keeps_undeclared_alias() -> None:
    # Same descriptor + same line, but the lossy match's FQN is NOT a declared
    # alias of the descriptor (and not a nested FQN), so it must not be merged —
    # the alias-merge only unifies FQNs the provider itself declared.
    descriptor = RouteCallPattern(fqn=("requests.get",))
    precise = _match(_call("requests.get", source=EdgeSource.AST, line=10), descriptor)
    lossy = _match(_call("other.endpoint", source=EdgeSource.HIERARCHY, line=10), descriptor)

    assert _matching._prefer_precise_call_matches((precise, lossy)) == (precise, lossy)
