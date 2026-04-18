"""Regression guard: L1 emits repo-relative paths/FQNs for *L1-derived*
facts, so the L2 detection match keys resolve cross-module callers.

The abs-vs-relative match-key false negative: the extractor.s call-edge / symbol dumps
named an in-repo function by an ABSOLUTE path
(``/abs/pkg/routes/orders.list_orders``) and stamped absolute span files, while
every *structural* fact is repo-relative (``pkg.routes.orders.list_orders``,
``pkg/routes/orders.py``). Those absolute strings are the very keys L2 matches
on, so a cross-module caller — most visibly a cross-module authorization
decorator — silently failed every ``functions_by_fqn`` /
``_call_edges_for_caller`` / ``(file, line)`` lookup: a false negative with no
``AnalysisGap`` (the cardinal sin per the project's #1 priority).

The ``nested_pkg_authz`` fixture is the shape that flat single-file fixtures
cannot exercise — the file stem ``orders`` differs from the module FQN
``pkg.routes.orders``, so the historical "stem == module" coincidence that let
single-file fixtures pass collapses. These assertions fail against the
pre-relativization engine (extractor facts absolute) and pass once L1 relativizes
at the source.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed._index._pipeline import load_index_from_artifacts
from flawed._semantic._matching import _call_edges_for_caller
from tests.helpers.artifact_fixtures import fixture_app_path

if TYPE_CHECKING:
    from flawed._index import CodeIndex

_FIXTURE = "nested_pkg_authz"
_LIST_ORDERS = "pkg.routes.orders.list_orders"
_READ_ORDER_ID = "pkg.services.helpers.read_order_id"
_LOAD_ORDER = "pkg.services.helpers.load_order"
_REQUIRE_AUTH = "pkg.auth.decorators.require_auth"
_ORDERS_FILE = "pkg/routes/orders.py"


def _load_index() -> CodeIndex:
    """Load the committed ``nested_pkg_authz`` artifacts as a CodeIndex.

    Mirrors :func:`tests.helpers.artifact_fixtures.load_fixture` but returns the
    raw L1 index so the test can assert on L1-derived call edges / symbol
    refs (the facts that carried the absolute match keys).
    """
    app = fixture_app_path(_FIXTURE)
    artifact_root = app.parents[1] / "artifacts" / _FIXTURE
    return load_index_from_artifacts(app, artifact_root)


def _is_absolute_pathish(value: str) -> bool:
    """True if *value* is an absolute filesystem path (the leaked machine form)."""
    return value.startswith("/")


def test_no_l1_fact_carries_an_absolute_path() -> None:
    """Every L1-derived FQN/path is repo-relative — no machine paths leak.

    This is both the false-negative guard (absolute keys never match the
    relative structural keys) and the portability guard (artifacts must not bind
    to the producing machine).
    """
    idx = _load_index()

    offenders: list[str] = []
    for edge in idx.call_graph.edges:
        for label, value in (
            ("caller_fqn", edge.caller_fqn),
            ("callee_fqn", edge.callee_fqn),
            ("location.file", edge.location.file),
        ):
            if value is not None and _is_absolute_pathish(value):
                offenders.append(f"call_edge.{label}={value!r}")
    for ref in idx.symbols.refs:
        for label, value in (("fqn", ref.fqn), ("location.file", ref.location.file)):
            if value is not None and _is_absolute_pathish(value):
                offenders.append(f"symbol_ref.{label}={value!r}")

    assert not offenders, (
        "L1-derived L1 facts still carry absolute machine paths (the "
        f"abs/relative match-key false negative): {offenders[:10]}"
    )


def test_cross_module_caller_resolves_to_structural_fqn() -> None:
    """The relativized extractor caller key matches the structural FunctionRecord.

    ``list_orders`` lives in the nested module ``pkg.routes.orders``; pre-fix its
    extractor call edges were keyed by an absolute path and were invisible to a
    lookup by the structural FQN. The relativized edges must now resolve.
    """
    idx = _load_index()

    functions_by_fqn = {fn.fqn: fn for fn in idx.functions}
    assert _LIST_ORDERS in functions_by_fqn, (
        "structural FunctionRecord for the nested caller is missing — fixture regression"
    )

    edges = _call_edges_for_caller(idx, _LIST_ORDERS)
    assert edges, (
        f"_call_edges_for_caller({_LIST_ORDERS!r}) returned no edges: the "
        "cross-module caller's call graph is empty (silent false negative)"
    )

    callees = {e.callee_fqn for e in edges if e.callee_fqn}
    # Cross-module calls list_orders -> {read_order_id, load_order} are resolved by
    # the AST+oracle structural extractor; the call-graph contribution was
    # dropped (AST-only call graph) and this resolution is preserved without it.
    assert {_READ_ORDER_ID, _LOAD_ORDER} <= callees, (
        "the nested cross-module caller's call graph does not resolve the helpers; "
        f"callees seen: {sorted(callees)}"
    )


def test_cross_module_decorator_symbol_ref_is_relative() -> None:
    """The cross-module ``require_auth`` decorator ref is keyed by a relative
    ``(file, line)`` so ``_symbol_refs_for_file_line`` resolves it.

    Decorator application crosses a package boundary (defined in
    ``pkg.auth.decorators``, applied in ``pkg.routes.orders``) and gets no AST
    call-edge twin, so it rides entirely on the symbol ref — the
    un-twinned edge whose absolute ``location.file`` was the silent FN.
    """
    idx = _load_index()

    decorator_refs = [
        ref
        for ref in idx.symbols.refs
        if ref.name.endswith("require_auth") and ref.location.file == _ORDERS_FILE
    ]
    assert decorator_refs, (
        "no require_auth symbol ref with a repo-relative location.file in "
        f"{_ORDERS_FILE!r} — the decorator (file, line) match key would miss"
    )
    assert any(ref.fqn == _REQUIRE_AUTH for ref in decorator_refs), (
        "the require_auth ref resolves to a non-relative / wrong fqn: "
        f"{[r.fqn for r in decorator_refs]}"
    )


def test_module_level_caller_sentinel_is_preserved() -> None:
    """Relativization leaves the ``<module>`` caller sentinel verbatim.

    Module-level call edges carry the literal ``<module>`` caller, which several
    L2 consumers branch on by exact string; rewriting it would break them.
    """
    idx = _load_index()

    callers = {edge.caller_fqn for edge in idx.call_graph.edges}
    assert "<module>" in callers, (
        "the <module> caller sentinel was lost or rewritten during relativization"
    )
