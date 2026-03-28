"""Layer 2: Semantic Layer — Framework-specific interpretation.

This package transforms raw Code Index facts into framework-aware domain objects.
It runs per-detection and is extensible via interpreter plugins (one per framework
concept: routes, request reads, effects, security checks, hooks, etc.).

The Semantic Layer consumes Layer 1 (Code Index) data and produces typed domain
objects that the Rule API (Layer 3) queries against.

Boundary rules:
  - This package MAY import from flawed._index (Layer 1)
  - This package MAY import domain type definitions (frozen dataclasses,
    enums, type aliases) from flawed top-level modules to construct
    the domain objects it returns to Layer 3
  - This package must NOT import Rule API orchestration modules
    (collections, detector, evidence, repo, scopes)
  - Violations are enforced by import-linter and will fail pre-commit

Public API:
  ``WebApp`` is the sole entry point for constructing the Semantic Layer.
  Rule API code calls ``WebApp.from_index(idx)`` and receives a ``WebApp``
  that can produce a populated ``RepoView``.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING

from flawed._index._pipeline import _PIPELINE_VERSION, build_index, load_index_from_artifacts
from flawed._index._structural import discover_python_files
from flawed._semantic._branch import attach_condition_branch_scopes, build_method_branch_scopes
from flawed._semantic._callee_graph import build_callee_graph, reachable_callees
from flawed._semantic._cfgview import ControlFlowView, InterproceduralControlFlowView
from flawed._semantic._check_conversion import ConcreteCondition, convert_check_matches
from flawed._semantic._collections import (
    ConcreteBlueprintCollection,
    ConcreteClassCollection,
    ConcreteDecoratorCollection,
    ConcreteFunctionCollection,
    ConcreteRouteCollection,
)
from flawed._semantic._condition_conversion import (
    ConcretePredicate,
    convert_structural_conditions,
    convert_value_predicates,
)
from flawed._semantic._container_argument_inputs import infer_container_argument_reads
from flawed._semantic._conversion import (
    convert_call_edge,
    convert_class,
    convert_decorator,
    convert_extraction_error,
    convert_functions_grouped,
)
from flawed._semantic._conversion_utils import dedupe_domain as _dedupe_domain
from flawed._semantic._dependency_conversion import convert_dependency_matches
from flawed._semantic._dispatch_conversion import DispatchEdge, convert_dispatch_matches
from flawed._semantic._effect_conversion import (
    convert_effect_match,
    convert_inferred_state_writes,
    convert_principal_attr_writes,
    convert_server_state_writes,
)
from flawed._semantic._enriched import EnrichedBlueprint, EnrichedInputRead
from flawed._semantic._flow_engine import (
    _WHOLE_VALUE_PRESERVING_STEP_KINDS as _WHOLE_VALUE_PRESERVING_STEP_KINDS,
)
from flawed._semantic._flow_engine import (
    _merge_auth_inference,
    _SemanticFlowEngine,
)
from flawed._semantic._flow_propagation import (
    FlowPropagationEdge,
    convert_flow_propagator_matches,
)
from flawed._semantic._input_conversion import (
    convert_input_match,
    path_param_reads_for_route,
    rekey_read_for_scope,
)
from flawed._semantic._lifecycle_conversion import (
    ControlPlaneExemption,
    ImplicitCheck,
    LifecycleHook,
    build_exemption_effect,
    build_group_nesting,
    control_plane_exemption_applies_to_route,
    convert_lifecycle_match,
    implicit_check_applies_to_route,
    lifecycle_function_fqns_for_route,
)
from flawed._semantic._membership_inputs import infer_membership_reads
from flawed._semantic._method_dispatch import infer_method_dispatch_edges
from flawed._semantic._property_setter_dispatch import infer_property_setter_dispatch_edges
from flawed._semantic._provider_engine import (
    MembershipContainerSpec,
    ProviderEngine,
    ProviderEngineResult,
    ProviderMatch,
    ProviderPhase,
    RouterGroupInfo,
    discover_builtin_provider_classes,
)
from flawed._semantic._proxy_flow import convert_proxy_flow_matches
from flawed._semantic._route_conversion import convert_class_view_matches, convert_route_match
from flawed._semantic._safe_generated_url_conversion import convert_safe_generated_url_matches
from flawed._semantic._scope import ConcreteCodeScope, dedupe_gaps
from flawed._semantic._sink_conversion import convert_sink_match
from flawed._semantic._structural_url_guard import convert_structural_url_guards
from flawed._semantic._table_dispatch import infer_table_dispatch_edges
from flawed._semantic._type_disagreement_conversion import convert_type_disagreements
from flawed._semantic._validation_guard_conversion import convert_validation_guard_matches
from flawed._semantic.providers import ClassViewPattern, HookType
from flawed.conditions import Condition, ConditionKind, DenialKind, GuardClassification
from flawed.core import AnalysisGap, GapKind

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from flawed._index import CodeIndex
    from flawed._index._graphs import CallGraph, ValueFlowGraph
    from flawed._index._type_enrichment import TypeOracle
    from flawed._index._types import FunctionRecord
    from flawed.blueprint import Blueprint
    from flawed.calls import CallSite
    from flawed.core import Location
    from flawed.disagreement import TypeDisagreement
    from flawed.effects import Effect
    from flawed.flow import (
        FlowTrace,
    )
    from flawed.function import Decorator, Function
    from flawed.generated import SafeGeneratedURL
    from flawed.inputs import InputRead
    from flawed.route import Route
    from flawed.sinks import TaintSink
    from flawed.validation import ValidatedValue


def repo_view_from_path(path: str | Path, *, oracle: TypeOracle | None = None) -> ConcreteRepoView:
    """Build the public RepoView for a repository source tree.

    Layer 3 calls this instead of reaching into Layer 1 directly.  The
    Semantic Layer owns the handoff from structural extraction to interpreted
    domain objects.

    ``oracle`` injects a type-enrichment oracle into the Layer-1 build.  Passing
    a deterministic/no-op oracle lets a from-source test avoid spawning the real
    basedpyright subprocess; ``None`` (production default) runs the configured
    oracles.  Most tests should instead consume committed artifacts via
    :func:`repo_view_from_artifacts`, which avoids *all* external tools.
    """
    idx = build_index(Path(path), oracle=oracle)
    webapp = WebApp.from_index(idx)
    return webapp.repo_view()


def repo_view_from_artifacts(repo_root: str | Path, artifact_root: str | Path) -> ConcreteRepoView:
    """Build the public RepoView from pre-generated L1 artifacts, no extraction.

    Loads a ``CodeIndex`` from committed ``normalized/`` artifacts (no external
    tools) and interprets it through the Semantic Layer — the
    artifact-backed twin of :func:`repo_view_from_path`.  ``repo_root`` is the
    source tree the artifacts describe (paths in the artifacts are relative to
    it); ``artifact_root`` is the directory whose ``normalized/`` subtree holds
    the JSONL.

    The loader raises ``CorruptCacheError`` if a non-empty index lacks its CFG
    artifact, so a stale or partial fixture fails loudly rather than silently
    dropping CFG-derived rules (no fail-open).
    """
    idx = load_index_from_artifacts(Path(repo_root), Path(artifact_root))
    webapp = WebApp.from_index(idx)
    return webapp.repo_view()


# In-process memo for repeated open_repo() of an unchanged tree (FLAW-132).
# The L2 semantic build is the expensive phase (~28s on a medium real-world app,
# ~183s on a large one) and is NOT disk-cached, so interactive rule authoring re-paid it on
# every open_repo call.  This caches the built RepoView in-process, keyed so it
# invalidates the moment anything that could change the result changes:
#   - the resolved absolute path,
#   - a content fingerprint of every analyzed .py file (path + mtime + size),
#   - the pipeline version (extraction/conversion logic), and
#   - the builtin provider set (which providers interpret the code).
# Only open_repo() goes through this; repo_view_from_path / WebApp.from_index
# stay un-memoized so internal callers and provider tests always build fresh.
_REPO_VIEW_MEMO: dict[tuple[str, str, str, tuple[str, ...]], ConcreteRepoView] = {}


@cache
def _provider_fingerprint() -> tuple[str, ...]:
    """Stable identifier for the active builtin provider set (cached once)."""
    return tuple(sorted(cls.meta.id for cls in discover_builtin_provider_classes()))


def _source_fingerprint(path: Path) -> str:
    """Content fingerprint of a repo's Python files via (relpath, mtime, size).

    A stat-based digest -- no file reads -- so it is cheap even on large trees
    yet changes whenever any source file is edited, added, or removed.  This is
    the in-process stand-in for the L1 content hash in the memo key.
    """
    digest = hashlib.blake2b(digest_size=16)
    for file in sorted(discover_python_files(path)):
        try:
            stat = file.stat()
        except OSError:
            # A file that vanished mid-walk still perturbs the digest via its
            # path, which is the correct invalidation signal.
            digest.update(f"{file}\0missing".encode())
            continue
        digest.update(f"{file}\0{stat.st_mtime_ns}\0{stat.st_size}\0".encode())
    return digest.hexdigest()


def repo_view_from_path_cached(path: str | Path) -> ConcreteRepoView:
    """Like :func:`repo_view_from_path`, but memoized per process (FLAW-132).

    Returns a previously built :class:`ConcreteRepoView` when the same path is
    requested again and nothing affecting the analysis has changed.  The cached
    view is immutable for queries, so sharing it across calls is safe.
    """
    resolved = Path(path)
    key = (
        str(resolved.resolve()),
        _source_fingerprint(resolved),
        _PIPELINE_VERSION,
        _provider_fingerprint(),
    )
    cached = _REPO_VIEW_MEMO.get(key)
    if cached is not None:
        return cached
    view = repo_view_from_path(path)
    _REPO_VIEW_MEMO[key] = view
    return view


def clear_repo_view_cache() -> None:
    """Clear the in-process open_repo memo (FLAW-132).

    Primarily for tests and long-lived REPL sessions that need to force a fresh
    rebuild without restarting the process.
    """
    _REPO_VIEW_MEMO.clear()


class WebApp:
    """Semantic Layer runtime: converts CodeIndex facts into domain objects.

    Constructed via :meth:`from_index`.  Holds the converted domain
    collections and can produce a populated :class:`~flawed.repo.RepoView`.

    Example::

        idx = build_index(repo_root)
        webapp = WebApp.from_index(idx)
        rv = webapp.repo_view()
        for fn in rv.functions:
            ...
    """

    __slots__ = (
        "_blueprints",
        "_call_graph",
        "_classes",
        "_flow_propagators",
        "_function_records",
        "_functions",
        "_gaps",
        "_repo_path",
        "_routes",
        "_type_disagreements",
        "_value_flow",
    )

    def __init__(
        self,
        *,
        repo_path: str,
        functions: ConcreteFunctionCollection,
        function_records: tuple[FunctionRecord, ...],
        classes: ConcreteClassCollection,
        routes: ConcreteRouteCollection,
        type_disagreements: tuple[TypeDisagreement, ...],
        value_flow: ValueFlowGraph,
        call_graph: CallGraph,
        blueprints: ConcreteBlueprintCollection | None = None,
        flow_propagators: tuple[FlowPropagationEdge, ...] = (),
        gaps: tuple[AnalysisGap, ...] = (),
    ) -> None:
        self._repo_path = repo_path
        self._functions = functions
        self._function_records = function_records
        self._classes = classes
        self._routes = routes
        self._blueprints = blueprints if blueprints is not None else ConcreteBlueprintCollection()
        self._type_disagreements = type_disagreements
        self._value_flow = value_flow
        self._call_graph = call_graph
        self._flow_propagators = flow_propagators
        self._gaps = gaps

    @classmethod
    def from_index(
        cls,
        idx: CodeIndex,
        *,
        provider_engine: ProviderEngine | None = None,
        provider_engine_result: ProviderEngineResult | None = None,
    ) -> WebApp:
        """Build a WebApp from a CodeIndex.

        Converts all L1 structural facts into L3 domain objects,
        enriches them with navigation context, and runs the provider
        engine to produce routes and other semantic interpretations.
        """
        type_disagreements = convert_type_disagreements(idx.type_enrichment)
        type_disagreements_by_function = _type_disagreements_by_function(type_disagreements)

        # Phase 1: Convert L1 records into enriched domain objects.
        fn_by_fqn = convert_functions_grouped(idx.functions)
        cls_by_fqn = {rec.fqn: convert_class(rec) for rec in idx.classes}

        # Keep L1 records for provider-match conversion (routes need handler lookup).
        l1_fn_by_fqn = {rec.fqn: rec for rec in idx.functions}

        # Phase 2: Build decorator lookup (target_fqn → list of Decorator).
        dec_by_target: dict[str, list[Decorator]] = defaultdict(list)
        for fact in idx.decorators:
            dec_by_target[fact.target_fqn].append(convert_decorator(fact))

        # Phase 3: Build gap lookup (file → list of AnalysisGap).
        gaps_by_file: dict[str, list[AnalysisGap]] = defaultdict(list)
        for err in idx.errors:
            gaps_by_file[err.file].append(convert_extraction_error(err))

        # Phase 4: Enrich functions with decorators and gaps.
        for fqn, fn in fn_by_fqn.items():
            object.__setattr__(fn, "_repo_path", str(idx.repo_root))
            decs = ConcreteDecoratorCollection(tuple(dec_by_target.get(fqn, ())))
            object.__setattr__(fn, "_decorators", decs)

            fn_file = fn.location.file
            fn_gaps = tuple(g for g in gaps_by_file.get(fn_file, ()) if _gap_affects(g, fn))
            object.__setattr__(fn, "_gaps", fn_gaps)

        # Phase 5: Enrich classes with methods and gaps.
        for fqn, klass in cls_by_fqn.items():
            decs = ConcreteDecoratorCollection(tuple(dec_by_target.get(fqn, ())))
            object.__setattr__(klass, "_decorators", decs)

            method_fns = tuple(
                fn_by_fqn[f"{fqn}.{mname}"]
                for mname in klass.method_names
                if f"{fqn}.{mname}" in fn_by_fqn
            )
            object.__setattr__(klass, "_methods", ConcreteFunctionCollection(method_fns))

            cls_file = klass.location.file
            cls_gaps = tuple(g for g in gaps_by_file.get(cls_file, ()) if _gap_affects(g, klass))
            object.__setattr__(klass, "_gaps", cls_gaps)

        # Phase 6: Convert Python structural conditions and the sibling value
        # predicates (FLAW-113), then run provider engine.  Predicates are
        # captured by L1 with no branch edges, so they ride alongside but
        # never inside the branch-only ``conditions()`` machinery.
        conditions_by_function, predicates_by_function = _convert_structural_facts(idx, fn_by_fqn)

        if provider_engine is not None and provider_engine_result is not None:
            msg = "provider_engine and provider_engine_result are mutually exclusive"
            raise ValueError(msg)
        if provider_engine_result is None:
            engine = provider_engine or ProviderEngine()
            engine_result = engine.run(idx)
        else:
            engine_result = provider_engine_result
        router_group_info_by_var = {
            info.variable_fqn: info for info in engine_result.router_group_info
        }
        converted = _convert_provider_observations(
            engine_result.matches,
            idx=idx,
            l1_fn_by_fqn=l1_fn_by_fqn,
            functions_by_fqn=fn_by_fqn,
            router_group_info_by_var=router_group_info_by_var,
        )
        for fqn, provider_conditions in converted.conditions_by_function.items():
            conditions_by_function.setdefault(fqn, []).extend(provider_conditions)
        semantic_gaps: list[AnalysisGap] = [*engine_result.gaps, *converted.gaps]
        _attach_semantic_gaps_to_functions(fn_by_fqn, tuple(semantic_gaps))

        # Phase 6.3: Infer custom auth decorators (DISC-090).
        _merge_auth_inference(
            idx,
            fn_by_fqn,
            engine_result,
            conditions_by_function,
            semantic_gaps,
        )

        # Phase 6.5: Populate call graph navigation, including L2 dispatch edges.
        dispatch_edges_t = (
            *tuple(converted.dispatch_edges),
            *infer_property_setter_dispatch_edges(idx, functions_by_fqn=fn_by_fqn),
            *infer_table_dispatch_edges(idx, functions_by_fqn=fn_by_fqn),
            *infer_method_dispatch_edges(idx, functions_by_fqn=fn_by_fqn),
        )
        call_sites_by_caller = _populate_call_graph(
            idx,
            fn_by_fqn,
            dispatch_edges=dispatch_edges_t,
        )
        callee_graph = build_callee_graph(idx, dispatch_edges_t)
        # Augment fact-derived reads with the two L2 inference passes: container
        # arguments passed into helpers, and ``"k" in session``/``g`` membership
        # presence tests (FLAW-336) -- neither carries a direct input fact.
        _merge_inferred_input_reads(
            idx,
            converted.input_reads_by_function,
            l1_fn_by_fqn=l1_fn_by_fqn,
            functions_by_fqn=fn_by_fqn,
            conditions_by_function=conditions_by_function,
            engine_result=engine_result,
        )
        reachable_cache: dict[str, tuple[str, ...]] = {}
        branch_gaps = attach_condition_branch_scopes(
            idx,
            fn_by_fqn,
            input_reads_by_function=converted.input_reads_by_function,
            effects_by_function=converted.effects_by_function,
            sinks_by_function=converted.sinks_by_function,
            safe_generated_urls_by_function=converted.safe_generated_urls_by_function,
            validated_values_by_function=converted.validated_values_by_function,
            conditions_by_function=conditions_by_function,
            call_sites_by_caller=call_sites_by_caller,
            callee_graph=callee_graph,
        )
        semantic_gaps.extend(branch_gaps)

        route_objects = list(
            _attach_route_body_scopes(
                _merge_routes(tuple(converted.routes)),
                semantic_gaps=semantic_gaps,
                input_reads_by_function=converted.input_reads_by_function,
                effects_by_function=converted.effects_by_function,
                sinks_by_function=converted.sinks_by_function,
                safe_generated_urls_by_function=converted.safe_generated_urls_by_function,
                validated_values_by_function=converted.validated_values_by_function,
                type_disagreements_by_function=type_disagreements_by_function,
                conditions_by_function=conditions_by_function,
                predicates_by_function=predicates_by_function,
                lifecycle_hooks=tuple(converted.lifecycle_hooks),
                implicit_checks=tuple(converted.implicit_checks),
                control_plane_exemptions=tuple(converted.control_plane_exemptions),
                # Parent→child router-group nesting (e.g. nested
                # register_blueprint) so a parent group's lifecycle hooks reach
                # nested child routes (FLAW-114).
                group_ancestry=build_group_nesting(idx, router_group_info_by_var),
                call_sites_by_caller=call_sites_by_caller,
                l1_fn_by_fqn=l1_fn_by_fqn,
                functions_by_fqn=fn_by_fqn,
                callee_graph=callee_graph,
                reachable_cache=reachable_cache,
                idx=idx,
            )
        )

        # Phase 7: Build function body and reachable scopes.
        _attach_function_scopes(
            idx,
            fn_by_fqn,
            input_reads_by_function=converted.input_reads_by_function,
            effects_by_function=converted.effects_by_function,
            sinks_by_function=converted.sinks_by_function,
            safe_generated_urls_by_function=converted.safe_generated_urls_by_function,
            validated_values_by_function=converted.validated_values_by_function,
            type_disagreements_by_function=type_disagreements_by_function,
            conditions_by_function=conditions_by_function,
            predicates_by_function=predicates_by_function,
            call_sites_by_caller=call_sites_by_caller,
            callee_graph=callee_graph,
            reachable_cache=reachable_cache,
        )

        functions = ConcreteFunctionCollection(tuple(fn_by_fqn.values()))
        classes = ConcreteClassCollection(tuple(cls_by_fqn.values()))
        routes = ConcreteRouteCollection(tuple(route_objects))

        return cls(
            repo_path=str(idx.repo_root),
            functions=functions,
            function_records=tuple(idx.functions),
            classes=classes,
            routes=routes,
            # Builds Blueprint objects and back-links each route's ``_blueprint``.
            blueprints=_build_blueprints(tuple(route_objects), router_group_info_by_var),
            type_disagreements=type_disagreements,
            value_flow=idx.value_flow,
            call_graph=idx.call_graph,
            flow_propagators=tuple(converted.flow_propagators),
            gaps=tuple(semantic_gaps),
        )

    def repo_view(self) -> ConcreteRepoView:
        """Produce a populated RepoView for Rule API consumption."""
        return ConcreteRepoView(
            path=self._repo_path,
            functions=self._functions,
            function_records=self._function_records,
            classes=self._classes,
            routes=self._routes,
            blueprints=self._blueprints,
            type_disagreements=self._type_disagreements,
            value_flow=self._value_flow,
            call_graph=self._call_graph,
            flow_propagators=self._flow_propagators,
            gaps=self._gaps,
        )


def _build_blueprints(
    routes: tuple[Route, ...],
    router_group_info_by_var: Mapping[str, RouterGroupInfo],
) -> ConcreteBlueprintCollection:
    """Group routes into ``Blueprint`` objects and back-link each route.

    Blueprints are keyed by group *name* (the user-facing blueprint/router
    identity).  ``url_prefix`` is taken from the matching ``RouterGroupInfo``
    when one exists, else ``None`` -- honestly "absent or not statically
    resolvable", never fabricated.  Declared-but-routeless groups are still
    surfaced.  Every route receives a ``_blueprint`` back-reference (the owning
    ``Blueprint`` or ``None``) so ``Route.blueprint`` never raises.

    Order is deterministic: groups appear in first-seen route order, then any
    routeless declared groups in extraction order.
    """
    prefix_by_name: dict[str, str | None] = {}
    for info in router_group_info_by_var.values():
        if not info.group:
            continue
        # Prefer a resolved prefix if several variables share a group name.
        if info.group not in prefix_by_name or (
            prefix_by_name[info.group] is None and info.url_prefix is not None
        ):
            prefix_by_name[info.group] = info.url_prefix

    routes_by_name: dict[str, list[Route]] = {}
    for route in routes:
        if route.group:
            routes_by_name.setdefault(route.group, []).append(route)
    # Include declared groups that registered zero routes.
    for name in prefix_by_name:
        routes_by_name.setdefault(name, [])

    by_name: dict[str, Blueprint] = {}
    blueprints: list[Blueprint] = []
    for name, grouped in routes_by_name.items():
        blueprint = EnrichedBlueprint(name=name, url_prefix=prefix_by_name.get(name))
        object.__setattr__(blueprint, "_routes", ConcreteRouteCollection(tuple(grouped)))
        by_name[name] = blueprint
        blueprints.append(blueprint)

    for route in routes:
        owner = by_name.get(route.group) if route.group else None
        object.__setattr__(route, "_blueprint", owner)

    return ConcreteBlueprintCollection(tuple(blueprints))


def _merge_inferred_input_reads(
    idx: CodeIndex,
    input_reads_by_function: dict[str, list[InputRead]],
    *,
    l1_fn_by_fqn: Mapping[str, FunctionRecord],
    functions_by_fqn: Mapping[str, Function],
    conditions_by_function: Mapping[str, list[Condition]],
    engine_result: ProviderEngineResult,
) -> None:
    """Augment fact-derived reads with the L2 inference passes that have no input fact.

    Container-argument reads recover request containers passed into helpers;
    membership reads recover ``"k" in session`` / ``"k" in g`` presence tests
    (FLAW-336), whose container is a bare ``Name`` in an ``ast.Compare``.
    """
    _merge_container_argument_reads(
        idx,
        input_reads_by_function,
        l1_fn_by_fqn=l1_fn_by_fqn,
        functions_by_fqn=functions_by_fqn,
    )
    _merge_membership_reads(
        idx,
        input_reads_by_function,
        conditions_by_function=conditions_by_function,
        membership_specs=engine_result.membership_container_specs,
        aliases=engine_result.aliases,
    )


def _merge_container_argument_reads(
    idx: CodeIndex,
    input_reads_by_function: dict[str, list[InputRead]],
    *,
    l1_fn_by_fqn: Mapping[str, FunctionRecord],
    functions_by_fqn: Mapping[str, Function],
) -> None:
    inferred_reads = infer_container_argument_reads(
        idx,
        l1_fn_by_fqn=l1_fn_by_fqn,
        functions_by_fqn=functions_by_fqn,
        existing_reads_by_function=input_reads_by_function,
    )
    for fqn, reads in inferred_reads.items():
        input_reads_by_function[fqn].extend(reads)


def _merge_membership_reads(
    idx: CodeIndex,
    input_reads_by_function: dict[str, list[InputRead]],
    *,
    conditions_by_function: Mapping[str, list[Condition]],
    membership_specs: tuple[MembershipContainerSpec, ...],
    aliases: Mapping[str, str],
) -> None:
    inferred_reads = infer_membership_reads(
        idx,
        conditions_by_function=conditions_by_function,
        membership_specs=membership_specs,
        aliases=aliases,
        existing_reads_by_function=input_reads_by_function,
    )
    for fqn, reads in inferred_reads.items():
        input_reads_by_function.setdefault(fqn, []).extend(reads)


def _populate_call_graph(
    idx: CodeIndex,
    fn_by_fqn: Mapping[str, Function],
    *,
    dispatch_edges: tuple[DispatchEdge, ...] = (),
) -> dict[str, list[CallSite]]:
    """Populate calls/called_by on enriched functions from L1 and L2 dispatch edges.

    Returns a caller-FQN → call-sites map for use by scope building.
    """
    callee_map: dict[str, list[Function]] = defaultdict(list)
    caller_map: dict[str, list[Function]] = defaultdict(list)
    call_sites_by_caller: dict[str, list[CallSite]] = defaultdict(list)
    for edge in idx.call_graph.edges:
        caller_fn = fn_by_fqn.get(edge.caller_fqn)
        callee_fqn = edge.callee_fqn
        callee_fn = fn_by_fqn.get(callee_fqn) if callee_fqn else None
        if caller_fn is not None and callee_fn is not None and callee_fqn is not None:
            callee_map[edge.caller_fqn].append(callee_fn)
            caller_map[callee_fqn].append(caller_fn)
        if caller_fn is not None:
            call_sites_by_caller[edge.caller_fqn].append(
                convert_call_edge(edge, caller_fn, fn_by_fqn)
            )

    for dispatch_edge in dispatch_edges:
        caller_fn = fn_by_fqn.get(dispatch_edge.caller_fqn)
        if caller_fn is None:
            continue
        callee_map[dispatch_edge.caller_fqn].append(dispatch_edge.target)
        caller_map[dispatch_edge.target.fqn].append(caller_fn)

    for fqn, fn in fn_by_fqn.items():
        callees = tuple(dict.fromkeys(callee_map.get(fqn, ())))
        callers = tuple(dict.fromkeys(caller_map.get(fqn, ())))
        object.__setattr__(fn, "_calls", ConcreteFunctionCollection(callees))
        object.__setattr__(fn, "_called_by", ConcreteFunctionCollection(callers))

    return call_sites_by_caller


def _attach_function_scopes(
    idx: CodeIndex,
    fn_by_fqn: Mapping[str, Function],
    *,
    input_reads_by_function: dict[str, list[InputRead]],
    effects_by_function: dict[str, list[Effect]],
    sinks_by_function: dict[str, list[TaintSink]],
    safe_generated_urls_by_function: dict[str, list[SafeGeneratedURL]],
    validated_values_by_function: dict[str, list[ValidatedValue]],
    type_disagreements_by_function: dict[str, list[TypeDisagreement]],
    conditions_by_function: dict[str, list[Condition]],
    predicates_by_function: dict[str, list[ConcretePredicate]],
    call_sites_by_caller: dict[str, list[CallSite]],
    callee_graph: dict[str, set[str]],
    reachable_cache: dict[str, tuple[str, ...]] | None = None,
) -> None:
    """Build body and reachable scopes for every enriched function."""
    for fqn, fn in fn_by_fqn.items():
        fn_reads = tuple(
            EnrichedInputRead.from_base(r) for r in input_reads_by_function.get(fqn, ())
        )
        fn_effects = tuple(effects_by_function.get(fqn, ()))
        fn_sinks = tuple(sinks_by_function.get(fqn, ()))
        fn_safe_generated_urls = tuple(safe_generated_urls_by_function.get(fqn, ()))
        fn_validated_values = tuple(validated_values_by_function.get(fqn, ()))
        fn_type_disagreements = tuple(type_disagreements_by_function.get(fqn, ()))
        fn_sites = tuple(call_sites_by_caller.get(fqn, ()))
        fn_conditions = tuple(conditions_by_function.get(fqn, ()))
        fn_predicates = tuple(predicates_by_function.get(fqn, ()))
        body_scope = ConcreteCodeScope(
            input_reads=fn_reads,
            effects=fn_effects,
            sinks=fn_sinks,
            safe_generated_urls=fn_safe_generated_urls,
            validated_values=fn_validated_values,
            type_disagreements=fn_type_disagreements,
            call_sites=fn_sites,
            conditions=fn_conditions,
            predicates=fn_predicates,
            decorators=tuple(fn.decorators),
            gaps=fn.gaps,
            cfg=ControlFlowView(idx.cfg(fqn), gaps=fn.gaps),
            functions=(fn,),
        )
        object.__setattr__(fn, "_body", body_scope)

        reachable_fqns = reachable_callees(fqn, callee_graph, cache=reachable_cache)
        reachable_reads: list[InputRead] = list(fn_reads)
        reachable_effects: list[Effect] = list(fn_effects)
        reachable_sinks: list[TaintSink] = list(fn_sinks)
        reachable_safe_generated_urls: list[SafeGeneratedURL] = list(fn_safe_generated_urls)
        reachable_validated_values: list[ValidatedValue] = list(fn_validated_values)
        reachable_type_disagreements: list[TypeDisagreement] = list(fn_type_disagreements)
        reachable_sites: list[CallSite] = list(fn_sites)
        reachable_conditions: list[Condition] = list(fn_conditions)
        reachable_predicates: list[ConcretePredicate] = list(fn_predicates)
        reachable_decs: list[Decorator] = list(fn.decorators)
        reachable_gaps: list[AnalysisGap] = list(fn.gaps)
        for callee_fqn in reachable_fqns:
            if callee_fqn == fqn:
                continue
            reachable_reads.extend(
                EnrichedInputRead.from_base(r) for r in input_reads_by_function.get(callee_fqn, ())
            )
            reachable_effects.extend(effects_by_function.get(callee_fqn, ()))
            reachable_sinks.extend(sinks_by_function.get(callee_fqn, ()))
            reachable_safe_generated_urls.extend(
                safe_generated_urls_by_function.get(callee_fqn, ())
            )
            reachable_validated_values.extend(validated_values_by_function.get(callee_fqn, ()))
            reachable_type_disagreements.extend(type_disagreements_by_function.get(callee_fqn, ()))
            reachable_sites.extend(call_sites_by_caller.get(callee_fqn, ()))
            reachable_conditions.extend(conditions_by_function.get(callee_fqn, ()))
            reachable_predicates.extend(predicates_by_function.get(callee_fqn, ()))
            callee_fn = fn_by_fqn.get(callee_fqn)
            if callee_fn is not None:
                reachable_decs.extend(callee_fn.decorators)
                reachable_gaps.extend(callee_fn.gaps)
        # FLAW-231: surface dynamic-dispatch closure truncation on the function's
        # own reachable scope, consistent with route scopes.
        reachable_gaps.extend(
            _unresolved_dispatch_gaps(
                reachable_fqns, idx.call_graph, origin_phase="reachable_closure"
            )
        )
        reachable_scope = ConcreteCodeScope(
            input_reads=tuple(reachable_reads),
            effects=tuple(reachable_effects),
            sinks=tuple(reachable_sinks),
            safe_generated_urls=_dedupe_domain(reachable_safe_generated_urls),
            validated_values=_dedupe_domain(reachable_validated_values),
            type_disagreements=tuple(dict.fromkeys(reachable_type_disagreements)),
            call_sites=tuple(reachable_sites),
            conditions=tuple(reachable_conditions),
            predicates=tuple(reachable_predicates),
            decorators=tuple(reachable_decs),
            gaps=dedupe_gaps(tuple(reachable_gaps)),
            # FLAW-242b: an interprocedural CFG over the reachable scope (root +
            # callees), so auth-ordering rules can confirm read-before-write
            # orderings that span a helper -- previously these were undecidable
            # MEDIUM gaps. ``precedes`` stays conservative (False on any
            # uncertainty), so this never fabricates an order or silences a gap.
            cfg=InterproceduralControlFlowView(
                root_fqn=fqn,
                index=idx,
                reachable_fqns=reachable_fqns,
                gaps=dedupe_gaps(tuple(reachable_gaps)),
            ),
            functions=_resolve_functions(reachable_fqns, fn_by_fqn, first=fqn),
        )
        object.__setattr__(fn, "_reachable", reachable_scope)


def _gap_affects(gap: AnalysisGap, entity: object) -> bool:
    """Check whether an analysis gap is relevant to a specific entity.

    Gaps are file-scoped: a gap with ``affected_file`` matching the
    entity's file is considered relevant.  Function-specific gaps
    (with ``affected_function`` set) are further filtered by FQN.
    """
    entity_file = getattr(entity, "location", None)
    if entity_file is None:
        return False
    entity_file = entity_file.file

    if gap.affected_file and gap.affected_file != entity_file:
        return False

    if gap.affected_function:
        entity_fqn = getattr(entity, "fqn", None)
        if entity_fqn and gap.affected_function != entity_fqn:
            return False

    return True


def _attach_semantic_gaps_to_functions(
    functions_by_fqn: Mapping[str, Function],
    gaps: tuple[AnalysisGap, ...],
) -> None:
    """Attach function-scoped L2 conversion gaps before scopes are assembled.

    L1 extraction errors are attached to functions by file during the initial
    conversion pass.  L2 conversion gaps, however, are often repository- or
    file-scoped diagnostics produced from provider matches that could not be
    tied to a containing function.  Propagating those broad gaps onto every
    function in the file makes function-level gap inspection noisy, so only
    attach L2 gaps once they name the affected function explicitly.
    """
    scoped_gaps = tuple(gap for gap in gaps if gap.affected_function)
    if not scoped_gaps:
        return

    for fn in functions_by_fqn.values():
        fn_gaps = tuple(gap for gap in scoped_gaps if _gap_affects(gap, fn))
        if fn_gaps:
            object.__setattr__(fn, "_gaps", dedupe_gaps((*fn.gaps, *fn_gaps)))


def _collect_server_state_effects(
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
    gaps: list[AnalysisGap],
    effects_by_function: dict[str, list[Effect]],
) -> None:
    """Append server-state write effects into the mutable accumulators."""
    result = convert_server_state_writes(idx, functions_by_fqn)
    gaps.extend(result.gaps)
    for effect in result.effects:
        effects_by_function[effect.function.fqn].append(effect)


def _collect_inferred_state_effects(
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
    effects_by_function: dict[str, list[Effect]],
) -> None:
    """Append FLAW-281a inferred custom-mutation STATE_WRITEs.

    Runs after provider + server-state effects are collected so it can skip any
    call site a provider already modeled (dedup by location), only emitting for
    custom mutating calls that would otherwise be invisible.
    """
    modeled_locations = frozenset(
        (effect.location.file, effect.location.line, effect.location.column)
        for effects in effects_by_function.values()
        for effect in effects
    )
    result = convert_inferred_state_writes(idx, functions_by_fqn, modeled_locations)
    for effect in result.effects:
        effects_by_function[effect.function.fqn].append(effect)


def _collect_principal_attr_write_effects(
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
    effects_by_function: dict[str, list[Effect]],
) -> None:
    """Append FLAW-310 PRINCIPAL_ATTR_WRITE effects (attacker-writable principal attributes)."""
    result = convert_principal_attr_writes(idx, functions_by_fqn)
    for effect in result.effects:
        effects_by_function[effect.function.fqn].append(effect)


@dataclass
class ProviderConversionResult:
    """All domain objects produced by converting provider observations.

    Replaces a bare 12-element tuple with named, self-documenting fields.
    This is mutable during the conversion pass, then consumed once.
    """

    routes: list[Route]
    gaps: list[AnalysisGap]
    input_reads_by_function: dict[str, list[InputRead]]
    effects_by_function: dict[str, list[Effect]]
    sinks_by_function: dict[str, list[TaintSink]]
    safe_generated_urls_by_function: dict[str, list[SafeGeneratedURL]]
    validated_values_by_function: dict[str, list[ValidatedValue]]
    conditions_by_function: dict[str, list[Condition]]
    lifecycle_hooks: list[LifecycleHook]
    implicit_checks: list[ImplicitCheck]
    control_plane_exemptions: list[ControlPlaneExemption]
    flow_propagators: list[FlowPropagationEdge]
    dispatch_edges: list[DispatchEdge]


def _convert_provider_observations(
    matches: tuple[ProviderMatch, ...],
    *,
    idx: CodeIndex,
    l1_fn_by_fqn: dict[str, FunctionRecord],
    functions_by_fqn: Mapping[str, Function],
    router_group_info_by_var: dict[str, RouterGroupInfo],
) -> ProviderConversionResult:
    result = ProviderConversionResult(
        routes=[],
        gaps=[],
        input_reads_by_function=defaultdict(list),
        effects_by_function=defaultdict(list),
        sinks_by_function=defaultdict(list),
        safe_generated_urls_by_function=defaultdict(list),
        validated_values_by_function=defaultdict(list),
        conditions_by_function=defaultdict(list),
        lifecycle_hooks=[],
        implicit_checks=[],
        control_plane_exemptions=[],
        flow_propagators=[],
        dispatch_edges=[],
    )
    dispatch_matches: list[ProviderMatch] = []
    dependency_matches: list[ProviderMatch] = []
    class_view_matches: list[ProviderMatch] = []

    propagator_result = convert_flow_propagator_matches(matches)
    result.flow_propagators.extend(propagator_result.propagators)
    result.gaps.extend(propagator_result.gaps)

    proxy_flow_result = convert_proxy_flow_matches(matches, idx=idx)
    result.flow_propagators.extend(proxy_flow_result.propagators)
    result.gaps.extend(proxy_flow_result.gaps)

    safe_url_result = convert_safe_generated_url_matches(matches, functions_by_fqn)
    result.gaps.extend(safe_url_result.gaps)
    for safe_url in safe_url_result.safe_generated_urls:
        result.safe_generated_urls_by_function[safe_url.function.fqn].append(safe_url)

    validation_result = convert_validation_guard_matches(matches, functions_by_fqn, idx=idx)
    result.gaps.extend(validation_result.gaps)
    for fqn, values in validation_result.validated_values_by_function.items():
        result.validated_values_by_function[fqn].extend(values)
    for fqn, conditions in validation_result.conditions_by_function.items():
        result.conditions_by_function[fqn].extend(conditions)

    # FLAW-186: recognise arbitrarily-named project-local URL-safety guards by
    # body shape (not name) and emit the same validated-value facts, so renamed
    # / minified guards suppress open-redirect FPs like the named idiom does.
    structural_guard_result = convert_structural_url_guards(idx, functions_by_fqn)
    for fqn, values in structural_guard_result.validated_values_by_function.items():
        result.validated_values_by_function[fqn].extend(values)

    for match in matches:
        if match.phase is not ProviderPhase.ROUTES:
            _collect_non_route_observation(
                match,
                result=result,
                idx=idx,
                functions_by_fqn=functions_by_fqn,
                router_group_info_by_var=router_group_info_by_var,
                dispatch_matches=dispatch_matches,
                dependency_matches=dependency_matches,
            )
            continue

        if isinstance(match.descriptor, ClassViewPattern):
            class_view_matches.append(match)
        else:
            converted_route, route_gaps = convert_route_match(
                match,
                l1_fn_by_fqn,
                router_group_info_by_var,
                idx=idx,
            )
            result.gaps.extend(route_gaps)
            if converted_route is not None:
                result.routes.append(converted_route)

    if class_view_matches:
        cv_routes, cv_gaps = convert_class_view_matches(
            tuple(class_view_matches), idx, l1_fn_by_fqn, router_group_info_by_var
        )
        result.routes.extend(cv_routes)
        result.gaps.extend(cv_gaps)

    _collect_server_state_effects(idx, functions_by_fqn, result.gaps, result.effects_by_function)
    _collect_inferred_state_effects(idx, functions_by_fqn, result.effects_by_function)
    _collect_principal_attr_write_effects(idx, functions_by_fqn, result.effects_by_function)

    dependency_result = convert_dependency_matches(
        dependency_matches,
        matches,
        idx=idx,
        functions_by_fqn=functions_by_fqn,
    )
    result.gaps.extend(dependency_result.gaps)
    for fqn, reads in dependency_result.reads_by_function.items():
        result.input_reads_by_function[fqn].extend(reads)
    for fqn, conditions in dependency_result.conditions_by_function.items():
        result.conditions_by_function[fqn].extend(conditions)
    result.dispatch_edges.extend(dependency_result.dispatch_edges)

    dispatch_result = convert_dispatch_matches(dispatch_matches, functions_by_fqn, idx=idx)
    result.gaps.extend(dispatch_result.gaps)
    result.dispatch_edges.extend(dispatch_result.edges)
    result.lifecycle_hooks.extend(dispatch_result.hooks)

    return result


def _collect_non_route_observation(
    match: ProviderMatch,
    *,
    result: ProviderConversionResult,
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
    router_group_info_by_var: dict[str, RouterGroupInfo],
    dispatch_matches: list[ProviderMatch],
    dependency_matches: list[ProviderMatch],
) -> None:
    """Append one non-route provider match into the mutable conversion state."""
    if match.phase is ProviderPhase.INPUTS:
        input_result = convert_input_match(match, idx, functions_by_fqn)
        result.gaps.extend(input_result.gaps)
        for read in input_result.reads:
            result.input_reads_by_function[read.function.fqn].append(read)
    elif match.phase in {ProviderPhase.EFFECTS, ProviderPhase.PROXIES}:
        effect_result = convert_effect_match(match, functions_by_fqn)
        result.gaps.extend(effect_result.gaps)
        for effect in effect_result.effects:
            result.effects_by_function[effect.function.fqn].append(effect)
    elif match.phase is ProviderPhase.SINKS:
        sink_result = convert_sink_match(match, functions_by_fqn, idx=idx)
        result.gaps.extend(sink_result.gaps)
        for sink in sink_result.sinks:
            result.sinks_by_function[sink.function.fqn].append(sink)
    elif match.phase is ProviderPhase.CHECKS:
        check_result = convert_check_matches((match,), functions_by_fqn, idx=idx)
        result.gaps.extend(check_result.gaps)
        for fqn, conditions in check_result.conditions_by_function.items():
            result.conditions_by_function[fqn].extend(conditions)
    elif match.phase is ProviderPhase.LIFECYCLE:
        lifecycle_result = convert_lifecycle_match(
            match, functions_by_fqn, router_group_info_by_var
        )
        result.gaps.extend(lifecycle_result.gaps)
        result.lifecycle_hooks.extend(lifecycle_result.hooks)
        result.implicit_checks.extend(lifecycle_result.implicit_checks)
        result.control_plane_exemptions.extend(lifecycle_result.exemptions)
    elif match.phase is ProviderPhase.DEPENDENCIES:
        dependency_matches.append(match)
    elif match.phase is ProviderPhase.DISPATCHES:
        dispatch_matches.append(match)


def _resolve_functions(
    fqns: Iterable[str],
    functions_by_fqn: Mapping[str, Function],
    *,
    first: str | None = None,
) -> tuple[Function, ...]:
    """Resolve a set of FQNs to Function objects in deterministic order.

    *first* (the handler/owner) is listed first when present; the remainder
    follow in sorted FQN order.  Sorting makes the resulting collection (and
    thus ``scope.reachable_functions()``) deterministic regardless of the
    iteration order of the input -- defensive belt-and-braces now that
    ``reachable_callees`` already returns a stable order (FLAW-161), and
    independently correct for any other caller.
    """
    ordered: list[Function] = []
    seen: set[str] = set()
    if first is not None and first in functions_by_fqn:
        ordered.append(functions_by_fqn[first])
        seen.add(first)
    for fqn in sorted(fqns):
        if fqn in seen:
            continue
        fn = functions_by_fqn.get(fqn)
        if fn is not None:
            ordered.append(fn)
            seen.add(fqn)
    return tuple(ordered)


def _attach_route_body_scopes(
    routes: tuple[Route, ...],
    *,
    semantic_gaps: list[AnalysisGap],
    input_reads_by_function: dict[str, list[InputRead]],
    effects_by_function: dict[str, list[Effect]],
    sinks_by_function: dict[str, list[TaintSink]],
    safe_generated_urls_by_function: dict[str, list[SafeGeneratedURL]],
    validated_values_by_function: dict[str, list[ValidatedValue]],
    type_disagreements_by_function: dict[str, list[TypeDisagreement]],
    conditions_by_function: dict[str, list[Condition]],
    predicates_by_function: dict[str, list[ConcretePredicate]],
    lifecycle_hooks: tuple[LifecycleHook, ...],
    implicit_checks: tuple[ImplicitCheck, ...],
    control_plane_exemptions: tuple[ControlPlaneExemption, ...],
    group_ancestry: Mapping[str, frozenset[str]],
    call_sites_by_caller: dict[str, list[CallSite]],
    l1_fn_by_fqn: dict[str, FunctionRecord],
    functions_by_fqn: Mapping[str, Function],
    callee_graph: dict[str, set[str]],
    reachable_cache: dict[str, tuple[str, ...]] | None = None,
    idx: CodeIndex,
) -> tuple[Route, ...]:
    """Attach handler-body scopes including callee input reads.

    Traverses the L1 call graph from each handler to collect input reads
    from reachable callee functions.  This surfaces cross-function and
    cross-file input reads on the route's body scope without requiring
    framework-specific knowledge.
    """
    for route in routes:
        handler = functions_by_fqn.get(route.handler.fqn)
        if handler is not None:
            object.__setattr__(route, "handler", handler)
        handler_gaps = handler.gaps if handler is not None else ()
        reachable = reachable_callees(route.handler.fqn, callee_graph, cache=reachable_cache)
        (
            body_reads,
            body_effects,
            body_sinks,
            body_call_sites,
            body_conditions,
            body_decs,
            body_gaps,
        ) = _scope_parts_for_functions(
            tuple(reachable),
            input_reads_by_function=input_reads_by_function,
            effects_by_function=effects_by_function,
            sinks_by_function=sinks_by_function,
            conditions_by_function=conditions_by_function,
            call_sites_by_caller=call_sites_by_caller,
            functions_by_fqn=functions_by_fqn,
        )
        body_safe_generated_urls = _safe_generated_urls_for_functions(
            tuple(reachable),
            safe_generated_urls_by_function,
        )
        body_validated_values = _validated_values_for_functions(
            tuple(reachable),
            validated_values_by_function,
        )
        body_type_disagreements = _type_disagreements_for_functions(
            tuple(reachable),
            type_disagreements_by_function,
        )
        body_predicates = _predicates_for_functions(tuple(reachable), predicates_by_function)
        route_path_result = path_param_reads_for_route(route, l1_fn_by_fqn)
        route_path_reads = tuple(route_path_result.reads)
        if route_path_result.gaps:
            semantic_gaps.extend(route_path_result.gaps)
            object.__setattr__(
                route,
                "_gaps",
                dedupe_gaps((*route.gaps, *route_path_result.gaps)),
            )
        # Append route-path reads, then re-resolve generic multi-key accessor
        # reads (wildcard + gap globally) to this route's own key using only
        # callers in the route's reachable closure -- no cross-route leak (FLAW-243).
        _finalize_scope_reads(
            body_reads,
            route_path_reads,
            allowed_caller_fqns=frozenset(reachable) | {route.handler.fqn},
            idx=idx,
            functions_by_fqn=functions_by_fqn,
        )
        method_branches, branch_gaps = build_method_branch_scopes(
            route,
            idx,
            functions_by_fqn,
            input_reads_by_function=input_reads_by_function,
            effects_by_function=effects_by_function,
            sinks_by_function=sinks_by_function,
            safe_generated_urls_by_function=safe_generated_urls_by_function,
            validated_values_by_function=validated_values_by_function,
            conditions_by_function=conditions_by_function,
            call_sites_by_caller=call_sites_by_caller,
            callee_graph=callee_graph,
            route_input_reads=route_path_reads,
        )
        # FLAW-231: a dynamic-dispatch call reachable from the handler truncates
        # the reachable closure (its target's reads/effects are unattributed).
        # Surface that as a gap rather than a silent false negative.
        body_gaps.extend(
            _unresolved_dispatch_gaps(
                tuple(reachable), idx.call_graph, origin_phase="reachable_closure"
            )
        )
        body_scope = ConcreteCodeScope(
            input_reads=tuple(body_reads),
            effects=tuple(body_effects),
            sinks=tuple(body_sinks),
            safe_generated_urls=body_safe_generated_urls,
            validated_values=tuple(body_validated_values),
            type_disagreements=body_type_disagreements,
            call_sites=tuple(body_call_sites),
            conditions=tuple(body_conditions),
            predicates=body_predicates,
            decorators=tuple(body_decs),
            gaps=dedupe_gaps((*route.gaps, *handler_gaps, *body_gaps, *branch_gaps)),
            cfg=ControlFlowView(idx.cfg(route.handler.fqn), gaps=handler_gaps),
            method_branches=method_branches,
            functions=_resolve_functions(reachable, functions_by_fqn, first=route.handler.fqn),
        )
        object.__setattr__(route, "_body_scope", body_scope)
        # FLAW-242b: route.reachable carries the SAME interprocedurally-collected
        # reads/effects as route.body, but exposes the *interprocedural* CFG (per the
        # documented contract in scopes.py: body.cfg intra-procedural, reachable.cfg
        # interprocedural) so auth-ordering rules can confirm read-before-write
        # across a resolved call hop. ``precedes`` stays conservative -- True only
        # when proven, never fabricated. (Same fields as body_scope bar the CFG; a
        # scope-clone-with-cfg helper would DRY this up once _scope.py is free.)
        reachable_scope = ConcreteCodeScope(
            input_reads=tuple(body_reads),
            effects=tuple(body_effects),
            sinks=tuple(body_sinks),
            safe_generated_urls=body_safe_generated_urls,
            validated_values=tuple(body_validated_values),
            type_disagreements=body_type_disagreements,
            call_sites=tuple(body_call_sites),
            conditions=tuple(body_conditions),
            predicates=body_predicates,
            decorators=tuple(body_decs),
            gaps=dedupe_gaps((*route.gaps, *handler_gaps, *body_gaps, *branch_gaps)),
            cfg=InterproceduralControlFlowView(
                root_fqn=route.handler.fqn,
                index=idx,
                reachable_fqns=reachable,
                gaps=handler_gaps,
            ),
            method_branches=method_branches,
            functions=_resolve_functions(reachable, functions_by_fqn, first=route.handler.fqn),
        )
        object.__setattr__(route, "_reachable_scope", reachable_scope)

        # Lifecycle hook handler FQNs that apply to this route (before/after
        # request hooks, blueprint- and app-scoped, including nested groups).
        hook_fqns = lifecycle_function_fqns_for_route(route, lifecycle_hooks, group_ancestry)
        lifecycle_reachable: set[str] = set()
        for hook_fqn in hook_fqns:
            lifecycle_reachable.update(
                reachable_callees(hook_fqn, callee_graph, cache=reachable_cache)
            )
        # Surface the hook handler functions directly (FLAW-129): rule authors
        # otherwise infer hook presence from callee FQNs.  Deterministic order.
        object.__setattr__(
            route,
            "_lifecycle_hooks",
            _resolve_functions(hook_fqns, functions_by_fqn),
        )
        full_stack_fqns = tuple(dict.fromkeys((*reachable, *sorted(lifecycle_reachable))))
        (
            full_stack_reads,
            full_stack_effects,
            full_stack_sinks,
            full_stack_call_sites,
            full_stack_conditions,
            full_stack_decs,
            full_stack_gaps,
        ) = _scope_parts_for_functions(
            full_stack_fqns,
            input_reads_by_function=input_reads_by_function,
            effects_by_function=effects_by_function,
            sinks_by_function=sinks_by_function,
            conditions_by_function=conditions_by_function,
            call_sites_by_caller=call_sites_by_caller,
            functions_by_fqn=functions_by_fqn,
        )
        full_stack_safe_generated_urls = _safe_generated_urls_for_functions(
            full_stack_fqns,
            safe_generated_urls_by_function,
        )
        full_stack_validated_values = _validated_values_for_functions(
            full_stack_fqns,
            validated_values_by_function,
        )
        full_stack_type_disagreements = _type_disagreements_for_functions(
            full_stack_fqns,
            type_disagreements_by_function,
        )
        full_stack_predicates = _predicates_for_functions(full_stack_fqns, predicates_by_function)
        # FLAW-243: same finalize (extend + per-route re-key) over the full stack.
        _finalize_scope_reads(
            full_stack_reads,
            route_path_reads,
            allowed_caller_fqns=frozenset(full_stack_fqns) | {route.handler.fqn},
            idx=idx,
            functions_by_fqn=functions_by_fqn,
        )
        # Inject implicit checks from lifecycle registrations (e.g. CSRFProtect.init_app).
        _empty = ConcreteCodeScope()
        implicit_check_gaps: list[AnalysisGap] = []
        for ic in implicit_checks:
            if ic.hook_type not in {HookType.BEFORE_HANDLER, HookType.AFTER_HANDLER}:
                continue
            if not implicit_check_applies_to_route(ic, route):
                continue
            implicit_check_gaps.extend(ic.gaps)
            full_stack_conditions.append(
                ConcreteCondition(
                    expression=ic.expression,
                    location=ic.location,
                    function=route.handler,
                    kind=ConditionKind.CALL_RESULT,
                    provenance=ic.provenance,
                    category=ic.category,
                    provider_id=ic.provider_id,
                    _true_branch=_empty,
                    _false_branch=_empty,
                    _guard=GuardClassification(
                        guarded_branch=_empty,
                        denied_branch=_empty,
                        denial_kind=DenialKind.UNKNOWN,
                        confidence=0.8,
                    ),
                )
            )
        # Attribute call-form control-plane exemptions (e.g. module-level
        # ``csrf.exempt(view)`` / ``csrf.exempt(blueprint)``) onto the targeted
        # route(s).  The call form has no enclosing function, so the ordinary
        # effect-conversion path drops it; here it surfaces as a non-body
        # full_stack effect that effect-based consumers (``is_csrf_exemption``
        # over ``Config.write()`` effects) recognise -- symmetric with how a
        # programmatic lifecycle-hook exemption already appears in full_stack.
        if handler is not None:
            for exemption in control_plane_exemptions:
                if control_plane_exemption_applies_to_route(exemption, route):
                    full_stack_effects.append(build_exemption_effect(exemption, handler))
        # FLAW-231: same closure-truncation gap over the full lifecycle stack
        # (handler + before/after-request hooks and their callees).
        full_stack_gaps.extend(
            _unresolved_dispatch_gaps(
                full_stack_fqns, idx.call_graph, origin_phase="full_stack_closure"
            )
        )
        full_stack_scope = ConcreteCodeScope(
            input_reads=tuple(full_stack_reads),
            effects=tuple(full_stack_effects),
            sinks=tuple(full_stack_sinks),
            safe_generated_urls=full_stack_safe_generated_urls,
            validated_values=tuple(full_stack_validated_values),
            type_disagreements=full_stack_type_disagreements,
            call_sites=tuple(full_stack_call_sites),
            conditions=tuple(full_stack_conditions),
            predicates=full_stack_predicates,
            decorators=tuple(full_stack_decs),
            gaps=dedupe_gaps((*route.gaps, *handler_gaps, *full_stack_gaps, *implicit_check_gaps)),
            functions=_resolve_functions(
                full_stack_fqns, functions_by_fqn, first=route.handler.fqn
            ),
        )
        object.__setattr__(route, "_full_stack_scope", full_stack_scope)
        object.__setattr__(
            route,
            "_gaps",
            dedupe_gaps(
                (
                    *route.gaps,
                    *handler_gaps,
                    *body_gaps,
                    *full_stack_gaps,
                    *implicit_check_gaps,
                    *branch_gaps,
                )
            ),
        )
        object.__setattr__(route, "_repo_path", str(idx.repo_root))
    return routes


def _scope_parts_for_functions(
    function_fqns: tuple[str, ...],
    *,
    input_reads_by_function: dict[str, list[InputRead]],
    effects_by_function: dict[str, list[Effect]],
    sinks_by_function: dict[str, list[TaintSink]],
    conditions_by_function: dict[str, list[Condition]],
    call_sites_by_caller: dict[str, list[CallSite]],
    functions_by_fqn: Mapping[str, Function],
) -> tuple[
    list[InputRead],
    list[Effect],
    list[TaintSink],
    list[CallSite],
    list[Condition],
    list[Decorator],
    list[AnalysisGap],
]:
    reads: list[InputRead] = []
    effects: list[Effect] = []
    sinks: list[TaintSink] = []
    call_sites: list[CallSite] = []
    conditions: list[Condition] = []
    decorators: list[Decorator] = []
    gaps: list[AnalysisGap] = []
    for fn_fqn in function_fqns:
        reads.extend(input_reads_by_function.get(fn_fqn, ()))
        effects.extend(effects_by_function.get(fn_fqn, ()))
        sinks.extend(sinks_by_function.get(fn_fqn, ()))
        call_sites.extend(call_sites_by_caller.get(fn_fqn, ()))
        conditions.extend(conditions_by_function.get(fn_fqn, ()))
        fn = functions_by_fqn.get(fn_fqn)
        if fn is not None:
            decorators.extend(fn.decorators)
            gaps.extend(fn.gaps)
    return reads, effects, sinks, call_sites, conditions, decorators, gaps


def _unresolved_dispatch_gaps(
    function_fqns: tuple[str, ...] | frozenset[str],
    call_graph: CallGraph,
    *,
    origin_phase: str,
) -> list[AnalysisGap]:
    """Surface a reachable closure truncated by dynamic dispatch as a gap.

    The reachable scope of a route/function is built by following *resolved*
    call edges only (``build_callee_graph`` keeps an edge only when its
    ``callee_fqn`` is known).  A *dynamic-dispatch* call whose target could not
    be resolved -- ``handlers[name]()``, ``getattr(obj, name)()`` -- therefore
    silently truncates the closure: input reads and effects in the
    dispatched-to function are absent from ``reachable.reads()`` /
    ``reachable.effects()`` with no signal that analysis stopped there.  That is
    a silent false negative, the scope-level analog of the tracer dead-end
    closed in FLAW-217.  Emit a ``VALUE_FLOW_INCOMPLETE`` gap for each such call
    so the incompleteness is honest rather than invisible (priority 1: a gap
    beats a silent miss).

    Gated on ``dynamic_dispatch_kind`` so ordinary library / builtin / bound
    method boundaries (``request.args.get(...)``, ``str.lower()``) -- which are
    expected analysis boundaries, not closure truncations that hide project
    code -- never produce gaps.  Deduplicated by call-site location so a hot
    dispatch site reachable from many functions yields one gap.
    """
    gaps: list[AnalysisGap] = []
    seen: set[tuple[str, int, str]] = set()
    for fqn in function_fqns:
        for edge in call_graph.edges_from(fqn):
            if edge.callee_fqn is not None or edge.dynamic_dispatch_kind is None:
                continue
            expression = edge.call_expression or edge.unresolved_reason or "<dynamic call>"
            key = (edge.location.file, edge.location.line, expression)
            if key in seen:
                continue
            seen.add(key)
            gaps.append(
                AnalysisGap(
                    kind=GapKind.VALUE_FLOW_INCOMPLETE,
                    message=(
                        "Reachable-code analysis is incomplete: dynamic call "
                        f"`{expression}` in {fqn} resolves to no known target, so "
                        "reads and effects reachable through it are not attributed "
                        "to this scope."
                    ),
                    affected_file=edge.location.file,
                    affected_function=fqn,
                    source_error=edge.unresolved_reason,
                    origin_phase=origin_phase,
                )
            )
    return gaps


def _safe_generated_urls_for_functions(
    function_fqns: tuple[str, ...] | frozenset[str],
    safe_generated_urls_by_function: dict[str, list[SafeGeneratedURL]],
) -> tuple[SafeGeneratedURL, ...]:
    safe_urls: list[SafeGeneratedURL] = []
    for fn_fqn in function_fqns:
        safe_urls.extend(safe_generated_urls_by_function.get(fn_fqn, ()))
    return _dedupe_domain(safe_urls)


def _validated_values_for_functions(
    function_fqns: tuple[str, ...] | frozenset[str],
    validated_values_by_function: dict[str, list[ValidatedValue]],
) -> tuple[ValidatedValue, ...]:
    values: list[ValidatedValue] = []
    for fn_fqn in function_fqns:
        values.extend(validated_values_by_function.get(fn_fqn, ()))
    return _dedupe_domain(values)


def _convert_structural_facts(
    idx: CodeIndex,
    fn_by_fqn: Mapping[str, Function],
) -> tuple[dict[str, list[Condition]], dict[str, list[ConcretePredicate]]]:
    """Lift L1 branch conditions and sibling value predicates (FLAW-113).

    Both are returned as mutable per-function lists so later phases can
    append provider-derived facts.  Kept together because they share the
    same L1 CFG source, but they remain distinct dicts: ``predicates()``
    never feeds the branch-only ``conditions()`` surface.
    """
    conditions_by_function: dict[str, list[Condition]] = {
        fqn: list(conditions)
        for fqn, conditions in convert_structural_conditions(idx, fn_by_fqn).items()
    }
    predicates_by_function: dict[str, list[ConcretePredicate]] = {
        fqn: list(predicates)
        for fqn, predicates in convert_value_predicates(idx, fn_by_fqn).items()
    }
    return conditions_by_function, predicates_by_function


def _predicates_for_functions(
    function_fqns: tuple[str, ...] | frozenset[str],
    predicates_by_function: dict[str, list[ConcretePredicate]],
) -> tuple[ConcretePredicate, ...]:
    """Aggregate value predicates across a set of reachable functions.

    Kept separate from ``_scope_parts_for_functions`` so the established
    branch-condition tuple machinery stays untouched: predicates are a
    sibling fact, not a variant of conditions.
    """
    predicates: list[ConcretePredicate] = []
    for fn_fqn in function_fqns:
        predicates.extend(predicates_by_function.get(fn_fqn, ()))
    return tuple(predicates)


def _type_disagreements_by_function(
    disagreements: tuple[TypeDisagreement, ...],
) -> dict[str, list[TypeDisagreement]]:
    by_function: dict[str, list[TypeDisagreement]] = defaultdict(list)
    for disagreement in disagreements:
        if disagreement.containing_function_fqn is None:
            continue
        by_function[disagreement.containing_function_fqn].append(disagreement)
    return by_function


def _type_disagreements_for_functions(
    function_fqns: tuple[str, ...] | frozenset[str],
    type_disagreements_by_function: dict[str, list[TypeDisagreement]],
) -> tuple[TypeDisagreement, ...]:
    disagreements: list[TypeDisagreement] = []
    for fn_fqn in function_fqns:
        disagreements.extend(type_disagreements_by_function.get(fn_fqn, ()))
    return tuple(dict.fromkeys(disagreements))


def _merge_routes(routes: tuple[Route, ...]) -> tuple[Route, ...]:
    """Merge duplicate registrations into stable public Route objects.

    The merge key intentionally includes route metadata that changes request
    semantics.  A single handler can be reused for distinct URLs, router groups,
    providers, or group-scoped security contexts; those routes must remain
    separate so later lifecycle/check attachment sees the correct context.
    """
    merged: dict[tuple[str, str, str, str | None, str | None, str | None], Route] = {}
    for route in routes:
        key = _route_merge_key(route)
        existing = merged.get(key)
        if existing is None:
            merged[key] = route
            continue

        base, other = (
            (route, existing)
            if _route_sort_key(route) < _route_sort_key(existing)
            else (existing, route)
        )
        object.__setattr__(base, "methods", existing.methods | route.methods)
        object.__setattr__(base, "_gaps", dedupe_gaps((*base.gaps, *other.gaps)))
        merged[key] = base

    return tuple(sorted(merged.values(), key=_route_sort_key))


def _route_merge_key(
    route: Route,
) -> tuple[str, str, str, str | None, str | None, str | None]:
    return (
        route.endpoint,
        route.handler.fqn,
        route.url_rule,
        route.group,
        _route_provider_id(route),
        _route_router_group_variable_fqn(route),
    )


def _route_provider_id(route: Route) -> str | None:
    try:
        value: object = object.__getattribute__(route, "_provider_id")
    except AttributeError:
        return None
    return value if isinstance(value, str) else None


def _route_router_group_variable_fqn(route: Route) -> str | None:
    try:
        value: object = object.__getattribute__(route, "_router_group_variable_fqn")
    except AttributeError:
        return None
    return value if isinstance(value, str) else None


def _route_sort_key(route: Route) -> tuple[str, int, int, str, str]:
    return (
        route.location.file,
        route.location.line,
        route.location.column,
        route.url_rule,
        route.endpoint,
    )


def _finalize_scope_reads(
    reads: list[InputRead],
    route_path_reads: tuple[InputRead, ...],
    *,
    allowed_caller_fqns: frozenset[str],
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> None:
    """Append route-path reads, then re-key wildcard accessor reads for this scope.

    Combines the two finalisation steps a route scope needs (FLAW-243): the
    route's path-parameter reads are merged in, and any generic multi-key
    accessor read is re-resolved to this scope's own key.
    """
    _extend_input_reads_once(reads, route_path_reads)
    _rekey_scope_reads(
        reads,
        allowed_caller_fqns=allowed_caller_fqns,
        idx=idx,
        functions_by_fqn=functions_by_fqn,
    )


def _rekey_scope_reads(
    reads: list[InputRead],
    *,
    allowed_caller_fqns: frozenset[str],
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> None:
    """In place: re-resolve generic multi-key accessor reads for this scope.

    Replaces each wildcard read marked for per-route re-keying (FLAW-243) with a
    copy carrying the literal key resolved along this scope's own call paths.
    Reads without the marker (the common case) are left untouched.
    """
    for i, read in enumerate(reads):
        rekeyed = rekey_read_for_scope(
            read,
            allowed_caller_fqns=allowed_caller_fqns,
            idx=idx,
            functions_by_fqn=functions_by_fqn,
        )
        if rekeyed is not None:
            reads[i] = rekeyed


def _extend_input_reads_once(
    target: list[InputRead],
    additions: tuple[InputRead, ...],
) -> None:
    """Append route-derived reads without duplicating provider-derived reads."""
    seen = {_input_read_identity(read) for read in target}
    for read in additions:
        identity = _input_read_identity(read)
        if identity in seen:
            continue
        target.append(read)
        seen.add(identity)


def _input_read_identity(read: InputRead) -> tuple[object, ...]:
    return (
        read.source,
        read.function.fqn,
        read.location.file,
        read.location.line,
        read.location.column,
    )


class ConcreteRepoView:
    """Concrete implementation of RepoView backed by WebApp data.

    This is the actual runtime object returned to rule authors. It
    implements the RepoView interface with real data from L2 conversion.
    """

    __slots__ = (
        "_blueprints",
        "_call_graph",
        "_classes",
        "_flow_engine",
        "_flow_propagators",
        "_function_records",
        "_functions",
        "_gaps",
        "_routes",
        "_type_disagreements",
        "path",
        "snapshot",
    )

    # Explicit annotations so the static type matches the RepoView Protocol.
    # Without these, mypy infers ``snapshot`` as ``None`` from ``self.snapshot
    # = None`` in __init__, which is invariant-incompatible with the
    # Protocol's ``str | None`` and breaks structural conformance.
    path: str
    snapshot: str | None

    def __init__(
        self,
        *,
        path: str,
        functions: ConcreteFunctionCollection,
        function_records: tuple[FunctionRecord, ...],
        classes: ConcreteClassCollection,
        routes: ConcreteRouteCollection,
        type_disagreements: tuple[TypeDisagreement, ...],
        value_flow: ValueFlowGraph,
        call_graph: CallGraph,
        blueprints: ConcreteBlueprintCollection | None = None,
        flow_propagators: tuple[FlowPropagationEdge, ...] = (),
        gaps: tuple[AnalysisGap, ...] = (),
    ) -> None:
        self.path = path
        self.snapshot = None
        self._functions = functions
        self._function_records = function_records
        self._classes = classes
        self._routes = routes
        self._blueprints = blueprints if blueprints is not None else ConcreteBlueprintCollection()
        self._type_disagreements = type_disagreements
        self._flow_propagators = flow_propagators
        self._gaps = gaps
        self._call_graph = call_graph
        self._flow_engine = _SemanticFlowEngine(
            value_flow=value_flow,
            call_graph=call_graph,
            function_records=function_records,
            functions=functions,
            routes=routes,
            flow_propagators=flow_propagators,
        )

    @property
    def routes(self) -> ConcreteRouteCollection:
        """All HTTP routes identified in the repository."""
        return self._routes

    @property
    def functions(self) -> ConcreteFunctionCollection:
        """All functions discovered in the repository."""
        return self._functions

    @property
    def classes(self) -> ConcreteClassCollection:
        """All classes discovered in the repository."""
        return self._classes

    @property
    def blueprints(self) -> ConcreteBlueprintCollection:
        """All route groups (blueprints/routers) identified in the repository."""
        return self._blueprints

    @property
    def gaps(self) -> tuple[AnalysisGap, ...]:
        """Repository-level semantic analysis gaps."""
        return self._gaps

    @property
    def type_disagreements(self) -> tuple[TypeDisagreement, ...]:
        """Concrete type-checker disagreement signals in the repository."""
        return self._type_disagreements

    def trace_flow(self, source: Location, sink: Location) -> FlowTrace:
        """Trace data flow between two specific source locations.

        Supports intra-function traces backed by the L1 value-flow graph plus
        one-hop interprocedural stitches through the L1 call graph.
        """
        return self._flow_engine.trace_locations(source, sink)

    @property
    def flow_query_stats(self) -> tuple[int, int]:
        """Scan-cumulative ``(flow_query_count, bfs_count)`` (FLAW-194 telemetry).

        The L3 detector loop reads this before and after each rule; the delta is
        the flow-query cost attributable to that rule. Pure observation.
        """
        return self._flow_engine.flow_query_stats


__all__ = [
    "ConcreteRepoView",
    "WebApp",
    "clear_repo_view_cache",
    "repo_view_from_artifacts",
    "repo_view_from_path",
    "repo_view_from_path_cached",
]
