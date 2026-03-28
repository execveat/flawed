"""Call graph merge — combine edges from AST and hierarchy sources.

Implements the additive merge strategy from §5.2 of the spec: edges are
unioned with deduplication + source tagging. Consensus edges (same
caller+callee+site from ≥2 sources) receive highest confidence.
Conflicting targets at the same call site are kept as parallel
alternatives.

The merge produces a single :class:`CallGraph` that Layer 2 consumes.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from flawed._index._graphs import CallGraph
from flawed._index._types import (
    CallEdge,
    ClassRecord,
    EdgeSource,
    ExtractionError,
    ExtractionProvenance,
    FunctionRecord,
    ResolutionProvenance,
    ResolutionStatus,
)

# =====================================================================
# Edge identity key
# =====================================================================

# Two edges are "the same" if they share caller, callee, and call-site.
# This is used for deduplication and consensus detection.
type _FullKey = tuple[str, str | None, str, int]  # caller, callee, file, line

# A "site key" groups all edges that originate from the same call site
# regardless of which callee they resolve to.  Used to detect conflicts
# (same site, different callees).
type _SiteKey = tuple[str, str, int]  # caller, file, line


def _full_key(e: CallEdge) -> _FullKey:
    return (e.caller_fqn, e.callee_fqn, e.location.file, e.location.line)


def _site_key(e: CallEdge) -> _SiteKey:
    return (e.caller_fqn, e.location.file, e.location.line)


# =====================================================================
# Source priority (higher = preferred)
# =====================================================================

_SOURCE_PRIORITY: dict[EdgeSource, int] = {
    EdgeSource.HIERARCHY: 0,
    EdgeSource.AST: 1,
}

_MERGE_PROVENANCE = ExtractionProvenance(
    producer="call_graph_merge",
    producer_version="0.1.0",
    artifact="merged_call_graph",
)


# =====================================================================
# Public API
# =====================================================================


def _representative(group: list[CallEdge]) -> CallEdge:
    """Pick the edge resolution keeps for a full-key group (same caller/callee/site).

    Highest source priority wins the base edge. Different contributors to the same
    full key can carry complementary detail, so the base is enriched (never
    overridden) from the group: the richest argument list, a method-call receiver,
    and the call-target text are each restored from any contributor that has them —
    so a lower-priority edge can still donate a fact the base lacks.
    """
    best = max(group, key=lambda e: _SOURCE_PRIORITY.get(e.source, -1))
    updates: dict[str, Any] = {}
    richest_args = max((edge.arguments for edge in group), key=len)
    if len(richest_args) > len(best.arguments):
        updates["arguments"] = richest_args
    # The base may lack a faithful method-call receiver (receiver_expression/
    # _location). Dropping it silently erases the ``recv.method(...)`` shape that
    # receiver-keyed interpreters need — e.g. inferred_state_writes, which then
    # misses a real persistent write (an FN). Restore the receiver from any
    # contributor that carries it; the chosen source is unchanged.
    if best.receiver_expression is None:
        donor = next((e for e in group if e.receiver_expression is not None), None)
        if donor is not None:
            updates["receiver_expression"] = donor.receiver_expression
            updates["receiver_location"] = donor.receiver_location
    # The base may likewise lack the call-target text (call_expression is None).
    # Dropping it nulls EnrichedCallSite.target_expression, which target-keyed
    # provenance specs filter on (intra/interproc claim correlation keys calls
    # whose target_expression == "sink"). Restore it from any contributor that
    # carries it — fill-only, never override a present value, so the call-target
    # convention (target-only, no args) is preserved.
    if not best.call_expression:
        donor = next((e for e in group if e.call_expression), None)
        if donor is not None:
            updates["call_expression"] = donor.call_expression
    return dataclasses.replace(best, **updates) if updates else best


def merge_call_graph(
    ast_edges: tuple[CallEdge, ...],
    hierarchy_edges: tuple[CallEdge, ...] = (),
) -> tuple[CallGraph, tuple[ExtractionError, ...]]:
    """Merge call-graph edges from multiple extraction sources.

    Returns a unified :class:`CallGraph` and any errors encountered
    during the merge.

    Algorithm
    ---------
    1. **Group by full key** ``(caller, callee, file, line)`` to find
       duplicates (same edge from multiple sources → consensus).
    2. **Group by site key** ``(caller, file, line)`` to find conflicts
       (same call site, different callees).
    3. **Tag consensus** edges with ``confidence=1.0``.
    4. **Tag unique** edges with the source's default confidence.
    5. **Tag conflicting** edges: keep all (additive for security) but
       mark with lower confidence and record alternatives.
    """
    errors: list[ExtractionError] = []

    # Phase 1: Collect all edges, grouped by full key and site key.
    by_full: dict[_FullKey, list[CallEdge]] = {}
    by_site: dict[_SiteKey, list[CallEdge]] = {}

    for edge in (*ast_edges, *hierarchy_edges):
        fk = _full_key(edge)
        by_full.setdefault(fk, []).append(edge)
        sk = _site_key(edge)
        by_site.setdefault(sk, []).append(edge)

    # Phase 2: Resolve each full-key group into a single representative
    # edge, annotated with ResolutionProvenance.
    resolved: dict[_FullKey, CallEdge] = {}

    for fk, group in by_full.items():
        sources = tuple(sorted({e.source.value for e in group}))
        is_consensus = len({e.source for e in group}) >= 2

        best = _representative(group)

        confidence = 1.0 if is_consensus else _source_confidence(best.source)
        selected = "consensus" if is_consensus else best.source.value
        res_prov = ResolutionProvenance(
            selected_source=selected,
            contributing_sources=sources,
            alternatives=None,
            verification_method=None,
            confidence=confidence,
        )

        # Build a merged edge from the best representative.
        resolved[fk] = _with_resolution_provenance(best, res_prov)

    # Phase 3: Detect site-level conflicts (same site, different callees).
    # All alternatives are already in `resolved` from Phase 2 because we
    # process every full key.  Here we just annotate the *alternatives*
    # provenance field so consumers can see what the disagreement was.
    for site_group in by_site.values():
        callees_at_site = {e.callee_fqn for e in site_group if e.callee_fqn is not None}
        if len(callees_at_site) <= 1:
            continue  # no conflict

        # Multiple different callees at the same site.  Tag each
        # resolved edge with the alternatives it was chosen over.
        alts = tuple(sorted(callees_at_site))
        for edge in site_group:
            fk = _full_key(edge)
            if fk not in resolved:
                continue
            existing = resolved[fk]
            other_fqns = tuple(c for c in alts if c != existing.callee_fqn)
            if not other_fqns:
                continue
            # Downgrade confidence for ambiguous edges.
            old_prov = _get_resolution_provenance(existing)
            new_prov = ResolutionProvenance(
                selected_source=old_prov.selected_source if old_prov else existing.source.value,
                contributing_sources=(
                    old_prov.contributing_sources if old_prov else (existing.source.value,)
                ),
                alternatives=other_fqns,
                verification_method="site_conflict_detected",
                confidence=min(
                    old_prov.confidence if old_prov else 0.8,
                    0.7,
                ),
            )
            resolved[fk] = _with_resolution_provenance(existing, new_prov)

    merged_edges = tuple(resolved.values())
    return CallGraph(merged_edges), tuple(errors)


def build_hierarchy_edges(
    classes: tuple[ClassRecord, ...],
    functions: tuple[FunctionRecord, ...],
    call_edges: tuple[CallEdge, ...],
) -> tuple[CallEdge, ...]:
    """Produce call-graph edges resolved through the class hierarchy.

    For ``self.method()`` calls inside a method, resolves the target
    through the class's MRO to find the actual defining class.

    This is best-effort: when MRO is incomplete, no hierarchy edge is
    produced.
    """
    # Build lookup: method FQN → FunctionRecord.
    fn_by_fqn: dict[str, FunctionRecord] = {f.fqn: f for f in functions}

    # Build MRO method resolution: for each class, map method name →
    # the FQN where it's actually defined (through MRO traversal).
    mro_resolve: dict[str, dict[str, str]] = {}  # class_fqn → {method_name → defining_fqn}
    for cls in classes:
        resolution: dict[str, str] = {}
        for method_name in cls.method_names:
            resolution[method_name] = f"{cls.fqn}.{method_name}"
        for inh in cls.inherited_methods:
            if inh.name not in resolution:
                resolution[inh.name] = f"{inh.defining_class_fqn}.{inh.name}"
        mro_resolve[cls.fqn] = resolution

    hierarchy_edges: list[CallEdge] = []
    prov = ExtractionProvenance(
        producer="hierarchy_resolution",
        producer_version="0.1.0",
        artifact="hierarchy_edges",
    )

    for edge in call_edges:
        if edge.callee_fqn is None:
            continue

        # Only interested in unresolved or partially resolved self.method() calls.
        caller_fn = fn_by_fqn.get(edge.caller_fqn)
        if caller_fn is None or caller_fn.parent_class is None:
            continue

        # Check if the callee looks like a method call that could be
        # resolved via MRO.  This is a heuristic: if the callee FQN
        # ends with a method name and the caller's class has MRO data.
        parts = edge.callee_fqn.rsplit(".", maxsplit=1)
        if len(parts) != 2:
            continue
        _class_part, method_name = parts

        caller_class = caller_fn.parent_class
        if caller_class not in mro_resolve:
            continue

        mro_method_fqn = mro_resolve[caller_class].get(method_name)
        if mro_method_fqn is None or mro_method_fqn == edge.callee_fqn:
            continue  # already resolved correctly or not in MRO

        hierarchy_edges.append(
            CallEdge(
                caller_fqn=edge.caller_fqn,
                callee_fqn=mro_method_fqn,
                arguments=edge.arguments,
                resolution=ResolutionStatus.RESOLVED,
                source=EdgeSource.HIERARCHY,
                unresolved_reason=None,
                location=edge.location,
                provenance=prov,
            )
        )

    return tuple(hierarchy_edges)


# =====================================================================
# Helpers
# =====================================================================


def _source_confidence(source: EdgeSource) -> float:
    """Default confidence for a single-source edge."""
    return {
        EdgeSource.AST: 0.80,
        EdgeSource.HIERARCHY: 0.70,
    }.get(source, 0.5)


def _with_resolution_provenance(edge: CallEdge, prov: ResolutionProvenance) -> CallEdge:
    """Return a copy of *edge* with a new provenance that records the resolution."""
    new_extraction_prov = ExtractionProvenance(
        producer=prov.selected_source,
        producer_version=edge.provenance.producer_version,
        artifact=edge.provenance.artifact,
    )
    return dataclasses.replace(edge, provenance=new_extraction_prov)


def _get_resolution_provenance(edge: CallEdge) -> ResolutionProvenance | None:
    """Extract resolution provenance from an edge's metadata.

    Since ``CallEdge.provenance`` is ``ExtractionProvenance`` (not
    ``ResolutionProvenance``), we reconstruct what we can from the
    fields that ``_with_resolution_provenance`` set.
    """
    return ResolutionProvenance(
        selected_source=edge.provenance.producer,
        contributing_sources=(edge.provenance.producer,),
        alternatives=None,
        verification_method=None,
        confidence=_source_confidence(edge.source),
    )
