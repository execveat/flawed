"""L1 boundary invariant — every fact a :class:`CodeIndex` exposes must speak
the repo-relative structural vocabulary.

The Code Index is produced by *several* extraction paths (structural AST,
call-graph resolution, value-flow stitching). Each must emit the
**same** representation for the same entity: paths are repo-relative, and a
function/identifier FQN is the canonical structural FQN
(:attr:`FunctionRecord.fqn`) — never an absolute path, a ``{repo_root}/...``
prefix, or an under-qualified ``app.f`` form (where the
structural FQN is ``pkg.app.f``).

Representation drift here is the engine's cardinal sin: an absolute or
under-qualified key silently fails to match the relative structural key in a
downstream consumer, dropping a real edge with **no** ``AnalysisGap`` — a
silent false negative surfacing months later in L2/L3. :func:`validate_index`
turns that latent, far-away failure into a cheap, high-confidence assertion at
the L1 producer boundary.

This module imports nothing above Layer 1 and mutates nothing: it both
*inspects* an index (:func:`validate_index`, :func:`assert_index_invariant`)
and *canonicalizes* a producer's FQNs onto the structural representation
(:class:`FqnCanonicalizer`) by returning new
immutable facts. It is the single owner of the L1 representation contract —
called as a boundary check (artifact builder, tests), as the producer-side
canonicalization step (the pipeline), and as a diagnostic over a corpus.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from flawed._index import CodeIndex
    from flawed._index._types import CallEdge, SymbolRef

# FQN sentinels that are legitimately not structural FQNs. Any ``<...>``
# bracketed token is treated as a sentinel (``<module>``, ``<locals>``,
# ``<unknown>``, ``<lambda>``, ...): these never denote an in-repo definition
# and so are exempt from structural-resolution and path checks.
_FQN_SENTINELS = frozenset({"<module>", "<locals>", "<unknown>", "<lambda>"})


def _is_sentinel(value: str) -> bool:
    return value.startswith("<") and value.endswith(">")


# ---- violation record ------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IndexViolation:
    """A single L1 representation-drift finding.

    ``kind`` is the violation category (e.g. ``ABSOLUTE_PATH``,
    ``UNDER_QUALIFIED_UNIQUE``); ``fact`` is the originating fact/field
    (``call_edge.caller_fqn``); ``value`` is the offending string; ``where``
    is a best-effort ``file:line`` of the fact; ``candidates`` are the
    structural FQNs the value could reconcile to (drives the fix's
    feasibility classification).
    """

    kind: str
    fact: str
    value: str
    where: str
    candidates: tuple[str, ...] = field(default_factory=tuple)


# ---- path checks -----------------------------------------------------------


def _path_violation_kind(value: str, repo_root_str: str) -> str | None:
    """Return a violation kind if *value* is not a clean repo-relative path.

    Facts store POSIX-relative paths, so an absolute leak begins with ``/``.
    """
    if _is_sentinel(value):
        return None
    if "<<" in value:  # leaked portability sentinel (e.g. ``<<FLAWED_REPO_ROOT>>``)
        return "SENTINEL_PATH"
    if repo_root_str and value.startswith(repo_root_str):
        return "REPO_ROOT_PREFIX"
    if value.startswith("/"):
        return "ABSOLUTE_PATH"
    return None


# ---- FQN classification ----------------------------------------------------


def _build_suffix_index(structural: Iterable[str]) -> dict[str, tuple[str, ...]]:
    """Map every dotted suffix of every structural FQN to the FQNs bearing it.

    A bare/under-qualified ``app.f`` form suffix-matches the canonical
    ``pkg.app.f`` via the suffix ``app.f``. Precomputing this makes
    reconciliation a dict lookup rather than an O(functions) scan per value, so
    the invariant stays cheap on corpus-scale repos.
    """
    acc: dict[str, list[str]] = {}
    for fqn in structural:
        parts = fqn.split(".")
        for i in range(len(parts)):
            acc.setdefault(".".join(parts[i:]), []).append(fqn)
    return {suffix: tuple(fqns) for suffix, fqns in acc.items()}


def _structural_fqns(index: CodeIndex) -> frozenset[str]:
    """The canonical structural FQN universe of *index* (functions + classes)."""
    return frozenset([fn.fqn for fn in index.functions] + [cls.fqn for cls in index.classes])


def _classification_tables(
    structural: frozenset[str],
) -> tuple[dict[str, tuple[str, ...]], frozenset[str], frozenset[str]]:
    """Build ``(suffix_index, repo_top, qualifier_prefixes)`` for *structural*.

    Shared by :func:`validate_index` (which classifies) and
    :class:`FqnCanonicalizer` (which rewrites) so the two can never disagree on
    what "the structural universe" is.
    """
    suffix_index = _build_suffix_index(structural)
    repo_top = frozenset(s.split(".", 1)[0] for s in structural)
    # Every proper dotted prefix of a structural FQN — the set of in-repo
    # namespaces a value could legitimately be a member of.
    qualifier_prefixes = frozenset(
        ".".join(parts[:i])
        for s in structural
        for parts in (s.split("."),)
        for i in range(1, len(parts))
    )
    return suffix_index, repo_top, qualifier_prefixes


def _classify_fqn(
    value: str,
    structural: frozenset[str],
    suffix_index: dict[str, tuple[str, ...]],
    repo_top: frozenset[str],
    qualifier_prefixes: frozenset[str],
) -> tuple[str, tuple[str, ...]]:
    """Classify an FQN against the structural universe.

    Returns ``(category, candidates)``. Categories that are NOT violations:
    ``RESOLVED`` (exact structural match), ``SENTINEL``, ``EXTERNAL`` (names a
    definition outside the repo, including a method/attribute call on a local
    or framework object such as ``app.items.count`` — the ``app.`` head is the
    calling module, not a claim that ``app.items.count`` is defined here),
    ``EXTERNAL_METHOD_LIKE`` (ambiguous bare name whose head is not a repo
    module — an unresolved external method like ``request.args.get``).
    Violation categories: ``UNDER_QUALIFIED_UNIQUE`` (exactly one structural
    suffix-match — the canonical under-qualification bug, cheaply
    reconcilable), ``UNDER_QUALIFIED_AMBIGUOUS`` (several in-repo
    suffix-matches), ``IN_REPO_MISSING`` (names a member of a known in-repo
    namespace — its parent is a structural-FQN prefix — yet no such definition
    exists).
    """
    if _is_sentinel(value):
        return ("SENTINEL", ())
    if value in structural:
        return ("RESOLVED", ())
    matches = suffix_index.get(value, ())
    head = value.split(".", 1)[0]
    parent = value.rsplit(".", 1)[0] if "." in value else ""
    if len(matches) == 1:
        result = ("UNDER_QUALIFIED_UNIQUE", tuple(matches))
    elif len(matches) > 1:
        result = (
            ("UNDER_QUALIFIED_AMBIGUOUS", tuple(matches[:6]))
            if head in repo_top
            else ("EXTERNAL_METHOD_LIKE", ())
        )
    elif parent and parent in qualifier_prefixes:
        # Names a member of a known in-repo namespace, but no such definition
        # exists — a genuinely missing in-repo target.
        result = ("IN_REPO_MISSING", ())
    else:
        result = ("EXTERNAL", ())
    return result


# FQN categories worth REPORTING on a classified field (callee / symbol):
# in-repo-reconcilable forms and missing in-repo members. Externals pass silently.
_FQN_VIOLATION_KINDS = frozenset(
    {"UNDER_QUALIFIED_UNIQUE", "UNDER_QUALIFIED_AMBIGUOUS", "IN_REPO_MISSING"}
)

# Path drift is always blocking — a stored path must be repo-relative.
_PATH_VIOLATION_KINDS = frozenset({"SENTINEL_PATH", "REPO_ROOT_PREFIX", "ABSOLUTE_PATH"})

# An FQN finding is BLOCKING only when a concrete in-repo structural target
# EXISTS that the producer failed to use — i.e. the value suffix-matches one (or
# several) structural FQNs. These are representation drift; the canonicalizer
# resolves the unique case, so a clean L1 boundary carries zero of them.
_BLOCKING_FQN_KINDS = frozenset({"UNDER_QUALIFIED_UNIQUE", "UNDER_QUALIFIED_AMBIGUOUS"})

# The remaining FQN findings are honest GAPs — surfaced for visibility but NOT
# blocking, because there is no in-repo target to canonicalize to:
#   * IN_REPO_MISSING — a member of a known in-repo namespace with no definition;
#     overwhelmingly external attribute access on an in-repo module (``app.session``).
#   * STRONG_UNRESOLVED — a strong field (caller / containing fn) naming a
#     definition absent from this index's structural universe: a sibling-file edge
#     leaked into a single-file fixture (FLAW-307) or an un-extracted closure
#     (FLAW-308). Reporting these as blocking would only mask the real extraction
#     gap they represent — canonicalisation cannot manufacture a target for them.
_GAP_KINDS = frozenset({"IN_REPO_MISSING", "STRONG_UNRESOLVED"})

#: Kinds that MUST be zero for the L1 boundary to be clean. Drives the
#: parametrized boundary test and the strict producer-side assertion.
BLOCKING_KINDS = _PATH_VIOLATION_KINDS | _BLOCKING_FQN_KINDS


def blocking_violations(violations: Iterable[IndexViolation]) -> list[IndexViolation]:
    """Filter *violations* to the blocking subset (drift), dropping honest gaps."""
    return [v for v in violations if v.kind in BLOCKING_KINDS]


class FqnCanonicalizer:
    """Rewrite an under-qualified FQN to its unique structural form.

    The L1 extractor can emit the same in-repo entity under several FQN
    spellings: the canonical structural ``pkg.app.f`` and bare/under-qualified
    ``app.f`` forms (the namespace prefix dropped) from import-based resolution.
    Built once from the structural universe, this collapses each
    spelling onto the single canonical :attr:`FunctionRecord.fqn`. Only an
    under-qualified form with EXACTLY ONE structural suffix-match is rewritten;
    sentinels, externals, already-canonical, and ambiguous (>1 match) values are
    returned verbatim — an unresolvable in-repo FQN is left for the boundary to
    surface as a gap, never guessed.
    """

    __slots__ = ("_qualifier_prefixes", "_repo_top", "_structural", "_suffix_index")

    def __init__(self, structural: frozenset[str]) -> None:
        self._structural = structural
        (
            self._suffix_index,
            self._repo_top,
            self._qualifier_prefixes,
        ) = _classification_tables(structural)

    @classmethod
    def from_index(cls, index: CodeIndex) -> FqnCanonicalizer:
        """Build a canonicalizer from an assembled :class:`CodeIndex`."""
        return cls(_structural_fqns(index))

    @classmethod
    def from_structural_fqns(cls, fqns: Iterable[str]) -> FqnCanonicalizer:
        """Build a canonicalizer from a raw structural-FQN iterable."""
        return cls(frozenset(fqns))

    def canonical(self, value: str) -> str:
        """Return *value*'s canonical structural FQN, or *value* unchanged.

        Idempotent: a value that is already canonical (or has no unique in-repo
        target) is returned as-is.
        """
        category, candidates = _classify_fqn(
            value,
            self._structural,
            self._suffix_index,
            self._repo_top,
            self._qualifier_prefixes,
        )
        if category == "UNDER_QUALIFIED_UNIQUE":
            return candidates[0]
        return value


def canonicalize_call_edges(
    canonicalizer: FqnCanonicalizer, edges: tuple[CallEdge, ...]
) -> tuple[CallEdge, ...]:
    """Rewrite each edge's caller/callee FQN to its canonical structural form.

    Applied to the AST extractor's edges (whose import-based callees can be
    under-qualified, e.g. ``flask_wtf.FlaskForm``) BEFORE the call-graph merge,
    so under-qualified and canonical spellings of one entity collapse into a
    single confident edge (FLAW-301) and the L2 ``(caller_fqn)``-keyed
    reachability lookups resolve. Externals, sentinels,
    and already-canonical names pass through unchanged; nothing is mutated (new
    immutable edges are returned).
    """
    canon = canonicalizer.canonical
    return tuple(
        replace(
            edge,
            caller_fqn=canon(edge.caller_fqn),
            callee_fqn=canon(edge.callee_fqn) if edge.callee_fqn is not None else None,
        )
        for edge in edges
    )


def canonicalize_symbol_refs(
    canonicalizer: FqnCanonicalizer, refs: tuple[SymbolRef, ...]
) -> tuple[SymbolRef, ...]:
    """Rewrite each symbol ref's FQN to its canonical structural form.

    The structural pass can under-qualify: it records an import
    (``from flask_wtf import FlaskForm``) under its as-written path
    ``flask_wtf.FlaskForm`` when the package is local. Canonicalisation collapses
    such forms onto the structural FQN.
    """
    canon = canonicalizer.canonical
    return tuple(replace(ref, fqn=canon(ref.fqn)) if ref.fqn is not None else ref for ref in refs)


# ---- the invariant ---------------------------------------------------------


def validate_index(index: CodeIndex) -> list[IndexViolation]:
    """Return every representation-drift violation in *index* (empty == clean).

    Strong fields (``caller_fqn``, ``containing_function_fqn``) must be a
    sentinel or an exact structural FQN — they name a definition that, by
    construction, exists in this repo. Classified fields (``callee_fqn``,
    symbol ``fqn``, ``callsite_callee_fqn``) may legitimately name externals,
    so only the in-repo-but-unreconciled categories are reported.
    """
    violations: list[IndexViolation] = []
    repo_root_str = str(index.repo_root)

    structural = _structural_fqns(index)
    suffix_index, repo_top, qualifier_prefixes = _classification_tables(structural)

    def check_path(value: str | None, fact: str, where: str) -> None:
        if value is None:
            return
        kind = _path_violation_kind(value, repo_root_str)
        if kind is not None:
            violations.append(IndexViolation(kind, fact, value, where))

    def check_strong_fqn(value: str | None, fact: str, where: str) -> None:
        """A field that must name an in-repo definition (or a sentinel)."""
        if value is None:
            return
        category, candidates = _classify_fqn(
            value, structural, suffix_index, repo_top, qualifier_prefixes
        )
        if category not in ("RESOLVED", "SENTINEL"):
            # For a strong field, even an "external-looking" value is wrong:
            # you cannot make a call from a definition that isn't in the repo.
            kind = category if category in _FQN_VIOLATION_KINDS else "STRONG_UNRESOLVED"
            violations.append(IndexViolation(kind, fact, value, where, candidates))

    def check_classified_fqn(value: str | None, fact: str, where: str) -> None:
        if value is None:
            return
        category, candidates = _classify_fqn(
            value, structural, suffix_index, repo_top, qualifier_prefixes
        )
        if category in _FQN_VIOLATION_KINDS:
            violations.append(IndexViolation(category, fact, value, where, candidates))

    # -- structural facts (the reference representation) --
    for fn in index.functions:
        check_path(fn.file, "function.file", f"{fn.file}")
        check_path(fn.location.file, "function.location.file", _loc(fn.location))
    for cls in index.classes:
        check_path(cls.file, "class.file", f"{cls.file}")

    # -- call edges --
    for edge in index.call_graph.edges:
        where = _loc(edge.location)
        check_path(edge.location.file, "call_edge.location.file", where)
        if edge.receiver_location is not None:
            check_path(edge.receiver_location.file, "call_edge.receiver_location.file", where)
        check_strong_fqn(edge.caller_fqn, "call_edge.caller_fqn", where)
        check_classified_fqn(edge.callee_fqn, "call_edge.callee_fqn", where)

    # -- symbol refs --
    for ref in index.symbols.refs:
        where = _loc(ref.location)
        check_path(ref.location.file, "symbol_ref.location.file", where)
        check_classified_fqn(ref.fqn, "symbol_ref.fqn", where)

    # -- value-flow edges (stitched from call edges; same vocabulary) --
    for vf in index.value_flow.edges:
        where = _loc(vf.source_location)
        check_path(vf.source_location.file, "value_flow.source_location.file", where)
        check_path(vf.target_location.file, "value_flow.target_location.file", where)
        check_strong_fqn(vf.containing_function_fqn, "value_flow.containing_function_fqn", where)
        check_classified_fqn(vf.callsite_callee_fqn, "value_flow.callsite_callee_fqn", where)

    # -- extraction errors --
    for err in index.errors:
        where = _loc(err.location) if err.location is not None else err.file
        check_path(err.file, "extraction_error.file", where)
        if err.location is not None:
            check_path(err.location.file, "extraction_error.location.file", where)

    return violations


class IndexInvariantError(AssertionError):
    """Raised when a :class:`CodeIndex` carries blocking L1 representation drift."""


def assert_index_invariant(index: CodeIndex) -> None:
    """Fail loud (fail-CLOSED) if *index* carries blocking representation drift.

    The strict producer-boundary form of :func:`validate_index`: drift an
    in-repo FQN the producer could have canonicalised, or a non-relative path
    is a bug that must abort rather than ride downstream as a silent false
    negative (the engine's cardinal sin). Honest gaps (:data:`_GAP_KINDS`) are
    not drift and never raise. Cheap — O(facts) dict lookups — so dev/test and
    the artifact builder can run it unconditionally; production callers that
    must not abort a scan simply do not call it (canonicalisation has already
    removed the drift, leaving only honest gaps).
    """
    blocking = blocking_violations(validate_index(index))
    if blocking:
        sample = "; ".join(f"{v.kind} {v.fact}={v.value!r}@{v.where}" for v in blocking[:5])
        raise IndexInvariantError(
            f"{len(blocking)} blocking L1 representation-drift violation(s); first: {sample}"
        )


def _loc(span: object) -> str:
    file = getattr(span, "file", "?")
    line = getattr(span, "line", "?")
    return f"{file}:{line}"
