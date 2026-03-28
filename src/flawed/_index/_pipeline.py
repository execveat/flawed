"""Step 7: Pipeline assembly — orchestrate all extraction steps into a CodeIndex.

Runs the complete L1 extraction pipeline sequentially:

1. Discover Python files
2. Run structural entity pass (Step 3)
3. Build CFGs per function (Step 4)
4. Merge call graph (Step 5)
5. Extract value flow (Step 6)
6. Assemble CodeIndex (Step 7)

Design: straightforward sequential execution.  No parallelism.  Correctness
first (principles §4.1).  Later L1 stages may reuse successful per-file parse
artifacts from earlier stages when that preserves the same error boundaries.

:func:`incremental_build` rebuilds the index from cached artifacts by
re-extracting the changed files and their transitive reverse-import closure;
its LibCST-derived normalized facts are guaranteed identical to a full build
of the same final source (FLAW-120/121).
"""

from __future__ import annotations

import functools
import hashlib
import json
import resource
import sys
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, fields, is_dataclass
from enum import Enum
from pathlib import Path
from types import UnionType
from typing import TYPE_CHECKING, Union, cast, get_args, get_origin, get_type_hints

import libcst as cst
from libcst.metadata import MetadataWrapper, PositionProvider

from flawed._index._callgraph import build_hierarchy_edges, merge_call_graph
from flawed._index._cfg import build_cfg
from flawed._index._invariants import (
    FqnCanonicalizer,
    assert_index_invariant,
    canonicalize_call_edges,
    canonicalize_symbol_refs,
)
from flawed._index._resolution import (
    _module_fqn_for_path,
    _namespace_package_roots_from_files,
)
from flawed._index._structural import (
    ParsedFile,
    discover_python_files,
    extract_structural,
)
from flawed._index._type_enrichment import (
    build_type_enrichment_index,
    queries_from_assignments,
)
from flawed._index._types import (
    ErrorKind,
    ExtractionError,
    ExtractionProvenance,
)
from flawed._index._valueflow import extract_value_flow

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping, Sequence

    from flawed._index import CodeIndex
    from flawed._index._dominance import DominanceGraph
    from flawed._index._graphs import CallGraph
    from flawed._index._type_enrichment import TypeOracle
    from flawed._index._types import (
        CallEdge,
        CFGBlock,
        CFGEdge,
        FunctionRecord,
        ImportFact,
        TryExceptRegion,
    )

    _CfgDict = dict[
        str,
        tuple[tuple[CFGBlock, ...], tuple[CFGEdge, ...], tuple[TryExceptRegion, ...]],
    ]

_PIPELINE_VERSION = "0.6.0"  # AST-only L1

#: Explicit L1 index schema version, DECOUPLED from the package version
#: (FLAW-344).  The cache-validity gate keys on this constant plus the
#: record-schema fingerprint below — NOT on a byte-hash of the extraction
#: source.  Consequences:
#:
#: * A behaviour-preserving refactor of ``_index`` (which *would* move the old
#:   ``extraction_code_signature`` byte-hash) does NOT invalidate the corpus.
#: * A real on-disk format change is caught automatically by the fingerprint.
#: * A deliberate output change with no format change is declared by bumping
#:   this constant.
#:
#: Policy: this is **not** bumped within a
#: minor release series, so cached indices stay valid across releases that do
#: not bump it.  ``tools.check_l1_schema`` enforces that any ``_index`` source
#: change is accompanied by a fingerprint move or an explicit schema decision,
#: preserving the FLAW-198/207 anti-silent-FN guarantee that the byte-hash used
#: to provide.
L1_SCHEMA_VERSION = "1"
_WRITTEN_NORMALIZED_ARTIFACTS = (
    ("functions.jsonl", "Function and method definitions."),
    ("classes.jsonl", "Class definitions with currently available structural fields."),
    ("decorators.jsonl", "Decorator applications without semantic classification."),
    ("imports.jsonl", "Import statements and syntactic aliases."),
    ("attributes.jsonl", "Current attribute-access observations."),
    ("call_edges.jsonl", "Merged call edges from AST and hierarchy sources."),
    ("value_flow_edges.jsonl", "Current intra-function value-flow edges."),
    ("symbol_refs.jsonl", "Resolved symbol references from the structural pass."),
    ("errors.jsonl", "Fatal and non-fatal extraction errors."),
    ("type_enrichment.jsonl", "Declared-type facts from type-enrichment probes."),
    (
        "cfgs.jsonl",
        "Per-function control-flow graphs (blocks, edges, try-regions) so cached "
        "loads retain CFG-derived conditions()/predicates() facts.",
    ),
    ("summary.json", "Aggregate artifact counts."),
)
_DEFERRED_NORMALIZED_ARTIFACTS = (
    {
        "path": "aliases.jsonl",
        "status": "internal_only",
        "producer": "structural_entity_pass",
        "reason": (
            "Alias facts currently feed value-flow construction; public persistence "
            "is deferred to the symbol-resolution baseline."
        ),
    },
    {
        "path": "assignments.jsonl",
        "status": "internal_only",
        "producer": "structural_entity_pass",
        "reason": (
            "Assignment facts currently feed value-flow construction; public "
            "persistence is deferred until assignment fact scope is finalized."
        ),
    },
    {
        "path": "type_enrichment.jsonl",
        "status": "written",
        "producer": "type_enrichment",
        "reason": (
            "Type-enrichment facts persisted as JSONL for cache-hit recovery. "
            "Cache identity includes a type_enrichment_signature so stale facts "
            "are invalidated when oracle versions or configuration change."
        ),
    },
    {
        "path": "locations.jsonl",
        "status": "embedded",
        "producer": "all_passes",
        "reason": (
            "Source spans are embedded on each persisted fact; there is no "
            "standalone location index in the current runtime."
        ),
    },
)


_CACHE_KEY_FILE = "cache_key.json"
_FILE_MANIFEST = "file_manifest.json"
_CFG_ARTIFACT = "cfgs.jsonl"

_DESERIALIZE_SCHEMA_CACHE: dict[type, tuple[tuple[str, object], ...]] = {}


class CorruptCacheError(Exception):
    """Raised when cached artifacts cannot be deserialized."""


@dataclass(frozen=True)
class FileChanges:
    """Result of comparing current files with a cached manifest."""

    changed: tuple[Path, ...]
    added: tuple[Path, ...]
    removed: tuple[str, ...]


@dataclass(frozen=True)
class IndexBuildPhase:
    """Timing and RSS measurement for one L1 build subphase."""

    name: str
    status: str
    wall_ms: float
    cpu_ms: float
    rss_high_water_start_bytes: int
    rss_high_water_end_bytes: int
    details: Mapping[str, object]


# ── L1 record-schema fingerprint (FLAW-344) ───────────────────────


def _persisted_record_roots() -> tuple[type, ...]:
    """Top-level record types persisted to the normalized JSONL artifacts.

    These are exactly the types :func:`load_index_from_artifacts` deserializes
    (plus the CFG block/edge/region types persisted by :func:`write_cfgs`).  The
    fingerprint walks their transitive dataclass/enum closure, so nested record
    shapes (``SourceSpan``, ``Parameter``, ``CallArgument``, …) are covered too.
    """
    from flawed._index._type_enrichment import TypeFact
    from flawed._index._types import (
        AttributeAccess,
        CallEdge,
        CFGBlock,
        CFGEdge,
        ClassRecord,
        DecoratorFact,
        ExtractionError,
        FunctionRecord,
        ImportFact,
        SymbolRef,
        TryExceptRegion,
        ValueFlowEdge,
    )

    return (
        AttributeAccess,
        CallEdge,
        CFGBlock,
        CFGEdge,
        ClassRecord,
        DecoratorFact,
        ExtractionError,
        FunctionRecord,
        ImportFact,
        SymbolRef,
        TryExceptRegion,
        TypeFact,
        ValueFlowEdge,
    )


def _referenced_types(hint: object) -> Iterator[type]:
    """Yield dataclass/enum types referenced by a resolved type hint, recursively."""
    origin = get_origin(hint)
    if origin is not None:
        for arg in get_args(hint):
            yield from _referenced_types(arg)
        return
    if isinstance(hint, type) and (is_dataclass(hint) or issubclass(hint, Enum)):
        yield hint


def _schema_fingerprint(roots: tuple[type, ...]) -> str:
    """Pure fingerprint of the dataclass/enum closure reachable from *roots*.

    Hashes the field sets (name + annotation string) of every dataclass and the
    member sets of every enum reachable from *roots*.  Any *format* change — a
    field added / removed / renamed / retyped, or an enum value added / removed —
    moves the result.  Extracted from :func:`record_schema_fingerprint` so the
    sensitivity is unit-testable with synthetic record sets.
    """
    dataclasses_seen: dict[str, list[tuple[str, str]]] = {}
    enums_seen: dict[str, list[str]] = {}
    visited: set[type] = set()
    stack: list[type] = list(roots)
    while stack:
        tp = stack.pop()
        if tp in visited:
            continue
        visited.add(tp)
        if isinstance(tp, type) and issubclass(tp, Enum):
            enums_seen[tp.__qualname__] = sorted(str(member.value) for member in tp)
            continue
        if is_dataclass(tp):
            hints = get_type_hints(tp)
            field_pairs: list[tuple[str, str]] = []
            for field in fields(tp):
                field_pairs.append((field.name, str(field.type)))
                stack.extend(_referenced_types(hints[field.name]))
            dataclasses_seen[tp.__qualname__] = sorted(field_pairs)
    canonical = {
        "algo_version": 1,
        "dataclasses": {name: dataclasses_seen[name] for name in sorted(dataclasses_seen)},
        "enums": {name: enums_seen[name] for name in sorted(enums_seen)},
    }
    blob = json.dumps(canonical, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


@functools.cache
def record_schema_fingerprint() -> str:
    """Stable fingerprint of the persisted L1 record schema (FLAW-344).

    Walks the transitive dataclass/enum closure of the persisted artifact records
    (see :func:`_persisted_record_roots`).  Any *format* change moves the
    fingerprint, so :func:`cache_key_matches` auto-invalidates a stale index even
    when nobody bumped :data:`L1_SCHEMA_VERSION`.  It is deliberately decoupled
    from source *bytes*: a behaviour-preserving refactor that leaves the record
    shapes untouched does NOT move it, which is the whole point of scheme C.

    Memoized: the schema is fixed for the life of the process.
    """
    return _schema_fingerprint(_persisted_record_roots())


# ── Cache key management ──────────────────────────────────────────


def write_cache_key(
    artifact_root: Path,
    *,
    content_hash: str,
    type_enrichment_signature: str = "",
    extraction_code_signature: str = "",
) -> None:
    """Write cache metadata after a successful extraction run.

    The cache-validity gate (FLAW-344, scheme C) is ``content_hash`` +
    :data:`L1_SCHEMA_VERSION` + :func:`record_schema_fingerprint` +
    ``type_enrichment_signature``.  ``pipeline_version`` and
    ``extraction_code_signature`` (the old FLAW-207 byte-hash) are still
    written, but **purely as provenance** — they let a cache's exact engine
    state be audited without being the invalidation gate.  Demoting the
    byte-hash is what lets a behaviour-preserving ``_index`` refactor keep the
    corpus valid; ``tools.check_l1_schema`` preserves the anti-silent-FN
    guarantee at commit time instead.
    """
    payload = {
        "content_hash": content_hash,
        "l1_schema_version": L1_SCHEMA_VERSION,
        "record_schema_fingerprint": record_schema_fingerprint(),
        "type_enrichment_signature": type_enrichment_signature,
        # Provenance only (NOT part of the validity gate):
        "pipeline_version": _PIPELINE_VERSION,
        "extraction_code_signature": extraction_code_signature,
    }
    (artifact_root / _CACHE_KEY_FILE).write_text(
        json.dumps(payload, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def cache_key_matches(
    artifact_root: Path,
    *,
    content_hash: str,
    type_enrichment_signature: str = "",
    extraction_code_signature: str = "",  # noqa: ARG001 (provenance; kept for caller symmetry)
) -> bool:
    """Return ``True`` when cached artifacts match the current repo state.

    The validity gate (FLAW-344, scheme C) is the repository content hash, the
    explicit :data:`L1_SCHEMA_VERSION`, the :func:`record_schema_fingerprint`,
    and the type-enrichment signature.  It is **fail-closed on unknown**: a
    legacy cache that predates these fields (or carries a different schema
    version / fingerprint) compares unequal and forces a safe re-extraction —
    a missing or unrecognized schema can never read as a hit.

    ``extraction_code_signature`` is accepted for caller symmetry but is no
    longer part of the gate (it is recorded as provenance only), so a
    behaviour-preserving ``_index`` refactor does not invalidate the cache.
    Returns ``False`` on any I/O or parse error.
    """
    key_path = artifact_root / _CACHE_KEY_FILE
    if not key_path.exists():
        return False
    try:
        data = json.loads(key_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    if not isinstance(data, dict):
        return False
    return (
        data.get("content_hash") == content_hash
        and data.get("l1_schema_version") == L1_SCHEMA_VERSION
        and data.get("record_schema_fingerprint") == record_schema_fingerprint()
        and data.get("type_enrichment_signature", "") == type_enrichment_signature
    )


def type_enrichment_signature(
    *,
    enable_mypy_batch: bool = False,
    basedpyright_max_queries: int = 2000,
    basedpyright_max_probe_files: int = 500,
    basedpyright_max_source_files: int = 5000,
    basedpyright_max_workspace_bytes: int = 250_000_000,
) -> str:
    """Compute a cache-identity string for type-enrichment configuration.

    Changes to oracle versions or gating caps produce a different signature,
    invalidating cached type-enrichment facts.
    """
    from flawed._index._type_enrichment import BASEDPYRIGHT_ORACLE_VERSION

    parts: dict[str, object] = {
        "basedpyright_oracle_version": BASEDPYRIGHT_ORACLE_VERSION,
        "enable_mypy_batch": enable_mypy_batch,
        "basedpyright_max_queries": basedpyright_max_queries,
        "basedpyright_max_probe_files": basedpyright_max_probe_files,
        "basedpyright_max_source_files": basedpyright_max_source_files,
        "basedpyright_max_workspace_bytes": basedpyright_max_workspace_bytes,
    }
    if enable_mypy_batch:
        from flawed._index._mypy_batch_oracle import MYPY_BATCH_ORACLE_VERSION

        parts["mypy_batch_oracle_version"] = MYPY_BATCH_ORACLE_VERSION

    canonical = json.dumps(parts, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


# ── Per-file manifest (incremental support) ──────────────────────


def write_file_manifest(
    artifact_root: Path,
    python_files: tuple[Path, ...],
    repo_root: Path,
    *,
    extraction_code_signature: str = "",
) -> None:
    """Write per-file metadata for incremental change detection.

    Keyed (FLAW-344) on :data:`L1_SCHEMA_VERSION` + :func:`record_schema_fingerprint`
    so the incremental path self-invalidates on a schema change: otherwise an
    incremental rebuild would re-extract only the changed files under a new
    schema and leave unchanged files' artifacts stale (a silent FN).
    ``pipeline_version`` and ``extraction_code_signature`` are recorded as
    provenance only.
    """
    files: dict[str, dict[str, int]] = {}
    for py_file in python_files:
        rel = str(py_file.relative_to(repo_root))
        try:
            stat = py_file.stat()
        except OSError:
            continue
        files[rel] = {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
    payload = {
        "l1_schema_version": L1_SCHEMA_VERSION,
        "record_schema_fingerprint": record_schema_fingerprint(),
        # Provenance only:
        "pipeline_version": _PIPELINE_VERSION,
        "extraction_code_signature": extraction_code_signature,
        "files": files,
    }
    (artifact_root / _FILE_MANIFEST).write_text(
        json.dumps(payload, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def read_file_manifest(
    artifact_root: Path,
    *,
    extraction_code_signature: str = "",  # noqa: ARG001 (provenance; kept for caller symmetry)
) -> dict[str, dict[str, int]] | None:
    """Read cached file manifest.  Returns the ``files`` dict or ``None``.

    Returns ``None`` (forcing a full rebuild) when the L1 schema version or the
    record-schema fingerprint (FLAW-344) does not match the current engine, so a
    stale manifest can never seed an incremental rebuild against a changed
    schema.  Fail-closed on unknown: a manifest predating these fields compares
    unequal and forces a full rebuild.
    """
    path = artifact_root / _FILE_MANIFEST
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("l1_schema_version") != L1_SCHEMA_VERSION:
        return None
    if data.get("record_schema_fingerprint") != record_schema_fingerprint():
        return None
    files = data.get("files")
    return files if isinstance(files, dict) else None


def detect_changed_files(
    manifest_files: dict[str, dict[str, int]],
    repo_root: Path,
    python_files: tuple[Path, ...],
) -> FileChanges:
    """Compare current files against a cached manifest."""
    changed: list[Path] = []
    added: list[Path] = []
    current_rels: set[str] = set()

    for py_file in python_files:
        rel = str(py_file.relative_to(repo_root))
        current_rels.add(rel)
        cached = manifest_files.get(rel)
        if cached is None:
            added.append(py_file)
        else:
            try:
                stat = py_file.stat()
            except OSError:
                added.append(py_file)
                continue
            if stat.st_size != cached.get("size") or stat.st_mtime_ns != cached.get("mtime_ns"):
                changed.append(py_file)

    removed = tuple(rel for rel in manifest_files if rel not in current_rels)
    return FileChanges(changed=tuple(changed), added=tuple(added), removed=removed)


# ── Artifact loader (cache hit path) ─────────────────────────────


def load_index_from_artifacts(
    repo_root: Path,
    artifact_root: Path,
    *,
    progress: Callable[[str], None] | None = None,
) -> CodeIndex:
    """Reconstruct a ``CodeIndex`` from previously written normalized artifacts.

    CFGs are restored from ``cfgs.jsonl`` and dominance is recomputed, so a
    cached load is faithful to a full extraction for CFG-derived rules
    (``conditions()`` / ``predicates()``).  A non-empty index whose cache lacks
    the CFG artifact (a pre-FLAW-118 cache) raises :class:`CorruptCacheError`
    so the caller re-extracts instead of serving silently incomplete data.
    """
    from flawed._index import CodeIndex
    from flawed._index._type_enrichment import TypeEnrichmentIndex, TypeFact
    from flawed._index._types import (
        AttributeAccess,
        CallEdge,
        ClassRecord,
        DecoratorFact,
        ExtractionError,
        ExtractionProvenance,
        FunctionRecord,
        ImportFact,
        SymbolRef,
        ValueFlowEdge,
    )

    repo_root = repo_root.expanduser().resolve()
    normalized = artifact_root / "normalized"

    _notify(progress, "Loading cached L1 artifacts")

    # L1 emits repo-relative paths/FQNs at the source, so persisted artifacts are
    # portable as-written: no sentinel rebasing on load. The builder's portability
    # guard is the tripwire that keeps them that way.
    functions = _read_jsonl(normalized / "functions.jsonl", FunctionRecord)
    classes = _read_jsonl(normalized / "classes.jsonl", ClassRecord)
    decorators = _read_jsonl(normalized / "decorators.jsonl", DecoratorFact)
    imports = _read_jsonl(normalized / "imports.jsonl", ImportFact)
    attributes = _read_jsonl(normalized / "attributes.jsonl", AttributeAccess)
    call_edges = _read_jsonl(normalized / "call_edges.jsonl", CallEdge)
    value_flow_edges = _read_jsonl(normalized / "value_flow_edges.jsonl", ValueFlowEdge)
    symbol_refs = _read_jsonl(normalized / "symbol_refs.jsonl", SymbolRef)
    errors = _read_jsonl(normalized / "errors.jsonl", ExtractionError)
    type_facts = _read_jsonl(normalized / "type_enrichment.jsonl", TypeFact)

    # CFGs carry the condition_expr / value_predicate facts that L2 turns into
    # conditions() and predicates().  A cache that omits them (e.g. written by a
    # pre-FLAW-118 pipeline) would silently suppress every CFG-derived rule, so
    # treat a missing CFG artifact on a non-empty index as a stale cache and
    # force re-extraction rather than fail open (principles: no silent FN).
    cfg_path = normalized / _CFG_ARTIFACT
    if functions and not cfg_path.exists():
        raise CorruptCacheError(
            f"{_CFG_ARTIFACT}: absent from a non-empty index cache "
            "(stale pre-FLAW-118 artifacts); re-extraction required"
        )
    cfgs, _cfg_files = _read_cfgs(cfg_path)
    dominance_graphs, _dom_errors = _build_dominance_graphs(cfgs)

    return CodeIndex(
        repo_root=repo_root,
        functions=functions,
        classes=classes,
        decorators=decorators,
        imports=imports,
        attributes=attributes,
        call_edges=call_edges,
        cfgs=cfgs,
        value_flow_edges=value_flow_edges,
        symbol_refs=symbol_refs,
        errors=errors,
        provenance=ExtractionProvenance(
            producer="pipeline_cached",
            producer_version=_PIPELINE_VERSION,
            artifact=str(artifact_root),
        ),
        type_enrichment=TypeEnrichmentIndex(facts=type_facts),
        dominance_graphs=dominance_graphs,
    )


def _read_jsonl[T](
    path: Path,
    record_type: type[T],
) -> tuple[T, ...]:
    """Read a JSONL file and reconstruct typed records.

    Artifacts are written with repo-relative paths/FQNs (L1 relativizes at the
    source), so lines are parsed verbatim — no sentinel rebasing.

    Raises :class:`CorruptCacheError` if any line cannot be parsed or
    deserialized — the caller falls back to full re-extraction.
    """
    if not path.exists():
        return ()
    records: list[T] = []
    try:
        with path.open(encoding="utf-8") as fh:
            for raw_line in fh:
                stripped = raw_line.strip()
                if not stripped:
                    continue
                records.append(cast("T", _deserialize(json.loads(stripped), record_type)))
    except (json.JSONDecodeError, KeyError, TypeError, ValueError, OSError) as exc:
        raise CorruptCacheError(f"{path.name}: {exc}") from exc
    return tuple(records)


def _deserialize(data: object, cls: object) -> object:  # noqa: PLR0911
    """Recursively reconstruct a frozen dataclass from JSON-decoded data."""
    if data is None:
        return None

    origin = get_origin(cls)
    args = get_args(cls)

    # Union[X, None] (i.e. Optional[X])
    if origin in (Union, UnionType):
        non_none = [a for a in args if a is not type(None)]
        if len(non_none) == 1:
            return _deserialize(data, non_none[0])
        return data

    # tuple[X, ...] (homogeneous) or tuple[X, Y] (heterogeneous)
    if origin is tuple and isinstance(data, list | tuple):
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_deserialize(item, args[0]) for item in data)
        return tuple(_deserialize(item, arg) for item, arg in zip(data, args, strict=False))

    # Enum subclasses
    if isinstance(cls, type) and issubclass(cls, Enum):
        return cls(data)

    # Frozen dataclasses
    if is_dataclass(cls) and isinstance(cls, type) and isinstance(data, dict):
        kwargs: dict[str, object] = {}
        for name, hint in _deserialization_schema(cls):
            if name in data:
                kwargs[name] = _deserialize(data[name], hint)
        return cls(**kwargs)

    # Primitives (str, int, float, bool) and unrecognized types
    return data


def _deserialization_schema(cls: type) -> tuple[tuple[str, object], ...]:
    """Return cached dataclass field names and resolved type hints."""
    schema = _DESERIALIZE_SCHEMA_CACHE.get(cls)
    if schema is None:
        hints = get_type_hints(cls)
        schema = tuple((field.name, hints[field.name]) for field in fields(cls))
        _DESERIALIZE_SCHEMA_CACHE[cls] = schema
    return schema


# ── CFG persistence (cache-hit fidelity for conditions()/predicates()) ──


def _cfg_file_hint(blocks: tuple[CFGBlock, ...]) -> str:
    """Best-effort source file for a function's CFG, for incremental filtering."""
    for block in blocks:
        if block.statements:
            return block.statements[0].file
        if block.condition_location is not None:
            return block.condition_location.file
    return ""


def write_cfgs(
    cfg_path: Path,
    cfgs: _CfgDict,
    fqn_to_file: Mapping[str, str],
) -> None:
    """Persist per-function CFGs (blocks, edges, try-regions) as JSONL.

    CFG blocks carry the ``condition_expr`` and ``value_predicates`` facts that
    Layer 2 converts into ``conditions()`` and ``predicates()``.  Persisting
    them keeps cache-hit and incremental loads faithful to a full extraction
    instead of silently dropping every CFG-derived rule (FLAW-118).
    """
    with cfg_path.open("w", encoding="utf-8") as handle:
        for fqn, (blocks, edges, regions) in cfgs.items():
            record = {
                "fqn": fqn,
                "file": fqn_to_file.get(fqn) or _cfg_file_hint(blocks),
                "blocks": [_jsonable(block) for block in blocks],
                "edges": [_jsonable(edge) for edge in edges],
                "try_regions": [_jsonable(region) for region in regions],
            }
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def _read_cfgs(
    cfg_path: Path,
) -> tuple[_CfgDict, dict[str, str]]:
    """Reconstruct the per-function CFG dict and an fqn→file map from JSONL.

    Returns empty mappings when the artifact is absent. Raises
    :class:`CorruptCacheError` on a malformed artifact so the caller can fall
    back to full re-extraction.
    """
    from flawed._index._types import CFGBlock, CFGEdge, TryExceptRegion

    cfgs: dict[
        str,
        tuple[tuple[CFGBlock, ...], tuple[CFGEdge, ...], tuple[TryExceptRegion, ...]],
    ] = {}
    files: dict[str, str] = {}
    if not cfg_path.exists():
        return cfgs, files
    try:
        with cfg_path.open(encoding="utf-8") as handle:
            for raw_line in handle:
                stripped = raw_line.strip()
                if not stripped:
                    continue
                data = json.loads(stripped)
                fqn = data["fqn"]
                blocks = tuple(
                    cast("CFGBlock", _deserialize(item, CFGBlock))
                    for item in data.get("blocks", ())
                )
                edges = tuple(
                    cast("CFGEdge", _deserialize(item, CFGEdge)) for item in data.get("edges", ())
                )
                regions = tuple(
                    cast("TryExceptRegion", _deserialize(item, TryExceptRegion))
                    for item in data.get("try_regions", ())
                )
                cfgs[fqn] = (blocks, edges, regions)
                files[fqn] = data.get("file", "")
    except (json.JSONDecodeError, KeyError, TypeError, ValueError, OSError) as exc:
        raise CorruptCacheError(f"{cfg_path.name}: {exc}") from exc
    return cfgs, files


def build_index(  # noqa: PLR0915
    repo_root: Path,
    *,
    artifact_root: Path | None = None,
    enable_mypy_batch: bool = False,
    basedpyright_max_queries: int = 2000,
    basedpyright_max_probe_files: int = 500,
    basedpyright_max_source_files: int = 5000,
    basedpyright_max_workspace_bytes: int = 250_000_000,
    basedpyright_timeout_seconds: int = 120,
    mypy_batch_timeout_seconds: int = 120,
    mypy_batch_max_files: int = 5000,
    mypy_batch_cache_dir: Path | None = None,
    extraction_code_signature: str = "",
    oracle: TypeOracle | None = None,
    progress: Callable[[str], None] | None = None,
    phase_recorder: Callable[[IndexBuildPhase], None] | None = None,
    validate: bool = False,
) -> CodeIndex:
    """Run the complete L1 extraction pipeline on a repository.

    Parameters
    ----------
    repo_root:
        Path to the repository root.  Relative paths are resolved to absolute
        paths before any extraction stage runs.  The pipeline reads source
        files from this directory tree.
    artifact_root:
        Optional per-repository cache/artifact directory.  When present,
        normalized L1 artifacts are written under it for cached reuse.
    enable_mypy_batch:
        If true, run the mypy batch type-enrichment oracle alongside the
        default basedpyright probes with timeout and source-count guardrails.
    basedpyright_max_queries:
        Maximum reveal_type queries submitted to the basedpyright oracle.
    basedpyright_max_probe_files:
        Maximum source files mutated with basedpyright reveal_type probes.
    basedpyright_max_source_files:
        Maximum Python source files in the basedpyright workspace input.
    basedpyright_max_workspace_bytes:
        Maximum ignore-pruned workspace bytes copied for basedpyright probes.
    mypy_batch_timeout_seconds:
        Wall-clock timeout for the mypy batch build. Defaults to 120s.
    mypy_batch_max_files:
        Maximum source files passed to the mypy batch oracle. Defaults to 5000.
    mypy_batch_cache_dir:
        Optional stable cache root for mypy's ``.mypy_cache`` reuse.
    oracle:
        Optional explicit type-enrichment oracle. When ``None`` (production
        default) the configured basedpyright/mypy oracles run. Injecting a
        deterministic oracle lets tests exercise the enrichment integration
        (including incremental-vs-full parity) without the slow real tools.
    validate:
        When true, assert the L1 representation invariant on the assembled index
        before returning (fail-CLOSED on blocking drift via
        :func:`assert_index_invariant`). The dev/test/artifact-builder path opts
        in; production leaves it false so a scan is never aborted — FQN
        canonicalization has already removed the drift, leaving only honest gaps.

    Returns
    -------
    CodeIndex:
        Fully populated structural index ready for Layer 2 consumption.

    Notes
    -----
    Errors from each stage are collected and included in the resulting
    ``CodeIndex.errors``.
    """
    from flawed._index import CodeIndex

    repo_root = repo_root.expanduser().resolve()
    if artifact_root is not None:
        artifact_root = artifact_root.expanduser().resolve()

    # Normalise: when given a single file, use its parent as root
    # and restrict discovery to only that file.
    _single_file: Path | None = None
    if repo_root.is_file():
        _single_file = repo_root
        repo_root = repo_root.parent

    all_errors: list[ExtractionError] = []

    # Discover Python files and classify PEP 420 namespace roots up front: both
    # depend only on repo_root, and the structural step below reuses both — no
    # recomputation.
    python_files: tuple[Path, ...]
    with _record_phase(phase_recorder, "l1_discover_python_files") as phase:
        if _single_file is not None:
            python_files = (_single_file,)
        else:
            python_files = discover_python_files(repo_root)
        phase["python_file_count"] = len(python_files)
    namespace_roots = _namespace_package_roots_from_files(repo_root, python_files)

    # -- Step 3-4: Structural entity pass + per-file CFG construction -----
    _notify(progress, "LibCST structural entity pass")
    cfgs: _CfgDict = {}
    cfg_phase = _AggregatePhaseRecorder(phase_recorder, "l1_cfg")
    try:
        with _record_phase(phase_recorder, "l1_libcst_extraction") as phase:
            phase["python_file_count"] = len(python_files)
            phase["includes_interleaved_cfg_callbacks"] = True
            structural = extract_structural(
                repo_root,
                python_files,
                namespace_roots=namespace_roots,
                per_file_callback=lambda parsed_file, functions: cfg_phase.measure(
                    lambda: _build_file_cfgs(parsed_file, functions, cfgs),
                    file=parsed_file.rel_path,
                    function_count=len(functions),
                ),
            )
            phase["function_count"] = len(structural.functions)
            phase["class_count"] = len(structural.classes)
            phase["assignment_count"] = len(structural.assignments)
            phase["error_count"] = len(structural.errors)
            phase["cfg_callback_wall_ms"] = cfg_phase.wall_ms
    finally:
        cfg_phase.finish(
            {
                "cfg_count": len(cfgs),
                "note": (
                    "CFG construction is measured as callbacks interleaved with LibCST extraction."
                ),
            }
        )
    all_errors.extend(structural.errors)

    # -- Step 4b: Canonicalize every producer's FQNs to the structural form ----
    # The AST extractor emits a local package's as-written import path
    # (``flask_wtf.X`` when ``flask_wtf/`` is vendored in-repo). Now that the
    # structural pass has run, rewrite EVERY call edge and symbol ref to its
    # unique structural FQN BEFORE the merge, so value-flow inherits the canonical
    # forms and every persisted artifact speaks the one representation the L2
    # match keys use. Externals/sentinels/already-canonical names pass through.
    with _record_phase(phase_recorder, "l1_fqn_canonicalize") as phase:
        canonicalizer = FqnCanonicalizer.from_structural_fqns(
            [fn.fqn for fn in structural.functions] + [cls.fqn for cls in structural.classes]
        )
        ast_edges = canonicalize_call_edges(canonicalizer, structural.call_edges)
        structural_symbols = canonicalize_symbol_refs(canonicalizer, structural.symbol_refs)
        phase["edge_count"] = len(ast_edges)
        phase["symbol_count"] = len(structural_symbols)

    # -- Step 5: Merge call graph ----------------------------------------
    _notify(progress, "Call graph merge")
    with _record_phase(phase_recorder, "l1_call_graph") as phase:
        hierarchy_edges = build_hierarchy_edges(
            structural.classes, structural.functions, ast_edges
        )
        call_graph, merge_errors = merge_call_graph(
            ast_edges=ast_edges,
            hierarchy_edges=hierarchy_edges,
        )
        all_errors.extend(merge_errors)
        merged_call_edges = _extract_all_call_edges(call_graph)
        phase["ast_edge_count"] = len(ast_edges)
        phase["hierarchy_edge_count"] = len(hierarchy_edges)
        phase["merged_edge_count"] = len(merged_call_edges)
        phase["error_count"] = len(merge_errors)

    # -- Step 6: Value flow extraction -----------------------------------
    _notify(progress, "Intra-function value flow")
    with _record_phase(phase_recorder, "l1_value_flow") as phase:
        attribute_writes = tuple(attr for attr in structural.attributes if attr.is_write)
        value_flow_edges, vf_errors = extract_value_flow(
            assignments=structural.assignments,
            aliases=structural.aliases,
            functions=structural.functions,
            call_edges=ast_edges,
            returns=structural.returns,
            comprehension_bindings=structural.comprehension_bindings,
            attribute_writes=attribute_writes,
            yields=structural.yields,
        )
        all_errors.extend(vf_errors)
        phase["assignment_count"] = len(structural.assignments)
        phase["alias_count"] = len(structural.aliases)
        phase["function_count"] = len(structural.functions)
        phase["edge_count"] = len(value_flow_edges)
        phase["error_count"] = len(vf_errors)

    # -- Step 6b: Type enrichment (basedpyright declared-type probes) ----
    if enable_mypy_batch:
        _notify(progress, "Type enrichment (mypy batch + basedpyright)")
    else:
        _notify(progress, "Type enrichment (basedpyright)")
    with _record_phase(phase_recorder, "l1_type_enrichment") as phase:
        type_queries = queries_from_assignments(structural.assignments)
        type_enrichment = build_type_enrichment_index(
            repo_root,
            type_queries,
            oracle=oracle,
            enable_mypy_batch=enable_mypy_batch,
            basedpyright_max_queries=basedpyright_max_queries,
            basedpyright_max_probe_files=basedpyright_max_probe_files,
            basedpyright_max_source_files=basedpyright_max_source_files,
            basedpyright_max_workspace_bytes=basedpyright_max_workspace_bytes,
            basedpyright_timeout_seconds=basedpyright_timeout_seconds,
            mypy_batch_timeout_seconds=mypy_batch_timeout_seconds,
            mypy_batch_max_files=mypy_batch_max_files,
            mypy_batch_cache_dir=mypy_batch_cache_dir,
        )
        all_errors.extend(type_enrichment.errors)
        phase["query_count"] = len(type_queries)
        phase["fact_count"] = len(type_enrichment.facts)
        phase["error_count"] = len(type_enrichment.errors)
        phase["mypy_batch_enabled"] = enable_mypy_batch
        # Surface a single, visible top-level notice when enrichment produced no
        # facts despite having work to do (e.g. an over-budget workspace aborted
        # the shared probe). Without this the only signal is a buried per-finding
        # gap, so type-blind detection looks identical to "nothing to enrich".
        if type_queries and not type_enrichment.facts and type_enrichment.errors:
            _notify(
                progress,
                "type enrichment produced no facts "
                f"({len(type_queries)} queries): {type_enrichment.errors[0].message}",
            )

    # -- Step 6c: Dominance analysis (frozen query snapshots) --------------
    _notify(progress, "Dominance analysis")
    with _record_phase(phase_recorder, "l1_dominance") as phase:
        dominance_graphs, dominance_errors = _build_dominance_graphs(cfgs)
        all_errors.extend(dominance_errors)
        phase["cfg_count"] = len(cfgs)
        phase["dominance_graph_count"] = len(dominance_graphs)
        phase["error_count"] = len(dominance_errors)

    # -- Step 7: Persist normalized artifacts and assemble CodeIndex ------
    if artifact_root is not None:
        _notify(progress, "Writing normalized L1 artifacts")
        with _record_phase(phase_recorder, "l1_write_artifacts") as phase:
            _write_normalized_artifacts(
                artifact_root,
                functions=structural.functions,
                classes=structural.classes,
                decorators=structural.decorators,
                imports=structural.imports,
                attributes=structural.attributes,
                call_edges=merged_call_edges,
                cfgs=cfgs,
                fqn_to_file={fn.fqn: fn.file for fn in structural.functions},
                value_flow_edges=value_flow_edges,
                symbol_refs=structural_symbols,
                errors=tuple(all_errors),
                type_enrichment_facts=type_enrichment.facts,
            )
            write_file_manifest(
                artifact_root,
                python_files,
                repo_root,
                extraction_code_signature=extraction_code_signature,
            )
            phase["artifact_root"] = str(artifact_root)
            phase["error_count"] = len(all_errors)

    index = CodeIndex(
        repo_root=repo_root,
        functions=structural.functions,
        classes=structural.classes,
        decorators=structural.decorators,
        imports=structural.imports,
        attributes=structural.attributes,
        call_edges=merged_call_edges,
        cfgs=cfgs,
        value_flow_edges=value_flow_edges,
        symbol_refs=structural_symbols,
        errors=tuple(all_errors),
        provenance=ExtractionProvenance(
            producer="pipeline",
            producer_version=_PIPELINE_VERSION,
            artifact=str(repo_root),
        ),
        type_enrichment=type_enrichment,
        dominance_graphs=dominance_graphs,
    )
    if validate:
        assert_index_invariant(index)
    return index


def _transitive_dependents(
    seed_rels: set[str],
    all_python_files: tuple[Path, ...],
    imports: tuple[ImportFact, ...],
    repo_root: Path,
    namespace_roots: frozenset[str],
) -> set[str]:
    """Expand changed files to every file that transitively imports them.

    Incremental rebuild re-extracts only changed files, but a file B that
    imports a changed module A holds cached cross-file facts (resolved
    call-edge targets, symbol FQNs, re-export resolution) computed against A's
    *previous* contents.  Unless B is re-extracted too, those facts silently
    desync from a full build — the FLAW-120 silent-FN class.  This computes the
    reverse-import reachability so the incremental extraction set covers exactly
    the files whose resolution a change can affect.

    Matching is by resolved module FQN.  A file importing module ``m`` depends
    on changed module ``am`` when ``m == am`` (direct import), ``am`` is a
    submodule of ``m`` (``am.startswith(m + ".")`` — importing a re-export
    package whose ``__init__`` pulls from the changed submodule), or ``m`` is a
    submodule of ``am``.  Over-approximation is correctness-safe: re-extracting
    an unaffected file recomputes byte-identical facts; the only cost is time,
    which the caller already bounds by falling back to a full rebuild when more
    than half the repo changed.
    """
    rel_to_module: dict[str, str] = {}
    for path in all_python_files:
        rel = str(path.relative_to(repo_root))
        module, _ = _module_fqn_for_path(path, repo_root, namespace_roots)
        rel_to_module[rel] = module

    def module_for(rel: str) -> str:
        # Removed files are no longer on disk, but the module FQN is pure path
        # arithmetic, so their (now-dangling) dependents are still re-resolved.
        if rel in rel_to_module:
            return rel_to_module[rel]
        module, _ = _module_fqn_for_path(repo_root / rel, repo_root, namespace_roots)
        return module

    importer_modules: dict[str, set[str]] = {}
    for fact in imports:
        importer_modules.setdefault(fact.location.file, set()).add(fact.module)

    affected = set(seed_rels)
    affected_modules = {module_for(rel) for rel in affected}
    affected_modules.discard("")

    expanding = True
    while expanding:
        expanding = False
        for importer_rel, modules in importer_modules.items():
            if importer_rel in affected:
                continue
            if any(
                m == am or am.startswith(m + ".") or m.startswith(am + ".")
                for m in modules
                for am in affected_modules
            ):
                affected.add(importer_rel)
                imported_module = rel_to_module.get(importer_rel, "")
                if imported_module:
                    affected_modules.add(imported_module)
                expanding = True
    return affected


def incremental_build(  # noqa: PLR0915
    repo_root: Path,
    artifact_root: Path,
    file_changes: FileChanges,
    all_python_files: tuple[Path, ...],
    *,
    enable_mypy_batch: bool = False,
    basedpyright_max_queries: int = 2000,
    basedpyright_max_probe_files: int = 500,
    basedpyright_max_source_files: int = 5000,
    basedpyright_max_workspace_bytes: int = 250_000_000,
    basedpyright_timeout_seconds: int = 120,
    mypy_batch_timeout_seconds: int = 120,
    mypy_batch_max_files: int = 5000,
    mypy_batch_cache_dir: Path | None = None,
    extraction_code_signature: str = "",
    oracle: TypeOracle | None = None,
    progress: Callable[[str], None] | None = None,
    phase_recorder: Callable[[IndexBuildPhase], None] | None = None,
) -> CodeIndex:
    """Rebuild the L1 index incrementally, re-extracting the affected files.

    Reuses cached normalized artifacts (JSONL) for unaffected files, then
    re-runs LibCST structural extraction + CFG + value-flow + type enrichment
    on the changed/added files **and every file that transitively imports
    them**.

    Cross-file invalidation (FLAW-120): a file B that imports a changed module
    A holds cached cross-file facts (resolved call-edge targets, symbol FQNs,
    re-export resolution) computed against A's previous contents.  The affected
    set is therefore expanded to the transitive reverse-import closure of the
    changed files (:func:`_transitive_dependents`), and the cross-file
    resolution passes run with the **repo-wide** namespace classification and
    full project-file list so a partial re-extraction mints the same module
    FQNs and validates the same project imports a full build would.  The net
    result is that all LibCST-derived normalized facts equal a from-scratch
    full build of the same final source state (the FLAW-121 parity invariant).

    Type-enrichment re-extraction (FLAW-083): cached type facts for affected
    files are dropped and freshly re-probed against current source, mirroring
    value-flow re-extraction.  The enrichment tuning kwargs MUST match the
    values the caller passed to :func:`build_index` for the same scan,
    otherwise the changed files' facts can diverge from a full build under
    non-default configuration.
    """
    from flawed._index import CodeIndex  # noqa: I001
    from flawed._index._type_enrichment import TypeEnrichmentIndex, TypeFact
    from flawed._index._types import (
        AttributeAccess,
        CallEdge,
        ClassRecord,
        DecoratorFact,
        ExtractionError as ExtErr,
        ExtractionProvenance,
        FunctionRecord,
        ImportFact,
        SymbolRef,
        ValueFlowEdge,
    )

    repo_root = repo_root.expanduser().resolve()
    normalized = artifact_root / "normalized"

    # Repo-wide PEP 420 namespace classification: the deciding ``from <ns>.x``
    # import evidence may live in a file outside the changed subset, so it must
    # be computed from ALL files, not just the ones being re-extracted (else a
    # partial re-extraction mis-mints module FQNs — FLAW-120).
    namespace_roots = _namespace_package_roots_from_files(repo_root, all_python_files)

    # Expand the changed set to its transitive reverse-import closure so every
    # file whose cross-file resolution a change can affect is re-extracted and
    # re-resolved, not served stale from cache (FLAW-120).
    seed_rels = {
        str(p.relative_to(repo_root)) for p in (*file_changes.changed, *file_changes.added)
    } | set(file_changes.removed)
    all_cached_imports = _read_jsonl(normalized / "imports.jsonl", ImportFact)
    affected_rels = _transitive_dependents(
        seed_rels, all_python_files, all_cached_imports, repo_root, namespace_roots
    )

    # -- Load cached records, filter out affected files --------------------
    _notify(progress, "Loading cached artifacts for unchanged files")
    with _record_phase(phase_recorder, "l1_incremental_load") as phase:
        cached_functions = _filter_by_file(
            _read_jsonl(normalized / "functions.jsonl", FunctionRecord),
            affected_rels,
            lambda r: r.file,
        )
        cached_classes = _filter_by_file(
            _read_jsonl(normalized / "classes.jsonl", ClassRecord),
            affected_rels,
            lambda r: r.file,
        )
        cached_decorators = _filter_by_file(
            _read_jsonl(normalized / "decorators.jsonl", DecoratorFact),
            affected_rels,
            lambda r: r.location.file,
        )
        cached_imports = _filter_by_file(
            _read_jsonl(normalized / "imports.jsonl", ImportFact),
            affected_rels,
            lambda r: r.location.file,
        )
        cached_attributes = _filter_by_file(
            _read_jsonl(normalized / "attributes.jsonl", AttributeAccess),
            affected_rels,
            lambda r: r.location.file,
        )
        cached_call_edges = _filter_by_file(
            _read_jsonl(normalized / "call_edges.jsonl", CallEdge),
            affected_rels,
            lambda r: r.location.file,
        )
        cached_vf_edges = _filter_by_file(
            _read_jsonl(normalized / "value_flow_edges.jsonl", ValueFlowEdge),
            affected_rels,
            lambda r: r.source_location.file,
        )
        cached_symbols = _filter_by_file(
            _read_jsonl(normalized / "symbol_refs.jsonl", SymbolRef),
            affected_rels,
            lambda r: r.location.file,
        )
        cached_errors = _filter_by_file(
            _read_jsonl(normalized / "errors.jsonl", ExtErr),
            affected_rels,
            lambda r: r.file,
        )
        cached_type_facts = _filter_by_file(
            _read_jsonl(normalized / "type_enrichment.jsonl", TypeFact),
            affected_rels,
            lambda r: r.location.file,
        )
        phase["affected_files"] = len(affected_rels)
        phase["cached_functions"] = len(cached_functions)

    # -- Re-extract the affected closure (changed/added + dependents) ------
    # The affected set spans the changed files AND their transitive importers;
    # everything in it except removed files (which no longer exist) is
    # re-extracted so its cross-file facts are re-resolved against current
    # source rather than served stale.
    removed_rels = set(file_changes.removed)
    rel_to_path = {str(p.relative_to(repo_root)): p for p in all_python_files}
    files_to_extract = tuple(
        rel_to_path[rel] for rel in sorted(affected_rels - removed_rels) if rel in rel_to_path
    )
    all_errors: list[ExtErr] = list(cached_errors)
    cfgs: _CfgDict = {}

    _notify(progress, f"Re-extracting {len(files_to_extract)} affected file(s)")
    cfg_phase = _AggregatePhaseRecorder(phase_recorder, "l1_incremental_cfg")
    try:
        with _record_phase(phase_recorder, "l1_incremental_libcst") as phase:
            structural = extract_structural(
                repo_root,
                files_to_extract,
                per_file_callback=lambda parsed_file, functions: cfg_phase.measure(
                    lambda: _build_file_cfgs(parsed_file, functions, cfgs),
                    file=parsed_file.rel_path,
                    function_count=len(functions),
                ),
                # Resolve the re-extracted subset against the repo-wide namespace
                # classification and full project-file list so FQNs and project
                # import validation match a full build (FLAW-120).
                namespace_roots=namespace_roots,
                resolution_files=all_python_files,
            )
            phase["file_count"] = len(files_to_extract)
            phase["function_count"] = len(structural.functions)
    finally:
        cfg_phase.finish({"cfg_count": len(cfgs)})
    all_errors.extend(structural.errors)

    # -- Merge cached + fresh records --------------------------------------
    _notify(progress, "Merging incremental records")
    with _record_phase(phase_recorder, "l1_incremental_merge") as phase:
        merged_functions = cached_functions + structural.functions
        merged_classes = cached_classes + structural.classes
        merged_decorators = cached_decorators + structural.decorators
        merged_imports = cached_imports + structural.imports
        merged_attributes = cached_attributes + structural.attributes

        # Call graph: cached edges for unchanged files + fresh AST edges
        merged_ast_edges = cached_call_edges + structural.call_edges
        hierarchy_edges = build_hierarchy_edges(merged_classes, merged_functions, merged_ast_edges)
        call_graph, merge_errors = merge_call_graph(
            ast_edges=merged_ast_edges,
            hierarchy_edges=hierarchy_edges,
        )
        all_errors.extend(merge_errors)
        merged_call_edges = _extract_all_call_edges(call_graph)

        # Value flow: cached edges for unchanged + fresh for changed
        attribute_writes = tuple(attr for attr in structural.attributes if attr.is_write)
        fresh_vf_edges, vf_errors = extract_value_flow(
            assignments=structural.assignments,
            aliases=structural.aliases,
            functions=structural.functions,
            call_edges=structural.call_edges,
            returns=structural.returns,
            comprehension_bindings=structural.comprehension_bindings,
            attribute_writes=attribute_writes,
            yields=structural.yields,
        )
        all_errors.extend(vf_errors)
        merged_vf_edges = cached_vf_edges + fresh_vf_edges

        merged_symbols = cached_symbols + structural.symbol_refs
        phase["merged_functions"] = len(merged_functions)
        phase["merged_call_edges"] = len(merged_call_edges)

    # -- Re-run type enrichment for changed/added files (FLAW-083) ---------
    # Without this, changed files permanently lose their type-enrichment
    # facts on every incremental rebuild (cached_type_facts already excludes
    # them), silently serving incomplete facts to the rule layer — the same
    # silent-FN class fixed for CFGs in FLAW-118. Mirrors value-flow re-extraction:
    # probe only the changed files' assignments against current source and
    # merge with the retained cached facts for unchanged files.
    _notify(progress, "Type enrichment (changed files)")
    with _record_phase(phase_recorder, "l1_incremental_type_enrichment") as phase:
        fresh_type_queries = queries_from_assignments(structural.assignments)
        fresh_type_enrichment = build_type_enrichment_index(
            repo_root,
            fresh_type_queries,
            oracle=oracle,
            enable_mypy_batch=enable_mypy_batch,
            basedpyright_max_queries=basedpyright_max_queries,
            basedpyright_max_probe_files=basedpyright_max_probe_files,
            basedpyright_max_source_files=basedpyright_max_source_files,
            basedpyright_max_workspace_bytes=basedpyright_max_workspace_bytes,
            basedpyright_timeout_seconds=basedpyright_timeout_seconds,
            mypy_batch_timeout_seconds=mypy_batch_timeout_seconds,
            mypy_batch_max_files=mypy_batch_max_files,
            mypy_batch_cache_dir=mypy_batch_cache_dir,
        )
        all_errors.extend(fresh_type_enrichment.errors)
        merged_type_facts = cached_type_facts + fresh_type_enrichment.facts
        phase["query_count"] = len(fresh_type_queries)
        phase["fresh_fact_count"] = len(fresh_type_enrichment.facts)
        phase["cached_fact_count"] = len(cached_type_facts)
        phase["error_count"] = len(fresh_type_enrichment.errors)

    # -- Merge cached CFGs (unchanged files) with freshly built ones -------
    # CFGs carry condition_expr / value_predicate facts; dropping the cached
    # ones for unchanged files would silently suppress their conditions()/
    # predicates() on the incremental result (FLAW-118).
    cached_cfgs, cached_cfg_files = _read_cfgs(normalized / _CFG_ARTIFACT)
    merged_cfgs: _CfgDict = {
        fqn: entry
        for fqn, entry in cached_cfgs.items()
        if cached_cfg_files.get(fqn, "") not in affected_rels
    }
    merged_cfgs.update(cfgs)

    # -- Dominance for the merged CFG set ----------------------------------
    _notify(progress, "Dominance analysis (changed files)")
    with _record_phase(phase_recorder, "l1_incremental_dominance") as phase:
        dominance_graphs, dom_errors = _build_dominance_graphs(merged_cfgs)
        all_errors.extend(dom_errors)
        phase["dominance_graph_count"] = len(dominance_graphs)

    # -- Write updated artifacts -------------------------------------------
    _notify(progress, "Writing updated artifacts")
    fqn_to_file = dict(cached_cfg_files)
    fqn_to_file.update({fn.fqn: fn.file for fn in merged_functions})
    with _record_phase(phase_recorder, "l1_incremental_write") as phase:
        _write_normalized_artifacts(
            artifact_root,
            functions=merged_functions,
            classes=merged_classes,
            decorators=merged_decorators,
            imports=merged_imports,
            attributes=merged_attributes,
            call_edges=merged_call_edges,
            cfgs=merged_cfgs,
            fqn_to_file=fqn_to_file,
            value_flow_edges=merged_vf_edges,
            symbol_refs=merged_symbols,
            errors=tuple(all_errors),
            type_enrichment_facts=merged_type_facts,
        )
        write_file_manifest(
            artifact_root,
            all_python_files,
            repo_root,
            extraction_code_signature=extraction_code_signature,
        )
        phase["artifact_root"] = str(artifact_root)

    return CodeIndex(
        repo_root=repo_root,
        functions=merged_functions,
        classes=merged_classes,
        decorators=merged_decorators,
        imports=merged_imports,
        attributes=merged_attributes,
        call_edges=merged_call_edges,
        cfgs=merged_cfgs,
        value_flow_edges=merged_vf_edges,
        symbol_refs=merged_symbols,
        errors=tuple(all_errors),
        provenance=ExtractionProvenance(
            producer="pipeline_incremental",
            producer_version=_PIPELINE_VERSION,
            artifact=str(artifact_root),
        ),
        type_enrichment=TypeEnrichmentIndex(facts=merged_type_facts),
        dominance_graphs=dominance_graphs,
    )


def _filter_by_file[T](
    records: tuple[T, ...],
    affected_files: set[str],
    file_getter: Callable[[T], str],
) -> tuple[T, ...]:
    return tuple(r for r in records if file_getter(r) not in affected_files)


def _build_dominance_graphs(
    cfgs: _CfgDict,
) -> tuple[dict[str, DominanceGraph], list[ExtractionError]]:
    """Compute frozen dominance query objects for all per-function CFGs.

    Errors from individual CFGs are collected as non-fatal extraction errors
    rather than failing the entire pipeline.
    """
    from flawed._index._dominance import dominance_from_cfg
    from flawed._index._graphs import ControlFlowGraph

    graphs: dict[str, DominanceGraph] = {}
    errors: list[ExtractionError] = []

    for fqn, (blocks, edges, regions) in cfgs.items():
        try:
            cfg = ControlFlowGraph(blocks, edges, try_regions=regions)
            graphs[fqn] = dominance_from_cfg(cfg)
        except Exception as exc:
            errors.append(
                ExtractionError(
                    file="",
                    pass_name="dominance_analysis",
                    error_kind=ErrorKind.CFG,
                    message=f"Dominance analysis failed for {fqn}: {exc}",
                    is_fatal=False,
                    location=None,
                )
            )

    return graphs, errors


@contextmanager
def _record_phase(
    phase_recorder: Callable[[IndexBuildPhase], None] | None,
    name: str,
) -> Iterator[dict[str, object]]:
    details: dict[str, object] = {}
    if phase_recorder is None:
        yield details
        return

    wall_start_ns = time.perf_counter_ns()
    cpu_start_ns = time.process_time_ns()
    rss_start = _rss_high_water_bytes()
    status = "completed"
    try:
        yield details
    except BaseException:
        status = "failed"
        raise
    finally:
        phase_recorder(
            IndexBuildPhase(
                name=name,
                status=status,
                wall_ms=_elapsed_ms(wall_start_ns, time.perf_counter_ns()),
                cpu_ms=_elapsed_ms(cpu_start_ns, time.process_time_ns()),
                rss_high_water_start_bytes=rss_start,
                rss_high_water_end_bytes=_rss_high_water_bytes(),
                details=dict(details),
            )
        )


class _AggregatePhaseRecorder:
    """Collect one aggregate phase from repeated short callbacks."""

    def __init__(
        self,
        phase_recorder: Callable[[IndexBuildPhase], None] | None,
        name: str,
    ) -> None:
        self._phase_recorder = phase_recorder
        self._name = name
        self._rss_start = _rss_high_water_bytes()
        self._rss_end = self._rss_start
        self._wall_ns = 0
        self._cpu_ns = 0
        self._file_count = 0
        self._function_count = 0
        self._status = "completed"
        self._finished = False

    @property
    def wall_ms(self) -> float:
        return _elapsed_ms(0, self._wall_ns)

    def measure(
        self,
        callback: Callable[[], Sequence[ExtractionError]],
        *,
        file: str,
        function_count: int,
    ) -> Sequence[ExtractionError]:
        wall_start_ns = time.perf_counter_ns()
        cpu_start_ns = time.process_time_ns()
        self._file_count += 1
        self._function_count += function_count
        try:
            return callback()
        except BaseException:
            self._status = "failed"
            raise
        finally:
            self._wall_ns += time.perf_counter_ns() - wall_start_ns
            self._cpu_ns += time.process_time_ns() - cpu_start_ns
            self._rss_end = max(self._rss_end, _rss_high_water_bytes())
            _ = file  # retained in the signature for readable call sites

    def finish(self, details: Mapping[str, object]) -> None:
        if self._finished:
            return
        self._finished = True
        if self._phase_recorder is None:
            return
        payload = {
            "file_count": self._file_count,
            "function_count": self._function_count,
            **details,
        }
        self._phase_recorder(
            IndexBuildPhase(
                name=self._name,
                status=self._status,
                wall_ms=self.wall_ms,
                cpu_ms=_elapsed_ms(0, self._cpu_ns),
                rss_high_water_start_bytes=self._rss_start,
                rss_high_water_end_bytes=self._rss_end,
                details=payload,
            )
        )


def _rss_high_water_bytes() -> int:
    raw = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if sys.platform == "darwin":
        return raw
    return raw * 1024


def _elapsed_ms(start_ns: int, end_ns: int) -> float:
    return round((end_ns - start_ns) / 1_000_000, 3)


def _build_file_cfgs(
    parsed_file: ParsedFile,
    functions: tuple[FunctionRecord, ...],
    cfgs: _CfgDict,
) -> tuple[ExtractionError, ...]:
    """Build CFGs for one parsed file while its LibCST wrapper is still live."""
    if not functions:
        return ()

    rel_path = parsed_file.rel_path
    try:
        fn_defs = _find_function_defs(parsed_file.wrapper)
    except cst.MetadataException as exc:
        return (
            ExtractionError(
                file=rel_path,
                pass_name="cfg_builder",
                error_kind=ErrorKind.CFG,
                message=f"Could not resolve function positions for CFG construction: {exc}",
                is_fatal=False,
                location=None,
            ),
        )

    errors: list[ExtractionError] = []
    fn_by_line: dict[int, FunctionRecord] = {f.line: f for f in functions}

    for func_node, start_line in fn_defs:
        fn_record = fn_by_line.get(start_line)
        if fn_record is None:
            continue

        try:
            cfg_result, cfg_errs = build_cfg(
                func_node,
                fn_record.fqn,
                Path(rel_path),
                parsed_file.wrapper,
                span_interner=parsed_file.span_interner,
            )
        except Exception as exc:
            errors.append(
                ExtractionError(
                    file=rel_path,
                    pass_name="cfg_builder",
                    error_kind=ErrorKind.CFG,
                    message=f"CFG build failed for {fn_record.fqn}: {exc}",
                    is_fatal=False,
                    location=None,
                )
            )
            continue

        cfgs[fn_record.fqn] = (cfg_result.blocks, cfg_result.edges, cfg_result.try_regions)
        errors.extend(cfg_errs)

    return tuple(errors)


def _find_function_defs(wrapper: MetadataWrapper) -> list[tuple[cst.FunctionDef, int]]:
    """Find all FunctionDef nodes with their start line numbers.

    Walks the tree manually since we need to find function defs at all
    nesting levels (top-level, inside classes, nested functions).
    """
    results: list[tuple[cst.FunctionDef, int]] = []
    positions = wrapper.resolve(PositionProvider)

    class _PositionFinder(cst.CSTVisitor):
        def visit_FunctionDef(self, node: cst.FunctionDef) -> bool | None:  # noqa: N802
            try:
                pos = positions[node]
            except KeyError:
                return True
            results.append((node, pos.start.line))
            return True

    wrapper.visit(_PositionFinder())
    return results


def _extract_all_call_edges(call_graph: CallGraph) -> tuple[CallEdge, ...]:
    """Extract the merged call edges from the CallGraph.

    The CallGraph stores edges internally; we pull them back out as a
    flat tuple for the CodeIndex constructor.  Module-level call sites use
    the synthetic ``<module>`` caller and must remain available to Layer 2
    for framework registration APIs such as ``app.add_url_rule()``.
    """
    seen: set[tuple[str, str | None, str, int]] = set()
    edges: list[CallEdge] = []

    for e in call_graph.edges:
        key = (e.caller_fqn, e.callee_fqn, e.location.file, e.location.line)
        if key not in seen:
            seen.add(key)
            edges.append(e)

    return tuple(edges)


def _notify(progress: Callable[[str], None] | None, message: str) -> None:
    if progress is not None:
        progress(message)


def _write_normalized_artifacts(
    artifact_root: Path,
    *,
    functions: tuple[FunctionRecord, ...],
    classes: tuple[object, ...],
    decorators: tuple[object, ...],
    imports: tuple[object, ...],
    attributes: tuple[object, ...],
    call_edges: tuple[CallEdge, ...],
    cfgs: _CfgDict,
    fqn_to_file: Mapping[str, str],
    value_flow_edges: tuple[object, ...],
    symbol_refs: tuple[object, ...],
    errors: tuple[ExtractionError, ...],
    type_enrichment_facts: tuple[object, ...] = (),
) -> None:
    normalized = artifact_root / "normalized"
    normalized.mkdir(parents=True, exist_ok=True)
    cfg_count = len(cfgs)

    _write_jsonl(normalized / "functions.jsonl", functions)
    _write_jsonl(normalized / "classes.jsonl", classes)
    _write_jsonl(normalized / "decorators.jsonl", decorators)
    _write_jsonl(normalized / "imports.jsonl", imports)
    _write_jsonl(normalized / "attributes.jsonl", attributes)
    _write_jsonl(normalized / "call_edges.jsonl", call_edges)
    _write_jsonl(normalized / "value_flow_edges.jsonl", value_flow_edges)
    _write_jsonl(normalized / "symbol_refs.jsonl", symbol_refs)
    _write_jsonl(normalized / "errors.jsonl", errors)
    _write_jsonl(normalized / "type_enrichment.jsonl", type_enrichment_facts)
    write_cfgs(normalized / _CFG_ARTIFACT, cfgs, fqn_to_file)

    summary = {
        # L1 schema identity (FLAW-344) — recorded for auditing and as a second,
        # in-artifact copy of the cache-validity key (cache_key.json is the gate).
        "l1_schema_version": L1_SCHEMA_VERSION,
        "record_schema_fingerprint": record_schema_fingerprint(),
        "pipeline_version": _PIPELINE_VERSION,
        "functions": len(functions),
        "classes": len(classes),
        "decorators": len(decorators),
        "imports": len(imports),
        "attributes": len(attributes),
        "call_edges": len(call_edges),
        "value_flow_edges": len(value_flow_edges),
        "symbol_refs": len(symbol_refs),
        "errors": len(errors),
        "fatal_errors": sum(1 for error in errors if error.is_fatal),
        "type_enrichment_facts": len(type_enrichment_facts),
        "cfgs": cfg_count,
    }
    (normalized / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    artifact_counts = {
        "functions.jsonl": len(functions),
        "classes.jsonl": len(classes),
        "decorators.jsonl": len(decorators),
        "imports.jsonl": len(imports),
        "attributes.jsonl": len(attributes),
        "call_edges.jsonl": len(call_edges),
        "value_flow_edges.jsonl": len(value_flow_edges),
        "symbol_refs.jsonl": len(symbol_refs),
        "errors.jsonl": len(errors),
        "type_enrichment.jsonl": len(type_enrichment_facts),
        "cfgs.jsonl": cfg_count,
        "summary.json": 1,
    }
    _write_normalized_manifest(
        normalized,
        artifact_counts=artifact_counts,
        cfg_count=cfg_count,
    )


def _write_normalized_manifest(
    normalized: Path,
    *,
    artifact_counts: dict[str, int],
    cfg_count: int,
) -> None:
    written_artifacts = [
        {
            "path": path,
            "status": "written",
            "record_count": artifact_counts[path],
            "description": description,
        }
        for path, description in _WRITTEN_NORMALIZED_ARTIFACTS
    ]
    manifest = {
        "schema_version": 1,
        "producer": "pipeline",
        "producer_version": _PIPELINE_VERSION,
        "cfg_persistence": "written",
        "cfg_count": cfg_count,
        "written_artifacts": written_artifacts,
        "deferred_artifacts": list(_DEFERRED_NORMALIZED_ARTIFACTS),
    }
    (normalized / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, records: tuple[object, ...]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(_jsonable(record), sort_keys=True) + "\n")


def _jsonable(value: object) -> object:
    if isinstance(value, Enum):
        result: object = value.value
    elif isinstance(value, Path):
        result = str(value)
    elif is_dataclass(value) and not isinstance(value, type):
        result = _jsonable(asdict(value))
    elif isinstance(value, dict):
        result = {str(key): _jsonable(item) for key, item in value.items()}
    elif isinstance(value, tuple | list):
        result = [_jsonable(item) for item in value]
    elif isinstance(value, str | int | float | bool) or value is None:
        result = value
    else:
        result = str(value)
    return result
