"""Layer 1: Code Index — Python-generic structural extraction.

This package implements language-level structural extraction that runs once per
repository snapshot. It produces frozen, typed facts about the source code:
functions, classes, calls, control flow graphs, value flow, decorators, imports,
attributes, and symbols.

The Code Index persists Python-structural facts only. Layer 1 may host
static-analysis tool adapters (for example astroid brain plugins that make
library runtime objects inferable), but framework-specific interpretation of
those structural facts is the Semantic Layer's job.

Boundary rules:
  - This package may NOT import from flawed._semantic (Layer 2)
  - This package may NOT import from flawed top-level modules (Rule API / Layer 3)
  - Violations are enforced by import-linter and will fail pre-commit

Public API:
  ``CodeIndex`` is the sole entry point for Layer 2 to access Layer 1 data.
  No Layer 2 code reads JSONL files, raw extractor output, or internal indexes
  directly.  All access goes through this typed API.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flawed._index._collections import (
    AttributeAccessCollection,
    ClassCollection,
    DecoratorCollection,
    ExtractionErrorCollection,
    FunctionCollection,
    ImportCollection,
)
from flawed._index._dominance import (
    DominanceGap,
    DominanceGraph,
    DominanceLoop,
    GuardResult,
)
from flawed._index._graphs import (
    CallGraph,
    ControlFlowGraph,
    SymbolIndex,
    ValueFlowGraph,
)
from flawed._index._type_enrichment import TypeEnrichmentIndex
from flawed._index._types import (
    AttributeAccess,
    CallEdge,
    CFGBlock,
    CFGEdge,
    ClassRecord,
    DecoratorFact,
    ExceptHandler,
    ExtractionError,
    ExtractionProvenance,
    FunctionRecord,
    HierarchyGap,
    ImportFact,
    SourceSpan,
    SymbolRef,
    TryExceptRegion,
    ValueFlowEdge,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


class CodeIndex:
    """Sole entry point for Layer 2 to access Layer 1 structural data.

    Constructed by the extraction pipeline (Steps 1-7).  All access by
    consumers goes through the typed properties and query objects exposed
    here - no raw file reads, no JSONL parsing.

    Example::

        idx = CodeIndex.open("/path/to/analysis-store/repos/slug/snapshot")
        for fn in idx.functions.decorated_with("route"):
            edges = idx.call_graph.edges_from(fn.fqn)
            ...
    """

    __slots__ = (
        "_attributes",
        "_call_graph",
        "_cfgs",
        "_classes",
        "_decorators",
        "_dominance",
        "_errors",
        "_functions",
        "_imports",
        "_namespace_roots_cache",
        "_provenance",
        "_repo_root",
        "_source_cache",
        "_symbols",
        "_type_enrichment",
        "_value_flow",
    )

    def __init__(
        self,
        *,
        repo_root: Path,
        functions: tuple[FunctionRecord, ...],
        classes: tuple[ClassRecord, ...],
        decorators: tuple[DecoratorFact, ...],
        imports: tuple[ImportFact, ...],
        attributes: tuple[AttributeAccess, ...],
        call_edges: tuple[CallEdge, ...],
        cfgs: dict[
            str,
            tuple[tuple[CFGBlock, ...], tuple[CFGEdge, ...], tuple[TryExceptRegion, ...]],
        ],
        value_flow_edges: tuple[ValueFlowEdge, ...],
        symbol_refs: tuple[SymbolRef, ...],
        errors: tuple[ExtractionError, ...],
        provenance: ExtractionProvenance,
        type_enrichment: TypeEnrichmentIndex | None = None,
        dominance_graphs: Mapping[str, DominanceGraph] | None = None,
    ) -> None:
        self._repo_root = repo_root
        self._functions = FunctionCollection(functions)
        self._classes = ClassCollection(classes, decorators)
        self._decorators = DecoratorCollection(decorators)
        self._imports = ImportCollection(imports)
        self._attributes = AttributeAccessCollection(attributes)
        self._call_graph = CallGraph(call_edges)
        self._cfgs: dict[str, ControlFlowGraph] = {
            fqn: ControlFlowGraph(blocks, edges, try_regions=regions)
            for fqn, (blocks, edges, regions) in cfgs.items()
        }
        self._value_flow = ValueFlowGraph(value_flow_edges)
        self._symbols = SymbolIndex(symbol_refs)
        self._type_enrichment = (
            type_enrichment if type_enrichment is not None else TypeEnrichmentIndex.empty()
        )
        self._dominance: Mapping[str, DominanceGraph] = MappingProxyType(
            dict(dominance_graphs or {})
        )
        self._errors = ExtractionErrorCollection(errors)
        self._provenance = provenance
        self._source_cache: dict[str, list[str]] = {}
        self._namespace_roots_cache: frozenset[str] | None = None

    # -- Entity collections -------------------------------------------

    @property
    def functions(self) -> FunctionCollection:
        """All extracted function records."""
        return self._functions

    @property
    def classes(self) -> ClassCollection:
        """All extracted class records."""
        return self._classes

    @property
    def decorators(self) -> DecoratorCollection:
        """All extracted decorator facts."""
        return self._decorators

    @property
    def imports(self) -> ImportCollection:
        """All extracted import facts."""
        return self._imports

    @property
    def attributes(self) -> AttributeAccessCollection:
        """All attribute-access observations."""
        return self._attributes

    # -- Graph queries ------------------------------------------------

    @property
    def call_graph(self) -> CallGraph:
        """Merged call graph across all extraction sources."""
        return self._call_graph

    def cfg(self, function_fqn: str) -> ControlFlowGraph | None:
        """Per-function control-flow graph, or ``None`` if unavailable."""
        return self._cfgs.get(function_fqn)

    @property
    def value_flow(self) -> ValueFlowGraph:
        """Pre-computed intra-function value-flow edges."""
        return self._value_flow

    @property
    def symbols(self) -> SymbolIndex:
        """Symbol resolution index."""
        return self._symbols

    @property
    def type_enrichment(self) -> TypeEnrichmentIndex:
        """Declared-type facts produced by L1 type-enrichment probes."""
        return self._type_enrichment

    def dominance(self, function_fqn: str) -> DominanceGraph | None:
        """Frozen/query-only per-function dominance facts, or ``None`` if unavailable."""
        return self._dominance.get(function_fqn)

    # -- Errors and metadata ------------------------------------------

    @property
    def errors(self) -> ExtractionErrorCollection:
        """Extraction errors from all pipeline steps."""
        return self._errors

    @property
    def provenance(self) -> ExtractionProvenance:
        """Provenance of this CodeIndex snapshot."""
        return self._provenance

    @property
    def repo_root(self) -> Path:
        """Absolute path to the repository root."""
        return self._repo_root

    def module_fqn_for_file(self, file: str) -> str:
        """Return the Python module FQN for a repository-relative source file.

        Uses the same PEP 420 namespace-prefix classification as extraction so
        that the FQN returned here matches the FQNs minted for the file's own
        functions and classes (e.g. ``src.app`` for a ``src/`` namespace-root
        layout, not ``app``).
        """
        from flawed._index._resolution import _module_fqn_for_path

        return _module_fqn_for_path(
            self._repo_root / file, self._repo_root, self._namespace_roots()
        )[0]

    def _namespace_roots(self) -> frozenset[str]:
        """Lazily classify and cache PEP 420 namespace-prefix directories."""
        if self._namespace_roots_cache is None:
            from flawed._index._resolution import _namespace_package_roots
            from flawed._index._structural import discover_python_files

            self._namespace_roots_cache = _namespace_package_roots(
                self._repo_root,
                discover_python_files(self._repo_root),
                tuple(self._imports),
            )
        return self._namespace_roots_cache

    # -- Source text ---------------------------------------------------

    def source(self, location: SourceSpan, *, context: int = 0) -> str:
        """Read source text at *location* with optional surrounding context.

        Returns the empty string if the file cannot be read.
        """
        filepath = self._repo_root / location.file
        if location.file not in self._source_cache:
            try:
                self._source_cache[location.file] = filepath.read_text().splitlines()
            except (OSError, UnicodeDecodeError):
                return ""

        lines = self._source_cache[location.file]
        start = max(0, location.line - 1 - context)
        end = min(len(lines), location.end_line + context)
        return "\n".join(lines[start:end])

    # -- Factory methods ----------------------------------------------

    @classmethod
    def empty(cls, repo_root: Path) -> CodeIndex:
        """Create an empty CodeIndex for testing."""
        return cls(
            repo_root=repo_root,
            functions=(),
            classes=(),
            decorators=(),
            imports=(),
            attributes=(),
            call_edges=(),
            cfgs={},
            value_flow_edges=(),
            symbol_refs=(),
            errors=(),
            provenance=ExtractionProvenance(
                producer="empty",
                producer_version="0.0.0",
                artifact="",
            ),
        )

    def __repr__(self) -> str:
        return (
            f"CodeIndex("
            f"{len(self._functions)} functions, "
            f"{len(self._classes)} classes, "
            f"{len(self._decorators)} decorators, "
            f"call_graph={self._call_graph!r})"
        )


__all__ = [
    "AttributeAccessCollection",
    "CallGraph",
    "ClassCollection",
    "CodeIndex",
    "ControlFlowGraph",
    "DecoratorCollection",
    "DominanceGap",
    "DominanceGraph",
    "DominanceLoop",
    "ExceptHandler",
    "ExtractionErrorCollection",
    "FunctionCollection",
    "GuardResult",
    "HierarchyGap",
    "ImportCollection",
    "SymbolIndex",
    "TryExceptRegion",
    "TypeEnrichmentIndex",
    "ValueFlowGraph",
]
