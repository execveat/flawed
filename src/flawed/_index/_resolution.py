"""Structural cross-file resolution helpers for the Layer 1 index."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

import libcst as cst

from flawed._index._parsing import parse_analyzed_module
from flawed._index._types import (
    AliasFact,
    AliasMechanism,
    AssignmentFact,
    CallEdge,
    ClassRecord,
    DecoratorFact,
    ErrorKind,
    ExtractionError,
    ExtractionProvenance,
    FunctionRecord,
    ImportFact,
    ResolutionStatus,
    SourceSpan,
    SymbolRef,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from flawed._index._structural import StructuralOutput

# ── Constants ─────────────────────────────────────────────────────────

_PASS_NAME = "structural_entity_pass"
_PASS_VERSION = "0.1.0"
_BOUND_RECEIVER_UNRESOLVED = "receiver_not_bound"
_RECEIVER_METHOD_MISSING = "receiver_method_not_in_mro"
_RECEIVER_MRO_INCOMPLETE = "receiver_mro_incomplete"
_RECEIVER_ATTRIBUTE_CHAIN = "receiver_attribute_chain"
_SUPER_NOT_IN_METHOD = "super_not_in_method"
_SUPER_NO_PARENT_CLASS = "super_no_parent_class"
_SUPER_METHOD_MISSING = "super_method_not_in_mro"
_SUPER_MRO_INCOMPLETE = "super_mro_incomplete"
_SUPER_CALL_PREFIX = "super()."


@dataclass(frozen=True)
class _FromImportShadow:
    file: str
    local_name: str
    imported_fqn: str
    local_fqn: str
    shadow_line: int
    end_line: int | None = None


@dataclass(frozen=True)
class _ImportAliasShadow:
    file: str
    local_name: str
    imported_fqn: str
    local_fqn: str
    import_line: int
    end_line: int | None
    end_inclusive: bool


@dataclass(frozen=True)
class _ImportBindingRange:
    file: str
    local_name: str
    imported_fqn: str
    local_fqn: str
    import_line: int
    end_line: int | None
    end_inclusive: bool


@dataclass(frozen=True)
class _ProjectModuleIndex:
    """Precomputed project module membership for import validation."""

    exact_modules: frozenset[str]
    path_prefixes: frozenset[str]
    project_roots: frozenset[str]

    @classmethod
    def build(
        cls,
        repo_root: Path,
        python_files: Sequence[Path],
        namespace_roots: frozenset[str] = frozenset(),
    ) -> _ProjectModuleIndex:
        exact_modules = _project_module_fqns(repo_root, python_files, namespace_roots)
        return cls.from_modules(exact_modules)

    @classmethod
    def from_modules(cls, exact_modules: frozenset[str]) -> _ProjectModuleIndex:
        path_prefixes: set[str] = set()
        for module in exact_modules:
            parts = module.split(".")
            path_prefixes.update(
                ".".join(parts[:part_count]) for part_count in range(1, len(parts))
            )

        return cls(
            exact_modules=exact_modules,
            path_prefixes=frozenset(path_prefixes),
            project_roots=frozenset(
                module.split(".", maxsplit=1)[0] for module in exact_modules if module
            ),
        )

    def path_exists(self, module_fqn: str) -> bool:
        return module_fqn in self.exact_modules or module_fqn in self.path_prefixes

    def is_project_local_module_path(self, module_fqn: str) -> bool:
        root = module_fqn.split(".", maxsplit=1)[0]
        return root in self.project_roots


@dataclass(frozen=True)
class _ImportedModuleValidationIndex:
    """Project import-member validation index with stable pre-sorted imports."""

    project_modules: _ProjectModuleIndex
    imported_modules: frozenset[str]
    imported_modules_by_length: tuple[str, ...]
    project_classes: frozenset[str]


@dataclass(frozen=True)
class _ImportBindingSourceOrderIndex:
    """Lookup tables for from-import source-order restoration."""

    bindings: tuple[_ImportBindingRange, ...]
    by_file: dict[str, tuple[_ImportBindingRange, ...]]
    by_file_first_segment: dict[tuple[str, str], tuple[_ImportBindingRange, ...]]
    by_file_local_name: dict[tuple[str, str], tuple[_ImportBindingRange, ...]]

    @classmethod
    def build(
        cls,
        bindings: Sequence[_ImportBindingRange],
    ) -> _ImportBindingSourceOrderIndex:
        ordered_bindings = tuple(
            sorted(bindings, key=lambda item: (item.file, item.import_line, item.local_name))
        )
        by_file: dict[str, list[_ImportBindingRange]] = {}
        by_file_first_segment: dict[tuple[str, str], list[_ImportBindingRange]] = {}
        by_file_local_name: dict[tuple[str, str], list[_ImportBindingRange]] = {}
        for binding in ordered_bindings:
            by_file.setdefault(binding.file, []).append(binding)
            by_file_first_segment.setdefault((binding.file, binding.local_name), []).append(
                binding
            )
            by_file_local_name.setdefault((binding.file, binding.local_name), []).append(binding)

        return cls(
            bindings=ordered_bindings,
            by_file={
                file: tuple(
                    sorted(
                        items,
                        key=lambda item: (len(item.local_fqn), item.import_line),
                        reverse=True,
                    )
                )
                for file, items in by_file.items()
            },
            by_file_first_segment={
                key: tuple(
                    sorted(
                        items,
                        key=lambda item: (len(item.local_fqn), item.import_line),
                        reverse=True,
                    )
                )
                for key, items in by_file_first_segment.items()
            },
            by_file_local_name={
                key: tuple(
                    sorted(
                        items,
                        key=lambda item: (len(item.imported_fqn), item.import_line),
                        reverse=True,
                    )
                )
                for key, items in by_file_local_name.items()
            },
        )

    def candidates_for_source_name(
        self,
        file: str,
        name: str,
    ) -> tuple[_ImportBindingRange, ...]:
        first_segment = name.split(".", maxsplit=1)[0]
        return self.by_file_first_segment.get((file, first_segment), ())

    def candidates_for_file(self, file: str) -> tuple[_ImportBindingRange, ...]:
        return self.by_file.get(file, ())

    def previous_candidates_for(
        self,
        binding: _ImportBindingRange,
    ) -> tuple[_ImportBindingRange, ...]:
        return self.by_file_local_name.get((binding.file, binding.local_name), ())


@dataclass(frozen=True)
class _AssignmentValueIndex:
    by_file_line: dict[tuple[str, int], tuple[AssignmentFact, ...]]

    @classmethod
    def build(cls, assignments: Sequence[AssignmentFact]) -> _AssignmentValueIndex:
        by_file_line: dict[tuple[str, int], list[AssignmentFact]] = {}
        for assignment in assignments:
            by_file_line.setdefault(
                (assignment.target_location.file, assignment.target_location.line),
                [],
            ).append(assignment)
        return cls(
            by_file_line={key: tuple(items) for key, items in by_file_line.items()},
        )

    def value_expressions_for_target(
        self,
        *,
        file: str,
        line: int,
        target_name: str,
    ) -> tuple[str, ...]:
        expressions: list[str] = []
        for assignment in self.by_file_line.get((file, line), ()):
            expressions.extend(_assignment_value_expressions_for_target(assignment, target_name))
        return tuple(expressions)


def _provenance(rel_path: str) -> ExtractionProvenance:
    return ExtractionProvenance(
        producer=_PASS_NAME,
        producer_version=_PASS_VERSION,
        artifact=rel_path,
    )


def _namespace_candidate_dirs(
    repo_root: Path,
    python_files: Sequence[Path],
) -> set[str]:
    """Top-level dirs (immediate children of *repo_root*) lacking ``__init__.py``.

    These are the only directories that can be PEP 420 namespace prefixes; a
    top dir that ships its own ``__init__.py`` is an ordinary package and is
    excluded. This is a cheap directory scan (no source parsing).
    """
    candidate_dirs: set[str] = set()
    for path in python_files:
        file_path = path if path.is_absolute() else repo_root / path
        parts = file_path.relative_to(repo_root).parts
        if len(parts) < 2:
            continue
        top = parts[0]
        if (repo_root / top / "__init__.py").exists():
            continue
        candidate_dirs.add(top)
    return candidate_dirs


def _namespace_package_roots(
    repo_root: Path,
    python_files: Sequence[Path],
    imports: Sequence[ImportFact],
) -> frozenset[str]:
    """Classify top-level directories that act as PEP 420 namespace prefixes.

    A repository may place its source under a directory (commonly ``src``)
    that has no ``__init__.py`` of its own while its subpackages do.  Such a
    directory is ambiguous:

    - **Source root (STRIP)** — the installable ``src/<pkg>/__init__.py``
      layout, where the repo imports ``from <pkg> import ...``.  ``src`` is
      not part of any module FQN and the package-root walk already strips it.
    - **Namespace prefix (KEEP)** — the ``src/app.py`` + ``src/utils/...``
      layout where the repo imports ``from src.utils import ...``.  Here
      ``src`` is a real leading segment of every module FQN.

    The two cases are indistinguishable from the filesystem alone; the
    repository's own import statements are the deciding evidence.  A top-level
    directory ``D`` (immediate child of *repo_root*, lacking ``__init__.py``)
    is treated as a namespace prefix iff some module in the repo imports a
    module whose first dotted segment is ``D`` (``from D.x import ...`` or
    ``import D.x``).  This never fires for source-root layouts because those
    repos import their packages directly (``from <pkg> import ...``), so
    ``D`` itself never appears as an import head.

    The deciding import evidence comes from the index's already-extracted
    :class:`ImportFact`s (``imports``) rather than a fresh filesystem AST
    re-scan: every ``import``/``from import`` in the repo was parsed once
    during L1 extraction, so re-reading and re-parsing every source file here
    would be pure duplicated work — an O(files) re-parse on the resolution hot
    path that the L2 build pays per scan (FLAW-102 perf regression). Relative
    imports are excluded because a package's intra-package imports are not
    evidence that the top directory is an imported namespace; their
    ``ImportFact.module`` is the *resolved* absolute name, so the relative
    origin is recovered from :attr:`ImportFact.is_relative`.

    The classification is computed once per index build and threaded into
    :func:`_module_fqn_for_path` so that every sibling module under ``D``
    roots consistently (both ``src/app.py`` and ``src/utils/token_auth.py``
    keep the ``src`` prefix), which in turn lets project-local imports such as
    ``from src.utils.token_auth import ...`` resolve against the index.
    """
    candidate_dirs = _namespace_candidate_dirs(repo_root, python_files)
    if not candidate_dirs:
        return frozenset()

    import_heads = _import_module_heads(imports)
    return frozenset(candidate_dirs & import_heads)


def _namespace_package_roots_from_files(
    repo_root: Path,
    python_files: Sequence[Path],
) -> frozenset[str]:
    """``_namespace_package_roots`` variant for the L1 extraction entry point.

    Structural extraction needs ``namespace_roots`` to mint module FQNs, so it
    runs *before* any :class:`ImportFact` exists. This variant reads import
    heads directly from source via :mod:`ast`. It is only reached on a cold L1
    build (the index is cached to disk afterwards) and short-circuits the parse
    entirely when there are no namespace-candidate directories, so the common
    flat-/source-layout repo never pays it. The hot per-scan path
    (:meth:`CodeIndex._namespace_roots`) uses :func:`_namespace_package_roots`
    with already-extracted facts instead.
    """
    candidate_dirs = _namespace_candidate_dirs(repo_root, python_files)
    if not candidate_dirs:
        return frozenset()

    import_heads = _import_module_heads_from_files(repo_root, python_files)
    return frozenset(candidate_dirs & import_heads)


def _import_module_heads(imports: Sequence[ImportFact]) -> frozenset[str]:
    """Return the set of first dotted segments of every imported module name.

    Derives the leading segment of each ``import x.y`` / ``from x.y import ...``
    target from the index's already-extracted :class:`ImportFact`s. Relative
    imports (``from . import``) are skipped: their :attr:`ImportFact.module`
    holds the resolved absolute name, but the relative origin means the head is
    the file's own package, not external namespace evidence.
    """
    heads: set[str] = set()
    for fact in imports:
        if fact.is_relative:
            continue
        head = fact.module.split(".", maxsplit=1)[0]
        if head:
            heads.add(head)
    return frozenset(heads)


def _import_module_heads_from_files(
    repo_root: Path,
    python_files: Sequence[Path],
) -> frozenset[str]:
    """Import heads read from source — for the cold L1 extraction path only.

    Reads each file once with :mod:`ast` and collects the leading segment of
    every ``import x.y`` / ``from x.y import ...`` target.  Relative imports
    (``from . import``) have no module head and are skipped.
    """
    heads: set[str] = set()
    for path in python_files:
        file_path = path if path.is_absolute() else repo_root / path
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
            tree = parse_analyzed_module(source, filename=str(file_path))
        except (OSError, SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    head = alias.name.split(".", maxsplit=1)[0]
                    if head:
                        heads.add(head)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    continue
                module = node.module or ""
                head = module.split(".", maxsplit=1)[0]
                if head:
                    heads.add(head)
    return frozenset(heads)


def _module_fqn_for_path(
    file_path: Path,
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> tuple[str, bool]:
    """Return the Python module FQN for *file_path* plus whether it is a package.

    *namespace_roots* names top-level directories that are PEP 420 namespace
    prefixes (see :func:`_namespace_package_roots`).  When a file lives under
    such a directory, the directory is kept as the leading FQN segment even
    though it has no ``__init__.py`` — this makes every sibling under the
    namespace directory root consistently.  When empty (the default and the
    common source-root / flat-layout case), behaviour is unchanged.
    """
    is_package_module = file_path.name == "__init__.py"

    rel_parts = file_path.relative_to(repo_root).parts
    namespace_prefix: str | None = (
        rel_parts[0] if rel_parts and rel_parts[0] in namespace_roots else None
    )

    package_root: Path | None = None
    current = file_path.parent
    while current == repo_root or repo_root in current.parents:
        if namespace_prefix is not None and current == repo_root / namespace_prefix:
            # The namespace directory itself has no ``__init__.py``; stop the
            # walk here and root FQNs at the namespace prefix rather than
            # re-rooting at an inner ``__init__.py`` chain.
            break
        # Keep climbing past directories that lack ``__init__.py`` and record the
        # OUTERMOST ancestor that is a regular package. Python 3.3+ treats an
        # ``__init__``-less directory nested inside a regular package as an
        # implicit namespace subpackage, so ``pkg/sub/mod.py`` (where ``pkg`` has
        # ``__init__.py`` but ``sub`` does not) is the module ``pkg.sub.mod`` —
        # not ``sub.mod``. Terminating at the first gap dropped the outer package
        # prefix and broke both the function FQN and the ``..`` relative-import
        # base derived from it (FLAW-115).
        if (current / "__init__.py").exists():
            package_root = current
        if current == repo_root:
            break
        current = current.parent

    if namespace_prefix is not None:
        rel = file_path.relative_to(repo_root).with_suffix("")
        module_parts = [part for part in rel.parts if part != "__init__"]
    elif package_root is not None:
        module_parts = [package_root.name]
        rel_to_package = file_path.relative_to(package_root).with_suffix("")
        path_parts = list(rel_to_package.parts)
        if path_parts and path_parts[-1] == "__init__":
            path_parts = path_parts[:-1]
        module_parts.extend(part for part in path_parts if part)
    else:
        rel = file_path.relative_to(repo_root).with_suffix("")
        module_parts = [part for part in rel.parts if part != "__init__"]

    return ".".join(module_parts), is_package_module


def _module_package_parts(module_fqn: str, is_package_module: bool) -> tuple[str, ...]:
    parts = tuple(part for part in module_fqn.split(".") if part)
    if is_package_module:
        return parts
    return parts[:-1]


def _build_reexport_map(
    imports: Sequence[ImportFact],
    functions: Sequence[FunctionRecord],
    classes: Sequence[ClassRecord],
    assignments: Sequence[AssignmentFact],
    aliases: Sequence[AliasFact],
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
    project_modules: _ProjectModuleIndex | None = None,
) -> dict[str, str]:
    """Map package-level re-export FQNs to the imported original FQNs.

    *project_modules*, when supplied, suppresses any entry whose
    ``exported_fqn`` is itself a real project module or package path. A
    ``__init__.py`` line such as ``from .routes import auth`` rebinds the name
    ``auth`` in the package namespace to the ``routes.auth`` module — but when
    the package ALSO ships a real ``auth/`` subpackage, that subpackage's
    submodules (``pkg.auth.helpers``) are imported via the submodule path and
    must not be redirected by the name rebinding. Building the entry would let
    the prefix rewrite in :func:`_longest_reexport_match` clobber genuine
    ``pkg.auth.<sub>`` FQNs (FLAW-115).
    """
    module_by_init_file: dict[str, str] = {}
    for import_fact in imports:
        rel_path = import_fact.location.file
        if Path(rel_path).name != "__init__.py" or rel_path in module_by_init_file:
            continue
        module_by_init_file[rel_path] = _module_fqn_for_path(
            repo_root / rel_path, repo_root, namespace_roots
        )[0]

    definition_lines = _local_package_definition_lines(functions, classes)
    assignment_lines = _top_level_assignment_lines(assignments, classes, repo_root)
    reexports: dict[str, str] = {}
    for import_fact in imports:
        package_fqn = module_by_init_file.get(import_fact.location.file)
        if package_fqn is None or not import_fact.is_from_import:
            continue
        alias_by_name = dict(import_fact.aliases)
        for imported_name in import_fact.names:
            if imported_name == "*":
                continue
            exported_name = alias_by_name.get(imported_name, imported_name)
            exported_fqn = f"{package_fqn}.{exported_name}"
            original_fqn = (
                f"{import_fact.module}.{imported_name}" if import_fact.module else imported_name
            )
            if project_modules is not None and project_modules.path_exists(exported_fqn):
                # ``exported_fqn`` names a real project module/package: a
                # submodule import resolves there directly, so the name
                # rebinding must not redirect its FQN namespace.
                continue
            if _reexport_is_shadowed_by_later_definition(
                import_fact,
                exported_fqn,
                definition_lines,
            ) or _reexport_is_shadowed_by_later_assignment(
                import_fact,
                exported_fqn,
                exported_name,
                original_fqn,
                assignment_lines,
                aliases,
            ):
                continue
            if exported_fqn == original_fqn:
                continue
            # Reject self-embedding rewrites: when the target FQN starts
            # with the source as a prefix (e.g. ``pkg.db → pkg.db.db``),
            # repeated application grows the string unboundedly while
            # producing a distinct value each iteration — defeating
            # seen-set cycle detection.  This occurs in real-world code
            # when ``__init__.py`` re-exports a symbol whose name
            # matches a submodule: ``from pkg.db import db``.
            if original_fqn.startswith(f"{exported_fqn}."):
                continue
            reexports[exported_fqn] = original_fqn
    return reexports


def _build_static_dunder_all_exports(
    assignments: Sequence[AssignmentFact],
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> dict[str, tuple[str, ...]]:
    exports_by_module: dict[str, tuple[str, ...] | None] = {}

    for assignment in sorted(
        assignments,
        key=lambda item: (
            item.target_location.file,
            item.target_location.line,
            item.target_location.column,
        ),
    ):
        if assignment.containing_function_fqn is not None or assignment.target != "__all__":
            continue

        module_fqn = _module_fqn_for_path(
            repo_root / assignment.target_location.file, repo_root, namespace_roots
        )[0]
        exports_by_module[module_fqn] = _static_string_exports(assignment.value_expression)

    return {
        module_fqn: exports
        for module_fqn, exports in exports_by_module.items()
        if exports is not None
    }


def _static_string_exports(source: str) -> tuple[str, ...] | None:
    expression = _parse_expression_source(source)
    if not isinstance(expression, (cst.List, cst.Tuple)):
        return None

    exports: list[str] = []
    seen: set[str] = set()
    for element in expression.elements:
        if not isinstance(element, cst.Element) or not isinstance(
            element.value,
            cst.SimpleString,
        ):
            return None

        try:
            value = ast.literal_eval(element.value.value)
        except (SyntaxError, ValueError):
            return None
        if not isinstance(value, str) or not value.isidentifier():
            return None
        if value in seen:
            continue
        seen.add(value)
        exports.append(value)

    return tuple(exports)


def _apply_static_star_import_expansion(
    output: StructuralOutput,
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> StructuralOutput:
    exports_by_module = _build_static_dunder_all_exports(
        output.assignments, repo_root, namespace_roots
    )
    if not exports_by_module:
        return output

    expanded_aliases: list[AliasFact] = []
    expanded_imports: list[ImportFact] = []
    expanded_error_locations: set[tuple[str, int, int, str]] = set()

    for import_fact in output.imports:
        if (
            not import_fact.is_from_import
            or import_fact.names != ("*",)
            or import_fact.module not in exports_by_module
        ):
            continue

        exports = exports_by_module[import_fact.module]
        expanded_error_locations.add(
            (
                import_fact.location.file,
                import_fact.location.line,
                import_fact.location.column,
                import_fact.module,
            )
        )
        if not exports:
            continue

        expanded_imports.append(
            replace(
                import_fact,
                names=exports,
                aliases=(),
            )
        )
        expanded_aliases.extend(
            AliasFact(
                original_fqn=f"{import_fact.module}.{exported_name}",
                alias_name=exported_name,
                mechanism=AliasMechanism.WILDCARD_IMPORT,
                location=import_fact.location,
            )
            for exported_name in exports
        )

    if not expanded_error_locations:
        return output

    return replace(
        output,
        aliases=output.aliases + tuple(expanded_aliases),
        imports=output.imports + tuple(expanded_imports),
        errors=tuple(
            error
            for error in output.errors
            if not _is_expanded_star_import_gap(error, expanded_error_locations)
        ),
    )


def _is_expanded_star_import_gap(
    error: ExtractionError,
    expanded_error_locations: set[tuple[str, int, int, str]],
) -> bool:
    if (
        error.error_kind is not ErrorKind.RESOLUTION
        or error.location is None
        or "wildcard import" not in error.message
    ):
        return False

    return any(
        (
            error.location.file,
            error.location.line,
            error.location.column,
            module_fqn,
        )
        in expanded_error_locations
        and f"{module_fqn!r}" in error.message
        for module_fqn in {item[3] for item in expanded_error_locations}
    )


def _local_package_definition_lines(
    functions: Sequence[FunctionRecord],
    classes: Sequence[ClassRecord],
) -> dict[tuple[str, str], tuple[int, ...]]:
    lines_by_file_fqn: dict[tuple[str, str], list[int]] = {}
    for function in functions:
        if function.is_nested or function.is_method or Path(function.file).name != "__init__.py":
            continue
        lines_by_file_fqn.setdefault((function.file, function.fqn), []).append(
            function.location.line
        )
    for class_ in classes:
        if Path(class_.file).name != "__init__.py":
            continue
        lines_by_file_fqn.setdefault((class_.file, class_.fqn), []).append(class_.location.line)
    return {key: tuple(sorted(lines)) for key, lines in lines_by_file_fqn.items()}


def _reexport_is_shadowed_by_later_definition(
    import_fact: ImportFact,
    exported_fqn: str,
    definition_lines: dict[tuple[str, str], tuple[int, ...]],
) -> bool:
    return any(
        line > import_fact.location.line
        for line in definition_lines.get((import_fact.location.file, exported_fqn), ())
    )


def _reexport_is_shadowed_by_later_assignment(
    import_fact: ImportFact,
    exported_fqn: str,
    exported_name: str,
    original_fqn: str,
    assignment_lines: dict[tuple[str, str], tuple[int, ...]],
    aliases: Sequence[AliasFact],
) -> bool:
    return any(
        line > import_fact.location.line
        and not _assignment_preserves_import_binding(
            aliases,
            file=import_fact.location.file,
            line=line,
            local_name=exported_name,
            imported_fqn=original_fqn,
        )
        for line in assignment_lines.get((import_fact.location.file, exported_fqn), ())
    )


def _resolve_reexported_fqn(fqn: str | None, reexports: dict[str, str]) -> str | None:
    """Return *fqn* with the longest matching re-export prefix rewritten.

    Termination is guaranteed by two independent mechanisms:

    1. **Seen-set**: detects exact cycles (A -> B -> A).
    2. **Growth guard**: if a rewrite makes the string longer than
       ``initial_len + 500``, the rewriting system is divergent and we
       stop immediately.  This catches self-embedding entries that
       should have been filtered by ``_build_reexport_map`` but
       weren't.
    """
    if fqn is None or not reexports:
        return fqn

    current = fqn
    seen: set[str] = set()
    initial_len = len(fqn)
    while current not in seen:
        seen.add(current)
        match = _longest_reexport_match(current, reexports)
        if match is None:
            return current
        exported_fqn, original_fqn = match
        suffix = current[len(exported_fqn) :]
        candidate = f"{original_fqn}{suffix}"
        # Defense-in-depth: stop if the string grew beyond what any
        # legitimate chain could produce.
        if len(candidate) > initial_len + 500:
            return current
        current = candidate
    return current


def _longest_reexport_match(
    fqn: str,
    reexports: dict[str, str],
) -> tuple[str, str] | None:
    for exported_fqn in sorted(reexports, key=len, reverse=True):
        if fqn == exported_fqn or fqn.startswith(f"{exported_fqn}."):
            return exported_fqn, reexports[exported_fqn]
    return None


def _apply_reexport_resolution(
    output: StructuralOutput,
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> StructuralOutput:
    reexports = _build_reexport_map(
        output.imports,
        output.functions,
        output.classes,
        output.assignments,
        output.aliases,
        repo_root,
        namespace_roots,
        project_modules=_project_module_index_from_output(output, repo_root, namespace_roots),
    )
    if not reexports:
        return output

    return replace(
        output,
        functions=tuple(_rewrite_function_record(item, reexports) for item in output.functions),
        classes=tuple(_rewrite_class_record(item, reexports) for item in output.classes),
        decorators=tuple(_rewrite_decorator_fact(item, reexports) for item in output.decorators),
        call_edges=tuple(_rewrite_call_edge(item, reexports) for item in output.call_edges),
        aliases=tuple(_rewrite_alias_fact(item, reexports) for item in output.aliases),
        symbol_refs=tuple(_rewrite_symbol_ref(item, reexports) for item in output.symbol_refs),
    )


def _build_assignment_alias_map(
    output: StructuralOutput,
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> dict[str, str]:
    definition_lines = _top_level_definition_lines(output.functions, output.classes)
    assignment_lines = _top_level_assignment_lines(
        output.assignments,
        output.classes,
        repo_root,
        namespace_roots,
    )
    aliases: dict[str, str] = {}
    for fact in output.aliases:
        if fact.mechanism is not AliasMechanism.ASSIGNMENT_ALIAS:
            continue
        if _alias_is_inside_function_or_class(fact, output.functions, output.classes):
            continue
        module_fqn = _module_fqn_for_path(
            repo_root / fact.location.file, repo_root, namespace_roots
        )[0]
        alias_fqn = f"{module_fqn}.{fact.alias_name}"
        if (
            alias_fqn == fact.original_fqn
            or _assignment_alias_shadowed_by_later_definition(
                fact,
                definition_lines,
                repo_root,
                namespace_roots,
            )
            or _alias_shadowed_by_later_assignment(
                fact,
                assignment_lines,
                repo_root,
                namespace_roots,
            )
        ):
            continue
        aliases[alias_fqn] = fact.original_fqn
    return aliases


def _apply_assignment_alias_resolution(
    output: StructuralOutput,
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> StructuralOutput:
    aliases = _build_assignment_alias_map(output, repo_root, namespace_roots)
    definition_lines = _top_level_definition_lines(output.functions, output.classes)
    assignment_lines = _top_level_assignment_lines(
        output.assignments,
        output.classes,
        repo_root,
        namespace_roots,
    )
    output_aliases = tuple(
        fact
        for fact in output.aliases
        if _alias_is_inside_function_or_class(fact, output.functions, output.classes)
        or (
            not _assignment_alias_shadowed_by_later_definition(
                fact,
                definition_lines,
                repo_root,
                namespace_roots,
            )
            and not _alias_shadowed_by_later_assignment(
                fact, assignment_lines, repo_root, namespace_roots
            )
        )
    )
    if not aliases and output_aliases == output.aliases:
        return output

    return replace(
        output,
        functions=tuple(_rewrite_function_record(item, aliases) for item in output.functions),
        classes=tuple(_rewrite_class_record(item, aliases) for item in output.classes),
        decorators=tuple(_rewrite_decorator_fact(item, aliases) for item in output.decorators),
        call_edges=tuple(_rewrite_call_edge(item, aliases) for item in output.call_edges),
        aliases=tuple(_rewrite_alias_fact(item, aliases) for item in output_aliases),
        symbol_refs=tuple(_rewrite_symbol_ref(item, aliases) for item in output.symbol_refs),
    )


def _top_level_definition_lines(
    functions: Sequence[FunctionRecord],
    classes: Sequence[ClassRecord],
) -> dict[tuple[str, str], tuple[int, ...]]:
    lines_by_file_fqn: dict[tuple[str, str], list[int]] = {}
    for function in functions:
        if function.is_nested or function.is_method:
            continue
        lines_by_file_fqn.setdefault((function.file, function.fqn), []).append(
            function.location.line
        )
    for class_ in classes:
        if _class_is_nested(class_, functions, classes):
            continue
        lines_by_file_fqn.setdefault((class_.file, class_.fqn), []).append(class_.location.line)
    return {key: tuple(sorted(lines)) for key, lines in lines_by_file_fqn.items()}


def _top_level_assignment_lines(
    assignments: Sequence[AssignmentFact],
    classes: Sequence[ClassRecord],
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> dict[tuple[str, str], tuple[int, ...]]:
    classes_by_file: dict[str, list[ClassRecord]] = {}
    for class_ in classes:
        classes_by_file.setdefault(class_.file, []).append(class_)
    class_lookup = {file: tuple(file_classes) for file, file_classes in classes_by_file.items()}

    lines_by_file_fqn: dict[tuple[str, str], list[int]] = {}
    for assignment in assignments:
        target_names = _assignment_target_names_from_source(assignment.target)
        if (
            assignment.containing_function_fqn is not None
            or not target_names
            or _assignment_is_inside_class(assignment, class_lookup)
        ):
            continue
        module_fqn = _module_fqn_for_path(
            repo_root / assignment.target_location.file,
            repo_root,
            namespace_roots,
        )[0]
        for target_name in target_names:
            target_fqn = f"{module_fqn}.{target_name}"
            lines_by_file_fqn.setdefault(
                (assignment.target_location.file, target_fqn),
                [],
            ).append(assignment.target_location.line)
    return {key: tuple(sorted(lines)) for key, lines in lines_by_file_fqn.items()}


def _class_is_nested(
    class_: ClassRecord,
    functions: Sequence[FunctionRecord],
    classes: Sequence[ClassRecord],
) -> bool:
    return any(
        function.file == class_.file
        and function.location.line < class_.location.line <= function.location.end_line
        for function in functions
    ) or any(
        parent.file == class_.file
        and parent.location.line < class_.location.line <= parent.location.end_line
        for parent in classes
    )


def _line_is_inside_span(line: int, span: SourceSpan) -> bool:
    return span.line <= line <= span.end_line


def _alias_is_inside_function_or_class(
    fact: AliasFact,
    functions: Sequence[FunctionRecord],
    classes: Sequence[ClassRecord],
) -> bool:
    return any(
        function.file == fact.location.file
        and _line_is_inside_span(fact.location.line, function.location)
        for function in functions
    ) or any(
        class_.file == fact.location.file
        and _line_is_inside_span(fact.location.line, class_.location)
        for class_ in classes
    )


def _import_alias_shadowed_by_later_definition(
    fact: AliasFact,
    definition_lines: dict[tuple[str, str], tuple[int, ...]],
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> bool:
    if fact.mechanism is not AliasMechanism.IMPORT_ALIAS or not fact.alias_name.isidentifier():
        return False

    module_fqn = _module_fqn_for_path(repo_root / fact.location.file, repo_root, namespace_roots)[
        0
    ]
    alias_fqn = f"{module_fqn}.{fact.alias_name}"
    return any(
        line > fact.location.line
        for line in definition_lines.get((fact.location.file, alias_fqn), ())
    )


def _assignment_alias_shadowed_by_later_definition(
    fact: AliasFact,
    definition_lines: dict[tuple[str, str], tuple[int, ...]],
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> bool:
    if fact.mechanism is not AliasMechanism.ASSIGNMENT_ALIAS or not fact.alias_name.isidentifier():
        return False

    module_fqn = _module_fqn_for_path(repo_root / fact.location.file, repo_root, namespace_roots)[
        0
    ]
    alias_fqn = f"{module_fqn}.{fact.alias_name}"
    return any(
        line > fact.location.line
        for line in definition_lines.get((fact.location.file, alias_fqn), ())
    )


def _alias_shadowed_by_later_assignment(
    fact: AliasFact,
    assignment_lines: dict[tuple[str, str], tuple[int, ...]],
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> bool:
    if fact.mechanism not in {AliasMechanism.IMPORT_ALIAS, AliasMechanism.ASSIGNMENT_ALIAS}:
        return False
    if not fact.alias_name.isidentifier():
        return False

    module_fqn = _module_fqn_for_path(repo_root / fact.location.file, repo_root, namespace_roots)[
        0
    ]
    alias_fqn = f"{module_fqn}.{fact.alias_name}"
    return any(
        line > fact.location.line
        for line in assignment_lines.get((fact.location.file, alias_fqn), ())
    )


def _apply_import_alias_shadowing(
    output: StructuralOutput,
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> StructuralOutput:
    definition_lines = _top_level_definition_lines(output.functions, output.classes)
    assignment_lines = _top_level_assignment_lines(
        output.assignments,
        output.classes,
        repo_root,
        namespace_roots,
    )
    if not definition_lines and not assignment_lines:
        return output

    aliases = tuple(
        fact
        for fact in output.aliases
        if _alias_is_inside_function_or_class(fact, output.functions, output.classes)
        or (
            not _import_alias_shadowed_by_later_definition(
                fact, definition_lines, repo_root, namespace_roots
            )
            and not _alias_shadowed_by_later_assignment(
                fact, assignment_lines, repo_root, namespace_roots
            )
        )
    )
    if aliases == output.aliases:
        return output
    return replace(output, aliases=aliases)


def _build_import_alias_shadows(
    output: StructuralOutput,
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> tuple[_ImportAliasShadow, ...]:
    definition_lines = _top_level_definition_lines(output.functions, output.classes)
    assignment_lines = _top_level_assignment_lines(
        output.assignments,
        output.classes,
        repo_root,
        namespace_roots,
    )

    shadows: list[_ImportAliasShadow] = []
    for fact in output.aliases:
        if (
            fact.mechanism is not AliasMechanism.IMPORT_ALIAS
            or not fact.alias_name.isidentifier()
            or _alias_is_inside_function_or_class(fact, output.functions, output.classes)
        ):
            continue

        module_fqn = _module_fqn_for_path(
            repo_root / fact.location.file, repo_root, namespace_roots
        )[0]
        local_fqn = f"{module_fqn}.{fact.alias_name}"
        definition_shadow_lines = definition_lines.get((fact.location.file, local_fqn), ())
        assignment_shadow_lines = assignment_lines.get((fact.location.file, local_fqn), ())
        shadow_lines = [
            line
            for line in definition_shadow_lines + assignment_shadow_lines
            if line > fact.location.line
        ]
        rebind_line = _next_import_rebinding_line(
            output.imports,
            file=fact.location.file,
            local_name=fact.alias_name,
            after_line=fact.location.line,
            functions=output.functions,
            classes=output.classes,
        )
        stop_candidates = [(line, True) for line in shadow_lines]
        if rebind_line is not None:
            stop_candidates.append((rebind_line, False))
        end_line: int | None = None
        end_inclusive = False
        if stop_candidates:
            end_line = min(line for line, _ in stop_candidates)
            end_inclusive = any(
                inclusive for line, inclusive in stop_candidates if line == end_line
            )

        shadows.append(
            _ImportAliasShadow(
                file=fact.location.file,
                local_name=fact.alias_name,
                imported_fqn=fact.original_fqn,
                local_fqn=local_fqn,
                import_line=fact.location.line,
                end_line=end_line,
                end_inclusive=end_inclusive,
            )
        )

    return tuple(sorted(shadows, key=lambda item: (item.file, item.import_line, item.local_name)))


def _line_is_inside_import_alias_binding_range(
    line: int,
    shadow: _ImportAliasShadow,
) -> bool:
    if line <= shadow.import_line:
        return False
    if shadow.end_line is None:
        return True
    if line < shadow.end_line:
        return True
    return shadow.end_inclusive and line == shadow.end_line


def _restore_pre_shadowed_import_alias_fqn(
    fqn: str | None,
    *,
    file: str,
    line: int,
    shadows: Sequence[_ImportAliasShadow],
    allow_rebound_imported: bool = False,
) -> str | None:
    if fqn is None:
        return None

    for shadow in sorted(shadows, key=lambda item: len(item.local_fqn), reverse=True):
        if file != shadow.file or not _line_is_inside_import_alias_binding_range(line, shadow):
            continue
        if _fqn_matches_shadowed_import(fqn, shadow.local_fqn):
            suffix = fqn[len(shadow.local_fqn) :]
            return f"{shadow.imported_fqn}{suffix}"
        if allow_rebound_imported:
            rebound = _restore_rebound_import_alias_fqn(fqn, shadow, shadows)
            if rebound is not None:
                return rebound
    return fqn


def _restore_rebound_import_alias_fqn(
    fqn: str,
    shadow: _ImportAliasShadow,
    shadows: Sequence[_ImportAliasShadow],
) -> str | None:
    previous_imports = (
        previous
        for previous in shadows
        if previous.file == shadow.file
        and previous.local_name == shadow.local_name
        and previous.import_line < shadow.import_line
    )
    for previous in sorted(
        previous_imports, key=lambda item: len(item.imported_fqn), reverse=True
    ):
        if not _fqn_matches_shadowed_import(fqn, previous.imported_fqn):
            continue
        suffix = fqn[len(previous.imported_fqn) :]
        return f"{shadow.imported_fqn}{suffix}"
    return None


def _restore_symbol_ref_pre_shadowed_import_alias(
    ref: SymbolRef,
    shadows: Sequence[_ImportAliasShadow],
) -> SymbolRef:
    if not any(
        ref.location.file == shadow.file
        and _name_matches_shadowed_import(ref.name, shadow.local_name)
        for shadow in shadows
    ):
        return ref

    fqn = _restore_pre_shadowed_import_alias_fqn(
        ref.fqn,
        file=ref.location.file,
        line=ref.location.line,
        shadows=shadows,
        allow_rebound_imported=True,
    )
    if fqn == ref.fqn:
        return ref
    return replace(ref, fqn=fqn)


def _restore_decorator_pre_shadowed_import_alias(
    fact: DecoratorFact,
    shadows: Sequence[_ImportAliasShadow],
) -> DecoratorFact:
    if not any(
        fact.location.file == shadow.file
        and _name_matches_shadowed_import(fact.name, shadow.local_name)
        for shadow in shadows
    ):
        return fact

    fqn = _restore_pre_shadowed_import_alias_fqn(
        fact.fqn,
        file=fact.location.file,
        line=fact.location.line,
        shadows=shadows,
        allow_rebound_imported=True,
    )
    if fqn == fact.fqn:
        return fact
    return replace(fact, fqn=fqn)


def _restore_function_pre_shadowed_import_alias(
    record: FunctionRecord,
    shadows: Sequence[_ImportAliasShadow],
) -> FunctionRecord:
    decorator_fqns = tuple(
        _restore_pre_shadowed_import_alias_fqn(
            fqn,
            file=record.file,
            line=record.location.line,
            shadows=shadows,
            allow_rebound_imported=True,
        )
        if any(_name_matches_shadowed_import(name, shadow.local_name) for shadow in shadows)
        else fqn
        for name, fqn in zip(record.decorator_names, record.decorator_fqns, strict=True)
    )
    if decorator_fqns == record.decorator_fqns:
        return record
    return replace(record, decorator_fqns=decorator_fqns)


def _restore_class_pre_shadowed_import_alias(
    record: ClassRecord,
    shadows: Sequence[_ImportAliasShadow],
) -> ClassRecord:
    bases = tuple(
        _restore_pre_shadowed_import_alias_fqn(
            base,
            file=record.file,
            line=record.location.line,
            shadows=shadows,
            allow_rebound_imported=True,
        )
        or base
        for base in record.bases
    )
    if bases == record.bases:
        return record
    return replace(record, bases=bases)


def _assignment_value_matches_import_alias_shadow(
    fact: AliasFact,
    assignments: Sequence[AssignmentFact],
    shadow: _ImportAliasShadow,
) -> bool:
    return any(
        assignment.target_location.file == fact.location.file
        and assignment.target_location.line == fact.location.line
        and _line_is_inside_import_alias_binding_range(
            assignment.target_location.line,
            shadow,
        )
        and any(
            _name_matches_shadowed_import(value_expression, shadow.local_name)
            for value_expression in _assignment_value_expressions_for_target(
                assignment,
                fact.alias_name,
            )
        )
        for assignment in assignments
    )


def _restore_alias_fact_pre_shadowed_import_alias(
    fact: AliasFact,
    assignments: Sequence[AssignmentFact],
    shadows: Sequence[_ImportAliasShadow],
) -> AliasFact:
    for shadow in sorted(shadows, key=lambda item: len(item.local_fqn), reverse=True):
        if fact.location.file != shadow.file or not _assignment_value_matches_import_alias_shadow(
            fact, assignments, shadow
        ):
            continue
        original_fqn = _restore_pre_shadowed_import_alias_fqn(
            fact.original_fqn,
            file=fact.location.file,
            line=fact.location.line,
            shadows=(shadow,),
        )
        if original_fqn == fact.original_fqn:
            original_fqn = _restore_rebound_import_alias_fqn(
                fact.original_fqn,
                shadow,
                shadows,
            )
        if original_fqn is None or original_fqn == fact.original_fqn:
            continue
        return replace(fact, original_fqn=original_fqn)
    return fact


def _apply_import_alias_source_ordering(
    output: StructuralOutput,
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> StructuralOutput:
    shadows = _build_import_alias_shadows(output, repo_root, namespace_roots)
    if not shadows:
        return output

    symbol_refs: list[SymbolRef] = []
    symbol_rewrites: dict[tuple[str, int, int, str | None], str] = {}
    for ref in output.symbol_refs:
        rewritten = _restore_symbol_ref_pre_shadowed_import_alias(ref, shadows)
        symbol_refs.append(rewritten)
        if rewritten.fqn != ref.fqn and ref.fqn is not None and rewritten.fqn is not None:
            symbol_rewrites[
                (
                    ref.location.file,
                    ref.location.line,
                    ref.location.column,
                    ref.fqn,
                )
            ] = rewritten.fqn

    return replace(
        output,
        functions=tuple(
            _restore_function_pre_shadowed_import_alias(item, shadows) for item in output.functions
        ),
        classes=tuple(
            _restore_class_pre_shadowed_import_alias(item, shadows) for item in output.classes
        ),
        decorators=tuple(
            _restore_decorator_pre_shadowed_import_alias(item, shadows)
            for item in output.decorators
        ),
        call_edges=tuple(
            _rewrite_call_edge_from_import_shadow(item, symbol_rewrites)
            for item in output.call_edges
        ),
        aliases=tuple(
            _restore_alias_fact_pre_shadowed_import_alias(item, output.assignments, shadows)
            for item in output.aliases
        ),
        symbol_refs=tuple(symbol_refs),
    )


def _build_from_import_binding_ranges(
    output: StructuralOutput,
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> tuple[_ImportBindingRange, ...]:
    definition_lines = _top_level_definition_lines(output.functions, output.classes)
    assignment_lines = _top_level_assignment_lines(
        output.assignments,
        output.classes,
        repo_root,
        namespace_roots,
    )

    ranges: list[_ImportBindingRange] = []
    for import_fact in output.imports:
        if (
            not import_fact.is_from_import
            or not import_fact.module
            or _line_is_inside_function_or_class(
                import_fact.location.file,
                import_fact.location.line,
                output.functions,
                output.classes,
            )
        ):
            continue

        module_fqn = _module_fqn_for_path(
            repo_root / import_fact.location.file, repo_root, namespace_roots
        )[0]
        alias_by_name = dict(import_fact.aliases)
        for imported_name in import_fact.names:
            if imported_name == "*" or imported_name in alias_by_name:
                continue

            local_name = imported_name
            if not local_name.isidentifier():
                continue

            imported_fqn = f"{import_fact.module}.{imported_name}"
            local_fqn = f"{module_fqn}.{local_name}"
            if imported_fqn == local_fqn:
                continue

            shadow_lines = [
                line
                for line in definition_lines.get((import_fact.location.file, local_fqn), ())
                + tuple(
                    line
                    for line in assignment_lines.get(
                        (import_fact.location.file, local_fqn),
                        (),
                    )
                    if not _assignment_preserves_import_binding(
                        output.aliases,
                        file=import_fact.location.file,
                        line=line,
                        local_name=local_name,
                        imported_fqn=imported_fqn,
                    )
                )
                if line > import_fact.location.line
            ]
            rebind_line = _next_import_rebinding_line(
                output.imports,
                file=import_fact.location.file,
                local_name=local_name,
                after_line=import_fact.location.line,
                functions=output.functions,
                classes=output.classes,
            )

            stop_candidates = [(line, True) for line in shadow_lines]
            if rebind_line is not None:
                stop_candidates.append((rebind_line, False))
            end_line: int | None = None
            end_inclusive = False
            if stop_candidates:
                end_line = min(line for line, _ in stop_candidates)
                end_inclusive = any(
                    inclusive for line, inclusive in stop_candidates if line == end_line
                )

            ranges.append(
                _ImportBindingRange(
                    file=import_fact.location.file,
                    local_name=local_name,
                    imported_fqn=imported_fqn,
                    local_fqn=local_fqn,
                    import_line=import_fact.location.line,
                    end_line=end_line,
                    end_inclusive=end_inclusive,
                )
            )

    return tuple(sorted(ranges, key=lambda item: (item.file, item.import_line, item.local_name)))


def _line_is_inside_import_binding_range(
    line: int,
    binding: _ImportBindingRange,
) -> bool:
    if line <= binding.import_line:
        return False
    if binding.end_line is None:
        return True
    if line < binding.end_line:
        return True
    return binding.end_inclusive and line == binding.end_line


def _restore_from_import_binding_fqn(
    fqn: str | None,
    *,
    file: str,
    line: int,
    bindings: Sequence[_ImportBindingRange],
    binding_index: _ImportBindingSourceOrderIndex,
    allow_rebound_imported: bool = False,
) -> str | None:
    if fqn is None:
        return None

    for binding in bindings:
        if file != binding.file or not _line_is_inside_import_binding_range(line, binding):
            continue
        if _fqn_matches_shadowed_import(fqn, binding.local_fqn):
            suffix = fqn[len(binding.local_fqn) :]
            return f"{binding.imported_fqn}{suffix}"
        if allow_rebound_imported:
            rebound = _restore_rebound_from_import_binding_fqn(fqn, binding, binding_index)
            if rebound is not None:
                return rebound
    return fqn


def _restore_rebound_from_import_binding_fqn(
    fqn: str,
    binding: _ImportBindingRange,
    binding_index: _ImportBindingSourceOrderIndex,
) -> str | None:
    previous_bindings = (
        previous
        for previous in binding_index.previous_candidates_for(binding)
        if previous.import_line < binding.import_line
    )
    for previous in previous_bindings:
        if not _fqn_matches_shadowed_import(fqn, previous.imported_fqn):
            continue
        suffix = fqn[len(previous.imported_fqn) :]
        return f"{binding.imported_fqn}{suffix}"
    return None


def _restore_symbol_ref_from_import_binding(
    ref: SymbolRef,
    binding_index: _ImportBindingSourceOrderIndex,
) -> SymbolRef:
    bindings = binding_index.candidates_for_source_name(ref.location.file, ref.name)
    if not bindings:
        return ref

    fqn = (
        _resolve_unqualified_import_binding_fqn(
            ref.name,
            file=ref.location.file,
            line=ref.location.line,
            binding_index=binding_index,
        )
        if ref.fqn is None
        else _restore_from_import_binding_fqn(
            ref.fqn,
            file=ref.location.file,
            line=ref.location.line,
            bindings=bindings,
            binding_index=binding_index,
            allow_rebound_imported=True,
        )
    )
    if fqn == ref.fqn:
        return ref
    return replace(ref, fqn=fqn, resolution=ResolutionStatus.RESOLVED if fqn else ref.resolution)


def _resolve_unqualified_import_binding_fqn(
    name: str,
    *,
    file: str,
    line: int,
    binding_index: _ImportBindingSourceOrderIndex,
) -> str | None:
    for binding in binding_index.candidates_for_source_name(file, name):
        if (
            file != binding.file
            or not _line_is_inside_import_binding_range(line, binding)
            or not _name_matches_shadowed_import(name, binding.local_name)
        ):
            continue
        suffix = name[len(binding.local_name) :]
        return f"{binding.imported_fqn}{suffix}"
    return None


def _restore_decorator_from_import_binding(
    fact: DecoratorFact,
    binding_index: _ImportBindingSourceOrderIndex,
) -> DecoratorFact:
    bindings = binding_index.candidates_for_source_name(fact.location.file, fact.name)
    if not bindings:
        return fact

    fqn = _restore_from_import_binding_fqn(
        fact.fqn,
        file=fact.location.file,
        line=fact.location.line,
        bindings=bindings,
        binding_index=binding_index,
        allow_rebound_imported=True,
    )
    if fqn == fact.fqn:
        return fact
    return replace(fact, fqn=fqn)


def _restore_function_from_import_binding(
    record: FunctionRecord,
    binding_index: _ImportBindingSourceOrderIndex,
) -> FunctionRecord:
    decorator_fqns: list[str | None] = []
    for name, fqn in zip(record.decorator_names, record.decorator_fqns, strict=True):
        bindings = binding_index.candidates_for_source_name(record.file, name)
        if not bindings:
            decorator_fqns.append(fqn)
            continue
        decorator_fqns.append(
            _restore_from_import_binding_fqn(
                fqn,
                file=record.file,
                line=record.location.line,
                bindings=bindings,
                binding_index=binding_index,
                allow_rebound_imported=True,
            )
        )
    decorator_fqns_tuple = tuple(decorator_fqns)
    if decorator_fqns_tuple == record.decorator_fqns:
        return record
    return replace(record, decorator_fqns=decorator_fqns_tuple)


def _restore_class_from_import_binding(
    record: ClassRecord,
    binding_index: _ImportBindingSourceOrderIndex,
) -> ClassRecord:
    bindings = binding_index.candidates_for_file(record.file)
    bases = tuple(
        _restore_from_import_binding_fqn(
            base,
            file=record.file,
            line=record.location.line,
            bindings=bindings,
            binding_index=binding_index,
            allow_rebound_imported=True,
        )
        or base
        for base in record.bases
    )
    if bases == record.bases:
        return record
    return replace(record, bases=bases)


def _assignment_value_matches_from_import_binding(
    fact: AliasFact,
    assignment_values: _AssignmentValueIndex,
    binding: _ImportBindingRange,
) -> bool:
    return _line_is_inside_import_binding_range(
        fact.location.line,
        binding,
    ) and any(
        _name_matches_shadowed_import(value_expression, binding.local_name)
        for value_expression in assignment_values.value_expressions_for_target(
            file=fact.location.file,
            line=fact.location.line,
            target_name=fact.alias_name,
        )
    )


def _restore_alias_fact_from_import_binding(
    fact: AliasFact,
    assignment_values: _AssignmentValueIndex,
    binding_index: _ImportBindingSourceOrderIndex,
) -> AliasFact:
    if fact.mechanism is not AliasMechanism.ASSIGNMENT_ALIAS:
        return fact

    value_expressions = assignment_values.value_expressions_for_target(
        file=fact.location.file,
        line=fact.location.line,
        target_name=fact.alias_name,
    )
    candidate_bindings = tuple(
        binding
        for value_expression in value_expressions
        for binding in binding_index.candidates_for_source_name(
            fact.location.file, value_expression
        )
    )
    for binding in candidate_bindings:
        if fact.location.file != binding.file or not _assignment_value_matches_from_import_binding(
            fact,
            assignment_values,
            binding,
        ):
            continue

        original_fqn = _restore_from_import_binding_fqn(
            fact.original_fqn,
            file=fact.location.file,
            line=fact.location.line,
            bindings=binding_index.candidates_for_source_name(
                fact.location.file,
                binding.local_name,
            ),
            binding_index=binding_index,
            allow_rebound_imported=True,
        )
        if original_fqn is None or original_fqn == fact.original_fqn:
            continue
        return replace(fact, original_fqn=original_fqn)

    return fact


def _apply_from_import_binding_source_ordering(
    output: StructuralOutput,
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> StructuralOutput:
    bindings = _build_from_import_binding_ranges(output, repo_root, namespace_roots)
    if not bindings:
        return output
    binding_index = _ImportBindingSourceOrderIndex.build(bindings)
    assignment_values = _AssignmentValueIndex.build(output.assignments)

    symbol_refs: list[SymbolRef] = []
    symbol_rewrites: dict[tuple[str, int, int, str | None], str] = {}
    for ref in output.symbol_refs:
        rewritten = _restore_symbol_ref_from_import_binding(ref, binding_index)
        symbol_refs.append(rewritten)
        if rewritten.fqn != ref.fqn and rewritten.fqn is not None:
            symbol_rewrites[
                (
                    ref.location.file,
                    ref.location.line,
                    ref.location.column,
                    ref.fqn,
                )
            ] = rewritten.fqn

    return replace(
        output,
        functions=tuple(
            _restore_function_from_import_binding(item, binding_index) for item in output.functions
        ),
        classes=tuple(
            _restore_class_from_import_binding(item, binding_index) for item in output.classes
        ),
        decorators=tuple(
            _restore_decorator_from_import_binding(item, binding_index)
            for item in output.decorators
        ),
        call_edges=tuple(
            _rewrite_call_edge_from_import_shadow(item, symbol_rewrites)
            for item in output.call_edges
        ),
        aliases=tuple(
            _restore_alias_fact_from_import_binding(item, assignment_values, binding_index)
            for item in output.aliases
        ),
        symbol_refs=tuple(symbol_refs),
    )


def _build_from_import_shadows(
    output: StructuralOutput,
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> tuple[_FromImportShadow, ...]:
    definition_lines = _top_level_definition_lines(output.functions, output.classes)
    assignment_lines = _top_level_assignment_lines(
        output.assignments,
        output.classes,
        repo_root,
        namespace_roots,
    )

    shadows: list[_FromImportShadow] = []
    for import_fact in output.imports:
        if (
            not import_fact.is_from_import
            or not import_fact.module
            or _line_is_inside_function_or_class(
                import_fact.location.file,
                import_fact.location.line,
                output.functions,
                output.classes,
            )
        ):
            continue

        module_fqn = _module_fqn_for_path(
            repo_root / import_fact.location.file, repo_root, namespace_roots
        )[0]
        alias_by_name = dict(import_fact.aliases)
        for imported_name in import_fact.names:
            if imported_name == "*":
                continue
            local_name = alias_by_name.get(imported_name, imported_name)
            if not local_name.isidentifier():
                continue

            local_fqn = f"{module_fqn}.{local_name}"
            imported_fqn = f"{import_fact.module}.{imported_name}"
            if imported_fqn == local_fqn:
                continue

            definition_shadow_lines = definition_lines.get(
                (import_fact.location.file, local_fqn),
                (),
            )
            assignment_shadow_lines = tuple(
                line
                for line in assignment_lines.get((import_fact.location.file, local_fqn), ())
                if not _assignment_preserves_import_binding(
                    output.aliases,
                    file=import_fact.location.file,
                    line=line,
                    local_name=local_name,
                    imported_fqn=imported_fqn,
                )
            )
            shadow_lines = [
                line
                for line in definition_shadow_lines + assignment_shadow_lines
                if line > import_fact.location.line
            ]
            if not shadow_lines:
                continue
            shadow_line = min(shadow_lines)

            shadows.append(
                _FromImportShadow(
                    file=import_fact.location.file,
                    local_name=local_name,
                    imported_fqn=imported_fqn,
                    local_fqn=local_fqn,
                    shadow_line=shadow_line,
                    end_line=_next_import_rebinding_line(
                        output.imports,
                        file=import_fact.location.file,
                        local_name=local_name,
                        after_line=shadow_line,
                        functions=output.functions,
                        classes=output.classes,
                    ),
                )
            )

    return tuple(sorted(shadows, key=lambda item: (item.file, item.shadow_line, item.local_name)))


def _assignment_preserves_import_binding(
    aliases: Sequence[AliasFact],
    *,
    file: str,
    line: int,
    local_name: str,
    imported_fqn: str,
) -> bool:
    return any(
        alias.location.file == file
        and alias.location.line == line
        and alias.alias_name == local_name
        and _fqn_matches_shadowed_import(alias.original_fqn, imported_fqn)
        for alias in aliases
    )


def _line_is_inside_function_or_class(
    file: str,
    line: int,
    functions: Sequence[FunctionRecord],
    classes: Sequence[ClassRecord],
) -> bool:
    return any(
        function.file == file and _line_is_inside_span(line, function.location)
        for function in functions
    ) or any(
        class_.file == file and _line_is_inside_span(line, class_.location) for class_ in classes
    )


def _name_matches_shadowed_import(name: str, local_name: str) -> bool:
    return name == local_name or name.startswith(f"{local_name}.")


def _fqn_matches_shadowed_import(fqn: str | None, imported_fqn: str) -> bool:
    return fqn == imported_fqn or bool(fqn and fqn.startswith(f"{imported_fqn}."))


def _line_is_inside_import_shadow_range(line: int, shadow: _FromImportShadow) -> bool:
    return line > shadow.shadow_line and (shadow.end_line is None or line < shadow.end_line)


def _import_bound_names(import_fact: ImportFact) -> tuple[str, ...]:
    if import_fact.is_from_import:
        alias_by_name = dict(import_fact.aliases)
        return tuple(
            alias_by_name.get(imported_name, imported_name)
            for imported_name in import_fact.names
            if imported_name != "*"
        )

    alias_by_module = dict(import_fact.aliases)
    if import_fact.module in alias_by_module:
        return (alias_by_module[import_fact.module],)
    return (import_fact.module.split(".", maxsplit=1)[0],)


def _next_import_rebinding_line(
    imports: Sequence[ImportFact],
    *,
    file: str,
    local_name: str,
    after_line: int,
    functions: Sequence[FunctionRecord],
    classes: Sequence[ClassRecord],
) -> int | None:
    lines = [
        import_fact.location.line
        for import_fact in imports
        if import_fact.location.file == file
        and import_fact.location.line > after_line
        and not _line_is_inside_function_or_class(
            import_fact.location.file,
            import_fact.location.line,
            functions,
            classes,
        )
        and local_name in _import_bound_names(import_fact)
    ]
    return min(lines) if lines else None


def _resolve_from_import_shadowed_fqn(
    fqn: str | None,
    *,
    file: str,
    line: int,
    name: str,
    shadows: Sequence[_FromImportShadow],
) -> str | None:
    if fqn is None:
        return None
    for shadow in sorted(shadows, key=lambda item: len(item.imported_fqn), reverse=True):
        if (
            file != shadow.file
            or not _line_is_inside_import_shadow_range(line, shadow)
            or not _name_matches_shadowed_import(name, shadow.local_name)
            or not _fqn_matches_shadowed_import(fqn, shadow.imported_fqn)
        ):
            continue
        suffix = fqn[len(shadow.imported_fqn) :]
        return f"{shadow.local_fqn}{suffix}"
    return fqn


def _rewrite_symbol_ref_from_import_shadow(
    ref: SymbolRef,
    shadows: Sequence[_FromImportShadow],
) -> SymbolRef:
    fqn = _resolve_from_import_shadowed_fqn(
        ref.fqn,
        file=ref.location.file,
        line=ref.location.line,
        name=ref.name,
        shadows=shadows,
    )
    if fqn == ref.fqn:
        return ref
    return replace(ref, fqn=fqn)


def _rewrite_decorator_fact_from_import_shadow(
    fact: DecoratorFact,
    shadows: Sequence[_FromImportShadow],
) -> DecoratorFact:
    fqn = _resolve_from_import_shadowed_fqn(
        fact.fqn,
        file=fact.location.file,
        line=fact.location.line,
        name=fact.name,
        shadows=shadows,
    )
    if fqn == fact.fqn:
        return fact
    return replace(fact, fqn=fqn)


def _rewrite_function_record_from_import_shadow(
    record: FunctionRecord,
    shadows: Sequence[_FromImportShadow],
) -> FunctionRecord:
    decorator_fqns = tuple(
        _resolve_from_import_shadowed_fqn(
            fqn,
            file=record.file,
            line=record.location.line,
            name=name,
            shadows=shadows,
        )
        for name, fqn in zip(record.decorator_names, record.decorator_fqns, strict=True)
    )
    if decorator_fqns == record.decorator_fqns:
        return record
    return replace(record, decorator_fqns=decorator_fqns)


def _rewrite_class_record_from_import_shadow(
    record: ClassRecord,
    shadows: Sequence[_FromImportShadow],
) -> ClassRecord:
    bases: list[str] = []
    for base in record.bases:
        rewritten = base
        for shadow in sorted(shadows, key=lambda item: len(item.imported_fqn), reverse=True):
            if (
                record.file != shadow.file
                or not _line_is_inside_import_shadow_range(record.location.line, shadow)
                or not _fqn_matches_shadowed_import(base, shadow.imported_fqn)
            ):
                continue
            suffix = base[len(shadow.imported_fqn) :]
            rewritten = f"{shadow.local_fqn}{suffix}"
            break
        bases.append(rewritten)

    bases_tuple = tuple(bases)
    if bases_tuple == record.bases:
        return record
    return replace(record, bases=bases_tuple)


def _assignment_value_matches_shadowed_import(
    fact: AliasFact,
    assignments: Sequence[AssignmentFact],
    shadow: _FromImportShadow,
) -> bool:
    return any(
        assignment.target_location.file == fact.location.file
        and assignment.target_location.line == fact.location.line
        and _line_is_inside_import_shadow_range(assignment.target_location.line, shadow)
        and any(
            _name_matches_shadowed_import(value_expression, shadow.local_name)
            for value_expression in _assignment_value_expressions_for_target(
                assignment,
                fact.alias_name,
            )
        )
        for assignment in assignments
    )


def _rewrite_alias_fact_from_import_shadow(
    fact: AliasFact,
    assignments: Sequence[AssignmentFact],
    shadows: Sequence[_FromImportShadow],
) -> AliasFact:
    for shadow in sorted(shadows, key=lambda item: len(item.imported_fqn), reverse=True):
        if (
            fact.location.file != shadow.file
            or not _fqn_matches_shadowed_import(fact.original_fqn, shadow.imported_fqn)
            or not _assignment_value_matches_shadowed_import(fact, assignments, shadow)
        ):
            continue
        suffix = fact.original_fqn[len(shadow.imported_fqn) :]
        return replace(fact, original_fqn=f"{shadow.local_fqn}{suffix}")
    return fact


def _rewrite_call_edge_from_import_shadow(
    edge: CallEdge,
    symbol_rewrites: dict[tuple[str, int, int, str | None], str],
) -> CallEdge:
    fqn = symbol_rewrites.get(
        (
            edge.location.file,
            edge.location.line,
            edge.location.column,
            edge.callee_fqn,
        )
    )
    if fqn is None:
        return edge
    return replace(
        edge, callee_fqn=fqn, resolution=ResolutionStatus.RESOLVED, unresolved_reason=None
    )


def _apply_from_import_shadowing(
    output: StructuralOutput,
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> StructuralOutput:
    shadows = _build_from_import_shadows(output, repo_root, namespace_roots)
    if not shadows:
        return output

    symbol_refs: list[SymbolRef] = []
    symbol_rewrites: dict[tuple[str, int, int, str | None], str] = {}
    for ref in output.symbol_refs:
        rewritten = _rewrite_symbol_ref_from_import_shadow(ref, shadows)
        symbol_refs.append(rewritten)
        if rewritten.fqn != ref.fqn and ref.fqn is not None and rewritten.fqn is not None:
            symbol_rewrites[
                (
                    ref.location.file,
                    ref.location.line,
                    ref.location.column,
                    ref.fqn,
                )
            ] = rewritten.fqn

    return replace(
        output,
        functions=tuple(
            _rewrite_function_record_from_import_shadow(item, shadows) for item in output.functions
        ),
        classes=tuple(
            _rewrite_class_record_from_import_shadow(item, shadows) for item in output.classes
        ),
        decorators=tuple(
            _rewrite_decorator_fact_from_import_shadow(item, shadows) for item in output.decorators
        ),
        call_edges=tuple(
            _rewrite_call_edge_from_import_shadow(item, symbol_rewrites)
            for item in output.call_edges
        ),
        aliases=tuple(
            _rewrite_alias_fact_from_import_shadow(item, output.assignments, shadows)
            for item in output.aliases
        ),
        symbol_refs=tuple(symbol_refs),
    )


def _build_bare_import_shadows(
    output: StructuralOutput,
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> tuple[_FromImportShadow, ...]:
    definition_lines = _top_level_definition_lines(output.functions, output.classes)
    assignment_lines = _top_level_assignment_lines(
        output.assignments,
        output.classes,
        repo_root,
        namespace_roots,
    )

    shadows: list[_FromImportShadow] = []
    for import_fact in output.imports:
        if (
            import_fact.is_from_import
            or not import_fact.module
            or _line_is_inside_function_or_class(
                import_fact.location.file,
                import_fact.location.line,
                output.functions,
                output.classes,
            )
        ):
            continue

        local_name = import_fact.module.split(".", maxsplit=1)[0]
        if not local_name.isidentifier():
            continue

        module_fqn = _module_fqn_for_path(
            repo_root / import_fact.location.file, repo_root, namespace_roots
        )[0]
        imported_fqn = local_name
        local_fqn = f"{module_fqn}.{local_name}"
        if imported_fqn == local_fqn:
            continue

        definition_shadow_lines = definition_lines.get((import_fact.location.file, local_fqn), ())
        assignment_shadow_lines = tuple(
            line
            for line in assignment_lines.get((import_fact.location.file, local_fqn), ())
            if not _assignment_preserves_import_binding(
                output.aliases,
                file=import_fact.location.file,
                line=line,
                local_name=local_name,
                imported_fqn=imported_fqn,
            )
        )
        shadow_lines = [
            line
            for line in definition_shadow_lines + assignment_shadow_lines
            if line > import_fact.location.line
        ]
        if not shadow_lines:
            continue
        shadow_line = min(shadow_lines)

        shadows.append(
            _FromImportShadow(
                file=import_fact.location.file,
                local_name=local_name,
                imported_fqn=imported_fqn,
                local_fqn=local_fqn,
                shadow_line=shadow_line,
                end_line=_next_import_rebinding_line(
                    output.imports,
                    file=import_fact.location.file,
                    local_name=local_name,
                    after_line=shadow_line,
                    functions=output.functions,
                    classes=output.classes,
                ),
            )
        )

    return tuple(sorted(shadows, key=lambda item: (item.file, item.shadow_line, item.local_name)))


def _apply_bare_import_shadowing(
    output: StructuralOutput,
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> StructuralOutput:
    shadows = _build_bare_import_shadows(output, repo_root, namespace_roots)
    if not shadows:
        return output

    symbol_refs: list[SymbolRef] = []
    symbol_rewrites: dict[tuple[str, int, int, str | None], str] = {}
    for ref in output.symbol_refs:
        rewritten = _rewrite_symbol_ref_from_import_shadow(ref, shadows)
        symbol_refs.append(rewritten)
        if rewritten.fqn != ref.fqn and ref.fqn is not None and rewritten.fqn is not None:
            symbol_rewrites[
                (
                    ref.location.file,
                    ref.location.line,
                    ref.location.column,
                    ref.fqn,
                )
            ] = rewritten.fqn

    return replace(
        output,
        functions=tuple(
            _rewrite_function_record_from_import_shadow(item, shadows) for item in output.functions
        ),
        classes=tuple(
            _rewrite_class_record_from_import_shadow(item, shadows) for item in output.classes
        ),
        decorators=tuple(
            _rewrite_decorator_fact_from_import_shadow(item, shadows) for item in output.decorators
        ),
        call_edges=tuple(
            _rewrite_call_edge_from_import_shadow(item, symbol_rewrites)
            for item in output.call_edges
        ),
        aliases=tuple(
            _rewrite_alias_fact_from_import_shadow(item, output.assignments, shadows)
            for item in output.aliases
        ),
        symbol_refs=tuple(symbol_refs),
    )


def _rewrite_function_record(
    record: FunctionRecord,
    reexports: dict[str, str],
) -> FunctionRecord:
    decorator_fqns = tuple(
        _resolve_reexported_fqn(fqn, reexports) for fqn in record.decorator_fqns
    )
    if decorator_fqns == record.decorator_fqns:
        return record
    return replace(record, decorator_fqns=decorator_fqns)


def _rewrite_class_record(record: ClassRecord, reexports: dict[str, str]) -> ClassRecord:
    bases = tuple(_resolve_reexported_fqn(base, reexports) or base for base in record.bases)
    if bases == record.bases:
        return record
    return replace(record, bases=bases)


def _rewrite_decorator_fact(
    fact: DecoratorFact,
    reexports: dict[str, str],
) -> DecoratorFact:
    fqn = _resolve_reexported_fqn(fact.fqn, reexports)
    if fqn == fact.fqn:
        return fact
    return replace(fact, fqn=fqn)


def _rewrite_call_edge(edge: CallEdge, reexports: dict[str, str]) -> CallEdge:
    callee_fqn = _resolve_reexported_fqn(edge.callee_fqn, reexports)
    if callee_fqn == edge.callee_fqn:
        return edge
    return replace(edge, callee_fqn=callee_fqn)


def _rewrite_alias_fact(fact: AliasFact, reexports: dict[str, str]) -> AliasFact:
    original_fqn = _resolve_reexported_fqn(fact.original_fqn, reexports)
    if original_fqn is None:
        return fact
    if original_fqn == fact.original_fqn:
        return fact
    return replace(fact, original_fqn=original_fqn)


def _rewrite_symbol_ref(ref: SymbolRef, reexports: dict[str, str]) -> SymbolRef:
    fqn = _resolve_reexported_fqn(ref.fqn, reexports)
    if fqn == ref.fqn:
        return ref
    return replace(ref, fqn=fqn)


def _project_module_fqns(
    repo_root: Path,
    python_files: Sequence[Path],
    namespace_roots: frozenset[str] = frozenset(),
) -> frozenset[str]:
    modules: set[str] = set()
    for path in python_files:
        file_path = path if path.is_absolute() else repo_root / path
        modules.add(_module_fqn_for_path(file_path, repo_root, namespace_roots)[0])
    return frozenset(modules)


def _project_module_index_from_output(
    output: StructuralOutput,
    repo_root: Path,
    namespace_roots: frozenset[str] = frozenset(),
) -> _ProjectModuleIndex:
    """Build a module-membership index from the files present in *output*.

    Used where the canonical ``python_files`` list is not threaded in (the
    re-export resolution pass). Every fact carries its source file, so the set
    of module FQNs the repo defines is recoverable from the output alone.
    """
    files: set[str] = set()
    files.update(function.file for function in output.functions)
    files.update(class_.file for class_ in output.classes)
    files.update(import_fact.location.file for import_fact in output.imports)
    files.update(assignment.target_location.file for assignment in output.assignments)
    exact_modules = frozenset(
        _module_fqn_for_path(repo_root / file, repo_root, namespace_roots)[0] for file in files
    )
    return _ProjectModuleIndex.from_modules(exact_modules)


def _module_path_exists(module_fqn: str, project_modules: _ProjectModuleIndex) -> bool:
    return project_modules.path_exists(module_fqn)


def _is_project_local_module_path(module_fqn: str, project_modules: _ProjectModuleIndex) -> bool:
    return project_modules.is_project_local_module_path(module_fqn)


def _assignment_is_inside_class(
    assignment: AssignmentFact,
    classes_by_file: dict[str, tuple[ClassRecord, ...]],
) -> bool:
    return any(
        assignment.target_location.line >= class_.location.line
        and assignment.target_location.end_line <= class_.location.end_line
        for class_ in classes_by_file.get(assignment.target_location.file, ())
    )


def _project_member_fqns(
    output: StructuralOutput,
    repo_root: Path,
    project_modules: _ProjectModuleIndex,
    namespace_roots: frozenset[str] = frozenset(),
) -> frozenset[str]:
    members: set[str] = set(project_modules.exact_modules)
    members.update(
        function.fqn
        for function in output.functions
        if not function.is_method and not function.is_nested
    )
    members.update(class_.fqn for class_ in output.classes)

    classes_by_file: dict[str, list[ClassRecord]] = {}
    for class_ in output.classes:
        classes_by_file.setdefault(class_.file, []).append(class_)
    class_lookup = {file: tuple(classes) for file, classes in classes_by_file.items()}

    for assignment in output.assignments:
        target_names = _assignment_target_names_from_source(assignment.target)
        if (
            assignment.containing_function_fqn is not None
            or not target_names
            or _assignment_is_inside_class(assignment, class_lookup)
        ):
            continue
        module_fqn = _module_fqn_for_path(
            repo_root / assignment.target_location.file, repo_root, namespace_roots
        )[0]
        for target_name in target_names:
            members.add(f"{module_fqn}.{target_name}")

    members.update(
        _build_reexport_map(
            output.imports,
            output.functions,
            output.classes,
            output.assignments,
            output.aliases,
            repo_root,
            namespace_roots,
            project_modules=project_modules,
        )
    )
    return frozenset(members)


def _project_class_member_fqns(output: StructuralOutput) -> frozenset[str]:
    members: set[str] = set()
    for class_ in output.classes:
        for method_name in class_.method_names:
            members.add(f"{class_.fqn}.{method_name}")
        for class_var_name in class_.class_var_names:
            members.add(f"{class_.fqn}.{class_var_name}")

    for function in output.functions:
        if function.is_method and function.parent_class is not None:
            members.add(f"{function.parent_class}.{function.name}")

    return frozenset(members)


def _missing_project_import_modules(
    imports: Sequence[ImportFact],
    repo_root: Path,
    python_files: Sequence[Path],
    namespace_roots: frozenset[str] = frozenset(),
) -> tuple[frozenset[str], _ProjectModuleIndex, tuple[ExtractionError, ...]]:
    project_modules = _ProjectModuleIndex.build(repo_root, python_files, namespace_roots)
    missing_modules: set[str] = set()
    errors: list[ExtractionError] = []

    for import_fact in imports:
        module_fqn = import_fact.module
        if (
            not module_fqn
            or not _is_project_local_module_path(module_fqn, project_modules)
            or _module_path_exists(module_fqn, project_modules)
        ):
            continue

        missing_modules.add(module_fqn)
        errors.append(
            ExtractionError(
                file=import_fact.location.file,
                pass_name=_PASS_NAME,
                error_kind=ErrorKind.RESOLUTION,
                message=(
                    f"Cannot resolve project-local import module {module_fqn!r}; "
                    "no matching source module exists."
                ),
                is_fatal=False,
                location=import_fact.location,
            )
        )

    return frozenset(missing_modules), project_modules, tuple(errors)


def _missing_project_import_members(
    output: StructuralOutput,
    repo_root: Path,
    project_modules: _ProjectModuleIndex,
    missing_modules: frozenset[str],
    namespace_roots: frozenset[str] = frozenset(),
) -> tuple[frozenset[str], tuple[ExtractionError, ...]]:
    project_members = _project_member_fqns(output, repo_root, project_modules, namespace_roots)
    project_classes = frozenset(class_.fqn for class_ in output.classes)
    project_class_members = _project_class_member_fqns(output)
    missing_members: set[str] = set()
    errors: list[ExtractionError] = []

    for import_fact in output.imports:
        module_fqn = import_fact.module
        if (
            not import_fact.is_from_import
            or not module_fqn
            or not _is_project_local_module_path(module_fqn, project_modules)
            or module_fqn in missing_modules
            or not _module_path_exists(module_fqn, project_modules)
        ):
            continue

        for imported_name in import_fact.names:
            if imported_name == "*":
                continue
            imported_fqn = f"{module_fqn}.{imported_name}"
            if imported_fqn in project_members or _module_path_exists(
                imported_fqn,
                project_modules,
            ):
                continue

            missing_members.add(imported_fqn)
            errors.append(
                ExtractionError(
                    file=import_fact.location.file,
                    pass_name=_PASS_NAME,
                    error_kind=ErrorKind.RESOLUTION,
                    message=(
                        f"Cannot resolve project-local import member {imported_fqn!r}; "
                        f"{module_fqn!r} exists but no matching source module or top-level "
                        "member exists."
                    ),
                    is_fatal=False,
                    location=import_fact.location,
                )
            )

    imported_modules = _existing_project_imported_modules(
        output.imports,
        project_modules,
        missing_modules,
    )
    imported_module_index = _ImportedModuleValidationIndex(
        project_modules=project_modules,
        imported_modules=imported_modules,
        imported_modules_by_length=tuple(sorted(imported_modules, key=len, reverse=True)),
        project_classes=project_classes,
    )

    def record_missing_imported_member(fqn: str | None, location: SourceSpan) -> None:
        member_to_validate = _imported_module_member_to_validate(
            fqn,
            imported_module_index,
        )
        if member_to_validate is None:
            return
        imported_module, imported_member = member_to_validate
        if (
            imported_member in missing_members
            or imported_member in project_members
            or imported_member in project_class_members
            or _module_path_exists(imported_member, project_modules)
        ):
            return

        missing_members.add(imported_member)
        errors.append(
            ExtractionError(
                file=location.file,
                pass_name=_PASS_NAME,
                error_kind=ErrorKind.RESOLUTION,
                message=(
                    f"Cannot resolve project-local imported attribute member "
                    f"{imported_member!r}; {imported_module!r} exists but no matching "
                    "source module, top-level member, or class member exists."
                ),
                is_fatal=False,
                location=location,
            )
        )

    for alias in output.aliases:
        if alias.mechanism is not AliasMechanism.ASSIGNMENT_ALIAS:
            continue
        record_missing_imported_member(alias.original_fqn, alias.location)

    for ref in output.symbol_refs:
        record_missing_imported_member(ref.fqn, ref.location)

    for class_ in output.classes:
        for base in class_.bases:
            record_missing_imported_member(base, class_.location)

    for decorator in output.decorators:
        record_missing_imported_member(decorator.fqn, decorator.location)

    return frozenset(missing_members), tuple(errors)


def _existing_project_imported_modules(
    imports: Sequence[ImportFact],
    project_modules: _ProjectModuleIndex,
    missing_modules: frozenset[str],
) -> frozenset[str]:
    modules: set[str] = set()
    for import_fact in imports:
        module_fqn = import_fact.module
        if (
            not module_fqn
            or module_fqn in missing_modules
            or not _is_project_local_module_path(module_fqn, project_modules)
            or not _module_path_exists(module_fqn, project_modules)
        ):
            continue
        modules.add(module_fqn)
        if import_fact.is_from_import:
            for imported_name in import_fact.names:
                if imported_name == "*":
                    continue
                imported_module_fqn = f"{module_fqn}.{imported_name}"
                if _module_path_exists(imported_module_fqn, project_modules):
                    modules.add(imported_module_fqn)
    return frozenset(modules)


def _imported_module_member_to_validate(
    fqn: str | None,
    index: _ImportedModuleValidationIndex,
) -> tuple[str, str] | None:
    if fqn is None:
        return None

    for imported_module in index.imported_modules_by_length:
        prefix = f"{imported_module}."
        if not fqn.startswith(prefix):
            continue
        module_fqn = _deepest_project_module_prefix(
            fqn,
            imported_module=imported_module,
            project_modules=index.project_modules,
        )
        member_path = fqn[len(module_fqn) :].lstrip(".")
        if not member_path:
            continue
        member_parts = member_path.split(".")
        class_member = _project_class_member_to_validate(
            module_fqn,
            member_parts,
            index.project_classes,
        )
        if class_member is not None:
            return module_fqn, class_member
        return module_fqn, f"{module_fqn}.{member_parts[0]}"
    return None


def _project_class_member_to_validate(
    module_fqn: str,
    member_parts: Sequence[str],
    project_classes: frozenset[str],
) -> str | None:
    deepest_class: tuple[str, int] | None = None
    for part_count in range(1, len(member_parts) + 1):
        candidate = f"{module_fqn}.{'.'.join(member_parts[:part_count])}"
        if candidate in project_classes:
            deepest_class = candidate, part_count

    if deepest_class is None:
        return None

    class_fqn, class_part_count = deepest_class
    if class_part_count == len(member_parts):
        return class_fqn
    return f"{class_fqn}.{member_parts[class_part_count]}"


def _deepest_project_module_prefix(
    fqn: str,
    *,
    imported_module: str,
    project_modules: _ProjectModuleIndex,
) -> str:
    fqn_parts = fqn.split(".")
    imported_part_count = len(imported_module.split("."))
    deepest_module = imported_module
    for part_count in range(imported_part_count + 1, len(fqn_parts) + 1):
        candidate = ".".join(fqn_parts[:part_count])
        if _module_path_exists(candidate, project_modules):
            deepest_module = candidate
    return deepest_module


def _depends_on_unresolved_project_import(
    fqn: str | None,
    unresolved_imports: frozenset[str],
) -> bool:
    if fqn is None:
        return False
    return any(
        fqn == unresolved or fqn.startswith(f"{unresolved}.") for unresolved in unresolved_imports
    )


def _unresolve_project_import_fqn(
    fqn: str | None,
    unresolved_imports: frozenset[str],
) -> str | None:
    if _depends_on_unresolved_project_import(fqn, unresolved_imports):
        return None
    return fqn


def _rewrite_function_unresolved_imports(
    record: FunctionRecord,
    unresolved_imports: frozenset[str],
) -> FunctionRecord:
    decorator_fqns = tuple(
        _unresolve_project_import_fqn(fqn, unresolved_imports) for fqn in record.decorator_fqns
    )
    if decorator_fqns == record.decorator_fqns:
        return record
    return replace(record, decorator_fqns=decorator_fqns)


def _rewrite_class_unresolved_imports(
    record: ClassRecord,
    unresolved_imports: frozenset[str],
) -> ClassRecord:
    bases = tuple(
        base.rsplit(".", maxsplit=1)[-1]
        if _depends_on_unresolved_project_import(base, unresolved_imports)
        else base
        for base in record.bases
    )
    if bases == record.bases:
        return record
    return replace(record, bases=bases)


def _rewrite_decorator_unresolved_imports(
    fact: DecoratorFact,
    unresolved_imports: frozenset[str],
) -> DecoratorFact:
    fqn = _unresolve_project_import_fqn(fact.fqn, unresolved_imports)
    if fqn == fact.fqn:
        return fact
    return replace(fact, fqn=fqn)


def _rewrite_call_edge_unresolved_imports(
    edge: CallEdge,
    unresolved_imports: frozenset[str],
) -> CallEdge:
    callee_fqn = _unresolve_project_import_fqn(edge.callee_fqn, unresolved_imports)
    if callee_fqn == edge.callee_fqn:
        return edge
    return replace(
        edge,
        callee_fqn=callee_fqn,
        resolution=ResolutionStatus.UNRESOLVED,
        unresolved_reason="unresolved_project_import",
    )


def _rewrite_symbol_ref_unresolved_imports(
    ref: SymbolRef,
    unresolved_imports: frozenset[str],
) -> SymbolRef:
    fqn = _unresolve_project_import_fqn(ref.fqn, unresolved_imports)
    if fqn == ref.fqn:
        return ref
    return replace(ref, fqn=fqn, resolution=ResolutionStatus.UNRESOLVED)


def _apply_project_import_validation(
    output: StructuralOutput,
    repo_root: Path,
    python_files: Sequence[Path],
    namespace_roots: frozenset[str] = frozenset(),
) -> StructuralOutput:
    missing_modules, project_modules, module_errors = _missing_project_import_modules(
        output.imports,
        repo_root,
        python_files,
        namespace_roots,
    )
    missing_members, member_errors = _missing_project_import_members(
        output,
        repo_root,
        project_modules,
        missing_modules,
        namespace_roots,
    )
    unresolved_imports = missing_modules | missing_members
    if not unresolved_imports:
        return output

    return replace(
        output,
        functions=tuple(
            _rewrite_function_unresolved_imports(item, unresolved_imports)
            for item in output.functions
        ),
        classes=tuple(
            _rewrite_class_unresolved_imports(item, unresolved_imports) for item in output.classes
        ),
        decorators=tuple(
            _rewrite_decorator_unresolved_imports(item, unresolved_imports)
            for item in output.decorators
        ),
        call_edges=tuple(
            _rewrite_call_edge_unresolved_imports(item, unresolved_imports)
            for item in output.call_edges
        ),
        aliases=tuple(
            item
            for item in output.aliases
            if not _depends_on_unresolved_project_import(item.original_fqn, unresolved_imports)
        ),
        symbol_refs=tuple(
            _rewrite_symbol_ref_unresolved_imports(item, unresolved_imports)
            for item in output.symbol_refs
        ),
        errors=output.errors + module_errors + member_errors,
    )


def _apply_receiver_method_call_resolution(output: StructuralOutput) -> StructuralOutput:
    """Resolve receiver-relative method calls after class hierarchy enrichment."""
    if not output.classes or not output.functions or not output.call_edges:
        return output

    class_by_fqn = {class_.fqn: class_ for class_ in output.classes}
    function_by_fqn = {function.fqn: function for function in output.functions}

    call_edges = tuple(
        _resolve_receiver_call_edge(edge, function_by_fqn, class_by_fqn)
        for edge in output.call_edges
    )
    return replace(output, call_edges=call_edges)


def _resolve_receiver_call_edge(
    edge: CallEdge,
    function_by_fqn: dict[str, FunctionRecord],
    class_by_fqn: dict[str, ClassRecord],
) -> CallEdge:
    receiver_call = _receiver_call_from_placeholder(edge)
    if receiver_call is None:
        return edge

    receiver_name, method_name = receiver_call
    function = function_by_fqn.get(edge.caller_fqn)
    if function is None or function.parent_class is None:
        return _unresolved_receiver_edge(edge, _BOUND_RECEIVER_UNRESOLVED)

    return _resolve_receiver_call_for_function(
        edge,
        receiver_name,
        method_name,
        function,
        function.parent_class,
        class_by_fqn,
    )


def _resolve_receiver_call_for_function(
    edge: CallEdge,
    receiver_name: str,
    method_name: str | None,
    function: FunctionRecord,
    parent_class_fqn: str,
    class_by_fqn: dict[str, ClassRecord],
) -> CallEdge:
    class_ = class_by_fqn.get(parent_class_fqn)
    if class_ is None:
        return _unresolved_receiver_edge(edge, _RECEIVER_MRO_INCOMPLETE)

    if not _is_bound_receiver(function, receiver_name):
        return _unresolved_receiver_edge(edge, _BOUND_RECEIVER_UNRESOLVED)

    if method_name is None:
        return _unresolved_receiver_edge(edge, _RECEIVER_ATTRIBUTE_CHAIN)

    target = _resolve_method_in_mro(class_, method_name, class_by_fqn)
    if target is not None:
        return replace(
            edge,
            callee_fqn=target,
            resolution=ResolutionStatus.RESOLVED,
            unresolved_reason=None,
        )

    reason = _RECEIVER_MRO_INCOMPLETE if not class_.mro_complete else _RECEIVER_METHOD_MISSING
    return _unresolved_receiver_edge(edge, reason)


def _receiver_call_from_placeholder(edge: CallEdge) -> tuple[str, str | None] | None:
    if edge.callee_fqn is None:
        return None

    prefix = f"{edge.caller_fqn}.<locals>."
    if not edge.callee_fqn.startswith(prefix):
        return None

    parts = edge.callee_fqn.removeprefix(prefix).split(".")
    if not parts or parts[0] not in {"self", "cls"}:
        return None
    if len(parts) == 2:
        return (parts[0], parts[1])
    if len(parts) > 2:
        return (parts[0], None)
    return None


def _is_bound_receiver(function: FunctionRecord, receiver_name: str) -> bool:
    if receiver_name == "self":
        return _has_first_parameter(function, "self") and not _has_function_decorator(
            function,
            "staticmethod",
        )
    return (
        receiver_name == "cls"
        and _has_first_parameter(function, "cls")
        and _has_function_decorator(function, "classmethod")
    )


def _has_first_parameter(function: FunctionRecord, name: str) -> bool:
    return any(param.name == name and param.position == 0 for param in function.params)


def _has_function_decorator(function: FunctionRecord, decorator_name: str) -> bool:
    decorator_names = set(function.decorator_names)
    decorator_names.update(
        fqn.rsplit(".", maxsplit=1)[-1] for fqn in function.decorator_fqns if fqn is not None
    )
    return decorator_name in decorator_names


def _resolve_method_in_mro(
    class_: ClassRecord,
    method_name: str,
    class_by_fqn: dict[str, ClassRecord],
) -> str | None:
    for class_fqn in class_.mro_chain:
        mro_class = class_by_fqn.get(class_fqn)
        if mro_class is not None and method_name in mro_class.method_names:
            return f"{mro_class.fqn}.{method_name}"
    return None


def _unresolved_receiver_edge(edge: CallEdge, reason: str) -> CallEdge:
    return replace(
        edge,
        callee_fqn=None,
        resolution=ResolutionStatus.UNRESOLVED,
        unresolved_reason=reason,
    )


def _apply_super_call_resolution(output: StructuralOutput) -> StructuralOutput:
    """Resolve super().method() calls after class hierarchy enrichment."""
    if not output.call_edges:
        return output

    class_by_fqn = {class_.fqn: class_ for class_ in output.classes}
    function_by_fqn = {function.fqn: function for function in output.functions}

    call_edges = tuple(
        _resolve_super_call_edge(edge, function_by_fqn, class_by_fqn) for edge in output.call_edges
    )
    return replace(output, call_edges=call_edges)


def _resolve_super_call_edge(
    edge: CallEdge,
    function_by_fqn: dict[str, FunctionRecord],
    class_by_fqn: dict[str, ClassRecord],
) -> CallEdge:
    """Resolve a single super().method() call edge."""
    if edge.callee_fqn != "builtins.super":
        return edge

    method_name = _super_method_name(edge)
    if method_name is None:
        return edge  # Bare super() call — leave unchanged.

    reason = _super_call_unresolved_reason(edge, method_name, function_by_fqn, class_by_fqn)
    if reason is not None:
        return _unresolved_edge(edge, reason)

    function = function_by_fqn[edge.caller_fqn]
    parent_fqn = function.parent_class
    assert parent_fqn is not None  # Guaranteed by _super_call_unresolved_reason.
    class_ = class_by_fqn[parent_fqn]
    target = _resolve_super_method_in_mro(class_, method_name, class_by_fqn)
    return replace(
        edge,
        callee_fqn=target,
        resolution=ResolutionStatus.RESOLVED,
        unresolved_reason=None,
    )


def _super_call_unresolved_reason(
    edge: CallEdge,
    method_name: str,
    function_by_fqn: dict[str, FunctionRecord],
    class_by_fqn: dict[str, ClassRecord],
) -> str | None:
    """Return the unresolved reason for a super().method() call, or None if resolvable."""
    function = function_by_fqn.get(edge.caller_fqn)
    if function is None or not function.is_method or function.parent_class is None:
        return _SUPER_NOT_IN_METHOD

    class_ = class_by_fqn.get(function.parent_class)
    if class_ is None:
        return _SUPER_NO_PARENT_CLASS

    if not class_.mro_complete:
        return _SUPER_MRO_INCOMPLETE

    target = _resolve_super_method_in_mro(class_, method_name, class_by_fqn)
    if target is None:
        return _SUPER_METHOD_MISSING

    return None


def _super_method_name(edge: CallEdge) -> str | None:
    """Extract method name from a ``super().method`` call expression."""
    expr = edge.call_expression
    if expr is None:
        return None

    stripped = expr.strip()
    if not stripped.startswith(_SUPER_CALL_PREFIX):
        return None

    method = stripped[len(_SUPER_CALL_PREFIX) :].strip()
    if method.isidentifier():
        return method
    return None


def _resolve_super_method_in_mro(
    class_: ClassRecord,
    method_name: str,
    class_by_fqn: dict[str, ClassRecord],
) -> str | None:
    """Walk MRO starting AFTER the current class to find the method."""
    mro = class_.mro_chain
    if not mro:
        return None

    # Skip the current class (first in MRO) — super() starts from the next.
    for class_fqn in mro[1:]:
        mro_class = class_by_fqn.get(class_fqn)
        if mro_class is not None and method_name in mro_class.method_names:
            return f"{mro_class.fqn}.{method_name}"
    return None


def _unresolved_edge(edge: CallEdge, reason: str) -> CallEdge:
    """Mark a call edge as unresolved with a specific reason."""
    return replace(
        edge,
        callee_fqn=None,
        resolution=ResolutionStatus.UNRESOLVED,
        unresolved_reason=reason,
    )


def _apply_constructor_call_resolution(output: StructuralOutput) -> StructuralOutput:
    """Redirect constructor calls to __init__ when a project-local class has one."""
    if not output.classes or not output.call_edges:
        return output

    class_by_fqn = {class_.fqn: class_ for class_ in output.classes}

    call_edges = tuple(
        _resolve_constructor_call_edge(edge, class_by_fqn) for edge in output.call_edges
    )
    return replace(output, call_edges=call_edges)


def _resolve_constructor_call_edge(
    edge: CallEdge,
    class_by_fqn: dict[str, ClassRecord],
) -> CallEdge:
    """Redirect Class(...) to Class.__init__ when __init__ exists in MRO."""
    if edge.callee_fqn is None or edge.callee_fqn not in class_by_fqn:
        return edge

    class_ = class_by_fqn[edge.callee_fqn]
    init_target = _find_init_in_mro(class_, class_by_fqn)
    if init_target is not None:
        return replace(edge, callee_fqn=init_target)
    return edge


def _find_init_in_mro(
    class_: ClassRecord,
    class_by_fqn: dict[str, ClassRecord],
) -> str | None:
    """Find __init__ in the class's MRO chain."""
    for class_fqn in class_.mro_chain:
        mro_class = class_by_fqn.get(class_fqn)
        if mro_class is not None and "__init__" in mro_class.method_names:
            return f"{mro_class.fqn}.__init__"
    return None


# ── SQLAlchemy ORM query-chain resolution (FLAW-116) ──────────────────
#
# A method call like ``APIToken.query.filter_by(...).first()`` or
# ``db.session.query(M).filter(...).first()`` leaves L1 with a *textual*
# ``callee_fqn`` (e.g. ``app.APIToken.query.filter_by.first``) because the
# chain receiver's library type is never resolved. The SQLAlchemy provider's
# effect/propagator patterns key off the canonical library FQN
# (``sqlalchemy.orm.query.Query.first``), so they never fire and the ORM read
# produces no ``Db.read()`` effect — the root cause behind credential-derivation rules leaning on
# a source-string idiom fallback.
#
# This pass canonicalizes those chains by anchoring on a ``query`` opener whose
# receiver is *provably* a declarative model class (``<Model>.query``) or a
# session expression (``<db>.session``), plus bare ``<db>.session.<method>``
# calls. The receiver gating (real model classes / session roots derived from
# model bases) is what keeps this a structural type resolution, not a
# rule-side string heuristic: an unrelated ``foo.query.first`` or dict ``.get``
# is never rewritten because ``foo`` is not a known model/session.
_QUERY_FQN = "sqlalchemy.orm.query.Query"
_SESSION_FQN = "sqlalchemy.orm.session.Session"
_MODEL_BASE_SUFFIX = ".Model"

#: Methods on the 1.x ``Query`` object — chain (return Query) and terminal
#: (execute). The provider models the read/propagator subset; canonicalizing
#: the whole set is harmless and keeps flow propagation intact.
_QUERY_METHODS = frozenset(
    {
        # chain (return Query) — propagators
        "filter",
        "filter_by",
        "order_by",
        "group_by",
        "having",
        "join",
        "outerjoin",
        "limit",
        "offset",
        "distinct",
        "options",
        "with_entities",
        "from_self",
        "union",
        "union_all",
        "subquery",
        # terminal (execute) — effects
        "first",
        "all",
        "one",
        "one_or_none",
        "get",
        "count",
        "exists",
        "scalar",
        "update",
        "delete",
        # flask-sqlalchemy BaseQuery extras
        "first_or_404",
        "get_or_404",
        "one_or_404",
        "paginate",
    }
)

#: Methods invoked directly on a ``Session`` instance (``db.session.<m>``).
_SESSION_METHODS = frozenset(
    {
        "get",
        "get_one",
        "scalar",
        "scalars",
        "refresh",
        "add",
        "add_all",
        "merge",
        "delete",
        "flush",
        "commit",
        "rollback",
        "execute",
        "expire",
        "expunge",
        "bulk_save_objects",
        "bulk_insert_mappings",
        "bulk_update_mappings",
        "query",
    }
)

_DECLARATIVE_BASE_RE = re.compile(r"(?:\w+\.)*declarative_base\s*\(")
_DECLARATIVE_BASE_NAMES = frozenset({"DeclarativeBase"})


def _declarative_base_simple_names(output: StructuralOutput) -> frozenset[str]:
    """Module-level names bound to ``declarative_base(...)`` (e.g. ``Base``)."""
    return frozenset(
        assignment.target
        for assignment in output.assignments
        if assignment.containing_function_fqn is None
        and assignment.target.isidentifier()
        and _DECLARATIVE_BASE_RE.match(assignment.value_expression.strip())
    )


def _orm_model_fqns_and_session_roots(
    output: StructuralOutput,
) -> tuple[frozenset[str], frozenset[str]]:
    """Identify declarative-model class FQNs and SQLAlchemy session expressions.

    A class is a declarative model when it inherits from ``<db>.Model``
    (flask-sqlalchemy), a project-local ``declarative_base()`` result, or
    ``DeclarativeBase`` (SQLAlchemy 2.0). The flask-sqlalchemy ``db`` instance
    root is recovered directly from the ``<db>.Model`` base, which yields the
    ``<db>.session`` expression with no extra inference.
    """
    declarative_bases = _declarative_base_simple_names(output)
    model_fqns: set[str] = set()
    db_roots: set[str] = set()
    for class_ in output.classes:
        is_model = False
        for base in class_.bases:
            if base.endswith(_MODEL_BASE_SUFFIX):
                is_model = True
                db_roots.add(base[: -len(_MODEL_BASE_SUFFIX)])
            elif (
                base.rsplit(".", maxsplit=1)[-1] in declarative_bases
                or base.rsplit(".", maxsplit=1)[-1] in _DECLARATIVE_BASE_NAMES
            ):
                is_model = True
        if is_model:
            model_fqns.add(class_.fqn)
    session_exprs = frozenset(f"{root}.session" for root in db_roots)
    return frozenset(model_fqns), session_exprs


def _canonical_orm_callee_fqn(
    callee_fqn: str,
    model_fqns: frozenset[str],
    session_exprs: frozenset[str],
) -> str | None:
    """Map a textual ORM query/session chain to its canonical library FQN."""
    segments = callee_fqn.split(".")
    # Query chain: anchor on a ``query`` opener whose receiver is a known model
    # (descriptor form ``Model.query``) or session expression (``session.query``).
    for index in range(1, len(segments)):
        if segments[index] != "query":
            continue
        receiver = ".".join(segments[:index])
        if receiver not in model_fqns and receiver not in session_exprs:
            continue
        terminal = segments[-1]
        if index == len(segments) - 1:
            # Bare ``session.query`` call (the ``Model.query`` descriptor is an
            # attribute access and never produces its own call edge).
            return f"{_SESSION_FQN}.query" if receiver in session_exprs else None
        return f"{_QUERY_FQN}.{terminal}" if terminal in _QUERY_METHODS else None
    # Direct session method: ``<db>.session.<method>`` with no ``query`` opener.
    for session_expr in session_exprs:
        prefix = f"{session_expr}."
        if not callee_fqn.startswith(prefix):
            continue
        method = callee_fqn[len(prefix) :]
        if "." not in method and method in _SESSION_METHODS:
            return f"{_SESSION_FQN}.{method}"
    return None


def _dotted_attr_path(expression: str) -> tuple[str, tuple[str, ...]] | None:
    """Parse ``Root.attr.method(...).attr`` into ``(root_name, attr_path)``.

    Call argument groups are dropped so only the attribute spine remains, e.g.
    ``APIToken.query.filter_by(token_hash=h).first`` ->
    ``("APIToken", ("query", "filter_by", "first"))``. Returns ``None`` when the
    receiver root is not a bare name (e.g. a subscript or literal).
    """
    try:
        node: ast.expr = ast.parse(expression.strip(), mode="eval").body
    except (SyntaxError, ValueError):
        return None
    attrs: list[str] = []
    while True:
        if isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, ast.Attribute):
            attrs.append(node.attr)
            node = node.value
        else:
            break
    if not isinstance(node, ast.Name) or not attrs:
        return None
    return node.id, tuple(reversed(attrs))


def _file_import_bindings(output: StructuralOutput) -> dict[str, dict[str, str]]:
    """Map ``file -> {local_name: imported_fqn}`` for ``from X import Name`` forms.

    Only ``from``-imports bind a bare local name that can root an ORM query
    chain (``from app.models import Token`` -> ``Token`` -> ``app.models.Token``).
    """
    bindings: dict[str, dict[str, str]] = {}
    for imp in output.imports:
        if not imp.is_from_import or not imp.module:
            continue
        aliased = dict(imp.aliases)
        file_map = bindings.setdefault(imp.location.file, {})
        for name in imp.names:
            local = aliased.get(name, name)
            file_map[local] = f"{imp.module}.{name}"
    return bindings


def _canonical_orm_unresolved_edge(
    edge: CallEdge,
    model_fqns: frozenset[str],
    model_simple_names: frozenset[str],
    session_exprs: frozenset[str],
    import_bindings: dict[str, dict[str, str]],
) -> str | None:
    """Canonicalize an unresolved query chain via its imported receiver root."""
    if edge.call_expression is None:
        return None
    parsed = _dotted_attr_path(edge.call_expression)
    if parsed is None:
        return None
    root_name, attr_path = parsed
    # Precise path: resolve the imported root name to its declared FQN.
    root_fqn = import_bindings.get(edge.location.file, {}).get(root_name)
    if root_fqn is not None:
        canonical = _canonical_orm_callee_fqn(
            ".".join((root_fqn, *attr_path)), model_fqns, session_exprs
        )
        if canonical is not None:
            return canonical
    # Re-export fallback: ``from pkg import Model`` resolves the root to a
    # re-export alias (``pkg.Model``) that is not the declaring FQN. The root
    # name written at the call site is the model's simple class name, so a
    # ``<Model>.query.…`` descriptor chain is recognizable directly.
    if root_name in model_simple_names and attr_path and attr_path[0] == "query":
        terminal = attr_path[-1]
        if len(attr_path) > 1 and terminal in _QUERY_METHODS:
            return f"{_QUERY_FQN}.{terminal}"
    return None


def _orm_query_bound_vars(
    output: StructuralOutput,
    model_fqns: frozenset[str],
    model_simple_names: frozenset[str],
    import_bindings: dict[str, dict[str, str]],
) -> frozenset[tuple[str, str]]:
    """Local variables bound directly to a ``<Model>.query`` descriptor.

    Returns ``{(containing_function_fqn, variable_name)}`` for assignments of the
    form ``q = <Model>.query`` whose receiver is a provably declarative model
    (the same gating as the call-chain rewrite). Split-statement chains —
    ``q = Model.query`` then ``q.filter_by(...).first()``, idiomatic in real apps
    — otherwise resolve the chain off the local variable to a
    namespace-local pseudo-FQN, so the SQLAlchemy ``Query`` provider never fires
    and the ``Db.read`` is lost. Recovering the bound variable's type lets the
    chain canonicalize against the library ``Query`` FQN, matching what the
    single-expression form already resolves. Deeper bindings
    (``q = Model.query.filter_by(...)``) are intentionally left as honest gaps.
    """
    bound: set[tuple[str, str]] = set()
    for assignment in output.assignments:
        if assignment.containing_function_fqn is None or not assignment.target.isidentifier():
            continue
        parsed = _dotted_attr_path(assignment.value_expression)
        if parsed is None:
            continue
        root_name, attr_path = parsed
        if attr_path != ("query",):
            continue
        root_fqn = import_bindings.get(assignment.value_location.file, {}).get(root_name)
        is_model = (
            (root_fqn is not None and root_fqn in model_fqns)
            or root_name in model_simple_names
            or root_name in model_fqns
        )
        if is_model:
            bound.add((assignment.containing_function_fqn, assignment.target))
    return frozenset(bound)


def _canonical_orm_query_var_edge(
    edge: CallEdge,
    query_vars: frozenset[tuple[str, str]],
) -> str | None:
    """Canonicalize a query chain rooted on a local ``<Model>.query`` variable."""
    if edge.call_expression is None or not query_vars:
        return None
    parsed = _dotted_attr_path(edge.call_expression)
    if parsed is None:
        return None
    root_name, attr_path = parsed
    if (edge.caller_fqn, root_name) not in query_vars or not attr_path:
        return None
    terminal = attr_path[-1]
    return f"{_QUERY_FQN}.{terminal}" if terminal in _QUERY_METHODS else None


def _apply_orm_query_chain_resolution(output: StructuralOutput) -> StructuralOutput:
    """Canonicalize SQLAlchemy ORM query-chain call edges to library FQNs."""
    if not output.classes or not output.call_edges:
        return output

    model_fqns, session_exprs = _orm_model_fqns_and_session_roots(output)
    if not model_fqns and not session_exprs:
        return output

    model_simple_names = frozenset(fqn.rsplit(".", maxsplit=1)[-1] for fqn in model_fqns)
    import_bindings = _file_import_bindings(output)
    query_vars = _orm_query_bound_vars(output, model_fqns, model_simple_names, import_bindings)

    def _rewrite(edge: CallEdge) -> CallEdge:
        if edge.callee_fqn is not None:
            canonical = _canonical_orm_callee_fqn(edge.callee_fqn, model_fqns, session_exprs)
        else:
            # Cross-file chains on an imported model (``Token.query.…first()``)
            # leave L1 fully unresolved (the imported receiver's chain has no
            # resolvable callee). Recover the chain from the call expression by
            # resolving the imported root name to its declared FQN.
            canonical = _canonical_orm_unresolved_edge(
                edge, model_fqns, model_simple_names, session_exprs, import_bindings
            )
        if canonical is None:
            # Split-statement chains rooted on a ``q = Model.query`` variable
            # resolve to a namespace-local pseudo-FQN; recover them here.
            canonical = _canonical_orm_query_var_edge(edge, query_vars)
        if canonical is None or canonical == edge.callee_fqn:
            return edge
        return replace(
            edge,
            callee_fqn=canonical,
            resolution=ResolutionStatus.RESOLVED,
            unresolved_reason=None,
        )

    return replace(output, call_edges=tuple(_rewrite(edge) for edge in output.call_edges))


def _simple_unpack_values(
    node: cst.Tuple | cst.List,
) -> tuple[cst.BaseExpression, ...] | None:
    values: list[cst.BaseExpression] = []
    for element in node.elements:
        if not isinstance(element, cst.Element):
            return None
        values.append(element.value)
    return tuple(values)


def _assignment_target_names_from_source(target: str) -> tuple[str, ...]:
    if target.isidentifier():
        return (target,)

    target_expression = _parse_expression_source(target)
    if not isinstance(target_expression, (cst.Tuple, cst.List)):
        return ()

    target_values = _simple_unpack_values(target_expression)
    if target_values is None:
        return ()

    return tuple(value.value for value in target_values if isinstance(value, cst.Name))


def _assignment_value_expressions_for_target(
    assignment: AssignmentFact,
    target_name: str,
) -> tuple[str, ...]:
    if assignment.target == target_name:
        return (assignment.value_expression,)

    target_expression = _parse_expression_source(assignment.target)
    value_expression = _parse_expression_source(assignment.value_expression)
    if not isinstance(target_expression, (cst.Tuple, cst.List)) or not isinstance(
        value_expression,
        (cst.Tuple, cst.List),
    ):
        return ()

    target_values = _simple_unpack_values(target_expression)
    value_values = _simple_unpack_values(value_expression)
    if target_values is None or value_values is None or len(target_values) != len(value_values):
        return ()

    module = cst.Module(body=[])
    return tuple(
        module.code_for_node(value_value).strip()
        for target_value, value_value in zip(target_values, value_values, strict=True)
        if isinstance(target_value, cst.Name) and target_value.value == target_name
    )


def _parse_expression_source(source: str) -> cst.BaseExpression | None:
    try:
        return cst.parse_expression(source)
    except cst.ParserSyntaxError:
        return None
