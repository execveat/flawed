"""Step 3: Structural entity pass — extract functions, classes, decorators, calls,
attribute accesses, assignments, and imports from Python source files using LibCST.

Each source file is parsed independently.  Per-file failures are recorded as
``ExtractionError`` and never prevent extraction of other files.

FQN resolution uses LibCST's ``QualifiedNameProvider`` (in-file scope analysis).
Cross-file resolution and astroid inference are handled by later merge steps.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

import libcst as cst
from libcst.metadata import (
    MetadataWrapper,
    ParentNodeProvider,
    PositionProvider,
    QualifiedNameProvider,
    QualifiedNameSource,
)

from flawed._index._resolution import (
    _PASS_NAME,
    _apply_assignment_alias_resolution,
    _apply_bare_import_shadowing,
    _apply_constructor_call_resolution,
    _apply_from_import_binding_source_ordering,
    _apply_from_import_shadowing,
    _apply_import_alias_shadowing,
    _apply_import_alias_source_ordering,
    _apply_orm_query_chain_resolution,
    _apply_project_import_validation,
    _apply_receiver_method_call_resolution,
    _apply_reexport_resolution,
    _apply_static_star_import_expansion,
    _apply_super_call_resolution,
    _module_fqn_for_path,
    _module_package_parts,
    _namespace_package_roots_from_files,
    _provenance,
    _simple_unpack_values,
)
from flawed._index._spans import SpanInterner
from flawed._index._types import (
    AccessKind,
    AliasFact,
    AliasMechanism,
    AssignmentFact,
    AssignmentKind,
    AttributeAccess,
    CallArgument,
    CallEdge,
    ClassRecord,
    ComprehensionBindingFact,
    DecoratorFact,
    EdgeSource,
    ErrorKind,
    ExtractionError,
    FunctionKind,
    FunctionRecord,
    HierarchyGap,
    ImportFact,
    InheritedMethod,
    Parameter,
    ParameterKind,
    ResolutionStatus,
    ReturnFact,
    SourceSpan,
    SymbolRef,
    YieldFact,
)

if TYPE_CHECKING:
    from collections.abc import Callable, MutableMapping, Sequence
    from pathlib import Path

# ── Constants ─────────────────────────────────────────────────────────

_OBJECT_FQN = "builtins.object"
_OBJECT_BASES = frozenset({"object", _OBJECT_FQN})
_ABC_FQNS = frozenset({"abc.ABC", "ABC"})
_ABCMETA_FQNS = frozenset({"abc.ABCMeta", "ABCMeta"})
_ABSTRACTMETHOD_FQNS = frozenset({"abc.abstractmethod", "abstractmethod"})
_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        ".env",
        "env",
        "node_modules",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".eggs",
        "build",
        "dist",
        ".hatch",
    }
)
_CALL_MUTATOR_METHODS = frozenset(
    {
        "add",
        "append",
        "clear",
        "difference_update",
        "discard",
        "extend",
        "insert",
        "intersection_update",
        "pop",
        "popitem",
        "remove",
        "reverse",
        "setdefault",
        "sort",
        "symmetric_difference_update",
        "update",
    }
)
_DYNAMIC_DISPATCH_GETATTR = "getattr"
_DYNAMIC_DISPATCH_TABLE = "table"
_DYNAMIC_DISPATCH_IMPORTLIB = "importlib"
_DYNAMIC_DISPATCH_ENTRY_POINT = "entry_point"
_DYNAMIC_DISPATCH_PLUGGY_HOOK = "pluggy_hook"
_IMPORTLIB_IMPORT_FQNS = frozenset(
    {
        "importlib.import_module",
        "builtins.__import__",
        "__import__",
    }
)
_GETATTR_FQNS = frozenset({"builtins.getattr", "getattr"})
_ENTRY_POINT_LOAD_FQNS = frozenset(
    {
        "importlib.metadata.entry_points",
        "pkg_resources.iter_entry_points",
        "pkg_resources.load_entry_point",
    }
)


# ── Astroid brain registration ────────────────────────────────────────


def _ensure_astroid_brains_registered() -> None:
    """Register L1's custom astroid inference adapters for this process."""
    from flawed._index._brains import register

    register()


# ── Output container ──────────────────────────────────────────────────


@dataclass(frozen=True)
class StructuralOutput:
    """Aggregate output of the structural entity pass across all files."""

    functions: tuple[FunctionRecord, ...]
    classes: tuple[ClassRecord, ...]
    decorators: tuple[DecoratorFact, ...]
    call_edges: tuple[CallEdge, ...]
    attributes: tuple[AttributeAccess, ...]
    assignments: tuple[AssignmentFact, ...]
    comprehension_bindings: tuple[ComprehensionBindingFact, ...]
    returns: tuple[ReturnFact, ...]
    yields: tuple[YieldFact, ...]
    aliases: tuple[AliasFact, ...]
    imports: tuple[ImportFact, ...]
    symbol_refs: tuple[SymbolRef, ...]
    errors: tuple[ExtractionError, ...]


@dataclass(frozen=True)
class ParsedFile:
    """Parsed CST and metadata wrapper captured during structural extraction."""

    rel_path: str
    wrapper: MetadataWrapper
    span_interner: SpanInterner


@dataclass(frozen=True)
class _ExtractedFile:
    """Per-file structural output plus temporary parse state."""

    visitor: StructuralVisitor
    parsed_file: ParsedFile


# ── File discovery ────────────────────────────────────────────────────


def discover_python_files(repo_root: Path) -> tuple[Path, ...]:
    """Recursively find all ``.py`` files, excluding common non-source directories."""
    results: list[Path] = []
    for path in sorted(repo_root.rglob("*.py")):
        if any(part in _EXCLUDED_DIRS for part in path.relative_to(repo_root).parts):
            continue
        results.append(path)
    return tuple(results)


# ── SourceSpan helpers ────────────────────────────────────────────────


def _span(
    pos: cst.metadata.CodeRange,
    rel_path: str,
    span_interner: SpanInterner | None = None,
) -> SourceSpan:
    if span_interner is not None:
        return span_interner.intern(
            file=rel_path,
            line=pos.start.line,
            column=pos.start.column,
            end_line=pos.end.line,
            end_column=pos.end.column,
        )
    return SourceSpan(
        file=rel_path,
        line=pos.start.line,
        column=pos.start.column,
        end_line=pos.end.line,
        end_column=pos.end.column,
    )


# ── Node-to-source helper ────────────────────────────────────────────


def _src(module: cst.Module, node: cst.BaseExpression | cst.CSTNode) -> str:
    """Render a CST node back to source text, stripping whitespace."""
    return module.code_for_node(node).strip()


def _call_argument_source(module: cst.Module, args: Sequence[cst.Arg]) -> str | None:
    """Return a compact source representation of call arguments."""
    if not args:
        return None

    parts: list[str] = []
    for arg in args:
        value = _src(module, arg.value)
        if arg.keyword is not None:
            parts.append(f"{arg.keyword.value}={value}")
        else:
            parts.append(f"{arg.star}{value}")
    return ", ".join(parts)


def _call_edge_expression(
    module: cst.Module,
    node: cst.Call,
    dynamic_dispatch_kind: str | None,
) -> str:
    """Return the call expression payload for an AST-derived call edge.

    Most existing AST call edges store the callable expression (``app.route``)
    so higher layers can reconstruct the full call from structured arguments.
    For calls to a decorator returned by another call, such as
    ``limiter.limit("5/minute")(auth)``, the callable expression alone loses
    the outer target argument. Preserve the full two-stage expression while
    keeping dynamic-dispatch edges on their callable target.
    """
    if dynamic_dispatch_kind is None and isinstance(node.func, cst.Call):
        return _src(module, node)
    return _src(module, node.func)


def _apply_class_hierarchy(output: StructuralOutput) -> StructuralOutput:
    if not output.classes:
        return output

    class_by_fqn = {class_.fqn: class_ for class_ in output.classes}
    direct_subclasses = _direct_subclasses_by_base(output.classes, class_by_fqn)
    source_order = tuple(class_.fqn for class_ in output.classes)
    mro_cache: dict[str, tuple[str, ...]] = {}

    classes = tuple(
        _enrich_class_hierarchy(
            class_,
            class_by_fqn,
            direct_subclasses,
            source_order,
            mro_cache,
        )
        for class_ in output.classes
    )
    return replace(output, classes=classes)


def _enrich_class_hierarchy(
    class_: ClassRecord,
    class_by_fqn: dict[str, ClassRecord],
    direct_subclasses: dict[str, tuple[str, ...]],
    source_order: tuple[str, ...],
    mro_cache: dict[str, tuple[str, ...]],
) -> ClassRecord:
    mro_chain = _project_local_mro(class_.fqn, class_by_fqn, mro_cache, set())
    subclasses = direct_subclasses[class_.fqn]
    all_subclasses = _all_subclasses(class_.fqn, direct_subclasses, source_order)
    inherited_methods = _inherited_methods(class_, mro_chain, class_by_fqn)
    hierarchy_gaps = _hierarchy_gaps(class_, class_by_fqn)
    mro_complete = len(hierarchy_gaps) == 0
    is_abstract = class_.is_abstract or _is_abstract_from_bases(class_, class_by_fqn)
    return replace(
        class_,
        mro_chain=mro_chain,
        mro_complete=mro_complete,
        subclasses=subclasses,
        all_subclasses=all_subclasses,
        inherited_methods=inherited_methods,
        hierarchy_gaps=hierarchy_gaps,
        is_abstract=is_abstract,
    )


def _direct_subclasses_by_base(
    classes: tuple[ClassRecord, ...],
    class_by_fqn: dict[str, ClassRecord],
) -> dict[str, tuple[str, ...]]:
    direct: dict[str, list[str]] = {class_.fqn: [] for class_ in classes}
    for class_ in classes:
        seen_bases: set[str] = set()
        for base in class_.bases:
            normalized_base = _normalize_object_base(base)
            if normalized_base not in class_by_fqn or normalized_base in seen_bases:
                continue
            direct[normalized_base].append(class_.fqn)
            seen_bases.add(normalized_base)
    return {base_fqn: tuple(subclasses) for base_fqn, subclasses in direct.items()}


def _all_subclasses(
    class_fqn: str,
    direct_subclasses: dict[str, tuple[str, ...]],
    source_order: tuple[str, ...],
) -> tuple[str, ...]:
    reachable: set[str] = set()
    pending = list(direct_subclasses[class_fqn])
    while pending:
        subclass_fqn = pending.pop(0)
        if subclass_fqn in reachable:
            continue
        reachable.add(subclass_fqn)
        pending.extend(direct_subclasses[subclass_fqn])
    return tuple(fqn for fqn in source_order if fqn in reachable)


def _project_local_mro(
    class_fqn: str,
    class_by_fqn: dict[str, ClassRecord],
    mro_cache: dict[str, tuple[str, ...]],
    visiting: set[str],
) -> tuple[str, ...]:
    cached = mro_cache.get(class_fqn)
    if cached is not None:
        return cached

    if class_fqn in visiting:
        mro_cache[class_fqn] = (class_fqn,)
        return (class_fqn,)

    class_ = class_by_fqn[class_fqn]
    visiting.add(class_fqn)
    bases = tuple(_normalize_object_base(base) for base in class_.bases)
    mro_chain: tuple[str, ...]
    if not bases:
        mro_chain = (class_fqn, _OBJECT_FQN)
    elif any(base != _OBJECT_FQN and base not in class_by_fqn for base in bases):
        mro_chain = (class_fqn,)
    else:
        base_mros = tuple(
            (_OBJECT_FQN,)
            if base == _OBJECT_FQN
            else _project_local_mro(base, class_by_fqn, mro_cache, visiting)
            for base in bases
        )
        merged = _c3_merge((*base_mros, bases))
        mro_chain = (class_fqn,) if merged is None else (class_fqn, *merged)

    visiting.remove(class_fqn)
    mro_cache[class_fqn] = mro_chain
    return mro_chain


def _normalize_object_base(base: str) -> str:
    return _OBJECT_FQN if base in _OBJECT_BASES else base


def _c3_merge(sequences: tuple[tuple[str, ...], ...]) -> tuple[str, ...] | None:
    remaining = [list(sequence) for sequence in sequences if sequence]
    result: list[str] = []

    while remaining:
        candidate = _next_c3_candidate(remaining)
        if candidate is None:
            return None

        result.append(candidate)
        remaining = [
            [item for item in sequence if item != candidate]
            for sequence in remaining
            if any(item != candidate for item in sequence)
        ]

    return tuple(result)


def _next_c3_candidate(sequences: list[list[str]]) -> str | None:
    for sequence in sequences:
        candidate = sequence[0]
        if all(candidate not in other_sequence[1:] for other_sequence in sequences):
            return candidate
    return None


def _inherited_methods(
    class_: ClassRecord,
    mro_chain: tuple[str, ...],
    class_by_fqn: dict[str, ClassRecord],
) -> tuple[InheritedMethod, ...]:
    inherited: list[InheritedMethod] = []
    seen_methods = set(class_.method_names)

    for base_fqn in mro_chain[1:]:
        base = class_by_fqn.get(base_fqn)
        if base is None:
            continue
        for method_name in base.method_names:
            if method_name in seen_methods:
                continue
            seen_methods.add(method_name)
            inherited.append(
                InheritedMethod(
                    name=method_name,
                    defining_class_fqn=base.fqn,
                    resolution="mro",
                )
            )

    return tuple(inherited)


def _hierarchy_gaps(
    class_: ClassRecord,
    class_by_fqn: dict[str, ClassRecord],
) -> tuple[HierarchyGap, ...]:
    """Identify base classes that could not be resolved to project-local definitions."""
    gaps: list[HierarchyGap] = []
    for base in class_.bases:
        normalized = _normalize_object_base(base)
        if normalized == _OBJECT_FQN:
            continue
        if normalized in class_by_fqn:
            continue
        gaps.append(HierarchyGap(base_expression=base, reason="external"))
    return tuple(gaps)


def _is_abstract_from_bases(
    class_: ClassRecord,
    class_by_fqn: dict[str, ClassRecord],
) -> bool:
    """Detect abstractness from ABC in bases (complements source-level detection)."""
    for base in class_.bases:
        if base in _ABC_FQNS:
            return True
        base_record = class_by_fqn.get(base)
        if base_record is not None and base_record.is_abstract:
            continue  # Inherited abstractness doesn't make the subclass abstract
    return False


# ── Parameter extraction ──────────────────────────────────────────────


def _extract_params(
    params: cst.Parameters,
    module: cst.Module,
    rel_path: str,
    visitor: StructuralVisitor,
    span_interner: SpanInterner,
) -> tuple[Parameter, ...]:
    """Extract all parameters from a function signature."""
    result: list[Parameter] = []
    idx = 0

    def _add(
        param: cst.Param,
        kind: ParameterKind,
    ) -> None:
        nonlocal idx
        ann = _src(module, param.annotation.annotation) if param.annotation else None
        dflt = _src(module, param.default) if param.default else None
        try:
            pos = visitor.get_metadata(PositionProvider, param)
            loc = _span(pos, rel_path, span_interner)
        except Exception:
            loc = span_interner.intern(
                file=rel_path,
                line=0,
                column=0,
                end_line=0,
                end_column=0,
            )
        result.append(
            Parameter(
                name=param.name.value,
                annotation=ann,
                default=dflt,
                kind=kind,
                position=idx,
                location=loc,
            )
        )
        idx += 1

    for p in params.posonly_params:
        _add(p, ParameterKind.POSITIONAL_ONLY)
    for p in params.params:
        _add(p, ParameterKind.POSITIONAL_OR_KEYWORD)
    if isinstance(params.star_arg, cst.Param):
        _add(params.star_arg, ParameterKind.VAR_POSITIONAL)
    for p in params.kwonly_params:
        _add(p, ParameterKind.KEYWORD_ONLY)
    if params.star_kwarg is not None:
        _add(params.star_kwarg, ParameterKind.VAR_KEYWORD)
    return tuple(result)


# ── Decorator extraction helper ───────────────────────────────────────


def _extract_deco_info(
    deco_node: cst.Decorator,
    module: cst.Module,
    resolve_fqn: Callable[[cst.CSTNode], str | None],
) -> tuple[str, str | None, tuple[str, ...], tuple[tuple[str, str], ...]]:
    """Return (syntactic_name, resolved_fqn, pos_args, kwargs) for a decorator."""
    result = _extract_decorator_expression_info(
        deco_node.decorator,
        module,
        resolve_fqn,
        require_callable_shape=False,
    )
    if result is None:  # pragma: no cover - preserved for type narrowing.
        return _src(module, deco_node.decorator), None, (), ()
    return result


def _extract_decorator_expression_info(
    raw: cst.BaseExpression,
    module: cst.Module,
    resolve_fqn: Callable[[cst.CSTNode], str | None],
    *,
    require_callable_shape: bool,
) -> tuple[str, str | None, tuple[str, ...], tuple[tuple[str, str], ...]] | None:
    """Return decorator metadata for either ``@decorator`` or list elements.

    ``resolve_fqn`` is the visitor's qualified-name resolver
    (:meth:`StructuralVisitor._resolve_fqn`), injected so decorators go through
    the same normalization as call targets and other references. This matters
    for relative imports: LibCST's ``QualifiedNameProvider`` reports a decorator
    imported via ``from .. import bp`` / ``from ..auth.decorators import guard``
    with leading dots (``.bp.before_request``, ``..auth.decorators.guard``).
    Without normalization the FQN stayed mangled and never matched a lifecycle
    hook, so blueprint ``before_request`` guards silently dropped out of route
    stacks (FLAW-115).
    """
    if isinstance(raw, cst.Call):
        func_node = raw.func
        args = tuple(_src(module, a.value) for a in raw.args if a.keyword is None)
        kwargs = tuple(
            (a.keyword.value, _src(module, a.value)) for a in raw.args if a.keyword is not None
        )
    else:
        func_node = raw
        args = ()
        kwargs = ()

    if require_callable_shape and not _is_decorator_callable_expression(func_node):
        return None

    name = _src(module, func_node)
    return name, resolve_fqn(func_node), args, kwargs


def _is_decorator_callable_expression(expr: cst.BaseExpression) -> bool:
    """Return True for expression shapes that can name a decorator callable."""
    return isinstance(expr, (cst.Name, cst.Attribute))


def _class_decorator_attribute_value(
    stmt: cst.CSTNode,
) -> cst.BaseExpression | None:
    """Return ``decorators = [...]`` / annotated-assignment value from a class body."""
    if not isinstance(stmt, cst.SimpleStatementLine):
        return None

    for small_stmt in stmt.body:
        if isinstance(small_stmt, cst.Assign) and _assign_sets_simple_name(
            small_stmt,
            "decorators",
        ):
            return small_stmt.value
        if (
            isinstance(small_stmt, cst.AnnAssign)
            and isinstance(small_stmt.target, cst.Name)
            and small_stmt.target.value == "decorators"
            and small_stmt.value is not None
        ):
            return small_stmt.value
    return None


def _assign_sets_simple_name(node: cst.Assign, name: str) -> bool:
    """Return True when an assignment targets a simple name."""
    return any(
        isinstance(target.target, cst.Name) and target.target.value == name
        for target in node.targets
    )


def _attribute_root(expr: cst.BaseExpression) -> cst.BaseExpression:
    """Return the leftmost receiver expression in an attribute chain."""
    current = expr
    while isinstance(current, cst.Attribute):
        current = current.value
    return current


# ── Core visitor ──────────────────────────────────────────────────────


class StructuralVisitor(cst.CSTVisitor):
    """LibCST visitor that extracts structural entities from a single file."""

    METADATA_DEPENDENCIES = (
        QualifiedNameProvider,
        PositionProvider,
        ParentNodeProvider,
    )

    def __init__(
        self,
        module: cst.Module,
        rel_path: str,
        module_fqn: str,
        *,
        is_package_module: bool,
        span_interner: SpanInterner,
    ) -> None:
        self._module = module
        self._rel = rel_path
        self._span_interner = span_interner
        self._module_fqn = module_fqn
        self._package_parts = _module_package_parts(module_fqn, is_package_module)
        self._prov = _provenance(rel_path)

        # Collected records
        self.functions: list[FunctionRecord] = []
        self.classes: list[ClassRecord] = []
        self.decorators: list[DecoratorFact] = []
        self.call_edges: list[CallEdge] = []
        self.attributes: list[AttributeAccess] = []
        self.assignments: list[AssignmentFact] = []
        self.comprehension_bindings: list[ComprehensionBindingFact] = []
        self.returns: list[ReturnFact] = []
        self.yields: list[YieldFact] = []
        self.aliases: list[AliasFact] = []
        self.imports: list[ImportFact] = []
        self.symbol_refs: list[SymbolRef] = []
        self.errors: list[ExtractionError] = []

        # Scope tracking
        self._class_stack: list[str] = []
        self._func_stack: list[str] = []
        self._importlib_module_bindings_stack: list[set[str]] = [set()]
        self._conditional_import_depth: int = 0

    def _span(self, pos: cst.metadata.CodeRange) -> SourceSpan:
        return _span(pos, self._rel, self._span_interner)

    # ── Scope context ─────────────────────────────────────────────

    @property
    def _current_function_fqn(self) -> str | None:
        return self._func_stack[-1] if self._func_stack else None

    @property
    def _current_class_fqn(self) -> str | None:
        return self._class_stack[-1] if self._class_stack else None

    def _resolve_fqn(self, node: cst.CSTNode) -> str | None:
        try:
            qnames = self.get_metadata(QualifiedNameProvider, node)
            if qnames:
                qname = sorted(qnames, key=lambda item: item.name)[0]
                return self._normalize_qname(qname.name, qname.source)
        except (KeyError, StopIteration):
            pass
        return None

    def _normalize_qname(self, name: str, source: QualifiedNameSource) -> str:
        if name.startswith("."):
            return self._resolve_relative_name(name)
        if source is QualifiedNameSource.LOCAL:
            return self._module_qualified(name)
        return name

    def _module_qualified(self, name: str) -> str:
        if name == self._module_fqn or name.startswith(f"{self._module_fqn}."):
            return name
        return f"{self._module_fqn}.{name}"

    def _resolve_relative_name(self, name: str) -> str:
        level = len(name) - len(name.lstrip("."))
        tail = name[level:]
        return self._resolve_relative_module(tail, level)

    def _resolve_relative_module(self, module: str, level: int) -> str:
        if level == 0:
            return module
        keep = max(len(self._package_parts) - (level - 1), 0)
        parts = list(self._package_parts[:keep])
        if module:
            parts.extend(part for part in module.split(".") if part)
        return ".".join(parts)

    def _add_symbol_ref(self, name: str, fqn: str | None, node: cst.CSTNode) -> None:
        self.symbol_refs.append(
            SymbolRef(
                name=name,
                fqn=fqn,
                resolution=ResolutionStatus.RESOLVED if fqn else ResolutionStatus.UNRESOLVED,
                location=self._span(self._pos(node)),
                provenance=self._prov,
            )
        )

    def _pos(self, node: cst.CSTNode) -> cst.metadata.CodeRange:
        return self.get_metadata(PositionProvider, node)

    def _record_assignment_alias(
        self,
        target: cst.BaseAssignTargetExpression,
        value: cst.BaseExpression,
        location: SourceSpan,
    ) -> None:
        for alias_name, alias_value in _assignment_alias_pairs(target, value):
            resolved = self._resolve_fqn(alias_value)
            if not resolved:
                continue

            self.aliases.append(
                AliasFact(
                    original_fqn=resolved,
                    alias_name=alias_name,
                    mechanism=AliasMechanism.ASSIGNMENT_ALIAS,
                    location=location,
                )
            )

    def _record_importlib_module_binding(
        self,
        target: cst.BaseAssignTargetExpression,
        value: cst.BaseExpression,
    ) -> None:
        if not isinstance(target, cst.Name):
            return

        bindings = self._importlib_module_bindings_stack[-1]
        if self._is_importlib_import_module_call(value):
            bindings.add(target.value)
        else:
            bindings.discard(target.value)

    def _is_importlib_module_binding(self, name: str) -> bool:
        return name in self._importlib_module_bindings_stack[-1]

    def _is_importlib_import_module_call(self, expr: cst.BaseExpression) -> bool:
        return isinstance(expr, cst.Call) and self._call_callee_fqn(expr) in _IMPORTLIB_IMPORT_FQNS

    def _call_callee_fqn(self, call: cst.Call) -> str | None:
        return self._resolve_fqn(call.func) or self._resolve_fqn(call)

    def _dynamic_dispatch_kind(self, node: cst.Call) -> str | None:
        if self._is_getattr_dispatch_call(node.func):
            return _DYNAMIC_DISPATCH_GETATTR
        if self._is_table_dispatch_call(node.func):
            return _DYNAMIC_DISPATCH_TABLE
        if self._is_importlib_dispatch_call(node.func):
            return _DYNAMIC_DISPATCH_IMPORTLIB
        if self._is_entry_point_dispatch_call(node.func):
            return _DYNAMIC_DISPATCH_ENTRY_POINT
        if self._is_pluggy_hook_dispatch_call(node.func):
            return _DYNAMIC_DISPATCH_PLUGGY_HOOK
        return None

    def _is_getattr_dispatch_call(self, func: cst.BaseExpression) -> bool:
        if isinstance(func, cst.Call):
            return self._call_callee_fqn(func) in _GETATTR_FQNS
        if isinstance(func, cst.Attribute) and isinstance(func.value, cst.Call):
            return self._call_callee_fqn(func.value) in _GETATTR_FQNS
        return False

    def _is_table_dispatch_call(self, func: cst.BaseExpression) -> bool:
        if isinstance(func, cst.Subscript):
            return True
        if isinstance(func, cst.Attribute):
            return isinstance(_attribute_root(func.value), cst.Subscript)
        return False

    def _is_importlib_dispatch_call(self, func: cst.BaseExpression) -> bool:
        if not isinstance(func, cst.Attribute):
            return False

        value = func.value
        if isinstance(value, cst.Call):
            return self._is_importlib_import_module_call(value)

        root = _attribute_root(value)
        return isinstance(root, cst.Name) and self._is_importlib_module_binding(root.value)

    def _is_entry_point_dispatch_call(self, func: cst.BaseExpression) -> bool:
        if not isinstance(func, cst.Call):
            return False
        callee_fqn = self._call_callee_fqn(func)
        if callee_fqn in _ENTRY_POINT_LOAD_FQNS:
            return True
        if not isinstance(func.func, cst.Attribute) or func.func.attr.value != "load":
            return False
        return self._is_entry_point_object(func.func.value)

    def _is_entry_point_object(self, node: cst.BaseExpression) -> bool:
        if isinstance(node, cst.Call):
            callee = self._call_callee_fqn(node)
            return callee in _ENTRY_POINT_LOAD_FQNS
        if isinstance(node, cst.Subscript) and isinstance(node.value, cst.Call):
            return self._call_callee_fqn(node.value) in _ENTRY_POINT_LOAD_FQNS
        return False

    def _is_pluggy_hook_dispatch_call(self, func: cst.BaseExpression) -> bool:
        if not isinstance(func, cst.Attribute):
            return False
        parent = func.value
        return isinstance(parent, cst.Attribute) and parent.attr.value == "hook"

    def _record_subscript_setitem_call(
        self,
        target: cst.BaseAssignTargetExpression,
        value: cst.BaseExpression,
    ) -> None:
        if (
            not isinstance(target, cst.Subscript)
            or len(target.slice) != 1
            or not isinstance(target.slice[0], cst.SubscriptElement)
            or not isinstance(target.slice[0].slice, cst.Index)
        ):
            return

        key_node = target.slice[0].slice.value
        key_src = _src(self._module, key_node)
        value_src = _src(self._module, value)
        receiver_src = _src(self._module, target.value)
        callee_base = self._resolve_fqn(target.value) or receiver_src
        callee_fqn = f"{callee_base}.__setitem__"
        callee_expression = f"{receiver_src}.__setitem__({key_src}, {value_src})"
        target_pos = self._pos(target)

        self.call_edges.append(
            CallEdge(
                caller_fqn=self._current_function_fqn or "<module>",
                callee_fqn=callee_fqn,
                arguments=(
                    CallArgument(
                        position=0,
                        keyword=None,
                        expression=key_src,
                        location=self._span(self._pos(key_node)),
                    ),
                    CallArgument(
                        position=1,
                        keyword=None,
                        expression=value_src,
                        location=self._span(self._pos(value)),
                    ),
                ),
                resolution=ResolutionStatus.RESOLVED,
                source=EdgeSource.AST,
                unresolved_reason=None,
                location=self._span(target_pos),
                provenance=self._prov,
                call_expression=callee_expression,
            )
        )

    # ── Functions ─────────────────────────────────────────────────

    def visit_FunctionDef(self, node: cst.FunctionDef) -> bool | None:
        pos = self._pos(node)
        fqn = self._resolve_fqn(node) or node.name.value
        is_async = node.asynchronous is not None

        # Determine kind
        in_class = self._current_class_fqn is not None
        in_func = self._current_function_fqn is not None
        if in_class:
            kind = FunctionKind.METHOD
        elif in_func:
            kind = FunctionKind.NESTED
        else:
            kind = FunctionKind.TOP_LEVEL

        params = _extract_params(
            node.params,
            self._module,
            self._rel,
            self,
            self._span_interner,
        )

        # Decorator names and FQNs
        deco_names: list[str] = []
        deco_fqns: list[str | None] = []
        for i, d in enumerate(node.decorators):
            name, resolved_fqn, args, kwargs = _extract_deco_info(
                d,
                self._module,
                self._resolve_fqn,
            )
            deco_names.append(name)
            deco_fqns.append(resolved_fqn)
            deco_pos = self._pos(d)
            self.decorators.append(
                DecoratorFact(
                    name=name,
                    fqn=resolved_fqn,
                    args=args,
                    kwargs=kwargs,
                    target_fqn=fqn,
                    application_order=i,
                    location=self._span(deco_pos),
                    provenance=self._prov,
                )
            )

        self.functions.append(
            FunctionRecord(
                fqn=fqn,
                name=node.name.value,
                file=self._rel,
                line=pos.start.line,
                params=params,
                decorator_names=tuple(deco_names),
                decorator_fqns=tuple(deco_fqns),
                kind=kind,
                is_method=in_class,
                is_nested=in_func,
                is_async=is_async,
                parent_class=self._current_class_fqn,
                location=self._span(pos),
                provenance=self._prov,
                parent_function=self._current_function_fqn,
            )
        )

        self._func_stack.append(fqn)
        self._importlib_module_bindings_stack.append(set())
        return True  # visit children

    def leave_FunctionDef(self, node: cst.FunctionDef) -> None:
        if self._func_stack:
            self._func_stack.pop()
        if len(self._importlib_module_bindings_stack) > 1:
            self._importlib_module_bindings_stack.pop()

    def visit_Lambda(self, node: cst.Lambda) -> bool | None:
        pos = self._pos(node)
        name = self._lambda_name(node, pos)
        parent_function = self._current_function_fqn
        parent_class = self._current_class_fqn
        if parent_function is not None:
            fqn = f"{parent_function}.<locals>.{name}"
        elif parent_class is not None:
            fqn = f"{parent_class}.{name}"
        else:
            fqn = self._module_qualified(name)

        self.functions.append(
            FunctionRecord(
                fqn=fqn,
                name=name,
                file=self._rel,
                line=pos.start.line,
                params=_extract_params(
                    node.params,
                    self._module,
                    self._rel,
                    self,
                    self._span_interner,
                ),
                decorator_names=(),
                decorator_fqns=(),
                kind=FunctionKind.LAMBDA,
                is_method=False,
                is_nested=parent_function is not None,
                is_async=False,
                parent_class=parent_class,
                location=self._span(pos),
                provenance=self._prov,
                parent_function=parent_function,
            )
        )
        return True

    def _lambda_name(self, node: cst.Lambda, pos: cst.metadata.CodeRange) -> str:
        try:
            parent = self.get_metadata(ParentNodeProvider, node)
        except KeyError:
            parent = None

        if isinstance(parent, cst.Assign):
            target_name = _single_assignment_target_name(parent)
            if target_name is not None:
                return target_name
        if isinstance(parent, cst.AnnAssign) and isinstance(parent.target, cst.Name):
            return parent.target.value

        return f"<lambda_{pos.start.line}_{pos.start.column}>"

    # ── Classes ───────────────────────────────────────────────────

    def _extract_metaclass(self, node: cst.ClassDef) -> str | None:
        """Extract metaclass FQN from class keyword arguments."""
        for kw in node.keywords:
            if isinstance(kw.keyword, cst.Name) and kw.keyword.value == "metaclass":
                return self._resolve_fqn(kw.value) or _src(self._module, kw.value)
        return None

    def _has_abstractmethod(self, node: cst.ClassDef) -> bool:
        """Check if any method in the class body has an @abstractmethod decorator."""
        for stmt in node.body.body:
            if not isinstance(stmt, cst.FunctionDef):
                continue
            for d in stmt.decorators:
                deco_fqn = self._resolve_fqn(d.decorator)
                deco_name = _src(self._module, d.decorator)
                if (deco_fqn or deco_name) in _ABSTRACTMETHOD_FQNS:
                    return True
        return False

    def visit_ClassDef(self, node: cst.ClassDef) -> bool | None:
        pos = self._pos(node)
        fqn = self._resolve_fqn(node) or node.name.value

        # Base classes
        bases: list[str] = []
        for arg in node.bases:
            base_src = _src(self._module, arg.value)
            base_fqn = self._resolve_fqn(arg.value)
            bases.append(base_fqn or base_src)

        metaclass_raw = self._extract_metaclass(node)

        # Method names and class variables
        method_names: list[str] = []
        class_var_names: list[str] = []
        for stmt in node.body.body:
            if isinstance(stmt, cst.FunctionDef):
                method_names.append(stmt.name.value)
            elif isinstance(stmt, cst.SimpleStatementLine):
                for s in stmt.body:
                    if isinstance(s, (cst.Assign, cst.AnnAssign)):
                        class_var_names.extend(_assign_target_names(s))

        # Decorators
        for i, d in enumerate(node.decorators):
            name, resolved_fqn, args, kwargs = _extract_deco_info(
                d,
                self._module,
                self._resolve_fqn,
            )
            deco_pos = self._pos(d)
            self.decorators.append(
                DecoratorFact(
                    name=name,
                    fqn=resolved_fqn,
                    args=args,
                    kwargs=kwargs,
                    target_fqn=fqn,
                    application_order=i,
                    location=self._span(deco_pos),
                    provenance=self._prov,
                )
            )

        for value in (
            class_decorator_value
            for stmt in node.body.body
            if (class_decorator_value := _class_decorator_attribute_value(stmt)) is not None
        ):
            if not isinstance(value, (cst.List, cst.Tuple)):
                continue
            for i, element in enumerate(value.elements):
                if not isinstance(element, cst.Element):
                    continue
                info = _extract_decorator_expression_info(
                    element.value,
                    self._module,
                    self._resolve_fqn,
                    require_callable_shape=True,
                )
                if info is None:
                    continue
                name, resolved_fqn, args, kwargs = info
                deco_pos = self._pos(element.value)
                self.decorators.append(
                    DecoratorFact(
                        name=name,
                        fqn=resolved_fqn,
                        args=args,
                        kwargs=kwargs,
                        target_fqn=fqn,
                        application_order=i,
                        location=self._span(deco_pos),
                        provenance=self._prov,
                    )
                )

        # Abstract detection from metaclass and @abstractmethod (pre-hierarchy)
        is_abstract_from_source = self._has_abstractmethod(node) or (
            metaclass_raw is not None and metaclass_raw in _ABCMETA_FQNS
        )

        self.classes.append(
            ClassRecord(
                fqn=fqn,
                name=node.name.value,
                file=self._rel,
                bases=tuple(bases),
                mro_chain=(),
                mro_complete=False,
                method_names=tuple(method_names),
                class_var_names=tuple(class_var_names),
                is_abstract=is_abstract_from_source,
                metaclass=metaclass_raw,
                subclasses=(),
                all_subclasses=(),
                inherited_methods=(),
                hierarchy_gaps=(),
                location=self._span(pos),
                provenance=self._prov,
            )
        )

        self._class_stack.append(fqn)
        return True

    def leave_ClassDef(self, node: cst.ClassDef) -> None:
        if self._class_stack:
            self._class_stack.pop()

    # ── Calls (AST-derived call edges) ────────────────────────────

    def visit_Call(self, node: cst.Call) -> bool | None:
        dynamic_dispatch_kind = self._dynamic_dispatch_kind(node)
        callee_fqn = None if dynamic_dispatch_kind is not None else self._resolve_fqn(node.func)
        pos = self._pos(node)
        self._add_symbol_ref(_src(self._module, node.func), callee_fqn, node.func)

        # Extract arguments
        call_args: list[CallArgument] = []
        positional_idx = 0
        for a in node.args:
            arg_pos = self._pos(a)
            if a.keyword is not None:
                call_args.append(
                    CallArgument(
                        position=None,
                        keyword=a.keyword.value,
                        expression=_src(self._module, a.value),
                        location=self._span(arg_pos),
                    )
                )
            else:
                call_args.append(
                    CallArgument(
                        position=positional_idx,
                        keyword=None,
                        expression=_src(self._module, a.value),
                        location=self._span(arg_pos),
                    )
                )
                positional_idx += 1

        # Method-call receiver (``x`` in ``x.lower()``): the value the call is
        # invoked on.  Captured here from the CST so ``CallSite.receiver``
        # (FLAW-187) can hand rule authors a provenance handle for the subject
        # of a transform.  ``None`` for plain function calls.
        receiver_node = node.func.value if isinstance(node.func, cst.Attribute) else None

        caller_fqn = self._current_function_fqn or "<module>"
        resolution = ResolutionStatus.RESOLVED if callee_fqn else ResolutionStatus.UNRESOLVED
        unresolved_reason = (
            f"dynamic_dispatch_{dynamic_dispatch_kind}"
            if dynamic_dispatch_kind is not None
            else "no_qualified_name"
            if not callee_fqn
            else None
        )

        self.call_edges.append(
            CallEdge(
                caller_fqn=caller_fqn,
                callee_fqn=callee_fqn,
                arguments=tuple(call_args),
                resolution=resolution,
                source=EdgeSource.AST,
                unresolved_reason=unresolved_reason,
                location=self._span(pos),
                provenance=self._prov,
                call_expression=_call_edge_expression(
                    self._module,
                    node,
                    dynamic_dispatch_kind,
                ),
                dynamic_dispatch_kind=dynamic_dispatch_kind,
                receiver_expression=(
                    _src(self._module, receiver_node) if receiver_node is not None else None
                ),
                receiver_location=(
                    self._span(self._pos(receiver_node)) if receiver_node is not None else None
                ),
            )
        )

        if isinstance(node.func, cst.Attribute) and node.func.attr.value in _CALL_MUTATOR_METHODS:
            self.attributes.append(
                AttributeAccess(
                    target_expr=_src(self._module, node.func.value),
                    attr_name=node.func.attr.value,
                    is_write=True,
                    access_kind=AccessKind.CALL_MUTATOR,
                    value_expr=_call_argument_source(self._module, node.args),
                    containing_function_fqn=self._current_function_fqn,
                    location=self._span(pos),
                    provenance=self._prov,
                )
            )
        return True

    # ── Attribute accesses ────────────────────────────────────────

    def visit_Attribute(self, node: cst.Attribute) -> bool | None:
        pos = self._pos(node)
        parent = self.get_metadata(ParentNodeProvider, node)

        is_write = isinstance(parent, cst.AssignTarget)
        access_kind = AccessKind.ATTR
        value_expr: str | None = None

        if is_write:
            # Try to get the value from the parent Assign
            try:
                grandparent = self.get_metadata(ParentNodeProvider, parent)
                if isinstance(grandparent, cst.Assign):
                    value_expr = _src(self._module, grandparent.value)
            except KeyError:
                pass

        self.attributes.append(
            AttributeAccess(
                target_expr=_src(self._module, node.value),
                attr_name=node.attr.value,
                is_write=is_write,
                access_kind=access_kind,
                value_expr=value_expr,
                containing_function_fqn=self._current_function_fqn,
                location=self._span(pos),
                provenance=self._prov,
            )
        )
        return True

    # ── Subscript accesses ───────────────────────────────────────

    def visit_Subscript(self, node: cst.Subscript) -> bool | None:
        # Only track simple single-element subscripts like obj[key]
        if len(node.slice) != 1:
            return True
        slice_item = node.slice[0]
        if not isinstance(slice_item, cst.SubscriptElement):
            return True
        if isinstance(slice_item.slice, cst.Index):
            key_node = slice_item.slice.value
        else:
            return True  # skip slices like obj[1:2]

        pos = self._pos(node)
        parent = self.get_metadata(ParentNodeProvider, node)

        is_write = isinstance(parent, cst.AssignTarget)
        value_expr: str | None = None

        if is_write:
            try:
                grandparent = self.get_metadata(ParentNodeProvider, parent)
                if isinstance(grandparent, cst.Assign):
                    value_expr = _src(self._module, grandparent.value)
            except KeyError:
                pass

        self.attributes.append(
            AttributeAccess(
                target_expr=_src(self._module, node.value),
                attr_name=_src(self._module, key_node),
                is_write=is_write,
                access_kind=AccessKind.SUBSCRIPT,
                value_expr=value_expr,
                containing_function_fqn=self._current_function_fqn,
                location=self._span(pos),
                provenance=self._prov,
            )
        )
        return True

    # ── Delete tracking ──────────────────────────────────────────

    def visit_Del(self, node: cst.Del) -> bool | None:
        target = node.target
        pos = self._pos(node)

        if isinstance(target, cst.Attribute):
            self.attributes.append(
                AttributeAccess(
                    target_expr=_src(self._module, target.value),
                    attr_name=target.attr.value,
                    is_write=True,
                    access_kind=AccessKind.DEL,
                    value_expr=None,
                    containing_function_fqn=self._current_function_fqn,
                    location=self._span(pos),
                    provenance=self._prov,
                )
            )
        elif (
            isinstance(target, cst.Subscript)
            and len(target.slice) == 1
            and isinstance(target.slice[0], cst.SubscriptElement)
            and isinstance(target.slice[0].slice, cst.Index)
        ):
            self.attributes.append(
                AttributeAccess(
                    target_expr=_src(self._module, target.value),
                    attr_name=_src(self._module, target.slice[0].slice.value),
                    is_write=True,
                    access_kind=AccessKind.DEL,
                    value_expr=None,
                    containing_function_fqn=self._current_function_fqn,
                    location=self._span(pos),
                    provenance=self._prov,
                )
            )
        return True

    # ── Assignments ───────────────────────────────────────────────

    def visit_Assign(self, node: cst.Assign) -> bool | None:
        pos = self._pos(node)
        val_src = _src(self._module, node.value)
        val_pos = self._pos(node.value)

        for target in node.targets:
            tgt_src = _src(self._module, target.target)
            tgt_pos = self._pos(target.target)
            is_unpacking = isinstance(target.target, (cst.Tuple, cst.List))
            self._record_importlib_module_binding(target.target, node.value)
            self.assignments.append(
                AssignmentFact(
                    target=tgt_src,
                    target_location=self._span(tgt_pos),
                    value_expression=val_src,
                    value_location=self._span(val_pos),
                    kind=AssignmentKind.UNPACKING if is_unpacking else AssignmentKind.SIMPLE,
                    containing_function_fqn=self._current_function_fqn,
                )
            )
            self._record_assignment_alias(
                target.target,
                node.value,
                self._span(pos),
            )
            self._record_subscript_setitem_call(target.target, node.value)

        return True

    def visit_AugAssign(self, node: cst.AugAssign) -> bool | None:
        tgt_src = _src(self._module, node.target)
        tgt_pos = self._pos(node.target)
        val_src = _src(self._module, node.value)
        val_pos = self._pos(node.value)

        self.assignments.append(
            AssignmentFact(
                target=tgt_src,
                target_location=self._span(tgt_pos),
                value_expression=val_src,
                value_location=self._span(val_pos),
                kind=AssignmentKind.AUGMENTED,
                containing_function_fqn=self._current_function_fqn,
            )
        )

        # Emit AttributeAccess for attribute/subscript augmented writes
        if isinstance(node.target, cst.Attribute):
            self.attributes.append(
                AttributeAccess(
                    target_expr=_src(self._module, node.target.value),
                    attr_name=node.target.attr.value,
                    is_write=True,
                    access_kind=AccessKind.AUGMENTED,
                    value_expr=val_src,
                    containing_function_fqn=self._current_function_fqn,
                    location=self._span(tgt_pos),
                    provenance=self._prov,
                )
            )
        elif (
            isinstance(node.target, cst.Subscript)
            and len(node.target.slice) == 1
            and isinstance(node.target.slice[0], cst.SubscriptElement)
            and isinstance(node.target.slice[0].slice, cst.Index)
        ):
            self.attributes.append(
                AttributeAccess(
                    target_expr=_src(self._module, node.target.value),
                    attr_name=_src(
                        self._module,
                        node.target.slice[0].slice.value,
                    ),
                    is_write=True,
                    access_kind=AccessKind.AUGMENTED,
                    value_expr=val_src,
                    containing_function_fqn=self._current_function_fqn,
                    location=self._span(tgt_pos),
                    provenance=self._prov,
                )
            )

        return True

    def visit_AnnAssign(self, node: cst.AnnAssign) -> bool | None:
        pos = self._pos(node)
        if node.value is None:
            return True  # annotation without value (e.g. x: int)
        tgt_src = _src(self._module, node.target)
        tgt_pos = self._pos(node.target)
        val_src = _src(self._module, node.value)
        val_pos = self._pos(node.value)

        self.assignments.append(
            AssignmentFact(
                target=tgt_src,
                target_location=self._span(tgt_pos),
                value_expression=val_src,
                value_location=self._span(val_pos),
                kind=AssignmentKind.ANNOTATED,
                containing_function_fqn=self._current_function_fqn,
            )
        )
        self._record_assignment_alias(node.target, node.value, self._span(pos))
        self._record_importlib_module_binding(node.target, node.value)
        return True

    # ── Comprehension bindings ───────────────────────────────────────

    def visit_ListComp(self, node: cst.ListComp) -> bool | None:
        self._record_comprehension_bindings(node, node.for_in)
        return True

    def visit_SetComp(self, node: cst.SetComp) -> bool | None:
        self._record_comprehension_bindings(node, node.for_in)
        return True

    def visit_DictComp(self, node: cst.DictComp) -> bool | None:
        self._record_comprehension_bindings(node, node.for_in)
        return True

    def visit_GeneratorExp(self, node: cst.GeneratorExp) -> bool | None:
        self._record_comprehension_bindings(node, node.for_in)
        return True

    def _record_comprehension_bindings(
        self,
        node: cst.BaseExpression,
        for_in: cst.CompFor,
    ) -> None:
        comprehension_expr = _src(self._module, node)
        comprehension_location = self._span(self._pos(node))
        current: cst.CompFor | None = for_in
        while current is not None:
            self.comprehension_bindings.append(
                ComprehensionBindingFact(
                    target=_src(self._module, current.target),
                    target_location=self._span(self._pos(current.target)),
                    iterable_expression=_src(self._module, current.iter),
                    iterable_location=self._span(self._pos(current.iter)),
                    comprehension_expr=comprehension_expr,
                    comprehension_location=comprehension_location,
                    containing_function_fqn=self._current_function_fqn,
                    provenance=self._prov,
                )
            )
            current = current.inner_for_in

    # ── Returns ───────────────────────────────────────────────────

    def visit_Return(self, node: cst.Return) -> bool | None:
        if self._current_function_fqn is None:
            return True

        expression = node.value
        self.returns.append(
            ReturnFact(
                expression=_src(self._module, expression) if expression is not None else None,
                expression_location=(
                    self._span(self._pos(expression)) if expression is not None else None
                ),
                statement_location=self._span(self._pos(node)),
                containing_function_fqn=self._current_function_fqn,
                provenance=self._prov,
            )
        )
        return True

    # ── Yields ────────────────────────────────────────────────────

    def visit_Yield(self, node: cst.Yield) -> bool | None:
        if self._current_function_fqn is None:
            return True

        expression = node.value
        is_from = isinstance(expression, cst.From)
        yielded_node = (
            expression.item if is_from and isinstance(expression, cst.From) else expression
        )

        self.yields.append(
            YieldFact(
                expression=_src(self._module, yielded_node) if yielded_node is not None else None,
                expression_location=(
                    self._span(self._pos(yielded_node)) if yielded_node is not None else None
                ),
                statement_location=self._span(self._pos(node)),
                is_from=is_from,
                containing_function_fqn=self._current_function_fqn,
                provenance=self._prov,
            )
        )
        return True

    # ── Conditional import tracking ──────────────────────────────

    @staticmethod
    def _is_type_checking_guard(node: cst.If) -> bool:
        """Return ``True`` when ``node`` is ``if TYPE_CHECKING:``."""
        return isinstance(node.test, cst.Name) and node.test.value == "TYPE_CHECKING"

    @staticmethod
    def _is_import_error_guard(node: cst.Try) -> bool:
        """Return ``True`` when any handler catches ``ImportError``."""
        for handler in node.handlers:
            if isinstance(handler, cst.ExceptHandler) and handler.type is not None:
                if isinstance(handler.type, cst.Name) and handler.type.value == "ImportError":
                    return True
                if (
                    isinstance(handler.type, cst.Attribute)
                    and isinstance(handler.type.attr, cst.Name)
                    and handler.type.attr.value == "ImportError"
                ):
                    return True
            # bare except (no type) does not count as an ImportError guard
        return False

    def visit_If(self, node: cst.If) -> bool | None:
        if self._is_type_checking_guard(node):
            self._conditional_import_depth += 1
        return True

    def leave_If(self, original_node: cst.If) -> None:
        if self._is_type_checking_guard(original_node):
            self._conditional_import_depth -= 1

    def visit_Try(self, node: cst.Try) -> bool | None:
        if self._is_import_error_guard(node):
            self._conditional_import_depth += 1
        return True

    def leave_Try(self, original_node: cst.Try) -> None:
        if self._is_import_error_guard(original_node):
            self._conditional_import_depth -= 1

    # ── Imports ───────────────────────────────────────────────────

    def visit_Import(self, node: cst.Import) -> bool | None:
        pos = self._pos(node)
        if isinstance(node.names, cst.ImportStar):
            return True  # star import handled in visit_ImportFrom

        is_conditional = self._conditional_import_depth > 0
        for alias in node.names:
            mod_name = _src(self._module, alias.name)
            as_name = alias.asname
            alias_pairs: list[tuple[str, str]] = []
            if as_name is not None and isinstance(as_name, cst.AsName):
                alias_name = _src(self._module, as_name.name)
                alias_pairs.append((mod_name, alias_name))
                self.aliases.append(
                    AliasFact(
                        original_fqn=mod_name,
                        alias_name=alias_name,
                        mechanism=AliasMechanism.IMPORT_ALIAS,
                        location=self._span(pos),
                        is_conditional=is_conditional,
                    )
                )
            else:
                alias_name = mod_name.split(".", maxsplit=1)[0]

            self._add_symbol_ref(alias_name, mod_name, alias.name)

            self.imports.append(
                ImportFact(
                    module=mod_name,
                    names=(),
                    aliases=tuple(alias_pairs),
                    is_from_import=False,
                    location=self._span(pos),
                    provenance=self._prov,
                    is_conditional=is_conditional,
                )
            )
        return True

    def visit_ImportFrom(self, node: cst.ImportFrom) -> bool | None:
        pos = self._pos(node)
        relative_level = len(node.relative)
        module_name = _src(self._module, node.module) if node.module is not None else ""
        mod_name = self._resolve_relative_module(module_name, relative_level)
        is_conditional = self._conditional_import_depth > 0

        if isinstance(node.names, cst.ImportStar):
            self.errors.append(
                ExtractionError(
                    file=self._rel,
                    pass_name=_PASS_NAME,
                    error_kind=ErrorKind.RESOLUTION,
                    message=(
                        f"Cannot statically expand wildcard import from {mod_name!r}; "
                        "imported names are unresolved."
                    ),
                    is_fatal=False,
                    location=self._span(pos),
                )
            )
            self.aliases.append(
                AliasFact(
                    original_fqn=mod_name + ".*",
                    alias_name="*",
                    mechanism=AliasMechanism.WILDCARD_IMPORT,
                    location=self._span(pos),
                    is_conditional=is_conditional,
                )
            )
            self.imports.append(
                ImportFact(
                    module=mod_name,
                    names=("*",),
                    aliases=(),
                    is_from_import=True,
                    location=self._span(pos),
                    provenance=self._prov,
                    is_conditional=is_conditional,
                    is_relative=relative_level > 0,
                )
            )
            return True

        names: list[str] = []
        alias_pairs: list[tuple[str, str]] = []
        for alias in node.names:
            imported = _src(self._module, alias.name)
            names.append(imported)
            target_fqn = f"{mod_name}.{imported}" if mod_name else imported
            if alias.asname is not None and isinstance(alias.asname, cst.AsName):
                alias_name = _src(self._module, alias.asname.name)
                alias_pairs.append((imported, alias_name))
                self.aliases.append(
                    AliasFact(
                        original_fqn=target_fqn,
                        alias_name=alias_name,
                        mechanism=AliasMechanism.IMPORT_ALIAS,
                        location=self._span(pos),
                        is_conditional=is_conditional,
                    )
                )
            else:
                alias_name = imported
            self._add_symbol_ref(alias_name, target_fqn, alias.name)

        self.imports.append(
            ImportFact(
                module=mod_name,
                names=tuple(names),
                aliases=tuple(alias_pairs),
                is_from_import=True,
                location=self._span(pos),
                provenance=self._prov,
                is_conditional=is_conditional,
                is_relative=relative_level > 0,
            )
        )
        return True


# ── Assignment target name helper ─────────────────────────────────────


def _assignment_alias_pairs(
    target: cst.BaseAssignTargetExpression,
    value: cst.BaseExpression,
) -> tuple[tuple[str, cst.BaseExpression], ...]:
    if isinstance(target, cst.Name) and isinstance(value, (cst.Name, cst.Attribute)):
        return ((target.value, value),)

    if not isinstance(target, (cst.Tuple, cst.List)) or not isinstance(
        value,
        (cst.Tuple, cst.List),
    ):
        return ()

    target_values = _simple_unpack_values(target)
    value_values = _simple_unpack_values(value)
    if target_values is None or value_values is None or len(target_values) != len(value_values):
        return ()

    return tuple(
        (target_value.value, value_value)
        for target_value, value_value in zip(target_values, value_values, strict=True)
        if isinstance(target_value, cst.Name)
        and isinstance(value_value, (cst.Name, cst.Attribute))
    )


def _assign_target_names(node: cst.Assign | cst.AnnAssign) -> list[str]:
    """Extract simple names from assignment targets (for class variable detection)."""
    if isinstance(node, cst.Assign):
        return [t.target.value for t in node.targets if isinstance(t.target, cst.Name)]
    if isinstance(node, cst.AnnAssign) and isinstance(node.target, cst.Name):
        return [node.target.value]
    return []


def _single_assignment_target_name(node: cst.Assign) -> str | None:
    if len(node.targets) != 1:
        return None
    target = node.targets[0].target
    if isinstance(target, cst.Name):
        return target.value
    return None


# ── Single-file extraction ────────────────────────────────────────────


def _extract_file(
    file_path: Path,
    repo_root: Path,
    parsed_files: MutableMapping[str, ParsedFile] | None = None,
    namespace_roots: frozenset[str] = frozenset(),
) -> _ExtractedFile | ExtractionError:
    """Parse and extract from a single Python file."""
    rel_path = str(file_path.relative_to(repo_root))
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return ExtractionError(
            file=rel_path,
            pass_name=_PASS_NAME,
            error_kind=ErrorKind.PARSE,
            message=f"Cannot read file: {exc}",
            is_fatal=True,
            location=None,
        )

    try:
        tree = cst.parse_module(source)
    except cst.ParserSyntaxError as exc:
        return ExtractionError(
            file=rel_path,
            pass_name=_PASS_NAME,
            error_kind=ErrorKind.PARSE,
            message=f"Syntax error: {exc.message}",
            is_fatal=True,
            location=SourceSpan(
                file=rel_path,
                line=exc.raw_line,
                column=exc.raw_column,
                end_line=exc.raw_line,
                end_column=exc.raw_column,
            ),
        )

    try:
        wrapper = MetadataWrapper(tree)
    except Exception as exc:
        return ExtractionError(
            file=rel_path,
            pass_name=_PASS_NAME,
            error_kind=ErrorKind.PARSE,
            message=f"Metadata wrapper failed: {exc}",
            is_fatal=True,
            location=None,
        )

    module = wrapper.module
    span_interner = SpanInterner()
    parsed_file = ParsedFile(
        rel_path=rel_path,
        wrapper=wrapper,
        span_interner=span_interner,
    )
    module_fqn, is_package_module = _module_fqn_for_path(file_path, repo_root, namespace_roots)
    visitor = StructuralVisitor(
        module,
        rel_path,
        module_fqn,
        is_package_module=is_package_module,
        span_interner=span_interner,
    )
    if parsed_files is not None:
        parsed_files[rel_path] = parsed_file
    try:
        wrapper.visit(visitor)
    except Exception as exc:
        visitor.errors.append(
            ExtractionError(
                file=rel_path,
                pass_name=_PASS_NAME,
                error_kind=ErrorKind.PARSE,
                message=f"Visitor failed: {exc}",
                is_fatal=True,
                location=None,
            )
        )

    return _ExtractedFile(visitor=visitor, parsed_file=parsed_file)


def _apply_structural_resolution_passes(
    output: StructuralOutput,
    repo_root: Path,
    python_files: Sequence[Path],
    namespace_roots: frozenset[str] = frozenset(),
) -> StructuralOutput:
    output = _apply_static_star_import_expansion(output, repo_root, namespace_roots)
    output = _apply_from_import_binding_source_ordering(output, repo_root, namespace_roots)
    output = _apply_reexport_resolution(output, repo_root, namespace_roots)
    output = _apply_import_alias_source_ordering(output, repo_root, namespace_roots)
    output = _apply_assignment_alias_resolution(output, repo_root, namespace_roots)
    output = _apply_import_alias_shadowing(output, repo_root, namespace_roots)
    output = _apply_bare_import_shadowing(output, repo_root, namespace_roots)
    output = _apply_from_import_shadowing(output, repo_root, namespace_roots)
    # From-import shadowing can rewrite later references to the local alias FQN;
    # bare-import shadowing can do the same for the imported root package name.
    # Resolve those through assignment aliases that replace the imported binding.
    output = _apply_assignment_alias_resolution(output, repo_root, namespace_roots)
    output = _apply_project_import_validation(output, repo_root, python_files, namespace_roots)
    output = _apply_class_hierarchy(output)
    output = _apply_receiver_method_call_resolution(output)
    output = _apply_super_call_resolution(output)
    output = _apply_constructor_call_resolution(output)
    return _apply_orm_query_chain_resolution(output)


# ── Entry point ───────────────────────────────────────────────────────


def extract_structural(
    repo_root: Path,
    python_files: Sequence[Path] | None = None,
    *,
    parsed_files: MutableMapping[str, ParsedFile] | None = None,
    per_file_callback: (
        Callable[[ParsedFile, tuple[FunctionRecord, ...]], Sequence[ExtractionError]] | None
    ) = None,
    namespace_roots: frozenset[str] | None = None,
    resolution_files: Sequence[Path] | None = None,
) -> StructuralOutput:
    """Run the structural entity pass on a repository.

    Parameters
    ----------
    repo_root:
        Absolute path to the repository root.
    python_files:
        Files to extract from.  If ``None``, discovered automatically.
    parsed_files:
        Optional mutable mapping populated with successfully parsed files for
        later L1 stages that need the same LibCST metadata wrapper.
    per_file_callback:
        Optional callback invoked after one file is structurally visited and
        before the next file is parsed.  Later L1 stages use this to consume the
        temporary LibCST wrapper without retaining all wrappers until the end.
    namespace_roots:
        Optional precomputed PEP 420 namespace prefixes (see
        :func:`_namespace_package_roots_from_files`).  When ``None`` (the cold
        full-build default) they are derived from ``python_files``.  The
        incremental path passes the **repo-wide** classification here so a
        partial re-extraction mints the same module FQNs a full build would —
        the deciding ``from <ns>.x import`` evidence may live in a file that is
        not in the changed subset (FLAW-120).
    resolution_files:
        Optional **repo-wide** file list used by the cross-file resolution
        passes (project-local import validation in particular).  When ``None``
        it defaults to ``python_files``.  The incremental path passes the full
        repository file set so imports that target unchanged project modules
        are not misclassified as missing when only a subset is re-extracted
        (FLAW-120).

    Returns
    -------
    StructuralOutput:
        Aggregated extraction results from all files.
    """
    _ensure_astroid_brains_registered()

    if python_files is None:
        python_files = discover_python_files(repo_root)

    if namespace_roots is None:
        namespace_roots = _namespace_package_roots_from_files(repo_root, python_files)
    resolution_files = python_files if resolution_files is None else resolution_files

    all_functions: list[FunctionRecord] = []
    all_classes: list[ClassRecord] = []
    all_decorators: list[DecoratorFact] = []
    all_call_edges: list[CallEdge] = []
    all_attributes: list[AttributeAccess] = []
    all_assignments: list[AssignmentFact] = []
    all_comprehension_bindings: list[ComprehensionBindingFact] = []
    all_returns: list[ReturnFact] = []
    all_yields: list[YieldFact] = []
    all_aliases: list[AliasFact] = []
    all_imports: list[ImportFact] = []
    all_symbol_refs: list[SymbolRef] = []
    all_errors: list[ExtractionError] = []

    for fpath in python_files:
        result = _extract_file(fpath, repo_root, parsed_files, namespace_roots)
        if isinstance(result, ExtractionError):
            all_errors.append(result)
            continue
        visitor = result.visitor
        if per_file_callback is not None:
            all_errors.extend(per_file_callback(result.parsed_file, tuple(visitor.functions)))
        all_functions.extend(visitor.functions)
        all_classes.extend(visitor.classes)
        all_decorators.extend(visitor.decorators)
        all_call_edges.extend(visitor.call_edges)
        all_attributes.extend(visitor.attributes)
        all_assignments.extend(visitor.assignments)
        all_comprehension_bindings.extend(visitor.comprehension_bindings)
        all_returns.extend(visitor.returns)
        all_yields.extend(visitor.yields)
        all_aliases.extend(visitor.aliases)
        all_imports.extend(visitor.imports)
        all_symbol_refs.extend(visitor.symbol_refs)
        all_errors.extend(visitor.errors)

    output = StructuralOutput(
        functions=tuple(all_functions),
        classes=tuple(all_classes),
        decorators=tuple(all_decorators),
        call_edges=tuple(all_call_edges),
        attributes=tuple(all_attributes),
        assignments=tuple(all_assignments),
        comprehension_bindings=tuple(all_comprehension_bindings),
        returns=tuple(all_returns),
        yields=tuple(all_yields),
        aliases=tuple(all_aliases),
        imports=tuple(all_imports),
        symbol_refs=tuple(all_symbol_refs),
        errors=tuple(all_errors),
    )
    return _apply_structural_resolution_passes(
        output, repo_root, resolution_files, namespace_roots
    )
