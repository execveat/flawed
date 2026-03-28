"""Layer 1 type enrichment over targeted basedpyright ``reveal_type`` probes."""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import sys
import tempfile
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from flawed import _process as managed_process
from flawed._index._parsing import parse_analyzed_expression
from flawed._index._types import (
    AssignmentKind,
    ErrorKind,
    ExtractionError,
    ExtractionProvenance,
    SourceSpan,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence

    from flawed._index._types import AssignmentFact

_PASS_NAME = "basedpyright_type_enrichment"
# 0.3.0 (FLAW-268): the query-count batch split was removed — basedpyright now
# runs as a SINGLE invocation over all probe files. basedpyright is stateless
# across subprocesses and re-binds the whole project on every run, so the old
# per-batch split multiplied that fixed cost N-fold, and each cold full-project
# check routinely blew the hardcoded 30 s timeout → large repos were cached with
# degraded/zero type facts (a false-negative pressure source). The timeout is now
# 120 s and configurable. Bumping the oracle version invalidates caches recorded
# with the old degraded facts so they recompute. (0.2.0: per-file query batching
# replaced the all-or-nothing query/probe-file cap, FLAW-125.)
_PASS_VERSION = "0.3.0"
BASEDPYRIGHT_ORACLE_VERSION = _PASS_VERSION
_REVEAL_RE = re.compile(r'^Type of "(.+)" is "(.+)"$')
_TEXT_REVEAL_RE = re.compile(
    r"^\s*(?P<file>.+?):(?P<line>\d+):(?P<column>\d+) - information: "
    r'Type of "(?P<expression>.+)" is "(?P<declared_type>.+)"$'
)
_IMPRECISE_MARKERS = ("Any", "Unknown", "Uninferable")
_DEFAULT_BASEDPYRIGHT_MAX_QUERIES = 2000
_DEFAULT_BASEDPYRIGHT_MAX_PROBE_FILES = 500
_DEFAULT_BASEDPYRIGHT_MAX_SOURCE_FILES = 5000
_DEFAULT_BASEDPYRIGHT_MAX_WORKSPACE_BYTES = 250_000_000
_DEFAULT_BASEDPYRIGHT_TIMEOUT_SECONDS = 120
_PROBE_SUPPRESSED_REPORTS = (
    "reportAny",
    "reportArgumentType",
    "reportAssignmentType",
    "reportAttributeAccessIssue",
    "reportCallIssue",
    "reportExplicitAny",
    "reportFunctionMemberAccess",
    "reportGeneralTypeIssues",
    "reportIgnoreCommentWithoutRule",
    "reportImplicitOverride",
    "reportImplicitStringConcatenation",
    "reportIncompatibleMethodOverride",
    "reportMissingImports",
    "reportMissingModuleSource",
    "reportMissingParameterType",
    "reportMissingSuperCall",
    "reportOptionalCall",
    "reportOptionalMemberAccess",
    "reportOptionalSubscript",
    "reportReturnType",
    "reportUnannotatedClassAttribute",
    "reportUnknownArgumentType",
    "reportUnknownLambdaType",
    "reportUnknownMemberType",
    "reportUnknownParameterType",
    "reportUnknownVariableType",
    "reportUnusedCallResult",
    "reportUnusedFunction",
    "reportUnusedImport",
    "reportUnusedParameter",
    "reportUntypedBaseClass",
    "reportUntypedClassDecorator",
    "reportUntypedFunctionDecorator",
)
_COPY_EXCLUDES = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "env",
        "local",
        "node_modules",
        "venv",
    }
)


@dataclass(frozen=True, slots=True)
class TypeQuery:
    """A source expression selected for declared-type probing."""

    expression: str
    """Source text to pass to ``reveal_type(...)``."""

    location: SourceSpan
    """Original source span of the expression."""

    reveal_after_line: int
    """1-based source line after which the reveal statement can be inserted."""

    containing_function_fqn: str | None
    """FQN of the containing function, or ``None`` for module-level queries."""


@dataclass(frozen=True, slots=True)
class TypeFact:
    """A declared type returned by a type-enrichment oracle."""

    expression: str
    """Expression that was probed."""

    declared_type: str
    """The type-checker's display type for the expression."""

    location: SourceSpan
    """Original source span of the expression."""

    source_tool: str
    """Tool that produced the fact."""

    is_concrete: bool
    """False when the tool returned an imprecise ``Any``/``Unknown`` result."""

    provenance: ExtractionProvenance
    """L1 provenance for the enrichment fact."""

    containing_function_fqn: str | None = None
    """FQN of the containing function for scoped expression lookups."""


class TypeOracle(Protocol):
    """Adapter boundary for tools that produce L1 type-enrichment facts."""

    def run(self, repo_root: Path, queries: Iterable[TypeQuery]) -> TypeEnrichmentIndex:
        """Return type facts and non-fatal errors for *queries* in *repo_root*."""
        ...


class TypeEnrichmentIndex:
    """Query object for L1 type-enrichment facts and probe errors."""

    __slots__ = ("_errors", "_facts", "_facts_by_expression_scope", "_facts_by_location")

    def __init__(
        self,
        facts: tuple[TypeFact, ...] = (),
        errors: tuple[ExtractionError, ...] = (),
    ) -> None:
        self._facts = facts
        self._errors = errors
        by_location: dict[tuple[str, int, int, str], list[TypeFact]] = {}
        by_expression_scope: dict[tuple[str, str, str | None], list[TypeFact]] = {}
        for fact in facts:
            by_location.setdefault(_fact_key(fact.expression, fact.location), []).append(fact)
            by_expression_scope.setdefault(
                _expression_scope_key(
                    fact.expression,
                    fact.location.file,
                    fact.containing_function_fqn,
                ),
                [],
            ).append(fact)
        self._facts_by_location = {
            location: tuple(location_facts) for location, location_facts in by_location.items()
        }
        self._facts_by_expression_scope = {
            expression_scope: tuple(expression_facts)
            for expression_scope, expression_facts in by_expression_scope.items()
        }

    @classmethod
    def empty(cls) -> TypeEnrichmentIndex:
        """Return an empty type-enrichment index."""
        return cls()

    @property
    def facts(self) -> tuple[TypeFact, ...]:
        """All type facts returned by enrichment tools."""
        return self._facts

    @property
    def errors(self) -> tuple[ExtractionError, ...]:
        """Non-fatal enrichment errors that must propagate as gaps downstream."""
        return self._errors

    def type_for(self, query: TypeQuery) -> TypeFact | None:
        """Return the exact fact for *query*, if one was produced."""
        return _best_fact(self.types_for(query))

    def types_for(self, query: TypeQuery) -> tuple[TypeFact, ...]:
        """Return every exact fact for *query* across all enrichment tools."""
        return self._facts_by_location.get(_fact_key(query.expression, query.location), ())

    def types_for_expression(
        self,
        expression: str,
        file: str,
        *,
        containing_function_fqn: str | None = None,
    ) -> tuple[TypeFact, ...]:
        """Return every fact for *expression* in *file* across enrichment tools.

        Function-scoped facts are preferred so same-named locals in sibling
        functions do not contaminate provider predicates. Unscoped facts are
        retained as a compatibility fallback for manually constructed indexes
        and older adapter outputs.
        """
        scoped = self._facts_by_expression_scope.get(
            _expression_scope_key(expression, file, containing_function_fqn),
            (),
        )
        if containing_function_fqn is None:
            return scoped
        if scoped:
            return scoped
        return self._facts_by_expression_scope.get(
            _expression_scope_key(expression, file, None),
            (),
        )

    def at(self, location: SourceSpan) -> tuple[TypeFact, ...]:
        """Return all type facts whose expression starts at *location*."""
        return tuple(
            fact
            for fact in self._facts
            if (
                fact.location.file == location.file
                and fact.location.line == location.line
                and fact.location.column == location.column
            )
        )

    def __len__(self) -> int:
        return len(self._facts)

    def __bool__(self) -> bool:
        return bool(self._facts or self._errors)


class BasedPyrightOracle:
    """Subprocess-backed declared-type oracle using basedpyright reveal diagnostics."""

    __slots__ = (
        "_command",
        "_max_probe_files",
        "_max_queries",
        "_max_source_files",
        "_max_workspace_bytes",
        "_timeout_seconds",
    )

    def __init__(
        self,
        *,
        command: Sequence[str] | None = None,
        timeout_seconds: int = _DEFAULT_BASEDPYRIGHT_TIMEOUT_SECONDS,
        max_queries: int = _DEFAULT_BASEDPYRIGHT_MAX_QUERIES,
        max_probe_files: int = _DEFAULT_BASEDPYRIGHT_MAX_PROBE_FILES,
        max_source_files: int = _DEFAULT_BASEDPYRIGHT_MAX_SOURCE_FILES,
        max_workspace_bytes: int = _DEFAULT_BASEDPYRIGHT_MAX_WORKSPACE_BYTES,
    ) -> None:
        self._command = tuple(command or (sys.executable, "-m", "basedpyright"))
        self._timeout_seconds = timeout_seconds
        self._max_queries = max_queries
        self._max_probe_files = max_probe_files
        self._max_source_files = max_source_files
        self._max_workspace_bytes = max_workspace_bytes

    def run(self, repo_root: Path, queries: Iterable[TypeQuery]) -> TypeEnrichmentIndex:
        """Run targeted ``reveal_type`` probes and return a type-enrichment index.

        All queries are probed in a SINGLE basedpyright invocation over one
        shared workspace (FLAW-268). basedpyright is stateless across
        subprocesses and re-binds the whole project on every run, so splitting
        queries into multiple batches multiplied that fixed cost N-fold and made
        each batch likelier to exceed the timeout; one invocation is both faster
        and recovers more facts. ``reveal_type`` insertion stays safe because
        :func:`_write_probe_files` mutates each source file exactly once.

        The workspace-input budgets (``max_source_files``, ``max_workspace_bytes``)
        remain hard guards: they bound the cost of the shared workspace, so an
        over-budget repo aborts with a single actionable repo-level error instead
        of per-query noise. ``max_queries``/``max_probe_files`` are retained for
        config compatibility but no longer split the run.
        """
        repo_root = repo_root.expanduser().resolve()
        query_tuple = tuple(queries)
        if not query_tuple:
            return TypeEnrichmentIndex.empty()

        workspace_error = _validate_workspace_input_caps(
            repo_root,
            max_source_files=self._max_source_files,
            max_workspace_bytes=self._max_workspace_bytes,
        )
        if workspace_error is not None:
            return TypeEnrichmentIndex(errors=(workspace_error,))

        try:
            with _probe_workspace(repo_root) as workspace:
                _write_default_probe_config(workspace)
                return self._run_probes(workspace, query_tuple)
        except OSError as exc:
            return TypeEnrichmentIndex(
                errors=(_file_error(query_tuple[0], f"basedpyright failed to start: {exc}"),)
            )

    def _run_probes(
        self,
        workspace: Path,
        queries: tuple[TypeQuery, ...],
    ) -> TypeEnrichmentIndex:
        """Probe *queries* in one basedpyright invocation against *workspace*.

        :func:`_write_probe_files` mutates each source file exactly once, so the
        in-place ``reveal_type`` insertion is safe. A timeout or start failure
        records a single representative non-fatal error (propagated downstream as
        an honest gap), never a silent repo-wide drop.
        """
        probe_files, reveal_lines, prep_errors = _write_probe_files(workspace, queries)
        if not probe_files:
            return TypeEnrichmentIndex(errors=prep_errors)
        try:
            completed = managed_process.run(
                (*self._command, *(str(path) for path in probe_files)),
                cwd=workspace,
                capture_output=True,
                text=True,
                timeout=self._timeout_seconds,
                check=False,
            )
        except managed_process.TimeoutExpired:
            message = f"basedpyright timed out after {self._timeout_seconds}s"
            return TypeEnrichmentIndex(errors=(*prep_errors, _file_error(queries[0], message)))
        except OSError as exc:
            start_error = _file_error(queries[0], f"basedpyright failed to start: {exc}")
            return TypeEnrichmentIndex(errors=(*prep_errors, start_error))
        probe_index = _index_from_completed_process(completed, reveal_lines, queries)
        if not prep_errors:
            return probe_index
        return TypeEnrichmentIndex(
            facts=probe_index.facts,
            errors=(*prep_errors, *probe_index.errors),
        )


def build_type_enrichment_index(
    repo_root: Path,
    queries: Iterable[TypeQuery],
    *,
    oracle: TypeOracle | None = None,
    enable_mypy_batch: bool = False,
    mypy_batch_timeout_seconds: int = 120,
    mypy_batch_max_files: int = 5000,
    mypy_batch_cache_dir: Path | None = None,
    basedpyright_timeout_seconds: int = _DEFAULT_BASEDPYRIGHT_TIMEOUT_SECONDS,
    basedpyright_max_queries: int = _DEFAULT_BASEDPYRIGHT_MAX_QUERIES,
    basedpyright_max_probe_files: int = _DEFAULT_BASEDPYRIGHT_MAX_PROBE_FILES,
    basedpyright_max_source_files: int = _DEFAULT_BASEDPYRIGHT_MAX_SOURCE_FILES,
    basedpyright_max_workspace_bytes: int = _DEFAULT_BASEDPYRIGHT_MAX_WORKSPACE_BYTES,
) -> TypeEnrichmentIndex:
    """Build a type-enrichment index for explicitly selected query locations."""
    query_tuple = tuple(queries)
    if oracle is not None:
        return oracle.run(repo_root, query_tuple)
    if not enable_mypy_batch:
        return BasedPyrightOracle(
            timeout_seconds=basedpyright_timeout_seconds,
            max_queries=basedpyright_max_queries,
            max_probe_files=basedpyright_max_probe_files,
            max_source_files=basedpyright_max_source_files,
            max_workspace_bytes=basedpyright_max_workspace_bytes,
        ).run(repo_root, query_tuple)

    from flawed._index._mypy_batch_oracle import MypyBatchOracle

    return _merge_type_enrichment_indexes(
        (
            MypyBatchOracle(
                timeout_seconds=mypy_batch_timeout_seconds,
                max_source_files=mypy_batch_max_files,
                cache_dir=mypy_batch_cache_dir,
            ).run(repo_root, query_tuple),
            BasedPyrightOracle(
                timeout_seconds=basedpyright_timeout_seconds,
                max_queries=basedpyright_max_queries,
                max_probe_files=basedpyright_max_probe_files,
                max_source_files=basedpyright_max_source_files,
                max_workspace_bytes=basedpyright_max_workspace_bytes,
            ).run(repo_root, query_tuple),
        )
    )


def queries_from_assignments(assignments: Iterable[AssignmentFact]) -> tuple[TypeQuery, ...]:
    """Select safe assignment-target locations for declared-type probing."""
    queries: list[TypeQuery] = []
    for assignment in assignments:
        if assignment.kind not in (AssignmentKind.SIMPLE, AssignmentKind.ANNOTATED):
            continue
        if not _is_safe_reveal_expression(assignment.target):
            continue
        queries.append(
            TypeQuery(
                expression=assignment.target,
                location=assignment.target_location,
                reveal_after_line=assignment.value_location.end_line,
                containing_function_fqn=assignment.containing_function_fqn,
            )
        )
    return tuple(queries)


def _index_from_completed_process(
    completed: managed_process.CompletedProcess[str],
    reveal_lines: dict[tuple[Path, int], TypeQuery],
    queries: tuple[TypeQuery, ...],
) -> TypeEnrichmentIndex:
    text_index = _index_from_text_output(completed.stdout, reveal_lines, queries)
    if text_index is not None:
        return text_index

    data = _json_object(completed.stdout)
    if data is None:
        return _index_from_reveals((), queries)

    diagnostics = data.get("generalDiagnostics", ())
    if not isinstance(diagnostics, list):
        diagnostics = []

    reveals: list[tuple[TypeQuery, str]] = []
    for diagnostic_obj in diagnostics:
        diagnostic = _diagnostic(diagnostic_obj)
        if diagnostic is None:
            continue
        path, line, message = diagnostic
        query = reveal_lines.get((path, line))
        if query is None:
            continue
        match = _REVEAL_RE.match(message)
        if match is None:
            continue

        reveals.append((query, match.group(2)))

    return _index_from_reveals(reveals, queries)


def _index_from_text_output(
    raw: str,
    reveal_lines: dict[tuple[Path, int], TypeQuery],
    queries: tuple[TypeQuery, ...],
) -> TypeEnrichmentIndex | None:
    reveals: list[tuple[TypeQuery, str]] = []
    for line in raw.splitlines():
        match = _TEXT_REVEAL_RE.match(line)
        if match is None:
            continue
        query = reveal_lines.get(
            (Path(match.group("file")).resolve(), int(match.group("line")) - 1)
        )
        if query is None:
            continue
        reveals.append((query, match.group("declared_type")))

    if reveals:
        return _index_from_reveals(reveals, queries)
    if raw.lstrip().startswith("{"):
        return None
    return _index_from_reveals((), queries)


def _index_from_reveals(
    reveals: Iterable[tuple[TypeQuery, str]],
    queries: tuple[TypeQuery, ...],
) -> TypeEnrichmentIndex:
    facts: list[TypeFact] = []
    errors: list[ExtractionError] = []
    seen_queries: set[TypeQuery] = set()

    for query, declared_type in reveals:
        is_concrete = not _is_imprecise_type(declared_type)
        facts.append(
            TypeFact(
                expression=query.expression,
                declared_type=declared_type,
                location=query.location,
                source_tool="basedpyright",
                is_concrete=is_concrete,
                provenance=ExtractionProvenance(
                    producer=_PASS_NAME,
                    producer_version=_PASS_VERSION,
                    artifact=query.location.file,
                ),
                containing_function_fqn=query.containing_function_fqn,
            )
        )
        seen_queries.add(query)
        if not is_concrete:
            errors.append(
                _file_error(
                    query,
                    f"basedpyright returned imprecise type {declared_type!r} for "
                    f"{query.expression!r}",
                )
            )

    errors.extend(
        _file_error(
            query,
            f"basedpyright produced no reveal_type diagnostic for {query.expression!r}",
        )
        for query in queries
        if query not in seen_queries
    )

    return TypeEnrichmentIndex(facts=tuple(facts), errors=tuple(errors))


def _errors_for_queries(
    queries: Iterable[TypeQuery],
    message: str,
) -> tuple[ExtractionError, ...]:
    return tuple(_file_error(query, message) for query in queries)


def _validate_workspace_input_caps(
    repo_root: Path,
    *,
    max_source_files: int,
    max_workspace_bytes: int,
) -> ExtractionError | None:
    source_files = 0
    workspace_bytes = 0
    stack = [repo_root]

    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if entry.name in _COPY_EXCLUDES:
                        continue
                    try:
                        stat = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        return _repo_error(repo_root, f"could not stat workspace input: {exc}")

                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                        continue

                    workspace_bytes += stat.st_size
                    if workspace_bytes > max_workspace_bytes:
                        return _repo_error(
                            repo_root,
                            "basedpyright workspace input bytes "
                            f"{workspace_bytes} exceeds limit {max_workspace_bytes}; "
                            "type enrichment skipped (type-aware detection degraded) — "
                            "raise type_enrichment.basedpyright_max_workspace_bytes to enrich",
                        )

                    if entry.name.endswith(".py"):
                        source_files += 1
                        if source_files > max_source_files:
                            return _repo_error(
                                repo_root,
                                "basedpyright source file count "
                                f"{source_files} exceeds limit {max_source_files}; "
                                "type enrichment skipped (type-aware detection degraded) — "
                                "raise type_enrichment.basedpyright_max_source_files to enrich",
                            )
        except OSError as exc:
            return _repo_error(repo_root, f"could not walk workspace input: {exc}")

    return None


def _diagnostic(diagnostic_obj: object) -> tuple[Path, int, str] | None:
    if not isinstance(diagnostic_obj, dict):
        return None
    diagnostic = cast("dict[str, object]", diagnostic_obj)
    file_obj = diagnostic.get("file")
    range_obj = diagnostic.get("range")
    message_obj = diagnostic.get("message")
    if not isinstance(file_obj, str) or not isinstance(range_obj, dict):
        return None
    if not isinstance(message_obj, str):
        return None

    range_data = cast("dict[str, object]", range_obj)
    start_obj = range_data.get("start")
    if not isinstance(start_obj, dict):
        return None
    start_data = cast("dict[str, object]", start_obj)
    line_obj = start_data.get("line")
    if not isinstance(line_obj, int):
        return None
    return Path(file_obj).resolve(), line_obj, message_obj


def _json_object(raw: str) -> dict[str, object] | None:
    try:
        data: object = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    return cast("dict[str, object]", data)


def _write_probe_files(
    workspace: Path,
    queries: tuple[TypeQuery, ...],
) -> tuple[tuple[Path, ...], dict[tuple[Path, int], TypeQuery], tuple[ExtractionError, ...]]:
    by_file: defaultdict[str, list[TypeQuery]] = defaultdict(list)
    for query in queries:
        by_file[query.location.file].append(query)

    reveal_lines: dict[tuple[Path, int], TypeQuery] = {}
    probe_files: list[Path] = []
    errors: list[ExtractionError] = []

    for rel_path, file_queries in by_file.items():
        path = workspace / rel_path
        if not path.exists():
            errors.extend(
                _errors_for_queries(file_queries, f"probe source file not found: {rel_path}")
            )
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            errors.extend(_errors_for_queries(file_queries, f"could not read probe source: {exc}"))
            continue

        inserts: defaultdict[int, list[TypeQuery]] = defaultdict(list)
        for query in file_queries:
            if not _is_safe_reveal_expression(query.expression):
                errors.append(
                    _file_error(query, f"unsafe reveal expression: {query.expression!r}")
                )
                continue
            if query.reveal_after_line < 1 or query.reveal_after_line > len(lines):
                errors.append(
                    _file_error(
                        query,
                        f"reveal insertion line {query.reveal_after_line} is outside {rel_path}",
                    )
                )
                continue
            inserts[query.reveal_after_line].append(query)

        if not inserts:
            continue

        rendered: list[str] = []
        for line_number, line in enumerate(lines, start=1):
            rendered.append(line)
            for query in inserts.get(line_number, ()):
                rendered.append(
                    f"{_indent_for_query(lines, query)}reveal_type({query.expression})"
                )
                reveal_lines[(path.resolve(), len(rendered) - 1)] = query

        path.write_text("\n".join(rendered) + "\n", encoding="utf-8")
        probe_files.append(path)

    return tuple(probe_files), reveal_lines, tuple(errors)


@contextmanager
def _probe_workspace(repo_root: Path) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="flawed-type-enrichment-") as tmp:
        workspace = Path(tmp) / "repo"
        shutil.copytree(
            repo_root,
            workspace,
            ignore=_ignore_copy_names,
            ignore_dangling_symlinks=True,
            symlinks=True,
        )
        yield workspace


def _ignore_copy_names(_directory: str, names: list[str]) -> set[str]:
    return set(names) & _COPY_EXCLUDES


def _write_default_probe_config(workspace: Path) -> None:
    """Constrain probe diagnostics when the target repo has no pyright config.

    ``reveal_type`` remains emitted even when report rules are suppressed, but
    basedpyright avoids serializing large volumes of unrelated diagnostics.
    Existing target configuration wins because it may be required for correct
    import paths or analysis settings.
    """
    if (workspace / "pyrightconfig.json").exists():
        return
    pyproject = workspace / "pyproject.toml"
    if pyproject.exists():
        try:
            content = pyproject.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return
        if "[tool.pyright]" in content or "[tool.basedpyright]" in content:
            return

    (workspace / "pyrightconfig.json").write_text(
        json.dumps(
            dict.fromkeys(_PROBE_SUPPRESSED_REPORTS, "none"),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _indent_for_query(lines: Sequence[str], query: TypeQuery) -> str:
    if query.location.line < 1 or query.location.line > len(lines):
        return ""
    line = lines[query.location.line - 1]
    return line[: len(line) - len(line.lstrip(" \t"))]


def _is_safe_reveal_expression(expression: str) -> bool:
    try:
        parsed = parse_analyzed_expression(expression)
    except SyntaxError:
        return False
    return isinstance(parsed.body, ast.Name | ast.Attribute | ast.Subscript)


def _is_imprecise_type(declared_type: str) -> bool:
    return any(marker in declared_type for marker in _IMPRECISE_MARKERS)


def _best_fact(facts: tuple[TypeFact, ...]) -> TypeFact | None:
    if not facts:
        return None
    concrete_facts = tuple(fact for fact in facts if fact.is_concrete)
    if concrete_facts:
        concrete_types: list[str] = []
        for fact in concrete_facts:
            if not any(_type_strings_agree(fact.declared_type, seen) for seen in concrete_types):
                concrete_types.append(fact.declared_type)
        if len(concrete_types) > 1:
            return None
        return concrete_facts[0]
    return facts[0]


def _merge_type_enrichment_indexes(indexes: Iterable[TypeEnrichmentIndex]) -> TypeEnrichmentIndex:
    facts: list[TypeFact] = []
    errors: list[ExtractionError] = []
    for index in indexes:
        facts.extend(index.facts)
        errors.extend(index.errors)
    return TypeEnrichmentIndex(facts=tuple(facts), errors=tuple(errors))


def _file_error(query: TypeQuery, message: str) -> ExtractionError:
    return ExtractionError(
        file=query.location.file,
        pass_name=_PASS_NAME,
        error_kind=ErrorKind.BASEDPYRIGHT,
        message=message,
        is_fatal=False,
        location=query.location,
    )


def _repo_error(repo_root: Path, message: str) -> ExtractionError:
    return ExtractionError(
        file=str(repo_root),
        pass_name=_PASS_NAME,
        error_kind=ErrorKind.BASEDPYRIGHT,
        message=message,
        is_fatal=False,
        location=None,
    )


def _fact_key(expression: str, location: SourceSpan) -> tuple[str, int, int, str]:
    return location.file, location.line, location.column, expression


def _expression_scope_key(
    expression: str,
    file: str,
    containing_function_fqn: str | None,
) -> tuple[str, str, str | None]:
    return file, expression, containing_function_fqn


def _type_strings_agree(left: str, right: str) -> bool:
    return left == right or left.endswith(f".{right}") or right.endswith(f".{left}")
