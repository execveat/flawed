"""Prototype mypy batch type oracle for Layer 1 type enrichment."""

from __future__ import annotations

import json
import multiprocessing
import os
import pickle
import re
import shutil
import tempfile
from collections import defaultdict
from contextlib import suppress
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import TYPE_CHECKING, cast

from flawed._index._type_enrichment import TypeEnrichmentIndex, TypeFact, TypeQuery
from flawed._index._types import ErrorKind, ExtractionError, ExtractionProvenance, SourceSpan

if TYPE_CHECKING:
    from collections.abc import Iterable
    from types import ModuleType


_PASS_NAME = "mypy_batch_type_enrichment"
_PASS_VERSION = "0.1.0"
MYPY_BATCH_ORACLE_VERSION = _PASS_VERSION
_SOURCE_TOOL = "mypy"
_IMPRECISE_MARKERS = ("Any", "Unknown", "Uninferable")
_CACHE_KEY_FILE = "flawed-mypy-batch-cache-key.json"
_TARGET_VENV_NAMES = (".venv", "venv", "env")
_SOURCE_EXCLUDES = (
    r"(^|/)(\.git|\.hg|\.mypy_cache|\.pytest_cache|\.ruff_cache|\.tox|\.nox|"
    r"\.venv|venv|env|node_modules|build|dist|__pycache__|"
    r"vendor|third_party|migrations|alembic|\.eggs|site-packages)(/|$)",
    r"_pb2(_grpc)?\.py$",
)
_SOURCE_EXCLUDE_PATTERNS = tuple(re.compile(pattern) for pattern in _SOURCE_EXCLUDES)
_CHILD_FIELDS = frozenset(
    {
        "args",
        "arguments",
        "base",
        "base_type_exprs",
        "body",
        "callee",
        "condlists",
        "decorators",
        "defs",
        "else_body",
        "else_expr",
        "expr",
        "exprs",
        "finally_body",
        "func",
        "handlers",
        "if_expr",
        "index",
        "indices",
        "initializer",
        "items",
        "key",
        "keys",
        "left",
        "left_expr",
        "lvalue",
        "lvalues",
        "op",
        "operands",
        "right",
        "rvalue",
        "sequence",
        "sequences",
        "then_expr",
        "try_body",
        "value",
        "values",
    }
)


class _SourceLimitError(Exception):
    """Raised when source file count exceeds the configured maximum."""


class _BuildTimeoutError(Exception):
    """Raised when the mypy build exceeds the wall-clock timeout."""


class _BuildWorkerError(Exception):
    """Raised when the isolated mypy worker fails before returning a result."""


@dataclass(frozen=True, slots=True)
class MypyBatchCoverage:
    """Coverage counters for a mypy batch snapshot."""

    typed_expressions: int
    concrete_expressions: int
    imprecise_expressions: int
    files_indexed: int
    build_errors: int

    @property
    def concrete_ratio(self) -> float:
        """Return the concrete expression ratio, or ``0.0`` for empty snapshots."""
        if self.typed_expressions == 0:
            return 0.0
        return self.concrete_expressions / self.typed_expressions


class MypyBatchSnapshot:
    """O(1) lookup view over expression types from one mypy batch build."""

    __slots__ = ("_errors", "_facts", "_facts_by_file", "_facts_by_position", "coverage")

    def __init__(
        self,
        facts: tuple[TypeFact, ...],
        errors: tuple[ExtractionError, ...],
        coverage: MypyBatchCoverage,
    ) -> None:
        self._facts = facts
        self._errors = errors
        self.coverage = coverage
        by_file: defaultdict[str, list[TypeFact]] = defaultdict(list)
        by_position: defaultdict[tuple[str, int, int], list[TypeFact]] = defaultdict(list)
        for fact in facts:
            by_file[fact.location.file].append(fact)
            by_position[(fact.location.file, fact.location.line, fact.location.column)].append(
                fact
            )
        self._facts_by_file = {file: tuple(file_facts) for file, file_facts in by_file.items()}
        self._facts_by_position = {
            position: tuple(position_facts) for position, position_facts in by_position.items()
        }

    @property
    def facts(self) -> tuple[TypeFact, ...]:
        """All indexed expression type facts."""
        return self._facts

    @property
    def errors(self) -> tuple[ExtractionError, ...]:
        """Non-fatal mypy build/indexing errors."""
        return self._errors

    def facts_for_file(self, file: str) -> tuple[TypeFact, ...]:
        """Return every indexed expression type for *file*."""
        return self._facts_by_file.get(file, ())

    def types_at(self, file: str, line: int, column: int) -> tuple[TypeFact, ...]:
        """Return every expression type starting at *file:line:column*."""
        return self._facts_by_position.get((file, line, column), ())

    def type_at(
        self,
        file: str,
        line: int,
        column: int,
        *,
        expression: str | None = None,
    ) -> TypeFact | None:
        """Return the best expression type at a source position."""
        candidates = self.types_at(file, line, column)
        if expression is not None:
            exact = tuple(fact for fact in candidates if fact.expression == expression)
            if exact:
                candidates = exact
        return _best_fact(candidates)


class MypyBatchOracle:
    """Process-isolated mypy ``build(export_types=True)`` batch oracle."""

    __slots__ = ("_cache_dir", "_max_source_files", "_timeout_seconds")

    def __init__(
        self,
        *,
        timeout_seconds: int = 120,
        max_source_files: int = 5000,
        cache_dir: Path | None = None,
    ) -> None:
        self._timeout_seconds = _validate_positive_int(
            timeout_seconds,
            name="timeout_seconds",
        )
        self._max_source_files = _validate_positive_int(
            max_source_files,
            name="max_source_files",
        )
        self._cache_dir = cache_dir.expanduser() if cache_dir is not None else None

    def run(self, repo_root: Path, queries: Iterable[TypeQuery]) -> TypeEnrichmentIndex:
        """Build once, then answer *queries* from the batch expression index."""
        query_tuple = tuple(queries)
        if not query_tuple:
            return TypeEnrichmentIndex.empty()

        snapshot = self.build_snapshot(repo_root)
        if snapshot.coverage.typed_expressions == 0 and snapshot.errors:
            return TypeEnrichmentIndex(errors=snapshot.errors)

        facts: list[TypeFact] = []
        errors = list(snapshot.errors)
        for query in query_tuple:
            fact = snapshot.type_at(
                query.location.file,
                query.location.line,
                query.location.column,
                expression=query.expression,
            )
            if fact is None:
                errors.append(_query_error(query, "mypy produced no batch type at query position"))
                continue

            query_fact = TypeFact(
                expression=query.expression,
                declared_type=fact.declared_type,
                location=query.location,
                source_tool=_SOURCE_TOOL,
                is_concrete=fact.is_concrete,
                provenance=fact.provenance,
                containing_function_fqn=query.containing_function_fqn,
            )
            facts.append(query_fact)
            if not query_fact.is_concrete:
                errors.append(
                    _query_error(
                        query,
                        f"mypy returned imprecise type {query_fact.declared_type!r} "
                        f"for {query.expression!r}",
                    )
                )

        return TypeEnrichmentIndex(facts=tuple(facts), errors=tuple(errors))

    def build_snapshot(self, repo_root: Path) -> MypyBatchSnapshot:
        """Run mypy once over *repo_root* and index all source expression types."""
        repo_root = repo_root.expanduser().resolve()
        try:
            result = _run_mypy_build_isolated(
                repo_root,
                max_source_files=self._max_source_files,
                timeout_seconds=self._timeout_seconds,
                cache_dir=self._cache_dir,
            )
        except _SourceLimitError as exc:
            return _empty_snapshot((_repo_error(repo_root, str(exc)),))
        except _BuildTimeoutError as exc:
            return _empty_snapshot((_repo_error(repo_root, str(exc)),))
        except _BuildWorkerError as exc:
            return _empty_snapshot((_repo_error(repo_root, str(exc)),))
        except Exception as exc:
            return _empty_snapshot((_repo_error(repo_root, f"mypy batch build failed: {exc}"),))

        if result.status != "ok":
            return _empty_snapshot((_repo_error(repo_root, result.message),))

        errors = tuple(_repo_error(repo_root, message) for message in result.errors)
        coverage = _coverage(result.facts, len(errors))
        return MypyBatchSnapshot(facts=result.facts, errors=errors, coverage=coverage)


@dataclass(frozen=True, slots=True)
class _MypyBuildResult:
    status: str
    facts: tuple[TypeFact, ...] = ()
    errors: tuple[str, ...] = ()
    message: str = ""


@dataclass(frozen=True, slots=True)
class _MypyApi:
    build_module: ModuleType
    find_sources_module: ModuleType
    fscache_module: ModuleType
    options_module: ModuleType


def _import_mypy_api() -> _MypyApi:
    return _MypyApi(
        build_module=import_module("mypy.build"),
        find_sources_module=import_module("mypy.find_sources"),
        fscache_module=import_module("mypy.fscache"),
        options_module=import_module("mypy.options"),
    )


def _run_mypy_build_isolated(
    repo_root: Path,
    *,
    max_source_files: int,
    timeout_seconds: int,
    cache_dir: Path | None,
) -> _MypyBuildResult:
    """Run mypy in a child process and return the serialized build result."""
    cache_dir = cache_dir.resolve() if cache_dir is not None else None
    with tempfile.TemporaryDirectory(prefix="flawed-mypy-batch-") as temp_dir:
        result_path = Path(temp_dir) / "result.pickle"
        context = multiprocessing.get_context(_process_start_method())
        process_factory = cast("type[multiprocessing.Process]", context.Process)  # type: ignore[attr-defined]
        process = process_factory(
            target=_mypy_build_worker,
            args=(
                str(repo_root),
                max_source_files,
                str(cache_dir) if cache_dir is not None else None,
                str(result_path),
            ),
        )
        process.start()
        process.join(timeout_seconds)

        if process.is_alive():
            process.terminate()
            process.join(5)
            if process.is_alive():
                process.kill()
                process.join()
            _discard_mypy_cache(cache_dir)
            raise _BuildTimeoutError(f"mypy build timed out after {timeout_seconds}s")

        if not result_path.is_file():
            raise _BuildWorkerError(
                f"mypy batch worker exited with code {process.exitcode} before returning a result"
            )
        return _read_worker_result(result_path)


def _process_start_method() -> str:
    """Return the safest available start method for local, bounded worker isolation."""
    if "fork" in multiprocessing.get_all_start_methods():
        return "fork"
    return "spawn"


def _mypy_build_worker(
    repo_root_raw: str,
    max_source_files: int,
    cache_dir_raw: str | None,
    result_path_raw: str,
) -> None:
    """Child-process entrypoint for mypy build/indexing."""
    repo_root = Path(repo_root_raw)
    result_path = Path(result_path_raw)
    cache_dir = Path(cache_dir_raw) if cache_dir_raw is not None else None
    try:
        api = _import_mypy_api()
    except ImportError as exc:
        _write_worker_result(
            result_path,
            _MypyBuildResult(status="error", message=f"mypy unavailable: {exc}"),
        )
        return

    try:
        result = _run_mypy_build(
            api,
            repo_root,
            max_source_files=max_source_files,
            cache_dir=cache_dir,
        )
    except _SourceLimitError as exc:
        _write_worker_result(
            result_path,
            _MypyBuildResult(status="error", message=str(exc)),
        )
        return
    except Exception as exc:
        _write_worker_result(
            result_path,
            _MypyBuildResult(status="error", message=f"mypy batch build failed: {exc}"),
        )
        return

    _write_worker_result(
        result_path,
        _MypyBuildResult(
            status="ok",
            facts=_facts_from_result(result, repo_root),
            errors=_build_errors(result),
        ),
    )


def _write_worker_result(path: Path, result: _MypyBuildResult) -> None:
    with path.open("wb") as handle:
        pickle.dump(result, handle, protocol=pickle.HIGHEST_PROTOCOL)


def _read_worker_result(path: Path) -> _MypyBuildResult:
    with path.open("rb") as handle:
        result = pickle.load(handle)
    if not isinstance(result, _MypyBuildResult):
        msg = f"mypy batch worker returned {type(result).__name__}, expected result"
        raise _BuildWorkerError(msg)
    return result


def _run_mypy_build(
    api: _MypyApi,
    repo_root: Path,
    *,
    max_source_files: int,
    cache_dir: Path | None,
) -> object:
    options = api.options_module.Options()
    options.export_types = True
    options.preserve_asts = True
    options.namespace_packages = True
    options.follow_imports = "normal"
    options.ignore_missing_imports = True
    options.exclude = list(_SOURCE_EXCLUDES)

    repo_python = _find_repo_python(repo_root)
    if repo_python is not None:
        options.python_executable = repo_python

    if cache_dir is not None:
        options.incremental = True
        options.use_fine_grained_cache = True
        options.cache_fine_grained = True
        options.cache_dir = str(cache_dir / ".mypy_cache")
    else:
        options.incremental = False

    fscache = api.fscache_module.FileSystemCache()
    sources = api.find_sources_module.create_source_list(
        [str(repo_root)],
        options,
        fscache,
        allow_empty_dir=True,
    )

    # Bounded source selection: refuse repos that exceed the file limit.
    if len(sources) > max_source_files:
        raise _SourceLimitError(
            f"repo has {len(sources)} source files, exceeding limit of {max_source_files}"
        )

    cache_key = _mypy_cache_key(
        repo_root=repo_root,
        sources=tuple(sources),
        repo_python=repo_python,
        api=api,
    )
    if cache_dir is not None:
        _prepare_mypy_cache(cache_dir, cache_key)

    result = api.build_module.build(sources=sources, options=options, fscache=fscache)
    if cache_dir is not None:
        _write_mypy_cache_key(cache_dir, cache_key)
    return result


def _validate_positive_int(value: int, *, name: str) -> int:
    if type(value) is not int or value < 1:
        msg = f"{name} must be a positive int, got {value!r}"
        raise ValueError(msg)
    return value


def _mypy_cache_key(
    *,
    repo_root: Path,
    sources: tuple[object, ...],
    repo_python: str | None,
    api: _MypyApi,
) -> dict[str, object]:
    source_entries: list[dict[str, object]] = []
    for source in sources:
        entry = _source_cache_entry(repo_root, source)
        if entry is not None:
            source_entries.append(entry)
    return {
        "schema_version": 1,
        "producer": _PASS_NAME,
        "producer_version": _PASS_VERSION,
        "mypy_version": _mypy_version(api),
        "repo_root": str(repo_root),
        "python_executable": repo_python,
        "source_excludes": _SOURCE_EXCLUDES,
        "options": {
            "export_types": True,
            "preserve_asts": True,
            "namespace_packages": True,
            "follow_imports": "normal",
            "ignore_missing_imports": True,
            "use_fine_grained_cache": True,
            "cache_fine_grained": True,
        },
        "sources": sorted(source_entries, key=lambda entry: str(entry["path"])),
    }


def _source_cache_entry(repo_root: Path, source: object) -> dict[str, object] | None:
    raw_path = getattr(source, "path", None)
    if not isinstance(raw_path, str):
        return None
    path = Path(raw_path).resolve()
    if not path.is_relative_to(repo_root):
        return None
    try:
        stat = path.stat()
    except OSError:
        return None
    return {
        "path": path.relative_to(repo_root).as_posix(),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def _mypy_version(api: _MypyApi) -> str:
    try:
        version_module = import_module("mypy.version")
    except ImportError:
        return "unknown"
    version = getattr(version_module, "__version__", None)
    if isinstance(version, str):
        return version
    version = getattr(api.build_module, "__version__", None)
    if isinstance(version, str):
        return version
    return "unknown"


def _prepare_mypy_cache(cache_dir: Path, cache_key: dict[str, object]) -> None:
    if _read_mypy_cache_key(cache_dir) == cache_key:
        cache_dir.mkdir(parents=True, exist_ok=True)
        return
    _discard_mypy_cache(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)


def _read_mypy_cache_key(cache_dir: Path) -> dict[str, object] | None:
    key_path = cache_dir / _CACHE_KEY_FILE
    try:
        raw = json.loads(key_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict):
        return None
    return cast("dict[str, object]", raw)


def _write_mypy_cache_key(cache_dir: Path, cache_key: dict[str, object]) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    key_path = cache_dir / _CACHE_KEY_FILE
    temp_path = key_path.with_suffix(".tmp")
    temp_path.write_text(
        json.dumps(cache_key, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    temp_path.replace(key_path)


def _discard_mypy_cache(cache_dir: Path | None) -> None:
    if cache_dir is None:
        return
    shutil.rmtree(cache_dir / ".mypy_cache", ignore_errors=True)
    with suppress(FileNotFoundError):
        (cache_dir / _CACHE_KEY_FILE).unlink()


def _find_repo_python(repo_root: Path) -> str | None:
    """Return the Python interpreter from the repo's own virtualenv, if any."""
    repo_root = repo_root.expanduser().resolve()
    for venv_name in _TARGET_VENV_NAMES:
        venv_root = repo_root / venv_name
        candidate = venv_root / "bin" / "python"
        if (venv_root / "pyvenv.cfg").is_file() and _is_executable_file(candidate):
            return str(candidate)
    return None


def _is_executable_file(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def _facts_from_result(result: object, repo_root: Path) -> tuple[TypeFact, ...]:
    types = cast("dict[object, object]", getattr(result, "types", {}))
    graph = cast("dict[str, object]", getattr(result, "graph", {}))
    facts: list[TypeFact] = []
    for state in graph.values():
        tree = getattr(state, "tree", None)
        tree_path = _source_tree_path(tree, repo_root)
        if tree_path is None:
            continue

        rel_file = tree_path.relative_to(repo_root).as_posix()
        lines = _read_lines(tree_path)
        for node in _walk_source_ast(tree):
            typ = types.get(node)
            if typ is None:
                continue
            fact = _fact_from_node(node, typ, rel_file, lines)
            if fact is not None:
                facts.append(fact)
    return tuple(facts)


def _source_tree_path(tree: object, repo_root: Path) -> Path | None:
    raw_path = getattr(tree, "path", None)
    if not isinstance(raw_path, str):
        return None
    path = Path(raw_path).resolve()
    if not path.is_relative_to(repo_root):
        return None
    rel_file = path.relative_to(repo_root).as_posix()
    if _is_excluded_source(rel_file):
        return None
    return path


def _is_excluded_source(rel_file: str) -> bool:
    return any(pattern.search(rel_file) for pattern in _SOURCE_EXCLUDE_PATTERNS)


def _read_lines(path: Path) -> tuple[str, ...]:
    try:
        return tuple(path.read_text(encoding="utf-8").splitlines())
    except (OSError, UnicodeDecodeError):
        return ()


def _walk_source_ast(root: object) -> tuple[object, ...]:
    seen: set[int] = set()
    nodes: list[object] = []
    stack = [root]
    while stack:
        node = stack.pop()
        identity = id(node)
        if identity in seen:
            continue
        seen.add(identity)
        nodes.append(node)
        stack.extend(reversed(tuple(_iter_child_nodes(node))))
    return tuple(nodes)


def _iter_child_nodes(node: object) -> tuple[object, ...]:
    children: list[object] = []
    for field in _CHILD_FIELDS:
        try:
            value = getattr(node, field)
        except AttributeError:
            continue
        children.extend(_node_values(value))
    return tuple(children)


def _node_values(value: object) -> tuple[object, ...]:
    if _looks_like_mypy_node(value):
        return (value,)
    if isinstance(value, tuple | list):
        nodes: list[object] = []
        for item in value:
            nodes.extend(_node_values(item))
        return tuple(nodes)
    return ()


def _looks_like_mypy_node(value: object) -> bool:
    return hasattr(value, "accept") and hasattr(value, "line")


def _fact_from_node(
    node: object,
    typ: object,
    rel_file: str,
    lines: tuple[str, ...],
) -> TypeFact | None:
    span = _span_from_node(node, rel_file)
    if span is None:
        return None

    declared_type = str(typ)
    expression = _source_fragment(lines, span) or _node_kind(node)
    return TypeFact(
        expression=expression,
        declared_type=declared_type,
        location=span,
        source_tool=_SOURCE_TOOL,
        is_concrete=not _is_imprecise_type(declared_type),
        provenance=ExtractionProvenance(
            producer=_PASS_NAME,
            producer_version=_PASS_VERSION,
            artifact=rel_file,
        ),
    )


def _span_from_node(node: object, rel_file: str) -> SourceSpan | None:
    line = _positive_int(getattr(node, "line", None))
    column = _nonnegative_int(getattr(node, "column", None))
    end_line = _positive_int(getattr(node, "end_line", None))
    end_column = _nonnegative_int(getattr(node, "end_column", None))
    if None in (line, column, end_line, end_column):
        return None
    return SourceSpan(
        file=rel_file,
        line=cast("int", line),
        column=cast("int", column),
        end_line=cast("int", end_line),
        end_column=cast("int", end_column),
    )


def _positive_int(value: object) -> int | None:
    if isinstance(value, int) and value >= 1:
        return value
    return None


def _nonnegative_int(value: object) -> int | None:
    if isinstance(value, int) and value >= 0:
        return value
    return None


def _source_fragment(lines: tuple[str, ...], span: SourceSpan) -> str | None:
    if not lines or span.line > len(lines) or span.end_line > len(lines):
        return None
    if span.line == span.end_line:
        return lines[span.line - 1][span.column : span.end_column]

    first = lines[span.line - 1][span.column :]
    middle = lines[span.line : span.end_line - 1]
    last = lines[span.end_line - 1][: span.end_column]
    return "\n".join((first, *middle, last)).strip()


def _node_kind(node: object) -> str:
    return type(node).__name__


def _is_imprecise_type(declared_type: str) -> bool:
    return declared_type == "object" or any(
        marker in declared_type for marker in _IMPRECISE_MARKERS
    )


def _best_fact(facts: tuple[TypeFact, ...]) -> TypeFact | None:
    if not facts:
        return None
    for fact in facts:
        if fact.is_concrete:
            return fact
    return facts[0]


def _coverage(facts: tuple[TypeFact, ...], build_errors: int) -> MypyBatchCoverage:
    concrete = sum(1 for fact in facts if fact.is_concrete)
    return MypyBatchCoverage(
        typed_expressions=len(facts),
        concrete_expressions=concrete,
        imprecise_expressions=len(facts) - concrete,
        files_indexed=len({fact.location.file for fact in facts}),
        build_errors=build_errors,
    )


def _build_errors(result: object) -> tuple[str, ...]:
    errors = getattr(result, "errors", ())
    if not isinstance(errors, list | tuple):
        return ()
    return tuple(str(error) for error in errors)


def _empty_snapshot(errors: tuple[ExtractionError, ...]) -> MypyBatchSnapshot:
    coverage = MypyBatchCoverage(
        typed_expressions=0,
        concrete_expressions=0,
        imprecise_expressions=0,
        files_indexed=0,
        build_errors=len(errors),
    )
    return MypyBatchSnapshot(facts=(), errors=errors, coverage=coverage)


def _repo_error(repo_root: Path, message: str) -> ExtractionError:
    return ExtractionError(
        file=str(repo_root),
        pass_name=_PASS_NAME,
        error_kind=ErrorKind.MYPY,
        message=message,
        is_fatal=False,
        location=None,
    )


def _query_error(query: TypeQuery, message: str) -> ExtractionError:
    return ExtractionError(
        file=query.location.file,
        pass_name=_PASS_NAME,
        error_kind=ErrorKind.MYPY,
        message=message,
        is_fatal=False,
        location=query.location,
    )
