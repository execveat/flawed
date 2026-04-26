"""Tests for the L1 type-enrichment declared-type oracle."""

from __future__ import annotations

import sys
import time
from typing import TYPE_CHECKING

import pytest

import flawed._index._mypy_batch_oracle as mypy_batch
import flawed._index._type_enrichment as type_enrichment
from flawed._index._mypy_batch_oracle import MypyBatchOracle
from flawed._index._structural import extract_structural
from flawed._index._type_enrichment import (
    BasedPyrightOracle,
    TypeEnrichmentIndex,
    TypeFact,
    TypeQuery,
    build_type_enrichment_index,
    queries_from_assignments,
)
from flawed._index._types import ErrorKind, ExtractionError, ExtractionProvenance, SourceSpan

# _type_enrichment imports managed_process/shutil at module scope and the tests
# patch those module attributes; mypy's no-implicit-reexport doesn't treat an
# imported module as an exported attribute, so alias them once here.
_te_process = type_enrichment.managed_process  # type: ignore[attr-defined]
_te_shutil = type_enrichment.shutil  # type: ignore[attr-defined]

if TYPE_CHECKING:
    from pathlib import Path

_PROV = ExtractionProvenance(
    producer="test",
    producer_version="0.0.0",
    artifact="test",
)


def _sleeping_mypy_build_worker(
    _repo_root_raw: str,
    _max_source_files: int,
    _cache_dir_raw: str | None,
    _result_path_raw: str,
) -> None:
    time.sleep(60)


def _write_app(tmp_path: Path, source: str) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(source, encoding="utf-8")
    return repo


def _query(expression: str = "value") -> TypeQuery:
    return TypeQuery(
        expression=expression,
        location=SourceSpan(file="app.py", line=1, column=0, end_line=1, end_column=5),
        reveal_after_line=1,
        containing_function_fqn=None,
    )


def _fact(
    expression: str = "value",
    declared_type: str = "int",
    *,
    source_tool: str = "test",
    is_concrete: bool = True,
    containing_function_fqn: str | None = None,
) -> TypeFact:
    return TypeFact(
        expression=expression,
        declared_type=declared_type,
        location=SourceSpan(file="app.py", line=1, column=0, end_line=1, end_column=5),
        source_tool=source_tool,
        is_concrete=is_concrete,
        provenance=_PROV,
        containing_function_fqn=containing_function_fqn,
    )


def test_assignment_targets_become_declared_type_queries(tmp_path: Path) -> None:
    repo = _write_app(
        tmp_path,
        """\
def view(raw: int) -> None:
    normalized = raw + 1
""",
    )
    structural = extract_structural(repo)

    queries = queries_from_assignments(structural.assignments)

    assert queries == (
        TypeQuery(
            expression="normalized",
            location=SourceSpan(
                file="app.py",
                line=2,
                column=4,
                end_line=2,
                end_column=14,
            ),
            reveal_after_line=2,
            containing_function_fqn="app.view",
        ),
    )


def test_basedpyright_reveal_probe_returns_declared_type(tmp_path: Path) -> None:
    repo = _write_app(
        tmp_path,
        """\
def view(raw: int) -> None:
    normalized = raw + 1
""",
    )
    structural = extract_structural(repo)
    query = queries_from_assignments(structural.assignments)[0]

    index = build_type_enrichment_index(repo, (query,))

    assert index.errors == ()
    assert len(index.facts) == 1
    fact = index.type_for(query)
    assert fact is not None
    assert fact.declared_type == "int"
    assert fact.is_concrete is True
    assert fact.source_tool == "basedpyright"


def test_type_enrichment_index_preserves_multiple_tool_facts() -> None:
    query = _query()
    imprecise = _fact(declared_type="Any", source_tool="mypy", is_concrete=False)
    concrete = _fact(declared_type="int", source_tool="basedpyright")

    index = TypeEnrichmentIndex(facts=(imprecise, concrete))

    assert index.types_for(query) == (imprecise, concrete)
    assert index.type_for(query) == concrete


def test_type_enrichment_index_preserves_concrete_tool_disagreement() -> None:
    query = _query()
    mypy_fact = _fact(declared_type="str", source_tool="mypy")
    basedpyright_fact = _fact(declared_type="int", source_tool="basedpyright")

    index = TypeEnrichmentIndex(facts=(mypy_fact, basedpyright_fact))

    assert index.types_for(query) == (mypy_fact, basedpyright_fact)
    assert index.type_for(query) is None


def test_type_enrichment_index_scopes_expression_lookup_by_function() -> None:
    handler_fact = _fact(
        declared_type="sqlalchemy.sql.dml.Delete",
        containing_function_fqn="app.handler",
    )
    sibling_fact = _fact(
        declared_type="sqlalchemy.sql.dml.Update",
        containing_function_fqn="app.sibling",
    )
    index = TypeEnrichmentIndex(facts=(sibling_fact, handler_fact))

    assert index.types_for_expression(
        "value",
        "app.py",
        containing_function_fqn="app.handler",
    ) == (handler_fact,)


def test_build_type_enrichment_index_mypy_batch_opt_in_merges_tool_facts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _write_app(tmp_path, "value = 1\n")
    query = _query()
    mypy_error = ExtractionError(
        file="app.py",
        pass_name="mypy_batch_type_enrichment",
        error_kind=ErrorKind.MYPY,
        message="mypy returned imprecise type",
        is_fatal=False,
        location=query.location,
    )

    class FakeMypyBatchOracle:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def run(self, _repo_root: Path, _queries: tuple[TypeQuery, ...]) -> TypeEnrichmentIndex:
            return TypeEnrichmentIndex(
                facts=(_fact(declared_type="str", source_tool="mypy"),),
                errors=(mypy_error,),
            )

    class FakeBasedPyrightOracle:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def run(self, _repo_root: Path, _queries: tuple[TypeQuery, ...]) -> TypeEnrichmentIndex:
            return TypeEnrichmentIndex(
                facts=(_fact(declared_type="int", source_tool="basedpyright"),)
            )

    monkeypatch.setattr(mypy_batch, "MypyBatchOracle", FakeMypyBatchOracle)
    monkeypatch.setattr(type_enrichment, "BasedPyrightOracle", FakeBasedPyrightOracle)

    index = build_type_enrichment_index(repo, (query,), enable_mypy_batch=True)

    assert [fact.source_tool for fact in index.types_for(query)] == ["mypy", "basedpyright"]
    assert {fact.declared_type for fact in index.types_for(query)} == {"str", "int"}
    assert index.errors == (mypy_error,)


def test_type_enrichment_index_error_only_is_not_empty() -> None:
    error = ExtractionError(
        file="app.py",
        pass_name="mypy_batch_type_enrichment",
        error_kind=ErrorKind.MYPY,
        message="mypy unavailable",
        is_fatal=False,
        location=None,
    )

    index = TypeEnrichmentIndex(errors=(error,))

    assert bool(index) is True
    assert len(index) == 0
    assert index.errors == (error,)


def test_mypy_batch_snapshot_indexes_expression_types(tmp_path: Path) -> None:
    repo = _write_app(
        tmp_path,
        """\
def view(raw: int) -> None:
    normalized = raw + 1
    rendered = str(normalized)
""",
    )

    snapshot = MypyBatchOracle().build_snapshot(repo)

    fact = snapshot.type_at("app.py", 2, 4, expression="normalized")
    assert snapshot.errors == ()
    assert fact is not None
    assert fact.declared_type == "int"
    assert fact.is_concrete is True
    assert fact.source_tool == "mypy"
    assert snapshot.coverage.typed_expressions >= 5
    assert snapshot.coverage.concrete_ratio > 0.0


def test_mypy_batch_oracle_returns_query_fact(tmp_path: Path) -> None:
    repo = _write_app(
        tmp_path,
        """\
def view(raw: int) -> None:
    normalized = raw + 1
""",
    )
    structural = extract_structural(repo)
    query = queries_from_assignments(structural.assignments)[0]

    index = build_type_enrichment_index(repo, (query,), oracle=MypyBatchOracle())

    assert index.errors == ()
    assert len(index.facts) == 1
    assert index.facts[0].expression == "normalized"
    assert index.facts[0].declared_type == "int"
    assert index.facts[0].source_tool == "mypy"


def test_mypy_batch_imprecise_result_records_error(tmp_path: Path) -> None:
    repo = _write_app(
        tmp_path,
        """\
def view(raw):
    value = raw
""",
    )
    structural = extract_structural(repo)
    query = queries_from_assignments(structural.assignments)[0]

    index = build_type_enrichment_index(repo, (query,), oracle=MypyBatchOracle())

    assert index.facts[0].declared_type == "Any"
    assert index.facts[0].is_concrete is False
    assert any(error.error_kind is ErrorKind.MYPY for error in index.errors)
    assert any("imprecise type" in error.message for error in index.errors)


def test_mypy_batch_unavailable_records_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _write_app(tmp_path, "value = 1\n")
    query = _query()

    def fail_import(_name: str) -> object:
        raise ImportError("missing mypy")

    monkeypatch.setattr(mypy_batch, "import_module", fail_import)

    index = build_type_enrichment_index(repo, (query,), oracle=MypyBatchOracle())

    assert index.facts == ()
    assert len(index.errors) == 1
    assert index.errors[0].error_kind is ErrorKind.MYPY
    assert "mypy unavailable" in index.errors[0].message


def test_basedpyright_unknown_result_is_nonfatal_error(tmp_path: Path) -> None:
    repo = _write_app(
        tmp_path,
        """\
def view(raw):
    value = raw
""",
    )
    structural = extract_structural(repo)
    query = queries_from_assignments(structural.assignments)[0]

    index = build_type_enrichment_index(repo, (query,))

    assert index.facts[0].declared_type in {"Any", "Unknown"}
    assert index.facts[0].is_concrete is False
    assert any(error.error_kind is ErrorKind.BASEDPYRIGHT for error in index.errors)
    assert any("imprecise type" in error.message for error in index.errors)


def test_unparseable_basedpyright_output_records_missing_reveal_error(tmp_path: Path) -> None:
    repo = _write_app(tmp_path, "value = 1\n")
    query = TypeQuery(
        expression="value",
        location=SourceSpan(file="app.py", line=1, column=0, end_line=1, end_column=5),
        reveal_after_line=1,
        containing_function_fqn=None,
    )
    oracle = BasedPyrightOracle(
        command=(sys.executable, "-c", "print('not json')"),
        timeout_seconds=5,
    )

    index = oracle.run(repo, (query,))

    assert index.facts == ()
    assert len(index.errors) == 1
    assert index.errors[0].error_kind is ErrorKind.BASEDPYRIGHT
    assert "no reveal_type diagnostic" in index.errors[0].message


def test_multiline_assignment_generates_correct_reveal_line(tmp_path: Path) -> None:
    repo = _write_app(
        tmp_path,
        """\
def view():
    result = (
        some_func(1, 2)
    )
    x = 1
""",
    )
    structural = extract_structural(repo)

    queries = queries_from_assignments(structural.assignments)

    # The multiline assignment: target on line 2, value spans to line 3.
    # reveal_after_line must follow the value end (line 3), not the target (line 2).
    result_query = next(q for q in queries if q.expression == "result")
    assert result_query.location.line == 2
    assert result_query.reveal_after_line > result_query.location.line
    # The single-line assignment for `x` has reveal_after_line on its own line.
    x_query = next(q for q in queries if q.expression == "x")
    assert x_query.reveal_after_line == 5


def test_missing_source_file_records_error(tmp_path: Path) -> None:
    repo = _write_app(tmp_path, "value = 1\n")
    query = TypeQuery(
        expression="missing_var",
        location=SourceSpan(
            file="nonexistent.py",
            line=1,
            column=0,
            end_line=1,
            end_column=11,
        ),
        reveal_after_line=1,
        containing_function_fqn=None,
    )

    index = build_type_enrichment_index(repo, (query,))

    assert index.facts == ()
    assert len(index.errors) == 1
    assert index.errors[0].error_kind is ErrorKind.BASEDPYRIGHT
    assert "probe source file not found" in index.errors[0].message
    assert "nonexistent.py" in index.errors[0].message


def _fake_completed_process_run(calls: list[object]) -> object:
    """Return a ``managed_process.run`` stand-in that records calls and yields no facts.

    Each call appends its ``args`` to *calls* and returns an empty successful
    process, so a test can count how many basedpyright invocations (batches)
    happened without running the real, slow oracle.
    """

    def _run(args: object, **_kwargs: object) -> object:
        calls.append(args)
        return _te_process.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    return _run


def test_basedpyright_runs_once_over_all_files_regardless_of_query_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # FLAW-268: queries across many files (and over the legacy max_queries budget)
    # are enriched in a SINGLE basedpyright invocation over one workspace — never
    # split into multiple full-project re-checks, never skipped repo-wide.
    repo = _write_app(tmp_path, "first = 1\n")
    (repo / "second.py").write_text("second = 2\n", encoding="utf-8")
    queries = (
        _query("first"),
        TypeQuery(
            expression="second",
            location=SourceSpan(file="second.py", line=1, column=0, end_line=1, end_column=6),
            reveal_after_line=1,
            containing_function_fqn=None,
        ),
    )

    copytree_calls: list[object] = []
    real_copytree = _te_shutil.copytree

    def _counting_copytree(*args: object, **kwargs: object) -> object:
        copytree_calls.append(args)
        return real_copytree(*args, **kwargs)

    run_calls: list[object] = []
    monkeypatch.setattr(_te_shutil, "copytree", _counting_copytree)
    monkeypatch.setattr(_te_process, "run", _fake_completed_process_run(run_calls))

    index = BasedPyrightOracle(max_queries=1).run(repo, queries)

    # No repo-wide cap abort, and the legacy max_queries budget no longer splits.
    assert not any("exceeds limit" in error.message for error in index.errors)
    assert len(run_calls) == 1  # single invocation over both files
    assert len(copytree_calls) == 1  # one shared workspace


def test_basedpyright_probe_file_budget_no_longer_splits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # FLAW-268: max_probe_files is retained for config compatibility but no longer
    # splits the run — all probe files go through one basedpyright invocation.
    repo = _write_app(tmp_path, "value = 1\n")
    (repo / "other.py").write_text("other = 2\n", encoding="utf-8")
    queries = (
        _query("value"),
        TypeQuery(
            expression="other",
            location=SourceSpan(file="other.py", line=1, column=0, end_line=1, end_column=5),
            reveal_after_line=1,
            containing_function_fqn=None,
        ),
    )

    run_calls: list[object] = []
    monkeypatch.setattr(_te_process, "run", _fake_completed_process_run(run_calls))

    index = BasedPyrightOracle(max_probe_files=1).run(repo, queries)

    assert not any("exceeds limit" in error.message for error in index.errors)
    assert len(run_calls) == 1


def test_basedpyright_source_file_limit_fails_before_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _write_app(tmp_path, "value = 1\n")
    (repo / "extra.py").write_text("extra = 2\n", encoding="utf-8")
    monkeypatch.setattr(_te_shutil, "copytree", _fail_if_called)

    index = BasedPyrightOracle(max_source_files=1).run(repo, (_query(),))

    assert index.facts == ()
    assert len(index.errors) == 1
    assert index.errors[0].location is None
    assert "source file count 2 exceeds limit 1" in index.errors[0].message


def test_basedpyright_workspace_byte_limit_fails_before_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _write_app(tmp_path, "value = 1\n")
    (repo / "asset.txt").write_text("x" * 64, encoding="utf-8")
    monkeypatch.setattr(_te_shutil, "copytree", _fail_if_called)

    index = BasedPyrightOracle(max_workspace_bytes=8).run(repo, (_query(),))

    assert index.facts == ()
    assert len(index.errors) == 1
    assert index.errors[0].location is None
    assert "workspace input bytes" in index.errors[0].message
    assert "exceeds limit 8" in index.errors[0].message


def test_basedpyright_timeout_records_error(tmp_path: Path) -> None:
    repo = _write_app(tmp_path, "value = 1\n")
    query = TypeQuery(
        expression="value",
        location=SourceSpan(file="app.py", line=1, column=0, end_line=1, end_column=5),
        reveal_after_line=1,
        containing_function_fqn=None,
    )
    oracle = BasedPyrightOracle(
        command=(sys.executable, "-c", "import time; time.sleep(60)"),
        timeout_seconds=1,
    )

    index = oracle.run(repo, (query,))

    assert index.facts == ()
    assert len(index.errors) == 1
    assert index.errors[0].error_kind is ErrorKind.BASEDPYRIGHT
    assert "timed out" in index.errors[0].message


def test_no_reveal_diagnostic_records_error(tmp_path: Path) -> None:
    repo = _write_app(tmp_path, "value = 1\n")
    query = TypeQuery(
        expression="value",
        location=SourceSpan(file="app.py", line=1, column=0, end_line=1, end_column=5),
        reveal_after_line=1,
        containing_function_fqn=None,
    )
    # Emit valid basedpyright JSON with zero diagnostics.
    oracle = BasedPyrightOracle(
        command=(
            sys.executable,
            "-c",
            "import json; print(json.dumps({'generalDiagnostics': []}))",
        ),
        timeout_seconds=5,
    )

    index = oracle.run(repo, (query,))

    assert index.facts == ()
    assert len(index.errors) == 1
    assert index.errors[0].error_kind is ErrorKind.BASEDPYRIGHT
    assert "no reveal_type diagnostic" in index.errors[0].message


def test_basedpyright_oserror_records_error(tmp_path: Path) -> None:
    repo = _write_app(tmp_path, "value = 1\n")
    query = TypeQuery(
        expression="value",
        location=SourceSpan(file="app.py", line=1, column=0, end_line=1, end_column=5),
        reveal_after_line=1,
        containing_function_fqn=None,
    )
    oracle = BasedPyrightOracle(
        command=("/nonexistent/binary/path",),
        timeout_seconds=5,
    )

    index = oracle.run(repo, (query,))

    assert index.facts == ()
    assert len(index.errors) == 1
    assert index.errors[0].error_kind is ErrorKind.BASEDPYRIGHT
    assert "failed to start" in index.errors[0].message


# ── P10.10b guardrail tests ──────────────────────────────────────────


def test_mypy_batch_oracle_default_params() -> None:
    oracle = MypyBatchOracle()

    assert oracle._timeout_seconds == 120
    assert oracle._max_source_files == 5000
    assert oracle._cache_dir is None


def test_basedpyright_oracle_default_caps() -> None:
    oracle = BasedPyrightOracle()

    # FLAW-268: the default timeout is 120s (was a hardcoded 30s that silently
    # dropped type facts on cold full-project checks of large repos).
    assert oracle._timeout_seconds == 120
    assert oracle._max_queries == 2000
    assert oracle._max_probe_files == 500
    assert oracle._max_source_files == 5000
    assert oracle._max_workspace_bytes == 250_000_000


def test_build_type_enrichment_index_threads_basedpyright_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # FLAW-268: the configured basedpyright timeout reaches the oracle (replacing
    # the old hardcoded 30s that the builder never overrode).
    repo = _write_app(tmp_path, "value = 1\n")
    captured: dict[str, object] = {}

    class FakeBasedPyrightOracle:
        def __init__(self, *, timeout_seconds: int, **_kwargs: object) -> None:
            captured["timeout_seconds"] = timeout_seconds

        def run(self, _repo_root: Path, _queries: tuple[TypeQuery, ...]) -> TypeEnrichmentIndex:
            return TypeEnrichmentIndex.empty()

    monkeypatch.setattr(type_enrichment, "BasedPyrightOracle", FakeBasedPyrightOracle)

    build_type_enrichment_index(repo, (_query(),), basedpyright_timeout_seconds=275)

    assert captured["timeout_seconds"] == 275


def test_default_probe_config_is_written_without_repo_pyright_config(tmp_path: Path) -> None:
    repo = _write_app(tmp_path, "value = 1\n")

    type_enrichment._write_default_probe_config(repo)

    content = (repo / "pyrightconfig.json").read_text(encoding="utf-8")
    assert '"reportMissingImports": "none"' in content
    assert '"reportUnknownMemberType": "none"' in content


def test_default_probe_config_preserves_existing_pyproject_config(tmp_path: Path) -> None:
    repo = _write_app(tmp_path, "value = 1\n")
    (repo / "pyproject.toml").write_text("[tool.basedpyright]\nstrict = ['app.py']\n")

    type_enrichment._write_default_probe_config(repo)

    assert not (repo / "pyrightconfig.json").exists()


def test_mypy_batch_source_limit_records_error(tmp_path: Path) -> None:
    repo = _write_app(tmp_path, "value = 1\n")
    (repo / "extra.py").write_text("extra = 2\n", encoding="utf-8")
    oracle = MypyBatchOracle(max_source_files=1)

    snapshot = oracle.build_snapshot(repo)

    assert snapshot.coverage.typed_expressions == 0
    assert len(snapshot.errors) == 1
    assert snapshot.errors[0].error_kind is ErrorKind.MYPY
    assert "exceeding limit" in snapshot.errors[0].message


def test_mypy_batch_timeout_records_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _write_app(tmp_path, "value = 1\n")
    oracle = MypyBatchOracle(timeout_seconds=1)

    monkeypatch.setattr(mypy_batch, "_mypy_build_worker", _sleeping_mypy_build_worker)

    snapshot = oracle.build_snapshot(repo)

    assert snapshot.coverage.typed_expressions == 0
    assert len(snapshot.errors) == 1
    assert snapshot.errors[0].error_kind is ErrorKind.MYPY
    assert "timed out" in snapshot.errors[0].message


def test_mypy_batch_cache_dir_creates_cache(tmp_path: Path) -> None:
    repo = _write_app(tmp_path, "value: int = 1\n")
    cache = tmp_path / "cache"
    cache.mkdir()
    oracle = MypyBatchOracle(cache_dir=cache)

    first = oracle.build_snapshot(repo)
    second = oracle.build_snapshot(repo)

    assert first.coverage.typed_expressions > 0
    assert second.coverage.typed_expressions == first.coverage.typed_expressions
    assert second.type_at("app.py", 1, 0, expression="value") is not None
    assert (cache / ".mypy_cache").is_dir()
    assert (cache / "flawed-mypy-batch-cache-key.json").is_file()


def _fail_if_called(*_args: object, **_kwargs: object) -> object:
    pytest.fail("unexpected copy/subprocess after basedpyright cap exhaustion")


def test_mypy_batch_finds_repo_venv(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    venv_bin = repo / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    (repo / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (venv_bin / "python").symlink_to(sys.executable)

    result = mypy_batch._find_repo_python(repo)

    assert result is not None
    assert ".venv/bin/python" in result


def test_mypy_batch_ignores_invalid_repo_venv(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    venv_bin = repo / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").write_text("#!/bin/sh\n", encoding="utf-8")
    (venv_bin / "python").chmod(0o755)

    result = mypy_batch._find_repo_python(repo)

    assert result is None


def test_mypy_batch_no_venv_returns_none(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    result = mypy_batch._find_repo_python(repo)

    assert result is None


def test_mypy_batch_excludes_vendor_dirs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    vendor = repo / "vendor"
    vendor.mkdir()
    (vendor / "lib.py").write_text("vendored: str = 'hello'\n", encoding="utf-8")
    (repo / "app.py").write_text(
        "from vendor.lib import vendored\nvalue: str = vendored\n",
        encoding="utf-8",
    )
    migrations = repo / "migrations"
    migrations.mkdir()
    (migrations / "0001_initial.py").write_text("migrated: bool = True\n", encoding="utf-8")

    snapshot = MypyBatchOracle().build_snapshot(repo)

    assert snapshot.facts_for_file("app.py")
    assert not snapshot.facts_for_file("vendor/lib.py")
    assert not snapshot.facts_for_file("migrations/0001_initial.py")
