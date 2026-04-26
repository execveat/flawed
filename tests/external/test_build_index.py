"""End-to-end test: build a CodeIndex from fixture repositories.

These tests run the full L1 extraction pipeline (Steps 1-7) on the
sample apps in ``tests/fixtures/apps/``.  External extraction is stubbed by default so
structural-pipeline assertions stay hermetic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import libcst as cst
import pytest

import flawed._index._pipeline as pipeline
from flawed._index._pipeline import build_index
from flawed._index._structural import extract_structural
from flawed._index._type_enrichment import TypeEnrichmentIndex
from flawed._index._types import (
    ErrorKind,
    ExtractionError,
    FlowKind,
    FunctionKind,
)

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "apps"

if TYPE_CHECKING:
    from collections.abc import Iterable

    from flawed._index._type_enrichment import TypeQuery

# These tests intentionally call build_index() directly to test the L1
# pipeline itself.  Each call runs extraction from scratch (~0.5s per small
# fixture).  The timing guard is bypassed via @pytest.mark.slow.
pytestmark = pytest.mark.slow


class TestBuildIndexMinimal:
    """Pipeline on the minimal fixture (one function, one assignment)."""

    def test_builds_without_error(self) -> None:
        idx = build_index(_FIXTURES / "minimal")
        assert idx is not None

    def test_finds_functions(self) -> None:
        idx = build_index(_FIXTURES / "minimal")
        assert len(idx.functions) >= 1
        names = {fn.name for fn in idx.functions}
        assert "hello" in names

    def test_finds_assignments(self) -> None:
        """The module-level ``greeting = hello()`` should create a value-flow edge."""
        idx = build_index(_FIXTURES / "minimal")
        assert len(idx.value_flow._edges) >= 1

    def test_provenance_set(self) -> None:
        idx = build_index(_FIXTURES / "minimal")
        assert idx.provenance.producer == "pipeline"

    def test_repo_root_set(self) -> None:
        root = _FIXTURES / "minimal"
        idx = build_index(root)
        assert idx.repo_root == root

    def test_writes_normalized_artifacts(self, tmp_path: Path, monkeypatch) -> None:

        build_index(
            _FIXTURES / "minimal",
            artifact_root=tmp_path,
        )

        assert (tmp_path / "normalized" / "summary.json").exists()
        assert (tmp_path / "normalized" / "functions.jsonl").exists()
        assert (tmp_path / "normalized" / "call_edges.jsonl").exists()

    def test_records_build_phase_timings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        phases: list[pipeline.IndexBuildPhase] = []

        idx = build_index(_FIXTURES / "minimal", phase_recorder=phases.append)

        phase_by_name = {phase.name: phase for phase in phases}
        assert tuple(phase_by_name) == (
            "l1_discover_python_files",
            "l1_libcst_extraction",
            "l1_cfg",
            "l1_fqn_canonicalize",
            "l1_call_graph",
            "l1_value_flow",
            "l1_type_enrichment",
            "l1_dominance",
        )
        assert all(phase.status == "completed" for phase in phases)
        assert all(phase.wall_ms >= 0 for phase in phases)
        assert phase_by_name["l1_libcst_extraction"].details["function_count"] == len(
            idx.functions
        )
        cfg_count = sum(1 for function in idx.functions if idx.cfg(function.fqn) is not None)
        assert phase_by_name["l1_cfg"].details["cfg_count"] == cfg_count
        assert phase_by_name["l1_value_flow"].details["edge_count"] == len(idx.value_flow._edges)

    def test_relative_repo_and_artifact_root_are_resolved(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("def hello():\n    return 'hi'\n", encoding="utf-8")
        artifact_root = tmp_path / "artifacts"

        monkeypatch.chdir(tmp_path)

        idx = build_index(
            Path("repo"),
            artifact_root=Path("artifacts"),
        )

        assert idx.repo_root == repo.resolve()
        assert (artifact_root / "normalized" / "summary.json").exists()

    def test_normalized_manifest_matches_artifact_contract(
        self, tmp_path: Path, monkeypatch
    ) -> None:

        build_index(
            _FIXTURES / "minimal",
            artifact_root=tmp_path,
        )

        normalized = tmp_path / "normalized"
        manifest_path = normalized / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        written_artifacts = {entry["path"] for entry in manifest["written_artifacts"]}
        assert written_artifacts == {
            "attributes.jsonl",
            "call_edges.jsonl",
            "cfgs.jsonl",
            "classes.jsonl",
            "decorators.jsonl",
            "errors.jsonl",
            "functions.jsonl",
            "imports.jsonl",
            "summary.json",
            "symbol_refs.jsonl",
            "type_enrichment.jsonl",
            "value_flow_edges.jsonl",
        }
        for relative_path in written_artifacts:
            assert (normalized / relative_path).exists()

        deferred_artifacts = {entry["path"]: entry for entry in manifest["deferred_artifacts"]}
        assert deferred_artifacts["aliases.jsonl"]["status"] == "internal_only"
        assert deferred_artifacts["assignments.jsonl"]["status"] == "internal_only"
        assert "cfgs.jsonl" not in deferred_artifacts  # FLAW-118: now persisted
        assert deferred_artifacts["type_enrichment.jsonl"]["status"] == "written"
        assert deferred_artifacts["locations.jsonl"]["status"] == "embedded"
        assert manifest["cfg_persistence"] == "written"

    def test_container_and_comprehension_value_flow_edges_are_written(
        self, tmp_path: Path, monkeypatch
    ) -> None:

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text(
            """\
def build(raw_items, count, name):
    payload = {"count": count, "name": name}
    labels = [item.label for item in raw_items]
    return payload, labels
"""
        )
        artifact_root = tmp_path / "artifacts"

        build_index(
            repo,
            artifact_root=artifact_root,
        )

        edges = [
            json.loads(line)
            for line in (artifact_root / "normalized" / "value_flow_edges.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line
        ]
        edge_triples = {(edge["source_expr"], edge["target_expr"], edge["kind"]) for edge in edges}
        assert ("count", "payload", FlowKind.ASSIGN.value) in edge_triples
        assert ("name", "payload", FlowKind.ASSIGN.value) in edge_triples
        assert (
            "raw_items",
            "item",
            FlowKind.COMPREHENSION_BINDING.value,
        ) in edge_triples

    def test_yield_and_attribute_write_value_flow_edges_are_written(
        self, tmp_path: Path, monkeypatch
    ) -> None:

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text(
            """\
class Config:
    def __init__(self):
        self.debug = True

def gen(items):
    for item in items:
        yield item.name
"""
        )
        artifact_root = tmp_path / "artifacts"

        build_index(
            repo,
            artifact_root=artifact_root,
        )

        edges = [
            json.loads(line)
            for line in (artifact_root / "normalized" / "value_flow_edges.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line
        ]
        edge_triples = {(edge["source_expr"], edge["target_expr"], edge["kind"]) for edge in edges}
        assert ("item.name", "yield", FlowKind.YIELD.value) in edge_triples
        assert ("True", "self.debug", FlowKind.ATTRIBUTE_WRITE.value) in edge_triples

    def test_dynamic_dispatch_metadata_written_to_call_edges(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text(
            """\
def run(handlers, action):
    return handlers[action]()
"""
        )

        build_index(
            repo,
            artifact_root=tmp_path / "artifacts",
        )

        call_edges_path = tmp_path / "artifacts" / "normalized" / "call_edges.jsonl"
        records = [
            json.loads(line) for line in call_edges_path.read_text(encoding="utf-8").splitlines()
        ]
        dynamic_edges = [
            record for record in records if record["unresolved_reason"] == "dynamic_dispatch_table"
        ]

        assert len(dynamic_edges) == 1
        assert dynamic_edges[0]["dynamic_dispatch_kind"] == "table"
        assert dynamic_edges[0]["resolution"] == "unresolved"

    def test_argument_and_return_value_flow_metadata_written(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text(
            """\
def helper(value, *, strict=False):
    return value


def run(raw):
    result = helper(raw, strict=True)
    return result
"""
        )

        build_index(
            repo,
            artifact_root=tmp_path / "artifacts",
        )

        value_flow_path = tmp_path / "artifacts" / "normalized" / "value_flow_edges.jsonl"
        records = [
            json.loads(line) for line in value_flow_path.read_text(encoding="utf-8").splitlines()
        ]
        argument_edges = [record for record in records if record["kind"] == "argument"]
        return_edges = [record for record in records if record["kind"] == "return"]

        assert len(argument_edges) == 2
        raw_edge = next(record for record in argument_edges if record["source_expr"] == "raw")
        strict_edge = next(record for record in argument_edges if record["source_expr"] == "True")
        assert raw_edge["target_expr"] == "helper"
        assert raw_edge["callsite_callee_fqn"] == "app.helper"
        assert raw_edge["callsite_expr"] == "helper"
        assert raw_edge["argument_position"] == 0
        assert raw_edge["argument_keyword"] is None
        assert strict_edge["argument_position"] is None
        assert strict_edge["argument_keyword"] == "strict"

        assert {record["source_expr"] for record in return_edges} == {"value", "result"}
        for record in return_edges:
            assert record["target_expr"] == "return"
            assert record["argument_position"] is None
            assert record["argument_keyword"] is None

    def test_chained_assignment_produces_chain_edges(self, tmp_path: Path, monkeypatch) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text(
            """\
def process():
    x = y = compute()
    a, b = 1, 2
"""
        )

        build_index(
            repo,
            artifact_root=tmp_path / "artifacts",
        )

        value_flow_path = tmp_path / "artifacts" / "normalized" / "value_flow_edges.jsonl"
        records = [
            json.loads(line) for line in value_flow_path.read_text(encoding="utf-8").splitlines()
        ]

        # Chained assignment: x = y = compute() should produce chain edges.
        # Structural pass emits targets left-to-right: x first, then y.
        # Chain link follows source order: x → y.
        chain_edges = [r for r in records if r["kind"] == "chain"]
        assert len(chain_edges) == 1
        assert chain_edges[0]["source_expr"] == "x"
        assert chain_edges[0]["target_expr"] == "y"

        # Per-element unpacking: a, b = 1, 2 should produce 2 unpack edges
        unpack_edges = [r for r in records if r["kind"] == "unpack"]
        assert len(unpack_edges) == 2
        unpack_pairs = {(r["source_expr"], r["target_expr"]) for r in unpack_edges}
        assert ("1", "a") in unpack_pairs
        assert ("2", "b") in unpack_pairs


class TestBuildIndexTypeEnrichment:
    """Pipeline wires type-enrichment probes into CodeIndex."""

    def test_default_pipeline_disables_mypy_batch(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("value = 1\n", encoding="utf-8")
        observed_flags: list[bool] = []

        def fake_build_type_enrichment_index(
            repo_root: Path,
            queries: Iterable[TypeQuery],
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
            oracle: object | None = None,
        ) -> TypeEnrichmentIndex:
            observed_flags.append(enable_mypy_batch)
            assert repo_root == repo.resolve()
            assert basedpyright_max_queries == 2000
            assert basedpyright_max_probe_files == 500
            assert basedpyright_max_source_files == 5000
            assert basedpyright_max_workspace_bytes == 250_000_000
            assert basedpyright_timeout_seconds == 120
            assert mypy_batch_timeout_seconds == 120
            assert mypy_batch_max_files == 5000
            assert mypy_batch_cache_dir is None
            assert oracle is None
            assert tuple(queries)
            return TypeEnrichmentIndex.empty()

        monkeypatch.setattr(
            pipeline,
            "build_type_enrichment_index",
            fake_build_type_enrichment_index,
        )

        pipeline.build_index(repo)

        assert observed_flags == [False]

    def test_mypy_batch_opt_in_preserves_mypy_errors(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("value = 1\n", encoding="utf-8")
        mypy_error = ExtractionError(
            file="app.py",
            pass_name="mypy_batch_type_enrichment",
            error_kind=ErrorKind.MYPY,
            message="mypy unavailable: test",
            is_fatal=False,
            location=None,
        )
        observed_flags: list[bool] = []

        def fake_build_type_enrichment_index(
            _repo_root: Path,
            _queries: Iterable[TypeQuery],
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
            oracle: object | None = None,
        ) -> TypeEnrichmentIndex:
            observed_flags.append(enable_mypy_batch)
            assert basedpyright_max_queries == 2000
            assert basedpyright_max_probe_files == 500
            assert basedpyright_max_source_files == 5000
            assert basedpyright_max_workspace_bytes == 250_000_000
            assert basedpyright_timeout_seconds == 120
            assert mypy_batch_timeout_seconds == 120
            assert mypy_batch_max_files == 5000
            assert mypy_batch_cache_dir is None
            assert oracle is None
            return TypeEnrichmentIndex(errors=(mypy_error,))

        monkeypatch.setattr(
            pipeline,
            "build_type_enrichment_index",
            fake_build_type_enrichment_index,
        )

        idx = pipeline.build_index(repo, enable_mypy_batch=True)

        assert observed_flags == [True]
        assert idx.type_enrichment.errors == (mypy_error,)
        assert any(error.error_kind is ErrorKind.MYPY for error in idx.errors)

    def test_typed_assignment_produces_type_enrichment_facts(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text(
            """\
def compute(raw: int) -> int:
    result = raw + 1
    return result
""",
            encoding="utf-8",
        )

        idx = build_index(repo)

        assert len(idx.type_enrichment) >= 1
        concrete_facts = [f for f in idx.type_enrichment.facts if f.is_concrete]
        assert len(concrete_facts) >= 1
        assert any(f.expression == "result" for f in concrete_facts)

    def test_untyped_assignment_records_enrichment_error(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text(
            """\
def compute(raw):
    value = raw
    return value
""",
            encoding="utf-8",
        )

        idx = build_index(repo)

        # basedpyright can't infer the type without annotations — should produce
        # an imprecision error or a "no reveal diagnostic" error.
        assert len(idx.type_enrichment.errors) >= 1


class TestBuildIndexFlaskBasic:
    """Pipeline on the flask_basic fixture (routes, request handling, db writes)."""

    def test_builds_without_error(self) -> None:
        idx = build_index(_FIXTURES / "flask_basic")
        assert idx is not None

    def test_finds_all_functions(self) -> None:
        idx = build_index(_FIXTURES / "flask_basic")
        names = {fn.name for fn in idx.functions}
        for expected in ("list_users", "create_user", "update_user", "profile", "get_db"):
            assert expected in names, f"Missing function: {expected}"

    def test_finds_decorators(self) -> None:
        idx = build_index(_FIXTURES / "flask_basic")
        assert len(idx.decorators) >= 4  # four @app.route decorators

    def test_finds_call_edges(self) -> None:
        """AST extraction should find call edges."""
        idx = build_index(_FIXTURES / "flask_basic")
        # The FQN resolution may vary, so just check the call graph has edges.
        total_edges = sum(len(idx.call_graph.edges_from(fn.fqn)) for fn in idx.functions)
        assert total_edges >= 1

    def test_finds_attribute_accesses(self) -> None:
        """request.json, g.get, session.get should be found."""
        idx = build_index(_FIXTURES / "flask_basic")
        assert len(idx.attributes) >= 1

    def test_cfg_built_for_functions(self) -> None:
        """At least some functions should have CFGs."""
        idx = build_index(_FIXTURES / "flask_basic")
        cfgs_built = sum(1 for fn in idx.functions if idx.cfg(fn.fqn) is not None)
        assert cfgs_built >= 1

    def test_cfg_reuses_structural_parse(self, tmp_path: Path, monkeypatch) -> None:
        """CFG construction should not re-parse files already parsed structurally."""

        repo = tmp_path / "repo"
        repo.mkdir()
        source = """\
def reachable(flag):
    if flag:
        return 1
    return 0
"""
        (repo / "app.py").write_text(source, encoding="utf-8")

        source_parse_count = 0
        real_parse_module = cst.parse_module

        def counting_parse_module(module_source, *args, **kwargs):
            nonlocal source_parse_count
            if module_source == source:
                source_parse_count += 1
            return real_parse_module(module_source, *args, **kwargs)

        monkeypatch.setattr(cst, "parse_module", counting_parse_module)

        idx = pipeline.build_index(repo)

        assert source_parse_count == 1
        assert idx.cfg("app.reachable") is not None

    def test_cfg_builds_during_structural_extraction(self, tmp_path: Path, monkeypatch) -> None:
        """CFG construction consumes each wrapper through the structural callback."""

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "first.py").write_text("def one():\n    return 1\n", encoding="utf-8")
        (repo / "second.py").write_text("def two():\n    return 2\n", encoding="utf-8")

        real_extract_structural = extract_structural
        callback_paths: list[str] = []
        parsed_files_arg = object()

        def tracking_extract_structural(*args, **kwargs):
            nonlocal parsed_files_arg
            parsed_files_arg = kwargs.get("parsed_files")
            per_file_callback = kwargs["per_file_callback"]

            def tracking_callback(parsed_file, functions):
                callback_paths.append(parsed_file.rel_path)
                return per_file_callback(parsed_file, functions)

            kwargs["per_file_callback"] = tracking_callback
            return real_extract_structural(*args, **kwargs)

        monkeypatch.setattr(pipeline, "extract_structural", tracking_extract_structural)

        idx = pipeline.build_index(repo)

        assert parsed_files_arg is None
        assert callback_paths == ["first.py", "second.py"]
        assert idx.cfg("first.one") is not None
        assert idx.cfg("second.two") is not None


class TestBuildIndexFlaskAddUrlRule:
    """Pipeline facts needed for imperative Flask route registration."""

    def test_module_level_add_url_rule_call_edges_survive_pipeline(self) -> None:
        idx = build_index(
            _FIXTURES / "semantic" / "flask_add_url_rule",
        )

        add_url_rule_edges = [
            edge
            for edge in idx.call_graph.edges
            if edge.caller_fqn == "<module>"
            and edge.callee_fqn == "flask_add_url_rule.app.app.add_url_rule"
        ]

        assert len(add_url_rule_edges) == 3
        assert {edge.location.line for edge in add_url_rule_edges} == {20, 21, 22}
        first_edge = next(edge for edge in add_url_rule_edges if edge.location.line == 20)
        assert [(arg.position, arg.keyword, arg.expression) for arg in first_edge.arguments] == [
            (0, None, '"/health"'),
            (None, "view_func", "health"),
        ]


class TestBuildIndexFunctions:
    """Pipeline on the functions fixture (helpers + main)."""

    def test_multi_file(self) -> None:
        idx = build_index(_FIXTURES / "functions")
        # Should find functions from both main.py and helpers.py
        files = {fn.file for fn in idx.functions}
        assert len(files) >= 2

    def test_extracts_assigned_lambdas(self) -> None:
        idx = build_index(_FIXTURES / "functions")

        lambdas = [fn for fn in idx.functions if fn.kind is FunctionKind.LAMBDA]

        assert len(lambdas) == 1
        assert lambdas[0].name == "transform"
        assert lambdas[0].parent_function == "main.with_lambda"

    def test_nested_functions_record_parent_function(self) -> None:
        idx = build_index(_FIXTURES / "functions")

        inner = next(fn for fn in idx.functions if fn.fqn == "main.with_nested.<locals>.inner")

        assert inner.parent_function == "main.with_nested"
        assert inner.is_nested is True


class TestBuildIndexClasses:
    """Pipeline on the classes fixture."""

    def test_finds_classes(self) -> None:
        idx = build_index(_FIXTURES / "classes")
        assert len(idx.classes) >= 1


class TestBuildIndexImports:
    """Pipeline on the imports fixture (cross-file imports)."""

    def test_finds_imports(self) -> None:
        idx = build_index(_FIXTURES / "imports")
        assert len(idx.imports) >= 1

    def test_symbols_resolve_relative_imports(self) -> None:
        idx = build_index(_FIXTURES / "imports")
        assert idx.symbols.resolve("process_data", "main.py") == ("imports.helpers.process_data")
        assert idx.symbols.resolve("t", "main.py") == "imports.helpers.transform"
