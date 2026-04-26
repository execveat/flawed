"""Tests for L1 artifact caching (P10.3).

Verifies cache key management, cache hit/miss behaviour, forced
re-extraction, and round-trip fidelity of the JSONL artifact loader.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

import flawed._index._pipeline as pipeline
from flawed._config.paths import repo_content_hash
from flawed._index._pipeline import (
    _PIPELINE_VERSION,
    L1_SCHEMA_VERSION,
    CorruptCacheError,
    _write_jsonl,
    build_index,
    cache_key_matches,
    load_index_from_artifacts,
    read_file_manifest,
    record_schema_fingerprint,
    type_enrichment_signature,
    write_cache_key,
    write_file_manifest,
)
from flawed._index._type_enrichment import TypeEnrichmentIndex, TypeFact
from flawed._index._types import ErrorKind, ExtractionError, ExtractionProvenance, SourceSpan

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "apps"
_PROV = ExtractionProvenance(producer="test", producer_version="0.0.0", artifact="test")

pytestmark = pytest.mark.slow


# ── repo_content_hash ─────────────────────────────────────────────


class TestRepoContentHash:
    """Content hashing for cache keys."""

    def test_non_git_dir_returns_hash(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1\n")
        h = repo_content_hash(tmp_path)
        assert isinstance(h, str)
        assert len(h) == 32  # SHA-256 truncated to 32 hex chars

    def test_non_git_dir_changes_on_modification(self, tmp_path: Path) -> None:
        py = tmp_path / "app.py"
        py.write_text("x = 1\n")
        h1 = repo_content_hash(tmp_path)
        py.write_text("x = 2\n")
        h2 = repo_content_hash(tmp_path)
        assert h1 != h2

    def test_non_git_dir_ignores_irrelevant_python_trees(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1\n")
        h1 = repo_content_hash(tmp_path)

        for dirname in (".venv", "local", "cache", ".hidden", "__pycache__", "vendor"):
            noise_dir = tmp_path / dirname
            noise_dir.mkdir()
            (noise_dir / "noise.py").write_text("ignored = True\n")

        assert repo_content_hash(tmp_path) == h1

    def test_git_repo_returns_commit_hash(self, tmp_path: Path) -> None:
        import subprocess

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("x = 1\n")
        subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=repo,
            capture_output=True,
            check=False,
        )
        subprocess.run(
            ["git", "config", "user.name", "test"],
            cwd=repo,
            capture_output=True,
            check=False,
        )
        subprocess.run(["git", "add", "."], cwd=repo, capture_output=True, check=True)
        subprocess.run(
            ["git", "commit", "-m", "init"],
            cwd=repo,
            capture_output=True,
            check=True,
        )
        h = repo_content_hash(repo)
        assert len(h) == 40  # full SHA-1 commit hash

    def test_git_dirty_tree_changes_hash(self, tmp_path: Path) -> None:
        """Uncommitted changes must produce a different hash than HEAD."""
        import subprocess

        repo = tmp_path / "repo"
        repo.mkdir()
        py = repo / "app.py"
        py.write_text("x = 1\n")
        subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@test.com"],
            cwd=repo,
            capture_output=True,
            check=False,
        )
        subprocess.run(
            ["git", "config", "user.name", "test"],
            cwd=repo,
            capture_output=True,
            check=False,
        )
        subprocess.run(["git", "add", "."], cwd=repo, capture_output=True, check=True)
        subprocess.run(
            ["git", "commit", "-m", "init"],
            cwd=repo,
            capture_output=True,
            check=True,
        )
        clean_hash = repo_content_hash(repo)
        assert len(clean_hash) == 40  # clean — just the commit hash

        # Edit without committing
        py.write_text("x = 2\n")
        dirty_hash = repo_content_hash(repo)
        assert dirty_hash != clean_hash
        assert ":" in dirty_hash  # commit:dirty_suffix format


# ── Cache key management ──────────────────────────────────────────


class TestCacheKeyManagement:
    """write_cache_key / cache_key_matches round-trip."""

    def test_write_and_match(self, tmp_path: Path) -> None:
        write_cache_key(tmp_path, content_hash="abc123")
        assert cache_key_matches(tmp_path, content_hash="abc123")

    def test_mismatch_content_hash(self, tmp_path: Path) -> None:
        write_cache_key(tmp_path, content_hash="abc123")
        assert not cache_key_matches(tmp_path, content_hash="different")

    def test_missing_cache_key(self, tmp_path: Path) -> None:
        assert not cache_key_matches(tmp_path, content_hash="anything")

    def test_corrupt_cache_key(self, tmp_path: Path) -> None:
        (tmp_path / "cache_key.json").write_text("not valid json{{{")
        assert not cache_key_matches(tmp_path, content_hash="anything")

    def test_incomplete_cache_key(self, tmp_path: Path) -> None:
        (tmp_path / "cache_key.json").write_text('{"content_hash": "x"}\n')
        assert not cache_key_matches(tmp_path, content_hash="x")

    def test_pipeline_version_embedded(self, tmp_path: Path) -> None:
        write_cache_key(tmp_path, content_hash="abc")
        data = json.loads((tmp_path / "cache_key.json").read_text())
        assert data["pipeline_version"] == _PIPELINE_VERSION

    def test_schema_version_mismatch_is_cache_miss(self, tmp_path: Path, monkeypatch) -> None:
        """FLAW-344: the explicit L1_SCHEMA_VERSION gates validity."""
        write_cache_key(tmp_path, content_hash="abc")
        monkeypatch.setattr("flawed._index._pipeline.L1_SCHEMA_VERSION", "99-future")
        assert not cache_key_matches(tmp_path, content_hash="abc")

    def test_pipeline_version_bump_does_not_invalidate(self, tmp_path: Path, monkeypatch) -> None:
        """FLAW-344: pipeline_version is provenance now, NOT the validity gate."""
        write_cache_key(tmp_path, content_hash="abc")
        monkeypatch.setattr("flawed._index._pipeline._PIPELINE_VERSION", "99.99.99")
        assert cache_key_matches(tmp_path, content_hash="abc")

    def test_extraction_signature_change_does_not_invalidate(self, tmp_path: Path) -> None:
        """FLAW-344 (scheme C): extraction_code_signature is demoted to provenance,
        so a behaviour-preserving ``_index`` refactor (which moves the byte-hash
        but not the record schema) must NOT invalidate the cache. The anti-silent-FN
        guarantee moved to the commit-time gate (``tools.check_l1_schema``)."""
        write_cache_key(tmp_path, content_hash="abc", extraction_code_signature="sigA")
        assert cache_key_matches(tmp_path, content_hash="abc", extraction_code_signature="sigA")
        assert cache_key_matches(tmp_path, content_hash="abc", extraction_code_signature="sigB")

    def test_extraction_signature_embedded(self, tmp_path: Path) -> None:
        write_cache_key(tmp_path, content_hash="abc", extraction_code_signature="sigA")
        data = json.loads((tmp_path / "cache_key.json").read_text())
        assert data["extraction_code_signature"] == "sigA"

    def test_schema_fields_embedded(self, tmp_path: Path) -> None:
        """FLAW-344: the validity-gate fields are written into cache_key.json."""
        write_cache_key(tmp_path, content_hash="abc")
        data = json.loads((tmp_path / "cache_key.json").read_text())
        assert data["l1_schema_version"] == L1_SCHEMA_VERSION
        assert data["record_schema_fingerprint"] == record_schema_fingerprint()

    def test_legacy_cache_without_schema_fields_is_miss(self, tmp_path: Path) -> None:
        """A pre-FLAW-344 ``cache_key.json`` carries no schema version / fingerprint.
        Fail-closed on unknown: the absent fields must be treated as a mismatch
        (re-extract) rather than served as a hit — no fail-open onto stale artifacts."""
        (tmp_path / "cache_key.json").write_text(
            json.dumps(
                {
                    "content_hash": "abc",
                    "pipeline_version": _PIPELINE_VERSION,
                    "type_enrichment_signature": "",
                    "extraction_code_signature": "real-sig",
                }
            )
            + "\n"
        )
        assert not cache_key_matches(tmp_path, content_hash="abc")


class TestFileManifestSignature:
    """FLAW-344: the incremental file-manifest self-invalidates on an L1 schema
    change (version or record-schema fingerprint), so the incremental path cannot
    rebuild only the changed files against a new schema while leaving unchanged
    files' artifacts stale (a silent FN). The extraction byte-hash is provenance."""

    def test_extraction_signature_change_does_not_invalidate(self, tmp_path: Path) -> None:
        """A behaviour-preserving _index refactor (byte-hash moves, schema stable)
        keeps the manifest valid."""
        write_file_manifest(tmp_path, (), tmp_path, extraction_code_signature="sigA")
        assert read_file_manifest(tmp_path, extraction_code_signature="sigA") is not None
        assert read_file_manifest(tmp_path, extraction_code_signature="sigB") is not None

    def test_schema_version_mismatch_returns_none(self, tmp_path: Path) -> None:
        write_file_manifest(tmp_path, (), tmp_path)
        manifest_path = tmp_path / "file_manifest.json"
        data = json.loads(manifest_path.read_text())
        data["l1_schema_version"] = "99-future"
        manifest_path.write_text(json.dumps(data))
        assert read_file_manifest(tmp_path) is None

    def test_fingerprint_mismatch_returns_none(self, tmp_path: Path) -> None:
        write_file_manifest(tmp_path, (), tmp_path)
        manifest_path = tmp_path / "file_manifest.json"
        data = json.loads(manifest_path.read_text())
        data["record_schema_fingerprint"] = "deadbeefdeadbeef"
        manifest_path.write_text(json.dumps(data))
        assert read_file_manifest(tmp_path) is None

    def test_legacy_manifest_without_schema_fields_returns_none(self, tmp_path: Path) -> None:
        (tmp_path / "file_manifest.json").write_text(
            json.dumps({"pipeline_version": _PIPELINE_VERSION, "files": {}}) + "\n"
        )
        assert read_file_manifest(tmp_path) is None

    def test_schema_fields_embedded(self, tmp_path: Path) -> None:
        write_file_manifest(tmp_path, (), tmp_path, extraction_code_signature="sigA")
        data = json.loads((tmp_path / "file_manifest.json").read_text())
        assert data["l1_schema_version"] == L1_SCHEMA_VERSION
        assert data["record_schema_fingerprint"] == record_schema_fingerprint()
        assert data["extraction_code_signature"] == "sigA"  # provenance


# ── Artifact loader round-trip ────────────────────────────────────


class TestLoadIndexFromArtifacts:
    """JSONL deserialization produces a usable CodeIndex."""

    def test_roundtrip_preserves_functions(self, tmp_path: Path, monkeypatch) -> None:

        repo = _FIXTURES / "minimal"
        artifact_root = tmp_path / "artifacts"
        original = build_index(repo, artifact_root=artifact_root)

        loaded = load_index_from_artifacts(repo, artifact_root)

        assert len(loaded.functions) == len(original.functions)
        orig_names = {fn.name for fn in original.functions}
        loaded_names = {fn.name for fn in loaded.functions}
        assert orig_names == loaded_names

    def test_roundtrip_preserves_classes(self, tmp_path: Path, monkeypatch) -> None:

        repo = _FIXTURES / "flask_basic"
        artifact_root = tmp_path / "artifacts"
        original = build_index(repo, artifact_root=artifact_root)

        loaded = load_index_from_artifacts(repo, artifact_root)

        assert len(loaded.classes) == len(original.classes)

    def test_roundtrip_preserves_call_edges(self, tmp_path: Path, monkeypatch) -> None:

        repo = _FIXTURES / "functions"
        artifact_root = tmp_path / "artifacts"
        original = build_index(repo, artifact_root=artifact_root)

        loaded = load_index_from_artifacts(repo, artifact_root)

        assert len(loaded.call_graph.edges) == len(original.call_graph.edges)

    def test_roundtrip_preserves_decorators(self, tmp_path: Path, monkeypatch) -> None:

        repo = _FIXTURES / "flask_basic"
        artifact_root = tmp_path / "artifacts"
        original = build_index(repo, artifact_root=artifact_root)

        loaded = load_index_from_artifacts(repo, artifact_root)

        assert len(loaded.decorators) == len(original.decorators)

    def test_roundtrip_preserves_value_flow(self, tmp_path: Path, monkeypatch) -> None:

        repo = _FIXTURES / "minimal"
        artifact_root = tmp_path / "artifacts"
        original = build_index(repo, artifact_root=artifact_root)

        loaded = load_index_from_artifacts(repo, artifact_root)

        assert len(loaded.value_flow._edges) == len(original.value_flow._edges)

    def test_cached_load_preserves_cfgs(self, tmp_path: Path, monkeypatch) -> None:
        """FLAW-118: CFGs round-trip so cached conditions()/predicates() are faithful.

        Before FLAW-118 the cache dropped all CFGs (they were ``in_memory_only``),
        silently suppressing every CFG-derived rule on cached scans.  The cache
        must now restore blocks (with their ``condition_expr`` /
        ``value_predicates``) and edges identically to a full extraction.
        """

        repo = _FIXTURES / "flask_basic"
        artifact_root = tmp_path / "artifacts"
        original = build_index(repo, artifact_root=artifact_root)

        cfgs_in_original = sum(1 for fn in original.functions if original.cfg(fn.fqn) is not None)
        assert cfgs_in_original > 0

        loaded = load_index_from_artifacts(repo, artifact_root)
        cfgs_in_loaded = sum(1 for fn in loaded.functions if loaded.cfg(fn.fqn) is not None)
        assert cfgs_in_loaded == cfgs_in_original

        # Deep fidelity: every function's blocks/edges survive the round-trip,
        # and dominance is recomputed (not silently empty).
        for fn in original.functions:
            orig_cfg = original.cfg(fn.fqn)
            if orig_cfg is None:
                continue
            loaded_cfg = loaded.cfg(fn.fqn)
            assert loaded_cfg is not None
            assert loaded_cfg.blocks == orig_cfg.blocks
            assert loaded_cfg.edges == orig_cfg.edges
            if orig_cfg.blocks:
                assert (loaded.dominance(fn.fqn) is None) == (original.dominance(fn.fqn) is None)

    def test_missing_cfg_artifact_raises_corrupt_cache_error(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """A non-empty cache lacking cfgs.jsonl (pre-FLAW-118) must re-extract, not fail open."""

        repo = _FIXTURES / "flask_basic"
        artifact_root = tmp_path / "artifacts"
        build_index(repo, artifact_root=artifact_root)

        (artifact_root / "normalized" / "cfgs.jsonl").unlink()

        with pytest.raises(CorruptCacheError, match=r"cfgs\.jsonl"):
            load_index_from_artifacts(repo, artifact_root)

    def test_cached_provenance_indicates_cached(self, tmp_path: Path, monkeypatch) -> None:

        artifact_root = tmp_path / "artifacts"
        build_index(_FIXTURES / "minimal", artifact_root=artifact_root)

        loaded = load_index_from_artifacts(_FIXTURES / "minimal", artifact_root)
        assert loaded.provenance.producer == "pipeline_cached"

    def test_roundtrip_preserves_function_kinds(self, tmp_path: Path, monkeypatch) -> None:

        repo = _FIXTURES / "functions"
        artifact_root = tmp_path / "artifacts"
        original = build_index(repo, artifact_root=artifact_root)

        loaded = load_index_from_artifacts(repo, artifact_root)

        orig_kinds = {fn.fqn: fn.kind for fn in original.functions}
        loaded_kinds = {fn.fqn: fn.kind for fn in loaded.functions}
        assert orig_kinds == loaded_kinds

    def test_roundtrip_preserves_imports(self, tmp_path: Path, monkeypatch) -> None:

        repo = _FIXTURES / "imports"
        artifact_root = tmp_path / "artifacts"
        original = build_index(repo, artifact_root=artifact_root)

        loaded = load_index_from_artifacts(repo, artifact_root)

        assert len(loaded.imports) == len(original.imports)

    def test_roundtrip_preserves_all_persisted_collections(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """Cached loads reconstruct the full persisted CodeIndex surface."""

        repo = _FIXTURES / "flask_basic"
        artifact_root = tmp_path / "artifacts"
        original = build_index(repo, artifact_root=artifact_root)

        loaded = load_index_from_artifacts(repo, artifact_root)

        assert loaded.functions.all() == original.functions.all()
        assert loaded.classes.all() == original.classes.all()
        assert loaded.decorators.all() == original.decorators.all()
        assert loaded.imports.all() == original.imports.all()
        assert loaded.attributes.all() == original.attributes.all()
        assert loaded.call_graph.edges == original.call_graph.edges
        assert loaded.value_flow.edges == original.value_flow.edges
        assert loaded.symbols.refs == original.symbols.refs
        assert loaded.errors.all() == original.errors.all()

    def test_deserializer_caches_resolved_schema_per_dataclass(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """Repeated records reuse resolved field schemas instead of re-running typing."""
        span = SourceSpan(file="app.py", line=1, column=0, end_line=1, end_column=10)
        errors = (
            ExtractionError(
                file="app.py",
                pass_name="parser",
                error_kind=ErrorKind.PARSE,
                message="first",
                is_fatal=False,
                location=span,
            ),
            ExtractionError(
                file="app.py",
                pass_name="parser",
                error_kind=ErrorKind.PARSE,
                message="second",
                is_fatal=False,
                location=span,
            ),
        )
        artifact_root = tmp_path / "artifacts"
        normalized = artifact_root / "normalized"
        normalized.mkdir(parents=True)
        _write_jsonl(normalized / "errors.jsonl", errors)

        pipeline._DESERIALIZE_SCHEMA_CACHE.clear()
        calls: Counter[type] = Counter()
        real_get_type_hints = pipeline.get_type_hints  # type: ignore[attr-defined]

        def counting_get_type_hints(cls: type) -> dict[str, object]:
            calls[cls] += 1
            return real_get_type_hints(cls)

        monkeypatch.setattr(pipeline, "get_type_hints", counting_get_type_hints)

        loaded = load_index_from_artifacts(tmp_path, artifact_root)

        assert loaded.errors.all() == errors
        assert calls[ExtractionError] == 1
        assert calls[SourceSpan] == 1
        pipeline._DESERIALIZE_SCHEMA_CACHE.clear()

    def test_optional_nested_dataclass_fields_reconstruct_objects(self, tmp_path: Path) -> None:
        """PEP 604 optional dataclass annotations must not deserialize as raw dicts."""
        span = SourceSpan(file="app.py", line=2, column=4, end_line=2, end_column=9)
        error = ExtractionError(
            file="app.py",
            pass_name="parser",
            error_kind=ErrorKind.PARSE,
            message="bad syntax",
            is_fatal=False,
            location=span,
        )
        artifact_root = tmp_path / "artifacts"
        normalized = artifact_root / "normalized"
        normalized.mkdir(parents=True)
        _write_jsonl(normalized / "errors.jsonl", (error,))

        loaded = load_index_from_artifacts(tmp_path, artifact_root)

        assert loaded.errors.one().location == span


# ── End-to-end cache integration ──────────────────────────────────


class TestCacheIntegration:
    """Cache write after extraction, load on second run."""

    def test_cache_key_written_after_build(self, tmp_path: Path, monkeypatch) -> None:

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("def hello(): return 1\n")
        artifact_root = tmp_path / "artifacts"

        build_index(repo, artifact_root=artifact_root)

        # Cache key is NOT written by build_index — it's written by run_index.
        # Verify the infrastructure works via write_cache_key directly.
        content_hash = repo_content_hash(repo)
        write_cache_key(artifact_root, content_hash=content_hash)

        assert cache_key_matches(artifact_root, content_hash=content_hash)

    def test_full_extract_then_cached_load(self, tmp_path: Path, monkeypatch) -> None:
        """Extract, write cache key, then load from cache — no re-extraction."""

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("def hello(): return 1\n")
        artifact_root = tmp_path / "artifacts"

        original = build_index(repo, artifact_root=artifact_root)
        content_hash = repo_content_hash(repo)
        write_cache_key(artifact_root, content_hash=content_hash)

        # Now load from cache
        assert cache_key_matches(artifact_root, content_hash=content_hash)
        loaded = load_index_from_artifacts(repo, artifact_root)

        assert len(loaded.functions) == len(original.functions)
        assert {fn.name for fn in loaded.functions} == {fn.name for fn in original.functions}

    def test_modification_invalidates_cache(self, tmp_path: Path, monkeypatch) -> None:

        repo = tmp_path / "repo"
        repo.mkdir()
        py = repo / "app.py"
        py.write_text("def hello(): return 1\n")
        artifact_root = tmp_path / "artifacts"

        build_index(repo, artifact_root=artifact_root)
        h1 = repo_content_hash(repo)
        write_cache_key(artifact_root, content_hash=h1)

        # Modify source
        py.write_text("def hello(): return 2\ndef goodbye(): pass\n")
        h2 = repo_content_hash(repo)

        assert h1 != h2
        assert not cache_key_matches(artifact_root, content_hash=h2)

    def test_corrupt_artifacts_raise_corrupt_cache_error(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """Corrupt JSONL triggers CorruptCacheError, not an unhandled crash."""

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("def hello(): return 1\n")
        artifact_root = tmp_path / "artifacts"

        build_index(repo, artifact_root=artifact_root)

        # Corrupt one JSONL file
        (artifact_root / "normalized" / "functions.jsonl").write_text("not valid json{{{\n")

        with pytest.raises(CorruptCacheError, match=r"functions\.jsonl"):
            load_index_from_artifacts(repo, artifact_root)

    def test_invalid_enum_artifact_raises_corrupt_cache_error(self, tmp_path: Path) -> None:
        """Invalid enum values are corrupt cache data, not unhandled ValueErrors."""
        artifact_root = tmp_path / "artifacts"
        normalized = artifact_root / "normalized"
        normalized.mkdir(parents=True)
        (normalized / "errors.jsonl").write_text(
            json.dumps(
                {
                    "file": "app.py",
                    "pass_name": "parser",
                    "error_kind": "not-a-real-kind",
                    "message": "bad enum",
                    "is_fatal": False,
                    "location": None,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        with pytest.raises(CorruptCacheError, match=r"errors\.jsonl"):
            load_index_from_artifacts(tmp_path, artifact_root)


# ── Type enrichment cache round-trip ─────────────────────────────


_SPAN_A = SourceSpan(file="app.py", line=5, column=0, end_line=5, end_column=8)

_DISAGREEMENT_FACTS = (
    TypeFact(
        expression="result",
        declared_type="str",
        location=_SPAN_A,
        source_tool="basedpyright",
        is_concrete=True,
        provenance=_PROV,
        containing_function_fqn="app.hello",
    ),
    TypeFact(
        expression="result",
        declared_type="int",
        location=_SPAN_A,
        source_tool="mypy",
        is_concrete=True,
        provenance=_PROV,
        containing_function_fqn="app.hello",
    ),
)

_INJECTED_ENRICHMENT = TypeEnrichmentIndex(facts=_DISAGREEMENT_FACTS)


def _fake_type_enrichment(*_args: object, **_kwargs: object) -> TypeEnrichmentIndex:
    return _INJECTED_ENRICHMENT


class TestTypeEnrichmentCacheRoundTrip:
    """FLAW-073: type-enrichment facts must survive a cache round-trip."""

    def test_fresh_extraction_has_type_facts(self, tmp_path: Path, monkeypatch) -> None:
        """Fresh build_index produces the injected type-enrichment facts."""
        monkeypatch.setattr(
            "flawed._index._pipeline.build_type_enrichment_index", _fake_type_enrichment
        )

        repo = _FIXTURES / "minimal"
        artifact_root = tmp_path / "artifacts"
        original = build_index(repo, artifact_root=artifact_root)

        assert len(original.type_enrichment.facts) == 2
        expressions = {f.declared_type for f in original.type_enrichment.facts}
        assert expressions == {"str", "int"}

    def test_cached_load_preserves_type_facts(self, tmp_path: Path, monkeypatch) -> None:
        """Cache-hit load reconstructs the same type-enrichment facts."""
        monkeypatch.setattr(
            "flawed._index._pipeline.build_type_enrichment_index", _fake_type_enrichment
        )

        repo = _FIXTURES / "minimal"
        artifact_root = tmp_path / "artifacts"
        original = build_index(repo, artifact_root=artifact_root)
        loaded = load_index_from_artifacts(repo, artifact_root)

        assert len(loaded.type_enrichment.facts) == len(original.type_enrichment.facts)
        orig_types = {(f.expression, f.declared_type) for f in original.type_enrichment.facts}
        loaded_types = {(f.expression, f.declared_type) for f in loaded.type_enrichment.facts}
        assert orig_types == loaded_types

    def test_disagreements_match_across_cache_boundary(self, tmp_path: Path, monkeypatch) -> None:
        """convert_type_disagreements produces identical output for fresh and cached indexes."""
        from flawed._semantic._type_disagreement_conversion import convert_type_disagreements

        monkeypatch.setattr(
            "flawed._index._pipeline.build_type_enrichment_index", _fake_type_enrichment
        )

        repo = _FIXTURES / "minimal"
        artifact_root = tmp_path / "artifacts"
        original = build_index(repo, artifact_root=artifact_root)
        loaded = load_index_from_artifacts(repo, artifact_root)

        fresh_disagreements = convert_type_disagreements(original.type_enrichment)
        cached_disagreements = convert_type_disagreements(loaded.type_enrichment)

        assert len(fresh_disagreements) > 0, "fixture must produce at least one disagreement"
        assert len(fresh_disagreements) == len(cached_disagreements)
        for fresh, cached in zip(fresh_disagreements, cached_disagreements, strict=True):
            assert fresh.expression == cached.expression
            assert fresh.kind == cached.kind
            assert len(fresh.observations) == len(cached.observations)


class TestTypeEnrichmentSignature:
    """Cache identity changes when type-enrichment configuration changes."""

    def test_same_config_same_signature(self) -> None:
        sig1 = type_enrichment_signature()
        sig2 = type_enrichment_signature()
        assert sig1 == sig2

    def test_mypy_batch_toggle_changes_signature(self) -> None:
        sig_off = type_enrichment_signature(enable_mypy_batch=False)
        sig_on = type_enrichment_signature(enable_mypy_batch=True)
        assert sig_off != sig_on

    def test_cap_change_invalidates_signature(self) -> None:
        sig_default = type_enrichment_signature()
        sig_changed = type_enrichment_signature(basedpyright_max_queries=100)
        assert sig_default != sig_changed

    def test_signature_in_cache_key(self, tmp_path: Path) -> None:
        """Cache key includes the type_enrichment_signature field."""
        sig = type_enrichment_signature()
        write_cache_key(tmp_path, content_hash="abc", type_enrichment_signature=sig)
        assert cache_key_matches(tmp_path, content_hash="abc", type_enrichment_signature=sig)

    def test_changed_signature_is_cache_miss(self, tmp_path: Path) -> None:
        """Changing type-enrichment config invalidates the cache."""
        sig1 = type_enrichment_signature(enable_mypy_batch=False)
        sig2 = type_enrichment_signature(enable_mypy_batch=True)
        write_cache_key(tmp_path, content_hash="abc", type_enrichment_signature=sig1)
        assert not cache_key_matches(tmp_path, content_hash="abc", type_enrichment_signature=sig2)
