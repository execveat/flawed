"""Tests for incremental L1 rebuild."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from flawed._index._pipeline import (
    _PIPELINE_VERSION,
    FileChanges,
    build_index,
    detect_changed_files,
    incremental_build,
    read_file_manifest,
    write_cache_key,
    write_file_manifest,
)
from flawed._index._type_enrichment import (
    TypeEnrichmentIndex,
    TypeFact,
)
from flawed._index._types import ExtractionProvenance

if TYPE_CHECKING:
    from collections.abc import Iterable

    from flawed._index._type_enrichment import TypeQuery

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "apps"


class _DeterministicOracle:
    """A fake ``TypeOracle`` for fast, deterministic enrichment tests.

    Emits exactly one concrete fact per query, with a declared type derived
    from the probed expression. Facts therefore track the *current* set of
    assignment-target queries (which come from fresh structural extraction),
    so adding/removing an assignment changes the fact set — letting a test
    assert that incremental rebuild actually re-probes changed files rather
    than serving stale/empty cached facts (FLAW-083). Avoids the slow, env-
    dependent real basedpyright/mypy oracles.
    """

    def run(self, repo_root: Path, queries: Iterable[TypeQuery]) -> TypeEnrichmentIndex:
        provenance = ExtractionProvenance(
            producer="deterministic-test-oracle",
            producer_version="test",
            artifact=str(repo_root),
        )
        facts = tuple(
            TypeFact(
                expression=query.expression,
                declared_type=f"T::{query.expression}",
                location=query.location,
                source_tool="fake",
                is_concrete=True,
                provenance=provenance,
                containing_function_fqn=query.containing_function_fqn,
            )
            for query in queries
        )
        return TypeEnrichmentIndex(facts=facts)


class TestFileManifest:
    """write/read/detect round-trip on the per-file manifest."""

    def test_write_and_read(self, tmp_path: Path) -> None:
        app_py = tmp_path / "app.py"
        app_py.write_text("x = 1\n")
        write_file_manifest(tmp_path, (app_py,), tmp_path)
        manifest = read_file_manifest(tmp_path)
        assert manifest is not None
        assert "app.py" in manifest

    def test_read_missing(self, tmp_path: Path) -> None:
        assert read_file_manifest(tmp_path) is None

    def test_read_wrong_schema_version(self, tmp_path: Path) -> None:
        """FLAW-344: a manifest with a mismatched/absent L1 schema version is rejected
        (fail-closed), forcing a full rebuild rather than an unsafe incremental one."""
        payload = {"l1_schema_version": "0.0.0", "files": {}}
        (tmp_path / "file_manifest.json").write_text(json.dumps(payload))
        assert read_file_manifest(tmp_path) is None

    def test_detect_no_changes(self, tmp_path: Path) -> None:
        app_py = tmp_path / "app.py"
        app_py.write_text("x = 1\n")
        write_file_manifest(tmp_path, (app_py,), tmp_path)
        manifest = read_file_manifest(tmp_path)
        assert manifest is not None
        changes = detect_changed_files(manifest, tmp_path, (app_py,))
        assert changes.changed == ()
        assert changes.added == ()
        assert changes.removed == ()

    def test_detect_changed_file(self, tmp_path: Path) -> None:
        app_py = tmp_path / "app.py"
        app_py.write_text("x = 1\n")
        write_file_manifest(tmp_path, (app_py,), tmp_path)
        time.sleep(0.01)
        app_py.write_text("x = 2\n")
        manifest = read_file_manifest(tmp_path)
        assert manifest is not None
        changes = detect_changed_files(manifest, tmp_path, (app_py,))
        assert len(changes.changed) == 1
        assert changes.changed[0].name == "app.py"

    def test_detect_added_file(self, tmp_path: Path) -> None:
        app_py = tmp_path / "app.py"
        app_py.write_text("x = 1\n")
        write_file_manifest(tmp_path, (app_py,), tmp_path)
        new_py = tmp_path / "new.py"
        new_py.write_text("y = 2\n")
        manifest = read_file_manifest(tmp_path)
        assert manifest is not None
        changes = detect_changed_files(manifest, tmp_path, (app_py, new_py))
        assert len(changes.added) == 1
        assert changes.added[0].name == "new.py"

    def test_detect_removed_file(self, tmp_path: Path) -> None:
        app_py = tmp_path / "app.py"
        app_py.write_text("x = 1\n")
        write_file_manifest(tmp_path, (app_py,), tmp_path)
        manifest = read_file_manifest(tmp_path)
        assert manifest is not None
        changes = detect_changed_files(manifest, tmp_path, ())
        assert changes.removed == ("app.py",)


@pytest.mark.slow
class TestIncrementalBuild:
    """Full incremental extraction on the functions fixture."""

    def test_incremental_preserves_unchanged_records(self, tmp_path: Path) -> None:
        fixture = _FIXTURES / "functions"
        artifact_dir = tmp_path / "artifacts"
        artifact_dir.mkdir()

        build_index(fixture, artifact_root=artifact_dir)
        write_cache_key(artifact_dir, content_hash="test-full")

        main_py = fixture / "main.py"
        all_files = (main_py, fixture / "helpers.py")

        file_changes = FileChanges(
            changed=(main_py,),
            added=(),
            removed=(),
        )

        inc_index = incremental_build(
            fixture,
            artifact_dir,
            file_changes,
            all_files,
        )

        helpers_inc = {fn.fqn for fn in inc_index.functions if fn.file == "helpers.py"}
        assert len(helpers_inc) > 0

    def test_incremental_re_extracts_changed_file(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        app_py = src_dir / "app.py"
        helpers_py = src_dir / "helpers.py"
        app_py.write_text("def original():\n    return 1\n")
        helpers_py.write_text("def helper():\n    return 2\n")

        artifact_dir = tmp_path / "artifacts"
        artifact_dir.mkdir()
        build_index(src_dir, artifact_root=artifact_dir)
        write_cache_key(artifact_dir, content_hash="v1")

        app_py.write_text("def replaced():\n    return 3\n")
        file_changes = FileChanges(
            changed=(app_py,),
            added=(),
            removed=(),
        )

        inc_index = incremental_build(
            src_dir,
            artifact_dir,
            file_changes,
            (app_py, helpers_py),
        )

        names = {fn.name for fn in inc_index.functions}
        assert "replaced" in names
        assert "original" not in names
        assert "helper" in names

    def test_incremental_handles_added_file(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        app_py = src_dir / "app.py"
        app_py.write_text("def existing():\n    return 1\n")

        artifact_dir = tmp_path / "artifacts"
        artifact_dir.mkdir()
        build_index(src_dir, artifact_root=artifact_dir)
        write_cache_key(artifact_dir, content_hash="v1")

        new_py = src_dir / "new_module.py"
        new_py.write_text("def added_func():\n    return 2\n")

        file_changes = FileChanges(
            changed=(),
            added=(new_py,),
            removed=(),
        )
        inc_index = incremental_build(
            src_dir,
            artifact_dir,
            file_changes,
            (app_py, new_py),
        )

        names = {fn.name for fn in inc_index.functions}
        assert "existing" in names
        assert "added_func" in names

    def test_incremental_handles_removed_file(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        app_py = src_dir / "app.py"
        extra_py = src_dir / "extra.py"
        app_py.write_text("def keep():\n    return 1\n")
        extra_py.write_text("def remove_me():\n    return 2\n")

        artifact_dir = tmp_path / "artifacts"
        artifact_dir.mkdir()
        build_index(src_dir, artifact_root=artifact_dir)
        write_cache_key(artifact_dir, content_hash="v1")

        extra_py.unlink()

        file_changes = FileChanges(
            changed=(),
            added=(),
            removed=("extra.py",),
        )
        inc_index = incremental_build(
            src_dir,
            artifact_dir,
            file_changes,
            (app_py,),
        )

        names = {fn.name for fn in inc_index.functions}
        assert "keep" in names
        assert "remove_me" not in names

    def test_incremental_provenance(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "app.py").write_text("def f():\n    pass\n")

        artifact_dir = tmp_path / "artifacts"
        artifact_dir.mkdir()
        build_index(src_dir, artifact_root=artifact_dir)
        write_cache_key(artifact_dir, content_hash="v1")

        file_changes = FileChanges(changed=(src_dir / "app.py",), added=(), removed=())
        inc_index = incremental_build(src_dir, artifact_dir, file_changes, (src_dir / "app.py",))

        assert inc_index.provenance.producer == "pipeline_incremental"
        assert inc_index.provenance.producer_version == _PIPELINE_VERSION

    @staticmethod
    def _type_fact_keys(
        index: object, rel_file: str | None = None
    ) -> set[tuple[str, int, str, str]]:
        """Comparable identity for type-enrichment facts (optionally per-file)."""
        return {
            (f.location.file, f.location.line, f.expression, f.declared_type)
            for f in index.type_enrichment.facts  # type: ignore[attr-defined]
            if rel_file is None or f.location.file == rel_file
        }

    def test_incremental_reruns_type_enrichment_for_changed_files(self, tmp_path: Path) -> None:
        """FLAW-083: incremental rebuild must re-probe changed files' types.

        Before the fix, ``incremental_build`` filtered cached type facts by
        affected file but never re-ran enrichment, so a changed file
        *permanently* lost all its type-enrichment facts — a silent false-
        negative source for type-dependent rules. This asserts parity: after
        an incremental rebuild, type facts equal a full rebuild of the same
        final source, for both changed and unchanged files.
        """
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        mod_a = src_dir / "mod_a.py"
        mod_b = src_dir / "mod_b.py"
        mod_a.write_text("x: int = 1\n")
        mod_b.write_text("y: str = 'hi'\n")

        artifact_dir = tmp_path / "artifacts"
        artifact_dir.mkdir()
        oracle = _DeterministicOracle()

        full_v1 = build_index(src_dir, artifact_root=artifact_dir, oracle=oracle)
        write_cache_key(artifact_dir, content_hash="v1")
        # Sanity: the full build records a fact for mod_a's assignment.
        assert ("mod_a.py", 1, "x", "T::x") in self._type_fact_keys(full_v1, "mod_a.py")

        # Change mod_a: add a second annotated assignment (line 2).
        mod_a.write_text("x: int = 1\nz: int = 3\n")
        file_changes = FileChanges(changed=(mod_a,), added=(), removed=())

        inc_index = incremental_build(
            src_dir,
            artifact_dir,
            file_changes,
            (mod_a, mod_b),
            oracle=oracle,
        )

        # Full rebuild of the final source state = the parity oracle.
        artifact_dir_2 = tmp_path / "artifacts2"
        artifact_dir_2.mkdir()
        full_v2 = build_index(src_dir, artifact_root=artifact_dir_2, oracle=oracle)

        # The changed file is freshly re-probed (the new assignment appears)...
        assert ("mod_a.py", 2, "z", "T::z") in self._type_fact_keys(inc_index, "mod_a.py")
        # ...and matches a full rebuild exactly (no stale/dropped facts).
        assert self._type_fact_keys(inc_index, "mod_a.py") == self._type_fact_keys(
            full_v2, "mod_a.py"
        )
        # The unchanged file's cached facts are preserved and also match.
        assert self._type_fact_keys(inc_index, "mod_b.py") == self._type_fact_keys(
            full_v2, "mod_b.py"
        )
        # Whole-index parity between incremental and full rebuild.
        assert self._type_fact_keys(inc_index) == self._type_fact_keys(full_v2)
        # The facts are also persisted to the cache (not just in the returned index).
        from flawed._index._pipeline import _read_jsonl

        persisted = _read_jsonl(artifact_dir / "normalized" / "type_enrichment.jsonl", TypeFact)
        persisted_keys = {
            (f.location.file, f.location.line, f.expression, f.declared_type) for f in persisted
        }
        assert ("mod_a.py", 2, "z", "T::z") in persisted_keys


def _normalized_fact_keys(normalized_dir: Path) -> dict[str, set[tuple[object, ...]]]:
    """Read persisted normalized L1 artifacts into provenance-free comparable keys.

    The artifact ``provenance`` field embeds the per-build artifact path, so it
    is excluded from every key; we compare the *facts*, not where they were
    written.  cross-file (interfile) call edges are excluded: incremental rebuild
    deliberately does not re-run whole-repo interfile analysis
    (documented staleness, bounded by the >half-changed full-rebuild gate), so
    they are the one category an incremental result is not expected to match a
    full build on.  Every other category MUST be byte-for-byte identical to a
    from-scratch full build of the same final source — that is the FLAW-121
    parity invariant.
    """
    from flawed._index._pipeline import _read_jsonl
    from flawed._index._types import (
        AttributeAccess,
        CallEdge,
        ClassRecord,
        DecoratorFact,
        FunctionRecord,
        ImportFact,
        SymbolRef,
        ValueFlowEdge,
    )

    def read(name: str, cls: type) -> tuple[object, ...]:
        return _read_jsonl(normalized_dir / name, cls)

    functions = read("functions.jsonl", FunctionRecord)
    classes = read("classes.jsonl", ClassRecord)
    decorators = read("decorators.jsonl", DecoratorFact)
    imports = read("imports.jsonl", ImportFact)
    attributes = read("attributes.jsonl", AttributeAccess)
    call_edges = read("call_edges.jsonl", CallEdge)
    vf_edges = read("value_flow_edges.jsonl", ValueFlowEdge)
    symbols = read("symbol_refs.jsonl", SymbolRef)
    return {
        "functions": {(f.fqn, f.name, f.file, f.line) for f in functions},  # type: ignore[attr-defined]
        "classes": {(c.fqn, c.name, c.file) for c in classes},  # type: ignore[attr-defined]
        "decorators": {
            (d.name, d.location.file, d.location.line, d.resolution.value)  # type: ignore[attr-defined]
            for d in decorators
        },
        "imports": {
            (i.module, i.names, i.is_from_import, i.is_relative, i.location.file)  # type: ignore[attr-defined]
            for i in imports
        },
        "attributes": {
            (a.target_expr, a.attr_name, a.location.file, a.location.line, a.is_write)  # type: ignore[attr-defined]
            for a in attributes
        },
        "call_edges": {
            (
                e.caller_fqn,  # type: ignore[attr-defined]
                e.callee_fqn,  # type: ignore[attr-defined]
                e.resolution.value,  # type: ignore[attr-defined]
                e.source.value,  # type: ignore[attr-defined]
                e.location.file,  # type: ignore[attr-defined]
                e.location.line,  # type: ignore[attr-defined]
            )
            for e in call_edges
        },
        "value_flow": {
            (
                v.source_expr,  # type: ignore[attr-defined]
                v.target_expr,  # type: ignore[attr-defined]
                v.kind.value,  # type: ignore[attr-defined]
                v.source_location.file,  # type: ignore[attr-defined]
                v.source_location.line,  # type: ignore[attr-defined]
            )
            for v in vf_edges
        },
        # All symbols come from the AST extractor now; no cross-file interfile
        # producer contributes, so no producer-based exclusion is needed.
        "symbol_refs_ast": {
            (s.name, s.fqn, s.resolution.value, s.location.file, s.location.line)  # type: ignore[attr-defined]
            for s in symbols
        },
    }


class TestIncrementalFullParity:
    """FLAW-120/121: incremental rebuild facts must equal a full build.

    These exercise *cross-file* invalidation — the class of silent false
    negatives where a change in file A leaves file B's cached cross-file facts
    (FQN resolution, call-edge targets, namespace prefixes) stale because B was
    never re-extracted and the repo-wide resolution context was computed from
    only the changed subset.
    """

    def _full_build(self, src_dir: Path, artifact_dir: Path) -> object:
        artifact_dir.mkdir()
        oracle = _DeterministicOracle()
        idx = build_index(src_dir, artifact_root=artifact_dir, oracle=oracle)
        write_cache_key(artifact_dir, content_hash="v1")
        return idx

    @pytest.mark.slow
    def test_namespace_roots_recomputed_repo_wide(self, tmp_path: Path) -> None:
        """A changed file's FQN must use repo-wide namespace prefixes.

        ``src/`` has no ``__init__.py`` (a PEP 420 namespace candidate). Only
        because ``app.py`` imports ``from src.helpers import ...`` is ``src``
        classified as a namespace prefix, so ``helpers.py``'s functions root at
        ``src.helpers.*``. Incrementally re-extracting only ``helpers.py``
        previously computed ``namespace_roots`` from that one file — which has
        no ``src.*`` import — and mis-minted the FQN as ``helpers.*``.
        """
        src_dir = tmp_path / "proj" / "src"
        src_dir.mkdir(parents=True)
        app = src_dir / "app.py"
        helpers = src_dir / "helpers.py"
        app.write_text("from src.helpers import compute\n\n\ndef run():\n    return compute()\n")
        helpers.write_text("def compute():\n    return 1\n")
        repo = tmp_path / "proj"

        artifact_dir = tmp_path / "artifacts"
        self._full_build(repo, artifact_dir)

        helpers.write_text("def compute():\n    return 1\n\n\ndef extra():\n    return 2\n")
        file_changes = FileChanges(changed=(helpers,), added=(), removed=())
        inc = incremental_build(
            repo, artifact_dir, file_changes, (app, helpers), oracle=_DeterministicOracle()
        )

        fqns = {f.fqn for f in inc.functions}
        assert "src.helpers.compute" in fqns
        assert "src.helpers.extra" in fqns
        assert "helpers.compute" not in fqns  # the mis-minted (no-namespace) FQN

    @pytest.mark.slow
    def test_dependent_call_edge_reresolved_after_change(self, tmp_path: Path) -> None:
        """Changing a definition in A updates dependent B's call-edge resolution.

        B imports ``foo`` from A and calls it (resolved, project-local). When A
        renames ``foo`` away, a full build marks B's import unresolved and B's
        call edge stops resolving to ``mod_a.foo``. Incremental must re-extract
        the dependent B (it imports the changed module), not retain its stale
        resolved edge.
        """
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        mod_a = src_dir / "mod_a.py"
        mod_b = src_dir / "mod_b.py"
        mod_a.write_text("def foo():\n    return 1\n")
        mod_b.write_text("from mod_a import foo\n\n\ndef call_it():\n    return foo()\n")

        artifact_dir = tmp_path / "artifacts"
        self._full_build(src_dir, artifact_dir)

        # Rename foo -> bar in A; B still imports the now-missing foo.
        mod_a.write_text("def bar():\n    return 1\n")
        file_changes = FileChanges(changed=(mod_a,), added=(), removed=())
        inc = incremental_build(
            src_dir, artifact_dir, file_changes, (mod_a, mod_b), oracle=_DeterministicOracle()
        )

        # Parity oracle: full rebuild of the final state.
        artifact_dir_2 = tmp_path / "artifacts2"
        full_v2 = self._full_build(src_dir, artifact_dir_2)

        def call_keys(index: object) -> set[tuple[object, ...]]:
            return {
                (e.caller_fqn, e.callee_fqn, e.resolution.value)
                for e in index.call_graph.edges  # type: ignore[attr-defined]
                if e.caller_fqn == "mod_b.call_it"
            }

        assert call_keys(inc) == call_keys(full_v2)

    @pytest.mark.slow
    def test_normalized_fact_parity_multifile(self, tmp_path: Path) -> None:
        """The FLAW-121 gate: incremental normalized facts == full build.

        Multi-file fixture with a cross-file dependency, a re-export hub, and a
        PEP 420 namespace prefix. After editing depended-upon files, every
        normalized fact category (excluding cross-file edges) must equal
        a from-scratch full build of the same final source.
        """
        repo = tmp_path / "proj"
        src = repo / "src"
        pkg = src / "pkg"
        pkg.mkdir(parents=True)
        # Namespace layout: src has no __init__.py; app imports `from src...`.
        (src / "app.py").write_text(
            "from src.pkg import handler\nfrom src.helpers import compute\n\n\n"
            "def run():\n    return handler() + compute()\n"
        )
        (src / "helpers.py").write_text("def compute():\n    return 1\n")
        (pkg / "__init__.py").write_text("from src.pkg.impl import handler\n")  # re-export hub
        (pkg / "impl.py").write_text("def handler():\n    return 10\n")

        artifact_dir = tmp_path / "artifacts"
        self._full_build(repo, artifact_dir)

        # Edit a depended-upon leaf (impl.py) and the helper; this shifts
        # line numbers and adds defs that dependents resolve against.
        (pkg / "impl.py").write_text(
            "def handler():\n    return 11\n\n\ndef helper2():\n    return 2\n"
        )
        (src / "helpers.py").write_text("def compute():\n    return 100\n")
        file_changes = FileChanges(
            changed=(pkg / "impl.py", src / "helpers.py"), added=(), removed=()
        )
        all_files = (
            src / "app.py",
            src / "helpers.py",
            pkg / "__init__.py",
            pkg / "impl.py",
        )
        incremental_build(
            repo, artifact_dir, file_changes, all_files, oracle=_DeterministicOracle()
        )

        artifact_dir_2 = tmp_path / "artifacts2"
        self._full_build(repo, artifact_dir_2)

        inc_keys = _normalized_fact_keys(artifact_dir / "normalized")
        full_keys = _normalized_fact_keys(artifact_dir_2 / "normalized")
        for category in sorted(full_keys):
            assert inc_keys[category] == full_keys[category], (
                f"incremental diverged from full build in category {category!r}: "
                f"only-incremental={inc_keys[category] - full_keys[category]}, "
                f"only-full={full_keys[category] - inc_keys[category]}"
            )
