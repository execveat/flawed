"""Tests for the structural entity pass (Step 3)."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from typing import TYPE_CHECKING

import pytest

from flawed._index._resolution import (
    _import_module_heads,
    _ImportBindingRange,
    _ImportBindingSourceOrderIndex,
    _module_fqn_for_path,
    _module_path_exists,
    _namespace_package_roots,
    _namespace_package_roots_from_files,
    _ProjectModuleIndex,
    _resolve_reexported_fqn,
)
from flawed._index._structural import (
    StructuralOutput,
    discover_python_files,
    extract_structural,
)
from flawed._index._types import (
    AccessKind,
    AliasMechanism,
    AssignmentKind,
    CallEdge,
    EdgeSource,
    ErrorKind,
    FunctionKind,
    HierarchyGap,
    ParameterKind,
    ResolutionStatus,
)
from tests.helpers.paths import APPS as FIXTURES
from tests.helpers.paths import REPO_ROOT as ROOT

if TYPE_CHECKING:
    from pathlib import Path

# ── File discovery ────────────────────────────────────────────────────


class TestDiscoverPythonFiles:
    def test_finds_py_files(self) -> None:
        files = discover_python_files(FIXTURES / "functions")
        names = {f.name for f in files}
        assert "main.py" in names
        assert "helpers.py" in names

    def test_excludes_pycache(self, tmp_path: Path) -> None:
        (tmp_path / "__pycache__").mkdir()
        (tmp_path / "__pycache__" / "cached.py").write_text("x = 1")
        (tmp_path / "real.py").write_text("x = 1")
        files = discover_python_files(tmp_path)
        assert len(files) == 1
        assert files[0].name == "real.py"

    def test_excludes_venv(self, tmp_path: Path) -> None:
        (tmp_path / ".venv" / "lib").mkdir(parents=True)
        (tmp_path / ".venv" / "lib" / "site.py").write_text("x = 1")
        (tmp_path / "app.py").write_text("x = 1")
        files = discover_python_files(tmp_path)
        assert len(files) == 1

    def test_returns_sorted(self, tmp_path: Path) -> None:
        (tmp_path / "z.py").write_text("x = 1")
        (tmp_path / "a.py").write_text("x = 1")
        files = discover_python_files(tmp_path)
        assert files[0].name == "a.py"
        assert files[1].name == "z.py"

    def test_empty_dir(self, tmp_path: Path) -> None:
        assert discover_python_files(tmp_path) == ()


class TestSourceSpanSharing:
    def test_import_statement_facts_share_equal_source_span(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("import os as operating_system\n", encoding="utf-8")

        out = extract_structural(tmp_path)

        alias = out.aliases[0]
        import_ = out.imports[0]
        assert alias.location is import_.location


class TestAstroidBrainRegistration:
    def test_structural_extraction_registers_custom_astroid_brains(
        self,
        tmp_path: Path,
    ) -> None:
        (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
        script = textwrap.dedent(
            f"""
            import sys
            from pathlib import Path

            import astroid

            sys.path.insert(0, {str(ROOT / "src")!r})
            from flawed._index._structural import extract_structural

            extract_structural(Path({str(tmp_path)!r}))
            module = astroid.parse(
                '''
                from flask import request
                form_data = request.form
                '''
            )
            results = tuple(module.body[1].value.infer())
            names = {{getattr(result, "name", None) for result in results}}
            if "ImmutableMultiDict" not in names:
                raise SystemExit(f"custom astroid brains were not registered: {{results!r}}")
            """
        )

        result = subprocess.run(
            [sys.executable, "-c", script],
            check=False,
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, result.stderr


class TestResolutionIndexes:
    def test_module_path_exists_uses_precomputed_prefixes(self) -> None:
        index = _ProjectModuleIndex.from_modules(
            frozenset({"pkg.deep.module", "pkg.sibling", "other.unrelated"})
        )

        assert _module_path_exists("pkg.deep.module", index)
        assert _module_path_exists("pkg.deep", index)
        assert _module_path_exists("pkg", index)
        assert not _module_path_exists("pkg.deep.missing", index)
        assert not _module_path_exists("missing", index)

    def test_import_binding_index_returns_only_matching_file_and_name_candidates(self) -> None:
        target = _ImportBindingRange(
            file="pkg/consumer.py",
            local_name="process_data",
            imported_fqn="pkg.helpers.process_data",
            local_fqn="pkg.consumer.process_data",
            import_line=10,
            end_line=None,
            end_inclusive=False,
        )
        unrelated_file = _ImportBindingRange(
            file="pkg/unrelated.py",
            local_name="process_data",
            imported_fqn="pkg.other.process_data",
            local_fqn="pkg.unrelated.process_data",
            import_line=20,
            end_line=None,
            end_inclusive=False,
        )
        unrelated_name = _ImportBindingRange(
            file="pkg/consumer.py",
            local_name="other_process",
            imported_fqn="pkg.other.other_process",
            local_fqn="pkg.consumer.other_process",
            import_line=30,
            end_line=None,
            end_inclusive=False,
        )

        index = _ImportBindingSourceOrderIndex.build((unrelated_file, unrelated_name, target))

        assert index.candidates_for_source_name(
            "pkg/consumer.py",
            "process_data.call",
        ) == (target,)


class TestNamespacePackageResolution:
    """PEP 420 / source-root rooting for ``src/``-style layouts (FLAW-102)."""

    def _make_namespace_layout(self, root: Path) -> None:
        """``src/`` lacks ``__init__.py`` but subpackages have it; imports use ``src.``."""
        src = root / "src"
        (src / "utils").mkdir(parents=True)
        (src / "utils" / "__init__.py").write_text("")
        (src / "models").mkdir(parents=True)
        (src / "models" / "__init__.py").write_text("")
        (src / "models" / "user.py").write_text("class User:\n    pass\n")
        (src / "utils" / "token_auth.py").write_text(
            "def is_token_authenticated():\n    return True\n"
        )
        (src / "app.py").write_text(
            textwrap.dedent(
                """\
                from src.models.user import User


                def before_request():
                    from src.utils.token_auth import is_token_authenticated

                    return is_token_authenticated()
                """
            )
        )

    def test_namespace_dir_classified_when_repo_imports_it(self, tmp_path: Path) -> None:
        self._make_namespace_layout(tmp_path)
        files = discover_python_files(tmp_path)

        assert _namespace_package_roots_from_files(tmp_path, files) == frozenset({"src"})

    def test_namespace_siblings_root_consistently(self, tmp_path: Path) -> None:
        self._make_namespace_layout(tmp_path)
        files = discover_python_files(tmp_path)
        namespace_roots = _namespace_package_roots_from_files(tmp_path, files)

        # The top-level module and the subpackage module both keep ``src``.
        assert (
            _module_fqn_for_path(tmp_path / "src" / "app.py", tmp_path, namespace_roots)[0]
            == "src.app"
        )
        assert (
            _module_fqn_for_path(
                tmp_path / "src" / "utils" / "token_auth.py", tmp_path, namespace_roots
            )[0]
            == "src.utils.token_auth"
        )

    def test_project_local_imports_resolve_without_root_init(self, tmp_path: Path) -> None:
        self._make_namespace_layout(tmp_path)
        out = extract_structural(tmp_path)

        fqns = {function.fqn for function in out.functions}
        assert "src.app.before_request" in fqns
        assert "src.utils.token_auth.is_token_authenticated" in fqns

        gap_messages = [
            error.message
            for error in out.errors
            if "Cannot resolve project-local" in error.message
        ]
        assert gap_messages == []

    def test_function_local_import_call_edge_resolves(self, tmp_path: Path) -> None:
        self._make_namespace_layout(tmp_path)
        out = extract_structural(tmp_path)

        edges = {(edge.caller_fqn, edge.callee_fqn): edge.resolution for edge in out.call_edges}
        key = (
            "src.app.before_request",
            "src.utils.token_auth.is_token_authenticated",
        )
        assert key in edges
        assert edges[key] is ResolutionStatus.RESOLVED

    def test_source_root_layout_still_strips_src(self, tmp_path: Path) -> None:
        """Regression guard: installable ``src/<pkg>/__init__.py`` repos keep stripping ``src``."""
        pkg = tmp_path / "src" / "pkg"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("")
        (pkg / "models.py").write_text("def make():\n    return 1\n")
        (pkg / "app.py").write_text(
            "from pkg.models import make\n\n\ndef go():\n    return make()\n"
        )
        files = discover_python_files(tmp_path)

        # ``src`` is a source root (imports reference ``pkg`` directly), not a prefix.
        assert _namespace_package_roots_from_files(tmp_path, files) == frozenset()

        out = extract_structural(tmp_path)
        fqns = {function.fqn for function in out.functions}
        assert "pkg.app.go" in fqns
        assert "pkg.models.make" in fqns
        assert all(not fqn.startswith("src.") for fqn in fqns)

        edges = {(edge.caller_fqn, edge.callee_fqn): edge.resolution for edge in out.call_edges}
        assert edges.get(("pkg.app.go", "pkg.models.make")) is ResolutionStatus.RESOLVED

    def test_flat_layout_unaffected(self, tmp_path: Path) -> None:
        """A repo with no top-level non-package dir yields no namespace roots."""
        (tmp_path / "app.py").write_text("def go():\n    return 1\n")
        (tmp_path / "helpers.py").write_text("def helper():\n    return 2\n")
        files = discover_python_files(tmp_path)

        assert _namespace_package_roots_from_files(tmp_path, files) == frozenset()

    def test_fact_based_classification_matches_file_based(self, tmp_path: Path) -> None:
        """The hot-path (ImportFact) classifier agrees with the file-based one.

        FLAW-102 perf: ``CodeIndex._namespace_roots`` derives namespace prefixes
        from already-extracted ``ImportFact``s instead of re-parsing every source
        file. This guards that the cheaper path yields the same classification as
        the cold-build file scan for a real namespace layout.
        """
        self._make_namespace_layout(tmp_path)
        files = discover_python_files(tmp_path)
        out = extract_structural(tmp_path)

        from_files = _namespace_package_roots_from_files(tmp_path, files)
        from_facts = _namespace_package_roots(tmp_path, files, out.imports)

        assert from_facts == from_files == frozenset({"src"})

    def test_import_module_heads_skips_relative_imports(self, tmp_path: Path) -> None:
        """Relative imports are not namespace evidence (ImportFact.is_relative).

        ``from .sibling import x`` resolves ``ImportFact.module`` to the file's
        own absolute package, but its head must not classify the top directory
        as an imported namespace prefix — matching the file-based scan, which
        skips ``node.level`` imports.
        """
        pkg = tmp_path / "src"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "sibling.py").write_text("def helper():\n    return 1\n")
        (pkg / "app.py").write_text(
            "from .sibling import helper\n\n\ndef go():\n    return helper()\n"
        )
        out = extract_structural(tmp_path)

        relative_fact = next(f for f in out.imports if "sibling" in f.module)
        assert relative_fact.is_relative is True
        # The relative import contributes no head, so ``src`` (a package dir
        # anyway) is never a namespace root.
        assert _import_module_heads(out.imports) == frozenset()

    def test_on_disk_src_namespace_fixture_resolves(self) -> None:
        """The checked-in ``src_namespace`` fixture resolves project-local imports."""
        out = extract_structural(FIXTURES / "src_namespace")

        fqns = {function.fqn for function in out.functions}
        assert "src.app.make_user" in fqns
        classes = {class_.fqn for class_ in out.classes}
        assert "src.models.user.User" in classes

        gap_messages = [
            error.message
            for error in out.errors
            if "Cannot resolve project-local" in error.message
        ]
        assert gap_messages == []


class TestNestedNamespaceSubpackageResolution:
    """Nested ``__init__``-less subpackages + relative-import FQNs (FLAW-115).

    Mirrors the ``e03_fake_header_refund`` benchmark layout: a regular package
    whose root ``__init__.py`` re-exports a submodule under a name that collides
    with a sibling namespace subpackage, decorators applied via a relative-
    imported object, and cross-module hook callees reached through ``..``
    relative imports.
    """

    def _make_layout(self, root: Path) -> Path:
        """Create the colliding nested-namespace package; return its root."""
        pkg = root / "app"
        pkg.mkdir()
        # Root __init__ re-exports ``routes.auth`` as the name ``auth`` — this
        # collides with the real ``auth/`` namespace subpackage below.
        (pkg / "__init__.py").write_text(
            textwrap.dedent(
                """\
                from .registry import bp
                from .routes import auth
                """
            )
        )
        (pkg / "registry.py").write_text(
            textwrap.dedent(
                """\
                class _Registry:
                    def before_request(self, fn):
                        return fn


                bp = _Registry()
                """
            )
        )
        # ``auth/`` is a namespace subpackage: NO __init__.py, nested inside the
        # regular ``app`` package.
        (pkg / "auth").mkdir()
        (pkg / "auth" / "helpers.py").write_text("def authenticate_customer():\n    return True\n")
        (pkg / "auth" / "middleware.py").write_text(
            textwrap.dedent(
                """\
                from .. import bp


                @bp.before_request
                def protect():
                    return True
                """
            )
        )
        # ``routes/`` is a regular subpackage; ``routes/auth.py`` is the module
        # whose re-export under the bare name ``auth`` causes the collision.
        (pkg / "routes").mkdir()
        (pkg / "routes" / "__init__.py").write_text("")
        (pkg / "routes" / "auth.py").write_text("def login():\n    return True\n")
        (pkg / "routes" / "orders.py").write_text(
            textwrap.dedent(
                """\
                from .. import bp
                from ..auth.helpers import authenticate_customer


                @bp.before_request
                def require_auth():
                    return authenticate_customer()
                """
            )
        )
        return pkg

    def test_nested_namespace_subpackage_keeps_outer_package_prefix(self, tmp_path: Path) -> None:
        """An ``__init__``-less dir inside a regular package keeps the prefix."""
        pkg = self._make_layout(tmp_path)

        fqn, is_package = _module_fqn_for_path(pkg / "auth" / "middleware.py", pkg)
        assert fqn == "app.auth.middleware"
        assert is_package is False
        # No truncation to ``auth.middleware`` and no leading dot.
        assert not fqn.startswith(".")
        assert fqn.split(".")[0] == "app"

    def test_relative_decorator_fqn_is_well_formed(self, tmp_path: Path) -> None:
        """``@bp.before_request`` (bp relative-imported) yields a clean FQN."""
        pkg = self._make_layout(tmp_path)
        out = extract_structural(pkg)

        protect = next(f for f in out.functions if f.fqn == "app.auth.middleware.protect")
        assert protect.decorator_fqns, "decorator FQN should be captured"
        for deco_fqn in protect.decorator_fqns:
            assert deco_fqn is not None
            assert not deco_fqn.startswith("."), deco_fqn
            assert ".." not in deco_fqn, deco_fqn
            assert deco_fqn.split(".")[0] == "app", deco_fqn

    def test_cross_module_hook_callee_resolves(self, tmp_path: Path) -> None:
        """The hook body's cross-module relative-import call resolves to a FQN."""
        pkg = self._make_layout(tmp_path)
        out = extract_structural(pkg)

        edges = {(edge.caller_fqn, edge.callee_fqn): edge.resolution for edge in out.call_edges}
        key = (
            "app.routes.orders.require_auth",
            "app.auth.helpers.authenticate_customer",
        )
        assert key in edges, [
            (e.caller_fqn, e.callee_fqn, e.unresolved_reason)
            for e in out.call_edges
            if e.caller_fqn == "app.routes.orders.require_auth"
        ]
        assert edges[key] is ResolutionStatus.RESOLVED

    def test_reexport_collision_does_not_clobber_real_subpackage(self, tmp_path: Path) -> None:
        """``from .routes import auth`` must not redirect the real ``auth/`` pkg.

        The root ``__init__`` rebinds the name ``auth`` to ``app.routes.auth``,
        but ``app.auth.helpers`` is a real submodule reached via ``..auth.helpers``
        and its FQN must stay rooted at the genuine subpackage.
        """
        pkg = self._make_layout(tmp_path)
        out = extract_structural(pkg)

        callee_fqns = {edge.callee_fqn for edge in out.call_edges}
        assert "app.auth.helpers.authenticate_customer" in callee_fqns
        # The collision must not produce a ``routes.auth.helpers`` mis-rooting.
        assert not any(fqn and "routes.auth.helpers" in fqn for fqn in callee_fqns), sorted(
            f for f in callee_fqns if f
        )


# ── Helper to run extraction on a fixture ─────────────────────────────


def _extract(fixture_name: str) -> StructuralOutput:
    return extract_structural(FIXTURES / fixture_name)


def _call_edges_from(out: StructuralOutput, caller_fqn: str) -> tuple[CallEdge, ...]:
    return tuple(edge for edge in out.call_edges if edge.caller_fqn == caller_fqn)


def _call_edge_on_line(out: StructuralOutput, caller_fqn: str, line: int) -> CallEdge:
    return next(
        edge
        for edge in out.call_edges
        if edge.caller_fqn == caller_fqn and edge.location.line == line
    )


# ── Function extraction ───────────────────────────────────────────────


class TestFunctionExtraction:
    @pytest.fixture(autouse=True)
    def _extract(self) -> None:
        self.out = _extract("functions")

    def test_function_count(self) -> None:
        # main.py: top_level, with_nested, inner, with_lambda, with_closure,
        #          transform lambda, inner, Calculator.add/multiply/zero/from_value
        # helpers.py: validate_positive, format_result
        assert len(self.out.functions) == 13

    def test_top_level_function(self) -> None:
        fn = next(f for f in self.out.functions if f.name == "top_level")
        assert fn.kind == FunctionKind.TOP_LEVEL
        assert not fn.is_method
        assert not fn.is_nested
        assert not fn.is_async
        assert fn.parent_class is None

    def test_function_params(self) -> None:
        fn = next(f for f in self.out.functions if f.name == "top_level")
        assert len(fn.params) == 2
        assert fn.params[0].name == "x"
        assert fn.params[0].default is None
        assert fn.params[0].kind == ParameterKind.POSITIONAL_OR_KEYWORD
        assert fn.params[1].name == "y"
        assert fn.params[1].default == "10"

    def test_nested_function(self) -> None:
        inner_fns = [f for f in self.out.functions if f.name == "inner"]
        assert len(inner_fns) == 2  # one in with_nested, one in with_closure
        for fn in inner_fns:
            assert fn.kind == FunctionKind.NESTED
            assert fn.is_nested

    def test_method_detection(self) -> None:
        add = next(f for f in self.out.functions if f.name == "add")
        assert add.kind == FunctionKind.METHOD
        assert add.is_method
        assert add.parent_class == "main.Calculator"

    def test_staticmethod(self) -> None:
        zero = next(f for f in self.out.functions if f.name == "zero")
        assert zero.is_method
        assert "staticmethod" in zero.decorator_names

    def test_classmethod(self) -> None:
        fv = next(f for f in self.out.functions if f.name == "from_value")
        assert fv.is_method
        assert "classmethod" in fv.decorator_names

    def test_source_locations(self) -> None:
        fn = next(f for f in self.out.functions if f.name == "top_level")
        assert fn.location.file == "main.py"
        assert fn.location.line == 4  # def top_level(x, y=10):

    def test_provenance(self) -> None:
        fn = next(f for f in self.out.functions if f.name == "top_level")
        assert fn.provenance.producer == "structural_entity_pass"


# ── Class extraction ──────────────────────────────────────────────────


class TestClassExtraction:
    @pytest.fixture(autouse=True)
    def _extract(self) -> None:
        self.out = _extract("classes")

    def test_class_count(self) -> None:
        assert len(self.out.classes) == 6

    def test_base_classes(self) -> None:
        user = next(c for c in self.out.classes if c.name == "User")
        assert len(user.bases) == 2
        # At minimum the short names should be present
        base_short = [b.split(".")[-1] for b in user.bases]
        assert "Timestamped" in base_short
        assert "Base" in base_short

    def test_method_names(self) -> None:
        user = next(c for c in self.out.classes if c.name == "User")
        assert "__init__" in user.method_names
        assert "greet" in user.method_names

    def test_class_variables(self) -> None:
        ts = next(c for c in self.out.classes if c.name == "Timestamped")
        assert "created_at" in ts.class_var_names
        assert "updated_at" in ts.class_var_names

    def test_abstract_class(self) -> None:
        s = next(c for c in self.out.classes if c.name == "Serializable")
        base_short = [b.split(".")[-1] for b in s.bases]
        assert "ABC" in base_short

    def test_class_location(self) -> None:
        base = next(c for c in self.out.classes if c.name == "Base")
        assert base.location.file == "models.py"
        assert base.location.line == 6


class TestClassHierarchyFacts:
    def test_populates_single_inheritance_mro_subclasses_and_inherited_methods(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "models.py").write_text(
            "class Base:\n"
            "    def save(self):\n"
            "        pass\n"
            "    def delete(self):\n"
            "        pass\n\n"
            "class User(Base):\n"
            "    def save(self):\n"
            "        pass\n\n"
            "class Admin(User):\n"
            "    pass\n"
        )

        classes = {cls.fqn: cls for cls in extract_structural(tmp_path).classes}

        assert classes["pkg.models.Base"].mro_chain == (
            "pkg.models.Base",
            "builtins.object",
        )
        assert classes["pkg.models.Base"].subclasses == ("pkg.models.User",)
        assert classes["pkg.models.Base"].all_subclasses == (
            "pkg.models.User",
            "pkg.models.Admin",
        )
        assert classes["pkg.models.User"].mro_chain == (
            "pkg.models.User",
            "pkg.models.Base",
            "builtins.object",
        )
        assert classes["pkg.models.Admin"].mro_chain == (
            "pkg.models.Admin",
            "pkg.models.User",
            "pkg.models.Base",
            "builtins.object",
        )
        assert [
            (method.name, method.defining_class_fqn, method.resolution)
            for method in classes["pkg.models.User"].inherited_methods
        ] == [("delete", "pkg.models.Base", "mro")]
        assert [
            (method.name, method.defining_class_fqn, method.resolution)
            for method in classes["pkg.models.Admin"].inherited_methods
        ] == [
            ("save", "pkg.models.User", "mro"),
            ("delete", "pkg.models.Base", "mro"),
        ]

    def test_uses_c3_linearization_for_project_local_diamond(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "diamond.py").write_text(
            "class Root:\n"
            "    def root(self):\n"
            "        pass\n\n"
            "class Left(Root):\n"
            "    def left(self):\n"
            "        pass\n\n"
            "class Right(Root):\n"
            "    def right(self):\n"
            "        pass\n\n"
            "class Leaf(Left, Right):\n"
            "    pass\n"
        )

        classes = {cls.fqn: cls for cls in extract_structural(tmp_path).classes}

        assert classes["pkg.diamond.Leaf"].mro_chain == (
            "pkg.diamond.Leaf",
            "pkg.diamond.Left",
            "pkg.diamond.Right",
            "pkg.diamond.Root",
            "builtins.object",
        )
        assert classes["pkg.diamond.Root"].subclasses == (
            "pkg.diamond.Left",
            "pkg.diamond.Right",
        )
        assert classes["pkg.diamond.Root"].all_subclasses == (
            "pkg.diamond.Left",
            "pkg.diamond.Right",
            "pkg.diamond.Leaf",
        )
        assert [
            (method.name, method.defining_class_fqn)
            for method in classes["pkg.diamond.Leaf"].inherited_methods
        ] == [
            ("left", "pkg.diamond.Left"),
            ("right", "pkg.diamond.Right"),
            ("root", "pkg.diamond.Root"),
        ]

    def test_resolves_mro_through_imported_project_bases(self, tmp_path: Path) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "base.py").write_text("class ProjectBase:\n    def load(self):\n        pass\n")
        (pkg / "mixins.py").write_text("class AuditMixin:\n    def audit(self):\n        pass\n")
        (pkg / "models.py").write_text(
            "from pkg.base import ProjectBase\n"
            "from .mixins import AuditMixin\n\n"
            "class Account(ProjectBase, AuditMixin):\n"
            "    pass\n"
        )

        classes = {cls.fqn: cls for cls in extract_structural(tmp_path).classes}

        assert classes["pkg.models.Account"].bases == (
            "pkg.base.ProjectBase",
            "pkg.mixins.AuditMixin",
        )
        assert classes["pkg.models.Account"].mro_chain == (
            "pkg.models.Account",
            "pkg.base.ProjectBase",
            "pkg.mixins.AuditMixin",
            "builtins.object",
        )
        assert [
            (method.name, method.defining_class_fqn)
            for method in classes["pkg.models.Account"].inherited_methods
        ] == [
            ("load", "pkg.base.ProjectBase"),
            ("audit", "pkg.mixins.AuditMixin"),
        ]

    def test_unresolved_external_base_does_not_create_fake_mro_entries(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "models.py").write_text(
            "from external.framework import ExternalBase\n\n"
            "class Local:\n"
            "    def local_method(self):\n"
            "        pass\n\n"
            "class Child(ExternalBase, Local):\n"
            "    pass\n"
        )

        classes = {cls.fqn: cls for cls in extract_structural(tmp_path).classes}

        assert classes["pkg.models.Child"].bases == (
            "external.framework.ExternalBase",
            "pkg.models.Local",
        )
        assert classes["pkg.models.Child"].mro_chain == ("pkg.models.Child",)
        assert classes["pkg.models.Child"].inherited_methods == ()
        assert classes["pkg.models.Local"].subclasses == ("pkg.models.Child",)
        assert classes["pkg.models.Local"].all_subclasses == ("pkg.models.Child",)

    def test_mro_complete_true_for_fully_resolved_local_hierarchy(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "models.py").write_text(
            "class Base:\n    def save(self):\n        pass\n\nclass Child(Base):\n    pass\n"
        )

        classes = {cls.fqn: cls for cls in extract_structural(tmp_path).classes}

        assert classes["pkg.models.Base"].mro_complete is True
        assert classes["pkg.models.Child"].mro_complete is True

    def test_mro_complete_false_when_external_base_present(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "models.py").write_text(
            "from some.library import RemoteBase\n\n"
            "class Local:\n"
            "    pass\n\n"
            "class Child(RemoteBase):\n"
            "    pass\n"
        )

        classes = {cls.fqn: cls for cls in extract_structural(tmp_path).classes}

        assert classes["pkg.models.Local"].mro_complete is True
        assert classes["pkg.models.Child"].mro_complete is False

    def test_hierarchy_gaps_record_external_bases(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "models.py").write_text(
            "from some.external import ExternalBase\n\n"
            "class Local:\n"
            "    pass\n\n"
            "class Child(ExternalBase, Local):\n"
            "    pass\n"
        )

        classes = {cls.fqn: cls for cls in extract_structural(tmp_path).classes}

        child = classes["pkg.models.Child"]
        assert len(child.hierarchy_gaps) == 1
        assert child.hierarchy_gaps[0] == HierarchyGap(
            base_expression="some.external.ExternalBase",
            reason="external",
        )

    def test_hierarchy_gaps_empty_for_fully_resolved(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "models.py").write_text("class Base:\n    pass\n\nclass Child(Base):\n    pass\n")

        classes = {cls.fqn: cls for cls in extract_structural(tmp_path).classes}

        assert classes["pkg.models.Base"].hierarchy_gaps == ()
        assert classes["pkg.models.Child"].hierarchy_gaps == ()

    def test_detects_abstract_class_with_abc(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "models.py").write_text(
            "from abc import ABC\n\n"
            "class AbstractBase(ABC):\n"
            "    pass\n\n"
            "class Concrete:\n"
            "    pass\n"
        )

        classes = {cls.fqn: cls for cls in extract_structural(tmp_path).classes}

        assert classes["pkg.models.AbstractBase"].is_abstract is True
        assert classes["pkg.models.Concrete"].is_abstract is False

    def test_detects_abstract_class_with_metaclass(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "models.py").write_text(
            "from abc import ABCMeta\n\nclass AbstractBase(metaclass=ABCMeta):\n    pass\n"
        )

        classes = {cls.fqn: cls for cls in extract_structural(tmp_path).classes}

        ab = classes["pkg.models.AbstractBase"]
        assert ab.is_abstract is True
        assert ab.metaclass == "abc.ABCMeta"

    def test_detects_abstract_class_with_abstractmethod_decorator(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "models.py").write_text(
            "from abc import abstractmethod\n\n"
            "class Handler:\n"
            "    @abstractmethod\n"
            "    def handle(self):\n"
            "        pass\n\n"
            "class ConcreteHandler(Handler):\n"
            "    def handle(self):\n"
            "        return 42\n"
        )

        classes = {cls.fqn: cls for cls in extract_structural(tmp_path).classes}

        assert classes["pkg.models.Handler"].is_abstract is True
        assert classes["pkg.models.ConcreteHandler"].is_abstract is False

    def test_external_base_still_tracks_subclass_relationships_with_gaps(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "models.py").write_text(
            "from external.framework import ExternalBase\n\n"
            "class Local:\n"
            "    def local_method(self):\n"
            "        pass\n\n"
            "class Child(ExternalBase, Local):\n"
            "    pass\n"
        )

        classes = {cls.fqn: cls for cls in extract_structural(tmp_path).classes}

        child = classes["pkg.models.Child"]
        assert child.mro_complete is False
        assert len(child.hierarchy_gaps) == 1
        assert child.hierarchy_gaps[0].reason == "external"
        assert classes["pkg.models.Local"].mro_complete is True
        assert classes["pkg.models.Local"].hierarchy_gaps == ()
        # Subclass tracking still works despite incomplete MRO
        assert classes["pkg.models.Local"].subclasses == ("pkg.models.Child",)
        assert classes["pkg.models.Local"].all_subclasses == ("pkg.models.Child",)


# ── Decorator extraction ──────────────────────────────────────────────


class TestDecoratorExtraction:
    @pytest.fixture(autouse=True)
    def _extract(self) -> None:
        self.out = _extract("decorators")

    def test_simple_decorator(self) -> None:
        plain_decos = [d for d in self.out.decorators if d.target_fqn == "app.plain"]
        assert len(plain_decos) == 1
        assert plain_decos[0].name == "simple_decorator"
        assert plain_decos[0].args == ()

    def test_parameterized_decorator(self) -> None:
        admin_decos = [d for d in self.out.decorators if d.target_fqn == "app.admin_only"]
        assert len(admin_decos) == 1
        assert admin_decos[0].name == "requires_role"
        assert admin_decos[0].args == ('"admin"',)

    def test_stacked_decorators(self) -> None:
        stacked_decos = sorted(
            [d for d in self.out.decorators if d.target_fqn == "app.stacked"],
            key=lambda d: d.application_order,
        )
        assert len(stacked_decos) == 3
        # Order 0 = innermost (closest to def)
        assert stacked_decos[0].name == "log_calls"
        assert stacked_decos[1].name == "requires_role"
        assert stacked_decos[2].name == "simple_decorator"

    def test_decorator_application_order(self) -> None:
        stacked_decos = [d for d in self.out.decorators if d.target_fqn == "app.stacked"]
        orders = {d.name: d.application_order for d in stacked_decos}
        assert orders["log_calls"] == 0
        assert orders["requires_role"] == 1
        assert orders["simple_decorator"] == 2


# ── MethodView class-level decorators (DISC-047) ─────────────────────


class TestMethodViewDecoratorsClassAttribute:
    """L1 extraction of ``decorators = [...]`` on MethodView subclasses.

    Flask's MethodView applies decorators listed in the ``decorators``
    class attribute to every HTTP method handler.  This pattern is
    universally used in Flask CBV apps and caused 72+ false positives
    on a real Flask CBV app because the engine only extracts
    ``@decorator`` syntax, not class-level ``decorators`` attributes.

    Gap ref: DISC-047
    """

    def test_decorators_class_attribute_produces_decorator_facts(
        self,
        tmp_path: Path,
    ) -> None:
        """``decorators = [login_required]`` should produce DecoratorFact entries.

        L1 stays framework-agnostic: class-attribute decorator entries
        attach to the class, and the semantic provider fans out MethodView
        checks to HTTP method handlers.
        """
        (tmp_path / "views.py").write_text(
            "from flask.views import MethodView\n"
            "from flask_login import login_required\n\n"
            "class AdminView(MethodView):\n"
            "    decorators = [login_required]\n\n"
            "    def get(self):\n"
            "        return 'ok'\n\n"
            "    def post(self):\n"
            "        return 'ok'\n"
        )

        out = extract_structural(tmp_path)

        admin_decos = [
            d
            for d in out.decorators
            if d.target_fqn == "views.AdminView" and d.name == "login_required"
        ]
        assert len(admin_decos) == 1
        assert admin_decos[0].fqn == "flask_login.login_required"
        assert admin_decos[0].application_order == 0

    def test_class_decorators_attribute_covers_all_methods(
        self,
        tmp_path: Path,
    ) -> None:
        """Class-attached facts give L2 one source covering every method."""
        (tmp_path / "views.py").write_text(
            "from flask.views import MethodView\n"
            "from flask_login import login_required\n\n"
            "def custom_guard(fn):\n"
            "    return fn\n\n"
            "class SecureView(MethodView):\n"
            "    decorators = (login_required, custom_guard)\n\n"
            "    def get(self):\n"
            "        return 'ok'\n"
            "    def post(self):\n"
            "        return 'ok'\n"
        )

        out = extract_structural(tmp_path)

        class_decos = [d for d in out.decorators if d.target_fqn == "views.SecureView"]
        assert [(d.name, d.application_order) for d in class_decos] == [
            ("login_required", 0),
            ("custom_guard", 1),
        ]
        assert all(
            d.target_fqn not in ("views.SecureView.get", "views.SecureView.post")
            for d in out.decorators
        )

    def test_annotated_decorators_class_attribute_is_extracted(
        self,
        tmp_path: Path,
    ) -> None:
        """Typed ``decorators: list = [...]`` attributes use the same contract."""
        (tmp_path / "views.py").write_text(
            "from flask.views import MethodView\n"
            "from flask_login import login_required\n\n"
            "class SecureView(MethodView):\n"
            "    decorators: list = [login_required]\n\n"
            "    def get(self):\n"
            "        return 'ok'\n"
        )

        out = extract_structural(tmp_path)

        class_decos = [d for d in out.decorators if d.target_fqn == "views.SecureView"]
        assert [d.name for d in class_decos] == ["login_required"]

    def test_no_decorators_attribute_means_no_extra_facts(
        self,
        tmp_path: Path,
    ) -> None:
        """MethodView WITHOUT ``decorators`` should NOT get phantom decorator facts."""
        (tmp_path / "views.py").write_text(
            "from flask.views import MethodView\n\n"
            "class PlainView(MethodView):\n"
            "    def get(self):\n"
            "        return 'ok'\n"
        )

        out = extract_structural(tmp_path)

        get_decos = [d for d in out.decorators if d.target_fqn == "views.PlainView.get"]
        # No class-level decorators → no extra decorator facts
        assert len(get_decos) == 0, (
            f"PlainView has no decorators attribute; "
            f"should produce no decorator facts; got {get_decos}"
        )


# ── Call edge extraction ──────────────────────────────────────────────


class TestCallEdgeExtraction:
    @pytest.fixture(autouse=True)
    def _extract(self) -> None:
        self.out = _extract("functions")

    def test_call_edges_exist(self) -> None:
        assert len(self.out.call_edges) > 0

    def test_inner_call(self) -> None:
        # with_nested calls inner(5)
        edges = [e for e in self.out.call_edges if "inner" in (e.callee_fqn or "")]
        assert len(edges) >= 1

    def test_call_arguments(self) -> None:
        # with_nested calls inner(5)
        edges = [e for e in self.out.call_edges if "inner" in (e.callee_fqn or "")]
        if edges:
            assert len(edges[0].arguments) >= 1

    def test_two_stage_call_preserves_outer_target_argument(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
from flask import Blueprint
from flask_limiter import Limiter

limiter = Limiter()
auth = Blueprint("auth", __name__)
limiter.limit("5/minute")(auth)
""",
            encoding="utf-8",
        )

        out = extract_structural(tmp_path)

        edge = next(
            edge
            for edge in out.call_edges
            if edge.location.line == 6 and edge.arguments[0].expression == "auth"
        )
        assert edge.call_expression == 'limiter.limit("5/minute")(auth)'
        assert edge.callee_fqn == "app.limiter.limit"
        assert [(arg.position, arg.expression) for arg in edge.arguments] == [(0, "auth")]

    def test_subscript_assignment_records_setitem_call_edge(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
def configure(app):
    app.config["DEBUG"] = True
""",
            encoding="utf-8",
        )

        out = extract_structural(tmp_path)

        edge = _call_edge_on_line(out, "app.configure", 2)
        assert edge.callee_fqn is not None
        assert edge.callee_fqn.endswith(".config.__setitem__")
        assert edge.call_expression == 'app.config.__setitem__("DEBUG", True)'
        assert [(arg.position, arg.expression) for arg in edge.arguments] == [
            (0, '"DEBUG"'),
            (1, "True"),
        ]
        assert edge.resolution is ResolutionStatus.RESOLVED
        assert edge.source is EdgeSource.AST


class TestReceiverMethodCallResolution:
    def test_self_method_call_resolves_to_local_method(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """
class Service:
    def run(self):
        self.helper()

    def helper(self):
        return None
""".lstrip()
        )

        out = extract_structural(tmp_path)

        callees = {edge.callee_fqn for edge in _call_edges_from(out, "app.Service.run")}
        assert "app.Service.helper" in callees
        assert not any("<locals>.self" in (callee or "") for callee in callees)

    def test_self_method_call_resolves_to_inherited_method(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """
class Base:
    def save(self):
        return None


class User(Base):
    def run(self):
        self.save()
""".lstrip()
        )

        out = extract_structural(tmp_path)

        callees = {edge.callee_fqn for edge in _call_edges_from(out, "app.User.run")}
        assert "app.Base.save" in callees
        assert "app.User.save" not in callees
        assert not any("<locals>.self" in (callee or "") for callee in callees)

    def test_classmethod_cls_method_call_resolves_to_local_method(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """
class Factory:
    @classmethod
    def build(cls):
        return cls.validate()

    @classmethod
    def validate(cls):
        return None
""".lstrip()
        )

        out = extract_structural(tmp_path)

        callees = {edge.callee_fqn for edge in _call_edges_from(out, "app.Factory.build")}
        assert "app.Factory.validate" in callees
        assert not any("<locals>.cls" in (callee or "") for callee in callees)

    def test_staticmethod_self_name_does_not_create_receiver_edge(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """
class Utility:
    @staticmethod
    def run(self):
        self.cleanup()

    def cleanup(self):
        return None
""".lstrip()
        )

        out = extract_structural(tmp_path)

        edge = _call_edge_on_line(out, "app.Utility.run", 4)
        assert edge.callee_fqn is None
        assert edge.resolution == ResolutionStatus.UNRESOLVED
        assert edge.unresolved_reason == "receiver_not_bound"

    def test_non_first_self_parameter_does_not_create_receiver_edge(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """
class Service:
    def run(context, self):
        self.helper()

    def helper(self):
        return None
""".lstrip()
        )

        out = extract_structural(tmp_path)

        edge = _call_edge_on_line(out, "app.Service.run", 3)
        assert edge.callee_fqn is None
        assert edge.resolution == ResolutionStatus.UNRESOLVED
        assert edge.unresolved_reason == "receiver_not_bound"

    def test_missing_receiver_method_records_unresolved_edge(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """
class Service:
    def run(self):
        self.missing()
""".lstrip()
        )

        out = extract_structural(tmp_path)

        edge = _call_edge_on_line(out, "app.Service.run", 3)
        assert edge.callee_fqn is None
        assert edge.resolution == ResolutionStatus.UNRESOLVED
        assert edge.unresolved_reason == "receiver_method_not_in_mro"


class TestSuperCallResolution:
    """super().method() resolves to the next MRO method (L1-007b)."""

    def test_super_method_resolves_to_parent_method(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
class Base:
    def save(self):
        return None

class User(Base):
    def run(self):
        super().save()
"""
        )
        out = extract_structural(tmp_path)
        edge = _call_edge_on_line(out, "app.User.run", 7)
        assert edge.callee_fqn == "app.Base.save"
        assert edge.resolution == ResolutionStatus.RESOLVED

    def test_super_method_resolves_through_mro_chain(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
class A:
    def save(self):
        return None

class B(A):
    pass

class C(B):
    def run(self):
        super().save()
"""
        )
        out = extract_structural(tmp_path)
        edge = _call_edge_on_line(out, "app.C.run", 10)
        assert edge.callee_fqn == "app.A.save"
        assert edge.resolution == ResolutionStatus.RESOLVED

    def test_bare_super_call_left_unmodified(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
class Base:
    pass

class User(Base):
    def run(self):
        x = super()
"""
        )
        out = extract_structural(tmp_path)
        edge = _call_edge_on_line(out, "app.User.run", 6)
        assert edge.callee_fqn == "builtins.super"
        assert edge.resolution == ResolutionStatus.RESOLVED

    def test_super_outside_method_produces_unresolved_edge(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
def standalone():
    super().run()
"""
        )
        out = extract_structural(tmp_path)
        edge = _call_edge_on_line(out, "app.standalone", 2)
        assert edge.callee_fqn is None
        assert edge.resolution == ResolutionStatus.UNRESOLVED
        assert edge.unresolved_reason == "super_not_in_method"

    def test_super_method_not_found_produces_unresolved_edge(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
class Base:
    pass

class User(Base):
    def run(self):
        super().missing()
"""
        )
        out = extract_structural(tmp_path)
        edge = _call_edge_on_line(out, "app.User.run", 6)
        assert edge.callee_fqn is None
        assert edge.resolution == ResolutionStatus.UNRESOLVED
        assert edge.unresolved_reason == "super_method_not_in_mro"

    def test_super_with_incomplete_mro_produces_unresolved_edge(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
from flask import Flask

class User(Flask):
    def run(self):
        super().save()
"""
        )
        out = extract_structural(tmp_path)
        edge = _call_edge_on_line(out, "app.User.run", 5)
        assert edge.callee_fqn is None
        assert edge.resolution == ResolutionStatus.UNRESOLVED
        assert edge.unresolved_reason == "super_mro_incomplete"

    def test_super_in_classmethod_resolves(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
class Base:
    @classmethod
    def validate(cls):
        return None

class User(Base):
    @classmethod
    def check(cls):
        super().validate()
"""
        )
        out = extract_structural(tmp_path)
        edge = _call_edge_on_line(out, "app.User.check", 9)
        assert edge.callee_fqn == "app.Base.validate"
        assert edge.resolution == ResolutionStatus.RESOLVED

    def test_super_skips_own_class_in_mro(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
class Base:
    def save(self):
        return None

class User(Base):
    def save(self):
        super().save()
"""
        )
        out = extract_structural(tmp_path)
        edge = _call_edge_on_line(out, "app.User.save", 7)
        assert edge.callee_fqn == "app.Base.save"
        assert edge.resolution == ResolutionStatus.RESOLVED


class TestConstructorCallResolution:
    """Constructor calls resolve to __init__ when present (L1-007b)."""

    def test_constructor_resolves_to_init(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
class User:
    def __init__(self, name):
        self.name = name

def create():
    return User("alice")
"""
        )
        out = extract_structural(tmp_path)
        edge = _call_edge_on_line(out, "app.create", 6)
        assert edge.callee_fqn == "app.User.__init__"
        assert edge.resolution == ResolutionStatus.RESOLVED

    def test_constructor_resolves_to_inherited_init(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
class Parent:
    def __init__(self, name):
        self.name = name

class Child(Parent):
    pass

def create():
    return Child("alice")
"""
        )
        out = extract_structural(tmp_path)
        edge = _call_edge_on_line(out, "app.create", 9)
        assert edge.callee_fqn == "app.Parent.__init__"
        assert edge.resolution == ResolutionStatus.RESOLVED

    def test_constructor_without_init_unchanged(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
class Config:
    debug = True

def create():
    return Config()
"""
        )
        out = extract_structural(tmp_path)
        edge = _call_edge_on_line(out, "app.create", 5)
        assert edge.callee_fqn == "app.Config"
        assert edge.resolution == ResolutionStatus.RESOLVED

    def test_constructor_non_project_class_unchanged(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
def create():
    x = dict()
    y = list()
    return x
"""
        )
        out = extract_structural(tmp_path)
        edges = _call_edges_from(out, "app.create")
        for edge in edges:
            assert edge.callee_fqn is not None
            assert "__init__" not in (edge.callee_fqn or "")

    def test_framework_decorator_does_not_create_dispatch_edge(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    return "hello"
"""
        )
        out = extract_structural(tmp_path)
        # L1 should not create a route→handler dispatch edge
        for edge in out.call_edges:
            if edge.callee_fqn == "app.index":
                # The only caller of index should be through a normal
                # call, not a framework dispatch edge
                assert edge.source.name in {"AST", "HIERARCHY"}


class TestDynamicDispatchGaps:
    """Dynamic dispatch shapes become explicit unresolved call edges (L1-007c)."""

    def test_getattr_call_records_dynamic_dispatch_edge(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
class Service:
    def handle(self):
        return None

def run(service, action):
    return getattr(service, action)()
"""
        )

        out = extract_structural(tmp_path)

        dynamic_edge = _call_edge_on_line(out, "app.run", 6)
        assert dynamic_edge.callee_fqn is None
        assert dynamic_edge.resolution == ResolutionStatus.UNRESOLVED
        assert dynamic_edge.unresolved_reason == "dynamic_dispatch_getattr"
        assert dynamic_edge.dynamic_dispatch_kind == "getattr"
        assert dynamic_edge.call_expression == "getattr(service, action)"

        getattr_edge = next(edge for edge in _call_edges_from(out, "app.run") if edge.callee_fqn)
        assert getattr_edge.callee_fqn == "builtins.getattr"
        assert getattr_edge.dynamic_dispatch_kind is None

    def test_table_dispatch_call_records_dynamic_dispatch_edge(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
def create():
    return "created"

def delete():
    return "deleted"

def run(action):
    handlers = {"create": create, "delete": delete}
    return handlers[action]()
"""
        )

        out = extract_structural(tmp_path)

        dynamic_edge = _call_edge_on_line(out, "app.run", 9)
        assert dynamic_edge.callee_fqn is None
        assert dynamic_edge.resolution == ResolutionStatus.UNRESOLVED
        assert dynamic_edge.unresolved_reason == "dynamic_dispatch_table"
        assert dynamic_edge.dynamic_dispatch_kind == "table"
        assert dynamic_edge.call_expression == "handlers[action]"

    def test_table_dispatch_method_records_dynamic_dispatch_edge(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
def run(registry, key, payload):
    return registry[key].handle(payload)
"""
        )

        out = extract_structural(tmp_path)

        dynamic_edge = _call_edge_on_line(out, "app.run", 2)
        assert dynamic_edge.callee_fqn is None
        assert dynamic_edge.resolution == ResolutionStatus.UNRESOLVED
        assert dynamic_edge.unresolved_reason == "dynamic_dispatch_table"
        assert dynamic_edge.dynamic_dispatch_kind == "table"
        assert dynamic_edge.call_expression == "registry[key].handle"

    def test_importlib_loaded_module_call_records_dynamic_dispatch_edge(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "app.py").write_text(
            """\
import importlib

def run(module_name, payload):
    module = importlib.import_module(module_name)
    return module.handle(payload)
"""
        )

        out = extract_structural(tmp_path)

        dynamic_edge = _call_edge_on_line(out, "app.run", 5)
        assert dynamic_edge.callee_fqn is None
        assert dynamic_edge.resolution == ResolutionStatus.UNRESOLVED
        assert dynamic_edge.unresolved_reason == "dynamic_dispatch_importlib"
        assert dynamic_edge.dynamic_dispatch_kind == "importlib"
        assert dynamic_edge.call_expression == "module.handle"

        import_edge = _call_edge_on_line(out, "app.run", 4)
        assert import_edge.callee_fqn == "importlib.import_module"
        assert import_edge.dynamic_dispatch_kind is None

    def test_benign_dynamic_looking_uses_keep_existing_call_edges(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
def run(service, table, key, factory):
    attr = getattr(service, "name")
    selected = table[key]
    return factory()()
"""
        )

        out = extract_structural(tmp_path)

        edges = _call_edges_from(out, "app.run")
        assert {edge.dynamic_dispatch_kind for edge in edges} == {None}
        assert "builtins.getattr" in {edge.callee_fqn for edge in edges}
        assert "table[key]" not in {edge.call_expression for edge in edges}

    def test_dunder_import_dispatch_records_importlib_edge(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
def load(module_name):
    mod = __import__(module_name)
    return mod.handle()
"""
        )

        out = extract_structural(tmp_path)

        dynamic_edge = _call_edge_on_line(out, "app.load", 3)
        assert dynamic_edge.callee_fqn is None
        assert dynamic_edge.resolution == ResolutionStatus.UNRESOLVED
        assert dynamic_edge.unresolved_reason == "dynamic_dispatch_importlib"
        assert dynamic_edge.dynamic_dispatch_kind == "importlib"

    def test_entry_points_load_records_entry_point_dispatch(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
from importlib.metadata import entry_points

def load_plugins():
    return entry_points(group="myapp.plugins")()
"""
        )

        out = extract_structural(tmp_path)

        dynamic_edge = _call_edge_on_line(out, "app.load_plugins", 4)
        assert dynamic_edge.callee_fqn is None
        assert dynamic_edge.resolution == ResolutionStatus.UNRESOLVED
        assert dynamic_edge.unresolved_reason == "dynamic_dispatch_entry_point"
        assert dynamic_edge.dynamic_dispatch_kind == "entry_point"

    def test_entry_point_load_call_records_entry_point_dispatch(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
from importlib.metadata import entry_points

def load_plugin(name):
    return entry_points(group="myapp.plugins")[name].load()()
"""
        )

        out = extract_structural(tmp_path)

        dynamic_edge = _call_edge_on_line(out, "app.load_plugin", 4)
        assert dynamic_edge.callee_fqn is None
        assert dynamic_edge.resolution == ResolutionStatus.UNRESOLVED
        assert dynamic_edge.unresolved_reason == "dynamic_dispatch_entry_point"
        assert dynamic_edge.dynamic_dispatch_kind == "entry_point"

    def test_pluggy_hook_call_records_pluggy_dispatch(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
def register_user(pm, user):
    pm.hook.plugin_event_user_registered(user=user)
"""
        )

        out = extract_structural(tmp_path)

        dynamic_edge = _call_edge_on_line(out, "app.register_user", 2)
        assert dynamic_edge.callee_fqn is None
        assert dynamic_edge.resolution == ResolutionStatus.UNRESOLVED
        assert dynamic_edge.unresolved_reason == "dynamic_dispatch_pluggy_hook"
        assert dynamic_edge.dynamic_dispatch_kind == "pluggy_hook"

    def test_non_hook_attribute_chain_not_tagged_pluggy(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
def run(obj):
    obj.config.get("key")
"""
        )

        out = extract_structural(tmp_path)

        edges = _call_edges_from(out, "app.run")
        assert all(edge.dynamic_dispatch_kind is None for edge in edges)


# ── Attribute access extraction ───────────────────────────────────────


def test_flask_request_attrs() -> None:
    """Existing baseline: Flask request attributes are captured."""
    out = _extract("flask_basic")
    assert len(out.attributes) > 0
    attr_names = [a.attr_name for a in out.attributes]
    assert "json" in attr_names


class TestAccessPatterns:
    """Comprehensive attribute and container access extraction (L1-003)."""

    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        self.out = _extract("access_patterns")

    def test_plain_attr_read(self) -> None:
        reads = [
            a
            for a in self.out.attributes
            if a.target_expr == "request" and a.attr_name == "args" and not a.is_write
        ]
        assert len(reads) >= 1
        assert reads[0].access_kind == AccessKind.ATTR

    def test_plain_attr_write(self) -> None:
        writes = [
            a
            for a in self.out.attributes
            if a.target_expr == "session"
            and a.attr_name == "user_id"
            and a.is_write
            and a.access_kind == AccessKind.ATTR
        ]
        assert len(writes) >= 1
        assert writes[0].value_expr == "42"

    def test_subscript_read(self) -> None:
        reads = [
            a
            for a in self.out.attributes
            if a.target_expr == "session"
            and a.attr_name == '"user_id"'
            and not a.is_write
            and a.access_kind == AccessKind.SUBSCRIPT
        ]
        assert len(reads) >= 1

    def test_subscript_write(self) -> None:
        writes = [
            a
            for a in self.out.attributes
            if a.target_expr == "session"
            and a.attr_name == '"user_id"'
            and a.is_write
            and a.access_kind == AccessKind.SUBSCRIPT
        ]
        assert len(writes) >= 1
        assert writes[0].value_expr == "42"

    def test_augmented_attr(self) -> None:
        augs = [
            a
            for a in self.out.attributes
            if a.target_expr == "db"
            and a.attr_name == "count"
            and a.access_kind == AccessKind.AUGMENTED
        ]
        assert len(augs) >= 1
        assert augs[0].is_write is True
        assert augs[0].value_expr == "1"

    def test_augmented_subscript(self) -> None:
        augs = [
            a
            for a in self.out.attributes
            if a.target_expr == "cache"
            and a.attr_name == '"hits"'
            and a.access_kind == AccessKind.AUGMENTED
        ]
        assert len(augs) >= 1
        assert augs[0].is_write is True

    def test_delete_attr(self) -> None:
        dels = [
            a
            for a in self.out.attributes
            if a.target_expr == "session"
            and a.attr_name == "user_id"
            and a.access_kind == AccessKind.DEL
        ]
        assert len(dels) >= 1
        assert dels[0].is_write is True
        assert dels[0].value_expr is None

    def test_delete_subscript(self) -> None:
        dels = [
            a
            for a in self.out.attributes
            if a.target_expr == "session"
            and a.attr_name == '"user_id"'
            and a.access_kind == AccessKind.DEL
        ]
        assert len(dels) >= 1
        assert dels[0].is_write is True

    def test_list_call_mutator(self) -> None:
        muts = [
            a
            for a in self.out.attributes
            if a.target_expr == "items"
            and a.attr_name == "append"
            and a.access_kind == AccessKind.CALL_MUTATOR
        ]
        assert len(muts) == 1
        assert muts[0].is_write is True
        assert muts[0].value_expr == '"new"'
        assert muts[0].containing_function_fqn == "app.call_mutator"

    def test_dict_call_mutator(self) -> None:
        muts = [
            a
            for a in self.out.attributes
            if a.target_expr == "cache"
            and a.attr_name == "update"
            and a.access_kind == AccessKind.CALL_MUTATOR
        ]
        assert len(muts) == 1
        assert muts[0].is_write is True
        assert muts[0].value_expr == '{"k": "v"}'

    def test_set_call_mutator(self) -> None:
        muts = [
            a
            for a in self.out.attributes
            if a.target_expr == "tokens"
            and a.attr_name == "add"
            and a.access_kind == AccessKind.CALL_MUTATOR
        ]
        assert len(muts) == 1
        assert muts[0].is_write is True
        assert muts[0].value_expr == '"session-token"'

    def test_nested_receiver_call_mutator(self) -> None:
        muts = [
            a
            for a in self.out.attributes
            if a.target_expr == "store.items"
            and a.attr_name == "extend"
            and a.access_kind == AccessKind.CALL_MUTATOR
        ]
        assert len(muts) == 1
        assert muts[0].is_write is True
        assert muts[0].value_expr == '["a", "b"]'

    def test_non_mutating_method_call_does_not_emit_call_mutator(self) -> None:
        muts = [
            a
            for a in self.out.attributes
            if a.target_expr == "items"
            and a.attr_name == "count"
            and a.access_kind == AccessKind.CALL_MUTATOR
        ]
        assert muts == []

    def test_dynamic_getattr_access_remains_absent_from_attribute_access(self) -> None:
        attrs = [
            a
            for a in self.out.attributes
            if a.containing_function_fqn == "app.dynamic_getattr_access"
        ]
        assert attrs == []

    def test_containing_function_fqn(self) -> None:
        """Each access records its containing function."""
        writes = [
            a
            for a in self.out.attributes
            if a.attr_name == "user_id" and a.is_write and a.access_kind == AccessKind.ATTR
        ]
        assert len(writes) >= 1
        assert writes[0].containing_function_fqn is not None
        assert "write_attrs" in writes[0].containing_function_fqn

    def test_collection_of_kind_filter(self) -> None:
        """The of_kind() collection filter works for all emitted kinds."""
        from flawed._index._collections import AttributeAccessCollection

        coll = AttributeAccessCollection(tuple(self.out.attributes))
        subs = coll.of_kind(AccessKind.SUBSCRIPT)
        assert len(subs) >= 4  # 2 reads + 2 writes
        for a in subs:
            assert a.access_kind == AccessKind.SUBSCRIPT

        augs = coll.of_kind(AccessKind.AUGMENTED)
        assert len(augs) >= 4  # 2 attr + 2 subscript
        for a in augs:
            assert a.access_kind == AccessKind.AUGMENTED

        dels = coll.of_kind(AccessKind.DEL)
        assert len(dels) >= 4  # 2 attr + 2 subscript
        for a in dels:
            assert a.access_kind == AccessKind.DEL

        mutators = coll.of_kind(AccessKind.CALL_MUTATOR)
        assert len(mutators) >= 4  # append, update, add, extend
        for a in mutators:
            assert a.access_kind == AccessKind.CALL_MUTATOR


# ── Assignment extraction ─────────────────────────────────────────────


class TestAssignmentExtraction:
    def test_simple_assignments(self) -> None:
        out = _extract("minimal")
        assert len(out.assignments) >= 1
        greeting = next(
            (a for a in out.assignments if a.target == "greeting"),
            None,
        )
        assert greeting is not None
        assert greeting.value_expression == "hello()"
        assert greeting.kind == AssignmentKind.SIMPLE

    def test_class_variable_assignments(self) -> None:
        out = _extract("classes")
        # Timestamped: created_at = None, updated_at = None
        assigns = [a for a in out.assignments if a.target in ("created_at", "updated_at")]
        assert len(assigns) == 2
        for a in assigns:
            assert a.value_expression == "None"


# ── Comprehension binding extraction ─────────────────────────────────


class TestComprehensionBindingExtraction:
    def test_list_comprehension_records_target_and_iterable(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
def collect(items):
    return [item.name for item in items if item.active]
"""
        )

        out = extract_structural(tmp_path)

        assert len(out.comprehension_bindings) == 1
        binding = out.comprehension_bindings[0]
        assert binding.target == "item"
        assert binding.iterable_expression == "items"
        assert binding.comprehension_expr == "[item.name for item in items if item.active]"
        assert binding.containing_function_fqn == "app.collect"
        assert binding.target_location.file == "app.py"
        assert binding.iterable_location.file == "app.py"

    def test_nested_comprehension_records_each_generator(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
def flatten(groups):
    return [(group.name, user.email) for group in groups for user in group.users]
"""
        )

        out = extract_structural(tmp_path)

        pairs = {
            (binding.iterable_expression, binding.target) for binding in out.comprehension_bindings
        }
        assert pairs == {("groups", "group"), ("group.users", "user")}
        assert {binding.containing_function_fqn for binding in out.comprehension_bindings} == {
            "app.flatten"
        }


# ── Return extraction ─────────────────────────────────────────────────


class TestReturnExtraction:
    def test_return_expression_records_expression_and_statement_locations(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "app.py").write_text(
            """\
def helper(value):
    return value.strip()
"""
        )

        out = extract_structural(tmp_path)

        assert len(out.returns) == 1
        ret = out.returns[0]
        assert ret.expression == "value.strip()"
        assert ret.expression_location is not None
        assert ret.expression_location.line == 2
        assert ret.statement_location.line == 2
        assert ret.containing_function_fqn == "app.helper"

    def test_bare_return_records_no_expression(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
def stop():
    return
"""
        )

        out = extract_structural(tmp_path)

        assert len(out.returns) == 1
        assert out.returns[0].expression is None
        assert out.returns[0].expression_location is None
        assert out.returns[0].statement_location.line == 2
        assert out.returns[0].containing_function_fqn == "app.stop"


# ── Yield extraction ─────────────────────────────────────────────────


class TestYieldExtraction:
    def test_yield_expression_records_expression_and_locations(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
def gen(items):
    for item in items:
        yield item.name
"""
        )

        out = extract_structural(tmp_path)

        assert len(out.yields) == 1
        yld = out.yields[0]
        assert yld.expression == "item.name"
        assert yld.expression_location is not None
        assert yld.expression_location.line == 3
        assert yld.statement_location.line == 3
        assert yld.is_from is False
        assert yld.containing_function_fqn == "app.gen"

    def test_bare_yield_records_no_expression(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
def gen():
    yield
"""
        )

        out = extract_structural(tmp_path)

        assert len(out.yields) == 1
        assert out.yields[0].expression is None
        assert out.yields[0].expression_location is None
        assert out.yields[0].statement_location.line == 2
        assert out.yields[0].is_from is False

    def test_yield_from_records_is_from_flag(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text(
            """\
def delegator(sub):
    yield from sub.generate()
"""
        )

        out = extract_structural(tmp_path)

        assert len(out.yields) == 1
        yld = out.yields[0]
        assert yld.expression == "sub.generate()"
        assert yld.is_from is True
        assert yld.containing_function_fqn == "app.delegator"


# ── Import extraction ─────────────────────────────────────────────────


class TestImportExtraction:
    @pytest.fixture(autouse=True)
    def _extract(self) -> None:
        self.out = _extract("imports")

    def test_package_local_module_fqns(self) -> None:
        fqns = {fn.fqn for fn in self.out.functions}
        assert "imports.helpers.process_data" in fqns
        assert "imports.main.run" in fqns

    def test_bare_import(self) -> None:
        os_imports = [i for i in self.out.imports if i.module == "os" and not i.is_from_import]
        assert len(os_imports) == 1

    def test_from_import(self) -> None:
        pathlib_imports = [i for i in self.out.imports if i.module == "pathlib"]
        assert len(pathlib_imports) == 1
        assert pathlib_imports[0].is_from_import
        assert "Path" in pathlib_imports[0].names

    def test_aliased_import(self) -> None:
        aliases = [a for a in self.out.aliases if a.alias_name == "osp"]
        assert len(aliases) == 1
        assert aliases[0].mechanism == AliasMechanism.IMPORT_ALIAS

    def test_from_import_alias(self) -> None:
        aliases = [a for a in self.out.aliases if a.alias_name == "OD"]
        assert len(aliases) == 1
        assert aliases[0].original_fqn == "collections.OrderedDict"

    def test_relative_imports_resolve_to_package_modules(self) -> None:
        package_imports = [
            i for i in self.out.imports if i.module == "imports" and "helpers" in i.names
        ]
        helper_imports = [
            i
            for i in self.out.imports
            if i.module == "imports.helpers" and "process_data" in i.names
        ]
        assert len(package_imports) == 1
        assert len(helper_imports) == 1

    def test_relative_import_alias(self) -> None:
        aliases = [a for a in self.out.aliases if a.alias_name == "t"]
        assert len(aliases) == 1
        assert aliases[0].mechanism == AliasMechanism.IMPORT_ALIAS
        assert aliases[0].original_fqn == "imports.helpers.transform"

    def test_relative_imports_create_symbol_refs(self) -> None:
        resolved = {
            (ref.name, ref.fqn) for ref in self.out.symbol_refs if ref.location.file == "main.py"
        }
        assert ("process_data", "imports.helpers.process_data") in resolved
        assert ("t", "imports.helpers.transform") in resolved

    def test_missing_project_absolute_import_module_records_resolution_gap_and_unresolved_refs(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "consumer.py").write_text(
            "from pkg.missing import process_data\n\n"
            "def run():\n"
            "    return process_data('input')\n"
        )

        out = extract_structural(tmp_path)

        gaps = [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]
        assert len(gaps) == 1
        assert not gaps[0].is_fatal
        assert gaps[0].location is not None
        assert "pkg.missing" in gaps[0].message

        refs = [
            ref
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py" and ref.name == "process_data"
        ]
        assert len(refs) == 2
        assert {ref.resolution for ref in refs} == {ResolutionStatus.UNRESOLVED}
        assert {ref.fqn for ref in refs} == {None}

        edge = next(edge for edge in out.call_edges if edge.caller_fqn == "pkg.consumer.run")
        assert edge.callee_fqn is None
        assert edge.resolution == ResolutionStatus.UNRESOLVED
        assert edge.unresolved_reason == "unresolved_project_import"

    def test_missing_project_import_member_records_resolution_gap_and_unresolved_refs(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import missing\n\ndef run():\n    return missing('input')\n"
        )

        out = extract_structural(tmp_path)

        gaps = [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]
        assert len(gaps) == 1
        assert not gaps[0].is_fatal
        assert gaps[0].location is not None
        assert "pkg.helpers.missing" in gaps[0].message

        refs = [
            ref
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py" and ref.name == "missing"
        ]
        assert len(refs) == 2
        assert {ref.resolution for ref in refs} == {ResolutionStatus.UNRESOLVED}
        assert {ref.fqn for ref in refs} == {None}

        edge = next(edge for edge in out.call_edges if edge.caller_fqn == "pkg.consumer.run")
        assert edge.callee_fqn is None
        assert edge.resolution == ResolutionStatus.UNRESOLVED
        assert edge.unresolved_reason == "unresolved_project_import"

    def test_missing_project_import_member_drops_dependent_alias_facts(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import missing as local_missing\n"
            "alias_missing = local_missing\n\n"
            "def run():\n"
            "    return alias_missing('input')\n"
        )

        out = extract_structural(tmp_path)

        gaps = [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]
        assert len(gaps) == 1
        assert "pkg.helpers.missing" in gaps[0].message

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert (
            "local_missing",
            "pkg.helpers.missing",
            AliasMechanism.IMPORT_ALIAS,
        ) not in aliases
        assert (
            "alias_missing",
            "pkg.helpers.missing",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) not in aliases

        refs = [
            ref
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py" and ref.name == "alias_missing"
        ]
        assert refs
        assert {ref.resolution for ref in refs} == {ResolutionStatus.UNRESOLVED}
        assert {ref.fqn for ref in refs} == {None}

        edge = next(edge for edge in out.call_edges if edge.caller_fqn == "pkg.consumer.run")
        assert edge.callee_fqn is None
        assert edge.resolution == ResolutionStatus.UNRESOLVED
        assert edge.unresolved_reason == "unresolved_project_import"

    def test_missing_project_imported_attribute_alias_records_gap_and_unresolved_refs(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "import pkg.helpers as helpers\n"
            "local_missing = helpers.missing\n\n"
            "def run():\n"
            "    return local_missing('input')\n"
        )

        out = extract_structural(tmp_path)

        gaps = [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]
        assert len(gaps) == 1
        assert not gaps[0].is_fatal
        assert gaps[0].location is not None
        assert "pkg.helpers.missing" in gaps[0].message

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert ("helpers", "pkg.helpers", AliasMechanism.IMPORT_ALIAS) in aliases
        assert (
            "local_missing",
            "pkg.helpers.missing",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) not in aliases

        refs = [
            ref
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py" and ref.name == "local_missing"
        ]
        assert refs
        assert {ref.resolution for ref in refs} == {ResolutionStatus.UNRESOLVED}
        assert {ref.fqn for ref in refs} == {None}

        edge = next(edge for edge in out.call_edges if edge.caller_fqn == "pkg.consumer.run")
        assert edge.callee_fqn is None
        assert edge.resolution == ResolutionStatus.UNRESOLVED
        assert edge.unresolved_reason == "unresolved_project_import"

    def test_missing_direct_project_imported_attribute_call_records_gap(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "import pkg.helpers as helpers\n\n"
            "def run():\n"
            "    return helpers.missing('input'), helpers.process_data('other')\n"
        )

        out = extract_structural(tmp_path)

        gaps = [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]
        assert len(gaps) == 1
        assert not gaps[0].is_fatal
        assert gaps[0].location is not None
        assert "pkg.helpers.missing" in gaps[0].message

        refs = {
            (ref.name, ref.fqn, ref.resolution)
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
        }
        assert ("helpers.missing", None, ResolutionStatus.UNRESOLVED) in refs
        assert (
            "helpers.process_data",
            "pkg.helpers.process_data",
            ResolutionStatus.RESOLVED,
        ) in refs

        run_edges = [edge for edge in out.call_edges if edge.caller_fqn == "pkg.consumer.run"]
        assert len(run_edges) == 2
        assert {edge.callee_fqn for edge in run_edges} == {
            None,
            "pkg.helpers.process_data",
        }
        unresolved_edge = next(edge for edge in run_edges if edge.callee_fqn is None)
        assert unresolved_edge.resolution == ResolutionStatus.UNRESOLVED
        assert unresolved_edge.unresolved_reason == "unresolved_project_import"

    def test_missing_project_imported_attribute_class_base_records_gap(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("class Base:\n    pass\n")
        (pkg / "consumer.py").write_text(
            "import pkg.helpers as helpers\n\nclass Child(helpers.Missing):\n    pass\n"
        )

        out = extract_structural(tmp_path)

        gaps = [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]
        assert len(gaps) == 1
        assert not gaps[0].is_fatal
        assert gaps[0].location is not None
        assert "pkg.helpers.Missing" in gaps[0].message

        child = next(class_ for class_ in out.classes if class_.fqn == "pkg.consumer.Child")
        assert child.bases == ("Missing",)

    def test_missing_project_imported_attribute_decorator_records_gap(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def deco(fn):\n    return fn\n")
        (pkg / "consumer.py").write_text(
            "import pkg.helpers as helpers\n\n@helpers.missing\ndef run():\n    return None\n"
        )

        out = extract_structural(tmp_path)

        gaps = [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]
        assert len(gaps) == 1
        assert not gaps[0].is_fatal
        assert gaps[0].location is not None
        assert "pkg.helpers.missing" in gaps[0].message

        decorator = next(
            decorator for decorator in out.decorators if decorator.target_fqn == "pkg.consumer.run"
        )
        assert decorator.fqn is None

        run = next(function for function in out.functions if function.fqn == "pkg.consumer.run")
        assert run.decorator_fqns == (None,)

    def test_missing_nested_project_imported_attribute_alias_records_gap_and_unresolved_refs(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "import pkg.helpers as helpers\n"
            "local_missing = helpers.missing.save\n\n"
            "def run():\n"
            "    return local_missing('input')\n"
        )

        out = extract_structural(tmp_path)

        gaps = [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]
        assert len(gaps) == 1
        assert not gaps[0].is_fatal
        assert gaps[0].location is not None
        assert "pkg.helpers.missing" in gaps[0].message

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert ("helpers", "pkg.helpers", AliasMechanism.IMPORT_ALIAS) in aliases
        assert (
            "local_missing",
            "pkg.helpers.missing.save",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) not in aliases

        refs = [
            ref
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py" and ref.name == "local_missing"
        ]
        assert refs
        assert {ref.resolution for ref in refs} == {ResolutionStatus.UNRESOLVED}
        assert {ref.fqn for ref in refs} == {None}

        edge = next(edge for edge in out.call_edges if edge.caller_fqn == "pkg.consumer.run")
        assert edge.callee_fqn is None
        assert edge.resolution == ResolutionStatus.UNRESOLVED
        assert edge.unresolved_reason == "unresolved_project_import"

    def test_existing_nested_project_imported_attribute_alias_is_accepted(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("class Model:\n    def save(self):\n        return None\n")
        (pkg / "consumer.py").write_text(
            "import pkg.helpers as helpers\n"
            "local_save = helpers.Model.save\n\n"
            "def run(model):\n"
            "    return local_save(model)\n"
        )

        out = extract_structural(tmp_path)

        assert not [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]

        alias = next(alias for alias in out.aliases if alias.alias_name == "local_save")
        assert alias.original_fqn == "pkg.helpers.Model.save"

        assert any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.helpers.Model.save"
            for edge in out.call_edges
        )

    def test_missing_class_member_project_imported_attribute_alias_records_gap(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("class Model:\n    def save(self):\n        return None\n")
        (pkg / "consumer.py").write_text(
            "import pkg.helpers as helpers\n"
            "local_missing = helpers.Model.missing\n\n"
            "def run(model):\n"
            "    return local_missing(model)\n"
        )

        out = extract_structural(tmp_path)

        gaps = [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]
        assert len(gaps) == 1
        assert not gaps[0].is_fatal
        assert gaps[0].location is not None
        assert "pkg.helpers.Model.missing" in gaps[0].message

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert (
            "local_missing",
            "pkg.helpers.Model.missing",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) not in aliases

        refs = [
            ref
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py" and ref.name == "local_missing"
        ]
        assert refs
        assert {ref.resolution for ref in refs} == {ResolutionStatus.UNRESOLVED}
        assert {ref.fqn for ref in refs} == {None}

        edge = next(edge for edge in out.call_edges if edge.caller_fqn == "pkg.consumer.run")
        assert edge.callee_fqn is None
        assert edge.resolution == ResolutionStatus.UNRESOLVED
        assert edge.unresolved_reason == "unresolved_project_import"

    def test_missing_nested_class_member_project_imported_attribute_alias_records_gap(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text(
            "class Outer:\n    class Inner:\n        def save(self):\n            return None\n"
        )
        (pkg / "consumer.py").write_text(
            "import pkg.helpers as helpers\n"
            "local_missing = helpers.Outer.Inner.missing\n\n"
            "def run(inner):\n"
            "    return local_missing(inner)\n"
        )

        out = extract_structural(tmp_path)

        gaps = [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]
        assert len(gaps) == 1
        assert not gaps[0].is_fatal
        assert gaps[0].location is not None
        assert "pkg.helpers.Outer.Inner.missing" in gaps[0].message

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert (
            "local_missing",
            "pkg.helpers.Outer.Inner.missing",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) not in aliases

        refs = [
            ref
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py" and ref.name == "local_missing"
        ]
        assert refs
        assert {ref.resolution for ref in refs} == {ResolutionStatus.UNRESOLVED}
        assert {ref.fqn for ref in refs} == {None}

        edge = next(edge for edge in out.call_edges if edge.caller_fqn == "pkg.consumer.run")
        assert edge.callee_fqn is None
        assert edge.resolution == ResolutionStatus.UNRESOLVED
        assert edge.unresolved_reason == "unresolved_project_import"

    def test_existing_nested_class_member_project_imported_attribute_alias_is_accepted(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text(
            "class Outer:\n    class Inner:\n        def save(self):\n            return None\n"
        )
        (pkg / "consumer.py").write_text(
            "import pkg.helpers as helpers\n"
            "local_save = helpers.Outer.Inner.save\n\n"
            "def run(inner):\n"
            "    return local_save(inner)\n"
        )

        out = extract_structural(tmp_path)

        assert not [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]

        alias = next(alias for alias in out.aliases if alias.alias_name == "local_save")
        assert alias.original_fqn == "pkg.helpers.Outer.Inner.save"

        assert any(
            edge.caller_fqn == "pkg.consumer.run"
            and edge.callee_fqn == "pkg.helpers.Outer.Inner.save"
            for edge in out.call_edges
        )

    def test_root_package_imported_submodule_missing_attribute_alias_records_gap(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "import pkg as p\n"
            "local_missing = p.helpers.missing\n\n"
            "def run():\n"
            "    return local_missing('input')\n"
        )

        out = extract_structural(tmp_path)

        gaps = [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]
        assert len(gaps) == 1
        assert not gaps[0].is_fatal
        assert gaps[0].location is not None
        assert "pkg.helpers.missing" in gaps[0].message

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert ("p", "pkg", AliasMechanism.IMPORT_ALIAS) in aliases
        assert (
            "local_missing",
            "pkg.helpers.missing",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) not in aliases

        refs = [
            ref
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py" and ref.name == "local_missing"
        ]
        assert refs
        assert {ref.resolution for ref in refs} == {ResolutionStatus.UNRESOLVED}
        assert {ref.fqn for ref in refs} == {None}

        edge = next(edge for edge in out.call_edges if edge.caller_fqn == "pkg.consumer.run")
        assert edge.callee_fqn is None
        assert edge.resolution == ResolutionStatus.UNRESOLVED
        assert edge.unresolved_reason == "unresolved_project_import"

    def test_root_package_imported_submodule_attribute_alias_is_accepted(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "import pkg as p\n"
            "local_process = p.helpers.process_data\n\n"
            "def run():\n"
            "    return local_process('input')\n"
        )

        out = extract_structural(tmp_path)

        assert not [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]

        local_alias = next(alias for alias in out.aliases if alias.alias_name == "local_process")
        assert local_alias.original_fqn == "pkg.helpers.process_data"

        assert any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.helpers.process_data"
            for edge in out.call_edges
        )

    def test_from_imported_project_submodule_missing_attribute_alias_records_gap(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "from pkg import helpers as h\n"
            "local_missing = h.missing\n\n"
            "def run():\n"
            "    return local_missing('input')\n"
        )

        out = extract_structural(tmp_path)

        gaps = [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]
        assert len(gaps) == 1
        assert not gaps[0].is_fatal
        assert gaps[0].location is not None
        assert "pkg.helpers.missing" in gaps[0].message

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert ("h", "pkg.helpers", AliasMechanism.IMPORT_ALIAS) in aliases
        assert (
            "local_missing",
            "pkg.helpers.missing",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) not in aliases

        refs = [
            ref
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py" and ref.name == "local_missing"
        ]
        assert refs
        assert {ref.resolution for ref in refs} == {ResolutionStatus.UNRESOLVED}
        assert {ref.fqn for ref in refs} == {None}

        edge = next(edge for edge in out.call_edges if edge.caller_fqn == "pkg.consumer.run")
        assert edge.callee_fqn is None
        assert edge.resolution == ResolutionStatus.UNRESOLVED
        assert edge.unresolved_reason == "unresolved_project_import"

    def test_from_imported_project_submodule_attribute_alias_is_accepted(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "from pkg import helpers\n"
            "local_process = helpers.process_data\n\n"
            "def run():\n"
            "    return local_process('input')\n"
        )

        out = extract_structural(tmp_path)

        assert not [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]

        local_alias = next(alias for alias in out.aliases if alias.alias_name == "local_process")
        assert local_alias.original_fqn == "pkg.helpers.process_data"

        assert any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.helpers.process_data"
            for edge in out.call_edges
        )

    def test_from_imported_project_submodule_direct_refs_use_imported_fqn_until_shadow(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "from pkg import helpers\n"
            "before = helpers.process_data('before')\n"
            "helpers = object()\n"
            "during = helpers.process_data('during')\n"
            "from pkg import helpers\n"
            "after = helpers.process_data('after')\n"
        )

        out = extract_structural(tmp_path)

        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 2
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.consumer.helpers.process_data"
            and edge.location.line == 4
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 6
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.consumer.helpers.process_data"
            and edge.location.line in {2, 6}
            for edge in out.call_edges
        )

        consumer_refs = {
            (ref.name, ref.fqn, ref.location.line)
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
        }
        assert ("helpers.process_data", "pkg.helpers.process_data", 2) in consumer_refs
        assert (
            "helpers.process_data",
            "pkg.consumer.helpers.process_data",
            4,
        ) in consumer_refs
        assert ("helpers.process_data", "pkg.helpers.process_data", 6) in consumer_refs

    def test_project_import_member_validation_accepts_top_level_assignments(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("DEFAULT_LIMIT = 10\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import DEFAULT_LIMIT\n\ndef run():\n    return DEFAULT_LIMIT\n"
        )

        out = extract_structural(tmp_path)

        assert not [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]

        refs = {
            (ref.name, ref.fqn, ref.resolution)
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
        }
        assert (
            "DEFAULT_LIMIT",
            "pkg.helpers.DEFAULT_LIMIT",
            ResolutionStatus.RESOLVED,
        ) in refs

    def test_star_import_records_resolution_gap(self, tmp_path: Path) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def exported():\n    return 1\n")
        (pkg / "main.py").write_text("from .helpers import *\n\nvalue = exported()\n")

        out = extract_structural(tmp_path)

        wildcard_aliases = [
            alias for alias in out.aliases if alias.mechanism == AliasMechanism.WILDCARD_IMPORT
        ]
        assert [(alias.original_fqn, alias.alias_name) for alias in wildcard_aliases] == [
            ("pkg.helpers.*", "*")
        ]

        gaps = [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/main.py"
        ]
        assert len(gaps) == 1
        assert not gaps[0].is_fatal
        assert gaps[0].location is not None
        assert "wildcard import" in gaps[0].message

    def test_star_import_with_static_dunder_all_expands_exported_names(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text(
            "__all__ = ['exported', 'other_exported']\n\n"
            "def exported():\n"
            "    return 1\n\n"
            "def other_exported():\n"
            "    return 2\n\n"
            "def hidden():\n"
            "    return 3\n"
        )
        (pkg / "main.py").write_text(
            "from .helpers import *\n\nvalue = exported()\nother = other_exported()\n"
        )

        out = extract_structural(tmp_path)

        wildcard_aliases = [
            (alias.original_fqn, alias.alias_name)
            for alias in out.aliases
            if alias.mechanism == AliasMechanism.WILDCARD_IMPORT
        ]
        assert ("pkg.helpers.*", "*") in wildcard_aliases
        assert ("pkg.helpers.exported", "exported") in wildcard_aliases
        assert ("pkg.helpers.other_exported", "other_exported") in wildcard_aliases
        assert ("pkg.helpers.hidden", "hidden") not in wildcard_aliases

        assert not [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/main.py"
        ]
        assert any(
            edge.caller_fqn == "<module>" and edge.callee_fqn == "pkg.helpers.exported"
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "<module>" and edge.callee_fqn == "pkg.helpers.other_exported"
            for edge in out.call_edges
        )

    def test_star_import_with_dynamic_dunder_all_keeps_resolution_gap(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text(
            "def get_exports():\n"
            "    return ['exported']\n\n"
            "__all__ = get_exports()\n\n"
            "def exported():\n"
            "    return 1\n"
        )
        (pkg / "main.py").write_text("from .helpers import *\n\nvalue = exported()\n")

        out = extract_structural(tmp_path)

        wildcard_aliases = [
            (alias.original_fqn, alias.alias_name)
            for alias in out.aliases
            if alias.mechanism == AliasMechanism.WILDCARD_IMPORT
        ]
        assert wildcard_aliases == [("pkg.helpers.*", "*")]

        gaps = [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/main.py"
        ]
        assert len(gaps) == 1
        assert not gaps[0].is_fatal
        assert gaps[0].location is not None
        assert "wildcard import" in gaps[0].message

    def test_star_import_static_dunder_all_resolves_through_reexport_chain(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "leaf.py").write_text("def exported():\n    return 1\n")
        (pkg / "__init__.py").write_text(
            "from .leaf import exported as public_exported\n__all__ = ['public_exported']\n"
        )
        (pkg / "consumer.py").write_text(
            "from pkg import *\n\ndef run():\n    return public_exported()\n"
        )

        out = extract_structural(tmp_path)

        assert not [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]
        assert any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.leaf.exported"
            for edge in out.call_edges
        )
        assert ("public_exported", "pkg.leaf.exported") in {
            (ref.name, ref.fqn)
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
        }

    def test_package_reexports_resolve_to_original_project_fqns(self, tmp_path: Path) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text(
            "from .decorators import mark\n"
            "from .helpers import process_data as exported\n"
            "from .models import Base as PublicBase\n"
        )
        (pkg / "decorators.py").write_text("def mark(fn):\n    return fn\n")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "models.py").write_text("class Base:\n    pass\n")
        (pkg / "consumer.py").write_text(
            "from pkg import PublicBase, exported as local_exported, mark\n\n"
            "@mark\n"
            "def run():\n"
            "    return local_exported('input')\n\n"
            "class Child(PublicBase):\n"
            "    pass\n"
        )

        out = extract_structural(tmp_path)

        consumer_refs = {
            (ref.name, ref.fqn)
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
        }
        assert ("local_exported", "pkg.helpers.process_data") in consumer_refs
        assert ("mark", "pkg.decorators.mark") in consumer_refs
        assert ("PublicBase", "pkg.models.Base") in consumer_refs

        run_edges = [
            edge
            for edge in out.call_edges
            if edge.caller_fqn == "pkg.consumer.run"
            and edge.callee_fqn == "pkg.helpers.process_data"
        ]
        assert len(run_edges) == 1

        run = next(fn for fn in out.functions if fn.fqn == "pkg.consumer.run")
        assert run.decorator_fqns == ("pkg.decorators.mark",)

        run_decorators = [
            decorator for decorator in out.decorators if decorator.target_fqn == "pkg.consumer.run"
        ]
        assert len(run_decorators) == 1
        assert run_decorators[0].fqn == "pkg.decorators.mark"

        child = next(cls for cls in out.classes if cls.fqn == "pkg.consumer.Child")
        assert child.bases == ("pkg.models.Base",)

        local_alias = next(alias for alias in out.aliases if alias.alias_name == "local_exported")
        assert local_alias.original_fqn == "pkg.helpers.process_data"

    def test_package_reexport_shadowed_by_local_definition_keeps_local_fqn(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "__init__.py").write_text(
            "from .helpers import process_data as exported\n\ndef exported(raw):\n    return raw\n"
        )
        (pkg / "consumer.py").write_text(
            "from pkg import exported\n\ndef run():\n    return exported('input')\n"
        )

        out = extract_structural(tmp_path)

        assert any(fn.fqn == "pkg.exported" for fn in out.functions)

        consumer_refs = {
            (ref.name, ref.fqn)
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
        }
        assert ("exported", "pkg.exported") in consumer_refs
        assert ("exported", "pkg.helpers.process_data") not in consumer_refs

        assert any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.exported"
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.helpers.process_data"
            for edge in out.call_edges
        )

    def test_package_reexport_shadowed_by_later_assignment_keeps_local_fqn(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "__init__.py").write_text(
            "from .helpers import process_data as exported\nexported = lambda raw: raw\n"
        )
        (pkg / "consumer.py").write_text(
            "from pkg import exported\n\ndef run():\n    return exported('input')\n"
        )

        out = extract_structural(tmp_path)

        consumer_refs = {
            (ref.name, ref.fqn)
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
        }
        assert ("exported", "pkg.exported") in consumer_refs
        assert ("exported", "pkg.helpers.process_data") not in consumer_refs

        assert any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.exported"
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.helpers.process_data"
            for edge in out.call_edges
        )

    def test_assignment_aliases_rewrite_symbol_refs_and_call_edges(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import process_data\n"
            "local_process = process_data\n\n"
            "def run():\n"
            "    return local_process('input')\n"
        )

        out = extract_structural(tmp_path)

        local_alias = next(alias for alias in out.aliases if alias.alias_name == "local_process")
        assert local_alias.mechanism == AliasMechanism.ASSIGNMENT_ALIAS
        assert local_alias.original_fqn == "pkg.helpers.process_data"

        consumer_refs = {
            (ref.name, ref.fqn)
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
        }
        assert ("local_process", "pkg.helpers.process_data") in consumer_refs

        run_edges = [
            edge
            for edge in out.call_edges
            if edge.caller_fqn == "pkg.consumer.run"
            and edge.callee_fqn == "pkg.helpers.process_data"
        ]
        assert len(run_edges) == 1

    def test_chained_assignment_aliases_rewrite_symbol_refs_and_call_edges(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import process_data\n"
            "local_process = also_process = process_data\n\n"
            "def run():\n"
            "    return local_process('input'), also_process('other')\n"
        )

        out = extract_structural(tmp_path)

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert (
            "local_process",
            "pkg.helpers.process_data",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) in aliases
        assert (
            "also_process",
            "pkg.helpers.process_data",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) in aliases

        consumer_refs = {
            (ref.name, ref.fqn)
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
        }
        assert ("local_process", "pkg.helpers.process_data") in consumer_refs
        assert ("also_process", "pkg.helpers.process_data") in consumer_refs

        run_edges = [
            edge
            for edge in out.call_edges
            if edge.caller_fqn == "pkg.consumer.run"
            and edge.callee_fqn == "pkg.helpers.process_data"
        ]
        assert len(run_edges) == 2

    def test_chained_missing_imported_attribute_aliases_record_gap(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "import pkg.helpers as helpers\n"
            "local_missing = also_missing = helpers.missing\n\n"
            "def run():\n"
            "    return local_missing('input'), also_missing('other')\n"
        )

        out = extract_structural(tmp_path)

        gaps = [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]
        assert len(gaps) == 1
        assert not gaps[0].is_fatal
        assert gaps[0].location is not None
        assert "pkg.helpers.missing" in gaps[0].message

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert ("helpers", "pkg.helpers", AliasMechanism.IMPORT_ALIAS) in aliases
        assert (
            "local_missing",
            "pkg.helpers.missing",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) not in aliases
        assert (
            "also_missing",
            "pkg.helpers.missing",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) not in aliases

        refs = [
            ref
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
            and ref.name in {"local_missing", "also_missing"}
        ]
        assert refs
        assert {ref.name for ref in refs} == {"local_missing", "also_missing"}
        assert {ref.resolution for ref in refs} == {ResolutionStatus.UNRESOLVED}
        assert {ref.fqn for ref in refs} == {None}

        run_edges = [edge for edge in out.call_edges if edge.caller_fqn == "pkg.consumer.run"]
        assert len(run_edges) == 2
        assert {edge.callee_fqn for edge in run_edges} == {None}
        assert {edge.resolution for edge in run_edges} == {ResolutionStatus.UNRESOLVED}
        assert {edge.unresolved_reason for edge in run_edges} == {"unresolved_project_import"}

    def test_unpacking_assignment_aliases_rewrite_symbol_refs_and_call_edges(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "more.py").write_text("def other_process(raw):\n    return raw\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import process_data\n"
            "import pkg.more as more\n\n"
            "local_process, attr_process = process_data, more.other_process\n\n"
            "def run():\n"
            "    return local_process('input'), attr_process('other')\n"
        )

        out = extract_structural(tmp_path)

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert (
            "local_process",
            "pkg.helpers.process_data",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) in aliases
        assert (
            "attr_process",
            "pkg.more.other_process",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) in aliases

        consumer_refs = {
            (ref.name, ref.fqn)
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
        }
        assert ("local_process", "pkg.helpers.process_data") in consumer_refs
        assert ("attr_process", "pkg.more.other_process") in consumer_refs

        run_edges = {
            edge.callee_fqn for edge in out.call_edges if edge.caller_fqn == "pkg.consumer.run"
        }
        assert run_edges == {"pkg.helpers.process_data", "pkg.more.other_process"}

    def test_unpacking_missing_imported_attribute_alias_records_gap(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "import pkg.helpers as helpers\n"
            "[local_missing, local_process] = [helpers.missing, helpers.process_data]\n\n"
            "def run():\n"
            "    return local_missing('input'), local_process('other')\n"
        )

        out = extract_structural(tmp_path)

        gaps = [
            error
            for error in out.errors
            if error.error_kind == ErrorKind.RESOLUTION and error.file == "pkg/consumer.py"
        ]
        assert len(gaps) == 1
        assert not gaps[0].is_fatal
        assert gaps[0].location is not None
        assert "pkg.helpers.missing" in gaps[0].message

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert ("helpers", "pkg.helpers", AliasMechanism.IMPORT_ALIAS) in aliases
        assert (
            "local_missing",
            "pkg.helpers.missing",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) not in aliases
        assert (
            "local_process",
            "pkg.helpers.process_data",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) in aliases

        refs = {
            (ref.name, ref.fqn, ref.resolution)
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
            and ref.name in {"local_missing", "local_process"}
        }
        assert ("local_missing", None, ResolutionStatus.UNRESOLVED) in refs
        assert ("local_process", "pkg.helpers.process_data", ResolutionStatus.RESOLVED) in refs

        run_edges = [edge for edge in out.call_edges if edge.caller_fqn == "pkg.consumer.run"]
        assert len(run_edges) == 2
        assert {edge.callee_fqn for edge in run_edges} == {None, "pkg.helpers.process_data"}
        unresolved_edge = next(edge for edge in run_edges if edge.callee_fqn is None)
        assert unresolved_edge.resolution == ResolutionStatus.UNRESOLVED
        assert unresolved_edge.unresolved_reason == "unresolved_project_import"

    def test_imported_attribute_assignment_aliases_rewrite_symbol_refs_and_call_edges(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "import pkg.helpers as helpers\n"
            "local_process = helpers.process_data\n\n"
            "def run():\n"
            "    return local_process('input')\n"
        )

        out = extract_structural(tmp_path)

        local_alias = next(alias for alias in out.aliases if alias.alias_name == "local_process")
        assert local_alias.mechanism == AliasMechanism.ASSIGNMENT_ALIAS
        assert local_alias.original_fqn == "pkg.helpers.process_data"

        consumer_refs = {
            (ref.name, ref.fqn)
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
        }
        assert ("local_process", "pkg.helpers.process_data") in consumer_refs

        run_edges = [
            edge
            for edge in out.call_edges
            if edge.caller_fqn == "pkg.consumer.run"
            and edge.callee_fqn == "pkg.helpers.process_data"
        ]
        assert len(run_edges) == 1

    def test_annotated_assignment_aliases_rewrite_symbol_refs_and_call_edges(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "from typing import Callable\n"
            "from pkg.helpers import process_data\n"
            "import pkg.helpers as helpers\n\n"
            "local_process: Callable[[str], str] = process_data\n"
            "attr_process: Callable[[str], str] = helpers.process_data\n\n"
            "def run():\n"
            "    return local_process('input'), attr_process('other')\n"
        )

        out = extract_structural(tmp_path)

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert (
            "local_process",
            "pkg.helpers.process_data",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) in aliases
        assert (
            "attr_process",
            "pkg.helpers.process_data",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) in aliases

        consumer_refs = {
            (ref.name, ref.fqn)
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
        }
        assert ("local_process", "pkg.helpers.process_data") in consumer_refs
        assert ("attr_process", "pkg.helpers.process_data") in consumer_refs

        run_edges = [
            edge
            for edge in out.call_edges
            if edge.caller_fqn == "pkg.consumer.run"
            and edge.callee_fqn == "pkg.helpers.process_data"
        ]
        assert len(run_edges) == 2

    def test_assignment_alias_shadowed_by_later_local_definition_drops_alias_fact(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "models.py").write_text("class Base:\n    pass\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import process_data\n"
            "from pkg.models import Base\n\n"
            "local_process = process_data\n"
            "PublicBase = Base\n\n"
            "def local_process(raw):\n"
            "    return raw\n\n"
            "class PublicBase:\n"
            "    pass\n\n"
            "def run():\n"
            "    return local_process('input')\n\n"
            "class Child(PublicBase):\n"
            "    pass\n"
        )

        out = extract_structural(tmp_path)

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert (
            "local_process",
            "pkg.helpers.process_data",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) not in aliases
        assert ("PublicBase", "pkg.models.Base", AliasMechanism.ASSIGNMENT_ALIAS) not in aliases

        assert any(
            edge.caller_fqn == "pkg.consumer.run"
            and edge.callee_fqn == "pkg.consumer.local_process"
            for edge in out.call_edges
        )

        child = next(cls for cls in out.classes if cls.fqn == "pkg.consumer.Child")
        assert child.bases == ("pkg.consumer.PublicBase",)

    def test_assignment_alias_shadowed_by_later_assignment_drops_alias_fact(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import process_data\n\n"
            "local_process = process_data\n"
            "local_process = lambda raw: raw\n\n"
            "def run():\n"
            "    return local_process('input')\n"
        )

        out = extract_structural(tmp_path)

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert (
            "local_process",
            "pkg.helpers.process_data",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) not in aliases

        assert any(
            edge.caller_fqn == "pkg.consumer.run"
            and edge.callee_fqn == "pkg.consumer.local_process"
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.helpers.process_data"
            for edge in out.call_edges
        )

    def test_assignment_alias_after_earlier_local_definition_still_rewrites_refs(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "models.py").write_text("class Base:\n    pass\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import process_data\n"
            "from pkg.models import Base\n\n"
            "def local_process(raw):\n"
            "    return raw\n\n"
            "class PublicBase:\n"
            "    pass\n\n"
            "local_process = process_data\n"
            "PublicBase = Base\n\n"
            "def run():\n"
            "    return local_process('input')\n\n"
            "class Child(PublicBase):\n"
            "    pass\n"
        )

        out = extract_structural(tmp_path)

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert (
            "local_process",
            "pkg.helpers.process_data",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) in aliases
        assert ("PublicBase", "pkg.models.Base", AliasMechanism.ASSIGNMENT_ALIAS) in aliases

        assert any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.helpers.process_data"
            for edge in out.call_edges
        )

        child = next(cls for cls in out.classes if cls.fqn == "pkg.consumer.Child")
        assert child.bases == ("pkg.models.Base",)

    def test_import_alias_shadowed_by_later_local_definition_drops_alias_fact(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "models.py").write_text("class Base:\n    pass\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import process_data as local_process\n"
            "from pkg.models import Base as PublicBase\n\n"
            "def local_process(raw):\n"
            "    return raw\n\n"
            "class PublicBase:\n"
            "    pass\n\n"
            "def run():\n"
            "    return local_process('input')\n\n"
            "class Child(PublicBase):\n"
            "    pass\n"
        )

        out = extract_structural(tmp_path)

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert (
            "local_process",
            "pkg.helpers.process_data",
            AliasMechanism.IMPORT_ALIAS,
        ) not in aliases
        assert ("PublicBase", "pkg.models.Base", AliasMechanism.IMPORT_ALIAS) not in aliases

        assert any(
            edge.caller_fqn == "pkg.consumer.run"
            and edge.callee_fqn == "pkg.consumer.local_process"
            for edge in out.call_edges
        )

        child = next(cls for cls in out.classes if cls.fqn == "pkg.consumer.Child")
        assert child.bases == ("pkg.consumer.PublicBase",)

    def test_function_scoped_import_alias_survives_later_top_level_definition(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "def load():\n"
            "    from pkg.helpers import process_data as local_process\n"
            "    return local_process('input')\n\n"
            "def local_process(raw):\n"
            "    return raw\n"
        )

        out = extract_structural(tmp_path)

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert (
            "local_process",
            "pkg.helpers.process_data",
            AliasMechanism.IMPORT_ALIAS,
        ) in aliases

    def test_nested_class_does_not_shadow_top_level_import_alias(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "models.py").write_text("class Base:\n    pass\n")
        (pkg / "consumer.py").write_text(
            "from pkg.models import Base as PublicBase\n\n"
            "def factory():\n"
            "    class PublicBase:\n"
            "        pass\n"
            "    return PublicBase\n\n"
            "def run():\n"
            "    return PublicBase()\n"
        )

        out = extract_structural(tmp_path)

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert ("PublicBase", "pkg.models.Base", AliasMechanism.IMPORT_ALIAS) in aliases

    def test_import_alias_shadowed_by_later_assignment_drops_alias_fact(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import process_data as local_process\n\n"
            "local_process = lambda raw: raw\n\n"
            "def run():\n"
            "    return local_process('input')\n"
        )

        out = extract_structural(tmp_path)

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert (
            "local_process",
            "pkg.helpers.process_data",
            AliasMechanism.IMPORT_ALIAS,
        ) not in aliases

        assert any(
            edge.caller_fqn == "pkg.consumer.run"
            and edge.callee_fqn == "pkg.consumer.local_process"
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.helpers.process_data"
            for edge in out.call_edges
        )

    def test_pre_shadow_assignment_alias_from_import_alias_keeps_imported_fqn(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "import pkg.helpers as helpers\n"
            "before = helpers.process_data('before')\n"
            "local_process = helpers.process_data\n"
            "helpers = object()\n\n"
            "def run():\n"
            "    return local_process('after')\n"
        )

        out = extract_structural(tmp_path)

        local_alias = next(alias for alias in out.aliases if alias.alias_name == "local_process")
        assert local_alias.original_fqn == "pkg.helpers.process_data"

        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 2
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.helpers.process_data"
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "pkg.consumer.run"
            and edge.callee_fqn == "pkg.consumer.helpers.process_data"
            for edge in out.call_edges
        )

    def test_pre_shadow_assignment_alias_from_non_aliased_import_keeps_imported_fqn(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text(
            "class Base:\n    pass\n\ndef process_data(raw):\n    return raw.strip()\n"
        )
        (pkg / "consumer.py").write_text(
            "import pkg.helpers\n"
            "before = pkg.helpers.process_data('before')\n"
            "local_process = pkg.helpers.process_data\n"
            "pkg = object()\n\n"
            "class Later(pkg.helpers.Base):\n"
            "    pass\n\n"
            "def run():\n"
            "    return local_process('after'), pkg.helpers.process_data('later')\n"
        )

        out = extract_structural(tmp_path)

        local_alias = next(alias for alias in out.aliases if alias.alias_name == "local_process")
        assert local_alias.original_fqn == "pkg.helpers.process_data"

        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 2
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.helpers.process_data"
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "pkg.consumer.run"
            and edge.callee_fqn == "pkg.consumer.pkg.helpers.process_data"
            for edge in out.call_edges
        )
        later_class = next(class_ for class_ in out.classes if class_.name == "Later")
        assert later_class.bases == ("pkg.consumer.pkg.helpers.Base",)

    def test_reimport_after_bare_import_root_shadow_restores_imported_fqn(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "import pkg.helpers\n"
            "before = pkg.helpers.process_data('before')\n"
            "pkg = object()\n"
            "during = pkg.helpers.process_data('during')\n"
            "import pkg.helpers\n"
            "after = pkg.helpers.process_data('after')\n"
        )

        out = extract_structural(tmp_path)

        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 2
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.consumer.pkg.helpers.process_data"
            and edge.location.line == 4
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 6
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.consumer.pkg.helpers.process_data"
            and edge.location.line == 6
            for edge in out.call_edges
        )

    def test_reimport_after_aliased_import_shadow_restores_imported_fqn(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "import pkg.helpers as helpers\n"
            "before = helpers.process_data('before')\n"
            "helpers = object()\n"
            "during = helpers.process_data('during')\n"
            "import pkg.helpers as helpers\n"
            "after = helpers.process_data('after')\n"
        )

        out = extract_structural(tmp_path)

        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 2
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.consumer.helpers.process_data"
            and edge.location.line == 4
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 6
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.consumer.helpers.process_data"
            and edge.location.line == 6
            for edge in out.call_edges
        )

    def test_later_aliased_import_rebinds_alias_range_without_assignment_shadow(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "other.py").write_text("def process_data(raw):\n    return raw\n")
        (pkg / "consumer.py").write_text(
            "import pkg.helpers as helpers\n"
            "before = helpers.process_data('before')\n"
            "import pkg.other as helpers\n"
            "after = helpers.process_data('after')\n"
        )

        out = extract_structural(tmp_path)

        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 2
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.other.process_data"
            and edge.location.line == 4
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 4
            for edge in out.call_edges
        )

    def test_later_aliased_from_import_rebinds_alias_range_without_assignment_shadow(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text(
            "class Base:\n    pass\n\ndef process_data(raw):\n    return raw.strip()\n"
        )
        (pkg / "other.py").write_text(
            "class Base:\n    pass\n\ndef process_data(raw):\n    return raw\n"
        )
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import Base as LocalBase, process_data as local_process\n"
            "before = local_process('before')\n"
            "class Before(LocalBase):\n"
            "    pass\n"
            "from pkg.other import Base as LocalBase, process_data as local_process\n"
            "after = local_process('after')\n"
            "class After(LocalBase):\n"
            "    pass\n"
        )

        out = extract_structural(tmp_path)

        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 2
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.other.process_data"
            and edge.location.line == 6
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 6
            for edge in out.call_edges
        )

        before_class = next(class_ for class_ in out.classes if class_.name == "Before")
        after_class = next(class_ for class_ in out.classes if class_.name == "After")
        assert before_class.bases == ("pkg.helpers.Base",)
        assert after_class.bases == ("pkg.other.Base",)
        assert after_class.bases != ("pkg.helpers.Base",)

    def test_later_non_aliased_from_import_rebinds_direct_refs_without_assignment_shadow(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "other.py").write_text("def process_data(raw):\n    return raw\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import process_data\n"
            "before = process_data('before')\n"
            "from pkg.other import process_data\n"
            "after = process_data('after')\n"
        )

        out = extract_structural(tmp_path)

        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 2
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.other.process_data"
            and edge.location.line == 4
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 4
            for edge in out.call_edges
        )

        consumer_refs = {
            (ref.name, ref.fqn, ref.location.line)
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
        }
        assert ("process_data", "pkg.helpers.process_data", 2) in consumer_refs
        assert ("process_data", "pkg.other.process_data", 4) in consumer_refs

    def test_later_non_aliased_from_import_rebinds_class_bases_without_assignment_shadow(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("class Base:\n    pass\n")
        (pkg / "other.py").write_text("class Base:\n    pass\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import Base\n"
            "class Before(Base):\n"
            "    pass\n"
            "from pkg.other import Base\n"
            "class After(Base):\n"
            "    pass\n"
        )

        out = extract_structural(tmp_path)

        before_class = next(class_ for class_ in out.classes if class_.name == "Before")
        after_class = next(class_ for class_ in out.classes if class_.name == "After")
        assert before_class.bases == ("pkg.helpers.Base",)
        assert after_class.bases == ("pkg.other.Base",)
        assert after_class.bases != ("pkg.helpers.Base",)

    def test_later_non_aliased_from_import_rebinds_decorators_without_assignment_shadow(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "decorators.py").write_text("def mark(fn):\n    return fn\n")
        (pkg / "other.py").write_text("def mark(fn):\n    return fn\n")
        (pkg / "consumer.py").write_text(
            "from pkg.decorators import mark\n"
            "@mark\n"
            "def before():\n"
            "    return None\n"
            "from pkg.other import mark\n"
            "@mark\n"
            "def after():\n"
            "    return None\n"
        )

        out = extract_structural(tmp_path)

        before = next(function for function in out.functions if function.name == "before")
        after = next(function for function in out.functions if function.name == "after")
        assert before.decorator_fqns == ("pkg.decorators.mark",)
        assert after.decorator_fqns == ("pkg.other.mark",)

        decorators = {
            decorator.target_fqn: decorator.fqn
            for decorator in out.decorators
            if decorator.location.file == "pkg/consumer.py"
        }
        assert decorators["pkg.consumer.before"] == "pkg.decorators.mark"
        assert decorators["pkg.consumer.after"] == "pkg.other.mark"

    def test_later_non_aliased_from_import_rebinds_assignment_alias_without_shadow(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "other.py").write_text("def process_data(raw):\n    return raw\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import process_data\n"
            "before_alias = process_data\n"
            "from pkg.other import process_data\n"
            "after_alias = process_data\n\n"
            "def run():\n"
            "    return before_alias('before'), after_alias('after')\n"
        )

        out = extract_structural(tmp_path)

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert (
            "before_alias",
            "pkg.helpers.process_data",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) in aliases
        assert (
            "after_alias",
            "pkg.other.process_data",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) in aliases
        assert (
            "after_alias",
            "pkg.helpers.process_data",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) not in aliases

        run_edges = {
            edge.callee_fqn for edge in out.call_edges if edge.caller_fqn == "pkg.consumer.run"
        }
        assert "pkg.helpers.process_data" in run_edges
        assert "pkg.other.process_data" in run_edges

    def test_reimport_after_aliased_from_import_shadow_restores_imported_fqn(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import process_data as local_process\n"
            "before = local_process('before')\n"
            "local_process = lambda raw: raw\n"
            "during = local_process('during')\n"
            "from pkg.helpers import process_data as local_process\n"
            "after = local_process('after')\n"
        )

        out = extract_structural(tmp_path)

        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 2
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.consumer.local_process"
            and edge.location.line == 4
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 6
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.consumer.local_process"
            and edge.location.line == 6
            for edge in out.call_edges
        )

    def test_function_scoped_import_alias_survives_later_top_level_assignment(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "def load():\n"
            "    from pkg.helpers import process_data as local_process\n"
            "    return local_process('input')\n\n"
            "local_process = lambda raw: raw\n"
        )

        out = extract_structural(tmp_path)

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert (
            "local_process",
            "pkg.helpers.process_data",
            AliasMechanism.IMPORT_ALIAS,
        ) in aliases

    def test_non_aliased_from_import_shadowed_by_later_definition_rewrites_later_refs(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import process_data\n\n"
            "before = process_data('before')\n\n"
            "def process_data(raw):\n"
            "    return raw\n\n"
            "def run():\n"
            "    return process_data('after')\n"
        )

        out = extract_structural(tmp_path)

        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 3
            for edge in out.call_edges
        )

        assert any(
            edge.caller_fqn == "pkg.consumer.run"
            and edge.callee_fqn == "pkg.consumer.process_data"
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.helpers.process_data"
            for edge in out.call_edges
        )

        consumer_refs = {
            (ref.name, ref.fqn, ref.location.line)
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
        }
        assert ("process_data", "pkg.helpers.process_data", 3) in consumer_refs
        assert ("process_data", "pkg.consumer.process_data", 9) in consumer_refs

    def test_non_aliased_from_import_shadowed_by_later_assignment_rewrites_later_refs(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import process_data\n\n"
            "process_data = lambda raw: raw\n\n"
            "def run():\n"
            "    return process_data('after')\n"
        )

        out = extract_structural(tmp_path)

        assert any(
            edge.caller_fqn == "pkg.consumer.run"
            and edge.callee_fqn == "pkg.consumer.process_data"
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.helpers.process_data"
            for edge in out.call_edges
        )

        consumer_refs = {
            (ref.name, ref.fqn, ref.location.line)
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
        }
        assert ("process_data", "pkg.consumer.process_data", 6) in consumer_refs

    def test_non_aliased_from_import_shadowed_by_assignment_alias_rewrites_later_refs(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "other.py").write_text("def other_process(raw):\n    return raw\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import process_data\n"
            "from pkg.other import other_process\n\n"
            "before = process_data('before')\n\n"
            "process_data = other_process\n\n"
            "def run():\n"
            "    return process_data('after')\n"
        )

        out = extract_structural(tmp_path)

        alias = next(alias for alias in out.aliases if alias.alias_name == "process_data")
        assert alias.original_fqn == "pkg.other.other_process"

        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 4
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.other.other_process"
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "pkg.consumer.run"
            and edge.callee_fqn in {"pkg.helpers.process_data", "pkg.consumer.process_data"}
            for edge in out.call_edges
        )

        consumer_refs = {
            (ref.name, ref.fqn, ref.location.line)
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
        }
        assert ("process_data", "pkg.helpers.process_data", 4) in consumer_refs
        assert ("process_data", "pkg.other.other_process", 9) in consumer_refs

    def test_non_aliased_from_import_shadowed_by_unpacking_assignment_alias_rewrites_later_refs(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "other.py").write_text("def other_process(raw):\n    return raw\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import process_data\n"
            "from pkg.other import other_process\n\n"
            "before = process_data('before')\n\n"
            "process_data, keep_process = other_process, process_data\n\n"
            "def run():\n"
            "    return process_data('after'), keep_process('again')\n"
        )

        out = extract_structural(tmp_path)

        aliases = {
            (alias.alias_name, alias.original_fqn, alias.mechanism) for alias in out.aliases
        }
        assert (
            "process_data",
            "pkg.other.other_process",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) in aliases
        assert (
            "keep_process",
            "pkg.helpers.process_data",
            AliasMechanism.ASSIGNMENT_ALIAS,
        ) in aliases

        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 4
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.other.other_process"
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.helpers.process_data"
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "pkg.consumer.run"
            and edge.callee_fqn == "pkg.consumer.process_data"
            for edge in out.call_edges
        )

        consumer_refs = {
            (ref.name, ref.fqn, ref.location.line)
            for ref in out.symbol_refs
            if ref.location.file == "pkg/consumer.py"
        }
        assert ("process_data", "pkg.helpers.process_data", 4) in consumer_refs
        assert ("process_data", "pkg.other.other_process", 9) in consumer_refs
        assert ("keep_process", "pkg.helpers.process_data", 9) in consumer_refs

    def test_pre_shadow_alias_from_non_aliased_from_import_keeps_imported_fqn(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import process_data\n"
            "local_process = process_data\n"
            "process_data = lambda raw: raw\n\n"
            "def run():\n"
            "    return local_process('after')\n"
        )

        out = extract_structural(tmp_path)

        local_alias = next(alias for alias in out.aliases if alias.alias_name == "local_process")
        assert local_alias.original_fqn == "pkg.helpers.process_data"

        assert any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.helpers.process_data"
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "pkg.consumer.run"
            and edge.callee_fqn == "pkg.consumer.process_data"
            for edge in out.call_edges
        )

    def test_self_assignment_of_non_aliased_from_import_keeps_imported_fqn(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import process_data\n"
            "process_data = process_data\n\n"
            "def run():\n"
            "    return process_data('after')\n"
        )

        out = extract_structural(tmp_path)

        alias = next(alias for alias in out.aliases if alias.alias_name == "process_data")
        assert alias.original_fqn == "pkg.helpers.process_data"

        assert any(
            edge.caller_fqn == "pkg.consumer.run" and edge.callee_fqn == "pkg.helpers.process_data"
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "pkg.consumer.run"
            and edge.callee_fqn == "pkg.consumer.process_data"
            for edge in out.call_edges
        )

    def test_reimport_after_from_import_shadow_restores_imported_fqn(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "helpers.py").write_text("def process_data(raw):\n    return raw.strip()\n")
        (pkg / "consumer.py").write_text(
            "from pkg.helpers import process_data\n"
            "before = process_data('before')\n"
            "process_data = lambda raw: raw\n"
            "during = process_data('during')\n"
            "from pkg.helpers import process_data\n"
            "after = process_data('after')\n"
        )

        out = extract_structural(tmp_path)

        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 2
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.consumer.process_data"
            and edge.location.line == 4
            for edge in out.call_edges
        )
        assert any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.helpers.process_data"
            and edge.location.line == 6
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "<module>"
            and edge.callee_fqn == "pkg.consumer.process_data"
            and edge.location.line == 6
            for edge in out.call_edges
        )

    def test_type_checking_import_marked_conditional(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "app.py").write_text(
            "from typing import TYPE_CHECKING\n\nif TYPE_CHECKING:\n    from foo import Bar as B\n"
        )

        out = extract_structural(tmp_path)

        conditional_aliases = [a for a in out.aliases if a.alias_name == "B" and a.is_conditional]
        assert len(conditional_aliases) == 1
        assert conditional_aliases[0].original_fqn == "foo.Bar"

        conditional_imports = [i for i in out.imports if i.module == "foo" and i.is_conditional]
        assert len(conditional_imports) == 1

    def test_try_except_import_error_marked_conditional(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "app.py").write_text("try:\n    import fast_lib\nexcept ImportError:\n    pass\n")

        out = extract_structural(tmp_path)

        conditional_imports = [
            i for i in out.imports if i.module == "fast_lib" and i.is_conditional
        ]
        assert len(conditional_imports) == 1

    def test_unconditional_import_not_marked_conditional(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "app.py").write_text("import foo\nfrom bar import baz\n")

        out = extract_structural(tmp_path)

        foo_imports = [i for i in out.imports if i.module == "foo"]
        assert len(foo_imports) == 1
        assert not foo_imports[0].is_conditional

        bar_imports = [i for i in out.imports if i.module == "bar"]
        assert len(bar_imports) == 1
        assert not bar_imports[0].is_conditional

    def test_conditional_import_does_not_shadow_unconditional(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "app.py").write_text(
            "import foo\nfrom typing import TYPE_CHECKING\n\nif TYPE_CHECKING:\n    import foo\n"
        )

        out = extract_structural(tmp_path)

        foo_imports = [i for i in out.imports if i.module == "foo"]
        assert len(foo_imports) == 2

        unconditional = [i for i in foo_imports if not i.is_conditional]
        assert len(unconditional) == 1

        conditional = [i for i in foo_imports if i.is_conditional]
        assert len(conditional) == 1

    def test_nested_conditional_depth(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "app.py").write_text(
            "from typing import TYPE_CHECKING\n\n"
            "if TYPE_CHECKING:\n"
            "    try:\n"
            "        from foo import Bar as B\n"
            "    except ImportError:\n"
            "        pass\n"
        )

        out = extract_structural(tmp_path)

        conditional_imports = [i for i in out.imports if i.module == "foo" and i.is_conditional]
        assert len(conditional_imports) == 1

        conditional_aliases = [a for a in out.aliases if a.alias_name == "B" and a.is_conditional]
        assert len(conditional_aliases) == 1

    def test_try_except_non_import_error_not_conditional(
        self,
        tmp_path: Path,
    ) -> None:
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "app.py").write_text("try:\n    import x\nexcept ValueError:\n    pass\n")

        out = extract_structural(tmp_path)

        x_imports = [i for i in out.imports if i.module == "x"]
        assert len(x_imports) == 1
        assert not x_imports[0].is_conditional

    def test_multihop_reexport_chain_resolves_to_original_fqn(
        self,
        tmp_path: Path,
    ) -> None:
        """A 3-hop re-export chain: a/__init__ → b/__init__ → c/__init__ → c/leaf."""
        for name in ("a", "a/b", "a/b/c"):
            (tmp_path / name).mkdir(parents=True, exist_ok=True)
        (tmp_path / "a/b/c/leaf.py").write_text("def helper():\n    return 1\n")
        (tmp_path / "a/b/c/__init__.py").write_text("from .leaf import helper\n")
        (tmp_path / "a/b/__init__.py").write_text("from .c import helper\n")
        (tmp_path / "a/__init__.py").write_text("from .b import helper\n")
        (tmp_path / "consumer.py").write_text(
            "from a import helper\n\ndef run():\n    return helper()\n"
        )

        out = extract_structural(tmp_path)

        consumer_refs = {
            (ref.name, ref.fqn) for ref in out.symbol_refs if ref.location.file == "consumer.py"
        }
        assert ("helper", "a.b.c.leaf.helper") in consumer_refs

        assert any(
            edge.caller_fqn == "consumer.run" and edge.callee_fqn == "a.b.c.leaf.helper"
            for edge in out.call_edges
        )

    def test_reexport_shadowed_by_local_definition_in_consumer_keeps_local(
        self,
        tmp_path: Path,
    ) -> None:
        """Local definition in consumer module shadows the re-exported name."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("from .impl import helper\n")
        (pkg / "impl.py").write_text("def helper():\n    return 1\n")
        (tmp_path / "consumer.py").write_text(
            "from pkg import helper\n\n"
            "def helper():\n"
            "    return 2\n\n"
            "def run():\n"
            "    return helper()\n"
        )

        out = extract_structural(tmp_path)

        # The local `helper` definition should shadow the import.
        assert any(
            edge.caller_fqn == "consumer.run" and edge.callee_fqn == "consumer.helper"
            for edge in out.call_edges
        )
        assert not any(
            edge.caller_fqn == "consumer.run" and edge.callee_fqn == "pkg.impl.helper"
            for edge in out.call_edges
        )

    def test_diamond_reexport_does_not_duplicate(
        self,
        tmp_path: Path,
    ) -> None:
        """Two packages re-export the same leaf symbol; consumer imports both."""
        leaf = tmp_path / "leaf"
        leaf.mkdir()
        (leaf / "__init__.py").write_text("")
        (leaf / "core.py").write_text("def util():\n    return 1\n")

        for name in ("alpha", "beta"):
            pkg = tmp_path / name
            pkg.mkdir()
            (pkg / "__init__.py").write_text("from leaf.core import util\n")

        (tmp_path / "consumer.py").write_text(
            "from alpha import util as a_util\n"
            "from beta import util as b_util\n\n"
            "def run():\n"
            "    return a_util() + b_util()\n"
        )

        out = extract_structural(tmp_path)

        run_edges = [
            edge
            for edge in out.call_edges
            if edge.caller_fqn == "consumer.run" and edge.callee_fqn == "leaf.core.util"
        ]
        # Both a_util() and b_util() should resolve to the same leaf.core.util
        assert len(run_edges) == 2

    def test_reexport_of_reexported_alias_preserves_full_chain(
        self,
        tmp_path: Path,
    ) -> None:
        """Re-export with alias at each hop preserves the full resolution chain."""
        inner = tmp_path / "inner"
        inner.mkdir()
        (inner / "__init__.py").write_text("")
        (inner / "impl.py").write_text("def original():\n    return 1\n")

        middle = tmp_path / "middle"
        middle.mkdir()
        (middle / "__init__.py").write_text("from inner.impl import original as renamed\n")

        outer = tmp_path / "outer"
        outer.mkdir()
        (outer / "__init__.py").write_text("from middle import renamed as public_api\n")

        (tmp_path / "consumer.py").write_text(
            "from outer import public_api\n\ndef run():\n    return public_api()\n"
        )

        out = extract_structural(tmp_path)

        consumer_refs = {
            (ref.name, ref.fqn) for ref in out.symbol_refs if ref.location.file == "consumer.py"
        }
        assert ("public_api", "inner.impl.original") in consumer_refs

        assert any(
            edge.caller_fqn == "consumer.run" and edge.callee_fqn == "inner.impl.original"
            for edge in out.call_edges
        )


# ── Reexport resolution termination ──────────────────────────────────


class TestResolveReexportedFqnTermination:
    """Direct unit tests for ``_resolve_reexported_fqn`` termination.

    These bypass ``_build_reexport_map`` and test the defense-in-depth
    growth guard in the resolution loop directly, ensuring that even if
    a divergent entry reaches the resolver, it terminates safely.
    """

    def test_self_embedding_entry_terminates_via_growth_guard(self) -> None:
        """Rewrite ``a.b -> a.b.b`` would grow on every step.

        The defense-in-depth guard stops growth at +500 chars.
        This tests that the function terminates at all — it should
        not be reachable in practice because ``_build_reexport_map``
        filters self-embedding entries.
        """
        reexports = {"a.b": "a.b.b"}
        result = _resolve_reexported_fqn("a.b.method", reexports)
        assert result is not None
        # Must terminate — the guard caps at input_len + 500.
        assert len(result) < len("a.b.method") + 600

    def test_mutual_cycle_terminates(self) -> None:
        """``a.x -> b.x`` and ``b.x -> a.x`` cycle without growth."""
        reexports = {"a.x": "b.x", "b.x": "a.x"}
        result = _resolve_reexported_fqn("a.x.call", reexports)
        assert result is not None
        assert len(result) < 200

    def test_valid_rewrite_resolves_normally(self) -> None:
        """Non-divergent rewrite works as before."""
        reexports = {"pkg.helper": "pkg.impl.helper"}
        result = _resolve_reexported_fqn("pkg.helper", reexports)
        assert result == "pkg.impl.helper"

    def test_chained_valid_rewrite_resolves(self) -> None:
        """Multi-hop non-divergent rewrite works."""
        reexports = {"a.x": "b.x", "b.x": "c.x"}
        result = _resolve_reexported_fqn("a.x.call", reexports)
        assert result == "c.x.call"

    def test_none_input_returns_none(self) -> None:
        result = _resolve_reexported_fqn(None, {"a": "b"})
        assert result is None

    def test_empty_reexports_returns_input(self) -> None:
        result = _resolve_reexported_fqn("a.b.c", {})
        assert result == "a.b.c"

    def test_no_match_returns_input(self) -> None:
        result = _resolve_reexported_fqn("x.y.z", {"a.b": "c.d"})
        assert result == "x.y.z"


class TestReexportResolutionTermination:
    """Guard against non-terminating FQN rewriting in reexport resolution.

    The reexport resolution loop rewrites FQN prefixes using a map of
    ``exported_fqn -> original_fqn``.  Certain real-world re-export
    patterns produce map entries where ``original_fqn`` starts with
    ``exported_fqn`` — causing the rewritten string to grow on every
    iteration while remaining *distinct* from all previous values, so
    naive ``seen``-set cycle detection never fires.

    These tests model the complete bug class — not just one symptom —
    and must all pass without timeouts or excessive memory.
    """

    def test_self_referential_reexport_terminates(self, tmp_path: Path) -> None:
        """``from pkg.sub.db import db`` in pkg/sub/__init__.py.

        Produces reexport ``pkg.sub.db -> pkg.sub.db.db``; a consumer
        reference ``pkg.sub.db.add_command`` would grow unboundedly
        without the fix: pkg.sub.db.db.add_command -> pkg.sub.db.db.db.add_command -> ...

        This is a real-world self-referential re-export pattern (a ``cli/__init__.py``).
        """
        pkg = tmp_path / "pkg" / "sub"
        pkg.mkdir(parents=True)
        (tmp_path / "pkg" / "__init__.py").write_text("")
        (pkg / "db.py").write_text(
            "import click\n\n@click.group()\ndef db():\n    pass\n\ndef add_command():\n    pass\n"
        )
        (pkg / "__init__.py").write_text("from pkg.sub.db import db\n")
        (tmp_path / "app.py").write_text(
            "from pkg.sub import db\n\ndef setup():\n    db.add_command()\n"
        )

        # Must complete without OOM or timeout.
        out = extract_structural(tmp_path)

        # The reference should resolve to the leaf module, not grow.
        app_edges = [e for e in out.call_edges if e.caller_fqn == "app.setup"]
        callee_fqns = {e.callee_fqn for e in app_edges}
        # Should NOT contain an infinitely-expanded string.
        for fqn in callee_fqns:
            if fqn is not None:
                assert len(fqn) < 200, f"FQN grew unboundedly: {fqn!r}"

    def test_multiple_self_referential_reexports_terminate(self, tmp_path: Path) -> None:
        """Multiple same-name re-exports in one __init__.py (real-world pattern).

        ``from pkg.cli.db import db`` + ``from pkg.cli.plugins import plugins``
        in pkg/cli/__init__.py — each creates a self-referential entry.
        """
        cli = tmp_path / "pkg" / "cli"
        cli.mkdir(parents=True)
        (tmp_path / "pkg" / "__init__.py").write_text("")
        (cli / "db.py").write_text("def db():\n    pass\n")
        (cli / "plugins.py").write_text("def plugins():\n    pass\n")
        (cli / "themes.py").write_text("def themes():\n    pass\n")
        (cli / "__init__.py").write_text(
            "from pkg.cli.db import db\n"
            "from pkg.cli.plugins import plugins\n"
            "from pkg.cli.themes import themes\n"
        )
        (tmp_path / "app.py").write_text(
            "from pkg import cli\n\n"
            "def setup():\n"
            "    cli.db()\n"
            "    cli.plugins()\n"
            "    cli.themes()\n"
        )

        out = extract_structural(tmp_path)

        for ref in out.symbol_refs:
            if ref.fqn is not None:
                assert len(ref.fqn) < 200, f"FQN grew unboundedly: {ref.fqn!r}"

    def test_mutual_reexport_cycle_terminates(self, tmp_path: Path) -> None:
        """Two packages re-export each other's symbols.

        ``alpha/__init__.py: from beta import shared``
        ``beta/__init__.py: from alpha import shared``
        This creates a cycle: alpha.shared -> beta.shared -> alpha.shared -> ...
        """
        alpha = tmp_path / "alpha"
        beta = tmp_path / "beta"
        alpha.mkdir()
        beta.mkdir()
        (alpha / "core.py").write_text("def shared():\n    pass\n")
        # alpha re-exports from beta, beta re-exports from alpha
        (alpha / "__init__.py").write_text("from beta import shared\n")
        (beta / "__init__.py").write_text("from alpha import shared\n")
        (tmp_path / "app.py").write_text("from alpha import shared\n\ndef run():\n    shared()\n")

        out = extract_structural(tmp_path)

        for ref in out.symbol_refs:
            if ref.fqn is not None:
                assert len(ref.fqn) < 200, f"FQN grew unboundedly: {ref.fqn!r}"

    def test_transitive_reexport_cycle_terminates(self, tmp_path: Path) -> None:
        """Three-package cycle: a -> b -> c -> a.

        Each package re-exports from the next, creating a transitive cycle.
        """
        for name in ("a", "b", "c"):
            (tmp_path / name).mkdir()
        (tmp_path / "a" / "impl.py").write_text("def func():\n    pass\n")
        (tmp_path / "a" / "__init__.py").write_text("from c import func\n")
        (tmp_path / "b" / "__init__.py").write_text("from a import func\n")
        (tmp_path / "c" / "__init__.py").write_text("from b import func\n")
        (tmp_path / "app.py").write_text("from a import func\n\ndef run():\n    func()\n")

        out = extract_structural(tmp_path)

        for ref in out.symbol_refs:
            if ref.fqn is not None:
                assert len(ref.fqn) < 200, f"FQN grew unboundedly: {ref.fqn!r}"

    def test_deep_valid_chain_still_resolves(self, tmp_path: Path) -> None:
        """A 5-hop re-export chain with no cycles resolves correctly.

        Ensures the termination fix doesn't break legitimate deep chains.
        """
        for name in ("a", "a/b", "a/b/c", "a/b/c/d", "a/b/c/d/e"):
            (tmp_path / name).mkdir(parents=True, exist_ok=True)
        (tmp_path / "a/b/c/d/e/leaf.py").write_text("def deep():\n    return 1\n")
        (tmp_path / "a/b/c/d/e/__init__.py").write_text("from .leaf import deep\n")
        (tmp_path / "a/b/c/d/__init__.py").write_text("from .e import deep\n")
        (tmp_path / "a/b/c/__init__.py").write_text("from .d import deep\n")
        (tmp_path / "a/b/__init__.py").write_text("from .c import deep\n")
        (tmp_path / "a/__init__.py").write_text("from .b import deep\n")
        (tmp_path / "consumer.py").write_text(
            "from a import deep\n\ndef run():\n    return deep()\n"
        )

        out = extract_structural(tmp_path)

        assert any(
            edge.caller_fqn == "consumer.run" and edge.callee_fqn == "a.b.c.d.e.leaf.deep"
            for edge in out.call_edges
        )

    def test_reexport_with_attribute_access_on_same_name_module(
        self,
        tmp_path: Path,
    ) -> None:
        """Attribute access on a re-exported same-name symbol.

        ``from pkg.cli.db import db`` makes ``pkg.cli.db`` -> ``pkg.cli.db.db``.
        When consumer does ``db.some_method()``, the FQN ``pkg.cli.db.some_method``
        must not grow into ``pkg.cli.db.db.db....some_method``.
        """
        pkg = tmp_path / "pkg" / "cli"
        pkg.mkdir(parents=True)
        (tmp_path / "pkg" / "__init__.py").write_text("")
        (pkg / "db.py").write_text(
            "class DB:\n"
            "    def migrate(self):\n        pass\n"
            "    def seed(self):\n        pass\n"
            "\ndb = DB()\n"
        )
        (pkg / "__init__.py").write_text("from pkg.cli.db import db\n")
        (tmp_path / "app.py").write_text(
            "from pkg.cli import db\n\ndef setup():\n    db.migrate()\n    db.seed()\n"
        )

        out = extract_structural(tmp_path)

        for ref in out.symbol_refs:
            if ref.fqn is not None:
                assert len(ref.fqn) < 200, f"FQN grew unboundedly: {ref.fqn!r}"
        for edge in out.call_edges:
            if edge.callee_fqn is not None:
                assert len(edge.callee_fqn) < 200, f"Callee FQN grew: {edge.callee_fqn!r}"


# ── Error handling ────────────────────────────────────────────────────


class TestErrorHandling:
    def test_unparseable_file(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.py"
        bad.write_text("def (broken syntax\n")
        out = extract_structural(tmp_path)
        assert len(out.errors) == 1
        assert out.errors[0].error_kind.value == "parse"
        assert out.errors[0].is_fatal

    def test_other_files_still_extracted(self, tmp_path: Path) -> None:
        (tmp_path / "good.py").write_text("def hello(): pass\n")
        (tmp_path / "bad.py").write_text("def (broken\n")
        out = extract_structural(tmp_path)
        assert len(out.functions) >= 1  # good.py extracted
        assert len(out.errors) >= 1  # bad.py recorded

    def test_empty_file(self, tmp_path: Path) -> None:
        (tmp_path / "empty.py").write_text("")
        out = extract_structural(tmp_path)
        assert len(out.errors) == 0
        assert len(out.functions) == 0
