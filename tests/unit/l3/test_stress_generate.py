"""Tests for the synthetic app generator (tools.stress.generate).

Validates that generated apps are syntactically correct Python, produce
expected file counts, and exercise the patterns the stress harness needs.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path
from tools.stress.generate import GeneratedApp, StressConfig, generate_stress_app


@pytest.fixture
def small_app(tmp_path: Path) -> GeneratedApp:
    """Generate the smallest stress app for testing."""
    config = StressConfig(
        file_count=25,
        functions_per_file=4,
        routes_per_file=2,
        call_edge_density=2,
        blueprint_count=3,
        helper_fan_out=3,
        providers=("flask", "sqlalchemy"),
        seed=42,
    )
    return generate_stress_app(config, tmp_path)


class TestGenerateStressApp:
    """Test the synthetic app generator."""

    def test_returns_generated_app_metadata(self, small_app: GeneratedApp) -> None:
        assert small_app.app_dir.is_dir()
        assert small_app.file_count > 0
        assert small_app.function_count > 0
        assert small_app.route_count > 0
        assert small_app.line_count > 0

    def test_all_python_files_are_syntactically_valid(self, small_app: GeneratedApp) -> None:
        py_files = list(small_app.app_dir.rglob("*.py"))
        assert len(py_files) > 0
        for f in py_files:
            source = f.read_text(encoding="utf-8")
            try:
                ast.parse(source, filename=str(f))
            except SyntaxError as exc:
                pytest.fail(f"Syntax error in {f.relative_to(small_app.app_dir)}: {exc}")

    def test_app_py_exists_with_flask_import(self, small_app: GeneratedApp) -> None:
        app_py = small_app.app_dir / "app.py"
        assert app_py.exists()
        content = app_py.read_text(encoding="utf-8")
        assert "from flask import Flask" in content
        assert "app = Flask(__name__)" in content

    def test_blueprint_packages_created(self, small_app: GeneratedApp) -> None:
        bp_dirs = [
            d for d in small_app.app_dir.iterdir() if d.is_dir() and d.name.startswith("bp_")
        ]
        assert len(bp_dirs) == 3  # blueprint_count=3

    def test_helper_modules_created(self, small_app: GeneratedApp) -> None:
        helpers_dir = small_app.app_dir / "helpers"
        assert helpers_dir.is_dir()
        assert (helpers_dir / "common.py").exists()
        assert (helpers_dir / "db.py").exists()  # sqlalchemy in providers

    def test_route_files_contain_flask_routes(self, small_app: GeneratedApp) -> None:
        route_files = list(small_app.app_dir.rglob("routes_*.py"))
        assert len(route_files) > 0
        for f in route_files:
            content = f.read_text(encoding="utf-8")
            assert "@bp.route(" in content

    def test_sqlalchemy_patterns_present(self, small_app: GeneratedApp) -> None:
        """SQLAlchemy provider patterns should appear when sqlalchemy is in providers."""
        all_content = "\n".join(
            f.read_text(encoding="utf-8") for f in small_app.app_dir.rglob("*.py")
        )
        assert "from sqlalchemy import text" in all_content

    def test_deterministic_output(self, tmp_path: Path) -> None:
        """Same seed should produce identical output."""
        config = StressConfig(file_count=25, seed=99)
        app1 = generate_stress_app(config, tmp_path / "run1")
        app2 = generate_stress_app(config, tmp_path / "run2")

        files1 = sorted(f.relative_to(app1.app_dir) for f in app1.app_dir.rglob("*.py"))
        files2 = sorted(f.relative_to(app2.app_dir) for f in app2.app_dir.rglob("*.py"))
        assert files1 == files2

        for rel in files1:
            content1 = (app1.app_dir / rel).read_text(encoding="utf-8")
            content2 = (app2.app_dir / rel).read_text(encoding="utf-8")
            assert content1 == content2, f"Files differ: {rel}"

    def test_pyjwt_provider_generates_auth_helpers(self, tmp_path: Path) -> None:
        config = StressConfig(
            file_count=25,
            blueprint_count=3,
            providers=("flask", "pyjwt"),
        )
        gen = generate_stress_app(config, tmp_path)
        auth_module = gen.app_dir / "helpers" / "auth.py"
        assert auth_module.exists()
        content = auth_module.read_text(encoding="utf-8")
        assert "import jwt" in content

    def test_file_count_matches_config(self, tmp_path: Path) -> None:
        """Generated Python file count should be close to configured file_count."""
        for target in (25, 50):
            config = StressConfig(file_count=target)
            gen = generate_stress_app(config, tmp_path / f"f{target}")
            py_files = list(gen.app_dir.rglob("*.py"))
            # Allow some overhead for __init__.py, helpers, etc.
            assert len(py_files) >= target - 5, (
                f"Too few files for target {target}: {len(py_files)}"
            )
