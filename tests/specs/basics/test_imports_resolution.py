"""Specs: import resolution and symbol tracking.

Fixture: tests/fixtures/apps/imports/ (session-scoped via root conftest)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flawed.repo import RepoView


class TestImportDiscovery:
    def test_discovers_functions_across_files(self, imports_app: RepoView) -> None:
        """Functions from both main.py and helpers.py are discovered."""
        names = {f.name for f in imports_app.functions}
        assert names >= {"run", "setup", "process_data", "transform"}

    def test_in_file_filters_to_module(self, imports_app: RepoView) -> None:
        """in_file() restricts results to a single module."""
        main_fns = imports_app.functions.in_file("main.py")
        assert {f.name for f in main_fns} == {"run"}

        helper_fns = imports_app.functions.in_file("helpers.py")
        assert {f.name for f in helper_fns} == {"setup", "process_data", "transform"}

    def test_fqn_includes_package_path(self, imports_app: RepoView) -> None:
        """FQNs encode the package-relative module path."""
        run_fn = imports_app.functions.named("run").one()
        assert run_fn.fqn == "imports.main.run"

        setup_fn = imports_app.functions.named("setup").one()
        assert setup_fn.fqn == "imports.helpers.setup"

    def test_with_fqn_filters_by_qualified_name(self, imports_app: RepoView) -> None:
        """with_fqn() locates functions by their fully-qualified name."""
        matches = imports_app.functions.with_fqn("imports.helpers.transform")
        assert len(matches) == 1
        assert matches.one().name == "transform"

    def test_cross_file_call_resolves(self, imports_app: RepoView) -> None:
        """Cross-file calls resolve through import aliases."""
        fn = imports_app.functions.named("run").one()
        callees = fn.calls
        # helpers.setup(), process_data(), t() should all resolve
        names = {f.name for f in callees}
        assert "setup" in names
