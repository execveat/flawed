"""Specs: call graph queries.

Fixture: tests/fixtures/apps/functions/ (session-scoped via root conftest)
         tests/fixtures/apps/imports/  (session-scoped via root conftest)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed.calls import Fn

if TYPE_CHECKING:
    from flawed.repo import RepoView


class TestCallGraph:
    def test_direct_calls(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("with_nested").one()
        callees = fn.calls
        # with_nested calls inner(5)
        names = {f.name for f in callees}
        assert "inner" in names

    def test_called_by(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("validate_positive").one()
        callers = fn.called_by
        # Only called if something in main.py calls it
        # In this fixture, nothing calls it directly
        # (it's defined but not invoked in the fixture)
        assert isinstance(callers, type(functions_app.functions))

    def test_cross_file_calls(self, imports_app: RepoView) -> None:
        fn = imports_app.functions.named("run").one()
        callees = fn.calls
        names = {f.name for f in callees}
        assert "setup" in names or "process_data" in names

    def test_reachable_from(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("with_nested").one()
        reachable = fn.reachable
        # Should include inner and anything inner calls
        # For this simple fixture, just inner
        calls_in_scope = reachable.calls(Fn.named("inner"))
        assert calls_in_scope


class TestCallSites:
    def test_call_site_has_location(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("with_nested").one()
        sites = fn.body.calls(Fn.named("inner"))
        assert len(sites) >= 1
        site = sites.first()
        assert site is not None
        assert site.location.line > 0

    def test_call_site_has_arguments(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("with_nested").one()
        site = fn.body.calls(Fn.named("inner")).first()
        assert site is not None
        assert len(site.arguments) == 1
        assert site.argument(0).expression == "5"

    def test_call_site_target(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("with_nested").one()
        site = fn.body.calls(Fn.named("inner")).first()
        assert site is not None
        assert site.target is not None
        assert site.target.name == "inner"
