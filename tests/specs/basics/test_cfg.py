"""Specs: control flow graph queries.

Fixture: tests/fixtures/apps/functions/ (session-scoped via root conftest)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed.core import Location

if TYPE_CHECKING:
    from flawed.repo import RepoView


def _loc(file: str, line: int, column: int, end_column: int) -> Location:
    return Location(
        file=file,
        line=line,
        column=column,
        end_line=line,
        end_column=end_column,
    )


class TestCFGAvailability:
    def test_cfg_available_for_function(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("top_level").one()
        cfg = fn.body.cfg
        assert cfg is not None

    def test_cfg_has_blocks(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("validate_positive").one()
        cfg = fn.body.cfg
        # validate_positive has an if statement -> at least 2 blocks
        assert len(list(cfg.blocks)) >= 2


class TestDominance:
    def test_entry_dominates_all(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("validate_positive").one()
        cfg = fn.body.cfg
        condition = _loc("helpers.py", 5, 7, 12)
        raise_stmt = _loc("helpers.py", 6, 8, 44)
        return_stmt = _loc("helpers.py", 7, 4, 12)

        assert cfg.dominates(condition, raise_stmt)
        assert cfg.dominates(condition, return_stmt)

    def test_dominates_reflexive(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("top_level").one()
        cfg = fn.body.cfg
        # A location dominates itself
        return_stmt = _loc("main.py", 5, 4, 16)
        assert cfg.dominates(return_stmt, return_stmt)

    def test_precedes_and_ordered_require_all_paths(self, functions_app: RepoView) -> None:
        fn = functions_app.functions.named("validate_positive").one()
        cfg = fn.body.cfg
        condition = _loc("helpers.py", 5, 7, 12)
        raise_stmt = _loc("helpers.py", 6, 8, 44)
        return_stmt = _loc("helpers.py", 7, 4, 12)

        assert cfg.precedes(condition, return_stmt)
        assert cfg.ordered(condition, return_stmt)
        assert not cfg.precedes(raise_stmt, return_stmt)
        assert not cfg.ordered(condition, raise_stmt, return_stmt)

    def test_reachable_between_distinguishes_sibling_branches(
        self, functions_app: RepoView
    ) -> None:
        fn = functions_app.functions.named("validate_positive").one()
        cfg = fn.body.cfg
        condition = _loc("helpers.py", 5, 7, 12)
        raise_stmt = _loc("helpers.py", 6, 8, 44)
        return_stmt = _loc("helpers.py", 7, 4, 12)

        assert cfg.reachable_between(condition, raise_stmt)
        assert cfg.reachable_between(condition, return_stmt)
        assert not cfg.dominates(raise_stmt, return_stmt)
        assert not cfg.reachable_between(raise_stmt, return_stmt)
