"""Exploration-API accessor + memo specs (FLAW-129 accessors, FLAW-132 memo).

Covers the semantic-model accessors added for fluid interactive exploration:

- ``CodeScope.reachable_functions()`` -- the code surface of a scope as a
  navigable FunctionCollection (replaces a hand-rolled ``.calls()`` walk).
- ``Route.lifecycle_hooks`` -- before/after-request handlers attributed to a
  route, surfaced as functions rather than inferred from callee FQNs.
- ``open_repo`` in-process memoization -- a second open of an unchanged tree
  returns the cached RepoView instead of re-paying the L2 build.

Uses session-scoped fixtures from the root conftest so individual tests do not
re-analyze (the timing guard fails direct open_repo/build_index calls).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from flawed import open_repo
from flawed._semantic import _REPO_VIEW_MEMO, clear_repo_view_cache

if TYPE_CHECKING:
    from flawed.repo import RepoView as RepoViewProto

_FLASK_BASIC = Path(__file__).parents[2] / "fixtures" / "apps" / "semantic" / "flask_basic"


class TestReachableFunctions:
    """``CodeScope.reachable_functions()`` returns the scope's code surface."""

    def test_route_reachable_includes_handler(self, flask_basic: RepoViewProto) -> None:
        route = next(r for r in flask_basic.routes if r.endpoint == "index")
        fqns = {fn.fqn for fn in route.reachable.reachable_functions()}
        assert route.handler.fqn in fqns

    def test_handler_is_listed_first(self, flask_basic: RepoViewProto) -> None:
        route = next(r for r in flask_basic.routes if r.endpoint == "index")
        functions = list(route.reachable.reachable_functions())
        assert functions
        assert functions[0].fqn == route.handler.fqn

    def test_returns_navigable_function_collection(self, flask_basic: RepoViewProto) -> None:
        route = next(r for r in flask_basic.routes if r.endpoint == "index")
        functions = route.reachable.reachable_functions()
        # The result is a real FunctionCollection: named() narrows it.
        handler_name = route.handler.name
        assert functions.named(handler_name).one().fqn == route.handler.fqn

    def test_deterministic_order_across_calls(self, flask_basic: RepoViewProto) -> None:
        route = next(r for r in flask_basic.routes if r.endpoint == "index")
        first = [fn.fqn for fn in route.reachable.reachable_functions()]
        second = [fn.fqn for fn in route.reachable.reachable_functions()]
        assert first == second

    def test_function_body_scope_is_single_function(self, flask_basic: RepoViewProto) -> None:
        index = flask_basic.functions.named("index").one()
        body_fns = list(index.body.reachable_functions())
        assert [fn.fqn for fn in body_fns] == [index.fqn]


class TestLifecycleHooks:
    """``Route.lifecycle_hooks`` surfaces before/after-request handlers."""

    def test_app_scoped_before_request_reaches_every_route(
        self, flask_csrf_lifecycle: RepoViewProto
    ) -> None:
        # The fixture registers an app-level @app.before_request hook, so every
        # route should attribute it.
        routes = list(flask_csrf_lifecycle.routes)
        assert routes
        for route in routes:
            hook_names = {fn.name for fn in route.lifecycle_hooks}
            assert "csrf_exempt_for_api_tokens" in hook_names

    def test_hooks_are_navigable_functions(self, flask_csrf_lifecycle: RepoViewProto) -> None:
        route = next(iter(flask_csrf_lifecycle.routes))
        hook = next(fn for fn in route.lifecycle_hooks if fn.name == "csrf_exempt_for_api_tokens")
        # A real Function: its own body is queryable.
        assert hook.fqn.endswith("csrf_exempt_for_api_tokens")
        assert hook.body is not None

    def test_hooks_are_always_a_tuple_of_functions(self, flask_basic: RepoViewProto) -> None:
        # No fail-open: the accessor always yields a tuple of real Function
        # objects (possibly empty), never None or an error.
        from flawed.function import Function

        for route in flask_basic.routes:
            hooks = route.lifecycle_hooks
            assert isinstance(hooks, tuple)
            assert all(isinstance(fn, Function) for fn in hooks)


class TestOpenRepoMemo:
    """``open_repo`` reuses an in-process RepoView for an unchanged tree.

    Self-contained and ``@slow`` (it performs one real L2 build, exceeding the
    per-test timing guard) so it does not depend on or disturb the shared
    session memo: it clears the memo at both ends to leave clean state.
    """

    @pytest.mark.slow
    def test_memo_caches_l2_build_and_clears(self) -> None:
        path = str(_FLASK_BASIC)
        clear_repo_view_cache()
        assert len(_REPO_VIEW_MEMO) == 0

        start = time.monotonic()
        first = open_repo(path)
        first_build = time.monotonic() - start
        assert len(_REPO_VIEW_MEMO) == 1

        start = time.monotonic()
        second = open_repo(path)
        second_build = time.monotonic() - start

        # Same object: the second open did not re-pay the L2 build...
        assert second is first
        # ...and is dramatically faster (the build dominated the first call).
        assert second_build < max(0.5, first_build * 0.2)

        clear_repo_view_cache()
        assert len(_REPO_VIEW_MEMO) == 0
