"""Tests for the shared callee-graph BFS reachability module.

Verifies ``reachable_callees`` with direct graph dicts — no CodeIndex
needed since the BFS operates on a plain ``dict[str, set[str]]``.

``reachable_callees`` returns an *ordered* ``tuple`` in deterministic
breadth-first discovery order (root first, each frontier and each node's
neighbours expanded ``sorted()``).  That order is load-bearing: downstream
the first reachable effect becomes a finding's representative evidence and
feeds its fingerprint, so a hash-seed-dependent order produced
nondeterministic finding counts across identical scans (FLAW-161).  These
tests pin both *membership* (what is reachable) and *order/determinism*.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

from flawed._semantic._callee_graph import reachable_callees


class TestReachableCalleesBasic:
    def test_root_with_no_callees_returns_self(self) -> None:
        graph: dict[str, set[str]] = {}
        result = reachable_callees("root", graph)
        assert result == ("root",)

    def test_root_not_in_graph_returns_self(self) -> None:
        graph: dict[str, set[str]] = {"other": {"child"}}
        result = reachable_callees("root", graph)
        assert result == ("root",)

    def test_direct_callee_included(self) -> None:
        graph: dict[str, set[str]] = {"root": {"child"}}
        result = reachable_callees("root", graph)
        assert result == ("root", "child")

    def test_transitive_callees_included(self) -> None:
        graph: dict[str, set[str]] = {
            "a": {"b"},
            "b": {"c"},
            "c": {"d"},
        }
        result = reachable_callees("a", graph)
        assert result == ("a", "b", "c", "d")


class TestReachableCalleesDepthLimit:
    def test_depth_5_limit_respected(self) -> None:
        # Build a chain of length 7: a -> b -> c -> d -> e -> f -> g -> h
        graph: dict[str, set[str]] = {
            "a": {"b"},
            "b": {"c"},
            "c": {"d"},
            "d": {"e"},
            "e": {"f"},
            "f": {"g"},
            "g": {"h"},
        }
        result = reachable_callees("a", graph)
        # BFS with 5 iterations from root: a(0) -> b(1) -> c(2) -> d(3) -> e(4) -> f(5)
        assert "a" in result
        assert "b" in result
        assert "f" in result
        # g is at depth 6, h at depth 7 — beyond the 5-iteration limit
        assert "g" not in result
        assert "h" not in result

    def test_exactly_depth_5_reachable(self) -> None:
        # a -> b -> c -> d -> e -> f (exactly 5 hops)
        graph: dict[str, set[str]] = {
            "a": {"b"},
            "b": {"c"},
            "c": {"d"},
            "d": {"e"},
            "e": {"f"},
        }
        result = reachable_callees("a", graph)
        assert result == ("a", "b", "c", "d", "e", "f")


class TestReachableCalleesCycles:
    def test_cycle_terminates(self) -> None:
        graph: dict[str, set[str]] = {
            "a": {"b"},
            "b": {"c"},
            "c": {"a"},  # cycle back to root
        }
        result = reachable_callees("a", graph)
        assert set(result) == {"a", "b", "c"}

    def test_self_loop_terminates(self) -> None:
        graph: dict[str, set[str]] = {"a": {"a"}}
        result = reachable_callees("a", graph)
        assert result == ("a",)

    def test_diamond_graph(self) -> None:
        # a -> b, a -> c, b -> d, c -> d
        graph: dict[str, set[str]] = {
            "a": {"b", "c"},
            "b": {"d"},
            "c": {"d"},
        }
        result = reachable_callees("a", graph)
        # Deterministic BFS: root, then sorted neighbours (b, c), then d once.
        assert result == ("a", "b", "c", "d")


class TestReachableCalleesCache:
    def test_cache_populated_after_call(self) -> None:
        graph: dict[str, set[str]] = {"a": {"b"}}
        cache: dict[str, tuple[str, ...]] = {}
        reachable_callees("a", graph, cache=cache)
        assert "a" in cache
        assert cache["a"] == ("a", "b")

    def test_cache_hit_returns_same_object(self) -> None:
        graph: dict[str, set[str]] = {"a": {"b"}}
        cache: dict[str, tuple[str, ...]] = {}
        first = reachable_callees("a", graph, cache=cache)
        second = reachable_callees("a", graph, cache=cache)
        assert first is second  # identity — same cached object

    def test_cache_not_required(self) -> None:
        graph: dict[str, set[str]] = {"a": {"b"}}
        result = reachable_callees("a", graph)
        assert result == ("a", "b")

    def test_cache_none_behaves_like_no_cache(self) -> None:
        graph: dict[str, set[str]] = {"a": {"b"}}
        result = reachable_callees("a", graph, cache=None)
        assert result == ("a", "b")

    def test_multiple_roots_share_cache(self) -> None:
        graph: dict[str, set[str]] = {
            "a": {"shared"},
            "b": {"shared"},
            "shared": {"leaf"},
        }
        cache: dict[str, tuple[str, ...]] = {}
        reachable_callees("a", graph, cache=cache)
        reachable_callees("b", graph, cache=cache)
        reachable_callees("shared", graph, cache=cache)
        assert len(cache) == 3
        assert cache["shared"] == ("shared", "leaf")


class TestReachableCalleesDeterminism:
    """FLAW-161: the result order must be stable and PYTHONHASHSEED-independent."""

    def test_returns_ordered_tuple(self) -> None:
        result = reachable_callees("a", {"a": {"b"}})
        assert isinstance(result, tuple)

    def test_breadth_first_sorted_order(self) -> None:
        # Neighbours deliberately listed in non-sorted set-literal order;
        # the result must still be sorted-BFS, root first.
        graph: dict[str, set[str]] = {
            "root": {"m", "a", "z"},
            "a": {"a2", "a1"},
            "m": {"m1"},
            "z": {"z1"},
        }
        result = reachable_callees("root", graph)
        # depth 0: root; depth 1: sorted(a, m, z); depth 2: their sorted callees
        assert result == ("root", "a", "m", "z", "a1", "a2", "m1", "z1")

    def test_seed_independent(self) -> None:
        # Build a wide graph whose neighbour sets, if iterated in raw hash
        # order, would differ across hash seeds.  Run the SAME computation in
        # two subprocesses under different PYTHONHASHSEED values and assert
        # byte-identical output.  This is the direct regression guard for the
        # FLAW-161 fingerprint flicker.
        script = textwrap.dedent(
            """
            from flawed._semantic._callee_graph import reachable_callees
            names = [f"n{i:02d}" for i in range(40)]
            graph = {"root": set(names)}
            for n in names:
                graph[n] = {f"{n}_c{j}" for j in range(5)}
            print(",".join(reachable_callees("root", graph)))
            """
        )

        def run(seed: str) -> str:
            proc = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONHASHSEED": seed},
                check=True,
            )
            return proc.stdout

        out0 = run("0")
        out1 = run("1")
        out2 = run("2")
        assert out0 == out1 == out2
        # And it is the sorted-BFS order, not merely stable.
        assert out0.split(",")[0] == "root"
