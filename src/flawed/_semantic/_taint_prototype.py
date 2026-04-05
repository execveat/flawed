"""Experimental intra-procedural taint propagation (spike).

NOT wired into the pipeline — a scratch prototype to evaluate whether a dedicated
taint pass buys anything over the value-flow graph Layer 2 already builds. Kept
out of the package exports on purpose.

TODO(spike): keep-or-drop decision after the value-flow benchmark.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TaintNode:
    name: str
    tainted: bool = False
    sources: set[str] = field(default_factory=set)


class TaintGraph:
    """Forward taint propagation over a single function's assignments."""

    def __init__(self) -> None:
        self._nodes: dict[str, TaintNode] = {}

    def mark_source(self, name: str, origin: str) -> None:
        node = self._nodes.setdefault(name, TaintNode(name))
        node.tainted = True
        node.sources.add(origin)

    def propagate(self, dst: str, srcs: list[str]) -> None:
        node = self._nodes.setdefault(dst, TaintNode(dst))
        for s in srcs:
            src = self._nodes.get(s)
            if src and src.tainted:
                node.tainted = True
                node.sources |= src.sources

    def is_tainted(self, name: str) -> bool:
        node = self._nodes.get(name)
        return bool(node and node.tainted)
