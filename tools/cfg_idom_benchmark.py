"""Synthetic guardrail benchmark for ControlFlowGraph immediate dominators."""

from __future__ import annotations

import argparse
import time
from typing import TYPE_CHECKING

from flawed._index._graphs import ControlFlowGraph
from flawed._index._types import CFGBlock, CFGEdge

if TYPE_CHECKING:
    from collections.abc import Sequence

DEFAULT_SIZES = (50, 200, 800)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    print("blocks,edges,shape,elapsed_ms")
    for size in args.sizes:
        for shape in ("linear", "diamonds"):
            blocks, edges = synthetic_cfg(size, shape=shape)
            started = time.perf_counter()
            ControlFlowGraph(blocks, edges)
            elapsed_ms = (time.perf_counter() - started) * 1000
            print(f"{len(blocks)},{len(edges)},{shape},{elapsed_ms:.3f}")
    return 0


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=int, nargs="+", default=DEFAULT_SIZES)
    return parser.parse_args(argv)


def synthetic_cfg(size: int, *, shape: str) -> tuple[tuple[CFGBlock, ...], tuple[CFGEdge, ...]]:
    if size < 1:
        raise ValueError("size must be positive")
    if shape == "linear":
        edge_pairs = tuple((index, index + 1) for index in range(size - 1))
    elif shape == "diamonds":
        edge_pairs = diamond_edges(size)
    else:
        raise ValueError(f"unknown CFG shape: {shape}")
    return blocks_for(size, edge_pairs), edges_for(edge_pairs)


def diamond_edges(size: int) -> tuple[tuple[int, int], ...]:
    pairs: list[tuple[int, int]] = []
    cursor = 0
    while cursor + 3 < size:
        branch = cursor
        left = cursor + 1
        right = cursor + 2
        merge = cursor + 3
        pairs.extend(((branch, left), (branch, right), (left, merge), (right, merge)))
        if merge + 1 < size:
            pairs.append((merge, merge + 1))
        cursor = merge + 1
    while cursor + 1 < size:
        pairs.append((cursor, cursor + 1))
        cursor += 1
    return tuple(pairs)


def blocks_for(size: int, edge_pairs: tuple[tuple[int, int], ...]) -> tuple[CFGBlock, ...]:
    successors: dict[int, list[int]] = {index: [] for index in range(size)}
    predecessors: dict[int, list[int]] = {index: [] for index in range(size)}
    for source, target in edge_pairs:
        successors[source].append(target)
        predecessors[target].append(source)
    return tuple(
        CFGBlock(
            id=index,
            statements=(),
            successors=tuple(successors[index]),
            predecessors=tuple(predecessors[index]),
            condition_expr=None,
        )
        for index in range(size)
    )


def edges_for(edge_pairs: tuple[tuple[int, int], ...]) -> tuple[CFGEdge, ...]:
    return tuple(
        CFGEdge(source_id=source, target_id=target, label="fallthrough", is_exceptional=False)
        for source, target in edge_pairs
    )


if __name__ == "__main__":
    raise SystemExit(main())
