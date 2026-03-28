"""Fail-closed size/memory budget for Layer 2 construction (FLAW-345).

The time-based layer timeout already fails closed: a layer that overruns its
deadline sets ``metrics.incomplete = True`` and the scan exits ``EXIT_TIMEOUT``
*before* the findings check, so a timed-out scan can never read as a clean zero
(``src/flawed/_cli/pipeline.py``).

The residual silent-false-negative path is **memory**.  On a pathological repo
the L2 value-flow construction can grow until the OS ``SIGKILL``s the process
(research PERF-01: a 231 MB value-flow graph on one real-world repo).  A ``SIGKILL`` is
uncatchable: it leaves *no result document at all*, which a batch harness can
misread as a clean "0 findings" — exactly the fail-open this engine forbids.

This module converts that one uncatchable failure mode into the same honest
``incomplete: true`` the timeout path already produces.  A :class:`ConstructionBudget`
is installed for the duration of the L2 build (see ``run_semantic``); the hot
construction loops periodically call :func:`check_active_budget`, which raises
:class:`ValueFlowBudgetError` once resident memory (or an explicit unit
ceiling) crosses the budget.  The CLI pipeline catches that typed error next to
``LayerTimeoutError`` and marks the scan incomplete.

**Why a process-RSS ceiling, not a config-file knob.**  The thing that gets you
``SIGKILL``ed is total process memory, which is *machine-specific* (a 16 GB eval
box vs a 128 GB workstation) — so the honest default is adaptive: a fraction of
physical RAM, computed at run time.  That is also why the override is an
environment variable rather than a committed config field: a per-machine memory
ceiling does not belong in a shared, version-controlled config file, and the
config override-merge path reconstructs ``ResolvedConfig`` without carrying every
field (see the note filed against ``_config/match.py``), which would silently
drop a stored budget.  ``FLAWED_L2_MAX_RSS_BYTES`` (and
``FLAWED_L2_MAX_VALUE_FLOW_EDGES``) override the adaptive default when set.
"""

from __future__ import annotations

import contextvars
import os
import resource
import sys
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

#: Environment overrides for the two ceilings (integers; see module docstring).
_ENV_MAX_RSS_BYTES = "FLAWED_L2_MAX_RSS_BYTES"
_ENV_MAX_VALUE_FLOW_EDGES = "FLAWED_L2_MAX_VALUE_FLOW_EDGES"

#: Default RSS ceiling as a fraction of total physical RAM.  Conservative enough
#: never to trip a normal scan (which uses a small fraction of RAM) while still
#: pre-empting the OS OOM killer on a runaway construction.
_DEFAULT_RSS_FRACTION = 0.9

#: How often :func:`budgeted` checks the budget (every Nth element).  Reading RSS
#: is a cheap syscall, but a per-element check across a multi-million-edge loop is
#: needless overhead; striding keeps the guard's cost negligible while still
#: catching a runaway well before the OS does.
_DEFAULT_STRIDE = 4096


class ValueFlowBudgetError(Exception):
    """L2 construction crossed a configured size/memory budget.

    Raised mid-construction so the pipeline can fail **closed** (mark the scan
    ``incomplete``) instead of letting the value-flow graph grow until the OS
    ``SIGKILL``s the process.  Mirrors the layer-timeout fail-closed contract.
    """

    def __init__(self, *, kind: str, observed: int, limit: int) -> None:
        self.kind = kind
        self.observed = observed
        self.limit = limit
        super().__init__(
            f"L2 value-flow construction exceeded its {kind} budget "
            f"({observed} > {limit}); failing closed to avoid an OOM kill "
            f"that would read as a clean zero"
        )


def _maxrss_bytes() -> int:
    """Peak resident set size of this process, in **bytes**.

    ``ru_maxrss`` is reported in kilobytes on Linux and in bytes on macOS;
    normalize to bytes so the ceiling is platform-independent.
    """
    raw = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if sys.platform == "darwin":
        return raw
    return raw * 1024


def _physical_ram_bytes() -> int | None:
    """Total physical RAM in bytes, or ``None`` if it cannot be determined."""
    try:
        return int(os.sysconf("SC_PAGE_SIZE")) * int(os.sysconf("SC_PHYS_PAGES"))
    except (ValueError, OSError, AttributeError):
        return None


def _env_int(name: str) -> int | None:
    """Parse a positive integer from environment variable ``name`` (else ``None``)."""
    raw = os.environ.get(name)
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value > 0 else None


@dataclass(frozen=True)
class ConstructionBudget:
    """Ceilings for a single Layer 2 construction.

    ``0`` for either ceiling disables that check.  Use :meth:`resolved` to build
    one from the adaptive default plus environment overrides.
    """

    max_rss_bytes: int = 0
    max_value_flow_edges: int = 0

    @classmethod
    def resolved(cls) -> ConstructionBudget:
        """Build the active budget: env overrides, else the adaptive RSS default."""
        rss = _env_int(_ENV_MAX_RSS_BYTES)
        if rss is None:
            total = _physical_ram_bytes()
            rss = int(total * _DEFAULT_RSS_FRACTION) if total is not None else 0
        edges = _env_int(_ENV_MAX_VALUE_FLOW_EDGES) or 0
        return cls(max_rss_bytes=rss, max_value_flow_edges=edges)

    def check_rss(self) -> None:
        """Raise :class:`ValueFlowBudgetError` if resident memory is over budget."""
        if self.max_rss_bytes <= 0:
            return
        rss = _maxrss_bytes()
        if rss > self.max_rss_bytes:
            raise ValueFlowBudgetError(
                kind="resident-memory", observed=rss, limit=self.max_rss_bytes
            )

    def check_edges(self, count: int) -> None:
        """Raise :class:`ValueFlowBudgetError` if ``count`` exceeds the edge ceiling."""
        if self.max_value_flow_edges <= 0:
            return
        if count > self.max_value_flow_edges:
            raise ValueFlowBudgetError(
                kind="value-flow-edge-count",
                observed=count,
                limit=self.max_value_flow_edges,
            )


#: The budget in force for the current L2 build, or ``None`` outside one.  A
#: ``ContextVar`` keeps it isolated per thread/task, so the parallel test runner
#: and any concurrent construction never see each other's budget.
_active_budget: contextvars.ContextVar[ConstructionBudget | None] = contextvars.ContextVar(
    "flawed_l2_construction_budget", default=None
)

#: RSS source label for trajectory samples taken here.  ``ru_maxrss`` is a
#: process high-water peak, so an intra-L2 series built from these can show the
#: construction *growing* but not freeing — the cross-phase freeing signal lives
#: in the true-current-RSS phase-boundary samples recorded by the CLI layer.
_RSS_SOURCE_PEAK = "rusage_maxrss_peak"

#: Cap on retained trajectory samples (a ring buffer) so a multi-million-edge
#: construction cannot grow the in-memory trajectory without bound.
_TRAJECTORY_CAP = 1024


@dataclass
class _Trajectory:
    """Bounded in-memory RSS trajectory for one L2 construction."""

    start_ns: int
    samples: deque[tuple[float, int, str]]


#: The trajectory for the current L2 build, or ``None`` outside one.  Paired with
#: :data:`_active_budget` and reset on the same boundary, so samples never leak
#: across constructions.
_active_trajectory: contextvars.ContextVar[_Trajectory | None] = contextvars.ContextVar(
    "flawed_l2_construction_trajectory", default=None
)


@contextmanager
def construction_budget(budget: ConstructionBudget) -> Iterator[ConstructionBudget]:
    """Install ``budget`` as the active L2 construction budget for the block.

    Also installs a bounded RSS trajectory (drained via :func:`current_trajectory`
    *inside* the block, before it exits and the context resets).
    """
    token = _active_budget.set(budget)
    traj_token = _active_trajectory.set(
        _Trajectory(start_ns=time.perf_counter_ns(), samples=deque(maxlen=_TRAJECTORY_CAP))
    )
    try:
        yield budget
    finally:
        _active_budget.reset(token)
        _active_trajectory.reset(traj_token)


def _record_trajectory_sample() -> None:
    """Append one ``(elapsed_ms_since_L2_start, rss_bytes, source)`` sample."""
    traj = _active_trajectory.get()
    if traj is None:
        return
    elapsed_ms = (time.perf_counter_ns() - traj.start_ns) / 1_000_000
    traj.samples.append((elapsed_ms, _maxrss_bytes(), _RSS_SOURCE_PEAK))


def current_trajectory() -> tuple[tuple[float, int, str], ...]:
    """Return the active L2 RSS trajectory as ``(elapsed_ms, rss_bytes, source)`` tuples.

    Empty outside an L2 construction.  ``elapsed_ms`` is relative to the start of
    the L2 build (the only window in which the budget samples).  Must be read
    *inside* the :func:`construction_budget` block, since the context resets on exit.
    """
    traj = _active_trajectory.get()
    if traj is None:
        return ()
    return tuple(traj.samples)


def check_active_budget() -> None:
    """Check resident memory against the active budget (no-op if none installed).

    Called from the hot L2 construction loops.  Cheap: one ``getrusage`` syscall
    when a budget is active, nothing otherwise.  Callers should stride this (call
    it once every N iterations) so a per-element loop does not syscall per element.
    Also records the sampled RSS onto the active trajectory (FLAW-355).
    """
    budget = _active_budget.get()
    if budget is not None:
        _record_trajectory_sample()
        budget.check_rss()


def check_active_budget_edges(count: int) -> None:
    """Check ``count`` against the active budget's edge ceiling (no-op if none)."""
    budget = _active_budget.get()
    if budget is not None:
        budget.check_edges(count)


def budgeted[T](iterable: Iterable[T], *, stride: int = _DEFAULT_STRIDE) -> Iterator[T]:
    """Yield from ``iterable``, checking the active budget every ``stride`` items.

    Wrap a hot L2 construction loop's iterable in this so resident memory is
    sampled as the loop grows the graph — the loop then fails closed via
    :class:`ValueFlowBudgetError` instead of running on into an OOM kill.  A
    no-op (beyond iteration) when no budget is installed.
    """
    for index, item in enumerate(iterable):
        if index % stride == 0:
            check_active_budget()
        yield item
