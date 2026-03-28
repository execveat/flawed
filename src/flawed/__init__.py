"""flawed: a static analysis engine for Python codebases.

Rule authors start here::

    from flawed import open_repo, detector
    from flawed.inputs import Query, Form, Json
    from flawed.effects import Mutation, State, Response, Cache
    from flawed.checks import Crypto, Token
    from flawed.route import Route, POST, accepting

The top-level package IS the Rule API. Deeper layers live in subpackages:

- ``flawed._semantic`` — Semantic Layer (framework interpretation)
- ``flawed._index`` — Code Index (structural extraction)
"""

from __future__ import annotations

import warnings
from importlib.metadata import version as _pkg_version
from typing import TYPE_CHECKING

from flawed._semantic import repo_view_from_artifacts, repo_view_from_path_cached
from flawed.calls import Argument, CallSite, Fn
from flawed.conditions import Check
from flawed.detector import detector
from flawed.effects import Effect
from flawed.findings import FindingCollection, load_findings
from flawed.inputs import InputRead, InputSource
from flawed.repo import RepoView
from flawed.severity import Severity

if TYPE_CHECKING:
    from pathlib import Path

__version__ = _pkg_version("flawed")


class RoutelessRepoWarning(UserWarning):
    """Warned when a repo yields functions but zero routes.

    A web-application repo with code but no detected routes almost always
    means the path points above the application package, or no provider
    recognized its routing — an explorer would otherwise silently investigate
    an empty tree.  Surfacing this honors the no-fail-open principle
    (``docs/analysis-model.md``): a missing analysis is made explicit, not masked.
    """


# A substantial codebase that yields zero routes is the signature of a
# misdirected target path (e.g. the dir *above* the app package) or an
# unsupported framework -- the FLAW-143 case.  A handful of functions with no
# routes is just a small non-web module, so we stay quiet below this floor to
# avoid crying wolf on libraries and test fixtures.  A fuller fix would gate on
# an actual web-framework-detected signal and route this through AnalysisGap
# (see the FLAW-143 follow-up note).
_ROUTELESS_MIN_FUNCTIONS = 25


def _routeless_warning(function_count: int, route_count: int, path: str) -> str | None:
    """Return a warning message for a substantial routeless repo, else None.

    Pure helper so the policy is unit-testable without building a repo.
    """
    if route_count == 0 and function_count >= _ROUTELESS_MIN_FUNCTIONS:
        return (
            f"open_repo({path!r}): {function_count} functions but 0 routes detected. "
            f"The path may point above the application package, or no installed "
            f"provider recognized its routing. Check the target path "
            f"(e.g. the inner package dir), or confirm the framework is supported."
        )
    return None


def open_repo(path: str, *, artifact_root: str | Path | None = None) -> RepoView:
    """Load an analyzed repository and return the top-level navigation object.

    Constructs a Code Index (Layer 1), runs the Semantic Layer
    interpreters (Layer 2), and returns a :class:`RepoView` -- the
    single entry point for all navigation and detection.

    Args:
        path: Path to the repository source tree to analyze.
        artifact_root: When given, load the Code Index from pre-generated
            committed L1 artifacts under ``artifact_root/normalized/`` instead
            of running Layer 1.  This skips *all* external tools (basedpyright)
            and is how tests and tooling consume committed
            fixtures.  ``path`` must still be the source tree the artifacts
            describe (their paths are relative to it).

    Returns:
        A :class:`RepoView` for querying the analyzed repository.

    Warns:
        RoutelessRepoWarning: if the repo has functions but zero detected
            routes (likely a wrong target path or unsupported framework).

    Note:
        Repeated calls for the same unchanged tree reuse an in-process cache
        (FLAW-132), so iterative exploration does not re-pay the L2 build.  The
        ``artifact_root`` path bypasses that memo (loading is already cheap).
    """
    if artifact_root is not None:
        view: RepoView = repo_view_from_artifacts(path, artifact_root)
    else:
        view = repo_view_from_path_cached(path)
    message = _routeless_warning(len(view.functions), len(view.routes), path)
    if message is not None:
        warnings.warn(message, RoutelessRepoWarning, stacklevel=2)
    return view


__all__ = [
    "Argument",
    "CallSite",
    "Check",
    "Effect",
    "FindingCollection",
    "Fn",
    "InputRead",
    "InputSource",
    "RepoView",
    "RoutelessRepoWarning",
    "Severity",
    "__version__",
    "detector",
    "load_findings",
    "open_repo",
]
