"""The single seam between flawed and the optional ``ribrarian`` library.

ribrarian is an *optional* dependency: flawed is fully functional without it.
The whole point of this module is to be the **only** place in the codebase that
names ``ribrarian`` — the engine, the CLI commands, and the dev tools reach repo
storage exclusively through here, so the optional dependency stays contained and
swappable. Importing ribrarian anywhere else is a layering defect.

``HAS_RIBRARIAN`` reflects whether ``import ribrarian`` succeeded. The CLI uses
it to decide whether the ``-r/--ribrarian`` selector flag exists at all.

Intentional optional integration — do not "clean up" the guarded import, the
``HAS_RIBRARIAN`` flag, or the ``-r`` wiring as dead code. Full rationale (why it is
absent from ``pyproject``/``uv.lock``, how it is injected at install time, and the
gate allowlist in ``tools/check_runtime_deps.py``).

Fail-loud, never fail-open (flawed priority #1 — no silent false negatives):

* Asking to resolve selectors when ribrarian is not installed raises rather than
  silently scanning nothing.
* A selector that matches *zero* repos-with-source raises naming the selector,
  rather than silently contributing no targets — a researcher who mistyped a
  selector must hear about it, not get an empty, falsely-clean run.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

try:  # pragma: no cover - import availability is environment-dependent
    # Intentional optional integration (see module docstring); not a pyproject dep.
    import ribrarian

    HAS_RIBRARIAN = True
except ImportError:  # pragma: no cover - exercised in the ribrarian-free env
    HAS_RIBRARIAN = False


class RibrarianBridgeError(Exception):
    """Raised when a ribrarian selector cannot be turned into repo paths.

    Covers both "ribrarian is not installed" and "the selector resolved to no
    usable repo". CLI commands surface the message and exit with a usage error.
    """


def resolve(selectors: Sequence[str]) -> list[Path]:
    """Resolve ribrarian *selectors* to a deduplicated list of repo-root paths.

    Each selector is resolved independently and the results are concatenated in
    selector order; duplicate roots (a repo matched by more than one selector)
    are collapsed, keeping first-seen order so the scan order is deterministic.

    Args:
        selectors: ribrarian selector strings (e.g. ``"class:target tier:1"``,
            ``"owner/name"``). An empty sequence resolves to ``[]``.

    Returns:
        Repo-root paths for every matched repo that has source on disk.

    Raises:
        RibrarianBridgeError: if ribrarian is not installed but selectors were
            given, or if any selector matches no repo with source on disk.
    """
    if not selectors:
        return []
    if not HAS_RIBRARIAN:
        msg = (
            "ribrarian selectors were given but ribrarian is not installed. "
            "ribrarian is an optional integration; install it alongside flawed to "
            "enable selector resolution (see your deployment docs)."
        )
        raise RibrarianBridgeError(msg)

    resolved: list[Path] = []
    seen: set[Path] = set()
    for selector in selectors:
        matches = ribrarian.resolve(selector)
        if not matches:
            msg = (
                f"ribrarian selector matched no repos with source on disk: {selector!r}. "
                "Refusing to scan nothing — check the selector or sync the repo source."
            )
            raise RibrarianBridgeError(msg)
        for match in matches:
            root = match.resolve()
            if root not in seen:
                seen.add(root)
                resolved.append(root)
    return resolved
