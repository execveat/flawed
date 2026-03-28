"""Custom astroid brain plugins for Layer 1 framework-aware inference.

Importing this package imports every bundled brain module; each module then
registers itself with astroid's global manager.  The brains live in Layer 1
because they enrich astroid's structural inference; semantic interpretation
remains in ``flawed._semantic``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from astroid import MANAGER

from flawed._index._brains import (
    brain_flask,
    brain_flask_login,
    brain_flask_restful,
    brain_flask_restx,
    brain_sqlalchemy,
    brain_wtforms,
)

if TYPE_CHECKING:
    from astroid.manager import AstroidManager

__all__ = ["register"]

_REGISTERED_MANAGER_IDS: set[int] = {id(MANAGER)}


def register(manager: AstroidManager = MANAGER) -> None:
    """Register every custom brain plugin with *manager*."""
    manager_id = id(manager)
    if manager_id in _REGISTERED_MANAGER_IDS:
        return

    brain_flask.register(manager)
    brain_sqlalchemy.register(manager)
    brain_flask_login.register(manager)
    brain_wtforms.register(manager)
    brain_flask_restful.register(manager)
    brain_flask_restx.register(manager)
    _REGISTERED_MANAGER_IDS.add(manager_id)
