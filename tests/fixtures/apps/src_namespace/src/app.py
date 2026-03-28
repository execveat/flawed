"""Top-level module under a ``src/`` namespace directory (no ``src/__init__.py``).

Mirrors the common src-layout where subpackages carry ``__init__.py`` but the
``src`` directory itself does not, and the repository imports ``src.models``
directly.  Both this module and ``src/models/user.py`` must root consistently
under the ``src`` prefix for these imports to resolve.
"""

from src.models.user import User


def make_user() -> User:
    return User()


def is_admin_request() -> bool:
    user = make_user()
    return user.is_admin()
