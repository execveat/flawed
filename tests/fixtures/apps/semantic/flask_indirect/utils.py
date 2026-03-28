"""Second-hop indirection for flask_indirect fixture.

These functions call helpers.py functions, exercising Level 6
multi-hop resolution (app.py → utils.py → helpers.py).
"""

from . import helpers


def process_input(key):
    """Read input via helpers — two-hop cross-file chain."""
    return helpers.get_query_param(key)


def run_user_query(query_str):
    """Execute raw SQL via helpers — two-hop sink chain."""
    return helpers.execute_raw(query_str)


def save_user_session(username):
    """Write to session via helpers — two-hop effect chain."""
    helpers.save_to_session("username", username)
