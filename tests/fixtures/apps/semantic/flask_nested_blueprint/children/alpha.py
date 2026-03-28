"""Child blueprint 'alpha' with its own group-scoped before_request hook.

``alpha_guard`` is declared directly on ``alpha.bp`` (same module).  It must
reach alpha's routes but MUST NOT leak onto sibling 'beta' routes.
"""

from flask import Blueprint, request

bp = Blueprint("alpha", __name__, url_prefix="/alpha")


def read_alpha_secret() -> str | None:
    """Transitive callee of alpha's own hook -- must NOT appear on beta."""
    return request.headers.get("X-Alpha-Secret")


@bp.before_request
def alpha_guard():
    """Group-scoped hook -- applies only to alpha routes."""
    if read_alpha_secret() is None:
        raise ValueError("alpha secret required")


@bp.get("/info")
def alpha_info():
    return "alpha"
