"""Child blueprint 'beta' with no hook of its own.

Used to assert non-leakage: the parent ``root_guard`` hook MUST reach beta
routes (beta is nested under the parent), while alpha's ``alpha_guard`` /
``read_alpha_secret`` MUST NOT.
"""

from flask import Blueprint

bp = Blueprint("beta", __name__, url_prefix="/beta")


@bp.get("/info")
def beta_info():
    return "beta"
