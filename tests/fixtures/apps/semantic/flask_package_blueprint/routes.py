"""Routes using a Blueprint imported from package __init__."""

from . import bp


@bp.route("/items", methods=["GET", "POST"])
def package_items():
    return "items"
