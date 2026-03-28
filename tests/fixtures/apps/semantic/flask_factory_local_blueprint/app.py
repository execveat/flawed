"""Plain-function ``add_url_rule`` route on a FUNCTION-LOCAL blueprint.

The blueprint ``bp`` is constructed inside the factory ``create_app`` (not at
module scope), then a route is registered with ``bp.add_url_rule(...)``.  The
receiver ``bp`` must still resolve to ``flask.Blueprint`` so the route is
detected (FLAW-169).
"""

from flask import Blueprint, Flask


def list_items():
    return "items"


def create_app():
    bp = Blueprint("shop", __name__, url_prefix="/shop")
    bp.add_url_rule("/items", "list_items", list_items, methods=["GET"])
    app = Flask(__name__)
    app.register_blueprint(bp)
    return app
