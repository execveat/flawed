"""Flask Blueprint route patterns for L2-004b testing.

Covers: blueprint group names, url_prefix on constructor and registration,
prefix interaction, and dynamic/missing prefix edge cases.
"""

from flask import Blueprint, Flask, jsonify

app = Flask(__name__)

# Blueprint with url_prefix on constructor.
admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/dashboard")
def admin_dashboard():
    """Route: /admin/dashboard, group=admin."""
    return jsonify({"page": "dashboard"})


@admin_bp.route("/users", methods=["GET", "POST"])
def admin_users():
    """Route: /admin/users, group=admin, methods GET+POST."""
    return jsonify({"users": []})


# Blueprint with no url_prefix on constructor; applied at registration.
api_bp = Blueprint("api", __name__)


@api_bp.route("/items")
def api_items():
    """Route: /api/v1/items, group=api (prefix from registration)."""
    return jsonify({"items": []})


@api_bp.route("/items/<int:item_id>", methods=["GET", "DELETE"])
def api_item_detail(item_id):
    """Route: /api/v1/items/<int:item_id>, group=api."""
    return jsonify({"item_id": item_id})


# Blueprint with no prefix at all.
public_bp = Blueprint("public", __name__)


@public_bp.route("/about")
def about():
    """Route: /about, group=public, no prefix."""
    return jsonify({"page": "about"})


# Registration.
app.register_blueprint(admin_bp)
app.register_blueprint(api_bp, url_prefix="/api/v1")
app.register_blueprint(public_bp)
