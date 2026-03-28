from flask import Blueprint, g, jsonify

bp = Blueprint("shared", __name__, url_prefix="/b")


def require_auth():
    return True


@bp.before_request
def mark_app_b_customer():
    g.customer_request = True


@bp.get("/users")
def users_b():
    require_auth()
    if g.get("admin_request"):
        return jsonify({"users": ["all-b"]})
    return jsonify({"users": []})
