from flask import Blueprint, g, jsonify

bp = Blueprint("shared", __name__, url_prefix="/a")


def require_auth():
    return True


@bp.before_request
def mark_app_a_admin():
    g.admin_request = True


@bp.get("/users")
def users_a():
    require_auth()
    if g.get("admin_request"):
        return jsonify({"users": ["all-a"]})
    return jsonify({"users": []})
