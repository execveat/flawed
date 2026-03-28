"""Plain function Flask routes registered imperatively."""

from flask import Flask

app = Flask(__name__)


def health():
    return "ok"


def create_user():
    return "created"


def user_detail(user_id):
    return f"user:{user_id}"


app.add_url_rule("/health", view_func=health)
app.add_url_rule("/users", "create_user_endpoint", create_user, methods=["POST"])
app.add_url_rule(
    "/users/<int:user_id>",
    endpoint="user_detail",
    view_func=user_detail,
    methods=("GET", "DELETE"),
)
