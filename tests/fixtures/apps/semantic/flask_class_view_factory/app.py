"""Flask app registering MethodViews inside a factory function.

Covers two factory-style patterns:
1. Direct add_url_rule inside a factory function (standard pattern).
2. A register_view() wrapper that receives the URL in a list arg
   (a factory-``register_view(bp, routes=["/path"], view_func=...)`` idiom).
"""

from flask import Blueprint, Flask

from .views import LoginView, LogoutView, ProfileView

app = Flask(__name__)
auth = Blueprint("auth", __name__)


def register_auth_views(application):
    """Register auth views via direct add_url_rule (pattern 1)."""
    application.add_url_rule(
        "/login",
        view_func=LoginView.as_view("login"),
        methods=["GET", "POST"],
    )
    application.add_url_rule(
        "/logout",
        view_func=LogoutView.as_view("logout"),
        methods=["POST"],
    )


def register_view(bp, routes, view_func):
    """A factory-style wrapper that forwards to add_url_rule.

    The call site passes ``routes=["/path"]`` — the URL is inside a
    list, not a bare string.  The conversion pipeline must extract it.
    """
    for route in routes:
        bp.add_url_rule(route, view_func=view_func)


def setup_profile_views():
    """Register profile views via register_view wrapper (pattern 2)."""
    register_view(auth, routes=["/profile"], view_func=ProfileView.as_view("profile"))


register_auth_views(app)
setup_profile_views()
