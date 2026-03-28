"""Factory-style: Blueprint constructed AND routes registered inside a factory.

Mirrors a factory ``load_blueprints(app)``: the Blueprint is a
function-local, routes are added via add_url_rule / a register_view wrapper
inside the function, and url_prefix is supplied at register_blueprint time.
The distinguishing trait vs flask_class_view_factory is that the Blueprint
itself is constructed INSIDE the function (not at module level).
"""

from flask import Blueprint, Flask

from .views import LoginView, LogoutView, ProfileView


def register_view(bp, routes, view_func):
    """Factory-style wrapper: the URL is inside a list arg."""
    for route in routes:
        bp.add_url_rule(route, view_func=view_func)


def load_blueprints(app):
    """A load_blueprints-style factory: blueprint is function-local."""
    auth = Blueprint("auth", __name__)

    auth.add_url_rule("/login", view_func=LoginView.as_view("login"))
    auth.add_url_rule("/logout", view_func=LogoutView.as_view("logout"))
    register_view(auth, routes=["/profile"], view_func=ProfileView.as_view("profile"))

    app.register_blueprint(auth, url_prefix="/auth")


def create_app():
    app = Flask(__name__)
    load_blueprints(app)
    return app


application = create_app()
