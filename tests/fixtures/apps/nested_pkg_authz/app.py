"""Application entry point that wires the nested ``pkg`` package into one repo.

This root module exists so the fixture is discovered as a SINGLE app rooted at
``nested_pkg_authz/``. The artifact builder roots an app at the top-most
directory holding a direct ``.py`` (``tools/build_fixture_artifacts._all_apps``);
without a root module, ``pkg/auth``, ``pkg/routes`` and ``pkg/services`` would
each be discovered as a separate single-package app, severing the cross-module
call/decorator edges this fixture exists to exercise.

It also anchors those edges realistically: ``create_app`` registers the
``pkg.routes.orders`` blueprint, so ``list_orders`` — guarded by the
cross-module ``require_auth`` — is a reachable Flask route.
"""

from flask import Flask

from pkg.routes.orders import bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.register_blueprint(bp)
    return app
