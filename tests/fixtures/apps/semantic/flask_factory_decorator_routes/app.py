"""App-factory with ``@app.route`` view functions defined INSIDE ``create_app()``.

Regression guard for FLAW-280. Routes nested in a factory function must each
locate on their OWN ``@app.route`` decorator line — they must NOT collapse onto a
single shared line. Historically every nested route anchored onto the
``@login_manager.unauthorized_handler`` decorator immediately preceding them
(reproduced on a real Flask app ``flask_app.py:614``: 15 distinct route
findings all mis-located to line 614, destroying navigability).

The collapse was a *route location-attribution* defect, not the L1
function-location bug the original ticket hypothesised — L1 always recorded each
nested ``def``/decorator on its correct line. FLAW-301's AST-only ``_index``
rewrite fixed the downstream attribution; this fixture pins the property so it
cannot silently regress.

Structure deliberately mirrors a real Flask app: an ``unauthorized_handler``
decorated function sits just before a run of decorator routes inside the factory.
"""

from flask import Flask, request
from flask_login import LoginManager

login_manager = LoginManager()


def create_app() -> Flask:
    app = Flask(__name__)

    @login_manager.unauthorized_handler
    def unauthorized_handler() -> tuple[str, int]:
        return "unauthorized", 401

    @app.route("/logout")
    def logout() -> str:
        return "bye"

    @app.route("/set-language/<locale>")
    def set_language(locale: str) -> str:
        return locale

    @app.route("/login", methods=["GET", "POST"])
    def login() -> str:
        return request.form.get("user", "")

    @app.route("/queue-status", methods=["GET"])
    def queue_status() -> str:
        return "ok"

    return app


application = create_app()
