"""Flask package-level Blueprint receiver fixture."""

from flask import Blueprint, Flask

app = Flask(__name__)
bp = Blueprint("package", __name__, url_prefix="/pkg")
app.register_blueprint(bp)

from . import routes  # noqa: E402, F401
from .auth import middleware  # noqa: E402, F401
