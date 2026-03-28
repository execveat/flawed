"""Flask app: global ``CSRFProtect(app)`` with module-level CALL-form exemptions (FLAW-181).

The decorator form (``@csrf.exempt``) is captured on the view and surfaces via
``route.body.decorators()`` (FLAW-173).  The CALL form -- ``csrf.exempt(view)``
and ``csrf.exempt(blueprint)`` -- is a bare module statement with no enclosing
function, so the ordinary effect-conversion path drops it (no caller function).

The engine must instead resolve the named argument and re-attribute the
``CONFIG_WRITE`` exemption onto the targeted view's route (and every route under
the targeted blueprint), so effect-based CSRF consumers recognise it on the
route's ``full_stack`` -- symmetric with how a programmatic lifecycle-hook
exemption already appears there.
"""

from flask import Blueprint, Flask, jsonify, session
from flask_wtf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)  # global before_request CSRF guard reaches every route


@app.route("/covered", methods=["POST"])
def covered():
    """Globally covered, not exempt -> NO exemption effect on its full_stack."""
    session["last"] = "covered"
    return jsonify(ok=True)


@app.route("/exempt-call", methods=["POST"])
def exempt_call_view():
    """Exempted by the module-level CALL form below -> exemption on full_stack."""
    session["last"] = "exempt-call"
    return jsonify(ok=True)


# CALL-form view exemption at module scope (no enclosing function).
csrf.exempt(exempt_call_view)


bp = Blueprint("api", __name__)


@bp.route("/bp-write", methods=["POST"])
def bp_write():
    """Under a blueprint exempted by the CALL form -> exemption on full_stack."""
    session["last"] = "bp-write"
    return jsonify(ok=True)


app.register_blueprint(bp)

# CALL-form blueprint exemption: every route under ``bp`` is exempted.
csrf.exempt(bp)
