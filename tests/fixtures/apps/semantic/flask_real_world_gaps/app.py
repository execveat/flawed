"""Flask app exercising real-world patterns that expose engine gaps.

Derived from a manual audit of flawed running against a real Flask app (May 2025).
Each pattern here represents a documented false-positive root cause
from the v1.0 gap analysis.

Gap references:
  - DISC-047: MethodView ``decorators`` class attribute not extracted
  - DISC-048: Application-level CSRFProtect via init_app not in full_stack
  - DISC-049: Blueprint-level rate limiting not propagated to routes
  - DISC-050: ``url_for()`` redirect targets not classified as safe
  - DISC-051: Custom validation functions not modeled as checks
  - DISC-008: Flask ``LocalProxy`` request reads must remain traceable
  - P28: flask-allows authorization decorator not recognized
"""

from flask import Blueprint, Flask, jsonify, redirect, request, session, url_for
from flask.views import MethodView
from flask_allows import Allows
from flask_limiter import Limiter
from flask_login import login_required
from flask_wtf import CSRFProtect

app = Flask(__name__)

# -- flask-allows authorization (P28) --------------------------------------

allows = Allows(app)


class IsAdmin:
    """Requirement: user must be admin."""

    def fulfill(self, identity, request):
        return identity.is_admin


@app.route("/management")
@allows.requires(IsAdmin)
def management_panel():
    """Management route guarded by flask-allows authorization."""
    return jsonify(panel="management")


# -- Global CSRF protection (DISC-048) ------------------------------------

csrf = CSRFProtect()
csrf.init_app(app)

# -- Blueprint-level rate limiting (DISC-049) ------------------------------

limiter = Limiter(app)
auth = Blueprint("auth", __name__)


# -- MethodView with decorators class attribute (DISC-047) -----------------


class AdminDashboard(MethodView):
    """MethodView whose auth guard is on the class, not individual methods."""

    decorators = [login_required]

    def get(self):
        return jsonify(dashboard="data")

    def post(self):
        session["last_action"] = "updated_settings"
        return jsonify(ok=True)


app.add_url_rule(
    "/admin/dashboard",
    view_func=AdminDashboard.as_view("admin_dashboard"),
    methods=["GET", "POST"],
)


class EditProfile(MethodView):
    """MethodView with no decorators — should be flagged as missing auth."""

    def post(self):
        session["name"] = request.form["name"]
        return jsonify(ok=True)


app.add_url_rule(
    "/profile/edit",
    view_func=EditProfile.as_view("edit_profile"),
    methods=["POST"],
)


# -- Blueprint routes with blueprint-level rate limiting (DISC-049) --------


@auth.route("/login", methods=["POST"])
def login():
    """Login route — rate-limited via blueprint-level decorator below."""
    return jsonify(ok=True)


@auth.route("/register", methods=["POST"])
def register():
    """Register route — rate-limited via blueprint-level decorator below."""
    return jsonify(ok=True)


def is_safe_url(target, allowed_hosts):
    """Project-local redirect validator."""
    return target.startswith("/") or "example.test" in allowed_hosts


def redirect_url(endpoint, use_referrer=True):
    """A real-app-shaped helper returning only validated candidate redirects."""
    targets = [endpoint]
    allowed_hosts = ["example.test"]
    if use_referrer:
        targets.insert(0, request.referrer)
    for target in targets:
        if target and is_safe_url(target, allowed_hosts):
            return target
    return None


def redirect_or_next(endpoint, use_referrer=True):
    """A real-app-shaped helper: query ``next`` flows through LocalProxy to redirect."""
    return redirect(
        redirect_url(request.args.get("next"), use_referrer)
        or redirect_url(endpoint, use_referrer)
    )


@auth.route("/login-redirect", methods=["POST"])
def login_redirect():
    """Auth route whose redirect target flows through a real-app helper."""
    return redirect_or_next(url_for("admin_dashboard"), False)


# Apply rate limit to all routes in the auth blueprint.
limiter.limit("5/minute")(auth)
app.register_blueprint(auth, url_prefix="/auth")


# -- Redirect target classification (DISC-050) ----------------------------


@app.route("/redirect/safe")
def redirect_safe():
    """Redirect to url_for() — server-generated, NOT open redirect."""
    return redirect(url_for("admin_dashboard"))


@app.route("/redirect/unsafe")
def redirect_unsafe():
    """Redirect to user input — genuine open redirect risk."""
    target = request.args.get("next", "/")
    return redirect(target)


@app.route("/redirect/validated")
def redirect_validated():
    """Redirect to user input validated by is_safe_url (DISC-051)."""
    target = request.args.get("next", "/")
    if is_safe_url(target):
        return redirect(target)
    return redirect(url_for("admin_dashboard"))


# -- Custom validation function (DISC-051) ---------------------------------


def is_safe_url(url):
    """Validate redirect URL to prevent open redirect.

    This is the same pattern as Django's ``url_has_allowed_host_and_scheme``
    and a real app's ``is_safe_url``.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return parsed.scheme in ("", "http", "https") and parsed.netloc == ""
