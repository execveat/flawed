"""Flask app: direct patterns -- routes, inputs, effects, checks, lifecycle.

Every pattern here uses the most common, direct form.  No aliasing,
no indirection, no subclassing.  Level 0 complexity.

The Semantic API should detect all patterns here using straightforward
FQN matching against provider declarations.
"""

import hashlib
import os
import subprocess
import unicodedata

import jwt

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from flask_cors import CORS
from flask_login import current_user, login_required, login_user, logout_user
from flask_restful import reqparse
from flask_wtf import CSRFProtect
from markupsafe import Markup
from redis import Redis
from sqlalchemy import text
from sqlalchemy.orm import Session as SaSession
from werkzeug.datastructures.file_storage import FileStorage
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
csrf = CSRFProtect()
cache = Redis()
FEATURE_FLAGS = {"enabled": False}
UPLOAD_DIR = "/var/uploads"


def require_roles(roles):
    """Project-specific role decorator used by L0 gadget inventory tests."""

    def decorator(fn):
        return fn

    return decorator


# -- EP-1: Route registration (RouteDecorator) --------------------------


@app.route("/")
def index():
    """GET-only route (default methods)."""
    return "hello"


@app.route("/users", methods=["GET", "POST"])
def users():
    """Multi-method route."""
    if request.method == "POST":
        return create_user()
    return list_users()


@app.get("/items")
def items_get():
    """Shorthand GET decorator."""
    return jsonify([])


@app.post("/items")
def items_post():
    """Shorthand POST decorator."""
    return jsonify({"created": True})


# -- EP-2: Input sources (InputAttributePattern, InputMethodPattern) -----


@app.route("/inputs/query")
def input_query():
    """request.args access → Query input source."""
    user_id = request.args.get("user_id")
    return jsonify({"user_id": user_id})


@app.route("/inputs/form", methods=["POST"])
def input_form():
    """request.form access → Form input source."""
    name = request.form["name"]
    email = request.form.get("email")
    return jsonify({"name": name, "email": email})


@app.route("/inputs/json", methods=["POST"])
def input_json_attr():
    """request.json attribute access → Json input source."""
    data = request.json
    return jsonify(data)


@app.route("/inputs/json_method", methods=["POST"])
def input_json_method():
    """request.get_json() method call → Json input source."""
    data = request.get_json()
    return jsonify(data)


@app.route("/inputs/headers")
def input_headers():
    """request.headers access → Header input source."""
    auth = request.headers.get("Authorization")
    return jsonify({"auth": auth})


@app.route("/inputs/cookies")
def input_cookies():
    """request.cookies access → Cookie input source."""
    token = request.cookies.get("session_token")
    return jsonify({"token": token})


@app.route("/inputs/path/<int:item_id>")
def input_path(item_id):
    """Path parameter → PathParam input source (via view_args)."""
    return jsonify({"item_id": item_id})


@app.route("/inputs/files", methods=["POST"])
def input_files():
    """request.files access → FileUpload input source."""
    f = request.files["document"]
    return jsonify({"filename": f.filename})


@app.route("/gadgets/file_upload_path_traversal", methods=["POST"])
def gadget_file_upload_path_traversal():
    """Uploaded filename is used to construct a save destination."""
    f: FileStorage = request.files["avatar"]
    path = os.path.join(UPLOAD_DIR, f.filename)
    f.save(path)
    return jsonify({"saved": True})


@app.route("/inputs/raw", methods=["POST"])
def input_raw():
    """request.data access → RawBody input source."""
    raw = request.data
    return jsonify({"length": len(raw)})


# -- L0 gadget rule smoke fixtures ---------------------------------------


@app.route("/gadgets/multi_container", methods=["GET", "POST"])
def gadget_multi_container_read():
    """Same key read from query and form containers."""
    query_user_id = request.args.get("user_id")
    form_user_id = request.form.get("user_id")
    return jsonify({"query": query_user_id, "form": form_user_id})


@app.route("/gadgets/getlist")
def gadget_getlist_usage():
    """request.args.getlist() → multi-value Query input read."""
    tags = request.args.getlist("tag")
    return jsonify({"tags": tags})


@app.route("/gadgets/session_rebind", methods=["POST"])
def gadget_session_read_and_write():
    """Read and overwrite the same session key."""
    previous_user_id = session["user_id"]
    session["user_id"] = request.form["user_id"]
    return jsonify({"previous_user_id": previous_user_id})


@app.route("/gadgets/merged_container", methods=["GET", "POST"])
def gadget_merged_container():
    """request.values plus a single container creates merge precedence ambiguity."""
    merged_user_id = request.values.get("user_id")
    form_user_id = request.form.get("user_id")
    return jsonify({"merged": merged_user_id, "form": form_user_id})


@app.route("/gadgets/bulk_container", methods=["POST"])
def gadget_bulk_container_access():
    """Bulk request container extraction exposes all attacker-controlled keys."""
    payload = request.form.to_dict()
    return jsonify(payload)


def gadget_read_parameter(name):
    """Helper that implicitly merges query, JSON, and form request containers."""
    return request.args.get(name) or request.json.get(name) or request.form.get(name)


@app.route("/gadgets/custom_accessor", methods=["POST"])
def gadget_custom_accessor():
    """Route that calls a helper with multi-container input precedence."""
    value = gadget_read_parameter("user_id")
    return jsonify({"value": value})


@app.route("/gadgets/json_root_parse", methods=["POST"])
def gadget_json_root_parse():
    """request.get_json() with force/silent options creates parser ambiguity."""
    payload = request.get_json(force=True, silent=True)
    return jsonify(payload)


class UserSchema:
    """Minimal schema-shaped class for static schema-load call detection."""

    @staticmethod
    def load(data):
        return data


@app.route("/gadgets/schema_load", methods=["POST"])
def gadget_schema_load_from_request():
    """Schema loading directly from request data."""
    payload = request.get_json()
    user = UserSchema.load(payload)
    return jsonify(user)


@app.route("/gadgets/reqparse", methods=["POST"])
def gadget_reqparse_multi_location():
    """RequestParser argument declared across multiple request locations."""
    parser = reqparse.RequestParser()
    parser.add_argument("user_id", location=["json", "values"])
    return jsonify(parser.parse_args())


@app.route("/gadgets/method_guarded_auth", methods=["GET", "POST"])
def gadget_method_guarded_auth():
    """Auth guard appears only in one method branch; mutation appears in the other."""
    if request.method == "POST":
        if "X-Token" not in request.headers:
            abort(401)
        return jsonify({"ok": True})
    session["preview_user_id"] = request.args.get("user_id")
    return jsonify({"preview": True})


@app.route("/gadgets/header_presence")
def gadget_presence_not_validity():
    """Presence-only API key check without a value verification call."""
    if "X-Api-Key" in request.headers:
        return jsonify({"trusted": True})
    return jsonify({"trusted": False}), 401


class GadgetAuthenticator:
    """Authenticator whose constructor writes state before verification."""

    def __init__(self):
        g.authenticated_user = session["user_id"]

    def authenticate(self):
        return False


@app.route("/gadgets/auth_constructor")
def gadget_auth_constructor_writes():
    """Instantiate an authenticator with constructor side effects."""
    auth = GadgetAuthenticator()
    return jsonify({"ok": auth.authenticate()})


class PropertyBackedAuthBase:
    """Authenticator base whose property setters write Flask request state."""

    @property
    def email(self):
        return getattr(g, "email", None)

    @email.setter
    def email(self, value):
        g.email = value
        self.user = {"name": "Sandy", "balance": 42}

    @property
    def user(self):
        return getattr(g, "user", None)

    @user.setter
    def user(self, value):
        g.user = value
        g.name = value and value["name"]
        g.balance = value and value["balance"]


class PropertyBackedSessionAuth(PropertyBackedAuthBase):
    def __init__(self):
        if "email" in session:
            self.email = session["email"]

    def authenticate(self):
        return False


class PropertyBackedCredentialAuth(PropertyBackedAuthBase):
    def __init__(self, email=None, password=None):
        if email and password:
            self.email = email
            self.password = password

    def authenticate(self):
        return bool(self.email and getattr(self, "password", None))

    @classmethod
    def from_basic_auth(cls):
        auth = request.authorization
        if not auth:
            return cls(None, None)
        return cls(auth.username, auth.password)


class BenignProfileBuilder:
    """Constructor mutates only instance state; it is not an auth pollutant."""

    def __init__(self):
        self.email = session.get("email")


@app.route("/gadgets/auth_constructor_property")
def gadget_auth_constructor_property_writes():
    """Multi-auth flow whose constructors invoke property setter side effects."""
    authenticators = [PropertyBackedSessionAuth(), PropertyBackedCredentialAuth.from_basic_auth()]
    if any(auth.authenticate() for auth in authenticators):
        return jsonify({"email": g.email, "name": g.name})
    return jsonify({"ok": False})


@app.route("/gadgets/benign_constructor_only")
def gadget_benign_constructor_only():
    profile = BenignProfileBuilder()
    return jsonify({"email": profile.email})


@app.route("/gadgets/multi_role")
@require_roles(["customer", "restaurant_api_key"])
def gadget_multi_role_decorator():
    """Decorator accepts multiple role types with disjunctive semantics."""
    return jsonify({"user": current_user.id})


# -- L4 ultra-specific positive fixtures --------------------------------


class Order:
    """Name-only model stand-in for static ORM call shapes."""


class BaseAuth:
    def __init__(self):
        g.email = session["email"]


class CustomerAuth(BaseAuth):
    def __init__(self):
        g.email = session["email"]

    def authenticate(self):
        return False


class ApiKeyAuth(BaseAuth):
    def __init__(self):
        g.email = session["email"]

    def authenticate(self):
        return True


def require_order_access(fn):
    order_id = request.view_args.get("order_id")

    def wrapper(*args, **kwargs):
        if order_id is None:
            return fn(*args, **kwargs)
        return fn(*args, **kwargs)

    return wrapper


class MethodDispatcher:
    def dispatch(self):
        handler = getattr(self, request.method.lower())
        return handler()

    def get(self):
        return jsonify({"method": "get"})

    def post(self):
        abort(403)


def delivery_fee_from_values():
    item = request.values.get("item")
    return item


class OrderSchema:
    @staticmethod
    def load(data):
        return data


@app.route("/scenarios/multi-auth-pollution")
def multi_auth_pollution():
    customer_auth = CustomerAuth()
    api_key_auth = ApiKeyAuth()
    if customer_auth.authenticate() or api_key_auth.authenticate():
        return jsonify({"email": g.email})
    abort(401)


@app.route("/scenarios/values-form-split", methods=["POST"])
def values_form_split():
    selected_item = request.form.get("item")
    fee_item = delivery_fee_from_values()
    return jsonify({"selected": selected_item, "fee_item": fee_item})


@app.route("/scenarios/dict-merge-server-override", methods=["POST"])
def dict_merge_server_override():
    db_session = g.db_session  # type: SaSession
    user_data = request.get_json()
    server_data = {"user_id": g.user_id, "total": "42.00"}
    order = OrderSchema.load({**server_data, **user_data})
    db_session.add(order)
    db_session.commit()
    return jsonify({"created": True})


@app.route("/scenarios/missing-order-param")
@require_order_access
def missing_order_param():
    return jsonify({"orders": []})


@app.route("/scenarios/raw-vs-nfkc-email", methods=["POST"])
def raw_vs_nfkc_email():
    email = request.form.get("email")
    normalized = unicodedata.normalize("NFKC", email)
    raw_domain = email.split("@")[-1]
    return jsonify({"normalized": normalized, "raw_domain": raw_domain})


@app.route("/scenarios/getattr-dispatch-bypass", methods=["GET", "POST", "OPTIONS"])
def getattr_dispatch_bypass():
    dispatcher = MethodDispatcher()
    handler = getattr(dispatcher, request.method.lower())
    return handler()


@app.route("/scenarios/multi-role-g-read")
@require_roles(["customer", "restaurant_api_key"])
def multi_role_g_read():
    return jsonify({"restaurant_id": g.restaurant_id})


@app.route("/scenarios/orm-update-where-only-auth", methods=["POST"])
def orm_update_where_only_auth():
    db_session = g.db_session  # type: SaSession
    order_id = request.form.get("order_id")
    order = db_session.execute(text("SELECT * FROM orders WHERE id=:id"), {"id": order_id})
    db_session.execute(
        text("UPDATE orders SET status='refunded' WHERE id=:id AND user_id=:user_id"),
        {"id": order_id, "user_id": g.user_id},
    )
    db_session.commit()
    return jsonify({"order": str(order)})


@app.route("/scenarios/redis-eval-injection", methods=["POST"])
def redis_eval_injection():
    script = request.form.get("script")
    result = cache.eval(script, 0)
    return jsonify({"result": result})


@app.route("/scenarios/cors-wildcard-credentials")
def cors_wildcard_credentials():
    CORS(app, origins="*", supports_credentials=True)
    return jsonify({"cors": "wide-open"})


@app.route("/scenarios/jwt-none-algorithm")
def jwt_none_algorithm():
    token = request.headers.get("Authorization")
    claims = jwt.decode(token, "secret", algorithms=["none", "HS256"])
    return jsonify(claims)


@app.route("/scenarios/weak-password-hash", methods=["POST"])
def weak_password_hash():
    password = request.form.get("password")
    digest = hashlib.sha256(password.encode()).hexdigest()
    weak_hash = generate_password_hash(password, method="sha1")
    return jsonify({"digest": digest, "hash": weak_hash})


@app.route("/gadgets/auth_in_where_only", methods=["POST"])
def gadget_auth_in_where_only():
    """Read then write through the database without an explicit auth guard."""
    db_session = g.db_session  # type: SaSession
    order_id = request.form["order_id"]
    current = db_session.execute(text("SELECT * FROM orders WHERE id=:id"), {"id": order_id})
    db_session.execute(text("UPDATE orders SET status='refunded' WHERE id=:id"), {"id": order_id})
    db_session.commit()
    return jsonify(list(current))


@app.route("/gadgets/get_vs_getlist")
def gadget_get_vs_getlist():
    """Same key read as both singular and plural cardinality."""
    first_item = request.args.get("item_id")
    all_items = request.args.getlist("item_id")
    return jsonify({"first": first_item, "all": all_items})


@app.route("/gadgets/limit_one_then_loop", methods=["POST"])
def gadget_limit_one_then_loop():
    """Single-row validation query followed by multi-item processing."""
    db_session = g.db_session  # type: SaSession
    item_ids = request.form.getlist("item_id")
    db_session.query(Order).filter_by(id=item_ids[0]).first()
    for item_id in item_ids:
        db_session.execute(text("UPDATE orders SET processed=1 WHERE id=:id"), {"id": item_id})
    db_session.commit()
    return jsonify({"processed": len(item_ids)})


@app.route("/gadgets/set_then_iterate", methods=["POST"])
def gadget_set_then_iterate():
    """Deduplicate for validation while still processing the original list."""
    db_session = g.db_session  # type: SaSession
    item_ids = request.form.getlist("item_id")
    unique_item_ids = set(item_ids)
    for item_id in item_ids:
        db_session.execute(text("INSERT INTO audit_log (item_id) VALUES (:id)"), {"id": item_id})
    db_session.commit()
    return jsonify({"unique": len(unique_item_ids), "processed": len(item_ids)})


@app.route("/gadgets/zero_negative_quantity", methods=["POST"])
def gadget_zero_negative_quantity():
    """Quantity input participates in an order write."""
    db_session = g.db_session  # type: SaSession
    quantity = request.form.get("quantity")
    db_session.execute(
        text("INSERT INTO orders (quantity) VALUES (:quantity)"), {"quantity": quantity}
    )
    db_session.commit()
    return jsonify({"quantity": quantity})


@app.route("/gadgets/different_transforms")
def gadget_different_transforms():
    """Same input goes through different normalization transforms."""
    email = request.args.get("email", "")
    lower_email = email.lower()
    stripped_email = email.strip()
    return jsonify({"lower": lower_email, "stripped": stripped_email})


@app.route("/gadgets/unicode_normalization")
def gadget_unicode_normalization():
    """Explicit Unicode normalization in a route."""
    email = request.args.get("email", "")
    normalized = unicodedata.normalize("NFKC", email)
    return jsonify({"email": normalized})


@app.route("/gadgets/global_state_mutation")
def gadget_global_state_mutation():
    """Module-level mutation persists beyond a single request."""
    FEATURE_FLAGS["enabled"] = request.args.get("enabled") == "1"
    return jsonify(FEATURE_FLAGS)


@app.route("/gadgets/csrf_exempt")
def gadget_csrf_exempt():
    """Programmatic CSRF exemption from inside a handler."""
    csrf.exempt(gadget_csrf_exempt)
    return jsonify({"ok": True})


@app.route("/gadgets/csrf_exempt_view_func")
def gadget_csrf_exempt_view_func():
    """Programmatic CSRF exemption using an intermediate view_func alias."""
    view_func = gadget_csrf_exempt_view_func
    csrf.exempt(view_func)
    return jsonify({"ok": True})


@app.route("/gadgets/config_write")
def gadget_config_write_in_route():
    """Runtime config mutation from inside a handler."""
    app.config["GADGET_FLAG"] = request.args.get("enabled")
    return jsonify({"ok": True})


@app.route("/gadgets/cookie_from_input")
def gadget_cookie_from_input():
    """Set a cookie in a route that also reads user input."""
    token = request.args.get("token", "")
    resp = jsonify({"ok": True})
    resp.set_cookie("tracking", token)
    return resp


def set_g_user_backup():
    """Helper that writes g.user for backup identity tracking."""
    g.user = {"id": 0, "name": "anonymous"}


@app.route("/gadgets/g_pollution")
def gadget_g_pollution():
    """Two distinct functions write g.user in this route's stack."""
    set_g_user_backup()
    g.user = {"id": 1, "name": "admin"}
    return jsonify(g.user)


@app.route("/gadgets/redirect_from_header")
def gadget_redirect_from_header():
    """Redirect target read from an unvalidated request header."""
    next_url = request.headers.get("Referer", "/")
    return redirect(next_url)


@app.route("/gadgets/error_disclosure", methods=["POST"])
def gadget_error_disclosure():
    """Exception message leaked to client via JSON response."""
    try:
        data = request.get_json()
        result = process_data(data)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -- EP-3: Effects (EffectCallPattern, EffectAttributePattern, etc.) -----


@app.route("/effects/db_write", methods=["POST"])
def effect_db_write():
    """db.session.commit() → DB_WRITE effect."""
    db_session = g.db_session  # type: SaSession
    db_session.commit()
    return jsonify({"ok": True})


@app.route("/effects/state_write")
def effect_state_write_attr():
    """g.user = value → STATE_WRITE effect (REQUEST scope, attribute)."""
    g.user = {"id": 1, "name": "admin"}
    return jsonify(g.user)


@app.route("/effects/state_write_aliased")
def effect_state_write_aliased():
    """local_g = g; local_g.user = value → STATE_WRITE via alias."""
    local_g = g
    local_g.user = {"id": 2, "name": "aliased"}
    return jsonify(local_g.user)


@app.route("/effects/session_write")
def effect_session_write():
    """session["key"] = value → STATE_WRITE effect (SESSION scope, subscript)."""
    session["user_id"] = 42
    session["role"] = "admin"
    return jsonify({"ok": True})


@app.route("/effects/session_read")
def effect_session_read():
    """session["key"] → STATE_READ effect (SESSION scope, subscript)."""
    user_id = session["user_id"]
    return jsonify({"user_id": user_id})


@app.route("/effects/session_read_aliased")
def effect_session_read_aliased():
    """local_sess = session; local_sess["user_id"] → STATE_READ via alias."""
    local_sess = session
    user_id = local_sess["user_id"]
    return jsonify({"user_id": user_id})


@app.route("/effects/response_write")
def effect_response_write():
    """redirect() → RESPONSE_WRITE effect."""
    return redirect(url_for("index"))


@app.route("/effects/response_cookie")
def effect_response_cookie():
    """response.set_cookie() → RESPONSE_WRITE effect."""
    resp = jsonify({"ok": True})
    resp.set_cookie("token", "abc123")
    return resp


@app.route("/effects/flash")
def effect_flash():
    """flash() → RESPONSE_WRITE effect."""
    flash("Message sent!")
    return redirect(url_for("index"))


@app.route("/effects/config_write")
def effect_config_write():
    """Modifying app.config → CONFIG_WRITE effect."""
    app.config["DEBUG"] = True
    return jsonify({"ok": True})


# -- EP-4: Security checks (SecurityCheckPattern) -----------------------


def require_admin(fn):
    """Project-specific auth decorator used by L0 gadget smoke tests."""
    return fn


@app.route("/checks/protected")
@login_required
def check_auth_decorator():
    """@login_required decorator → AUTHENTICATION check."""
    return jsonify({"user": current_user.id})


@app.route("/gadgets/multi_auth")
@login_required
@require_admin
def gadget_multi_auth_decorator():
    """Stacked auth decorators for composition smoke coverage."""
    return jsonify({"user": current_user.id})


@app.route("/checks/password", methods=["POST"])
def check_password():
    """check_password_hash() call → PASSWORD_VERIFY check."""
    pw = request.form["password"]
    stored_hash = "pbkdf2:sha256:..."
    if check_password_hash(stored_hash, pw):
        return jsonify({"ok": True})
    return jsonify({"ok": False}), 401


@app.route("/checks/hash", methods=["POST"])
def check_hash():
    """generate_password_hash() call → PASSWORD_HASH check."""
    pw = request.form["password"]
    hashed = generate_password_hash(pw)
    return jsonify({"hash": hashed})


# -- EP-6: Lifecycle hooks (LifecycleDecoratorPattern) -------------------


@app.before_request
def lifecycle_before():
    """@app.before_request → BEFORE_REQUEST lifecycle hook."""
    g.request_start = True


@app.after_request
def lifecycle_after(response):
    """@app.after_request → AFTER_REQUEST lifecycle hook."""
    response.headers["X-Custom"] = "1"
    return response


@app.teardown_request
def lifecycle_teardown(exc):
    """@app.teardown_request → TEARDOWN_REQUEST lifecycle hook."""
    pass


@app.errorhandler(404)
def lifecycle_error(e):
    """@app.errorhandler → ERROR_HANDLER lifecycle hook."""
    return jsonify({"error": "not found"}), 404


# -- EP-8: Flow propagation + EP-8b: Taint sinks -----------------------


@app.route("/sinks/sqli", methods=["POST"])
def sink_sql_injection():
    """text(user_input) → SQL_INJECTION taint sink."""
    db_session = g.db_session  # type: SaSession
    query = request.form["query"]
    # taint flow: user input reaches text()
    result = db_session.execute(text(query))
    return jsonify(list(result))


@app.route("/sinks/sqli_safe")
def sink_sql_safe():
    """text("literal") → should NOT fire (literal string)."""
    db_session = g.db_session  # type: SaSession
    result = db_session.execute(text("SELECT 1"))
    return jsonify(list(result))


@app.route("/sinks/ssti", methods=["POST"])
def sink_ssti():
    """render_template_string(user_input) → SSTI taint sink."""
    template = request.form["template"]
    return render_template_string(template)


@app.route("/sinks/xss")
def sink_xss():
    """Markup(user_input) → XSS taint sink."""
    name = request.args.get("name", "")
    safe = Markup(name)  # Bypasses autoescaping
    return f"<h1>{safe}</h1>"


@app.route("/sinks/redirect")
def sink_open_redirect():
    """redirect(user_input) → OPEN_REDIRECT taint sink."""
    url = request.args.get("next", "/")
    return redirect(url)


def is_safe_url(target):
    """Project-local redirect validator recognized by the Flask provider."""
    return target.startswith("/")


@app.route("/sinks/redirect_validated")
def sink_open_redirect_validated():
    """Validated redirect target guarded by is_safe_url()."""
    url = request.args.get("next", "/")
    if is_safe_url(url):
        return redirect(url)
    return redirect(url_for("index"))


@app.route("/sinks/redirect_validated_branch", methods=["GET", "POST"])
def sink_open_redirect_validated_branch():
    """Validated target inherited by method-specific branch scopes."""
    url = request.args.get("next", "/")
    if is_safe_url(url):
        if request.method == "POST":
            return redirect(url)
        return jsonify({"safe": True})
    return redirect(url_for("index"))


@app.route("/sinks/os-system")
def sink_os_system():
    """os.system(user_input) → COMMAND_INJECTION taint sink."""
    command = request.args.get("cmd", "")
    os.system(command)
    return jsonify({"ok": True})


@app.route("/sinks/subprocess-run")
def sink_subprocess_run():
    """subprocess.run(user_input) → COMMAND_INJECTION taint sink."""
    command = request.args.get("cmd", "")
    subprocess.run(command, shell=True, check=False)
    return jsonify({"ok": True})


@app.route("/sinks/eval")
def sink_eval():
    """eval(user_input) → CODE_INJECTION taint sink."""
    code = request.args.get("code", "")
    result = eval(code)
    return jsonify({"result": result})


@app.route("/sinks/exec")
def sink_exec():
    """exec(user_input) → CODE_INJECTION taint sink."""
    code = request.args.get("code", "")
    namespace = {}
    exec(code, namespace)
    return jsonify({"keys": sorted(namespace)})


# -- EP-10: State proxies (StateProxyPattern) ----------------------------


@app.route("/proxy/current_user")
@login_required
def proxy_current_user():
    """current_user → StateProxy resolving to g._login_user."""
    return jsonify({"name": current_user.name})


# -- Login / Logout (effects + checks combined) -------------------------


@app.route("/login", methods=["POST"])
def do_login():
    """login_user() → STATE_WRITE effect (SESSION scope)."""
    login_user(current_user)
    return redirect(url_for("index"))


@app.route("/logout")
def do_logout():
    """logout_user() → STATE_WRITE effect (SESSION scope)."""
    logout_user()
    return redirect(url_for("index"))


# -- Helpers used by tests for cross-function scenarios ------------------


def list_users():
    """Helper: reads from DB (called from users() route)."""
    db_session = g.db_session  # type: SaSession
    return jsonify(db_session.execute(text("SELECT * FROM users")).fetchall())


def create_user():
    """Helper: writes to DB (called from users() route)."""
    name = request.form["name"]
    db_session = g.db_session  # type: SaSession
    db_session.execute(text("INSERT INTO users (name) VALUES (:n)"), {"n": name})
    db_session.commit()
    return jsonify({"created": True}), 201


def process_data(data):
    """Helper: process arbitrary data (may raise)."""
    if not data:
        raise ValueError("No data provided")
    return {"processed": True}


def helper_form_cardinality(data):
    """Helper that reads a passed request container with mixed cardinality."""
    single_item = data.get("item")
    multiple_items = data.getlist("items")
    return single_item, multiple_items


def helper_form_action_items(data):
    """Second helper that consumes the plural lane as an action path."""
    return data.getlist("items")


@app.route("/gadgets/helper_form_cardinality", methods=["POST"])
def gadget_helper_form_cardinality():
    """Pass request.form into helpers that perform keyed reads."""
    single_item, multiple_items = helper_form_cardinality(request.form)
    action_items = helper_form_action_items(request.form)
    return jsonify({"single": single_item, "multiple": multiple_items, "action": action_items})


# -- FLAW-087: phase/source precondition mismatch fixtures ---------------


def get_phase_request_parameter(parameter):
    """Helper whose key is supplied by lifecycle/handler call sites."""
    from_args = request.args.get(parameter)
    from_json = request.is_json and isinstance(request.json, dict) and request.json.get(parameter)
    from_form = request.form.get(parameter)
    return from_args or from_json or from_form


@app.before_request
def lifecycle_validate_phase_amount():
    """Lifecycle validation through a literal helper argument."""
    if request.path != "/gadgets/middleware_handler_split":
        return None
    amount = get_phase_request_parameter("amount")
    if amount is not None and int(amount) < 0:
        return jsonify({"error": "amount cannot be negative"}), 400
    return None


@app.route("/gadgets/middleware_handler_split", methods=["POST"])
def gadget_middleware_handler_split():
    """Handler consumes a conditional body container after lifecycle validation."""
    payload = request.json if request.is_json else request.form
    amount = payload.get("amount", "0")
    return jsonify({"amount": amount})


def verify_registration_token(token):
    return bool(token)


def email_from_token(token):
    return "token@example.test" if token else None


def register_account(email, password):
    return jsonify({"email": email, "password": bool(password)})


@app.route("/gadgets/token_body_identity_split", methods=["POST"])
def gadget_token_body_identity_split():
    """Body identity takes precedence over a verified token-derived identity."""
    payload = request.json
    token = payload.get("token")
    email = payload.get("email") or email_from_token(token)
    password = payload.get("password")
    if not verify_registration_token(token):
        return jsonify({"error": "invalid token"}), 400
    return register_account(email, password)


# -- FLAW-089: method/auth validity fixtures -----------------------------


def credit_balance(user, amount):
    session["credited_user"] = user
    session["credited_amount"] = amount


def validate_admin_key():
    return request.headers.get("X-Admin-Key") == "secret"


def role_present(role):
    if role == "admin":
        return "X-Admin-Key" in request.headers
    return False


@app.route("/gadgets/method_guarded_shared_mutation", methods=["GET", "POST"])
def gadget_method_guarded_shared_mutation():
    """Method-conditioned auth followed by body-selected mutation."""
    if request.method == "GET" and not session.get("user_id"):
        abort(401)
    if request.method == "POST" and not validate_admin_key():
        abort(401)
    if "amount" in request.form and "user" in request.form:
        credit_balance(request.form["user"], request.form["amount"])
    return jsonify({"ok": True})


@app.route("/gadgets/helper_presence_role", methods=["PATCH"])
def gadget_helper_presence_role():
    """Validated auth exists, but role helper accepts header presence only."""
    validate_admin_key()
    if not role_present("admin"):
        abort(401)
    credit_balance("sandy", request.form.get("amount", "0"))
    return jsonify({"ok": True})


# -- FLAW-090: stale identity/session rebind fixtures --------------------


def mark_admin_request_before_validation():
    if request.headers.get("X-Admin-Key"):
        g.admin_request = True
    return validate_admin_key()


def mark_admin_request_after_validation():
    if not validate_admin_key():
        return False
    g.admin_request = True
    return True


def authenticate_current_session():
    if not session.get("email"):
        return False
    g.email = session["email"]
    return True


def bind_email_from_token_without_clear():
    token = request.headers.get("X-Email-Token")
    if token == "valid":
        g.email = "verified@example.com"
        g.email_confirmed = True
    else:
        g.email_confirmed = False


def bind_email_from_token_with_clear():
    token = request.headers.get("X-Email-Token")
    if token == "valid":
        g.email = "verified@example.com"
        g.email_confirmed = True
    else:
        g.email = None
        g.email_confirmed = False


def bind_email_from_session():
    if session.get("email"):
        g.email = session["email"]


@app.route("/gadgets/stale_email_multi_writer", methods=["GET"])
def gadget_stale_email_multi_writer():
    """Token-bound email is not cleared before fallback session identity."""
    bind_email_from_token_without_clear()
    bind_email_from_session()
    return jsonify({"email": g.email})


@app.route("/gadgets/safe_email_multi_writer_clear", methods=["GET"])
def gadget_safe_email_multi_writer_clear():
    """Failed token binding clears email before fallback session identity."""
    bind_email_from_token_with_clear()
    bind_email_from_session()
    return jsonify({"email": g.email})


@app.route("/gadgets/stale_identity_flag", methods=["GET"])
def gadget_stale_identity_flag():
    """Pre-validation request flag controls a privileged handler branch."""
    mark_admin_request_before_validation()
    if g.get("admin_request"):
        return jsonify({"users": ["all"]})
    return jsonify({"users": [g.email]})


@app.route("/gadgets/safe_validated_identity_flag", methods=["GET"])
def gadget_safe_validated_identity_flag():
    """Role flag is set only after validation succeeds."""
    mark_admin_request_after_validation()
    if g.get("admin_request"):
        return jsonify({"users": ["all"]})
    return jsonify({"users": [g.email]})


@app.route("/gadgets/session_identity_rebind", methods=["POST"])
def gadget_session_identity_rebind():
    """Authenticated session identity is overwritten from submitted JSON."""
    email = request.json.get("email")
    if not authenticate_current_session():
        abort(401)
    session["email"] = email
    return jsonify({"email": g.email})


@app.route("/gadgets/safe_session_identity_persist", methods=["POST"])
def gadget_safe_session_identity_persist():
    """Session identity persists the authenticated principal."""
    request.json.get("email")
    if not authenticate_current_session():
        abort(401)
    session["email"] = g.email
    return jsonify({"email": g.email})
