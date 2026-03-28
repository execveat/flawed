"""Flask app with aliased imports: same patterns as flask_basic but renamed.

Level 1 complexity: import aliasing.  The Semantic API must resolve
aliases back to their original FQNs via L1 import resolution.

Every pattern here has an exact counterpart in flask_basic/app.py.
If a test passes on flask_basic but fails here, the bug is in
import alias resolution.
"""

# --- Aliased imports ---
from flask import Flask as WebApp
from flask import g as ctx
from flask import jsonify as json_response
from flask import redirect as redir
from flask import request as req
from flask import session as sess
from flask_login import current_user as me
from flask_login import login_required as auth_required
from flask_login import login_user as sign_in
from flask_login import logout_user as sign_out
from sqlalchemy import text as raw_sql
from werkzeug.security import check_password_hash as verify_pw
from werkzeug.security import generate_password_hash as hash_pw

my_app = WebApp(__name__)


# -- Routes with aliased app --


@my_app.route("/")
def index():
    return "hello"


@my_app.route("/users", methods=["GET", "POST"])
def users():
    if req.method == "POST":
        return json_response({"created": True})
    return json_response([])


@my_app.get("/items")
def items_get():
    return json_response([])


# -- Inputs with aliased request --


@my_app.route("/inputs/query")
def input_query():
    """req.args.get("user_id") — aliased request → still Query input."""
    user_id = req.args.get("user_id")
    return json_response({"user_id": user_id})


@my_app.route("/inputs/form", methods=["POST"])
def input_form():
    """req.form["name"] — aliased request → still Form input."""
    name = req.form["name"]
    return json_response({"name": name})


@my_app.route("/inputs/json", methods=["POST"])
def input_json():
    """req.json — aliased request → still Json input."""
    data = req.json
    return json_response(data)


@my_app.route("/inputs/headers")
def input_headers():
    """req.headers — aliased request → still Header input."""
    auth = req.headers.get("Authorization")
    return json_response({"auth": auth})


@my_app.route("/inputs/cookies")
def input_cookies():
    """req.cookies — aliased request → still Cookie input."""
    token = req.cookies.get("session_token")
    return json_response({"token": token})


# -- Effects with aliased globals --


@my_app.route("/effects/state_write")
def effect_state_attr():
    """ctx.user = value — aliased g → still STATE_WRITE."""
    ctx.user = {"id": 1}
    return json_response(ctx.user)


@my_app.route("/effects/session_write")
def effect_session_write():
    """sess["key"] = val — aliased session → still STATE_WRITE."""
    sess["user_id"] = 42
    return json_response({"ok": True})


@my_app.route("/effects/redirect")
def effect_redirect():
    """redir(url) — aliased redirect → still RESPONSE_WRITE."""
    return redir("/")


# -- Checks with aliased decorators --


@my_app.route("/checks/protected")
@auth_required
def check_auth():
    """@auth_required (alias of @login_required) → AUTHENTICATION."""
    return json_response({"user": me.id})


@my_app.route("/checks/password", methods=["POST"])
def check_password():
    """verify_pw() alias of check_password_hash → PASSWORD_VERIFY."""
    pw = req.form["password"]
    return json_response({"ok": verify_pw("hash", pw)})


@my_app.route("/checks/hash", methods=["POST"])
def check_hash():
    """hash_pw() alias of generate_password_hash → PASSWORD_HASH."""
    pw = req.form["password"]
    return json_response({"hash": hash_pw(pw)})


# -- Sinks with aliased functions --


@my_app.route("/sinks/sqli", methods=["POST"])
def sink_sqli():
    """raw_sql(user_input) — aliased text() → SQL_INJECTION sink."""
    query = req.form["query"]
    db = ctx.db_session
    result = db.execute(raw_sql(query))
    return json_response(list(result))


# -- Lifecycle with aliased app --


@my_app.before_request
def lifecycle_before():
    ctx.started = True


@my_app.after_request
def lifecycle_after(response):
    return response


# -- Proxy with aliased current_user --


@my_app.route("/proxy")
@auth_required
def proxy():
    """me (alias of current_user) → StateProxy."""
    return json_response({"name": me.name})


# -- Login / Logout with aliases --


@my_app.route("/login", methods=["POST"])
def do_login():
    """sign_in() alias of login_user → STATE_WRITE."""
    sign_in(me)
    return redir("/")


@my_app.route("/logout")
def do_logout():
    """sign_out() alias of logout_user → STATE_WRITE."""
    sign_out()
    return redir("/")
