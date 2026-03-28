"""Flask app with variable indirection and cross-function calls.

Level 2-4 complexity: variable assignment, cross-function same-file,
cross-file imports, multi-level indirection chains.
"""

from flask import Flask, g, jsonify, redirect, request, session
from flask_login import login_required
from sqlalchemy import text

from . import helpers, utils

app = Flask(__name__)


# -- Level 2: Variable assignment ----------------------------------------


@app.route("/l2/query")
def l2_variable_assignment():
    """Input read via variable: r = request; r.args.get(...)."""
    r = request
    user_id = r.args.get("user_id")
    return jsonify({"user_id": user_id})


@app.route("/l2/session")
def l2_session_variable():
    """Session write via variable: s = session; s["key"] = val."""
    s = session
    s["role"] = "admin"
    return jsonify({"ok": True})


@app.route("/l2/effect_chain")
def l2_effect_chain():
    """Effect via chained variable: db = g.db_session; db.commit()."""
    db = g.db_session
    db.commit()
    return jsonify({"ok": True})


# -- Level 3: Cross-function same-file ----------------------------------


def _get_user_id():
    """Helper that reads request.args (should be detected as Query input)."""
    return request.args.get("user_id")


def _write_session(key, value):
    """Helper that writes to session (should be detected as STATE_WRITE)."""
    session[key] = value


def _run_query(query_str):
    """Helper that executes raw SQL (should be detected as SQL_INJECTION)."""
    db = g.db_session
    return db.execute(text(query_str))


@app.route("/l3/input")
def l3_cross_function_input():
    """Input read happens in helper function _get_user_id()."""
    user_id = _get_user_id()
    return jsonify({"user_id": user_id})


@app.route("/l3/effect")
def l3_cross_function_effect():
    """Effect happens in helper function _write_session()."""
    _write_session("user_id", 42)
    return jsonify({"ok": True})


@app.route("/l3/sink", methods=["POST"])
def l3_cross_function_sink():
    """User input flows through function boundary to SQL sink."""
    query = request.form["query"]
    result = _run_query(query)  # input → helper → text() sink
    return jsonify(list(result))


# -- Level 4: Cross-file import -----------------------------------------


@app.route("/l4/input")
def l4_cross_file_input():
    """Input read happens in helpers.py::get_query_param()."""
    value = helpers.get_query_param("search")
    return jsonify({"search": value})


@app.route("/l4/effect", methods=["POST"])
def l4_cross_file_effect():
    """Effect happens in helpers.py::save_to_session()."""
    helpers.save_to_session("username", request.form["name"])
    return jsonify({"ok": True})


@app.route("/l4/sink", methods=["POST"])
def l4_cross_file_sink():
    """Input → cross-file helper → SQL sink."""
    query = request.form["query"]
    result = helpers.execute_raw(query)
    return jsonify(list(result))


# -- Level 6: Multi-level indirection -----------------------------------


@app.route("/l6/chained")
def l6_chained_indirection():
    """x = request; a = x.args; v = a.get("k") — 3-step chain."""
    x = request
    a = x.args
    v = a.get("key")
    return jsonify({"key": v})


@app.route("/l6/nested_call")
def l6_nested_call():
    """Input → utils.process_input() → helpers.get_query_param()."""
    result = utils.process_input("user_id")
    return jsonify({"result": result})


@app.route("/l6/multi_hop_sink", methods=["POST"])
def l6_multi_hop_sink():
    """Input → utils.run_user_query() → helpers.execute_raw() → text()."""
    query = request.form["query"]
    result = utils.run_user_query(query)
    return jsonify(list(result))


# -- Level 7: Dynamic patterns (expected to NOT be detected) -------------


@app.route("/l7/getattr")
def l7_getattr():
    """getattr(request, 'args') — dynamic, should not be detected."""
    container = getattr(request, "args")
    user_id = container.get("user_id")
    return jsonify({"user_id": user_id})


@app.route("/l7/dict_dispatch")
def l7_dict_dispatch():
    """Dict-based dispatch — dynamic, not detectable."""
    sources = {"q": request.args, "f": request.form}
    src = sources.get("q")
    if src is not None:
        return jsonify({"val": src.get("key")})
    return jsonify({})
