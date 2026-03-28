"""Flask app exercising custom (non-provider-modeled) storage mutations.

FLAW-281a fixture. A route that calls a custom verb-named mutating method on
an app-defined object (``store.delete_result(...)``) emits no provider effect
today -- the persistent write is invisible, so coverage rules cannot see the
real mutation (the ``delete_report``-class false negative).  A sibling route
that only *reads* (``store.get_result(...)``) must NOT be treated as a mutation.
"""

from flask import Flask, jsonify, request

app = Flask(__name__)


class ResultStore:
    """An app-defined storage wrapper -- no provider models its methods."""

    def __init__(self):
        self._data = {}

    def delete_result(self, result_id):
        self._data.pop(result_id, None)

    def get_result(self, result_id):
        return self._data.get(result_id)


store = ResultStore()


@app.route("/results/<result_id>", methods=["DELETE"])
def delete_report(result_id):
    # Custom persistent write with no provider -- the inferred STATE_WRITE target.
    store.delete_result(result_id)
    return jsonify(deleted=result_id)


@app.route("/results/<result_id>", methods=["GET"])
def read_report(result_id):
    # Pure read on the same store -- must NOT be inferred as a mutation.
    value = store.get_result(result_id)
    return jsonify(value=value)
