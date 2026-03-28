"""Class-based views for subclass resolution tests.

MethodView subclass: the provider declares ClassViewPattern on
flask.views.MethodView.  The engine must detect HTTP verb dispatch
on subclasses.
"""

from flask import jsonify, request
from flask.views import MethodView


class ItemAPI(MethodView):
    """Class-based view dispatching by HTTP method.

    The provider declares ClassViewPattern with base_class_fqn=
    "flask.views.MethodView" and method_map={"get": "GET", ...}.

    The engine must:
    1. Detect ItemAPI as a MethodView subclass
    2. Map get() → GET, post() → POST, etc.
    3. Associate with the URL rule from add_url_rule()
    """

    def get(self, item_id=None):
        """GET handler → should create a GET route."""
        if item_id is not None:
            return jsonify({"item_id": item_id})
        return jsonify({"items": []})

    def post(self):
        """POST handler → should create a POST route."""
        data = request.json
        return jsonify({"created": True, "data": data}), 201

    def put(self, item_id):
        """PUT handler → should create a PUT route."""
        data = request.json
        return jsonify({"updated": True, "id": item_id})

    def delete(self, item_id):
        """DELETE handler → should create a DELETE route."""
        return jsonify({"deleted": True, "id": item_id})
