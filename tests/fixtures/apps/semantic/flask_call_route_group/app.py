"""Plain-function ``add_url_rule`` route registered on a module-level blueprint.

Exercises the ``_convert_call_route`` path (RouteCallPattern, not a class
view): the route must attribute to the ``shop`` group and inherit its
``/shop`` URL prefix.
"""

from flask import Blueprint, Flask

shop = Blueprint("shop", __name__, url_prefix="/shop")


def list_items():
    return "items"


shop.add_url_rule("/items", "list_items", list_items, methods=["GET"])

app = Flask(__name__)
app.register_blueprint(shop)
