"""Order routes guarded by the cross-module ``require_auth`` decorator.

``list_orders`` lives in the nested module ``pkg.routes.orders`` and:
  * is decorated with ``require_auth`` from ``pkg.auth.decorators`` (cross-module
    decorator edge), and
  * calls ``read_order_id`` / ``load_order`` from ``pkg.services.helpers``
    (cross-module call edges).

Every one of those edges has the package-qualified caller FQN
``pkg.routes.orders.list_orders``. The L1 extractor must emit that exact
relative FQN so the L2 match-key consumers (functions_by_fqn,
_call_edges_for_caller) resolve it against the structural FunctionRecord.
"""

from flask import Blueprint, jsonify

from pkg.auth.decorators import require_auth
from pkg.services.helpers import load_order, read_order_id

bp = Blueprint("orders", __name__)


@bp.route("/orders")
@require_auth
def list_orders() -> object:
    order_id = read_order_id()
    order = load_order(order_id)
    return jsonify(order)
