"""Helpers called cross-module from ``pkg.routes.orders``.

The call edge ``pkg.routes.orders.list_orders -> pkg.services.helpers.*`` and
the ``request.args.get`` input read both live in a nested package, so the
caller/callee FQNs and the read's containing-function FQN are package-qualified
(``pkg.services.helpers.read_order_id``) — never the bare file stem
(``helpers.read_order_id``). This is the shape that the abs/relative match-key
bug silently dropped before paths/FQNs were relativized at the L1 source.
"""

from flask import request


def read_order_id() -> str | None:
    return request.args.get("order_id")


def load_order(order_id: str | None) -> dict[str, object]:
    return {"id": order_id, "status": "open"}
