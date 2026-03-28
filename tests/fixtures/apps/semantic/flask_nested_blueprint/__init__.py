"""Flask nested-blueprint fixture (FLAW-114).

A parent Blueprint registers child Blueprints via
``bp.register_blueprint(child.bp)`` -- the e03_fake_header_refund shape.  A
``before_request`` hook declared on the *parent* blueprint must be attributed to
every nested child route's ``full_stack``, because Flask runs a parent
blueprint's before_request handlers for all routes registered under it.  A
child's own group-scoped hook must reach that child's routes but MUST NOT leak
onto sibling children.

The parent hook is declared in this module (where ``bp`` is constructed) so the
fixture isolates the FLAW-114 *attribution* concern (parent→child propagation)
from the separate L1 concern of resolving a relative-imported decorator
receiver (tracked under FLAW-102 / the e03 ``protect_order_id`` mangled-FQN).
"""

from flask import Blueprint, Flask, request

app = Flask(__name__)
bp = Blueprint("root", __name__)


def read_forbidden_param() -> str | None:
    """Transitive callee of the parent hook -- must reach child routes."""
    return request.args.get("forbidden")


@bp.before_request
def root_guard():
    """Runs before every route nested under the parent blueprint."""
    if read_forbidden_param() is not None:
        raise ValueError("forbidden parameter rejected")


from .children import alpha, beta  # noqa: E402

bp.register_blueprint(alpha.bp)
bp.register_blueprint(beta.bp)
app.register_blueprint(bp)
