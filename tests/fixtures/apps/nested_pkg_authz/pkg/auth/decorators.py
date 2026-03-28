"""A cross-module authorization decorator.

``require_auth`` is *defined* here in ``pkg.auth.decorators`` but *applied* in
``pkg.routes.orders`` — a decorator application that crosses a package
boundary. The extractor records that application as a call/symbol edge whose caller is
the package-qualified ``pkg.routes.orders.list_orders``; the AST extractor emits
no twin for it, so it is exactly the "un-twinned" edge whose dropped match key
was an invisible false negative.
"""

from functools import wraps
from typing import Any, Callable

from flask import abort, session


def require_auth(view: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(view)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not session.get("user_id"):
            abort(401)
        return view(*args, **kwargs)

    return wrapper
