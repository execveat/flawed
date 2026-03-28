"""Custom auth-guard decorators mirroring a real app's ``admins_only``/``authed_only``.

These are project-defined decorators whose nested wrapper enforces auth via
``abort(403)`` and/or a login redirect -- exactly the shape the call-graph
auth-inference pass (``_pass1_call_graph``) is designed to recognize as a
guard.  Defined in a *separate module* from the routes so the route-site
decorator FQN must resolve across a cross-module import
(``from .decorators import admins_only``), reproducing a real app's
cross-module guard-decorator import.
"""

from functools import wraps

from flask import abort, redirect, request, session, url_for


def is_admin():
    return bool(session.get("admin"))


def admins_only(f):
    @wraps(f)
    def admins_only_wrapper(*args, **kwargs):
        if is_admin():
            return f(*args, **kwargs)
        else:
            if request.is_json:
                abort(403)
            else:
                return redirect(url_for("auth.login", next=request.full_path))

    return admins_only_wrapper


def authed_only(f):
    @wraps(f)
    def authed_only_wrapper(*args, **kwargs):
        if session.get("id"):
            return f(*args, **kwargs)
        else:
            return redirect(url_for("auth.login", next=request.full_path))

    return authed_only_wrapper
