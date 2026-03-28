"""Middleware importing a package-level Blueprint via a parent-relative import."""

from flask import g

from .. import bp


@bp.before_request
def package_auth_middleware():
    g.package_seen = True
