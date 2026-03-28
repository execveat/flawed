"""Decorator patterns: simple, parameterized, stacked, class-based."""

import functools


def simple_decorator(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)

    return wrapper


def requires_role(role):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def log_calls(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)

    return wrapper


def class_marker(cls):
    return cls


@simple_decorator
def plain():
    return "plain"


@requires_role("admin")
def admin_only():
    return "admin"


@log_calls
@requires_role("editor")
@simple_decorator
def stacked():
    return "stacked"


class ViewBase:
    @staticmethod
    def public():
        return "public"

    @requires_role("admin")
    def restricted(self):
        return "restricted"


@class_marker
class MarkedView:
    def show(self):
        return "marked"
