"""FLAW-333: request-scoped framework housekeeping is not server-wide state.

``_is_request_scoped_infra_call`` decides whether a verb-named method call is
Flask/SQLAlchemy ``session`` housekeeping or Flask-Caching invalidation -- neither
is module-global "affects all users" state, even though ``db`` / ``cache`` are module
symbols. Scoping these REQUEST cuts the dominant wild FP (server-state-write rules over-firing on
~140 ``cache.delete_memoized`` calls on a real app). FN-safe: only the named idioms downgrade;
a genuine module-global write keeps its resolved SERVER scope.
"""

import pytest

from flawed._semantic._effect_conversion import _is_request_scoped_infra_call


@pytest.mark.parametrize(
    ("receiver", "method"),
    [
        ("cache", "delete_memoized"),  # the dominant real-world FP
        ("cache", "delete_memoized_verhash"),
        ("self.cache", "delete_memoized"),  # method-unique: receiver name irrelevant
        ("app.cache", "delete_memoized"),
        ("cache", "delete"),  # generic verb gated on a cache-named receiver
        ("cache", "clear"),
        ("cache", "delete_many"),
        ("db.session", "commit"),  # SQLAlchemy session lifecycle
        ("db.session", "flush"),
        ("db.session", "add"),
        ("session", "add"),  # bare session (Flask or SQLAlchemy) is request-scoped
        ("db_session", "commit"),
        ("DB.Session", "commit"),  # receiver name match is case-insensitive
    ],
)
def test_request_scoped_infra_calls_are_downgraded(receiver: str, method: str) -> None:
    assert _is_request_scoped_infra_call(receiver, method) is True


@pytest.mark.parametrize(
    ("receiver", "method"),
    [
        ("_STORE", "save"),  # module-global singleton write: must stay SERVER (TP)
        ("store", "delete"),  # generic verb on a non-cache receiver: stays SERVER
        ("store", "save"),
        ("_REGISTRY", "append"),  # module-global container mutation: stays SERVER
        ("_CACHE", "update"),  # a plain dict named _CACHE is not a Flask-Caching object
        ("cache", "set"),  # populating the cache is not an invalidation verb
        ("self.repo", "save"),
    ],
)
def test_genuine_state_writes_are_not_downgraded(receiver: str, method: str) -> None:
    assert _is_request_scoped_infra_call(receiver, method) is False
