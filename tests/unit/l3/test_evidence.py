"""Verify Finding immutable-builder behaviour."""

from __future__ import annotations

import pytest

from flawed.core import Location
from flawed.evidence import Evidence, Finding
from flawed.function import Decorator

_LOC = Location(file="a.py", line=1, column=0, end_line=1, end_column=10)


def _make_decorator() -> Decorator:
    return Decorator(
        name="login_required",
        fqn="flask_login.login_required",
        arguments=(),
        location=_LOC,
    )


class TestFinding:
    def test_empty_finding(self) -> None:
        f = Finding(route_endpoint="api.users", summary="Test finding")
        assert f.summary == "Test finding"
        assert f.route_endpoint == "api.users"
        assert f.evidence_items == ()

    def test_evidence_returns_new_instance(self) -> None:
        dec = _make_decorator()
        f1 = Finding(route_endpoint="idx", summary="s")
        f2 = f1.evidence(dec, "auth decorator")
        assert f1 is not f2
        assert f1.evidence_items == ()
        assert len(f2.evidence_items) == 1

    def test_evidence_accumulates(self) -> None:
        dec = _make_decorator()
        f = (
            Finding(route_endpoint="idx", summary="s")
            .evidence(dec, "first")
            .evidence(dec, "second")
        )
        assert len(f.evidence_items) == 2
        assert f.evidence_items[0].description == "first"
        assert f.evidence_items[1].description == "second"

    def test_evidence_location_extracted(self) -> None:
        dec = _make_decorator()
        f = Finding(route_endpoint="idx", summary="s").evidence(dec, "d")
        assert isinstance(f.evidence_items[0], Evidence)
        assert f.evidence_items[0].location == _LOC

    def test_finding_is_frozen(self) -> None:
        f = Finding(route_endpoint="idx", summary="s")
        with pytest.raises(AttributeError):
            f.summary = "changed"  # type: ignore[misc]
