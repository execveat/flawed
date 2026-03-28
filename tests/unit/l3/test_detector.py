"""Verify detector decorator."""

from __future__ import annotations


def test_detector_decorator_preserves_function() -> None:
    from flawed import detector

    @detector("test-rule")
    def my_detector() -> None:
        pass

    assert callable(my_detector)
    assert my_detector.__detector_name__ == "test-rule"


def test_detector_decorator_name_attribute() -> None:
    from flawed import detector

    @detector("path-guard-body-rebind")
    def detect(kb: object) -> None:
        pass

    assert detect.__detector_name__ == "path-guard-body-rebind"
