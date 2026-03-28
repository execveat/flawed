"""Function variety: top-level, nested, lambda, closure, method."""


def top_level(x, y=10):
    return x + y


def with_nested():
    def inner(a):
        return a * 2

    return inner(5)


def with_lambda():
    transform = lambda x: x.upper()  # noqa: E731
    return transform("hello")


def with_closure():
    captured = 42

    def inner():
        return captured

    return inner


class Calculator:
    def add(self, a, b):
        return a + b

    def multiply(self, a, b):
        return a * b

    @staticmethod
    def zero():
        return 0

    @classmethod
    def from_value(cls, v):
        return cls()
