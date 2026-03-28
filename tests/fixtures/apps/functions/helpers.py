"""Cross-file call targets."""


def validate_positive(n):
    if n < 0:
        raise ValueError("must be positive")
    return n


def format_result(value, prefix="Result"):
    return f"{prefix}: {value}"
