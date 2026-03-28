"""Source span construction helpers for Layer 1 extraction."""

from __future__ import annotations

from flawed._index._types import SourceSpan


class SpanInterner:
    """Per-extraction cache for sharing equal ``SourceSpan`` values."""

    __slots__ = ("_spans",)

    def __init__(self) -> None:
        self._spans: dict[tuple[str, int, int, int, int], SourceSpan] = {}

    def intern(
        self,
        *,
        file: str,
        line: int,
        column: int,
        end_line: int,
        end_column: int,
    ) -> SourceSpan:
        """Return a shared span for the exact source range."""
        key = (file, line, column, end_line, end_column)
        span = self._spans.get(key)
        if span is None:
            span = SourceSpan(
                file=file,
                line=line,
                column=column,
                end_line=end_line,
                end_column=end_column,
            )
            self._spans[key] = span
        return span
