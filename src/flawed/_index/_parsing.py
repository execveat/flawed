"""Centralised AST parsing for analyzed-repo source (FLAW-124).

Parsing the analyzed project's own source with the stdlib :mod:`ast` re-emits
*that project's* ``SyntaxWarning``s — invalid escape sequences, ``is`` against a
literal, and similar lint-level issues — onto flawed's stderr. They concern the
code under analysis, not the engine, so surfacing them as if they were flawed's
own warnings is noise (a single scan of a real-world repo produced ~45 identical
``<unknown>:280: SyntaxWarning: invalid escape sequence '\\s'`` lines).

Every site that parses analyzed-repo source MUST route through these helpers so
the policy lives in exactly one place. The helpers:

* mute :class:`SyntaxWarning` for the duration of the parse only — flawed's own
  source is already imported (and thus compiled) before any analysis runs, so
  this never hides a warning about the engine itself; and
* thread the real target ``filename`` through so any ``SyntaxError`` (or a
  diagnostic we choose to surface in verbose mode) is attributed to the actual
  file instead of Python's default ``<unknown>``.

These helpers assume single-threaded parsing: :func:`warnings.catch_warnings`
mutates the process-global filter list and is not thread-safe.
"""

from __future__ import annotations

import ast
import warnings

#: Placeholder used when the real target path is not available at the call site.
ANALYZED_SOURCE_FILENAME = "<analyzed-source>"


def parse_analyzed_module(
    source: str,
    *,
    filename: str = ANALYZED_SOURCE_FILENAME,
    type_comments: bool = False,
) -> ast.Module:
    """Parse a module of analyzed-repo source, muting the target's SyntaxWarnings.

    Equivalent to ``ast.parse(source, filename, mode="exec")`` but quiet about
    lint-level warnings originating in the analyzed code. ``SyntaxError`` still
    propagates (callers catch it) and now carries the real ``filename``.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        return ast.parse(source, filename=filename, type_comments=type_comments)


def parse_analyzed_expression(
    expression: str,
    *,
    filename: str = ANALYZED_SOURCE_FILENAME,
) -> ast.Expression:
    """Parse a single analyzed-repo expression (``mode="eval"``), muting SyntaxWarnings.

    Used for expression strings lifted out of the analyzed source, which may
    themselves be string literals carrying an invalid escape sequence.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        return ast.parse(expression, filename=filename, mode="eval")
