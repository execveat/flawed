"""FLAW-304: detection of lossy lenient text decoding in managed subprocesses.

``_apply_lenient_text_decoding`` decodes managed-subprocess text with
``errors="replace"`` so a non-UTF-8 byte can never crash extraction (a repo-wide
false negative, the #1 sin). The surviving ``U+FFFD`` is the only signal that a
byte was silently dropped. ``contains_decode_replacement`` exposes that signal so
callers (notably an L1 extraction boundary) can surface an honest ``AnalysisGap``
instead of analysing mojibake as if it were faithful.
"""

from __future__ import annotations

from flawed import _process as managed_process


def test_detects_replacement_char() -> None:
    assert managed_process.contains_decode_replacement("before�after") is True


def test_clean_text_has_no_replacement() -> None:
    # Valid non-ASCII Unicode must NOT be mistaken for a decode loss.
    assert managed_process.contains_decode_replacement("clean ascii / unicode é 中 🚀") is False


def test_empty_text_has_no_replacement() -> None:
    assert managed_process.contains_decode_replacement("") is False


def test_marker_matches_the_errors_replace_policy() -> None:
    # The marker MUST equal exactly what errors="replace" produces for an
    # undecodable byte. If the decode policy and this constant ever drift, the
    # detector would silently miss real losses (a false negative) -- so pin it.
    decoded = b"valid\xffbyte".decode("utf-8", errors="replace")
    assert managed_process.REPLACEMENT_CHARACTER in decoded
    assert managed_process.contains_decode_replacement(decoded) is True
