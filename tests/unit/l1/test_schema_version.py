"""FLAW-344: L1_SCHEMA_VERSION + record-schema fingerprint invalidation semantics.

Scheme C decouples L1 cache validity from a byte-hash of ``_index`` source: the
gate keys on ``L1_SCHEMA_VERSION`` + the record-schema fingerprint (+ content and
type-enrichment signatures), NOT on ``extraction_code_signature``.  These tests
pin the three guarantees the design promises:

1. A behaviour-preserving ``_index`` refactor (which moves the byte-hash but not
   the schema) does NOT invalidate a cached index.
2. A record-schema format change DOES invalidate (the fingerprint moves).
3. An unknown / mismatched schema version fails closed (forces a rebuild).
"""

from __future__ import annotations

import json
from dataclasses import make_dataclass
from enum import Enum
from typing import TYPE_CHECKING

from flawed._index._pipeline import (
    L1_SCHEMA_VERSION,
    _schema_fingerprint,
    cache_key_matches,
    record_schema_fingerprint,
    write_cache_key,
)

if TYPE_CHECKING:
    from pathlib import Path

_CONTENT = "content-hash-abc"
_TE_SIG = "te-sig-xyz"


def _write(path: Path, sig: str = "sig-A") -> None:
    write_cache_key(
        path,
        content_hash=_CONTENT,
        type_enrichment_signature=_TE_SIG,
        extraction_code_signature=sig,
    )


class TestCacheKeyGate:
    def test_matching_key_is_a_hit(self, tmp_path: Path) -> None:
        _write(tmp_path)
        assert cache_key_matches(
            tmp_path,
            content_hash=_CONTENT,
            type_enrichment_signature=_TE_SIG,
            extraction_code_signature="sig-A",
        )

    def test_refactor_changing_extraction_signature_does_not_invalidate(
        self, tmp_path: Path
    ) -> None:
        """A behaviour-preserving _index refactor moves the byte-hash but not the
        schema — the cache must still be a hit (the core scheme-C promise)."""
        _write(tmp_path, sig="sig-before-refactor")
        assert cache_key_matches(
            tmp_path,
            content_hash=_CONTENT,
            type_enrichment_signature=_TE_SIG,
            extraction_code_signature="sig-AFTER-refactor",  # changed bytes
        )

    def test_content_change_invalidates(self, tmp_path: Path) -> None:
        _write(tmp_path)
        assert not cache_key_matches(
            tmp_path,
            content_hash="different-content",
            type_enrichment_signature=_TE_SIG,
        )

    def test_type_enrichment_change_invalidates(self, tmp_path: Path) -> None:
        _write(tmp_path)
        assert not cache_key_matches(
            tmp_path,
            content_hash=_CONTENT,
            type_enrichment_signature="different-te-sig",
        )

    def test_format_change_invalidates(self, tmp_path: Path) -> None:
        """A record-schema fingerprint mismatch (a format change) invalidates."""
        _write(tmp_path)
        key_path = tmp_path / "cache_key.json"
        data = json.loads(key_path.read_text())
        data["record_schema_fingerprint"] = "deadbeefdeadbeef"  # simulate a format change
        key_path.write_text(json.dumps(data))
        assert not cache_key_matches(
            tmp_path,
            content_hash=_CONTENT,
            type_enrichment_signature=_TE_SIG,
        )

    def test_unknown_schema_version_fails_closed(self, tmp_path: Path) -> None:
        _write(tmp_path)
        key_path = tmp_path / "cache_key.json"
        data = json.loads(key_path.read_text())
        data["l1_schema_version"] = "999-from-the-future"
        key_path.write_text(json.dumps(data))
        assert not cache_key_matches(
            tmp_path,
            content_hash=_CONTENT,
            type_enrichment_signature=_TE_SIG,
        )

    def test_legacy_cache_without_schema_fields_fails_closed(self, tmp_path: Path) -> None:
        """A pre-FLAW-344 cache key (no schema_version / fingerprint) must not hit."""
        (tmp_path / "cache_key.json").write_text(
            json.dumps(
                {
                    "content_hash": _CONTENT,
                    "type_enrichment_signature": _TE_SIG,
                    "pipeline_version": "0.6.0",
                    "extraction_code_signature": "sig-A",
                }
            )
        )
        assert not cache_key_matches(
            tmp_path,
            content_hash=_CONTENT,
            type_enrichment_signature=_TE_SIG,
        )

    def test_missing_key_file_is_a_miss(self, tmp_path: Path) -> None:
        assert not cache_key_matches(tmp_path, content_hash=_CONTENT)

    def test_written_key_records_provenance(self, tmp_path: Path) -> None:
        """The demoted byte-hash + pipeline version are still written for auditing."""
        _write(tmp_path, sig="provenance-sig")
        data = json.loads((tmp_path / "cache_key.json").read_text())
        assert data["extraction_code_signature"] == "provenance-sig"
        assert "pipeline_version" in data
        assert data["l1_schema_version"] == L1_SCHEMA_VERSION
        assert data["record_schema_fingerprint"] == record_schema_fingerprint()


# --- Fingerprint sensitivity (synthetic record sets) -----------------------
#
# The fingerprint keys each record by ``__qualname__``, so to isolate the effect
# of a *field/type/enum* change from an incidental class-name change, every
# synthetic record is given the same stable qualname. Then only the field set
# differs between variants.


def _mk(fields_spec: list[tuple[str, object]], *, qualname: str = "R") -> type:
    cls = make_dataclass("R", fields_spec, frozen=True)
    cls.__qualname__ = qualname
    return cls


class _ColorTwo(Enum):
    RED = "red"
    BLUE = "blue"


class _ColorThree(Enum):
    RED = "red"
    BLUE = "blue"
    GREEN = "green"


class TestSchemaFingerprint:
    def test_deterministic(self) -> None:
        base = _mk([("a", str), ("b", int)])
        assert _schema_fingerprint((base,)) == _schema_fingerprint((base,))

    def test_field_order_does_not_matter(self) -> None:
        ab = _mk([("a", str), ("b", int)])
        ba = _mk([("b", int), ("a", str)])
        assert _schema_fingerprint((ab,)) == _schema_fingerprint((ba,))

    def test_field_addition_moves_fingerprint(self) -> None:
        base = _mk([("a", str), ("b", int)])
        plus = _mk([("a", str), ("b", int), ("c", bool)])
        assert _schema_fingerprint((base,)) != _schema_fingerprint((plus,))

    def test_field_rename_moves_fingerprint(self) -> None:
        base = _mk([("a", str), ("b", int)])
        renamed = _mk([("a", str), ("b_renamed", int)])
        assert _schema_fingerprint((base,)) != _schema_fingerprint((renamed,))

    def test_field_retype_moves_fingerprint(self) -> None:
        as_int = _mk([("a", str), ("b", int)])
        as_str = _mk([("a", str), ("b", str)])
        assert _schema_fingerprint((as_int,)) != _schema_fingerprint((as_str,))

    def test_enum_member_change_moves_fingerprint(self) -> None:
        two = _mk([("a", str), ("color", _ColorTwo)])
        three = _mk([("a", str), ("color", _ColorThree)])
        assert _schema_fingerprint((two,)) != _schema_fingerprint((three,))

    def test_real_schema_fingerprint_is_short_hex(self) -> None:
        fp = record_schema_fingerprint()
        assert len(fp) == 16
        assert all(c in "0123456789abcdef" for c in fp)
