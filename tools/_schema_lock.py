"""Shared helpers for the FLAW-344 L1 schema lock.

The lock (``src/flawed/_index/_schema_lock.json``) records the last *acknowledged*
L1 schema state — the explicit :data:`flawed._index._pipeline.L1_SCHEMA_VERSION`,
the record-schema fingerprint, and the (now provenance-only) extraction-code
byte-hash.  Both the gate check (:mod:`tools.check_l1_schema`) and the re-lock
tool (:mod:`tools.update_schema_lock`) read live state and the lock through here,
so the two can never drift in how they compute either side.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

#: ``_index`` source glob whose byte-hash is the (provenance-only) extraction
#: signature.  Must match ``_L1_EXTRACTION_SIGNATURE_PATTERNS`` in
#: :mod:`flawed._cli.pipeline`.
_EXTRACTION_PATTERNS: tuple[str, ...] = ("_index/**/*.py",)

_LOCK_PATH = (
    Path(__file__).resolve().parent.parent / "src" / "flawed" / "_index" / "_schema_lock.json"
)

_LOCK_COMMENT = (
    "FLAW-344 L1 schema lock. Do NOT hand-edit. Regenerate with "
    "`python -m tools.update_schema_lock` after a deliberate _index change. The "
    "quality gate (tools.check_l1_schema) fails when _index source changes "
    "without re-locking, preserving the anti-silent-FN guarantee that the old "
    "extraction_code_signature byte-hash provided at runtime."
)


@dataclass(frozen=True)
class SchemaState:
    """The three values that identify an L1 schema state."""

    l1_schema_version: str
    record_schema_fingerprint: str
    extraction_code_signature: str


def lock_path() -> Path:
    """Absolute path to the committed schema lock file."""
    return _LOCK_PATH


def live_state() -> SchemaState:
    """Compute the current schema state from live engine source."""
    from flawed._cli._code_signature import code_signature
    from flawed._index._pipeline import L1_SCHEMA_VERSION, record_schema_fingerprint

    return SchemaState(
        l1_schema_version=L1_SCHEMA_VERSION,
        record_schema_fingerprint=record_schema_fingerprint(),
        extraction_code_signature=code_signature(_EXTRACTION_PATTERNS),
    )


def read_lock() -> SchemaState | None:
    """Read the committed lock, or ``None`` when absent/unreadable/malformed."""
    try:
        raw = json.loads(_LOCK_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict):
        return None
    try:
        return SchemaState(
            l1_schema_version=str(raw["l1_schema_version"]),
            record_schema_fingerprint=str(raw["record_schema_fingerprint"]),
            extraction_code_signature=str(raw["extraction_code_signature"]),
        )
    except KeyError:
        return None


def write_lock(state: SchemaState) -> None:
    """Write *state* to the committed lock file (deterministic, trailing newline)."""
    payload = {
        "_comment": _LOCK_COMMENT,
        "l1_schema_version": state.l1_schema_version,
        "record_schema_fingerprint": state.record_schema_fingerprint,
        "extraction_code_signature": state.extraction_code_signature,
    }
    _LOCK_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
