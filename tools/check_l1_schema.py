"""FLAW-344 quality gate: an ``_index`` change must be a declared schema decision.

The L1 cache-validity gate (:func:`flawed._index._pipeline.cache_key_matches`)
keys on :data:`flawed._index._pipeline.L1_SCHEMA_VERSION` plus the record-schema
fingerprint, **not** on a byte-hash of ``_index`` source.  That lets a
behaviour-preserving refactor keep the corpus valid — but it removes the old
FLAW-207 byte-hash's anti-silent-FN protection at *runtime*.  This check restores
that protection at *commit time*: whenever ``_index`` source changes, the
developer must consciously re-lock, declaring whether the change is
output-neutral or an output change (which bumps ``L1_SCHEMA_VERSION``).

Exit status: ``0`` when the lock is in sync with live source, ``1`` otherwise
(with an actionable message naming the exact command to run).
"""

from __future__ import annotations

from tools._schema_lock import live_state, lock_path, read_lock

_UPDATE = "python -m tools.update_schema_lock"


def main() -> int:
    """Return 0 when the schema lock matches live source, 1 otherwise."""
    live = live_state()
    lock = read_lock()

    if lock is None:
        print(f"L1 schema lock missing or unreadable at {lock_path()}.\n  Run `{_UPDATE}`.")
        return 1

    if lock.record_schema_fingerprint != live.record_schema_fingerprint:
        print(
            "L1 record schema changed (fingerprint "
            f"{lock.record_schema_fingerprint} -> {live.record_schema_fingerprint}).\n"
            "  The runtime auto-invalidates cached indices on this. Re-lock the schema:\n"
            f"    {_UPDATE}\n"
            "  If this reflects an intended L1 OUTPUT change, also bump L1_SCHEMA_VERSION first."
        )
        return 1

    if lock.extraction_code_signature != live.extraction_code_signature:
        print(
            "L1 extraction source (_index) changed without a record-schema change.\n"
            "  A behaviour change here would NOT auto-invalidate the corpus (silent-FN risk),\n"
            "  so it must be declared. Choose one:\n"
            f"    - output-neutral refactor:  {_UPDATE} --output-neutral\n"
            f"    - changes L1 output:        bump L1_SCHEMA_VERSION, then {_UPDATE}"
        )
        return 1

    if lock.l1_schema_version != live.l1_schema_version:
        print(
            f"L1_SCHEMA_VERSION is {live.l1_schema_version} but the lock records "
            f"{lock.l1_schema_version}.\n  Re-lock after the version bump: `{_UPDATE}`."
        )
        return 1

    print(
        f"L1 schema OK (version={live.l1_schema_version}, "
        f"fingerprint={live.record_schema_fingerprint})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
