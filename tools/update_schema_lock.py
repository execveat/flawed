"""Re-lock the FLAW-344 L1 schema after a deliberate ``_index`` change.

Writes the live schema state (``L1_SCHEMA_VERSION`` + record-schema fingerprint +
extraction-code signature) to ``src/flawed/_index/_schema_lock.json``, which the
gate (:mod:`tools.check_l1_schema`) compares against on every commit that touches
``_index``.

The one guard that preserves the anti-silent-FN guarantee: when ``_index`` source
changed but **neither** the record-schema fingerprint **nor** ``L1_SCHEMA_VERSION``
moved, re-locking is refused unless ``--output-neutral`` is passed.  That is the
case where an L1 behaviour change could slip through invisibly, so the developer
must explicitly assert the change is a behaviour-preserving refactor (or bump
``L1_SCHEMA_VERSION`` to declare an output change).
"""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING

from tools._schema_lock import live_state, lock_path, read_lock, write_lock

if TYPE_CHECKING:
    from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    """Re-lock the schema. Return 0 on success, 1 when an explicit decision is required."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-neutral",
        action="store_true",
        help=(
            "Assert the _index change does not alter L1 output (a refactor). Required "
            "when _index source changed but neither the record-schema fingerprint nor "
            "L1_SCHEMA_VERSION moved."
        ),
    )
    args = parser.parse_args(argv)

    live = live_state()
    lock = read_lock()

    fingerprint_moved = (
        lock is None or lock.record_schema_fingerprint != live.record_schema_fingerprint
    )
    version_bumped = lock is not None and lock.l1_schema_version != live.l1_schema_version
    sig_changed = lock is None or lock.extraction_code_signature != live.extraction_code_signature

    if (
        lock is not None
        and sig_changed
        and not fingerprint_moved
        and not version_bumped
        and not args.output_neutral
    ):
        print(
            "Refusing to re-lock: _index source changed but the record-schema fingerprint\n"
            "and L1_SCHEMA_VERSION are both unchanged — the silent-FN danger zone.\n"
            "Choose one:\n"
            "  - behaviour-preserving refactor -> rerun with --output-neutral\n"
            "  - the change alters L1 output    -> bump L1_SCHEMA_VERSION in\n"
            "    src/flawed/_index/_pipeline.py, then rerun."
        )
        return 1

    write_lock(live)
    print(f"L1 schema lock updated at {lock_path()}:")
    print(f"  l1_schema_version         = {live.l1_schema_version}")
    print(f"  record_schema_fingerprint = {live.record_schema_fingerprint}")
    print(f"  extraction_code_signature = {live.extraction_code_signature}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
