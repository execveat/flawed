"""FLAW-344: the L1 schema gate check and the re-lock tool.

The gate (``tools.check_l1_schema``) must fail whenever ``_index`` changed without
a matching, deliberately-recorded schema decision; the re-lock tool
(``tools.update_schema_lock``) must refuse to silently bless an ``_index`` change
that neither moved the fingerprint nor bumped the version.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import tools.check_l1_schema as check_mod
import tools.update_schema_lock as update_mod
from tools._schema_lock import SchemaState

if TYPE_CHECKING:
    import pytest

_LIVE = SchemaState(
    l1_schema_version="1",
    record_schema_fingerprint="aaaa1111bbbb2222",
    extraction_code_signature="live-extraction-sig",
)


def _patch_live(monkeypatch: pytest.MonkeyPatch, mod: object) -> None:
    monkeypatch.setattr(mod, "live_state", lambda: _LIVE)


class TestGateCheck:
    def test_pass_when_lock_matches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_live(monkeypatch, check_mod)
        monkeypatch.setattr(check_mod, "read_lock", lambda: _LIVE)
        assert check_mod.main() == 0

    def test_fail_when_lock_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_live(monkeypatch, check_mod)
        monkeypatch.setattr(check_mod, "read_lock", lambda: None)
        assert check_mod.main() == 1

    def test_fail_on_fingerprint_mismatch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_live(monkeypatch, check_mod)
        stale = SchemaState("1", "OLDfingerprint000", "live-extraction-sig")
        monkeypatch.setattr(check_mod, "read_lock", lambda: stale)
        assert check_mod.main() == 1

    def test_fail_on_extraction_change_with_same_fingerprint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_live(monkeypatch, check_mod)
        stale = SchemaState("1", "aaaa1111bbbb2222", "OLD-extraction-sig")
        monkeypatch.setattr(check_mod, "read_lock", lambda: stale)
        assert check_mod.main() == 1

    def test_fail_on_version_mismatch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_live(monkeypatch, check_mod)
        stale = SchemaState("0", "aaaa1111bbbb2222", "live-extraction-sig")
        monkeypatch.setattr(check_mod, "read_lock", lambda: stale)
        assert check_mod.main() == 1


class TestUpdateTool:
    def test_refuses_output_change_without_declaration(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_index changed, fingerprint same, version same, no flag -> refuse (danger zone)."""
        _patch_live(monkeypatch, update_mod)
        stale = SchemaState("1", "aaaa1111bbbb2222", "OLD-extraction-sig")
        monkeypatch.setattr(update_mod, "read_lock", lambda: stale)
        wrote: list[SchemaState] = []
        monkeypatch.setattr(update_mod, "write_lock", wrote.append)
        assert update_mod.main([]) == 1
        assert wrote == []  # nothing written

    def test_output_neutral_flag_relocks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_live(monkeypatch, update_mod)
        stale = SchemaState("1", "aaaa1111bbbb2222", "OLD-extraction-sig")
        monkeypatch.setattr(update_mod, "read_lock", lambda: stale)
        wrote: list[SchemaState] = []
        monkeypatch.setattr(update_mod, "write_lock", wrote.append)
        assert update_mod.main(["--output-neutral"]) == 0
        assert wrote == [_LIVE]

    def test_fingerprint_move_relocks_without_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A format change auto-invalidates at runtime, so re-locking needs no flag."""
        _patch_live(monkeypatch, update_mod)
        stale = SchemaState("1", "OLDfingerprint000", "OLD-extraction-sig")
        monkeypatch.setattr(update_mod, "read_lock", lambda: stale)
        wrote: list[SchemaState] = []
        monkeypatch.setattr(update_mod, "write_lock", wrote.append)
        assert update_mod.main([]) == 0
        assert wrote == [_LIVE]

    def test_version_bump_relocks_without_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_live(monkeypatch, update_mod)
        stale = SchemaState("0", "aaaa1111bbbb2222", "OLD-extraction-sig")
        monkeypatch.setattr(update_mod, "read_lock", lambda: stale)
        wrote: list[SchemaState] = []
        monkeypatch.setattr(update_mod, "write_lock", wrote.append)
        assert update_mod.main([]) == 0
        assert wrote == [_LIVE]
