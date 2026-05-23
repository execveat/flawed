"""Disk cache for the Layer 2 provider-engine result (FLAW-189).

Covers the three correctness constraints from the ticket: a real result
round-trips by value through pickle; the key invalidates on a content-hash,
analysis-code, or provider-config change; and a missing/corrupt/disabled entry
fails closed (recompute, never a partial or stale result).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flawed._cli import provider_engine_cache as pec
from flawed._cli.pipeline import run_provider_engine
from flawed._cli.provider_engine_cache import ProviderEngineCache
from flawed._config.schema import ProviderConfig, ProviderEntry, ResolvedConfig

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    import pytest

    from flawed._index import CodeIndex
    from flawed._semantic._provider_engine import ProviderEngineResult


def _make_cache(
    cache_dir: Path,
    *,
    config: ResolvedConfig | None = None,
    content_hash: str = "content-aaa",
    read_enabled: bool = True,
    write_enabled: bool = True,
) -> ProviderEngineCache:
    return ProviderEngineCache.create(
        cache_dir=cache_dir,
        config=config if config is not None else ResolvedConfig(),
        content_hash=content_hash,
        read_enabled=read_enabled,
        write_enabled=write_enabled,
    )


def test_round_trips_real_engine_result(
    flask_basic_provider_result: ProviderEngineResult, tmp_path: Path
) -> None:
    """A real result — matches, descriptors, L1 facts, gaps — round-trips by value."""
    result = flask_basic_provider_result
    assert result.matches, "fixture must exercise the descriptor/source-fact graph"

    cache = _make_cache(tmp_path)
    cache.store(result)
    loaded = cache.load()

    assert loaded == result
    # Distinct objects (deserialized), structurally equal.
    assert loaded is not result


def test_miss_when_content_hash_differs(
    flask_basic_provider_result: ProviderEngineResult, tmp_path: Path
) -> None:
    _make_cache(tmp_path, content_hash="content-aaa").store(flask_basic_provider_result)
    assert _make_cache(tmp_path, content_hash="content-bbb").load() is None


def test_miss_when_code_signature_differs(
    flask_basic_provider_result: ProviderEngineResult,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A providers/_semantic/_index edit (changed source signature) invalidates."""
    writer = _make_cache(tmp_path)
    writer.store(flask_basic_provider_result)
    assert writer.load() is not None  # same signature still hits

    monkeypatch.setattr(pec, "_code_signature", lambda: "forced-different-signature")
    assert _make_cache(tmp_path).load() is None


def test_miss_when_provider_config_differs(
    flask_basic_provider_result: ProviderEngineResult, tmp_path: Path
) -> None:
    """Disabling a provider changes which providers run, hence the result/key."""
    _make_cache(tmp_path, config=ResolvedConfig()).store(flask_basic_provider_result)
    disabled = ResolvedConfig(
        providers=ProviderConfig(entries={"flask": ProviderEntry(enable=False)})
    )
    assert _make_cache(tmp_path, config=disabled).load() is None


def test_corrupt_entry_recomputes(tmp_path: Path) -> None:
    """A corrupt cache file returns None (recompute), never raises."""
    cache = _make_cache(tmp_path)
    cache.cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache.cache_path.write_bytes(b"not a pickle \x00\x01\x02")
    assert cache.load() is None


def test_read_disabled_returns_none(
    flask_basic_provider_result: ProviderEngineResult, tmp_path: Path
) -> None:
    _make_cache(tmp_path).store(flask_basic_provider_result)
    assert _make_cache(tmp_path, read_enabled=False).load() is None


def test_write_disabled_does_not_persist(
    flask_basic_provider_result: ProviderEngineResult, tmp_path: Path
) -> None:
    _make_cache(tmp_path, write_enabled=False).store(flask_basic_provider_result)
    assert not _make_cache(tmp_path).cache_path.exists()
    assert _make_cache(tmp_path).load() is None


def test_load_missing_file_returns_none(tmp_path: Path) -> None:
    assert _make_cache(tmp_path / "absent").load() is None


# -- run_provider_engine wrapper integration -------------------------------


class _FakeEngine:
    """Stand-in engine recording whether the (expensive) build ran."""

    def __init__(self, result: ProviderEngineResult) -> None:
        self._result = result
        self.ran = False

    def run(
        self, idx: CodeIndex, *, provider_ids: Sequence[str] | None = None
    ) -> ProviderEngineResult:
        self.ran = True
        return self._result


def test_wrapper_returns_cached_without_running_engine(
    flask_basic_provider_result: ProviderEngineResult, tmp_path: Path
) -> None:
    """A warm cache short-circuits the engine build entirely."""
    cache = _make_cache(tmp_path)
    cache.store(flask_basic_provider_result)

    engine = _FakeEngine(flask_basic_provider_result)
    sentinel_index = object()
    result = run_provider_engine(
        engine,  # type: ignore[arg-type]
        sentinel_index,  # type: ignore[arg-type]
        config=ResolvedConfig(),
        cache=cache,
    )

    assert result == flask_basic_provider_result
    assert engine.ran is False


def test_wrapper_computes_and_stores_on_miss(
    flask_basic_provider_result: ProviderEngineResult, tmp_path: Path
) -> None:
    """A cold cache runs the engine then persists the result for next time."""
    cache = _make_cache(tmp_path)
    assert cache.load() is None

    engine = _FakeEngine(flask_basic_provider_result)
    result = run_provider_engine(
        engine,  # type: ignore[arg-type]
        object(),  # type: ignore[arg-type]
        config=ResolvedConfig(),
        cache=cache,
    )

    assert engine.ran is True
    assert result == flask_basic_provider_result
    # Now warm: a fresh handle loads the stored result.
    assert _make_cache(tmp_path).load() == flask_basic_provider_result
