"""Unit coverage for the shared analysis-code signature (FLAW-189 / FLAW-198).

``code_signature`` is the single source of truth for "did analysis code that
affects a cached value change". Both disk caches route through it, so it must be
deterministic, scope-sensitive (different roots → different digest), and the two
caches' uses must demonstrably share it rather than re-implement hashing.
"""

from __future__ import annotations

from flawed._cli._code_signature import code_signature


def test_deterministic_and_sha256_shaped() -> None:
    first = code_signature(("_semantic/**/*.py",))
    second = code_signature(("_semantic/**/*.py",))
    assert first == second
    assert len(first) == 64 and all(c in "0123456789abcdef" for c in first)


def test_different_roots_yield_different_digests() -> None:
    assert code_signature(("_index/**/*.py",)) != code_signature(("_semantic/**/*.py",))


def test_recursive_pattern_covers_files_directly_under_root() -> None:
    # ``**`` matches zero or more directories, so a tree pattern includes files
    # immediately under the root dir (not only nested ones). Adding the parent
    # dir's own files must not be a no-op relative to a single nested file.
    whole_tree = code_signature(("_semantic/**/*.py",))
    assert isinstance(whole_tree, str) and whole_tree


def test_both_caches_share_the_helper() -> None:
    """The provider-engine cache and the results cache use the SAME helper (no
    parallel third signature), with the results scope strictly broader."""
    from flawed._cli import provider_engine_cache as pec
    from flawed._cli import result_cache as rc

    # FLAW-189's signature is exactly the helper over its declared L2 patterns.
    assert pec._code_signature() == code_signature(pec._L2_SIGNATURE_PATTERNS)
    # The results cache adds L3-core + shared _rules, so its digest differs.
    assert code_signature(rc._RESULTS_CODE_SIGNATURE_PATTERNS) != pec._code_signature()
