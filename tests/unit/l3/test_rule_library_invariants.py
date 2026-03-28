"""Invariants over the built-in detection-rule library.

Fast, hermetic guards (no fixture, no subprocess): they load the real detector
set the way the CLI does and assert library-level naming invariants.

``test_builtin_rule_filename_prefixes_are_unique`` is a standing guard
(FLAW-353): no two shipped rules may claim the same taxonomy id (filename
prefix), so the whole duplicate-prefix defect class is impossible by
construction rather than caught case-by-case.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from flawed._cli.rules import discover_rule_files, load_configured_detectors
from flawed._config.schema import ResolvedConfig
from flawed._rules import builtin_rules_dir

if TYPE_CHECKING:
    from collections.abc import Iterable


def _builtin_rule_ids() -> set[str]:
    config = ResolvedConfig()
    detectors = load_configured_detectors(config, discover_rule_files(config))
    return {d.rule_id for d in detectors}


def _rule_prefix(stem: str) -> str:
    """The taxonomy id a rule filename claims — the token before the first ``_``.

    ``alpha_presence_check`` -> ``alpha``; ``beta_coverage_report`` ->
    ``beta``. The trailing sub-pattern letter is significant: ``alpha2f`` and ``alpha2g``
    are distinct ids (FLAW-346), so the prefix keeps the whole leading token.
    """
    return stem.split("_", 1)[0]


def _duplicate_prefixes(stems: Iterable[str]) -> dict[str, list[str]]:
    """Map each filename prefix claimed by >1 rule to the colliding stems.

    Pure — operates on names, not the filesystem — so the guard's own
    collision-detection logic can be exercised against planted duplicates
    (``test_duplicate_prefix_detector_catches_planted_collision``) and is not
    merely trusted to be correct.
    """
    by_prefix: defaultdict[str, list[str]] = defaultdict(list)
    for stem in stems:
        by_prefix[_rule_prefix(stem)].append(stem)
    return {prefix: sorted(group) for prefix, group in by_prefix.items() if len(group) > 1}


def _builtin_rule_stems() -> list[str]:
    """Filenames (stems) of the shipped builtin rules only.

    Scoped to ``builtin_rules_dir()`` so a smoke/user rule that legitimately
    reuses a builtin id cannot make this guard false-positive.
    """
    builtin = builtin_rules_dir().resolve()
    return [
        e.name for e in discover_rule_files(ResolvedConfig()) if e.path.is_relative_to(builtin)
    ]


def test_builtin_rule_filename_prefixes_are_unique() -> None:
    """No two shipped rules may claim the same taxonomy id (filename prefix).

    A duplicate prefix is a silent naming-hygiene defect: two rules collide on
    one filename-prefix id token, making the taxonomy
    ambiguous and letting a ``--rules`` id-prefix filter resolve to the wrong
    file. FLAW-346 fixed one such collision by hand (``alpha2f`` claimed twice);
    this guard makes the whole class impossible going forward (FLAW-353).
    """
    stems = _builtin_rule_stems()
    assert stems, "no builtin rules discovered — rule discovery is broken"
    collisions = _duplicate_prefixes(stems)
    assert not collisions, f"duplicate rule filename prefixes (prefix -> files): {collisions}"


def test_duplicate_prefix_detector_catches_planted_collision() -> None:
    """The collision detector genuinely flags a duplicate — the guard is not vacuous.

    Models a planted collision (two ``alpha_`` files) to prove the
    detector would catch it, while a clean tree
    passes the guard above.
    """
    planted = ["alpha_presence_check", "alpha_session_presence", "beta_multi_container_read"]
    assert _duplicate_prefixes(planted) == {
        "alpha": ["alpha_presence_check", "alpha_session_presence"],
    }
