"""External `--rules-dir` loading ergonomics (FLAW-215, FLAW-216).

Rules loaded from a user ``--rules-dir`` must be able to import sibling helper
modules and a shared ``_lib`` package with *plain* imports — no ``sys.path``
shim in the rule file — and rule files must mix freely with helper files in one
directory (a module is a rule iff it carries an ``@detector``). A user rules dir
that resolves to nothing must warn, never silently load zero rules.

These pin the loader mechanics directly:

* the rules dir is placed on ``sys.path`` so ``from _lib import x`` / ``import
  helpers`` resolve when the rule module is imported;
* ``_``-prefixed *directories* are not scanned for rules (but stay importable);
* discovery stays decorator-based, so a decorator-less helper next to rules is
  simply not a rule;
* an empty / nonexistent user rules dir warns;
* the built-in library still loads (regression guard).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from flawed._cli.rules import discover_rule_files, load_configured_detectors
from flawed._config.schema import ResolvedConfig, RuleConfig

if TYPE_CHECKING:
    from pathlib import Path


def _config_for(rules_dir: Path) -> ResolvedConfig:
    return ResolvedConfig(rules=RuleConfig(paths=(str(rules_dir),)))


def _loaded_ids(rules_dir: Path) -> set[str]:
    config = _config_for(rules_dir)
    detectors = load_configured_detectors(config, discover_rule_files(config))
    return {d.rule_id for d in detectors}


_RULE_USING_LIB = """
from __future__ import annotations
from typing import TYPE_CHECKING
from flawed import detector
from _lib.predicates import marker  # shared package import, NO sys.path shim

if TYPE_CHECKING:
    from collections.abc import Iterator
    from flawed.evidence import Finding
    from flawed.repo import RepoView

# Module-level use: a broken `_lib` import would raise at load time.
_TAG = marker()

@detector("test-rule-uses-lib")
def detect(kb: "RepoView") -> "Iterator[Finding]":
    return iter(())
"""

_RULE_USING_SIBLING = """
from __future__ import annotations
from typing import TYPE_CHECKING
from flawed import detector
from sharedhelp import bonus  # plain sibling-module import, NO shim

if TYPE_CHECKING:
    from collections.abc import Iterator
    from flawed.evidence import Finding
    from flawed.repo import RepoView

_B = bonus()

@detector("test-rule-uses-sibling")
def detect(kb: "RepoView") -> "Iterator[Finding]":
    return iter(())
"""

# A helper module that *also* carries a decorator, placed under `_lib/`. It must
# NOT be discovered as a rule (the `_lib` dir is pruned from discovery), proving
# discovery is decorator-based AND `_`-dirs are skipped.
_SNEAKY_IN_LIB = """
from __future__ import annotations
from flawed import detector

@detector("should-not-be-discovered")
def detect(kb):
    return iter(())
"""

_PLAIN_HELPER = "def bonus() -> int:\n    return 7\n"
_LIB_PREDICATES = "def marker() -> str:\n    return 'ok'\n"


def test_rule_imports_shared_lib_package_without_shim(tmp_path: Path) -> None:
    """A nested rule importing a sibling `_lib` package loads with no shim."""
    rules = tmp_path / "rules"
    (rules / "r04_cardinality").mkdir(parents=True)
    (rules / "r04_cardinality" / "rule_alpha.py").write_text(_RULE_USING_LIB)
    (rules / "_lib").mkdir()
    (rules / "_lib" / "__init__.py").write_text("")
    (rules / "_lib" / "predicates.py").write_text(_LIB_PREDICATES)

    assert "test-rule-uses-lib" in _loaded_ids(rules)


def test_plain_helper_file_mixes_with_rule(tmp_path: Path) -> None:
    """A decorator-less helper.py next to a rule is importable and not a rule."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule_beta.py").write_text(_RULE_USING_SIBLING)
    (rules / "sharedhelp.py").write_text(_PLAIN_HELPER)

    ids = _loaded_ids(rules)
    assert "test-rule-uses-sibling" in ids
    # sharedhelp.py carries no @detector → contributes nothing.
    assert all("sharedhelp" not in rid for rid in ids)


def test_underscore_dir_is_not_scanned_for_rules(tmp_path: Path) -> None:
    """A decorated module under `_lib/` is importable infra, never a rule."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule_alpha.py").write_text(_RULE_USING_LIB)
    (rules / "_lib").mkdir()
    (rules / "_lib" / "__init__.py").write_text("")
    (rules / "_lib" / "predicates.py").write_text(_LIB_PREDICATES)
    (rules / "_lib" / "sneaky.py").write_text(_SNEAKY_IN_LIB)

    ids = _loaded_ids(rules)
    assert "test-rule-uses-lib" in ids
    assert "should-not-be-discovered" not in ids


def test_empty_user_rules_dir_warns(tmp_path: Path, caplog) -> None:
    empty = tmp_path / "empty_rules"
    empty.mkdir()
    with caplog.at_level(logging.WARNING, logger="flawed.rules"):
        entries = discover_rule_files(_config_for(empty))
    assert entries == ()
    assert any("empty_rules" in r.message for r in caplog.records)


def test_nonexistent_user_rules_dir_warns(tmp_path: Path, caplog) -> None:
    missing = tmp_path / "does_not_exist"
    with caplog.at_level(logging.WARNING, logger="flawed.rules"):
        entries = discover_rule_files(_config_for(missing))
    assert entries == ()
    assert any("does_not_exist" in r.message for r in caplog.records)


def test_builtin_library_still_loads(caplog) -> None:
    """Regression guard: the built-in ruleset loads unchanged and silently."""
    config = ResolvedConfig()  # default paths = ("builtin",)
    with caplog.at_level(logging.WARNING, logger="flawed.rules"):
        ids = {d.rule_id for d in load_configured_detectors(config, discover_rule_files(config))}
    # A representative spread across rule families must all be present.
    for known in (
        "endpoints",
        "request-inputs",
        "route-guards",
        "value-flow",
        "type-disagreements",
    ):
        assert known in ids
    assert len(ids) == 5  # the built-in library is the capability-demo core
    # Built-in discovery must NOT emit the empty-dir warning.
    assert not any(
        r.name == "flawed.rules" and "no rule files" in r.message for r in caplog.records
    )
