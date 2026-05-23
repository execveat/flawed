"""Detection rule discovery and execution for the CLI pipeline."""

from __future__ import annotations

import fnmatch
import hashlib
import importlib.util
import logging
import re
import sys
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, cast

from flawed._config.paths import iter_python_source_files, resolve_paths
from flawed.evidence import Finding
from flawed.severity import DEFAULT_SEVERITY, Severity

if TYPE_CHECKING:
    from types import ModuleType

    from flawed._config.schema import ResolvedConfig
    from flawed.repo import RepoView

RuleFunction = Callable[["RepoView"], object]

_log = logging.getLogger("flawed.rules")


class RuleExecutionError(Exception):
    """Raised when a rule cannot be imported or run completely."""


@dataclass(frozen=True)
class RuleEntry:
    """A discovered Python rule module."""

    name: str
    path: Path


@dataclass(frozen=True)
class RuleDetector:
    """A detector function loaded from a rule module."""

    rule_id: str
    path: Path
    function: RuleFunction


@dataclass(frozen=True)
class RuleFinding:
    """A finding annotated with the rule that produced it."""

    rule_id: str
    rule_path: Path
    finding: Finding

    @property
    def fingerprint(self) -> str:
        """Stable fingerprint incorporating the rule ID."""
        h = hashlib.sha256()
        h.update(self.rule_id.encode())
        h.update(b"\x00")
        h.update(self.finding.fingerprint.encode())
        return h.hexdigest()[:16]


@dataclass(frozen=True)
class RuleSummary:
    """Inventory metadata for one detector, for ``flawed rules`` listing."""

    rule_id: str
    description: str
    severity: Severity
    path: Path

    @property
    def stem(self) -> str:
        """The rule module filename stem (underscore form of the id)."""
        return self.path.stem


@dataclass(frozen=True)
class RuleProfile:
    """Per-rule profiling data collected during detector execution."""

    rule_id: str
    wall_ms: float
    finding_count: int
    finding_gap_count: int
    #: Flow-tracer invocations attributable to this rule (FLAW-194). Counts the
    #: *new* (engine-cache-miss) flow queries the rule triggered; a query an
    #: earlier rule already cached costs this rule nothing and is not counted.
    flow_query_count: int = 0
    #: Real BFS traversals (``FunctionFlowIndex.bfs_path``) this rule triggered
    #: (FLAW-194) — the dominant flow cost. ``bfs_count <= flow_query_count``.
    bfs_count: int = 0


def flow_query_stats_of(repo: object) -> tuple[int, int]:
    """Read a repo view's scan-cumulative ``(flow_query_count, bfs_count)``.

    Defensive by design (FLAW-194): repo views without flow telemetry — e.g.
    index-only runs or unit-test fakes — report ``(0, 0)`` so the detector loop
    records zero flow cost rather than failing.
    """
    stats = getattr(repo, "flow_query_stats", (0, 0))
    if isinstance(stats, tuple) and len(stats) == 2:
        return (int(stats[0]), int(stats[1]))
    return (0, 0)


def _ensure_on_syspath(directory: Path) -> None:
    """Put a rule search dir on ``sys.path`` so its rules can import siblings.

    A rule loaded from ``--rules-dir DIR`` is exec'd under a synthetic module
    name, so plain ``import helpers`` / ``from _lib import x`` (referring to
    other modules *in DIR*) would otherwise fail — forcing every rule author to
    paste a ``sys.path`` shim. Registering DIR here makes those imports resolve
    naturally. Idempotent; front of path so a rule pack's own helpers win.
    """
    entry = str(directory.resolve())
    if entry not in sys.path:
        sys.path.insert(0, entry)


def _is_rule_path(py_file: Path, search_dir: Path) -> bool:
    """Whether *py_file* under *search_dir* should be scanned for detectors.

    Skips any path with a ``_``-prefixed component *relative to the search dir*
    — both ``_helper.py`` files and whole ``_lib/`` packages. Those remain
    importable (the dir is on ``sys.path``) but are infrastructure, never rules.
    The search dir's own name is not part of the relative path, so a built-in
    library living under ``flawed/_rules`` is unaffected.
    """
    try:
        rel = py_file.relative_to(search_dir)
    except ValueError:
        rel = Path(py_file.name)
    return not any(part.startswith("_") for part in rel.parts)


def discover_rule_files(config: ResolvedConfig) -> tuple[RuleEntry, ...]:
    """Return all Python rule files under the configured rule directories.

    Rules are identified by the ``@detector`` decorator at load time, so a
    discovered file that carries no detector is simply not a rule — rule files
    and helper files mix freely in one directory. Helper packages named with a
    leading ``_`` (e.g. ``_lib/``) are importable but excluded from scanning.
    """
    entries: list[RuleEntry] = []
    seen: set[Path] = set()
    builtin_dirs = {_builtin_rules_dir().resolve(), _smoke_rules_dir().resolve()}

    for search_dir in _rule_search_dirs(config):
        is_user_dir = search_dir.resolve() not in builtin_dirs

        if not search_dir.is_dir():
            if is_user_dir:
                _log.warning(
                    "rules directory %s does not exist — 0 rules loaded from it. "
                    "A relative --rules-dir resolves against the config base dir, "
                    "not your shell's cwd; pass an absolute path.",
                    search_dir,
                )
            continue

        # Rules in this dir must be able to import sibling helpers / _lib.
        if is_user_dir:
            _ensure_on_syspath(search_dir)

        dir_entries: list[RuleEntry] = []
        for py_file in iter_python_source_files(search_dir):
            if not _is_rule_path(py_file, search_dir):
                continue
            resolved = py_file.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            dir_entries.append(RuleEntry(name=py_file.stem, path=resolved))

        if is_user_dir and not dir_entries:
            _log.warning(
                "rules directory %s contains no rule files — 0 rules loaded "
                "from it. (A module is a rule only if it carries an @detector; "
                "check that your rule files define one.)",
                search_dir,
            )
        entries.extend(dir_entries)

    return tuple(entries)


def load_configured_detectors(
    config: ResolvedConfig,
    rule_files: Iterable[RuleEntry],
) -> tuple[RuleDetector, ...]:
    """Import rule modules and return detector functions allowed by config filters."""
    detectors: list[RuleDetector] = []
    for rule_file in rule_files:
        if not _rule_file_might_match(rule_file.name, config):
            continue
        module = _load_rule_module(rule_file.path)
        detectors.extend(
            detector
            for detector in _module_detectors(module, rule_file.path)
            if _rule_id_matches(detector.rule_id, config)
        )
    return tuple(detectors)


def summarize_rules(config: ResolvedConfig) -> tuple[RuleSummary, ...]:
    """Load every discovered detector and return its inventory metadata.

    Unlike :func:`load_configured_detectors`, this does NOT apply the
    include/exclude filters — ``flawed rules`` is an inventory of everything
    available, not the subset a given scan would run.  Modules that fail to
    import are skipped (a broken third-party rule must not break the listing).
    """
    summaries: list[RuleSummary] = []
    seen: set[str] = set()
    for entry in discover_rule_files(config):
        try:
            module = _load_rule_module(entry.path)
        except RuleExecutionError:
            continue
        for detector in _module_detectors(module, entry.path):
            if detector.rule_id in seen:
                continue
            seen.add(detector.rule_id)
            fn = detector.function
            description = getattr(fn, "__detector_description__", None) or ""
            severity = getattr(fn, "__detector_severity__", DEFAULT_SEVERITY)
            summaries.append(
                RuleSummary(
                    rule_id=detector.rule_id,
                    description=description,
                    severity=severity,
                    path=detector.path,
                )
            )
    return tuple(sorted(summaries, key=lambda s: s.rule_id))


def all_rule_ids(config: ResolvedConfig) -> tuple[str, ...]:
    """Every built-in rule id, sorted — the data source for shell completion.

    Imports rule modules (no scan / no L1+L2), so it is fast enough to run on
    each TAB press. Defensive by design: a completion callback must NEVER raise
    (an exception there breaks the user's interactive shell), so any failure
    degrades to an empty tuple rather than propagating.
    """
    try:
        return tuple(summary.rule_id for summary in summarize_rules(config))
    except Exception:  # completion must never break the shell
        return ()


@dataclass(frozen=True)
class RuleExplanation:
    """Full explanatory metadata for one rule, for ``flawed explain``."""

    rule_id: str
    severity: Severity
    description: str
    #: The rule module's docstring — the rich, author-written prose (what it
    #: detects, why it matters, see-also). Sourced from the module, never
    #: hard-coded in the CLI, so it stays correct as rules evolve.
    doc: str
    path: Path
    see_also: tuple[str, ...]

    @property
    def stem(self) -> str:
        """The rule module filename stem (underscore form of the id)."""
        return self.path.stem


@dataclass(frozen=True)
class RuleLookup:
    """Result of resolving a rule id for ``explain``: a hit, plus the known ids.

    ``known_ids`` is always populated so the caller can offer did-you-mean
    suggestions when ``explanation`` is ``None``.
    """

    explanation: RuleExplanation | None
    known_ids: tuple[str, ...]


def _rule_family(rule_id: str) -> str:
    """Leading ``<letters><digits>`` family stem of a rule id.

    ``auth2a-strict`` and ``auth2-lenient`` both yield ``auth2`` so sibling
    variants surface as see-also. Falls back to the whole (normalized) id.
    """
    canonical = _normalize_rule_sep(rule_id)
    match = re.match(r"[a-z]+[0-9]+", canonical)
    return match.group(0) if match else canonical


def explain_rule(config: ResolvedConfig, rule_id: str) -> RuleLookup:
    """Resolve *rule_id* to its full explanatory metadata.

    Returns a :class:`RuleLookup`. ``explanation`` is ``None`` when no rule
    matches (the caller offers did-you-mean over ``known_ids``). Matching is
    separator-insensitive (FLAW-122) so ``value-flow`` and ``value_flow`` both resolve.
    Modules that fail to import are skipped, exactly as in
    :func:`summarize_rules` — a broken third-party rule must not break lookup.
    """
    target = _normalize_rule_sep(rule_id)
    known: list[str] = []
    found: tuple[RuleDetector, ModuleType] | None = None
    for entry in discover_rule_files(config):
        try:
            module = _load_rule_module(entry.path)
        except RuleExecutionError:
            continue
        for detector in _module_detectors(module, entry.path):
            known.append(detector.rule_id)
            if found is None and _normalize_rule_sep(detector.rule_id) == target:
                found = (detector, module)
    known_ids = tuple(sorted(set(known)))
    if found is None:
        return RuleLookup(explanation=None, known_ids=known_ids)

    detector, module = found
    fn = detector.function
    doc = (module.__doc__ or "").strip()
    description = getattr(fn, "__detector_description__", None) or ""
    if not description and doc:
        description = doc.splitlines()[0].strip()
    severity = getattr(fn, "__detector_severity__", DEFAULT_SEVERITY)
    family = _rule_family(detector.rule_id)
    see_also = tuple(
        rid for rid in known_ids if rid != detector.rule_id and _rule_family(rid) == family
    )
    return RuleLookup(
        explanation=RuleExplanation(
            rule_id=detector.rule_id,
            severity=severity,
            description=description,
            doc=doc,
            path=detector.path,
            see_also=see_also,
        ),
        known_ids=known_ids,
    )


def run_detectors(
    repo: RepoView,
    detectors: Iterable[RuleDetector],
) -> tuple[RuleFinding, ...]:
    """Run each detector and return all findings with rule provenance."""
    findings: list[RuleFinding] = []
    for detector in detectors:
        findings.extend(iter_detector_findings(repo, detector))
    return tuple(findings)


def run_detectors_profiled(
    repo: RepoView,
    detectors: Iterable[RuleDetector],
) -> tuple[tuple[RuleFinding, ...], tuple[RuleProfile, ...]]:
    """Run detectors with per-rule wall time and finding/gap counts."""
    all_findings: list[RuleFinding] = []
    profiles: list[RuleProfile] = []
    for detector in detectors:
        q0, b0 = flow_query_stats_of(repo)
        start_ns = time.perf_counter_ns()
        rule_findings = tuple(iter_detector_findings(repo, detector))
        elapsed_ns = time.perf_counter_ns() - start_ns
        q1, b1 = flow_query_stats_of(repo)
        all_findings.extend(rule_findings)
        gap_count = sum(len(rf.finding.gaps) for rf in rule_findings)
        profiles.append(
            RuleProfile(
                rule_id=detector.rule_id,
                wall_ms=(elapsed_ns / 1_000_000),
                finding_count=len(rule_findings),
                finding_gap_count=gap_count,
                flow_query_count=q1 - q0,
                bfs_count=b1 - b0,
            )
        )
    return tuple(all_findings), tuple(profiles)


def iter_detector_findings(repo: RepoView, detector: RuleDetector) -> Iterator[RuleFinding]:
    """Yield validated findings from one detector without materializing them."""
    try:
        detected = detector.function(repo)
    except Exception as exc:
        raise RuleExecutionError(f"{detector.rule_id}: detect() failed: {exc}") from exc

    try:
        iterator = iter(cast("Iterable[object]", detected))
    except TypeError as exc:
        raise RuleExecutionError(
            f"{detector.rule_id}: detect(repo) did not return an iterable"
        ) from exc

    while True:
        try:
            item = next(iterator)
        except StopIteration:
            return
        except Exception as exc:
            raise RuleExecutionError(
                f"{detector.rule_id}: detect() iteration failed: {exc}"
            ) from exc

        if not isinstance(item, Finding):
            raise RuleExecutionError(
                f"{detector.rule_id}: detect(repo) yielded non-Finding object(s): "
                f"{type(item).__name__}"
            )

        yield RuleFinding(rule_id=detector.rule_id, rule_path=detector.path, finding=item)


def _run_detector(repo: RepoView, detector: RuleDetector) -> tuple[RuleFinding, ...]:
    return tuple(iter_detector_findings(repo, detector))


def _rule_search_dirs(config: ResolvedConfig) -> tuple[Path, ...]:
    search_dirs: list[Path] = []
    seen: set[Path] = set()

    def _add(path: Path) -> None:
        key = path.resolve() if path.exists() else path.absolute()
        if key in seen:
            return
        seen.add(key)
        search_dirs.append(path)

    for raw_path in resolve_paths(config.rules.paths, config.rules.base_dir):
        if raw_path == "!reset":
            continue
        if raw_path == "builtin":
            _add(_builtin_rules_dir())
        elif raw_path == "smoke":
            # The smoke set is an id-manifest (FLAW-158): canonical entries live
            # in the built-in library and are referenced by id (see the smoke
            # gate in _rule_id_matches), while the prototype p-rules are physical
            # files in the smoke package. Search both; the gate keeps only the
            # manifest ids, so a smoke scan still imports just the curated set.
            _add(_builtin_rules_dir())
            _add(_smoke_rules_dir())
        else:
            path = Path(raw_path).expanduser()
            if not path.is_absolute() and not path.exists():
                project_relative = _project_root() / path
                if project_relative.exists():
                    path = project_relative
            _add(path)

    return tuple(search_dirs)


def _load_rule_module(path: Path) -> ModuleType:
    module_name = _module_name(path)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuleExecutionError(f"{path}: cannot load rule module")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise RuleExecutionError(f"{path}: import failed: {exc}") from exc
    return module


def _module_detectors(module: ModuleType, path: Path) -> tuple[RuleDetector, ...]:
    detectors: list[RuleDetector] = []
    for attr_name in sorted(dir(module)):
        candidate = getattr(module, attr_name)
        rule_id = getattr(candidate, "__detector_name__", None)
        if callable(candidate) and isinstance(rule_id, str):
            detectors.append(
                RuleDetector(
                    rule_id=rule_id,
                    path=path,
                    function=cast("RuleFunction", candidate),
                )
            )
    return tuple(detectors)


def _module_name(path: Path) -> str:
    digest = hashlib.sha256(str(path).encode()).hexdigest()[:12]
    safe_stem = path.stem.replace("-", "_")
    return f"_flawed_cli_rule_{safe_stem}_{digest}"


def _normalize_rule_sep(value: str) -> str:
    """Canonicalize rule separators so ``-`` and ``_`` are interchangeable in filters.

    Rule filenames use underscores (``request_inputs``) while
    ``@detector(...)`` ids use hyphens (``request-inputs``).
    A user naturally copies the filename stem into ``-i``/``--include``; without
    this normalization the glob would never bridge the separator and the rule would
    be silently dropped (FLAW-122). Glob metacharacters (``*?[]``) are unaffected.
    """
    return value.replace("_", "-")


def _rule_file_might_match(stem: str, config: ResolvedConfig) -> bool:
    # Matching is separator-insensitive (see _normalize_rule_sep), so the file-stem
    # prefilter is a single normalized check.
    return _rule_id_matches(stem, config)


@lru_cache(maxsize=1)
def _normalized_smoke_ids() -> frozenset[str]:
    """Smoke manifest ids in canonical (separator-insensitive) form, computed once."""
    from flawed._rules_smoke import SMOKE_RULE_IDS

    return frozenset(_normalize_rule_sep(rule_id) for rule_id in SMOKE_RULE_IDS)


def _smoke_active(config: ResolvedConfig) -> bool:
    """True when the ``"smoke"`` token selects the curated manifest for this scan."""
    return any(
        raw_path == "smoke"
        for raw_path in resolve_paths(config.rules.paths, config.rules.base_dir)
    )


# A single ``-i``/``-e`` value may bundle several patterns: ``-i endpoints,value-flow`` or
# ``-i "endpoints value-flow"``. Splitting on commas and whitespace makes one option value behave
# like the option repeated, and — because both include and exclude flow through this
# helper — keeps ``-i`` and ``-e`` symmetric (FLAW-178).
_SELECTOR_SPLIT = re.compile(r"[,\s]+")


def _expand_selectors(patterns: Iterable[str]) -> list[str]:
    expanded: list[str] = []
    for pattern in patterns:
        expanded.extend(token for token in _SELECTOR_SPLIT.split(pattern) if token)
    return expanded


def _selector_matches(canonical: str, pattern: str) -> bool:
    """Does normalized rule id *canonical* satisfy a single include/exclude *pattern*?

    A pattern carrying glob metacharacters (``*?[``) keeps fnmatch semantics. A bare
    token additionally matches as a *stem*: it selects any id that extends it at a
    separator boundary, so ``value`` selects ``value-flow`` — while
    ``val`` does not, because the boundary is a literal ``-``. Without the stem arm,
    fnmatch demands the whole id and a stem silently selects nothing (FLAW-178).
    """
    normalized = _normalize_rule_sep(pattern)
    if fnmatch.fnmatchcase(canonical, normalized):
        return True
    if any(ch in normalized for ch in "*?["):
        return False
    return canonical.startswith(f"{normalized}-")


def _rule_id_matches(rule_id: str, config: ResolvedConfig) -> bool:
    rules = config.rules
    canonical = _normalize_rule_sep(rule_id)
    # Smoke restricts the (otherwise full) built-in library to the curated
    # manifest ids (FLAW-158). Applied before the user include/exclude filters so
    # `--smoke -i <pat>` narrows *within* the smoke set, exactly as a separate
    # smoke directory used to.
    if _smoke_active(config) and canonical not in _normalized_smoke_ids():
        return False
    includes = _expand_selectors(rules.include or ("*",))
    if not any(_selector_matches(canonical, p) for p in includes):
        return False
    if rules.include_regex and not _matches_any_regex(rule_id, rules.include_regex):
        return False
    if any(_selector_matches(canonical, p) for p in _expand_selectors(rules.exclude)):
        return False
    return not _matches_any_regex(rule_id, rules.exclude_regex)


def _matches_any_regex(rule_id: str, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        try:
            if re.search(pattern, rule_id):
                return True
        except re.error as exc:
            raise RuleExecutionError(f"invalid rule regex {pattern!r}: {exc}") from exc
    return False


def _builtin_rules_dir() -> Path:
    from flawed._rules import builtin_rules_dir

    return builtin_rules_dir()


def _smoke_rules_dir() -> Path:
    from flawed._rules_smoke import smoke_rules_dir

    return smoke_rules_dir()


def smoke_rule_count() -> int:
    """Size of the ``--smoke`` set (fast; for the dashboard).

    Reads the curated id-manifest directly (FLAW-158) rather than walking a
    directory, so the count cannot drift from what a smoke scan actually runs.
    """
    from flawed._rules_smoke import SMOKE_RULE_IDS

    return len(SMOKE_RULE_IDS)


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]
