"""Finding deduplication and suppression for the CLI pipeline.

Suppression sources, in precedence order (most specific first):

1. **Inline comments** — ``# flawed: ignore[RULE_ID]`` (rule-scoped, comma
   separable) or ``# flawed: ignore`` (every rule on the line), placed on the
   finding's line *or the line directly above it*. An optional ``-- reason``
   justification may follow; under ``--strict`` a directive without a reason is
   ignored and warned (so suppressions cannot accumulate silently).
2. **``.flawedignore``** — path-glob (optionally rule-scoped) suppression with
   ``.gitignore`` semantics, for vendored / generated / test trees.
3. **``--baseline-commit <ref>``** — findings that already existed at a git ref,
   matched on a *location-stable* key (rule id + the finding's stripped source
   line) so a pure line shift does not resurface a finding.

Suppressed findings are NEVER silently dropped: they are excluded from the human
findings list and the headline count, but still emitted in ``--json`` and
``--sarif`` flagged as suppressed (the codeql ``InSource`` model) so that
suppressions stay visible and auditable rather than rotting (the failure mode
that gets scanners ripped out of CI).

The pre-existing stored ``--baseline`` file (a fingerprint list) keeps its
historical hard-drop semantics and is applied *before* this module's
record-based suppression; folding it into the surfaced-record model is a future
cleanup, tracked separately.
"""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pathspec

from flawed import _process as managed_process

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from flawed._cli.rules import RuleFinding


# ── Dedup + stored-baseline file (pre-existing) ────────────────────────────


def deduplicate_findings(findings: Sequence[RuleFinding]) -> tuple[RuleFinding, ...]:
    """Remove duplicate findings, keeping the first occurrence per fingerprint."""
    seen: set[str] = set()
    result: list[RuleFinding] = []
    for finding in findings:
        fp = finding.fingerprint
        if fp not in seen:
            seen.add(fp)
            result.append(finding)
    return tuple(result)


def load_baseline(path: Path) -> frozenset[str]:
    """Load a baseline file of suppressed fingerprints.

    The baseline is a JSON file with a ``"suppressions"`` key containing
    a list of fingerprint strings::

        {"suppressions": ["a1b2c3d4e5f67890", "..."]}

    Returns an empty set on any I/O or parse error.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return frozenset()
    if not isinstance(data, dict):
        return frozenset()
    raw = data.get("suppressions", [])
    if not isinstance(raw, list):
        return frozenset()
    return frozenset(str(item) for item in raw)


def write_baseline(path: Path, findings: Sequence[RuleFinding]) -> None:
    """Write a baseline file from current findings."""
    payload = {
        "suppressions": sorted({f.fingerprint for f in findings}),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def suppress_findings(
    findings: Sequence[RuleFinding],
    suppressed: frozenset[str],
) -> tuple[RuleFinding, ...]:
    """Filter out findings whose fingerprints appear in the suppression set."""
    return tuple(f for f in findings if f.fingerprint not in suppressed)


# ── Surfaced suppression: inline, .flawedignore, --baseline-commit ─────────

_INLINE_DIRECTIVE = re.compile(
    r"#\s*flawed:\s*ignore(?:\[(?P<ids>[^\]]*)\])?(?:\s*--\s*(?P<reason>.*\S))?",
    re.IGNORECASE,
)


def _norm_rule_id(rule_id: str) -> str:
    """Canonicalise a rule id for separator-insensitive matching (cf. FLAW-122)."""
    return rule_id.replace("-", "_").lower()


@dataclass(frozen=True)
class SuppressionRecord:
    """A finding that was suppressed, plus why — surfaced in --json/--sarif."""

    finding: RuleFinding
    source: str  # "inline" | ".flawedignore" | "--baseline-commit"
    reason: str  # human-readable label, e.g. the directive or matching pattern
    kind: str = "inSource"  # SARIF suppression kind: "inSource" | "external"
    justification: str | None = None


@dataclass(frozen=True)
class SuppressionOutcome:
    """The split of a finding set into active (shown/counted) and suppressed."""

    active: tuple[RuleFinding, ...]
    suppressed: tuple[SuppressionRecord, ...]

    @property
    def counts_by_source(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for rec in self.suppressed:
            out[rec.source] = out.get(rec.source, 0) + 1
        return out


# ── .flawedignore ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class IgnoreSpec:
    """Parsed ``.flawedignore``: gitignore-style path globs, optionally scoped
    to specific rule ids.

    Line format (``#`` comments and blank lines ignored)::

        vendor/                  # suppress every rule under vendor/
        tests/**                 # suppress every rule under tests/
        migrations/*.py  route-*  # suppress only route-* rules in migrations
        generated.py  endpoints,value-flow  # comma-separated rule ids

    The path part uses ``.gitignore`` semantics (via ``pathspec``). The optional
    second whitespace-delimited token is a comma-separated list of rule ids
    (separator-insensitive). A line with no rule-id token suppresses all rules
    for matching paths.
    """

    # Typed ``Any`` rather than ``pathspec.PathSpec`` because the installed
    # pathspec exposes ``PathSpec`` as generic to some mypy environments and
    # non-generic to others; ``Any`` is the one annotation both accept.
    all_rules: Any  # pathspec.PathSpec
    scoped: tuple[tuple[Any, frozenset[str]], ...] = ()  # (pathspec.PathSpec, rule ids)

    @classmethod
    def parse(cls, text: str) -> IgnoreSpec:
        all_patterns: list[str] = []
        scoped: list[tuple[Any, frozenset[str]]] = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            pattern = parts[0]
            if len(parts) == 1:
                all_patterns.append(pattern)
                continue
            ids = frozenset(_norm_rule_id(p.strip()) for p in parts[1].split(",") if p.strip())
            if ids:
                spec = pathspec.PathSpec.from_lines("gitignore", [pattern])
                scoped.append((spec, ids))
            else:
                all_patterns.append(pattern)
        return cls(
            all_rules=pathspec.PathSpec.from_lines("gitignore", all_patterns),
            scoped=tuple(scoped),
        )

    @classmethod
    def load(cls, root: Path) -> IgnoreSpec | None:
        """Load ``<root>/.flawedignore`` if present, else None."""
        path = root / ".flawedignore"
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return None
        return cls.parse(text)

    def matches(self, rel_file: str, rule_id: str) -> bool:
        if self.all_rules.match_file(rel_file):
            return True
        norm = _norm_rule_id(rule_id)
        return any(norm in ids and spec.match_file(rel_file) for spec, ids in self.scoped)


# ── Inline directive parsing ───────────────────────────────────────────────


def parse_inline_directives(
    text: str,
) -> dict[int, tuple[frozenset[str] | None, str | None]]:
    """Map 1-based line number -> (normalised rule ids, justification).

    A ``None`` rule-id set means "all rules on this line". ``justification`` is
    the optional ``-- reason`` text, or ``None``.
    """
    directives: dict[int, tuple[frozenset[str] | None, str | None]] = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        match = _INLINE_DIRECTIVE.search(line)
        if match is None:
            continue
        ids_raw = match.group("ids")
        if ids_raw is None or not ids_raw.strip():
            ids: frozenset[str] | None = None
        else:
            ids = frozenset(_norm_rule_id(p.strip()) for p in ids_raw.split(",") if p.strip())
        reason = match.group("reason")
        directives[lineno] = (ids, reason.strip() if reason else None)
    return directives


# ── Location-stable key (for --baseline-commit) ────────────────────────────


def location_stable_key(rule_id: str, root: Path, rel_file: str | None, line: int | None) -> str:
    """A fingerprint that survives line shifts: rule id + stripped source line.

    Unlike ``Finding.fingerprint`` (which hashes evidence *locations*, so a pure
    line shift changes it), this hashes the *content* of the finding's primary
    line. Moving the code up/down keeps the same key, so ``--baseline-commit``
    does not resurface a finding that merely shifted lines.
    """
    snippet = ""
    if rel_file is not None and line is not None:
        lines = _read_source_lines(root, rel_file)
        if lines is not None and 1 <= line <= len(lines):
            snippet = lines[line - 1].strip()
    digest = hashlib.sha256()
    digest.update(_norm_rule_id(rule_id).encode())
    digest.update(b"\x00")
    digest.update(snippet.encode())
    return digest.hexdigest()[:16]


_SOURCE_CACHE: dict[tuple[str, str], list[str] | None] = {}


def _read_source_lines(root: Path, rel_file: str) -> list[str] | None:
    cache_key = (str(root), rel_file)
    if cache_key not in _SOURCE_CACHE:
        try:
            text: str | None = (root / rel_file).read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = None
        _SOURCE_CACHE[cache_key] = text.splitlines() if text is not None else None
    return _SOURCE_CACHE[cache_key]


def _finding_file_line(finding: RuleFinding) -> tuple[str | None, int | None]:
    loc = finding.finding.location
    if loc is None:
        return (None, None)
    return (loc.file, loc.line)


# ── The suppression engine ─────────────────────────────────────────────────


@dataclass
class _DirectiveCache:
    root: Path
    _by_file: dict[str, dict[int, tuple[frozenset[str] | None, str | None]]] = field(
        default_factory=dict
    )

    def for_file(self, rel_file: str) -> dict[int, tuple[frozenset[str] | None, str | None]]:
        if rel_file not in self._by_file:
            lines = _read_source_lines(self.root, rel_file)
            text = "\n".join(lines) if lines is not None else ""
            self._by_file[rel_file] = parse_inline_directives(text)
        return self._by_file[rel_file]


def _inline_record(
    finding: RuleFinding,
    rel_file: str | None,
    line: int | None,
    cache: _DirectiveCache,
    *,
    strict: bool,
    warn: Callable[[str], None] | None,
) -> SuppressionRecord | None:
    if rel_file is None or line is None:
        return None
    directives = cache.for_file(rel_file)
    # A directive on the finding's line OR the line directly above it applies.
    for directive_line in (line, line - 1):
        entry = directives.get(directive_line)
        if entry is None:
            continue
        ids, justification = entry
        if ids is not None and _norm_rule_id(finding.rule_id) not in ids:
            continue
        if strict and justification is None:
            if warn is not None:
                warn(
                    f"{rel_file}:{directive_line}: '# flawed: ignore' lacks a "
                    "required '-- reason' (--strict); finding NOT suppressed"
                )
            continue
        scope = f"[{finding.rule_id}]" if ids is not None else ""
        return SuppressionRecord(
            finding=finding,
            source="inline",
            reason=f"# flawed: ignore{scope}",
            kind="inSource",
            justification=justification,
        )
    return None


def compute_suppressions(
    findings: Sequence[RuleFinding],
    *,
    root: Path,
    ignore_spec: IgnoreSpec | None = None,
    baseline_commit_keys: frozenset[str] | None = None,
    strict: bool = False,
    warn: Callable[[str], None] | None = None,
) -> SuppressionOutcome:
    """Split findings into active vs suppressed across all surfaced sources.

    Precedence (first match wins the attributed record): inline >
    ``.flawedignore`` > ``--baseline-commit``.
    """
    cache = _DirectiveCache(root)
    active: list[RuleFinding] = []
    suppressed: list[SuppressionRecord] = []
    for finding in findings:
        rel_file, line = _finding_file_line(finding)
        record = _inline_record(finding, rel_file, line, cache, strict=strict, warn=warn)
        if (
            record is None
            and ignore_spec is not None
            and rel_file is not None
            and ignore_spec.matches(rel_file, finding.rule_id)
        ):
            record = SuppressionRecord(
                finding=finding,
                source=".flawedignore",
                reason=f".flawedignore: {rel_file}",
                kind="external",
            )
        if record is None and baseline_commit_keys is not None:
            key = location_stable_key(finding.rule_id, root, rel_file, line)
            if key in baseline_commit_keys:
                record = SuppressionRecord(
                    finding=finding,
                    source="--baseline-commit",
                    reason="present at baseline ref",
                    kind="external",
                )
        if record is None:
            active.append(finding)
        else:
            suppressed.append(record)
    return SuppressionOutcome(tuple(active), tuple(suppressed))


# ── --baseline-commit: scan a git ref and collect location-stable keys ──────


class BaselineCommitError(RuntimeError):
    """Raised when a ``--baseline-commit`` ref cannot be scanned."""


def baseline_commit_keys(
    ref: str,
    *,
    repo_root: Path,
    scan_target: Path,
    rule_args: Sequence[str],
    timeout_seconds: int,
) -> frozenset[str]:
    """Scan ``ref`` in a throwaway worktree and return location-stable keys.

    Adds a detached ``git worktree`` at ``ref``, runs ``flawed scan`` there with
    the same rule selection and ``--json``, and hashes each baseline finding's
    primary source line into a location-stable key. The current scan suppresses
    any finding whose key is in this set (i.e. it already existed at ``ref``).
    """
    try:
        rel_target = scan_target.resolve().relative_to(repo_root.resolve())
    except ValueError as exc:  # scan target is outside the repo
        raise BaselineCommitError(
            f"scan target {scan_target} is not inside the git repo at {repo_root}"
        ) from exc

    with tempfile.TemporaryDirectory(prefix="flawed-baseline-") as tmp:
        worktree = Path(tmp) / "wt"
        try:
            managed_process.run(
                ["git", "-C", str(repo_root), "worktree", "add", "--detach", str(worktree), ref],
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except (
            managed_process.CalledProcessError,
            managed_process.TimeoutExpired,
            OSError,
        ) as exc:
            detail = getattr(exc, "stderr", "") or str(exc)
            raise BaselineCommitError(f"git worktree add {ref!r} failed: {detail}") from exc

        try:
            baseline_root = worktree / rel_target
            proc = managed_process.run(
                [
                    "flawed",
                    "scan",
                    str(baseline_root),
                    "--json",
                    "--no-error",
                    "--no-progress",
                    *rule_args,
                ],
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            try:
                payload = json.loads(proc.stdout)
            except json.JSONDecodeError as exc:
                raise BaselineCommitError(
                    f"baseline scan of {ref!r} did not return JSON: {proc.stderr[:200]}"
                ) from exc
            keys: set[str] = set()
            for entry in payload.get("findings", []):
                rule_id = entry.get("rule_id", "")
                loc = entry.get("location") or {}
                keys.add(
                    location_stable_key(rule_id, baseline_root, loc.get("file"), loc.get("line"))
                )
            return frozenset(keys)
        finally:
            managed_process.run(
                ["git", "-C", str(repo_root), "worktree", "remove", "--force", str(worktree)],
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout_seconds,
            )
