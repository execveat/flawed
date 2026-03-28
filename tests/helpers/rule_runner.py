"""Run example detection rules against a fixture repository.

This helper is intentionally small and path-oriented so planning items can triage
rule modules before they are packaged as importable Python modules.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import sys
import traceback
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, cast

from flawed import open_repo
from flawed.evidence import Finding

if TYPE_CHECKING:
    from types import ModuleType

RuleDetect = Callable[[object], object]


class RuleStatus(StrEnum):
    """Outcome for a single rule module run."""

    PASS = "pass"
    NO_FINDINGS = "no-findings"
    FAIL = "fail"
    ERROR = "error"


@dataclass(frozen=True)
class RuleResult:
    """Collected result from running one rule module."""

    rule_path: Path
    rule_name: str
    status: RuleStatus
    findings: tuple[Finding, ...] = ()
    message: str | None = None
    traceback_text: str | None = None

    @property
    def succeeded(self) -> bool:
        """Return true when the rule executed to completion."""
        return self.status in {RuleStatus.PASS, RuleStatus.NO_FINDINGS}


def run_rules(repo: object, rule_paths: Iterable[Path]) -> tuple[RuleResult, ...]:
    """Run each rule module against *repo* and return structured results."""
    return tuple(run_rule(repo, rule_path) for rule_path in rule_paths)


def run_rule(repo: object, rule_path: Path) -> RuleResult:
    """Load *rule_path*, call its ``detect(repo)``, and classify the outcome."""
    resolved_path = rule_path.resolve()
    try:
        module = _load_module(resolved_path)
    except Exception as exc:
        return RuleResult(
            rule_path=rule_path,
            rule_name=rule_path.stem,
            status=RuleStatus.ERROR,
            message=f"import failed: {exc}",
            traceback_text=traceback.format_exc(),
        )

    detect = getattr(module, "detect", None)
    return _run_detect(repo, rule_path, detect)


def _run_detect(repo: object, rule_path: Path, detect: object) -> RuleResult:
    if not callable(detect):
        return RuleResult(
            rule_path=rule_path,
            rule_name=rule_path.stem,
            status=RuleStatus.FAIL,
            message="module does not define callable detect(repo)",
        )

    rule_name = str(getattr(detect, "__detector_name__", rule_path.stem))
    detect_fn = cast("RuleDetect", detect)
    try:
        detected = detect_fn(repo)
    except Exception as exc:
        return RuleResult(
            rule_path=rule_path,
            rule_name=rule_name,
            status=RuleStatus.ERROR,
            message=f"detect() failed: {exc}",
            traceback_text=traceback.format_exc(),
        )

    try:
        iterator = iter(cast("Iterable[object]", detected))
    except TypeError:
        return RuleResult(
            rule_path=rule_path,
            rule_name=rule_name,
            status=RuleStatus.FAIL,
            message="detect(repo) did not return an iterable",
        )

    try:
        items = tuple(iterator)
    except Exception as exc:
        return RuleResult(
            rule_path=rule_path,
            rule_name=rule_name,
            status=RuleStatus.ERROR,
            message=f"detect() iteration failed: {exc}",
            traceback_text=traceback.format_exc(),
        )

    non_findings = tuple(item for item in items if not isinstance(item, Finding))
    if non_findings:
        type_names = ", ".join(type(item).__name__ for item in non_findings[:3])
        return RuleResult(
            rule_path=rule_path,
            rule_name=rule_name,
            status=RuleStatus.FAIL,
            message=f"detect(repo) yielded non-Finding object(s): {type_names}",
        )

    findings = cast("tuple[Finding, ...]", items)
    status = RuleStatus.PASS if findings else RuleStatus.NO_FINDINGS
    return RuleResult(
        rule_path=rule_path,
        rule_name=rule_name,
        status=status,
        findings=findings,
    )


def format_report(results: Sequence[RuleResult]) -> str:
    """Return a stable text report for CLI and agent logs."""
    counts = Counter(result.status for result in results)
    lines = [
        "Rule runner: "
        f"{counts[RuleStatus.PASS]} pass, "
        f"{counts[RuleStatus.NO_FINDINGS]} no-findings, "
        f"{counts[RuleStatus.FAIL]} fail, "
        f"{counts[RuleStatus.ERROR]} error",
    ]

    for result in results:
        lines.append(_format_result(result))
        lines.extend(
            f"  - {finding.route_endpoint}: {finding.summary}" for finding in result.findings
        )
        if result.message is not None:
            lines.append(f"  {result.message}")

    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for ``python -m tests.helpers.rule_runner``."""
    parser = argparse.ArgumentParser(
        description="Run detection rule modules against a fixture path.",
    )
    parser.add_argument("fixture_path", type=Path, help="Fixture app path to analyze.")
    parser.add_argument("rule_modules", nargs="+", type=Path, help="Rule module .py files.")
    args = parser.parse_args(argv)

    fixture_path = args.fixture_path
    rule_paths = tuple(args.rule_modules)
    usage_error = _validate_paths(fixture_path, rule_paths)
    if usage_error is not None:
        parser.error(usage_error)

    try:
        repo = open_repo(str(fixture_path))
    except Exception as exc:
        print(f"ERROR fixture analysis failed: {exc}", file=sys.stderr)
        return 1

    results = run_rules(repo, rule_paths)
    print(format_report(results))
    return 0 if all(result.succeeded for result in results) else 1


def _load_module(path: Path) -> ModuleType:
    module_name = _module_name(path)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        msg = f"cannot load module from {path}"
        raise ImportError(msg)

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _module_name(path: Path) -> str:
    digest = hashlib.sha256(str(path).encode()).hexdigest()[:12]
    safe_stem = path.stem.replace("-", "_")
    return f"_flawed_rule_runner_{safe_stem}_{digest}"


def _format_result(result: RuleResult) -> str:
    finding_count = len(result.findings)
    noun = "finding" if finding_count == 1 else "findings"
    return (
        f"{result.status.value.upper()} {result.rule_name} "
        f"({result.rule_path}) — {finding_count} {noun}"
    )


def _validate_paths(fixture_path: Path, rule_paths: Sequence[Path]) -> str | None:
    if not fixture_path.exists():
        return f"fixture path does not exist: {fixture_path}"
    if not fixture_path.is_dir() and fixture_path.suffix != ".py":
        return f"fixture path must be a directory or Python file: {fixture_path}"

    for rule_path in rule_paths:
        if not rule_path.exists():
            return f"rule module does not exist: {rule_path}"
        if not rule_path.is_file() or rule_path.suffix != ".py":
            return f"rule module must be a Python file: {rule_path}"
    return None


if __name__ == "__main__":
    raise SystemExit(main())
