"""Rich-based output formatting.

Single owner of all terminal output.  Every message, table, panel, and
progress indicator goes through :class:`Console`.  No bare ``print()``
anywhere in the CLI.

Stream discipline (FLAW-141): the *product* goes to stdout, everything else
to stderr.  Findings (human list or JSON) and data listings (``config show``,
``rules list``, ``providers list``) are results -> **stdout**.  Progress,
timings, warnings, panels, the scan-summary banner, and the findings headline/
footer are diagnostics -> **stderr**.  This keeps ``flawed scan repo > out.txt``
and ``flawed scan repo | jq`` clean while an interactive user still sees the
context on screen.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.console import Console as RichConsole
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from flawed.severity import DEFAULT_SEVERITY, Severity

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from typing import IO

    from flawed._cli._observability import ScanMetrics
    from flawed._cli.rules import RuleExplanation, RuleFinding, RuleSummary
    from flawed._cli.suppression import SuppressionRecord
    from flawed._config.schema import ResolvedConfig
    from flawed.core import Location
    from flawed.evidence import Evidence, Finding


def _resolve_color(color: str) -> str:
    """Resolve ``auto`` against ``NO_COLOR``/``FORCE_COLOR`` (NO_COLOR wins)."""
    if color not in ("auto", "always", "never"):
        color = "auto"
    if color == "auto":
        if os.environ.get("NO_COLOR"):
            return "never"
        if os.environ.get("FORCE_COLOR"):
            return "always"
    return color


@lru_cache(maxsize=1)
def _rules_package_parent() -> Path:
    """Directory that contains the ``flawed`` package.

    ``builtin_rules_dir()`` is ``<...>/flawed/_rules``, so its grandparent is the
    directory holding the ``flawed`` package — the anchor that makes built-in
    rule paths render as the portable ``flawed/_rules/…`` rather than an absolute
    install path.
    """
    from flawed._rules import builtin_rules_dir

    return builtin_rules_dir().parent.parent


def _display_rule_path(path: Path) -> str:
    """Render a rule's source path portably — never an absolute machine path.

    Built-in rules render package-relative (``flawed/_rules/endpoints.py``)
    so provenance is stable across machines and installs; a rule living outside
    the ``flawed`` package falls back to a path relative to the current
    directory. The result is always relative and POSIX-style, so machine output
    (``--json``, the rule inventory) leaks no home or install path.
    """
    path = Path(path)
    try:
        return path.relative_to(_rules_package_parent()).as_posix()
    except ValueError:
        return Path(os.path.relpath(path, Path.cwd())).as_posix()


def _make_rich(file: IO[str], color: str, width: int | None) -> RichConsole:
    """Build a Rich console with explicit colour control.

    ``always`` forces ANSI even into a pipe (``--color=always``); ``never``
    strips all styling even on a TTY (``--color=never``/``NO_COLOR``); ``auto``
    defers to Rich's own TTY detection.
    """
    kwargs: dict[str, Any] = {"file": file, "highlight": False}
    if width is not None:
        kwargs["width"] = width
    if color == "always":
        kwargs["force_terminal"] = True
    elif color == "never":
        kwargs["force_terminal"] = False
        kwargs["no_color"] = True
    return RichConsole(**kwargs)


#: Pattern categories a provider can declare. Single source of truth for the
#: ``providers`` count column, the per-provider breakdown, and the JSON schema.
_PROVIDER_PATTERN_ATTRS: tuple[str, ...] = (
    "routes",
    "inputs",
    "effects",
    "sinks",
    "checks",
    "lifecycle",
    "dispatches",
    "propagators",
    "dependencies",
    "proxies",
)


def _provider_pattern_counts(prov_cls: type[Any]) -> dict[str, int]:
    """Per-category declared-pattern counts for a provider class."""
    return {attr: len(getattr(prov_cls, attr, ())) for attr in _PROVIDER_PATTERN_ATTRS}


class Console:
    """Thin wrapper around :class:`rich.console.Console`.

    Enforces stderr for diagnostics and stdout for findings/data.
    Respects quiet, JSON, colour, and progress settings.
    """

    def __init__(
        self,
        *,
        verbosity: int = 0,
        quiet: bool = False,
        json_mode: bool = False,
        sarif_mode: bool = False,
        color: str = "auto",
        show_progress: bool = True,
        stdout: IO[str] | None = None,
        stderr: IO[str] | None = None,
        width: int | None = None,
    ) -> None:
        self.verbosity = verbosity
        self.quiet = quiet
        self.json_mode = json_mode
        self.sarif_mode = sarif_mode
        self.color = _resolve_color(color)
        # Progress is animated-ish noise: suppress under --quiet and --no-progress.
        self.show_progress = show_progress and not quiet
        self._out = _make_rich(stdout or sys.stdout, self.color, width)
        self._err = _make_rich(stderr or sys.stderr, self.color, width)

    @property
    def machine_mode(self) -> bool:
        """True when emitting a machine format (JSON or SARIF) on stdout.

        In machine mode, stdout carries ONLY the structured document, so all
        human chrome — progress lines, the findings headline/footer, summary
        tables — is suppressed there (diagnostics still go to stderr).
        """
        return self.json_mode or self.sarif_mode

    # ── Diagnostics (stderr) ──────────────────────────────────────

    def error(self, message: str) -> None:
        """Print an error message to stderr."""
        self._err.print(Text(f"error: {message}", style="bold red"))

    def warn(self, message: str) -> None:
        """Print a warning to stderr."""
        if not self.quiet:
            self._err.print(Text(f"warn: {message}", style="yellow"))

    def info(self, message: str) -> None:
        """Print an informational message to stderr."""
        if not self.quiet:
            self._err.print(message)

    def verbose(self, message: str, *, level: int = 1) -> None:
        """Print only when verbosity >= *level*."""
        if self.verbosity >= level:
            self._err.print(Text(message, style="dim"))

    # ── Config display (stdout: this is the product of `config show`) ──

    def show_config(self, config: ResolvedConfig, *, label: str) -> None:
        """Pretty-print resolved configuration."""
        table = Table(
            title=label,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Key", style="green")
        table.add_column("Value")

        table.add_row("data_dir", str(config.data_dir))
        table.add_row("state_dir", str(config.state_dir))
        table.add_row("repo_local", str(config.repo_local))
        table.add_row(
            "type_enrichment.enable_mypy_batch",
            str(config.type_enrichment.enable_mypy_batch),
        )
        table.add_row(
            "type_enrichment.mypy_batch_timeout_seconds",
            str(config.type_enrichment.mypy_batch_timeout_seconds),
        )
        table.add_row(
            "type_enrichment.mypy_batch_max_files",
            str(config.type_enrichment.mypy_batch_max_files),
        )

        t = config.timeouts
        table.add_row(
            "timeouts.overall",
            str(t.overall) + "s" if t.overall else "(disabled)",
        )
        table.add_row(
            "timeouts.per_layer",
            str(t.per_layer) + "s" if t.per_layer else "(disabled)",
        )
        table.add_row(
            "timeouts.per_rule",
            str(t.per_rule) + "s" if t.per_rule else "(disabled)",
        )

        prov = config.providers
        table.add_row(
            "providers.base_dir",
            str(prov.base_dir) if prov.base_dir else "(none)",
        )
        table.add_row("providers.paths", ", ".join(str(p) for p in prov.paths))
        for pid, entry in sorted(prov.entries.items()):
            table.add_row(f"providers.{pid}.enable", str(entry.enable))
            if entry.config:
                table.add_row(
                    f"providers.{pid}.config",
                    _format_dict(entry.config),
                )

        rules = config.rules
        table.add_row("rules.paths", ", ".join(str(p) for p in rules.paths))
        table.add_row("rules.include", ", ".join(rules.include))
        if rules.exclude:
            table.add_row("rules.exclude", ", ".join(rules.exclude))

        if config.meta_effects:
            for name, expr in sorted(config.meta_effects.items()):
                table.add_row(f"meta_effects.{name}", expr)

        if config.groups:
            for gname, gdef in sorted(config.groups.items()):
                table.add_row(
                    f"groups.{gname}",
                    f"repos={list(gdef.repos)}, tags={list(gdef.tags)}",
                )

        self._out.print(table)

    # ── Dry-run display ───────────────────────────────────────────

    def show_dry_run(
        self,
        *,
        target: str,
        repo_id: str,
        data_dir: str,
    ) -> None:
        """Show what a scan would do without executing."""
        panel = Panel(
            f"[bold]Target[/]    {target}\n"
            f"[bold]Repo ID[/]   {repo_id}\n"
            f"[bold]Data dir[/]  {data_dir}",
            title="[yellow]dry run[/yellow]",
            border_style="yellow",
        )
        self._err.print(panel)

    # ── Pipeline status (stderr; suppressed by --no-progress/--quiet) ──

    def status(self, message: str) -> None:
        """Print a pipeline step status line."""
        if self.show_progress and not self.machine_mode:
            self._err.print(Text(f"  → {message}", style="cyan"))

    def success(self, message: str) -> None:
        """Print a success message."""
        if self.show_progress:
            self._err.print(Text(f"  ✓ {message}", style="bold green"))

    @contextmanager
    def phase(self, name: str) -> Iterator[None]:
        """Time a named pipeline phase and print duration in verbose mode.

        Usage::

            with console.phase("L1 index"):
                index = build_index(...)
        """
        start = time.monotonic()
        yield
        elapsed = time.monotonic() - start
        self.verbose(f"[{elapsed:.1f}s] {name}")

    def finding_count(self, count: int, *, rule_count: int = 0) -> None:
        """Print the final findings summary."""
        if self.quiet or self.machine_mode:
            return
        if count == 0:
            self._err.print(Text("No findings.", style="green"))
        else:
            style = "bold red" if count > 0 else "yellow"
            msg = f"Found {count} finding(s)"
            if rule_count > 0:
                msg += f" across {rule_count} rule(s)"
            msg += "."
            self._err.print(Text(msg, style=style))

    def show_scan_summary(self, findings: Sequence[RuleFinding]) -> None:
        """Print a per-rule findings breakdown table to stderr."""
        if self.quiet or self.machine_mode or not findings:
            return

        from collections import Counter as _Counter

        by_rule: dict[str, int] = dict(_Counter(f.rule_id for f in findings).most_common())
        rules_with_findings = len(by_rule)
        total = sum(by_rule.values())

        table = Table(
            title="Findings by Rule",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Rule", style="green")
        table.add_column("Count", justify="right")

        for rule_id, count in by_rule.items():
            table.add_row(rule_id, str(count))

        table.add_row("[bold]Total[/bold]", f"[bold]{total}[/bold]")
        self._err.print(table)
        self._err.print(
            Text(
                f"{total} finding(s) from {rules_with_findings} rule(s)",
                style="dim",
            )
        )

    # ── Provider / rule / semantic display ──────────────────────────

    def show_providers(self, providers: Sequence[type[Any]]) -> None:
        """Display the available semantic providers: ID, Library, Patterns.

        The old ``Version`` column was dropped (every provider reports the same
        placeholder ``0.1.0`` — dead signal). ``providers list`` is repo-less,
        so active/detected status lives in ``providers coverage`` (which scans a
        repo), not here. Use ``flawed providers show <id>`` for the per-pattern
        breakdown, or ``--json`` for a machine-readable inventory.
        """
        if self.quiet:
            return
        if not providers:
            self.info("No providers found.")
            return

        table = Table(
            title=f"Available providers ({len(providers)})",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("ID", style="green", no_wrap=True)
        table.add_column("Library")
        table.add_column("Patterns", justify="right")

        for prov_cls in providers:
            meta = prov_cls.meta
            total = sum(_provider_pattern_counts(prov_cls).values())
            table.add_row(meta.id, meta.library, str(total))

        self._out.print(table)

    def emit_providers_json(self, providers: Sequence[type[Any]]) -> None:
        """Emit the provider inventory as stable JSON (stdout)."""
        payload = [
            {
                "id": prov_cls.meta.id,
                "library": prov_cls.meta.library,
                "version": prov_cls.meta.version,
                "patterns": sum(_provider_pattern_counts(prov_cls).values()),
                "pattern_breakdown": _provider_pattern_counts(prov_cls),
            }
            for prov_cls in providers
        ]
        self._out.file.write(f"{json.dumps(payload, indent=2, sort_keys=True)}\n")

    def show_provider_detail(self, prov_cls: type[Any]) -> None:
        """Render one provider's metadata + per-category pattern breakdown."""
        if self.quiet:
            return
        meta = prov_cls.meta
        counts = _provider_pattern_counts(prov_cls)

        head = Text()
        head.append(f"{meta.id}", style="bold green")
        head.append(f"  {meta.library} {meta.version}\n", style="dim")
        if getattr(meta, "description", ""):
            head.append(f"{meta.description}\n", style="dim")
        self._out.print(head)

        table = Table(show_header=True, header_style="bold cyan", title="Patterns")
        table.add_column("Category", style="green")
        table.add_column("Count", justify="right")
        for category, count in counts.items():
            if count:
                table.add_row(category, str(count))
        total = sum(counts.values())
        table.add_row(Text("total", style="bold"), Text(str(total), style="bold"))
        self._out.print(table)

    def emit_provider_detail_json(self, prov_cls: type[Any]) -> None:
        """Emit one provider's full detail as JSON (stdout)."""
        meta = prov_cls.meta
        counts = _provider_pattern_counts(prov_cls)
        payload = {
            "id": meta.id,
            "library": meta.library,
            "version": meta.version,
            "description": getattr(meta, "description", ""),
            "patterns": sum(counts.values()),
            "pattern_breakdown": counts,
        }
        self._out.file.write(f"{json.dumps(payload, indent=2, sort_keys=True)}\n")

    def show_rules(
        self,
        rules: Sequence[RuleSummary],
        *,
        paths: bool = False,
    ) -> None:
        """Display the detector inventory: id, severity, description, stem.

        Showing both the hyphenated rule id AND the underscore filename *stem*
        defuses the separator ambiguity (FLAW-122) — a user can copy either
        form into ``-i``/``--include``.  Pass *paths* (``--paths``) to add the
        absolute module path.
        """
        if self.quiet:
            return
        if not rules:
            self.info("No rules found.")
            return

        table = Table(
            title=f"Detection rules ({len(rules)})",
            show_header=True,
            header_style="bold cyan",
            expand=False,
        )
        table.add_column("Rule ID", style="green", no_wrap=True)
        table.add_column("Sev", no_wrap=True)
        table.add_column("Description")
        table.add_column("Stem", style="dim", no_wrap=True)
        if paths:
            table.add_column("Path", style="dim")

        for rule in rules:
            sev = rule.severity
            sev_cell = Text(sev.label.upper(), style=f"bold {sev.style}")
            row: list[Any] = [rule.rule_id, sev_cell, rule.description or "—", rule.stem]
            if paths:
                row.append(_display_rule_path(rule.path))
            table.add_row(*row)

        self._out.print(table)

    def emit_rules_json(self, rules: Sequence[RuleSummary]) -> None:
        """Emit the detector inventory as stable JSON (stdout)."""
        payload = [
            {
                "rule_id": rule.rule_id,
                "severity": rule.severity.label,
                "description": rule.description,
                "stem": rule.stem,
                "path": _display_rule_path(rule.path),
            }
            for rule in rules
        ]
        self._out.file.write(f"{json.dumps(payload, indent=2, sort_keys=True)}\n")

    # ── Rule explanation (stdout: product of `explain`) ───────────

    def show_explanation(self, explanation: RuleExplanation) -> None:
        """Render ``flawed explain <rule>``: id, severity, prose, suppress, see-also.

        The prose body is the rule module's own docstring — authored beside the
        detector, so it never drifts from the implementation.
        """
        sev = explanation.severity
        head = Text()
        head.append(f"{explanation.rule_id}  ", style="bold green")
        head.append(f"{sev.label.upper()}", style=f"bold {sev.style}")
        self._out.print(head)
        if explanation.description:
            self._out.print(Text(explanation.description, style="bold"))
        self._out.print(Text(f"{explanation.stem}  ·  {explanation.path}", style="dim"))
        self._out.print()

        if explanation.doc:
            self._out.print(Text(explanation.doc))
            self._out.print()

        suppress = Text()
        suppress.append("Suppress  ", style="bold")
        suppress.append(f"# flawed: ignore[{explanation.rule_id}]", style="dim")
        self._out.print(suppress)
        if explanation.see_also:
            see = Text()
            see.append("See also  ", style="bold")
            see.append(", ".join(explanation.see_also), style="dim")
            self._out.print(see)

    def emit_explanation_json(self, explanation: RuleExplanation) -> None:
        """Emit a rule explanation as JSON (stdout)."""
        payload = {
            "rule_id": explanation.rule_id,
            "severity": explanation.severity.label,
            "description": explanation.description,
            "doc": explanation.doc,
            "stem": explanation.stem,
            "path": str(explanation.path),
            "see_also": list(explanation.see_also),
            "suppress": f"# flawed: ignore[{explanation.rule_id}]",
        }
        self._out.file.write(f"{json.dumps(payload, indent=2, sort_keys=True)}\n")

    # ── Orientation dashboard (stdout: bare `flawed`) ─────────────

    def show_dashboard(
        self,
        *,
        version: str,
        config: ResolvedConfig,
        rule_count: int,
        smoke_count: int,
        cwd: Path,
        is_git_repo: bool,
        looks_like_python: bool,
        dry_run: bool = False,
    ) -> None:
        """Render the bare-``flawed`` orientation dashboard (fast; no L1/L2).

        Goes to stdout so ``flawed | …`` is inspectable, mirroring how a
        well-mannered tool orients rather than silently acting.
        """
        body = Text()
        body.append("flawed ", style="bold")
        body.append(f"{version}\n", style="cyan")
        body.append("Static analysis for Python codebases.\n\n", style="dim")

        body.append("Rules    ", style="bold")
        body.append(f"{rule_count} built-in", style="green")
        body.append(f"  (default)  ·  {smoke_count} in --smoke set\n", style="dim")

        body.append("Cache    ", style="bold")
        body.append(f"{config.data_dir}\n", style="dim")

        body.append("Here     ", style="bold")
        target_bits: list[str] = []
        target_bits.append("git repo" if is_git_repo else "not a git repo")
        if looks_like_python:
            target_bits.append("Python sources detected")
        body.append(f"{cwd}", style="green" if looks_like_python else "yellow")
        body.append(f"  ({', '.join(target_bits)})\n", style="dim")

        self._out.print(Panel(body, title="flawed", border_style="cyan", expand=False))

        hint = Text()
        if dry_run:
            hint.append("--dry-run needs a target: ", style="yellow")
            hint.append("flawed scan . --dry-run\n", style="bold")
        hint.append("Scan     ", style="bold")
        hint.append("flawed .", style="bold green")
        hint.append("  (this dir)   ", style="dim")
        hint.append("flawed /path/to/repo\n", style="bold green")
        hint.append("Explore  ", style="bold")
        hint.append("flawed rules", style="bold")
        hint.append("   inventory      ", style="dim")
        hint.append("flawed config show", style="bold")
        hint.append("   resolved config\n", style="dim")
        hint.append("Help     ", style="bold")
        hint.append("flawed --help", style="bold")
        hint.append("   all commands", style="dim")
        self._out.print(hint)

    def show_scan_metrics(self, metrics: ScanMetrics) -> None:
        """Print the scan summary banner to stderr (always shown)."""
        if self.quiet:
            return

        status = metrics.status_label()
        style = "bold green" if status == "COMPLETE" else "bold red"

        lines = [
            f"[bold]Target:[/]     {metrics.target}",
            f"[bold]Rules:[/]      {metrics.rules_loaded} loaded, "
            f"{metrics.rules_executed} executed, "
            f"{metrics.rules_skipped} skipped",
        ]
        findings_line = f"[bold]Findings:[/]   {metrics.finding_count}"
        if metrics.findings_truncated:
            findings_line += f" ({metrics.retained_finding_count} retained for output)"
        lines.append(findings_line)

        timing = (
            f"L1={metrics.phase_seconds('L1'):.1f}s "
            f"L2={metrics.phase_seconds('L2'):.1f}s "
            f"L3={metrics.phase_seconds('L3'):.1f}s "
            f"total={metrics.total_seconds:.1f}s"
        )
        lines.append(f"[bold]Time:[/]       {timing}")
        lines.append(f"[bold]Status:[/]     [{style}]{status}[/{style}]")

        if metrics.timed_out_rules:
            lines.append(f"[bold]Timed out:[/]  {', '.join(metrics.timed_out_rules)}")
        if metrics.findings_truncated:
            lines.append(
                "[bold]Output:[/]     "
                f"truncated to {metrics.retained_finding_count} retained finding(s)"
            )

        panel = Panel(
            "\n".join(lines),
            title="[cyan]Scan Summary[/cyan]",
            border_style="cyan",
        )
        self._err.print(panel)

    # ── Findings (the flagship surface) ─────────────────────────────

    def show_findings(
        self,
        findings: Sequence[RuleFinding],
        *,
        metrics: ScanMetrics | None = None,
        suppressed: Sequence[SuppressionRecord] = (),
    ) -> None:
        """Render findings: JSON to stdout, or a grouped severity-led list.

        Human mode groups findings by file, sorts worst-severity-first, and
        prints each finding on its own stacked card so ``file:line:col`` is
        never truncated.  The findings themselves go to stdout (the product);
        the one-line headline and the summary footer go to stderr so a redirect
        captures only findings.

        ``findings`` are the active (shown) findings; ``suppressed`` records are
        hidden from the human list (a count is shown) but emitted, flagged, in
        ``--json``/``--sarif`` (FLAW-148).
        """
        if self.sarif_mode:
            self._emit_sarif(findings, suppressed)
            return
        if self.json_mode:
            self._emit_json(findings, metrics, suppressed)
            return

        if metrics is not None and metrics.findings_truncated:
            self.warn(
                "Output truncated: showing "
                f"{metrics.retained_finding_count} of {metrics.finding_count} finding(s)."
            )

        # Headline -> stderr (always, even for zero findings).
        if not self.quiet:
            self._err.print(self._findings_headline(findings, metrics))

        for file_path, group in self._group_by_file(findings):
            self._out.print(Text(file_path, style="bold"))
            for item in group:
                self._render_finding(item)
            self._out.print()  # blank line between file groups

        if not self.quiet:
            if suppressed:
                self._err.print(self._suppressed_note(suppressed))
            self._err.print(self._findings_footer(findings))

    @staticmethod
    def _suppressed_note(suppressed: Sequence[SuppressionRecord]) -> Text:
        """One dim line summarising suppressed findings by source (stderr)."""
        by_source: dict[str, int] = {}
        for rec in suppressed:
            by_source[rec.source] = by_source.get(rec.source, 0) + 1
        detail = "  ·  ".join(f"{count} {source}" for source, count in sorted(by_source.items()))
        note = Text("Suppressed  ", style="bold yellow")
        note.append(f"{len(suppressed)} hidden", style="yellow")
        note.append(f"  ({detail})  · still in --json/--sarif", style="dim")
        return note

    def _render_finding(self, item: RuleFinding) -> None:
        """Render one finding as a stacked card to stdout (never truncates)."""
        finding = item.finding
        sev = _severity_of(finding)

        head = Text("  ")
        head.append(f"{sev.glyph} ", style=sev.style)
        head.append(f"{sev.label.upper():<8} ", style=f"bold {sev.style}")
        head.append(item.rule_id, style="cyan")
        linecol = _location_linecol(finding.location)
        if linecol:
            head.append("  ")
            head.append(linecol, style="green")
        self._out.print(head)

        self._out.print(Text(f"      {finding.summary}"))

        if self.verbosity >= 1 and finding.evidence_items:
            for evidence in finding.evidence_items:
                self._out.print(Text(f"        ↳ {_format_evidence(evidence)}", style="dim"))
        elif finding.evidence_items:
            count = len(finding.evidence_items)
            self._out.print(Text(f"      {count} evidence step(s) · -v to expand", style="dim"))

        # Action footer (teaching the next move; ties CLI to explain/suppress).
        footer = Text("      ")
        footer.append("explain ", style="dim")
        footer.append(f"flawed explain {item.rule_id}", style="dim cyan")
        footer.append("    suppress ", style="dim")
        footer.append(f"# flawed: ignore[{item.rule_id}]", style="dim")
        self._out.print(footer)

    def _findings_headline(
        self,
        findings: Sequence[RuleFinding],
        metrics: ScanMetrics | None,
    ) -> Text:
        """One-line severity-coloured headline for the findings (stderr)."""
        n = len(findings)
        if n == 0:
            return Text("No findings.", style="green")

        counts = _severity_counts(findings)
        head = Text()
        head.append(f"{n} finding{'s' if n != 1 else ''}", style="bold")
        for sev in Severity.ordered():
            count = counts.get(sev, 0)
            if count:
                head.append("  ·  ", style="dim")
                head.append(f"{count} {sev.label}", style=sev.style)
        if metrics is not None:
            head.append("  ·  ", style="dim")
            head.append(f"{metrics.total_seconds:.1f}s", style="dim")
        return head

    def _findings_footer(self, findings: Sequence[RuleFinding]) -> Text:
        """Summary footer with a next-step hint (stderr)."""
        counts = _severity_counts(findings)
        parts = [
            f"{counts.get(sev, 0)} {sev.label}" for sev in Severity.ordered() if counts.get(sev, 0)
        ]
        foot = Text("Summary  ", style="bold")
        foot.append(f"{len(findings)} findings", style="bold")
        if parts:
            foot.append("  ·  " + "  ·  ".join(parts), style="dim")
        foot.append("\nNext     ", style="bold")
        foot.append("-v for data-flow evidence  ·  --json for machine output", style="dim")
        return foot

    def _emit_json(
        self,
        findings: Sequence[RuleFinding],
        metrics: ScanMetrics | None,
        suppressed: Sequence[SuppressionRecord] = (),
    ) -> None:
        """Emit the machine-readable JSON payload to stdout.

        ``finding_count`` is the real count of active (non-suppressed) findings
        except when the output was truncated, where it preserves the total
        detected pre-truncation (and ``findings_truncated`` flags the
        difference).  This guarantees ``finding_count == len(findings)`` whenever
        not truncated (FLAW-142).  Suppressed findings are still emitted in the
        ``findings`` array flagged ``suppressed: true`` (never silently dropped —
        FLAW-148); ``suppressed_count`` reports how many.
        """
        truncated = metrics.findings_truncated if metrics is not None else False
        if metrics is not None and truncated:
            finding_count = metrics.finding_count
        else:
            finding_count = len(findings)
        retained_count = (
            metrics.retained_finding_count
            if metrics is not None and metrics.retained_finding_count
            else len(findings)
        )
        entries = [_finding_to_dict(finding) for finding in findings]
        entries.extend(_finding_to_dict(rec.finding, suppression=rec) for rec in suppressed)
        payload: dict[str, object] = {
            "finding_count": finding_count,
            "retained_finding_count": retained_count,
            "findings_truncated": truncated,
            "suppressed_count": len(suppressed),
            "findings": entries,
        }
        if metrics is not None:
            payload["metadata"] = metrics.to_metadata_dict()
        self._out.file.write(f"{json.dumps(payload, indent=2, sort_keys=True)}\n")
        self._out.file.flush()

    def _emit_sarif(
        self,
        findings: Sequence[RuleFinding],
        suppressed: Sequence[SuppressionRecord] = (),
    ) -> None:
        """Emit a SARIF 2.1.0 log to stdout.

        The SARIF is COMPLETE — it always contains every retained finding,
        independent of ``--fail-on``/``--min-severity`` (which govern the exit
        code and the human display, not the machine artifact). That keeps
        GitHub/GitLab code-scanning uploads from silently dropping findings
        (the trivy footgun). See FLAW-146. Suppressed findings appear as results
        with a ``suppressions`` array (codeql ``InSource`` model — FLAW-148).
        """
        log = build_sarif_log(findings, suppressed)
        self._out.file.write(f"{json.dumps(log, indent=2, sort_keys=True)}\n")
        self._out.file.flush()

    @staticmethod
    def _group_by_file(
        findings: Sequence[RuleFinding],
    ) -> list[tuple[str, list[RuleFinding]]]:
        """Group findings by file, files ordered by worst severity then path.

        Within each file, findings are sorted worst-severity-first then by line.
        """
        groups: dict[str, list[RuleFinding]] = {}
        for item in findings:
            groups.setdefault(_location_file(item.finding.location), []).append(item)

        def finding_rank(it: RuleFinding) -> tuple[int, int]:
            return (-int(_severity_of(it.finding)), _location_line(it.finding.location))

        for group in groups.values():
            group.sort(key=finding_rank)

        def file_rank(entry: tuple[str, list[RuleFinding]]) -> tuple[int, str]:
            worst = max(int(_severity_of(it.finding)) for it in entry[1])
            return (-worst, entry[0])

        return sorted(groups.items(), key=file_rank)

    def show_semantic_summary(
        self,
        *,
        active_providers: tuple[str, ...],
        route_count: int,
        gap_count: int,
    ) -> None:
        """Display L2 semantic analysis summary."""
        if self.quiet:
            return

        providers_str = ", ".join(active_providers) if active_providers else "(none)"
        panel = Panel(
            f"[bold]Providers[/]  {providers_str}\n"
            f"[bold]Routes[/]     {route_count}\n"
            f"[bold]Gaps[/]       {gap_count}",
            title="[green]L2 Semantic Analysis[/green]",
            border_style="green",
        )
        self._err.print(panel)


def _format_dict(d: dict[str, Any]) -> str:
    return ", ".join(f"{k}={v!r}" for k, v in sorted(d.items()))


def _finding_to_dict(
    item: RuleFinding, *, suppression: SuppressionRecord | None = None
) -> dict[str, Any]:
    finding = item.finding
    payload: dict[str, Any] = {
        "rule_id": item.rule_id,
        "rule_path": _display_rule_path(item.rule_path),
        "fingerprint": item.fingerprint,
        "severity": _finding_severity(finding),
        "route_endpoint": finding.route_endpoint,
        "summary": finding.summary,
        "location": _location_to_dict(finding.location),
        "evidence": [_evidence_to_dict(evidence) for evidence in finding.evidence_items],
        "gaps": [
            {
                "kind": gap.kind.value,
                "message": gap.message,
                "affected_file": gap.affected_file,
                "affected_function": gap.affected_function,
            }
            for gap in finding.gaps
        ],
        # Suppressed findings are emitted (never silently dropped) and flagged,
        # so suppressions stay auditable in machine output (FLAW-148).
        "suppressed": suppression is not None,
    }
    if suppression is not None:
        payload["suppression"] = {
            "source": suppression.source,
            "kind": suppression.kind,
            "reason": suppression.reason,
            "justification": suppression.justification,
        }
    return payload


def _evidence_to_dict(evidence: Evidence) -> dict[str, Any]:
    return {
        "description": evidence.description,
        "location": _location_to_dict(evidence.location),
    }


def _location_to_dict(location: Location | None) -> dict[str, int | str | None] | None:
    if location is None:
        return None
    return {
        "file": location.file,
        "line": location.line,
        "column": location.column,
        "end_line": location.end_line,
        "end_column": location.end_column,
    }


# ── SARIF 2.1.0 (FLAW-146) ────────────────────────────────────────
# The security-tool lingua franca: trivy/grype/codeql all emit it, and
# it unlocks free GitHub/GitLab code-scanning upload.

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
_SARIF_INFO_URI = "https://github.com/execveat/flawed"

# GitHub code scanning reads `security-severity` (a 0-10 string) to bucket
# results into its own critical/high/medium/low bands.
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def build_sarif_log(
    findings: Sequence[RuleFinding],
    suppressed: Sequence[SuppressionRecord] = (),
) -> dict[str, Any]:
    """Build a complete SARIF 2.1.0 log object from ``findings``.

    ``tool.driver.rules`` lists each distinct rule (id, level, description);
    ``results`` lists every finding with its location, level, and a stable
    ``partialFingerprints`` entry so code-scanning backends can track a finding
    across runs. Findings are never filtered here — completeness is the point.
    Suppressed findings are included as results carrying a ``suppressions``
    array (codeql ``InSource`` model) so they remain visible and auditable
    (FLAW-148).
    """
    try:
        from flawed import __version__

        version = __version__
    except Exception:
        version = "unknown"

    rule_indices: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    def _register_rule(item: RuleFinding, sev: Severity) -> int:
        rule_id = item.rule_id
        if rule_id not in rule_indices:
            rule_indices[rule_id] = len(rules)
            rules.append(
                {
                    "id": rule_id,
                    "name": _sarif_rule_name(rule_id),
                    "shortDescription": {"text": _sarif_rule_description(item.finding, rule_id)},
                    "defaultConfiguration": {"level": sev.sarif_level},
                    "properties": {
                        "security-severity": _SECURITY_SEVERITY[sev],
                        "severity": sev.label,
                        "tags": ["security"],
                    },
                }
            )
        return rule_indices[rule_id]

    for item in findings:
        sev = _severity_of(item.finding)
        results.append(_sarif_result(item, sev, _register_rule(item, sev)))
    for record in suppressed:
        item = record.finding
        sev = _severity_of(item.finding)
        results.append(_sarif_result(item, sev, _register_rule(item, sev), suppression=record))

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "flawed",
                        "version": version,
                        "informationUri": _SARIF_INFO_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _sarif_rule_name(rule_id: str) -> str:
    """A CamelCase display token for the rule (SARIF ``name``)."""
    return "".join(part.capitalize() for part in re.split(r"[-_]+", rule_id) if part) or rule_id


def _sarif_rule_description(finding: Finding, rule_id: str) -> str:
    summary = finding.summary or ""
    first_line = summary.strip().splitlines()[0] if summary.strip() else ""
    return first_line or rule_id


def _sarif_result(
    item: RuleFinding,
    sev: Severity,
    rule_index: int,
    *,
    suppression: SuppressionRecord | None = None,
) -> dict[str, Any]:
    finding = item.finding
    locations: list[dict[str, Any]] = []
    sarif_loc = _sarif_location(finding.location)
    if sarif_loc is not None:
        locations.append(sarif_loc)
    result: dict[str, Any] = {
        "ruleId": item.rule_id,
        "ruleIndex": rule_index,
        "level": sev.sarif_level,
        "message": {"text": finding.summary or item.rule_id},
        "locations": locations,
        "partialFingerprints": {"flawedFingerprint/v1": item.fingerprint},
        "properties": {"severity": sev.label},
    }
    if suppression is not None:
        entry: dict[str, Any] = {"kind": suppression.kind}
        if suppression.justification:
            entry["justification"] = suppression.justification
        result["suppressions"] = [entry]
    return result


def _sarif_location(location: Location | None) -> dict[str, Any] | None:
    if location is None or not location.file:
        return None
    physical: dict[str, Any] = {"artifactLocation": {"uri": location.file}}
    # SARIF requires region.startLine when a region is present, so only attach
    # a region once we have a line (columns/end are optional refinements).
    if location.line:
        region: dict[str, int] = {"startLine": location.line}
        if location.column:
            region["startColumn"] = location.column
        if location.end_line:
            region["endLine"] = location.end_line
        if location.end_column:
            region["endColumn"] = location.end_column
        physical["region"] = region
    return {"physicalLocation": physical}


def _format_evidence(evidence: Evidence) -> str:
    return f"{_format_location(evidence.location)} {evidence.description}"


def _format_location(location: Location | None) -> str:
    if location is None:
        return "(unknown)"
    return f"{location.file}:{location.line}"


def _location_file(location: Location | None) -> str:
    """File path for grouping; a stable placeholder when unknown."""
    if location is None:
        return "(unknown location)"
    return location.file


def _location_line(location: Location | None) -> int:
    return location.line if location is not None else 0


def _location_linecol(location: Location | None) -> str:
    """``:line:col`` suffix shown under a file group header (never truncated)."""
    if location is None:
        return ""
    if location.column:
        return f":{location.line}:{location.column}"
    return f":{location.line}"


def _severity_of(finding: Finding) -> Severity:
    """The finding's declared severity, or the default when unset."""
    return finding.severity if finding.severity is not None else DEFAULT_SEVERITY


def _severity_counts(findings: Sequence[RuleFinding]) -> dict[Severity, int]:
    counts: dict[Severity, int] = {}
    for item in findings:
        sev = _severity_of(item.finding)
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _finding_severity(finding: Finding) -> str:
    """Severity label of a finding, read from its declared severity.

    Findings carry a real :class:`~flawed.severity.Severity` stamped by the
    ``@detector`` decorator from the producing rule.  A finding with no
    severity set (e.g. constructed outside the detection engine) falls back
    to :data:`~flawed.severity.DEFAULT_SEVERITY`.
    """
    return _severity_of(finding).label
