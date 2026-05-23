"""Click command group and all CLI commands.

``flawed`` uses a custom :class:`_DefaultScanGroup` so that bare
``flawed [TARGET]`` runs the scan while ``flawed config show`` dispatches
to subcommands.  The trick: if the first word matches a registered
subcommand, Click dispatches normally; otherwise it's treated as a scan
TARGET.

Exit codes:
  0  success / no findings
  1  findings found
  2  user error (bad arguments, config error, lock held)
"""

from __future__ import annotations

import difflib
import os
import signal
import sys
import traceback
from pathlib import Path
from typing import TYPE_CHECKING

import click
from click.shell_completion import (
    CompletionItem,
    ShellComplete,
    add_completion_class,
    split_arg_string,
)

from flawed import _process as managed_process
from flawed._cli._common import _CONTEXT_SETTINGS, _Ctx, pass_ctx
from flawed._cli._observability import (
    OverallTimeoutError,
    ScanMetrics,
    configure_logging,
    overall_timeout,
)
from flawed._cli.output import Console
from flawed._cli.pipeline import (
    EXIT_INTERNAL,
    EXIT_TIMEOUT,
    PipelineError,
    run_index,
    run_provider_engine,
    run_scan,
)
from flawed._cli.profile import ScanProfiler
from flawed._cli.ribrarian_bridge import HAS_RIBRARIAN, RibrarianBridgeError
from flawed._cli.rules import (
    all_rule_ids,
    discover_rule_files,
    explain_rule,
    smoke_rule_count,
    summarize_rules,
)
from flawed._cli.suppression import (
    BaselineCommitError,
    IgnoreSpec,
    baseline_commit_keys,
)
from flawed._cli.target import (
    TargetError,
    entered_target,
    resolve_target,
    resolve_targets,
)
from flawed._config import load_config
from flawed._config.lock import LockHeldError, RepoLock
from flawed._config.match import apply_overrides
from flawed._config.schema import ConfigError, ResolvedConfig, TimeoutConfig
from flawed.severity import Severity

if TYPE_CHECKING:
    from flawed._config.paths import RepoIdentity

_EXIT_OK = 0
_EXIT_ERROR = 2
_SEVERITY_CHOICES = tuple(s.label for s in Severity.ordered())

#: Click re-invokes the program with this env var set to ``<shell>_complete``
#: when computing completions, and ``<shell>_source`` when emitting the script.
_COMPLETE_VAR = "_FLAWED_COMPLETE"
_COMPLETION_SHELLS = ("bash", "zsh", "fish", "powershell")


# ── Shell completion ─────────────────────────────────────────────


def _complete_rule_id(
    ctx: click.Context,  # noqa: ARG001
    param: click.Parameter,  # noqa: ARG001
    incomplete: str,
) -> list[CompletionItem]:
    """Dynamic completion of built-in rule ids (for ``-i``/``-e`` and ``explain``).

    Separator-insensitive (FLAW-122): typing either ``-`` or ``_`` matches.
    Reads the rule inventory metadata only — never triggers a scan. Returns the
    canonical (hyphenated) ids. Never raises: ``all_rule_ids`` swallows failures.
    """
    needle = incomplete.replace("_", "-")
    try:
        config = load_config()
    except Exception:  # completion must never break the shell
        return []
    return [
        CompletionItem(rule_id) for rule_id in all_rule_ids(config) if rule_id.startswith(needle)
    ]


def _complete_provider(
    ctx: click.Context,  # noqa: ARG001
    param: click.Parameter,  # noqa: ARG001
    incomplete: str,
) -> list[CompletionItem]:
    """Dynamic completion of semantic provider ids (for ``--provider``/``providers show``)."""
    try:
        # _discover_providers() is typed type[object]; provider classes carry a
        # ``.meta`` ProviderMeta — read it defensively (skip any without one).
        ids = sorted(
            meta.id
            for cls in _discover_providers()
            if (meta := getattr(cls, "meta", None)) is not None
        )
    except Exception:  # completion must never break the shell
        return []
    return [CompletionItem(pid) for pid in ids if pid.startswith(incomplete)]


_POWERSHELL_SOURCE = """\
Register-ArgumentCompleter -Native -CommandName %(prog_name)s -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $env:%(complete_var)s = "powershell_complete"
    $env:_FLAWED_COMPLETE_ARGS = $commandAst.ToString()
    $env:_FLAWED_COMPLETE_WORD = $wordToComplete
    %(prog_name)s | ForEach-Object {
        $parts = $_ -Split "::::", 2
        [System.Management.Automation.CompletionResult]::new(
            $parts[0], $parts[0], 'ParameterValue', $parts[1])
    }
    $env:%(complete_var)s = ""
    $env:_FLAWED_COMPLETE_ARGS = ""
    $env:_FLAWED_COMPLETE_WORD = ""
}
"""


class _PowershellComplete(ShellComplete):
    """PowerShell completion — Click ships bash/zsh/fish but not PowerShell.

    Mirrors Click's native completion protocol: the source script (printed by
    ``flawed completions powershell``) registers a native arg-completer that
    re-invokes ``flawed`` with ``_FLAWED_COMPLETE=powershell_complete`` and the
    current command line, then renders each emitted ``value::::help`` line into
    a PowerShell ``CompletionResult``.
    """

    name = "powershell"
    source_template = _POWERSHELL_SOURCE

    def get_completion_args(self) -> tuple[list[str], str]:
        line = os.environ.get("_FLAWED_COMPLETE_ARGS", "")
        incomplete = os.environ.get("_FLAWED_COMPLETE_WORD", "")
        args = split_arg_string(line)
        # Drop the program name (first token).
        if args:
            args = args[1:]
        # The word under the cursor is being completed, not a finished arg.
        if incomplete and args and args[-1] == incomplete:
            args = args[:-1]
        return args, incomplete

    def format_completion(self, item: CompletionItem) -> str:
        # Always emit a non-empty help field — the PowerShell source splits on
        # "::::" and passes the second part straight to CompletionResult.
        return f"{item.value}::::{item.help or ' '}"


add_completion_class(_PowershellComplete)


# ── Custom group: default to scan ────────────────────────────────


class _DefaultScanGroup(click.Group):
    """Group that defaults to the ``scan`` subcommand.

    When no subcommand is given (``flawed`` or ``flawed /path``),
    routes to scan.  Scan-specific options (``--dry-run``, ``-i``)
    require explicit ``flawed scan --dry-run`` — this is the standard
    Click pattern for subcommand-specific options.
    """

    def __init__(self, **kwargs: object) -> None:
        kwargs["invoke_without_command"] = True
        super().__init__(**kwargs)  # type: ignore[arg-type]

    def resolve_command(
        self,
        ctx: click.Context,
        args: list[str],
    ) -> tuple[str | None, click.Command | None, list[str]]:
        if not args:
            # Bare ``flawed`` (no subcommand, no target) orients rather than
            # silently scanning cwd (FLAW-134): route to the dashboard.
            return super().resolve_command(ctx, ["dashboard"])
        cmd_name = args[0]
        if cmd_name in self.commands:
            return super().resolve_command(ctx, args)
        # Unknown first token. It is a scan TARGET (path) unless it looks like a
        # *mistyped subcommand* — not an existing path, not an option, and close
        # to a known command name. Then we suggest rather than silently trying to
        # scan a path that does not exist (FLAW-154 did-you-mean).
        if not cmd_name.startswith("-") and not Path(cmd_name).exists():
            suggestion = _closest_command(cmd_name, self._visible_command_names(ctx))
            if suggestion is not None:
                ctx.fail(f"no such command {cmd_name!r}. Did you mean {suggestion!r}?")
        # First arg is a path (or an option) — route to scan.
        return super().resolve_command(ctx, ["scan", *args])

    def _visible_command_names(self, ctx: click.Context) -> list[str]:
        """User-facing subcommand names (hidden aliases excluded from suggestions)."""
        names: list[str] = []
        for name in self.list_commands(ctx):
            cmd = self.get_command(ctx, name)
            if cmd is not None and not cmd.hidden:
                names.append(name)
        return names


def _closest_command(word: str, names: list[str]) -> str | None:
    """Nearest visible subcommand to *word* (Levenshtein-ish), or None."""
    matches = difflib.get_close_matches(word, names, n=1, cutoff=0.6)
    return matches[0] if matches else None


def _closest_rule_ids(word: str, ids: tuple[str, ...], *, n: int = 3) -> list[str]:
    """Up to *n* rule ids closest to *word*, for did-you-mean on unknown ids."""
    return difflib.get_close_matches(word, list(ids), n=n, cutoff=0.5)


# ── Sectioned help (FLAW-153) ────────────────────────────────────
#
# Map each scan option's *param name* to a help section so grouping is
# position-independent (survives option reordering) and an unmapped option
# falls into the default "Options" group rather than vanishing from --help.

_SCAN_OPTION_SECTIONS: tuple[tuple[str, frozenset[str]], ...] = (
    (
        "Filtering",
        frozenset(
            {
                "rules_dirs",
                "smoke",
                "includes",
                "include_regexes",
                "excludes",
                "exclude_regexes",
                "force_providers",
                "disable_providers",
            }
        ),
    ),
    (
        "Output",
        frozenset(
            {
                "json_output",
                "sarif_output",
                "output_format",
                "fail_on",
                "min_severity",
                "error",
                "summary",
                "profile_output",
                "profile_tracemalloc",
                "dry_run",
                "verbose",
                "quiet",
            }
        ),
    ),
    (
        "Performance",
        frozenset(
            {
                "no_index",
                "reindex",
                "timeout_seconds",
                "layer_timeout_seconds",
                "rule_timeout_seconds",
            }
        ),
    ),
    (
        "Suppression",
        frozenset({"baseline_path", "write_baseline_path", "no_dedup"}),
    ),
    (
        "Advanced (engine internals)",
        frozenset(
            {
                "semantic",
                "data_dir",
                "enable_mypy_batch",
            }
        ),
    ),
)


class _SectionedCommand(click.Command):
    """A :class:`click.Command` whose ``--help`` groups options into sections.

    Click renders all options in one flat ``Options`` block; for the ~30-flag
    ``scan`` command that buries the handful a user actually wants under engine
    internals. We bucket by ``param.name`` via :attr:`option_sections`; anything
    unmapped lands in the leading default group so nothing is ever hidden.
    """

    def __init__(
        self,
        *args: object,
        option_sections: tuple[tuple[str, frozenset[str]], ...] = (),
        **kwargs: object,
    ) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.option_sections = option_sections

    def format_options(
        self,
        ctx: click.Context,
        formatter: click.HelpFormatter,
    ) -> None:
        section_of = {name: title for title, names in self.option_sections for name in names}
        default_title = "Options"
        buckets: dict[str, list[tuple[str, str]]] = {}
        for param in self.get_params(ctx):
            record = param.get_help_record(ctx)
            if record is None:
                continue
            title = section_of.get(param.name or "", default_title)
            buckets.setdefault(title, []).append(record)

        order = [default_title, *[title for title, _ in self.option_sections]]
        for title in order:
            records = buckets.get(title)
            if records:
                with formatter.section(title):
                    formatter.write_dl(records)


# ── Universal verbosity (FLAW-139) ───────────────────────────────
#
# ``-v``/``-q`` are accepted at the top level OR on any subcommand and
# merge into the one shared verbosity counter on ``_Ctx.console``.  They
# use ``expose_value=False`` callbacks so a command's signature is
# unchanged.  This replaces the per-command boolean ``-v`` flags that used
# to collide (``rules list -v`` / ``providers list -v`` meant "show detail").


def _bump_verbosity(ctx: click.Context, _param: object, value: int) -> int:
    if value:
        obj = ctx.find_object(_Ctx)
        if obj is not None:
            obj.console.verbosity = max(obj.console.verbosity, value)
            configure_logging(obj.console.verbosity)
    return value


def _set_quiet(ctx: click.Context, _param: object, value: bool) -> bool:
    if value:
        obj = ctx.find_object(_Ctx)
        if obj is not None:
            obj.console.quiet = True
            obj.console.show_progress = False
    return value


def _output_opts(f: click.decorators.FC) -> click.decorators.FC:
    """Attach shared ``-v``/``-q`` to a subcommand (merges with the global flags)."""
    quiet = click.option(
        "-q",
        "--quiet",
        is_flag=True,
        expose_value=False,
        callback=_set_quiet,
        help="Suppress non-finding output.",
    )
    verbose = click.option(
        "-v",
        "--verbose",
        count=True,
        expose_value=False,
        callback=_bump_verbosity,
        help="Increase verbosity (repeatable). Accepted here or before the subcommand.",
    )
    return verbose(quiet(f))


def _with_ribrarian(f: click.decorators.FC) -> click.decorators.FC:
    """Attach the repeatable ``-r/--ribrarian`` selector option — only if available.

    The option literally does not exist when ribrarian is not installed: the
    decorator returns the function untouched, so the flag is absent from
    ``--help`` and the command's ``ribrarian`` parameter falls back to its empty
    default. When ribrarian *is* installed, ``-r SELECTOR`` (repeatable) resolves
    through the bridge to one or more repo roots, each scanned in turn.

    The flag's absence in a flawed-only install is intentional (optional integration);
    do not remove this wiring. See ``ribrarian_bridge``.
    """
    if not HAS_RIBRARIAN:
        return f
    return click.option(
        "-r",
        "--ribrarian",
        "ribrarian",
        multiple=True,
        metavar="SELECTOR",
        help=(
            "Resolve a ribrarian selector (e.g. 'class:target tier:1') to repo "
            "root(s) and scan each. Repeatable; combines with positional paths."
        ),
    )(f)


# ── Version ──────────────────────────────────────────────────────


def _format_version() -> str:
    """Single source of truth for ``--version`` and the ``version`` subcommand."""
    from flawed import __version__

    return f"flawed {__version__}"


def _print_version(ctx: click.Context, _param: object, value: bool) -> None:
    """Eager ``--version`` handler: print the version and exit before any scan.

    Eager + ``expose_value=False`` so it fires during option parsing — ahead of
    ``_DefaultScanGroup``'s "unknown token is a scan target" routing — and never
    reaches the ``cli`` callback signature.
    """
    if not value or ctx.resilient_parsing:
        return
    click.echo(_format_version())
    ctx.exit()


# ── Root group ───────────────────────────────────────────────────


@click.group(cls=_DefaultScanGroup, context_settings=_CONTEXT_SETTINGS)
@click.option(
    "--version",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=_print_version,
    help="Show the engine version and exit.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Use a specific config file (skip global hierarchy).",
)
@click.option(
    "-v",
    "--verbose",
    count=True,
    help="Increase verbosity (repeat up to 3 times).",
)
@click.option(
    "-q",
    "--quiet",
    is_flag=True,
    help="Suppress non-finding output.",
)
@click.option(
    "--color",
    type=click.Choice(("auto", "always", "never")),
    default="auto",
    show_default=True,
    help="When to colourise output (honours NO_COLOR/FORCE_COLOR under 'auto').",
)
@click.option(
    "--no-progress",
    "no_progress",
    is_flag=True,
    help="Disable progress/status lines (auto-off when stderr is not a TTY or under --quiet).",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show the default scan plan without executing.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    config_path: Path | None,
    verbose: int,
    quiet: bool,
    color: str,
    no_progress: bool,
    dry_run: bool,
) -> None:
    """Static analysis engine for Python codebases.

    \b
    Examples:
      flawed                        Orientation dashboard (does not scan)
      flawed .                      Scan the current directory
      flawed /path/to/repo          Scan a specific repository
      flawed scan -i "flask-*" .    Only run flask-related rules
      flawed scan --no-semantic .   Skip Layer 2 (index only)
      flawed rules                  List detection rules
      flawed config show            Show resolved configuration
      flawed version                Show version
      flawed --version              Show version and exit
    """
    obj = _Ctx()
    obj.console = Console(
        verbosity=verbose,
        quiet=quiet,
        color=color,
        show_progress=not no_progress,
    )
    obj.config_path = config_path
    obj.root_dry_run = dry_run
    configure_logging(verbose)
    ctx.ensure_object(type(obj))
    ctx.obj = obj

    # Bare ``flawed`` (no subcommand, no target) orients rather than silently
    # scanning cwd (FLAW-134).  Click invokes this group callback directly when
    # no subcommand is resolved, so the dashboard is dispatched from here.
    if ctx.invoked_subcommand is None:
        _render_dashboard(obj)


# ── Dashboard (bare `flawed`) ────────────────────────────────────


def _render_dashboard(obj: _Ctx) -> None:
    """Gather fast orientation facts (no L1/L2) and render the dashboard."""
    from flawed import __version__

    con = obj.console
    try:
        config = load_config(config_path=obj.config_path)
    except ConfigError as exc:
        con.error(f"Configuration error: {exc}")
        sys.exit(_EXIT_ERROR)

    cwd = Path.cwd()
    looks_like_python = (
        (cwd / "pyproject.toml").exists()
        or (cwd / "setup.py").exists()
        or any(cwd.glob("*.py"))
        or any(cwd.glob("*/*.py"))
    )
    con.show_dashboard(
        version=__version__,
        config=config,
        rule_count=len(discover_rule_files(config)),
        smoke_count=smoke_rule_count(),
        cwd=cwd,
        is_git_repo=(cwd / ".git").is_dir(),
        looks_like_python=looks_like_python,
        dry_run=obj.root_dry_run,
    )


@cli.command("dashboard", hidden=True, context_settings=_CONTEXT_SETTINGS)
@pass_ctx
def dashboard_cmd(obj: _Ctx) -> None:
    """Orientation dashboard (also shown for bare ``flawed``)."""
    _render_dashboard(obj)


# ── Scan command (default) ───────────────────────────────────────


@cli.command(
    "scan",
    cls=_SectionedCommand,
    option_sections=_SCAN_OPTION_SECTIONS,
    context_settings=_CONTEXT_SETTINGS,
)
@_output_opts
@_with_ribrarian
@click.argument("targets", nargs=-1)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Alias for --output-format json.",
)
@click.option(
    "--sarif",
    "sarif_output",
    is_flag=True,
    help="Alias for --output-format sarif (SARIF 2.1.0 for code scanning).",
)
@click.option(
    "--output-format",
    type=click.Choice(("text", "json", "sarif")),
    default="text",
    show_default=True,
    help="Finding output format. sarif = SARIF 2.1.0 (always complete).",
)
@click.option(
    "--fail-on",
    type=click.Choice(_SEVERITY_CHOICES),
    default="medium",
    show_default=True,
    help=(
        "Exit 1 only when a finding at/above this severity exists, independent "
        "of what is displayed. Use with --no-error for report-only CI."
    ),
)
@click.option(
    "--min-severity",
    type=click.Choice(_SEVERITY_CHOICES),
    default=None,
    help=(
        "Hide findings below this severity in the human output. Does NOT affect "
        "--json/--sarif (kept complete) or the exit code (see --fail-on)."
    ),
)
@click.option(
    "--error/--no-error",
    "error",
    default=True,
    help="--no-error forces exit 0 even when findings exist (report-only CI).",
)
@click.option(
    "--rules-dir",
    "rules_dirs",
    multiple=True,
    type=click.Path(file_okay=False, path_type=Path),
    help=(
        "Rule directory to scan (repeatable). Overrides the built-in library; "
        "point at a directory of rule modules to run your own."
    ),
)
@click.option(
    "--smoke",
    "--quick",
    "smoke",
    is_flag=True,
    help=(
        "Run only the fast curated smoke rule set instead of the full built-in "
        "library (quick iteration / CI smoke runs). Ignored if --rules-dir is given."
    ),
)
@click.option(
    "-i",
    "--include",
    "includes",
    multiple=True,
    help="Include rules matching wildcard (repeatable).",
    shell_complete=_complete_rule_id,
)
@click.option(
    "-I",
    "--include-regex",
    "include_regexes",
    multiple=True,
    help="Include rules matching regex (repeatable).",
)
@click.option(
    "-e",
    "--exclude",
    "excludes",
    multiple=True,
    help="Exclude rules matching wildcard (repeatable).",
    shell_complete=_complete_rule_id,
)
@click.option(
    "-E",
    "--exclude-regex",
    "exclude_regexes",
    multiple=True,
    help="Exclude rules matching regex (repeatable).",
)
@click.option(
    "--provider",
    "force_providers",
    multiple=True,
    help="Force-enable a provider (repeatable).",
    shell_complete=_complete_provider,
)
@click.option(
    "--no-provider",
    "disable_providers",
    multiple=True,
    help="Force-disable a provider (repeatable).",
    shell_complete=_complete_provider,
)
@click.option("--data-dir", type=click.Path(path_type=Path), help="Override data directory.")
@click.option("--no-index", is_flag=True, help="Skip Layer 1 extraction.")
@click.option("--reindex", is_flag=True, help="Force Layer 1 re-extraction.")
@click.option(
    "--enable-mypy-batch/--disable-mypy-batch",
    default=None,
    help="Run experimental mypy batch type enrichment alongside basedpyright.",
)
@click.option("--dry-run", is_flag=True, help="Show plan without executing.")
@click.option(
    "--semantic/--no-semantic",
    default=True,
    show_default=True,
    help="Enable Layer 2 semantic analysis.",
)
@click.option(
    "--profile",
    "profile_output",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write a structured scan profile JSON report to PATH.",
)
@click.option(
    "--profile-tracemalloc",
    is_flag=True,
    help="Include tracemalloc allocation snapshots in --profile output.",
)
@click.option(
    "--timeout",
    "timeout_seconds",
    type=click.IntRange(min=1),
    default=None,
    help="Overall scan timeout in seconds (default: from config, 600).",
)
@click.option(
    "--layer-timeout",
    "layer_timeout_seconds",
    type=click.IntRange(min=1),
    default=None,
    help="Per-layer timeout in seconds (default: from config, 300).",
)
@click.option(
    "--rule-timeout",
    "rule_timeout_seconds",
    type=click.IntRange(min=1),
    default=None,
    help="Per-rule timeout in seconds (default: from config, 60).",
)
@click.option(
    "--summary",
    is_flag=True,
    help="Print a per-rule findings breakdown after scan completes.",
)
@click.option(
    "--no-dedup",
    is_flag=True,
    help="Disable finding deduplication.",
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Suppress findings matching fingerprints in a baseline JSON file.",
)
@click.option(
    "--write-baseline",
    "write_baseline_path",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write current findings as a baseline JSON file for future suppression.",
)
@click.option(
    "--baseline-commit",
    "baseline_commit",
    metavar="REF",
    help=(
        "Report only findings new since a git REF (diff-aware PR scanning). "
        "Matches on a location-stable key, so a pure line shift does not "
        "resurface a finding. Scans REF in a throwaway worktree."
    ),
)
@click.option(
    "--strict",
    is_flag=True,
    help="Require a '-- reason' on every inline '# flawed: ignore'; unreasoned "
    "directives are ignored (and warned) rather than silently honoured.",
)
@click.option(
    "--no-ignore",
    is_flag=True,
    help="Do not read a .flawedignore file in the scan target.",
)
@click.option(
    "--cache/--no-cache",
    "use_cache",
    default=True,
    show_default=True,
    help="Reuse persisted per-rule results when the engine, rules, and target "
    "are unchanged (FLAW-137). See `flawed cache status|clear`.",
)
@click.option(
    "--refresh",
    is_flag=True,
    help="Ignore any cached results and recompute, then repopulate the cache.",
)
@pass_ctx
def scan_cmd(
    obj: _Ctx,
    targets: tuple[str, ...],
    json_output: bool,
    sarif_output: bool,
    output_format: str,
    fail_on: str,
    min_severity: str | None,
    error: bool,
    rules_dirs: tuple[Path, ...],
    smoke: bool,
    includes: tuple[str, ...],
    include_regexes: tuple[str, ...],
    excludes: tuple[str, ...],
    exclude_regexes: tuple[str, ...],
    force_providers: tuple[str, ...],
    disable_providers: tuple[str, ...],
    data_dir: Path | None,
    no_index: bool,
    reindex: bool,
    enable_mypy_batch: bool | None,
    dry_run: bool,
    semantic: bool,
    profile_output: Path | None,
    profile_tracemalloc: bool,
    timeout_seconds: int | None,
    layer_timeout_seconds: int | None,
    rule_timeout_seconds: int | None,
    summary: bool,
    no_dedup: bool,
    baseline_path: Path | None,
    write_baseline_path: Path | None,
    baseline_commit: str | None,
    strict: bool,
    no_ignore: bool,
    use_cache: bool,
    refresh: bool,
    ribrarian: tuple[str, ...] = (),
) -> None:
    """Scan a repository with the active detection rules.

    \b
    TARGET is a filesystem path. Use ``.`` to scan the current directory.
    The full built-in rule library runs by default; use --smoke for the fast
    curated subset, or --rules-dir to run your own rule modules.

    \b
    Exit codes (CI-friendly; --fail-on governs 1 independently of display):
      0   no finding at/above --fail-on (default: medium)
      1   a finding at/above --fail-on exists
      2   usage/config error (bad flag, missing target/config)
      3   internal/analysis error (pipeline failure)
      124 a layer or the overall scan timed out

    \b
    Examples:
      flawed scan .                      Scan the current directory
      flawed scan . --smoke              Fast curated subset (CI smoke / iteration)
      flawed scan . -i "value-*"         Only rules whose id matches value-*
      flawed scan . --json > out.json    Machine-readable findings
      flawed scan . --sarif > out.sarif  SARIF 2.1.0 for code scanning
      flawed scan . --fail-on high       Fail CI only on high+ findings
      flawed scan . --no-semantic        Layer 1 only (skip semantic analysis)
    """
    if not targets and not ribrarian:
        # `flawed scan` with no target (no positional path, no -r selector) orients
        # rather than silently scanning cwd (FLAW-134). Scanning cwd stays
        # available, explicitly, via `flawed scan .` (or bare `flawed .`).
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        # main() now honours cli.main()'s return value (FLAW-165), so ctx.exit
        # propagates correctly even under standalone_mode=False.
        ctx.exit(_EXIT_ERROR)

    want_sarif = sarif_output or output_format == "sarif"
    want_json = json_output or output_format == "json"
    if want_sarif or want_json:
        obj.console = Console(
            verbosity=obj.console.verbosity,
            quiet=obj.console.quiet,
            json_mode=want_json and not want_sarif,
            sarif_mode=want_sarif,
            color=obj.console.color,
            show_progress=obj.console.show_progress,
        )

    fail_on_severity = Severity.parse(fail_on)
    min_severity_value = Severity.parse(min_severity) if min_severity is not None else None

    try:
        repo_paths = resolve_targets(targets, ribrarian)
    except (TargetError, RibrarianBridgeError) as exc:
        obj.console.error(str(exc))
        sys.exit(_EXIT_ERROR)

    # Sequential multi-target: scan each repo in turn, restoring cwd between them
    # (entered_target, inside _do_scan). A single target is the common case and
    # produces byte-for-byte the same output as before (no banner). The process
    # exit code is the worst (highest) per-repo code, so a finding/error/timeout
    # in any repo is not masked by a clean one elsewhere.
    multi = len(repo_paths) > 1
    worst_exit = _EXIT_OK
    for position, repo_path in enumerate(repo_paths, start=1):
        if multi:
            obj.console.info(f"── scanning [{position}/{len(repo_paths)}] {repo_path} ──")
        code = _do_scan(
            obj,
            repo_path=repo_path,
            data_dir=data_dir,
            rules_dirs=rules_dirs,
            smoke=smoke,
            includes=includes,
            include_regexes=include_regexes,
            excludes=excludes,
            exclude_regexes=exclude_regexes,
            force_providers=force_providers,
            disable_providers=disable_providers,
            no_index=no_index,
            reindex=reindex,
            enable_mypy_batch=enable_mypy_batch,
            dry_run=dry_run or obj.root_dry_run,
            semantic=semantic,
            profile_output=profile_output,
            profile_tracemalloc=profile_tracemalloc,
            timeout_seconds=timeout_seconds,
            layer_timeout_seconds=layer_timeout_seconds,
            rule_timeout_seconds=rule_timeout_seconds,
            show_summary=summary,
            deduplicate=not no_dedup,
            baseline_path=baseline_path,
            write_baseline_path=write_baseline_path,
            baseline_commit=baseline_commit,
            strict=strict,
            no_ignore=no_ignore,
            fail_on=fail_on_severity,
            min_severity=min_severity_value,
            error=error,
            use_cache=use_cache,
            refresh=refresh,
        )
        worst_exit = max(worst_exit, code)
    sys.exit(worst_exit)


def _git_toplevel(path: Path) -> Path | None:
    """Return the git repository root containing *path*, or None if not a repo."""
    try:
        result = managed_process.run(
            ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
    except (managed_process.CalledProcessError, managed_process.TimeoutExpired, OSError):
        return None
    top = result.stdout.strip()
    return Path(top) if top else None


def _baseline_rule_args(
    *,
    rules_dirs: tuple[Path, ...],
    smoke: bool,
    includes: tuple[str, ...],
    include_regexes: tuple[str, ...],
    excludes: tuple[str, ...],
    exclude_regexes: tuple[str, ...],
) -> list[str]:
    """Reconstruct rule-selection flags so the --baseline-commit ref scan (a
    separate ``flawed scan`` subprocess) runs the SAME rules as this scan."""
    args: list[str] = []
    for rules_dir in rules_dirs:
        args += ["--rules-dir", str(rules_dir)]
    if smoke:
        args.append("--smoke")
    for value in includes:
        args += ["--include", value]
    for value in include_regexes:
        args += ["--include-regex", value]
    for value in excludes:
        args += ["--exclude", value]
    for value in exclude_regexes:
        args += ["--exclude-regex", value]
    return args


def _resolve_baseline_commit_keys(
    con: Console,
    *,
    baseline_commit: str | None,
    identity: RepoIdentity,
    config: ResolvedConfig,
    rule_args: list[str],
) -> frozenset[str] | None:
    """Resolve ``--baseline-commit`` to location-stable keys, or None if unset.

    Scans the ref in a throwaway worktree (via the suppression helper); a usage
    error (not a git repo, or the ref scan failed) exits with ``_EXIT_ERROR``.
    """
    if baseline_commit is None:
        return None
    repo_root = _git_toplevel(identity.path)
    if repo_root is None:
        con.error(f"--baseline-commit: {identity.path} is not inside a git repository")
        sys.exit(_EXIT_ERROR)
    try:
        keys = baseline_commit_keys(
            baseline_commit,
            repo_root=repo_root,
            scan_target=identity.path,
            rule_args=rule_args,
            timeout_seconds=config.timeouts.overall or 600,
        )
    except BaselineCommitError as exc:
        con.error(f"--baseline-commit failed: {exc}")
        sys.exit(_EXIT_ERROR)
    con.verbose(f"--baseline-commit {baseline_commit}: {len(keys)} baseline key(s)")
    return keys


def _do_scan(  # noqa: PLR0915
    obj: _Ctx,
    *,
    repo_path: Path,
    data_dir: Path | None,
    rules_dirs: tuple[Path, ...],
    smoke: bool = False,
    includes: tuple[str, ...],
    include_regexes: tuple[str, ...],
    excludes: tuple[str, ...],
    exclude_regexes: tuple[str, ...],
    force_providers: tuple[str, ...],
    disable_providers: tuple[str, ...],
    no_index: bool,
    reindex: bool,
    enable_mypy_batch: bool | None,
    dry_run: bool,
    semantic: bool = True,
    profile_output: Path | None = None,
    profile_tracemalloc: bool = False,
    timeout_seconds: int | None = None,
    layer_timeout_seconds: int | None = None,
    rule_timeout_seconds: int | None = None,
    show_summary: bool = False,
    deduplicate: bool = True,
    baseline_path: Path | None = None,
    write_baseline_path: Path | None = None,
    baseline_commit: str | None = None,
    strict: bool = False,
    no_ignore: bool = False,
    fail_on: Severity = Severity.MEDIUM,
    min_severity: Severity | None = None,
    error: bool = True,
    use_cache: bool = True,
    refresh: bool = False,
) -> int:
    """Execute the scan pipeline for one already-resolved repo; return its exit code.

    The engine operates on cwd, so the scan runs inside :func:`entered_target`,
    which changes into ``repo_path`` and restores the previous cwd on the way out
    (even on error or ``sys.exit``). Returning the exit code rather than calling
    ``sys.exit`` lets the caller scan several repos in sequence and report the
    worst code once at the end.
    """
    con = obj.console

    try:
        config = load_config(config_path=obj.config_path, repo_path=repo_path)
    except ConfigError as exc:
        con.error(f"Configuration error: {exc}")
        return _EXIT_ERROR

    if data_dir is not None:
        config = _replace_data_dir(config, data_dir.expanduser().resolve())

    profile_output_path = profile_output.expanduser().resolve() if profile_output else None

    with entered_target(repo_path) as identity:
        config = apply_overrides(config, identity)
        config = _apply_cli_overrides(
            config,
            force_providers=force_providers,
            disable_providers=disable_providers,
            rules_dirs=rules_dirs,
            smoke=smoke,
            includes=includes,
            include_regexes=include_regexes,
            excludes=excludes,
            exclude_regexes=exclude_regexes,
            enable_mypy_batch=enable_mypy_batch,
        )

        con.verbose(f"Repo: {identity.canonical} ({identity.path})")
        con.verbose(f"Hash: {identity.hash}")
        con.verbose(f"Data: {config.data_dir}", level=2)

        if dry_run:
            con.show_dry_run(
                target=identity.display_name,
                repo_id=identity.canonical,
                data_dir=str(config.data_dir),
            )
            return _EXIT_OK

        profiler = (
            ScanProfiler(
                output_path=profile_output_path,
                identity=identity,
                config=config,
                options={
                    "semantic": semantic,
                    "skip_index": no_index,
                    "force_index": reindex,
                    "enable_mypy_batch": config.type_enrichment.enable_mypy_batch,
                    "basedpyright_max_queries": config.type_enrichment.basedpyright_max_queries,
                    "basedpyright_max_probe_files": (
                        config.type_enrichment.basedpyright_max_probe_files
                    ),
                    "basedpyright_max_source_files": (
                        config.type_enrichment.basedpyright_max_source_files
                    ),
                    "basedpyright_max_workspace_bytes": (
                        config.type_enrichment.basedpyright_max_workspace_bytes
                    ),
                    "basedpyright_timeout_seconds": (
                        config.type_enrichment.basedpyright_timeout_seconds
                    ),
                    "mypy_batch_timeout_seconds": (
                        config.type_enrichment.mypy_batch_timeout_seconds
                    ),
                    "mypy_batch_max_files": config.type_enrichment.mypy_batch_max_files,
                    "profile_tracemalloc": profile_tracemalloc,
                },
                enable_tracemalloc=profile_tracemalloc,
            )
            if profile_output_path is not None
            else None
        )
        # -- Apply CLI timeout overrides to config -------------------------
        t = config.timeouts
        any_override = (
            timeout_seconds is not None
            or layer_timeout_seconds is not None
            or rule_timeout_seconds is not None
        )
        if any_override:
            config = _rebuild(
                config,
                timeouts=TimeoutConfig(
                    overall=timeout_seconds or t.overall,
                    per_layer=layer_timeout_seconds or t.per_layer,
                    per_rule=rule_timeout_seconds or t.per_rule,
                ),
            )

        # Surfaced-suppression inputs (FLAW-148/149/150). Inline `# flawed: ignore`
        # directives are always honoured inside the pipeline; here we load any
        # .flawedignore and, for --baseline-commit, scan the ref for its keys.
        ignore_spec = None if no_ignore else IgnoreSpec.load(identity.path)
        commit_keys = _resolve_baseline_commit_keys(
            con,
            baseline_commit=baseline_commit,
            identity=identity,
            config=config,
            rule_args=_baseline_rule_args(
                rules_dirs=rules_dirs,
                smoke=smoke,
                includes=includes,
                include_regexes=include_regexes,
                excludes=excludes,
                exclude_regexes=exclude_regexes,
            ),
        )

        metrics = ScanMetrics()
        exit_code: int | None = None
        overall_limit = config.timeouts.overall
        try:
            with overall_timeout(overall_limit):
                lock = RepoLock(config.state_dir, identity)
                with lock:
                    exit_code = run_scan(
                        identity=identity,
                        config=config,
                        console=con,
                        skip_index=no_index,
                        force_index=reindex,
                        semantic=semantic,
                        profiler=profiler,
                        show_summary=show_summary,
                        metrics=metrics,
                        deduplicate=deduplicate,
                        baseline_path=baseline_path,
                        write_baseline_path=write_baseline_path,
                        ignore_spec=ignore_spec,
                        baseline_commit_keys=commit_keys,
                        strict=strict,
                        fail_on=fail_on,
                        min_severity=min_severity,
                        error=error,
                        use_cache=use_cache,
                        refresh_cache=refresh,
                    )
        except LockHeldError:
            # A concurrent flawed process holds the repo lock: an internal/runtime
            # condition, not a usage error -> EXIT_INTERNAL (3) per the contract.
            if profiler is not None:
                profiler.record_error(f"lock held for {identity.canonical!r}")
                profiler.write(exit_code=EXIT_INTERNAL)
            con.error(
                f"Another flawed process is running on {identity.canonical!r}.",
            )
            return EXIT_INTERNAL
        except PipelineError as exc:
            if profiler is not None:
                profiler.record_error(str(exc))
                profiler.write(exit_code=EXIT_INTERNAL)
            con.error(str(exc))
            return EXIT_INTERNAL
        except OverallTimeoutError as exc:
            metrics.incomplete = True
            metrics.overall_timed_out = True
            if profiler is not None:
                profiler.record_error(str(exc))
                profiler.write(exit_code=EXIT_TIMEOUT)
            con.error(f"TIMEOUT: {exc}")
            con.show_scan_metrics(metrics)
            return EXIT_TIMEOUT

        if profiler is not None:
            profiler.write(exit_code=exit_code)
        return exit_code if exit_code is not None else _EXIT_OK


# ── Index command ────────────────────────────────────────────────


@cli.command("index", context_settings=_CONTEXT_SETTINGS)
@_with_ribrarian
@click.argument("targets", nargs=-1)
@click.option("--force", is_flag=True, help="Force re-extraction.")
@click.option("--data-dir", type=click.Path(path_type=Path), help="Override data directory.")
@click.option(
    "--enable-mypy-batch/--disable-mypy-batch",
    default=None,
    help="Run experimental mypy batch type enrichment alongside basedpyright.",
)
@click.option(
    "--timeout",
    "timeout_seconds",
    type=click.IntRange(min=1),
    default=None,
    help="Abort after SECONDS with a stack trace (for batch safety).",
)
@pass_ctx
def index_cmd(
    obj: _Ctx,
    targets: tuple[str, ...],
    force: bool,
    data_dir: Path | None,
    enable_mypy_batch: bool | None,
    timeout_seconds: int | None,
    ribrarian: tuple[str, ...] = (),
) -> None:
    """Run Layer 1 structural extraction only."""
    con = obj.console

    try:
        repo_paths = resolve_targets(targets, ribrarian)
    except (TargetError, RibrarianBridgeError) as exc:
        con.error(str(exc))
        sys.exit(_EXIT_ERROR)

    # --timeout is an overall batch-safety guard; arm it once around the whole
    # (possibly multi-repo) run rather than per repo.
    if timeout_seconds is not None:

        def _timeout_handler(signum: int, frame: object) -> None:  # noqa: ARG001
            con.error(f"Timeout after {timeout_seconds}s — stack trace follows:")
            traceback.print_stack(frame)  # type: ignore[arg-type]
            sys.exit(_EXIT_ERROR)

        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(timeout_seconds)

    multi = len(repo_paths) > 1
    worst_exit = _EXIT_OK
    for position, repo_path in enumerate(repo_paths, start=1):
        if multi:
            con.info(f"── indexing [{position}/{len(repo_paths)}] {repo_path} ──")
        code = _run_index_for_repo(
            obj,
            repo_path=repo_path,
            force=force,
            data_dir=data_dir,
            enable_mypy_batch=enable_mypy_batch,
        )
        worst_exit = max(worst_exit, code)

    if timeout_seconds is not None:
        signal.alarm(0)
    sys.exit(worst_exit)


def _run_index_for_repo(
    obj: _Ctx,
    *,
    repo_path: Path,
    force: bool,
    data_dir: Path | None,
    enable_mypy_batch: bool | None,
) -> int:
    """Run Layer 1 extraction for one repo (cwd-restoring); return its exit code."""
    con = obj.console

    try:
        config = load_config(config_path=obj.config_path, repo_path=repo_path)
    except ConfigError as exc:
        con.error(f"Configuration error: {exc}")
        return _EXIT_ERROR

    if data_dir is not None:
        config = _replace_data_dir(config, data_dir.expanduser().resolve())

    with entered_target(repo_path) as identity:
        config = apply_overrides(config, identity)
        config = _apply_cli_overrides(
            config,
            force_providers=(),
            disable_providers=(),
            rules_dirs=(),
            includes=(),
            include_regexes=(),
            excludes=(),
            exclude_regexes=(),
            enable_mypy_batch=enable_mypy_batch,
        )

        try:
            lock = RepoLock(config.state_dir, identity)
            with lock:
                run_index(
                    identity=identity,
                    config=config,
                    console=con,
                    force=force,
                )
        except LockHeldError:
            con.error(
                f"Another flawed process is running on {identity.canonical!r}.",
            )
            return _EXIT_ERROR
        except PipelineError as exc:
            con.error(str(exc))
            return _EXIT_ERROR

    return _EXIT_OK


# ── Version command ──────────────────────────────────────────────


@cli.command("version", context_settings=_CONTEXT_SETTINGS)
def version_cmd() -> None:
    """Show the flawed engine version."""
    click.echo(_format_version())


# ── Completions command ──────────────────────────────────────────


@cli.command("completions", context_settings=_CONTEXT_SETTINGS)
@click.argument("shell", type=click.Choice(_COMPLETION_SHELLS))
def completions_cmd(shell: str) -> None:
    """Print a shell completion script for the given shell.

    Completes subcommands, flags, rule ids (for ``-i``/``-e``/``explain``)
    and provider names (for ``--provider``/``providers show``) dynamically.

    \b
    Install (current session or shell rc):
      bash:        eval "$(flawed completions bash)"
      zsh:         eval "$(flawed completions zsh)"
      fish:        flawed completions fish | source
      powershell:  flawed completions powershell | Out-String | Invoke-Expression

    \b
    Persist by appending the eval/source line to ~/.bashrc, ~/.zshrc,
    ~/.config/fish/config.fish, or your PowerShell $PROFILE.
    """
    from click.shell_completion import get_completion_class

    comp_cls = get_completion_class(shell)
    if comp_cls is None:  # pragma: no cover - guarded by click.Choice
        raise click.ClickException(f"unsupported shell: {shell}")
    comp = comp_cls(cli, {}, "flawed", _COMPLETE_VAR)
    click.echo(comp.source())


# ── Config commands ──────────────────────────────────────────────


@cli.group("config", context_settings=_CONTEXT_SETTINGS)
def config_group() -> None:
    """Inspect and validate configuration."""


@config_group.command("show", context_settings=_CONTEXT_SETTINGS)
@_with_ribrarian
@click.option(
    "--repo",
    help="Show config resolved for a specific repo (path or slug).",
)
@pass_ctx
def config_show(obj: _Ctx, repo: str | None, ribrarian: tuple[str, ...] = ()) -> None:
    """Show the fully resolved configuration.

    Use ``--repo PATH`` for a local path, or (when ribrarian is installed)
    ``-r SELECTOR`` to resolve a single repo by selector. The two are mutually
    exclusive, and a ``-r`` selector must resolve to exactly one repo.
    """
    con = obj.console

    try:
        config = load_config(config_path=obj.config_path)
    except ConfigError as exc:
        con.error(f"Configuration error: {exc}")
        sys.exit(_EXIT_ERROR)

    repo_path: Path | None = None
    if ribrarian:
        if repo is not None:
            con.error("config show: use --repo or -r/--ribrarian, not both.")
            sys.exit(_EXIT_ERROR)
        try:
            matches = resolve_targets((), ribrarian)
        except (TargetError, RibrarianBridgeError) as exc:
            con.error(str(exc))
            sys.exit(_EXIT_ERROR)
        if len(matches) != 1:
            con.error(
                f"config show needs exactly one repo; selector resolved to {len(matches)}.",
            )
            sys.exit(_EXIT_ERROR)
        repo_path = matches[0]
    elif repo is not None:
        try:
            repo_path = resolve_target(repo)
        except TargetError:
            repo_path = Path.cwd()

    if repo_path is not None:
        from flawed._config.paths import RepoIdentity

        identity = RepoIdentity.from_path(repo_path)
        config = apply_overrides(config, identity)
        label = f"Resolved config for {identity.canonical}"
    else:
        label = "Global resolved config (no repo context)"

    con.show_config(config, label=label)


@config_group.command("check", context_settings=_CONTEXT_SETTINGS)
@pass_ctx
def config_check(obj: _Ctx) -> None:
    """Validate all configuration files."""
    con = obj.console

    try:
        config = load_config(config_path=obj.config_path)
    except ConfigError as exc:
        con.error(f"Invalid configuration: {exc}")
        sys.exit(_EXIT_ERROR)

    con.success("All configuration files are valid.")
    con.verbose(f"  data_dir:  {config.data_dir}")
    con.verbose(f"  state_dir: {config.state_dir}")


# ── Results-cache commands (FLAW-137) ────────────────────────────


def _cache_target_dir(obj: _Ctx, target: str, data_dir: Path | None) -> tuple[RepoIdentity, Path]:
    """Resolve a scan target to its (identity, data_dir) for cache operations."""
    from flawed._config.paths import RepoIdentity

    try:
        repo_path = resolve_target(target)
    except TargetError as exc:
        obj.console.error(str(exc))
        sys.exit(_EXIT_ERROR)
    config = _load_config_or_exit(obj)
    if data_dir is not None:
        config = _replace_data_dir(config, data_dir.expanduser().resolve())
    return RepoIdentity.from_path(repo_path), config.data_dir


def _format_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


@cli.group("cache", context_settings=_CONTEXT_SETTINGS)
def cache_group() -> None:
    """Inspect and clear the persisted results cache (FLAW-137)."""


@cache_group.command("status", context_settings=_CONTEXT_SETTINGS)
@click.argument("target", default=".")
@click.option("--data-dir", type=click.Path(path_type=Path), help="Override data directory.")
@pass_ctx
def cache_status_cmd(obj: _Ctx, target: str, data_dir: Path | None) -> None:
    """Show the persisted results cache for a TARGET repository."""
    from flawed._cli.result_cache import cache_status

    con = obj.console
    identity, resolved_data_dir = _cache_target_dir(obj, target, data_dir)
    status = cache_status(resolved_data_dir, identity)
    con.info(f"Results cache for {identity.canonical}")
    con.info(f"  location: {status.root}")
    if status.entry_count:
        con.info(
            f"  cached:   {status.entry_count} detector result(s), "
            f"{_format_bytes(status.total_bytes)}"
        )
    else:
        con.info("  cached:   (empty)")


@cache_group.command("clear", context_settings=_CONTEXT_SETTINGS)
@click.argument("target", default=".")
@click.option("--data-dir", type=click.Path(path_type=Path), help="Override data directory.")
@pass_ctx
def cache_clear_cmd(obj: _Ctx, target: str, data_dir: Path | None) -> None:
    """Delete the persisted results cache for a TARGET repository."""
    from flawed._cli.result_cache import clear_cache

    con = obj.console
    identity, resolved_data_dir = _cache_target_dir(obj, target, data_dir)
    removed = clear_cache(resolved_data_dir, identity)
    con.success(f"Cleared {removed} cached detector result(s) for {identity.canonical}")


# ── Rules commands ───────────────────────────────────────────────


def _load_config_or_exit(obj: _Ctx) -> ResolvedConfig:
    """Load resolved config, reporting a clean error + exit 2 on failure."""
    try:
        return load_config(config_path=obj.config_path)
    except ConfigError as exc:
        obj.console.error(f"Configuration error: {exc}")
        sys.exit(_EXIT_ERROR)


def _render_rules(obj: _Ctx, *, paths: bool, json_output: bool) -> None:
    con = obj.console
    config = _load_config_or_exit(obj)
    rules = summarize_rules(config)
    if json_output:
        con.emit_rules_json(rules)
    else:
        con.show_rules(rules, paths=paths)


@cli.group(
    "rules",
    context_settings=_CONTEXT_SETTINGS,
    invoke_without_command=True,
)
@_output_opts
@click.option("--paths", is_flag=True, help="Show each rule's module file path.")
@click.option("--json", "json_output", is_flag=True, help="Emit the inventory as JSON.")
@click.pass_context
def rules_group(ctx: click.Context, paths: bool, json_output: bool) -> None:
    """List detection rules: id, severity, description, and filename stem.

    \b
    Bare `flawed rules` prints the inventory directly.

    \b
    Examples:
      flawed rules                  Full inventory (id, severity, description)
      flawed rules --json           Machine-readable inventory
      flawed explain <RULE_ID>      Deep-dive one rule
    """
    if ctx.invoked_subcommand is None:
        _render_rules(ctx.ensure_object(_Ctx), paths=paths, json_output=json_output)


@rules_group.command("list", hidden=True, context_settings=_CONTEXT_SETTINGS)
@_output_opts
@click.option("--paths", is_flag=True, help="Show each rule's module file path.")
@click.option("--json", "json_output", is_flag=True, help="Emit the inventory as JSON.")
@pass_ctx
def rules_list(obj: _Ctx, paths: bool, json_output: bool) -> None:
    """Alias for `flawed rules` (kept for back-compat and scripting)."""
    _render_rules(obj, paths=paths, json_output=json_output)


# ── Explain command (FLAW-151) ───────────────────────────────────


@cli.command("explain", context_settings=_CONTEXT_SETTINGS)
@_output_opts
@click.argument("rule_id", shell_complete=_complete_rule_id)
@click.option("--json", "json_output", is_flag=True, help="Emit the explanation as JSON.")
@pass_ctx
def explain_cmd(obj: _Ctx, rule_id: str, json_output: bool) -> None:
    """Explain a rule: what it detects, why it matters, how to suppress.

    \b
    The prose is the rule module's own docstring — authored beside the
    detector, so it never drifts from the implementation. RULE_ID accepts
    either separator form (``value-flow`` or ``value_flow``).

    \b
    Examples:
      flawed explain value-flow
      flawed explain value_flow --json
    """
    con = obj.console
    config = _load_config_or_exit(obj)
    lookup = explain_rule(config, rule_id)
    if lookup.explanation is None:
        con.error(f"no rule {rule_id!r}.")
        suggestions = _closest_rule_ids(rule_id, lookup.known_ids)
        if suggestions:
            con.info(f"Did you mean: {', '.join(suggestions)}?")
        con.info("Run `flawed rules` for the full inventory.")
        sys.exit(_EXIT_ERROR)
    if json_output:
        con.emit_explanation_json(lookup.explanation)
    else:
        con.show_explanation(lookup.explanation)


# ── Explore command (results exploration, FLAW-138) ──────────────


@cli.command("explore", context_settings=_CONTEXT_SETTINGS)
@click.argument("results", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--group-by",
    type=click.Choice(["rule", "severity", "file"]),
    default=None,
    help="Print finding counts grouped by this dimension instead of a REPL.",
)
@click.option(
    "--rule",
    "rule_id",
    default=None,
    help="Filter to one rule id and list its findings.",
)
@click.option(
    "--diff",
    "diff_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Compare RESULTS (newer) against a baseline results document by fingerprint.",
)
@click.option(
    "--top",
    type=click.IntRange(min=1),
    default=10,
    show_default=True,
    help="Cap rows shown in summaries and listings.",
)
@click.option(
    "--repl/--no-repl",
    "repl",
    default=None,
    help="Force or suppress the interactive REPL; default auto-detects a TTY.",
)
def explore_cmd(
    results: Path,
    group_by: str | None,
    rule_id: str | None,
    diff_path: Path | None,
    top: int,
    repl: bool | None,
) -> None:
    """Explore a completed scan's findings: filter, group, diff, or open a REPL.

    \b
    RESULTS is a results document written by a scan — a ``--json`` capture or a
    ``--output-format sarif`` log. With no projection flag on a TTY this drops
    into a Python REPL with the findings preloaded as ``findings``; otherwise it
    prints a one-shot summary.

    \b
    Examples:
      flawed scan ./app --json > scan.json && flawed explore scan.json
      flawed explore scan.json --group-by rule
      flawed explore scan.json --rule value-flow
      flawed explore scan.json --diff baseline.json
    """
    from flawed._cli.explore import explore_results

    interactive = sys.stdin.isatty() if repl is None else repl
    try:
        rendered = explore_results(
            results,
            group_by=group_by,
            rule=rule_id,
            diff=diff_path,
            top=top,
            interactive=interactive,
        )
    except ValueError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(_EXIT_ERROR)
    if rendered is not None:
        click.echo(rendered, nl=False)


# ── Providers commands ───────────────────────────────────────────


def _discover_providers() -> tuple[type[object], ...]:
    from flawed._semantic._provider_engine import discover_builtin_provider_classes

    return tuple(discover_builtin_provider_classes())


@cli.group("providers", context_settings=_CONTEXT_SETTINGS)
def providers_group() -> None:
    """Provider management."""


@providers_group.command("list", context_settings=_CONTEXT_SETTINGS)
@_output_opts
@click.option("--json", "json_output", is_flag=True, help="Emit the inventory as JSON.")
@click.option(
    "--counts",
    is_flag=True,
    hidden=True,
    help="Deprecated: the pattern count is always shown now (kept for back-compat).",
)
@pass_ctx
def providers_list(obj: _Ctx, json_output: bool, counts: bool) -> None:  # noqa: ARG001
    """List available semantic providers (id, library, pattern count).

    \b
    Examples:
      flawed providers list             Inventory of built-in providers
      flawed providers list --json      Machine-readable inventory
      flawed providers show flask       Per-pattern breakdown for one provider
    """
    # `--counts` is now redundant — the Patterns column is always shown — but is
    # accepted (hidden) so existing scripts/CI invoking it keep working.
    con = obj.console
    providers = _discover_providers()
    if json_output:
        con.emit_providers_json(providers)
    else:
        con.show_providers(providers)


@providers_group.command("show", context_settings=_CONTEXT_SETTINGS)
@_output_opts
@click.argument("provider_id", shell_complete=_complete_provider)
@click.option("--json", "json_output", is_flag=True, help="Emit the detail as JSON.")
@pass_ctx
def providers_show(obj: _Ctx, provider_id: str, json_output: bool) -> None:
    """Show one provider's metadata and per-category pattern breakdown."""
    con = obj.console
    providers = _discover_providers()
    by_id = {p.meta.id: p for p in providers}  # type: ignore[attr-defined]
    match = by_id.get(provider_id)
    if match is None:
        con.error(f"no provider {provider_id!r}.")
        suggestions = difflib.get_close_matches(provider_id, list(by_id), n=3, cutoff=0.5)
        if suggestions:
            con.info(f"Did you mean: {', '.join(suggestions)}?")
        con.info("Run `flawed providers list` for the full inventory.")
        sys.exit(_EXIT_ERROR)
    if json_output:
        con.emit_provider_detail_json(match)
    else:
        con.show_provider_detail(match)


@providers_group.command("coverage", context_settings=_CONTEXT_SETTINGS)
@_with_ribrarian
@click.argument("targets", nargs=-1)
@click.option("--json", "json_output", is_flag=True, help="Emit JSON.")
@click.option("--all", "include_inactive", is_flag=True, help="Include inactive providers.")
@click.option(
    "--provider",
    "force_providers",
    multiple=True,
    help="Force-enable a provider (repeatable).",
)
@click.option(
    "--no-provider",
    "disable_providers",
    multiple=True,
    help="Force-disable a provider (repeatable).",
)
@click.option("--data-dir", type=click.Path(path_type=Path), help="Override data directory.")
@click.option("--reindex", is_flag=True, help="Force Layer 1 re-extraction.")
@click.option(
    "--enable-mypy-batch/--disable-mypy-batch",
    default=None,
    help="Run experimental mypy batch type enrichment alongside basedpyright.",
)
@click.option(
    "--evidence-limit",
    type=click.IntRange(min=1),
    default=5,
    show_default=True,
    help="Maximum evidence examples per provider/phase.",
)
@pass_ctx
def providers_coverage(
    obj: _Ctx,
    targets: tuple[str, ...],
    json_output: bool,
    include_inactive: bool,
    force_providers: tuple[str, ...],
    disable_providers: tuple[str, ...],
    data_dir: Path | None,
    reindex: bool,
    enable_mypy_batch: bool | None,
    evidence_limit: int,
    ribrarian: tuple[str, ...] = (),
) -> None:
    """Show provider activation, pattern coverage, gaps, and evidence."""
    con = obj.console

    try:
        repo_paths = resolve_targets(targets, ribrarian)
    except (TargetError, RibrarianBridgeError) as exc:
        con.error(str(exc))
        sys.exit(_EXIT_ERROR)

    multi = len(repo_paths) > 1
    worst_exit = _EXIT_OK
    for position, repo_path in enumerate(repo_paths, start=1):
        if multi:
            con.info(f"── provider coverage [{position}/{len(repo_paths)}] {repo_path} ──")
        code = _run_coverage_for_repo(
            obj,
            repo_path=repo_path,
            json_output=json_output,
            include_inactive=include_inactive,
            force_providers=force_providers,
            disable_providers=disable_providers,
            data_dir=data_dir,
            reindex=reindex,
            enable_mypy_batch=enable_mypy_batch,
            evidence_limit=evidence_limit,
        )
        worst_exit = max(worst_exit, code)
    sys.exit(worst_exit)


def _run_coverage_for_repo(
    obj: _Ctx,
    *,
    repo_path: Path,
    json_output: bool,
    include_inactive: bool,
    force_providers: tuple[str, ...],
    disable_providers: tuple[str, ...],
    data_dir: Path | None,
    reindex: bool,
    enable_mypy_batch: bool | None,
    evidence_limit: int,
) -> int:
    """Build and emit the provider-coverage report for one repo; return exit code."""
    from flawed._cli.provider_coverage import (
        build_provider_coverage_report,
        format_provider_coverage_report,
    )
    from flawed._semantic._provider_engine import (
        ProviderEngine,
        discover_builtin_provider_classes,
    )

    con = obj.console

    try:
        config = load_config(config_path=obj.config_path, repo_path=repo_path)
    except ConfigError as exc:
        con.error(f"Configuration error: {exc}")
        return _EXIT_ERROR

    if data_dir is not None:
        config = _replace_data_dir(config, data_dir.expanduser().resolve())

    with entered_target(repo_path) as identity:
        config = apply_overrides(config, identity)
        config = _apply_cli_overrides(
            config,
            force_providers=force_providers,
            disable_providers=disable_providers,
            rules_dirs=(),
            includes=(),
            include_regexes=(),
            excludes=(),
            exclude_regexes=(),
            enable_mypy_batch=enable_mypy_batch,
        )

        try:
            lock = RepoLock(config.state_dir, identity)
            with lock:
                index = run_index(
                    identity=identity,
                    config=config,
                    console=con,
                    force=reindex,
                )
                provider_result = run_provider_engine(ProviderEngine(), index, config=config)
        except LockHeldError:
            con.error(
                f"Another flawed process is running on {identity.canonical!r}.",
            )
            return _EXIT_ERROR
        except PipelineError as exc:
            con.error(str(exc))
            return _EXIT_ERROR

        report = build_provider_coverage_report(
            index=index,
            result=provider_result,
            provider_classes=discover_builtin_provider_classes(),
            include_inactive=include_inactive,
            evidence_limit=evidence_limit,
        )
        output = report.to_json() if json_output else format_provider_coverage_report(report)
        click.echo(output, nl=False)

    return _EXIT_OK


# ── Helpers ──────────────────────────────────────────────────────


def _rebuild(config: ResolvedConfig, **overrides: object) -> ResolvedConfig:
    """Return a new ``ResolvedConfig`` with selected fields replaced."""
    from dataclasses import fields as dc_fields

    kw = {f.name: getattr(config, f.name) for f in dc_fields(config)}
    kw.update(overrides)
    return ResolvedConfig(**kw)


def _replace_data_dir(config: ResolvedConfig, data_dir: Path) -> ResolvedConfig:
    """Return a copy of *config* with *data_dir* replaced."""
    return _rebuild(config, data_dir=data_dir)


def _apply_cli_overrides(
    config: ResolvedConfig,
    *,
    force_providers: tuple[str, ...],
    disable_providers: tuple[str, ...],
    rules_dirs: tuple[Path, ...],
    smoke: bool = False,
    includes: tuple[str, ...],
    include_regexes: tuple[str, ...],
    excludes: tuple[str, ...],
    exclude_regexes: tuple[str, ...],
    enable_mypy_batch: bool | None,
) -> ResolvedConfig:
    """Apply CLI flags (--provider, --rules-dir, --smoke, -i/-e/-I/-E, L1 flags)."""
    from flawed._config.schema import (
        ProviderConfig,
        ProviderEntry,
        RuleConfig,
        TypeEnrichmentConfig,
    )

    prov = config.providers
    if force_providers or disable_providers:
        entries = dict(prov.entries)
        for pid in force_providers:
            entries[pid] = ProviderEntry(enable=True)
        for pid in disable_providers:
            entries[pid] = ProviderEntry(enable=False)
        prov = ProviderConfig(
            base_dir=prov.base_dir,
            paths=prov.paths,
            entries=entries,
        )

    rules = config.rules
    if rules_dirs or smoke or includes or include_regexes or excludes or exclude_regexes:
        include = (*rules.include, *includes)
        if rules.include == ("*",) and includes:
            include = includes
        include_regex = (*rules.include_regex, *include_regexes)
        if include_regexes:
            include_regex = include_regexes
        # Explicit --rules-dir wins; otherwise --smoke selects the curated pack.
        paths = rules_dirs or (("smoke",) if smoke else rules.paths)
        rules = RuleConfig(
            base_dir=None if rules_dirs else rules.base_dir,
            paths=paths,
            include=include,
            exclude=(*rules.exclude, *excludes),
            include_regex=include_regex,
            exclude_regex=(*rules.exclude_regex, *exclude_regexes),
        )

    type_enrichment = config.type_enrichment
    if enable_mypy_batch is not None:
        type_enrichment = TypeEnrichmentConfig(
            enable_mypy_batch=enable_mypy_batch,
            basedpyright_max_queries=type_enrichment.basedpyright_max_queries,
            basedpyright_max_probe_files=type_enrichment.basedpyright_max_probe_files,
            basedpyright_max_source_files=type_enrichment.basedpyright_max_source_files,
            basedpyright_max_workspace_bytes=type_enrichment.basedpyright_max_workspace_bytes,
            basedpyright_timeout_seconds=type_enrichment.basedpyright_timeout_seconds,
            mypy_batch_timeout_seconds=type_enrichment.mypy_batch_timeout_seconds,
            mypy_batch_max_files=type_enrichment.mypy_batch_max_files,
        )

    return _rebuild(
        config,
        providers=prov,
        rules=rules,
        type_enrichment=type_enrichment,
    )


# ── Attach extracted command groups ──────────────────────────────
from flawed._cli.inspect_commands import inspect_group  # noqa: E402

cli.add_command(inspect_group)
