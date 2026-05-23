"""The ``flawed inspect`` command group.

Thin Click wiring for inspecting L1 cache artifacts, scan findings, and
profile reports. All summarization logic lives in :mod:`flawed._cli.inspect`;
this module only defines the command surface and delegates. The group is
attached to the root ``cli`` in :mod:`flawed._cli.app`.
"""

from __future__ import annotations

from pathlib import Path

import click

from flawed._cli._common import _CONTEXT_SETTINGS, _Ctx, pass_ctx


@click.group("inspect", context_settings=_CONTEXT_SETTINGS)
def inspect_group() -> None:
    """Inspect L1 cache artifacts, scan findings, and profile reports."""


def _emit_artifact_summary(cache_dir: Path, family: str, top: int, json_output: bool) -> None:
    import json as _json

    from flawed._cli.inspect import (
        format_artifact_summary,
        load_artifact_records,
        summarize_artifact_family,
    )

    records = load_artifact_records(cache_dir, family)
    summary = summarize_artifact_family(family, records)

    if json_output:
        click.echo(_json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    else:
        click.echo(format_artifact_summary(summary, top=top), nl=False)


@inspect_group.command("artifacts", context_settings=_CONTEXT_SETTINGS)
@click.argument("cache_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "json_output", is_flag=True, help="JSON output.")
@pass_ctx
def inspect_artifacts(obj: _Ctx, cache_dir: Path, json_output: bool) -> None:  # noqa: ARG001
    """List written and deferred normalized artifact families."""
    import json as _json

    from flawed._cli.inspect import format_artifact_registry, load_artifact_registry

    registry = load_artifact_registry(cache_dir)
    if json_output:
        click.echo(_json.dumps(registry.to_dict(), indent=2, sort_keys=True))
    else:
        click.echo(format_artifact_registry(registry), nl=False)


@inspect_group.command("summary", context_settings=_CONTEXT_SETTINGS)
@click.argument("cache_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "json_output", is_flag=True, help="JSON output.")
@pass_ctx
def inspect_summary(obj: _Ctx, cache_dir: Path, json_output: bool) -> None:  # noqa: ARG001
    """Show aggregate normalized artifact counts."""
    import json as _json

    from flawed._cli.inspect import format_summary_counts, load_summary_counts

    summary = load_summary_counts(cache_dir)
    if json_output:
        click.echo(_json.dumps(summary, indent=2, sort_keys=True))
    else:
        click.echo(format_summary_counts(summary), nl=False)


@inspect_group.command("functions", context_settings=_CONTEXT_SETTINGS)
@click.argument("cache_dir", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--top",
    type=click.IntRange(min=1),
    default=10,
    show_default=True,
    help="Number of entries to show per section in text output.",
)
@click.option("--json", "json_output", is_flag=True, help="JSON output.")
@pass_ctx
def inspect_functions(obj: _Ctx, cache_dir: Path, top: int, json_output: bool) -> None:  # noqa: ARG001
    """Summarize function records from a normalized cache directory."""
    _emit_artifact_summary(cache_dir, "functions", top, json_output)


@inspect_group.command("classes", context_settings=_CONTEXT_SETTINGS)
@click.argument("cache_dir", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--top",
    type=click.IntRange(min=1),
    default=10,
    show_default=True,
    help="Number of entries to show per section in text output.",
)
@click.option("--json", "json_output", is_flag=True, help="JSON output.")
@pass_ctx
def inspect_classes(obj: _Ctx, cache_dir: Path, top: int, json_output: bool) -> None:  # noqa: ARG001
    """Summarize class records from a normalized cache directory."""
    _emit_artifact_summary(cache_dir, "classes", top, json_output)


@inspect_group.command("decorators", context_settings=_CONTEXT_SETTINGS)
@click.argument("cache_dir", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--top",
    type=click.IntRange(min=1),
    default=10,
    show_default=True,
    help="Number of entries to show per section in text output.",
)
@click.option("--json", "json_output", is_flag=True, help="JSON output.")
@pass_ctx
def inspect_decorators(obj: _Ctx, cache_dir: Path, top: int, json_output: bool) -> None:  # noqa: ARG001
    """Summarize decorator records from a normalized cache directory."""
    _emit_artifact_summary(cache_dir, "decorators", top, json_output)


@inspect_group.command("imports", context_settings=_CONTEXT_SETTINGS)
@click.argument("cache_dir", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--top",
    type=click.IntRange(min=1),
    default=10,
    show_default=True,
    help="Number of entries to show per section in text output.",
)
@click.option("--json", "json_output", is_flag=True, help="JSON output.")
@pass_ctx
def inspect_imports(obj: _Ctx, cache_dir: Path, top: int, json_output: bool) -> None:  # noqa: ARG001
    """Summarize import records from a normalized cache directory."""
    _emit_artifact_summary(cache_dir, "imports", top, json_output)


@inspect_group.command("attributes", context_settings=_CONTEXT_SETTINGS)
@click.argument("cache_dir", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--top",
    type=click.IntRange(min=1),
    default=10,
    show_default=True,
    help="Number of entries to show per section in text output.",
)
@click.option("--json", "json_output", is_flag=True, help="JSON output.")
@pass_ctx
def inspect_attributes(obj: _Ctx, cache_dir: Path, top: int, json_output: bool) -> None:  # noqa: ARG001
    """Summarize attribute-access records from a normalized cache directory."""
    _emit_artifact_summary(cache_dir, "attributes", top, json_output)


@inspect_group.command("valueflows", context_settings=_CONTEXT_SETTINGS)
@click.argument("cache_dir", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--top",
    type=click.IntRange(min=1),
    default=10,
    show_default=True,
    help="Number of entries to show per section in text output.",
)
@click.option("--json", "json_output", is_flag=True, help="JSON output.")
@pass_ctx
def inspect_valueflows(obj: _Ctx, cache_dir: Path, top: int, json_output: bool) -> None:  # noqa: ARG001
    """Summarize value-flow edge records from a normalized cache directory."""
    _emit_artifact_summary(cache_dir, "valueflows", top, json_output)


@inspect_group.command("symbolrefs", context_settings=_CONTEXT_SETTINGS)
@click.argument("cache_dir", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--top",
    type=click.IntRange(min=1),
    default=10,
    show_default=True,
    help="Number of entries to show per section in text output.",
)
@click.option("--json", "json_output", is_flag=True, help="JSON output.")
@pass_ctx
def inspect_symbolrefs(obj: _Ctx, cache_dir: Path, top: int, json_output: bool) -> None:  # noqa: ARG001
    """Summarize symbol-reference records from a normalized cache directory."""
    _emit_artifact_summary(cache_dir, "symbolrefs", top, json_output)


@inspect_group.command("calledges", context_settings=_CONTEXT_SETTINGS)
@click.argument("cache_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "json_output", is_flag=True, help="JSON output.")
@pass_ctx
def inspect_calledges(obj: _Ctx, cache_dir: Path, json_output: bool) -> None:  # noqa: ARG001
    """Summarize call edge counts from a normalized cache directory."""
    import json as _json

    from flawed._cli.inspect import format_summary, load_call_edges, summarize_call_edges

    records = load_call_edges(cache_dir)
    summary = summarize_call_edges(records)

    if json_output:
        click.echo(_json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    else:
        click.echo(format_summary(summary), nl=False)


@inspect_group.command("calledges-diff", context_settings=_CONTEXT_SETTINGS)
@click.argument("before_dir", type=click.Path(exists=True, path_type=Path))
@click.argument("after_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "json_output", is_flag=True, help="JSON output.")
@pass_ctx
def inspect_calledges_diff(
    obj: _Ctx,  # noqa: ARG001
    before_dir: Path,
    after_dir: Path,
    json_output: bool,
) -> None:
    """Compare call edge counts between two cache directories."""
    import json as _json

    from flawed._cli.inspect import (
        diff_summaries,
        format_diff,
        load_call_edges,
        summarize_call_edges,
    )

    before_records = load_call_edges(before_dir)
    after_records = load_call_edges(after_dir)
    before_summary = summarize_call_edges(before_records)
    after_summary = summarize_call_edges(after_records)
    diff = diff_summaries(before_summary, after_summary)

    if json_output:
        result = {
            "total_before": diff.total_before,
            "total_after": diff.total_after,
            "total_delta": diff.total_delta,
            "entries": [
                {
                    "category": e.category,
                    "key": e.key,
                    "before": e.before,
                    "after": e.after,
                    "delta": e.delta,
                }
                for e in diff.entries
            ],
        }
        click.echo(_json.dumps(result, indent=2))
    else:
        click.echo(format_diff(diff), nl=False)


@inspect_group.command("errors", context_settings=_CONTEXT_SETTINGS)
@click.argument("cache_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--kind", help="Only include one error kind, e.g. cfg or resolution.")
@click.option(
    "--top",
    type=click.IntRange(min=1),
    default=10,
    show_default=True,
    help="Number of messages/files to show in text output.",
)
@click.option("--json", "json_output", is_flag=True, help="JSON output.")
@pass_ctx
def inspect_errors(
    obj: _Ctx,  # noqa: ARG001
    cache_dir: Path,
    kind: str | None,
    top: int,
    json_output: bool,
) -> None:
    """Summarize extraction errors from a normalized cache directory."""
    import json as _json

    from flawed._cli.inspect import (
        format_error_summary,
        load_extraction_errors,
        summarize_extraction_errors,
    )

    records = load_extraction_errors(cache_dir)
    summary = summarize_extraction_errors(records, kind=kind)

    if json_output:
        click.echo(_json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    else:
        click.echo(format_error_summary(summary, top=top), nl=False)


@inspect_group.command("errors-diff", context_settings=_CONTEXT_SETTINGS)
@click.argument("before_dir", type=click.Path(exists=True, path_type=Path))
@click.argument("after_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--kind", help="Only include one error kind, e.g. cfg or resolution.")
@click.option("--json", "json_output", is_flag=True, help="JSON output.")
@pass_ctx
def inspect_errors_diff(
    obj: _Ctx,  # noqa: ARG001
    before_dir: Path,
    after_dir: Path,
    kind: str | None,
    json_output: bool,
) -> None:
    """Compare extraction error counts between two cache directories."""
    import json as _json

    from flawed._cli.inspect import (
        diff_error_summaries,
        format_error_diff,
        load_extraction_errors,
        summarize_extraction_errors,
    )

    before_records = load_extraction_errors(before_dir)
    after_records = load_extraction_errors(after_dir)
    before_summary = summarize_extraction_errors(before_records, kind=kind)
    after_summary = summarize_extraction_errors(after_records, kind=kind)
    diff = diff_error_summaries(before_summary, after_summary)

    if json_output:
        result = {
            "total_before": diff.total_before,
            "total_after": diff.total_after,
            "total_delta": diff.total_delta,
            "entries": [
                {
                    "category": e.category,
                    "key": e.key,
                    "before": e.before,
                    "after": e.after,
                    "delta": e.delta,
                }
                for e in diff.entries
            ],
        }
        click.echo(_json.dumps(result, indent=2, sort_keys=True))
    else:
        click.echo(format_error_diff(diff), nl=False)


@inspect_group.command("findings", context_settings=_CONTEXT_SETTINGS)
@click.argument("findings_json", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--top",
    type=click.IntRange(min=1),
    default=10,
    show_default=True,
    help="Number of entries to show per section in text output.",
)
@click.option("--json", "json_output", is_flag=True, help="JSON output.")
@pass_ctx
def inspect_findings(
    obj: _Ctx,  # noqa: ARG001
    findings_json: Path,
    top: int,
    json_output: bool,
) -> None:
    """Summarize scan findings from a stdout JSON capture."""
    import json as _json

    from flawed._cli.inspect import format_finding_summary, load_findings, summarize_findings

    payload = load_findings(findings_json)
    summary = summarize_findings(payload)

    if json_output:
        click.echo(_json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    else:
        click.echo(format_finding_summary(summary, top=top), nl=False)


@inspect_group.command("profile", context_settings=_CONTEXT_SETTINGS)
@click.argument("profile_json", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "json_output", is_flag=True, help="JSON output.")
@pass_ctx
def inspect_profile(
    obj: _Ctx,  # noqa: ARG001
    profile_json: Path,
    json_output: bool,
) -> None:
    """Summarize a scan profile report."""
    import json as _json

    from flawed._cli.inspect import format_profile_summary, load_profile, summarize_profile

    payload = load_profile(profile_json)
    summary = summarize_profile(payload)

    if json_output:
        click.echo(_json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    else:
        click.echo(format_profile_summary(summary), nl=False)


@inspect_group.command("gaps", context_settings=_CONTEXT_SETTINGS)
@click.argument("profile_json", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--top",
    type=click.IntRange(min=1),
    default=10,
    show_default=True,
    help="Number of entries to show per section in text output.",
)
@click.option("--json", "json_output", is_flag=True, help="JSON output.")
@pass_ctx
def inspect_gaps(
    obj: _Ctx,  # noqa: ARG001
    profile_json: Path,
    top: int,
    json_output: bool,
) -> None:
    """Summarize analysis gaps from a scan profile report."""
    import json as _json

    from flawed._cli.inspect import format_gap_summary, load_profile, summarize_gaps

    payload = load_profile(profile_json)
    summary = summarize_gaps(payload)

    if json_output:
        click.echo(_json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    else:
        click.echo(format_gap_summary(summary, top=top), nl=False)
