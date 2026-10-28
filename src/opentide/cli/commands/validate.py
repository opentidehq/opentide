"""``opentide validate``: object validation and query validation."""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import typer

from opentide.analysis import OFFLINE_QUERY_PLATFORMS
from opentide.cli.commands._plan import REMOVED_PLAN_HELP, refuse_removed_plan
from opentide.cli.context import CliContext, get_context
from opentide.cli.enums import (
    PLATFORM_METAVAR,
    QUERY_VALIDATION_PLATFORMS,
    DetectionPlatform,
    QueriesMode,
    ValidateCheck,
)
from opentide.cli.findings import (
    FORMAT_HELP,
    OUTPUT_HELP,
    check_report_options,
    print_report,
    publish_findings,
    publish_summary,
    write_report_file,
)
from opentide.cli.group_options import hand_down, refuse_dropped
from opentide.cli.output import (
    CommandResult,
    emit_error,
    emit_result,
    emit_success,
    emit_usage_error,
    text_mode,
)
from opentide.cli.ui.codeframe import render_diagnostics, render_diff, render_fixed
from opentide.cli.ui.contract import (
    USAGE_ERROR,
    USAGE_EXIT_CODE,
    USAGE_WATCH_NEEDS_TTY,
    NextAction,
)
from opentide.cli.ui.diagnostics import Diagnostic
from opentide.cli.ui.mode import OutputMode, elapsed_ms, get_mode
from opentide.cli.ui.render import render_warnings
from opentide.cli.ui.reports import ReportFormat
from opentide.cli.ui.watch import LiveView, PlainView, Watcher, WatchRun
from opentide.core.logging.config import get_console, get_stdout_console

if TYPE_CHECKING:
    from opentide.cli.ui.fixes import FixPlan

validate_app = typer.Typer(help="Validate objects and queries")

QUERY_STRATEGY_HELP = (
    "Check only rules a run with this strategy deploys (repeatable), on the tenants that "
    "accept it. Default: PREVIEW and RELEASE"
)

CHECK_HELP = "Run one check only: " + ", ".join(item.value for item in ValidateCheck)

QUERY_PLATFORM_HELP = (
    "Check this platform's queries. Offline, default every platform the engine parses: "
    + ", ".join(sorted(OFFLINE_QUERY_PLATFORMS))
    + ". --live needs one of: "
    + ", ".join(sorted(QUERY_VALIDATION_PLATFORMS))
)

QUERIES_HELP = (
    "How a query the platform would reject is reported: error (the default), warn (passes "
    "unless --strict) or off (queries are not checked)"
)


@validate_app.callback(invoke_without_command=True)
def validate_group(
    ctx: typer.Context,
    check: ValidateCheck | None = typer.Option(
        None,
        "--check",
        metavar="CHECK",
        help=CHECK_HELP,
    ),
    file: list[str] | None = typer.Option(
        None, "--file", help="Validate only this file (repeatable)"
    ),
    uuid: list[str] | None = typer.Option(
        None, "--uuid", help="Validate only the object with this UUID (repeatable)"
    ),
    object_type: list[str] | None = typer.Option(
        None, "--type", help="Validate only this type: rule, threat or objective (repeatable)"
    ),
    strict: bool = typer.Option(False, "--strict", help="Fail on warnings too"),
    queries: QueriesMode | None = typer.Option(
        None, "--queries", metavar="error|warn|off", help=QUERIES_HELP
    ),
    fix: bool = typer.Option(
        False, "--fix", help="Apply every safe fix (vocabulary typos), then validate again"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="With --fix: print the edits as a diff and change nothing"
    ),
    watch: bool = typer.Option(
        False, "--watch", help="Validate again each time an object file changes; Ctrl-C stops"
    ),
    report_format: ReportFormat = typer.Option(ReportFormat.text, "--format", help=FORMAT_HELP),
    output: Path | None = typer.Option(None, "--output", help=OUTPUT_HELP),
) -> None:
    """Validate detection objects: schema, UUIDs, uniqueness, configuration and queries."""
    from opentide.cli.services.validation import (
        fix_phrase,
        run_validate,
        run_validate_fix,
        validate_outcome_line,
    )

    if ctx.invoked_subcommand is not None:
        hand_down(ctx)
        return
    cli = get_context(ctx)
    check_report_options(cli, report_format, output)
    valid_object_types = ("rule", "threat", "objective")
    unknown_types = sorted(set(object_type or []) - set(valid_object_types))
    if unknown_types:
        emit_usage_error(
            cli,
            "Unknown object type(s): "
            + ", ".join(unknown_types)
            + ". Choose rule, threat, or objective.",
            argument="--type",
            value=unknown_types[0],
            choices=valid_object_types,
        )
    if dry_run and not fix:
        emit_usage_error(
            cli, "--dry-run previews --fix. Pass both.", argument="--dry-run", code=USAGE_ERROR
        )
    refuse_queries_mode(cli, queries, check)
    scope: dict[str, Any] = {
        "check": check,
        "strict": strict,
        "uuids": uuid,
        "object_types": object_type,
        "queries": queries or QueriesMode.error,
    }
    if watch:
        if fix:
            emit_usage_error(
                cli,
                "--watch cannot be combined with --fix: "
                "it would rewrite files while you edit them.",
                argument="--watch",
                code=USAGE_ERROR,
            )
        if report_format is not ReportFormat.text:
            emit_usage_error(
                cli,
                "--watch cannot be combined with --format: a watch prints a view, not a report.",
                argument="--watch",
                code=USAGE_ERROR,
            )
        _watch(cli, files=file, **scope)
        return
    from opentide.cli.ui.progress import busy

    # A report on stdout is whole: no spinner then either (it draws on stderr).
    with busy("Validating objects", quiet=cli.quiet or report_format is not ReportFormat.text):
        if fix:
            result = run_validate_fix(cli, dry_run=dry_run, files=file, **scope)
        else:
            result = run_validate(cli, files=file, **scope)
    diagnostics = cast("list[Diagnostic]", result.pop("_diagnostics", []))
    plan = cast("FixPlan | None", result.pop("_fix_plan", None))
    fixed = cast("FixPlan | None", result.pop("_fixed", None))
    unwritten = cast(list[str], result.pop("_unwritten", []))
    unwritten_fixes = cast(int, result.pop("_unwritten_fixes", 0))
    outcome = CommandResult.from_payload(result, default_message="Validation passed")
    write_report_file(report_format, output, diagnostics, command="validate")
    if cli.json_output:
        emit_result(cli, outcome)
        return
    if report_format is not ReportFormat.text and output is None:
        # The report is the whole of stdout: no diff, frames or outcome line.
        print_report(report_format, diagnostics, outcome, command="validate")
    stdout = get_stdout_console()
    mode = text_mode(cli)
    shown = diagnostics
    if fix and dry_run and plan:
        render_diff(stdout, plan.diff())
        # The diff shows the findings it fixes; the frames show the rest.
        planned = {(change.file_path, change.line, change.column) for change in plan.changes}
        shown = [
            item for item in diagnostics if (item.file_path, item.line, item.column) not in planned
        ]
    if fixed and not cli.quiet:
        render_fixed(stdout, fixed.changes)
    render_warnings(get_console(), [f"Could not write the fix to {line}" for line in unwritten])
    render_diagnostics(stdout, shown, mode=mode, quiet=cli.quiet)
    line = outcome.message
    if not line.startswith("Validation passed, but"):
        done = plan if dry_run else fixed
        phrase = None
        if fix and done is not None and (done or unwritten_fixes or not outcome.ok):
            phrase = fix_phrase(
                len(done.changes), done.file_count, dry_run=dry_run, unwritten=unwritten_fixes
            )
        line = validate_outcome_line(
            outcome.summary, failed=not outcome.ok, seconds=elapsed_ms() / 1000, fix=phrase
        )
    publish_findings(cli, diagnostics, outcome, command="validate", outcome=line)
    # The code frames above show every warning; a warning line would repeat it.
    emit_result(cli, replace(outcome, outcome=line, warnings=()))


def refuse_queries_mode(
    cli: CliContext, queries: QueriesMode | None, check: ValidateCheck | None
) -> None:
    """Refuse a ``--queries`` the run would ignore, or that contradicts ``--check``."""
    if queries is None or check is None:
        return
    if check is not ValidateCheck.queries:
        emit_usage_error(
            cli,
            f"--queries sets how the queries check reports; --check {check.value} does not run it",
            argument="--queries",
            code=USAGE_ERROR,
        )
    if queries is QueriesMode.off:
        emit_usage_error(
            cli,
            "--check queries runs the queries check and --queries off skips it: pass one of them",
            argument="--queries",
            code=USAGE_ERROR,
        )


def _watch(
    cli: CliContext,
    *,
    check: ValidateCheck | None,
    strict: bool,
    files: list[str] | None,
    uuids: list[str] | None,
    object_types: list[str] | None,
    queries: QueriesMode = QueriesMode.error,
) -> None:
    """``validate --watch``: a Live view in ``human`` mode, an outcome line per run in ``plain``."""
    from opentide.cli.services.validation import run_validate, validate_outcome_line

    mode = get_mode()
    if mode in (OutputMode.JSON, OutputMode.AGENT, OutputMode.MCP):
        emit_error(
            cli,
            f"--watch redraws the terminal until Ctrl-C, so it does not run in {mode} mode",
            exit_code=USAGE_EXIT_CODE,
            code=USAGE_WATCH_NEEDS_TTY,
            argument="--watch",
            next_actions=[NextAction("opentide validate", "validate once")],
        )
    from opentide.validation.disabled_platforms import STRICT_EXEMPT_WARNINGS

    def validate(changed: Sequence[Path] | None) -> tuple[list[Diagnostic], int]:
        # run_validate rebuilds the registry each time, so it reads the saved files.
        targets = files if changed is None else [str(path) for path in changed]
        result = run_validate(
            cli,
            check=check,
            strict=strict,
            files=targets,
            uuids=uuids if changed is None else None,
            object_types=object_types if changed is None else None,
            queries=queries,
        )
        summary = cast(dict[str, int], result.get("_summary") or {})
        diagnostics = cast("list[Diagnostic]", result.get("_diagnostics") or [])
        return list(diagnostics), int(summary.get("objects", 0))

    cli.apply_environment()
    roots = watched_folders()
    watcher = Watcher(
        roots=roots,
        validate=validate,
        strict=strict,
        scoped_runs=not (files or uuids or object_types),
        strict_exempt=frozenset(STRICT_EXEMPT_WARNINGS),
    )

    def describe(run: WatchRun) -> str:
        return validate_outcome_line(run.summary, failed=run.failed, seconds=run.seconds)

    stdout = get_stdout_console()
    try:
        if mode is OutputMode.HUMAN:
            footer = f"watching {_shown(roots)}"
            with LiveView(stdout, describe, footer=footer, quiet=cli.quiet) as view:
                watcher.run(view)
        else:
            watcher.run(PlainView(stdout, describe, mode=text_mode(cli), quiet=cli.quiet))
    except KeyboardInterrupt:
        return


def watched_folders() -> list[Path]:
    """The rule, threat and objective folders of the workspace that exist."""
    from opentide.registry.paths import resolve_workspace_paths

    paths = resolve_workspace_paths()
    return [
        Path(paths[key])
        for key in ("threat", "objective", "rule")
        if key in paths and Path(paths[key]).is_dir()
    ]


def _shown(roots: Sequence[Path]) -> str:
    """The folder that holds every watched one, relative to the current directory."""
    if not roots:
        return "nothing: no object folder exists"
    common = Path(os.path.commonpath([str(root) for root in roots]))
    try:
        return common.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return common.as_posix()


@validate_app.command("query")
def validate_query_cmd(
    ctx: typer.Context,
    platform: DetectionPlatform | None = typer.Option(
        None,
        "--platform",
        metavar=PLATFORM_METAVAR,
        help=QUERY_PLATFORM_HELP,
    ),
    strategy: list[str] | None = typer.Option(None, "--strategy", help=QUERY_STRATEGY_HELP),
    plan: str | None = typer.Option(None, "--plan", hidden=True, help=REMOVED_PLAN_HELP),
    wide: bool = typer.Option(
        False, "--wide", help="Check every status strategy but DISABLEMENT and DELETION (--live)"
    ),
    live: bool = typer.Option(
        False,
        "--live",
        help="Check the queries on the platform's tenants (needs credentials)",
    ),
    changed: bool = typer.Option(
        False,
        "--changed",
        help=(
            "Check only the rule files this run changed: the pull or merge request, the "
            "push, or outside CI the last commit (the files deploy reads)"
        ),
    ),
    file: list[str] | None = typer.Option(
        None,
        "--file",
        help=(
            "Check only this rule file, or this query file (.kql, .spl, .esql, .eql, .kuery, "
            ".lucene) offline (repeatable)"
        ),
    ),
    uuid: list[str] | None = typer.Option(
        None, "--uuid", help="Check only the rule with this UUID (repeatable)"
    ),
    strict: bool = typer.Option(False, "--strict", help="Fail on warnings too"),
    queries: QueriesMode | None = typer.Option(
        None,
        "--queries",
        metavar="error|warn",
        help="How a rejected query is reported offline: error (the default) or warn",
    ),
) -> None:
    """Check rule queries offline with the analysis engine, or on the tenants (--live).

    Offline, the engine reports the queries the platform would reject, as
    `opentide validate` does; `opentide lint` reports their style.
    """
    from opentide.analysis import is_query_file
    from opentide.cli.services.validation import validate_query_platform

    refuse_dropped(ctx)
    cli = get_context(ctx)
    refuse_removed_plan(cli, plan)
    if queries is QueriesMode.off:
        emit_usage_error(
            cli,
            "--queries off skips the queries check, which is all validate query runs",
            argument="--queries",
            code=USAGE_ERROR,
        )
    if not live:
        for flag, used in (("--strategy", bool(strategy)), ("--wide", wide)):
            if used:
                emit_usage_error(
                    cli,
                    f"{flag} chooses tenants, so it applies to --live; the offline check "
                    "reads every query whatever its status",
                    argument=flag,
                    code=USAGE_ERROR,
                )
    else:
        for flag, used in (("--strict", strict), ("--queries", queries is not None)):
            if used:
                emit_usage_error(
                    cli,
                    f"{flag} applies to the offline check: a tenant accepts or rejects a query",
                    argument=flag,
                    code=USAGE_ERROR,
                )
        if any(is_query_file(target) for target in file or ()):
            emit_usage_error(
                cli,
                "a query file is checked offline: --live sends the queries of rules to tenants",
                argument="--file",
                code=USAGE_ERROR,
            )
    result = validate_query_platform(
        cli,
        None if platform is None else platform.value,
        strategies=strategy or (),
        wide=wide,
        live=live,
        changed=changed,
        files=file or (),
        uuids=uuid or (),
        strict=strict,
        queries=queries or QueriesMode.error,
    )
    if result.get("mode") == "offline":
        _emit_offline_query_result(cli, result)
        return
    from opentide.cli.ui.summary import query_summary

    publish_summary(cli, query_summary(result), command="validate query", payload=result)
    emit_success(cli, result)


def _emit_offline_query_result(cli: CliContext, result: dict[str, Any]) -> None:
    """Code frames, CI annotations and one outcome line, like ``validate``."""
    diagnostics = cast("list[Diagnostic]", result.pop("_diagnostics", []))
    outcome = CommandResult.from_payload(result, default_message="Queries valid")
    if not cli.json_output:
        render_diagnostics(get_stdout_console(), diagnostics, mode=text_mode(cli), quiet=cli.quiet)
        publish_findings(
            cli,
            diagnostics,
            outcome,
            command="validate query",
            outcome=outcome.outcome or outcome.message,
        )
    emit_result(cli, outcome)
