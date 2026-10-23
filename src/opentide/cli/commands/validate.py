"""``opentide validate``: object validation and query validation."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import cast

import typer

from opentide.cli.commands._plan import REMOVED_PLAN_HELP, refuse_removed_plan
from opentide.cli.context import CliContext, get_context
from opentide.cli.enums import DetectionPlatform, ValidateCheck
from opentide.cli.output import (
    CommandResult,
    emit_error,
    emit_result,
    emit_success,
    emit_usage_error,
    text_mode,
)
from opentide.cli.services.validation import (
    fix_phrase,
    run_validate,
    run_validate_fix,
    validate_outcome_line,
    validate_query_platform,
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
from opentide.cli.ui.watch import LiveView, PlainView, Watcher, WatchRun
from opentide.core.logging.config import get_stdout_console

validate_app = typer.Typer(help="Object and query validation")

QUERY_STRATEGY_HELP = (
    "Check only rules a run with this strategy deploys (repeatable), on the tenants that "
    "accept it. Default: PREVIEW and RELEASE"
)


@validate_app.callback(invoke_without_command=True)
def validate_group(
    ctx: typer.Context,
    check: ValidateCheck | None = typer.Option(None, "--check"),
    file: list[str] | None = typer.Option(
        None, "--file", help="Validate only this file (repeatable)"
    ),
    uuid: list[str] | None = typer.Option(None, "--uuid"),
    object_type: list[str] | None = typer.Option(None, "--type"),
    strict: bool = typer.Option(False, "--strict"),
    fix: bool = typer.Option(
        False, "--fix", help="Apply every safe fix (vocabulary typos), then validate again"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="With --fix: print the edits as a diff and change nothing"
    ),
    watch: bool = typer.Option(
        False, "--watch", help="Validate again each time an object file changes; Ctrl-C stops"
    ),
) -> None:
    """Validate detection objects (schema, UUID, uniqueness)."""
    if ctx.invoked_subcommand is not None:
        return
    cli = get_context(ctx)
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
    scope = {"check": check, "strict": strict, "uuids": uuid, "object_types": object_type}
    if watch:
        if fix:
            emit_usage_error(
                cli,
                "--watch cannot be combined with --fix: it would rewrite files while you edit them.",
                argument="--watch",
                code=USAGE_ERROR,
            )
        _watch(cli, files=file, **scope)
        return
    if fix:
        result = run_validate_fix(cli, dry_run=dry_run, files=file, **scope)
    else:
        result = run_validate(cli, files=file, **scope)
    diagnostics = result.pop("_diagnostics", [])
    plan = result.pop("_fix_plan", None)
    fixed = result.pop("_fixed", None)
    outcome = CommandResult.from_payload(result, default_message="Validation passed")
    if cli.json_output:
        emit_result(cli, outcome)
        return
    stdout = get_stdout_console()
    mode = text_mode(cli)
    if fix and dry_run and plan:
        render_diff(stdout, plan.diff())
        # The diff shows the findings it fixes; the frames show the rest.
        planned = {(change.file_path, change.line, change.column) for change in plan.changes}
        diagnostics = [
            item for item in diagnostics if (item.file_path, item.line, item.column) not in planned
        ]
    if fixed and not cli.quiet:
        render_fixed(stdout, fixed.changes)
    render_diagnostics(stdout, diagnostics, mode=mode, quiet=cli.quiet)
    line = outcome.message
    if not line.startswith("Validation passed, but"):
        done = plan if dry_run else fixed
        phrase = None
        if fix and done is not None and (done or not outcome.ok):
            phrase = fix_phrase(len(done.changes), done.file_count, dry_run=dry_run)
        line = validate_outcome_line(
            outcome.summary, failed=not outcome.ok, seconds=elapsed_ms() / 1000, fix=phrase
        )
    # The code frames above show every warning; a warning line would repeat it.
    emit_result(cli, replace(outcome, outcome=line, warnings=()))


def _watch(
    cli: CliContext,
    *,
    check: ValidateCheck | None,
    strict: bool,
    files: list[str] | None,
    uuids: list[str] | None,
    object_types: list[str] | None,
) -> None:
    """``validate --watch``: a Live view in ``human`` mode, an outcome line per run in ``plain``."""
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
        )
        summary = cast(dict[str, int], result.get("_summary") or {})
        return list(result.get("_diagnostics") or []), int(summary.get("objects", 0))

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
            footer = "watching " + ", ".join(_shown(root) for root in roots)
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


def _shown(path: Path) -> str:
    try:
        return path.relative_to(Path.cwd()).as_posix() or "."
    except ValueError:
        return path.as_posix()


@validate_app.command("query")
def validate_query_cmd(
    ctx: typer.Context,
    platform: DetectionPlatform = typer.Option(..., "--platform"),
    strategy: list[str] | None = typer.Option(None, "--strategy", help=QUERY_STRATEGY_HELP),
    plan: str | None = typer.Option(None, "--plan", hidden=True, help=REMOVED_PLAN_HELP),
    wide: bool = typer.Option(
        False, "--wide", help="Check every status strategy but DISABLEMENT and DELETION"
    ),
    live: bool = typer.Option(
        False,
        "--live",
        help="Check the tenant (needs platform SDKs and credentials)",
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
        None, "--file", help="Check only this rule file (repeatable)"
    ),
    uuid: list[str] | None = typer.Option(
        None, "--uuid", help="Check only the rule with this UUID (repeatable)"
    ),
) -> None:
    """Query validation checks the tenant. Pass --live."""
    cli = get_context(ctx)
    refuse_removed_plan(cli, plan)
    result = validate_query_platform(
        cli,
        platform.value,
        strategies=strategy or (),
        wide=wide,
        live=live,
        changed=changed,
        files=file or (),
        uuids=uuid or (),
    )
    emit_success(cli, result)
