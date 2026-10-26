"""``opentide validate``: object validation and query validation."""

from __future__ import annotations

import typer

from opentide.cli.commands._plan import REMOVED_PLAN_HELP, refuse_removed_plan
from opentide.cli.context import get_context
from opentide.cli.enums import PLATFORM_METAVAR, DetectionPlatform, ValidateCheck, platform_help
from opentide.cli.group_options import hand_down, refuse_dropped
from opentide.cli.output import CommandResult, emit_result, emit_success, emit_usage_error
from opentide.cli.services.validation import run_validate, validate_query_platform

validate_app = typer.Typer(help="Validate objects and queries")

QUERY_STRATEGY_HELP = (
    "Check only rules a run with this strategy deploys (repeatable), on the tenants that "
    "accept it. Default: PREVIEW and RELEASE"
)


@validate_app.callback(invoke_without_command=True)
def validate_group(
    ctx: typer.Context,
    check: ValidateCheck | None = typer.Option(None, "--check", help="Run one check only"),
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
) -> None:
    """Validate detection objects (schema, UUID, uniqueness)."""
    if ctx.invoked_subcommand is not None:
        hand_down(ctx)
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
    result = run_validate(
        cli,
        check=check,
        strict=strict,
        files=file,
        uuids=uuid,
        object_types=object_type,
    )
    emit_result(cli, CommandResult.from_payload(result, default_message="Validation passed"))


@validate_app.command("query")
def validate_query_cmd(
    ctx: typer.Context,
    platform: DetectionPlatform = typer.Option(
        ..., "--platform", metavar=PLATFORM_METAVAR, help=platform_help()
    ),
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
    """Check rule queries against the platform's tenants (needs --live)."""
    refuse_dropped(ctx)
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
