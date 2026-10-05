"""``opentide share`` commands."""

from __future__ import annotations

import typer

from opentide.cli.context import get_context
from opentide.cli.output import CommandResult, emit_result
from opentide.cli.services.share import render_share, run_share

share_app = typer.Typer(
    help="Publish Tide objects to intelligence platforms",
    no_args_is_help=False,
)


def _dispatch(
    ctx: typer.Context,
    mode: str,
    *,
    target: list[str] | None,
    uuid: list[str] | None,
    object_type: list[str] | None,
    file: list[str] | None,
    dry_run: bool,
    publish: bool | None,
    workers: int,
    delete: bool,
    yes: bool,
    changed: bool = False,
) -> None:
    cli = get_context(ctx)
    payload = run_share(
        cli,
        mode=mode,
        targets=target,
        uuids=uuid,
        types=object_type,
        files=file,
        dry_run=dry_run,
        publish=publish,
        workers=workers,
        delete=delete,
        confirmed=yes,
        changed=changed,
    )
    if not cli.json_output:
        render_share(payload)
    emit_result(cli, CommandResult.from_payload(payload, default_message="Share finished"))


@share_app.callback(invoke_without_command=True)
def share_default(
    ctx: typer.Context,
    target: list[str] | None = typer.Option(
        None, "--target", help="Destination block name. Repeatable."
    ),
    uuid: list[str] | None = typer.Option(None, "--uuid", help="Limit to these object UUIDs."),
    object_type: list[str] | None = typer.Option(
        None, "--type", help="Limit to threat, objective, or rule."
    ),
    file: list[str] | None = typer.Option(None, "--file", help="Limit to these object files."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Resolve the run locally and make no request."
    ),
    publish: bool | None = typer.Option(
        None, "--publish/--no-publish", help="Override the block publish flag."
    ),
    workers: int = typer.Option(
        1, "--workers", help="Parallel object workers for one destination."
    ),
    changed: bool = typer.Option(
        False,
        "--changed",
        help="Share only objects the default-branch CI diff changed.",
    ),
) -> None:
    """Publish objects to every enabled sharing target (same as ``share push``)."""
    if ctx.invoked_subcommand is not None:
        return
    _dispatch(
        ctx,
        "push",
        target=target,
        uuid=uuid,
        object_type=object_type,
        file=file,
        dry_run=dry_run,
        publish=publish,
        workers=workers,
        delete=False,
        yes=False,
        changed=changed,
    )


@share_app.command("push")
def share_push(
    ctx: typer.Context,
    target: list[str] | None = typer.Option(None, "--target"),
    uuid: list[str] | None = typer.Option(None, "--uuid"),
    object_type: list[str] | None = typer.Option(None, "--type"),
    file: list[str] | None = typer.Option(None, "--file"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    publish: bool | None = typer.Option(None, "--publish/--no-publish"),
    workers: int = typer.Option(1, "--workers"),
    changed: bool = typer.Option(
        False,
        "--changed",
        help="Share only objects the default-branch CI diff changed.",
    ),
) -> None:
    """Create or update one MISP Event per selected Tide object."""
    _dispatch(
        ctx,
        "push",
        target=target,
        uuid=uuid,
        object_type=object_type,
        file=file,
        dry_run=dry_run,
        publish=publish,
        workers=workers,
        delete=False,
        yes=False,
        changed=changed,
    )


@share_app.command("preview")
def share_preview(
    ctx: typer.Context,
    target: list[str] | None = typer.Option(None, "--target"),
    uuid: list[str] | None = typer.Option(None, "--uuid"),
    object_type: list[str] | None = typer.Option(None, "--type"),
    file: list[str] | None = typer.Option(None, "--file"),
    workers: int = typer.Option(1, "--workers"),
) -> None:
    """Show what push would do. Makes no request and writes nothing."""
    _dispatch(
        ctx,
        "preview",
        target=target,
        uuid=uuid,
        object_type=object_type,
        file=file,
        dry_run=True,
        publish=None,
        workers=workers,
        delete=False,
        yes=False,
    )


@share_app.command("status")
def share_status(
    ctx: typer.Context,
    target: list[str] | None = typer.Option(None, "--target"),
    uuid: list[str] | None = typer.Option(None, "--uuid"),
    object_type: list[str] | None = typer.Option(None, "--type"),
    file: list[str] | None = typer.Option(None, "--file"),
) -> None:
    """Compare the local ledger with object versions. Does not contact the destination."""
    _dispatch(
        ctx,
        "status",
        target=target,
        uuid=uuid,
        object_type=object_type,
        file=file,
        dry_run=False,
        publish=None,
        workers=1,
        delete=False,
        yes=False,
    )


@share_app.command("retract")
def share_retract(
    ctx: typer.Context,
    target: list[str] | None = typer.Option(None, "--target"),
    uuid: list[str] | None = typer.Option(None, "--uuid"),
    object_type: list[str] | None = typer.Option(None, "--type"),
    file: list[str] | None = typer.Option(None, "--file"),
    delete: bool = typer.Option(
        False, "--delete", help="Delete the remote event instead of unpublishing it."
    ),
    yes: bool = typer.Option(False, "--yes", help="Confirm --delete."),
    workers: int = typer.Option(1, "--workers"),
) -> None:
    """Unpublish a shared event, or delete it when ``--delete --yes`` is set."""
    _dispatch(
        ctx,
        "retract",
        target=target,
        uuid=uuid,
        object_type=object_type,
        file=file,
        dry_run=False,
        publish=None,
        workers=workers,
        delete=delete,
        yes=yes,
    )


@share_app.command("targets")
def share_targets(ctx: typer.Context) -> None:
    """List sharing destinations. The API key is never printed."""
    _dispatch(
        ctx,
        "targets",
        target=None,
        uuid=None,
        object_type=None,
        file=None,
        dry_run=False,
        publish=None,
        workers=1,
        delete=False,
        yes=False,
    )
