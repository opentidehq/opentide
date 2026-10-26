"""``opentide share`` commands."""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer

from opentide.cli.context import get_context
from opentide.cli.group_options import hand_down, refuse_dropped
from opentide.cli.output import CommandResult, emit_result

if TYPE_CHECKING:
    from opentide.cli.services.share import ShareMode

share_app = typer.Typer(
    help="Publish objects to intelligence platforms",
    no_args_is_help=False,
)


def _dispatch(
    ctx: typer.Context,
    mode: ShareMode,
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
    from contextlib import nullcontext

    from opentide.cli.services.share import render_share, run_share
    from opentide.cli.ui.terminal_progress import TerminalProgress

    refuse_dropped(ctx)
    cli = get_context(ctx)
    # Listing targets reads one file; every other mode reads the catalogue.
    with nullcontext() if mode == "targets" else TerminalProgress():
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


#: Option help shared by ``share`` and its subcommands.
_TARGET_HELP = "Destination block name. Repeatable."
_UUID_HELP = "Limit to these object UUIDs."
_TYPE_HELP = "Limit to threat, objective, or rule."
_FILE_HELP = "Limit to these object files."
_DRY_RUN_HELP = "Resolve the run locally and make no request."
_PUBLISH_HELP = "Override the block publish flag."
_WORKERS_HELP = "Parallel object workers for one destination."


@share_app.callback(invoke_without_command=True)
def share_default(
    ctx: typer.Context,
    target: list[str] | None = typer.Option(None, "--target", help=_TARGET_HELP),
    uuid: list[str] | None = typer.Option(None, "--uuid", help=_UUID_HELP),
    object_type: list[str] | None = typer.Option(None, "--type", help=_TYPE_HELP),
    file: list[str] | None = typer.Option(None, "--file", help=_FILE_HELP),
    dry_run: bool = typer.Option(False, "--dry-run", help=_DRY_RUN_HELP),
    publish: bool | None = typer.Option(None, "--publish/--no-publish", help=_PUBLISH_HELP),
    workers: int = typer.Option(1, "--workers", help=_WORKERS_HELP),
    changed: bool = typer.Option(
        False,
        "--changed",
        help="Share only objects the default-branch CI diff changed.",
    ),
) -> None:
    """Publish objects to every enabled sharing target (same as ``share push``)."""
    if ctx.invoked_subcommand is not None:
        hand_down(ctx)
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
    target: list[str] | None = typer.Option(None, "--target", help=_TARGET_HELP),
    uuid: list[str] | None = typer.Option(None, "--uuid", help=_UUID_HELP),
    object_type: list[str] | None = typer.Option(None, "--type", help=_TYPE_HELP),
    file: list[str] | None = typer.Option(None, "--file", help=_FILE_HELP),
    dry_run: bool = typer.Option(False, "--dry-run", help=_DRY_RUN_HELP),
    publish: bool | None = typer.Option(None, "--publish/--no-publish", help=_PUBLISH_HELP),
    workers: int = typer.Option(1, "--workers", help=_WORKERS_HELP),
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
    target: list[str] | None = typer.Option(None, "--target", help=_TARGET_HELP),
    uuid: list[str] | None = typer.Option(None, "--uuid", help=_UUID_HELP),
    object_type: list[str] | None = typer.Option(None, "--type", help=_TYPE_HELP),
    file: list[str] | None = typer.Option(None, "--file", help=_FILE_HELP),
    workers: int = typer.Option(1, "--workers", help=_WORKERS_HELP),
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
    target: list[str] | None = typer.Option(None, "--target", help=_TARGET_HELP),
    uuid: list[str] | None = typer.Option(None, "--uuid", help=_UUID_HELP),
    object_type: list[str] | None = typer.Option(None, "--type", help=_TYPE_HELP),
    file: list[str] | None = typer.Option(None, "--file", help=_FILE_HELP),
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
    target: list[str] | None = typer.Option(None, "--target", help=_TARGET_HELP),
    uuid: list[str] | None = typer.Option(None, "--uuid", help=_UUID_HELP),
    object_type: list[str] | None = typer.Option(None, "--type", help=_TYPE_HELP),
    file: list[str] | None = typer.Option(None, "--file", help=_FILE_HELP),
    delete: bool = typer.Option(
        False, "--delete", help="Delete the remote event instead of unpublishing it."
    ),
    yes: bool = typer.Option(False, "--yes", help="Confirm --delete."),
    workers: int = typer.Option(1, "--workers", help=_WORKERS_HELP),
) -> None:
    """Unpublish a shared event, or delete it when `--delete --yes` is set."""
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
