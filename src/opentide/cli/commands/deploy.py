"""``opentide deploy``: rule deployment and deployment-state maintenance."""

from __future__ import annotations

import typer

from opentide.cli.commands._plan import REMOVED_PLAN_HELP, refuse_removed_plan
from opentide.cli.context import get_context
from opentide.cli.enums import DetectionPlatform
from opentide.cli.output import CommandResult, emit_error, emit_result
from opentide.cli.services.deploy import run_deploy

#: A status (DEVELOPMENT, STAGING, PRODUCTION, ... in the default configuration)
#: maps to a strategy; a run names the strategy it deploys, never a status.
DEPLOY_STRATEGY_HELP = (
    "Status strategy this run deploys (repeatable). PREVIEW: rules whose status maps to "
    "PREVIEW or UNIVERSAL. RELEASE: rules whose status maps to RELEASE or UNIVERSAL, and "
    "disables or deletes those mapping to DISABLEMENT or DELETION. Each rule goes to the "
    "tenants whose 'strategies' accept the run's strategy. Status names such as STAGING or "
    "PRODUCTION are not strategies"
)

deploy_app = typer.Typer(help="Rule deployment")


@deploy_app.callback(invoke_without_command=True)
def deploy_cmd(
    ctx: typer.Context,
    platform: DetectionPlatform | None = typer.Option(None, "--platform"),
    strategy: list[str] | None = typer.Option(None, "--strategy", help=DEPLOY_STRATEGY_HELP),
    all_files: bool = typer.Option(
        False,
        "--all",
        help=(
            "Read every rule file, not only those the run changed (the pull or merge "
            "request, the push, or outside CI the last commit)"
        ),
    ),
    plan: str | None = typer.Option(None, "--plan", hidden=True, help=REMOVED_PLAN_HELP),
    wide: bool = typer.Option(
        False,
        "--wide",
        help="Deploy the rule files read whatever their status strategy, INERT included",
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
    keep_deprecated: bool | None = typer.Option(
        None,
        "--keep-deprecated/--drop-deprecated",
        help=(
            "Include rules whose status maps to DISABLEMENT or DELETION, so a RELEASE run "
            "disables or deletes them. Default: on, off with --all"
        ),
    ),
    skip_promotion: bool = typer.Option(False, "--skip-promotion"),
    skip_unconfigured: bool = typer.Option(
        False,
        "--skip-unconfigured",
        help="Exit 0 when every platform with rules to deploy has no \\[\\[tenants]] block",
    ),
    persist_state_externally: bool = typer.Option(
        False,
        "--persist-state-externally",
        help=(
            "Allow Defender, SentinelOne and CrowdStrike creates in a CI run other than a "
            "RELEASE run on a push; this pipeline must commit .opentide/states/deployment/ itself"
        ),
    ),
) -> None:
    """Deploy the changed rules whose status maps to --strategy.

    A status (DEVELOPMENT, STAGING, PRODUCTION, ... in the default
    configuration) maps to a strategy in deployment.toml. A run deploys the
    rule files it changed whose status maps to its --strategy, to the tenants
    whose 'strategies' accept it. The pull or merge request job runs
    --strategy PREVIEW; the default-branch job runs --strategy RELEASE.
    """
    if ctx.invoked_subcommand is not None:
        return
    cli = get_context(ctx)
    refuse_removed_plan(cli, plan)
    result = run_deploy(
        cli,
        strategies=strategy or (),
        all_files=all_files,
        platform=platform,
        dry_run=dry_run,
        skip_promotion=skip_promotion,
        keep_deprecated=keep_deprecated,
        wide=wide,
        skip_unconfigured=skip_unconfigured,
        persist_state_externally=persist_state_externally,
    )
    from opentide.cli.findings import publish_summary
    from opentide.cli.ui.summary import deploy_summary

    publish_summary(cli, deploy_summary(result, dry_run=dry_run), command="deploy", payload=result)
    emit_result(cli, CommandResult.from_payload(result, default_message="Deployment completed"))


@deploy_app.command("migrate-state")
def deploy_migrate_state_cmd(ctx: typer.Context) -> None:
    """Move vendor rule ids off rules into .opentide/states/deployment/ (no vendor calls).

    Refuses with deployment_state_ignored, and edits nothing, while .gitignore
    hides .opentide/states/deployment/. Exits 1 when any rule cannot be migrated;
    ids dropped from other platforms (external_id_unused) are warnings only.
    """
    from opentide.cli.services.migrate_state import run_migrate_state
    from opentide.core.index_manager import IndexManager
    from opentide.registry.discovery import discover_workspace

    cli = get_context(ctx)
    cli.apply_environment()
    workspace = discover_workspace()
    rules_dir = (
        IndexManager.return_paths(tier="tide").get("rule") or workspace / "objects" / "rules"
    )
    result = run_migrate_state(workspace, rules_dir)
    emit_result(cli, CommandResult.from_payload(result, default_message="Migration completed"))


@deploy_app.command("replay-state", hidden=True)
def deploy_replay_state_cmd(
    state_commit: str = typer.Argument(..., help="Commit whose deployment-state changes to replay"),
) -> None:
    """Replay one commit's deployment-state changes onto the checkout (CI write-back).

    Used by the generated production write-back when its rule files conflict
    with a concurrent merge. A subcommand rather than ``python -m`` so it runs
    in the interpreter that has opentide, whatever ``python`` is on PATH.
    """
    from opentide.ci.state_replay import main as replay_main

    raise typer.Exit(replay_main([state_commit]))


@deploy_app.command("metadata", hidden=True)
def deploy_metadata_cmd(
    ctx: typer.Context, platform: DetectionPlatform = typer.Option(..., "--platform")
) -> None:
    """Reserved for a future metadata deployment implementation."""
    cli = get_context(ctx)
    emit_error(
        cli,
        f"Metadata deployment is not implemented for {platform.value}",
        exit_code=2,
        code="not_implemented",
    )
