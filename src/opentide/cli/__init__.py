"""OpenTide Typer CLI application."""

from __future__ import annotations

import structlog
import typer

from opentide.cli.context import CliContext, get_context
from opentide.cli.enums import (
    DetectionPlatform,
    DocumentScope,
    ExportTarget,
    ExtractImport,
    GeneratePhase,
    ValidateCheck,
)
from opentide.cli.output import emit, emit_success
from opentide.cli.services.deploy import run_deploy
from opentide.cli.services.document import run_document
from opentide.cli.services.export import run_export
from opentide.cli.services.extraction import run_extract
from opentide.cli.services.generation import run_generate
from opentide.cli.services.info import collect_info
from opentide.cli.services.mutate import run_mutate
from opentide.cli.services.validation import run_validate, validate_query_platform
from opentide.cli.setup_app import setup_app
from opentide.core.logging import LoggingConfig, init_logging, print_banner
from opentide.core.root import get_repo_root

logger = structlog.get_logger("opentide.cli.__init__")
app = typer.Typer(
    name="opentide",
    help="OpenTide — DetectionOps Engine",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


@app.callback()
def main_callback(
    ctx: typer.Context,
    repo: str | None = typer.Option(
        None, "--repo", envvar="OPENTIDE_REPO_ROOT", help="Repository root"
    ),
    data: str | None = typer.Option(
        None, "--data", envvar="OPENTIDE_DATA_ROOT", help="Bundled data root"
    ),
    debug: bool = typer.Option(False, "--debug", envvar="DEBUG", help="Enable debug logging"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable Rich colour output"),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON output"),
) -> None:
    from pathlib import Path

    cli_ctx = CliContext(
        repo=Path(repo) if repo else get_repo_root(),
        data=Path(data) if data else None,
        json_output=json_output,
        debug=debug,
        no_color=no_color,
    )
    ctx.obj = cli_ctx
    cli_ctx.activate()
    cli_ctx.apply_environment()
    init_logging(LoggingConfig.from_cli_context(cli_ctx), force=True)
    if not json_output:
        print_banner()


app.add_typer(setup_app, name="setup")


generate_app = typer.Typer(help="Framework generation pipeline")
app.add_typer(generate_app, name="generate")


@generate_app.callback(invoke_without_command=True)
def generate_cmd(
    ctx: typer.Context,
    phase: GeneratePhase | None = typer.Option(None, "--phase"),
    staging: bool = typer.Option(False, "--staging"),
    verbose: bool = typer.Option(False, "--verbose"),
) -> None:
    """Generate indexes, schemas, templates, and exports."""
    cli = get_context(ctx)
    if verbose:
        cli.debug = True
        cli.apply_environment()
        init_logging(LoggingConfig.from_cli_context(cli), force=True)
    result = run_generate(cli, phase=phase, staging=staging)
    emit_success(cli, result)


validate_app = typer.Typer(help="Object and query validation")
app.add_typer(validate_app, name="validate")


@validate_app.callback(invoke_without_command=True)
def validate_group(
    ctx: typer.Context,
    check: ValidateCheck | None = typer.Option(None, "--check"),
    file: str | None = typer.Option(None, "--file"),
    uuid: list[str] | None = typer.Option(None, "--uuid"),
    object_type: list[str] | None = typer.Option(None, "--type"),
    strict: bool = typer.Option(False, "--strict"),
) -> None:
    """Validate detection objects (schema, UUID, uniqueness)."""
    if ctx.invoked_subcommand is not None:
        return
    cli = get_context(ctx)
    result = run_validate(
        cli,
        check=check,
        strict=strict,
        file=file,
        uuids=uuid,
        object_types=object_type,
    )
    emit_success(cli, result)


@validate_app.command("query")
def validate_query_cmd(
    ctx: typer.Context,
    platform: DetectionPlatform = typer.Option(..., "--platform"),
    plan: str | None = typer.Option(None, "--plan", envvar="DEPLOYMENT_PLAN"),
    wide: bool = typer.Option(False, "--wide"),
) -> None:
    """Validate platform query syntax (5 supported platforms)."""
    cli = get_context(ctx)
    result = validate_query_platform(cli, platform.value, plan=plan, wide=wide)
    emit_success(cli, result)


deploy_app = typer.Typer(help="Rule deployment")
app.add_typer(deploy_app, name="deploy")


@deploy_app.callback(invoke_without_command=True)
def deploy_cmd(
    ctx: typer.Context,
    platform: DetectionPlatform | None = typer.Option(None, "--platform"),
    plan: str | None = typer.Option(None, "--plan", envvar="DEPLOYMENT_PLAN"),
    tenant: str | None = typer.Option(None, "--tenant"),
    file: str | None = typer.Option(None, "--file"),
    wide: bool = typer.Option(False, "--wide"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    keep_deprecated: bool = typer.Option(False, "--keep-deprecated"),
    skip_promotion: bool = typer.Option(False, "--skip-promotion"),
) -> None:
    """Deploy detection rules to configured platforms."""
    cli = get_context(ctx)
    result = run_deploy(
        cli,
        platform=platform,
        plan=plan,
        dry_run=dry_run,
        skip_promotion=skip_promotion,
        keep_deprecated=keep_deprecated,
        wide=wide,
    )
    if tenant:
        result["tenant"] = tenant
    if file:
        result["file"] = file
    emit_success(cli, result)


@deploy_app.command("metadata")
def deploy_metadata_cmd(
    ctx: typer.Context, platform: DetectionPlatform = typer.Option(..., "--platform")
) -> None:
    """Deploy Splunk metadata lookup table (platform-specific)."""
    cli = get_context(ctx)
    cli.apply_environment()
    logger.info("metadata_deployment", platform=platform.value)
    emit_success(cli, {"message": "Metadata deployment signalled", "platform": platform.value})


document_app = typer.Typer(help="Wiki documentation generation")
app.add_typer(document_app, name="document")


@document_app.callback(invoke_without_command=True)
def document_cmd(
    ctx: typer.Context,
    scope: DocumentScope | None = typer.Option(None, "--scope"),
    output: str | None = typer.Option(None, "--output"),
) -> None:
    """Generate wiki documentation from detection content."""
    cli = get_context(ctx)
    result = run_document(cli, scope=scope, output=output)
    emit_success(cli, result)


mutate_app = typer.Typer(help="Object mutations")
app.add_typer(mutate_app, name="mutate")


@mutate_app.command("promote")
def mutate_promote(ctx: typer.Context) -> None:
    cli = get_context(ctx)
    emit_success(cli, run_mutate(cli, action="promote"))


@mutate_app.command("rename")
def mutate_rename(ctx: typer.Context) -> None:
    cli = get_context(ctx)
    emit_success(cli, run_mutate(cli, action="rename"))


@mutate_app.command("references")
def mutate_references(ctx: typer.Context) -> None:
    cli = get_context(ctx)
    emit_success(cli, run_mutate(cli, action="references"))


@mutate_app.command("security-domain")
def mutate_security_domain(ctx: typer.Context) -> None:
    cli = get_context(ctx)
    emit_success(cli, run_mutate(cli, action="security-domain"))


@mutate_app.callback(invoke_without_command=True)
def mutate_all(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is not None:
        return
    cli = get_context(ctx)
    emit_success(cli, run_mutate(cli))


export_app = typer.Typer(help="Data exports")
app.add_typer(export_app, name="export")


@export_app.command("navigator")
def export_navigator(ctx: typer.Context) -> None:
    cli = get_context(ctx)
    emit_success(cli, run_export(cli, target=ExportTarget.navigator))


@export_app.command("table")
def export_table(ctx: typer.Context) -> None:
    cli = get_context(ctx)
    emit_success(cli, run_export(cli, target=ExportTarget.table))


@export_app.command("playbook-map")
def export_playbook_map(ctx: typer.Context) -> None:
    cli = get_context(ctx)
    emit_success(cli, run_export(cli, target=ExportTarget.playbook_map))


extract_app = typer.Typer(help="Platform rule imports")
app.add_typer(extract_app, name="extract")


@extract_app.command("sentinel")
def import_sentinel(ctx: typer.Context) -> None:
    cli = get_context(ctx)
    emit_success(cli, run_extract(cli, import_target=ExtractImport.sentinel))


@extract_app.command("defender")
def import_defender(ctx: typer.Context) -> None:
    cli = get_context(ctx)
    emit_success(cli, run_extract(cli, import_target=ExtractImport.defender))


info_app = typer.Typer(help="System information")
app.add_typer(info_app, name="info")


@info_app.callback(invoke_without_command=True)
def info_cmd(
    ctx: typer.Context,
    platform: DetectionPlatform | None = typer.Option(None, "--platform"),
    section: str | None = typer.Argument(None),
    technique: str | None = typer.Option(None, "--technique"),
) -> None:
    """Show repository and platform information."""
    cli = get_context(ctx)
    result = collect_info(cli, platform=platform, section=section, technique=technique)
    if cli.json_output:
        emit(cli, result)
    else:
        from rich.console import Console
        from rich.table import Table

        table = Table(title="OpenTide Info")
        table.add_column("Key")
        table.add_column("Value")
        table.add_row("Version", str(result["version"]))
        table.add_row("Rules", str(result["counts"]["rules"]))
        table.add_row("Threats", str(result["counts"]["threats"]))
        table.add_row("Objectives", str(result["counts"]["objectives"]))
        for plat in result["platforms"]:
            caps = []
            if plat["can_deploy"]:
                caps.append("deploy")
            if plat["can_validate"]:
                caps.append("validate")
            table.add_row(plat["name"], f"enabled={plat['enabled']} [{', '.join(caps) or 'none'}]")
        Console().print(table)


@app.command("migrate")
def migrate_cmd(
    ctx: typer.Context,
    check: bool = typer.Option(
        False, "--check", help="Report legacy patterns without changing files"
    ),
    apply: bool = typer.Option(False, "--apply", help="Rewrite known legacy patterns in place"),
) -> None:
    """Scan or rewrite legacy submodule imports and Orchestration script calls."""
    from opentide.cli.migrate import apply_migrations, scan_repo

    cli = get_context(ctx)
    cli.apply_environment()
    repo = cli.repo
    if apply:
        changed = apply_migrations(repo)
        emit_success(cli, {"message": "Migration applied", "changed_files": changed})
        return
    findings = scan_repo(repo)
    if check or not apply:
        emit_success(
            cli,
            {"message": "Migration scan complete", "findings": findings, "count": len(findings)},
        )


def main() -> None:
    """Console script entry point."""
    app()


if __name__ == "__main__":
    main()
