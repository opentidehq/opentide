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
    ValidateCheck,
    platform_label,
)
from opentide.cli.output import CommandResult, emit_error, emit_result, emit_success
from opentide.cli.services.deploy import run_deploy
from opentide.cli.services.document import run_document
from opentide.cli.services.export import run_export
from opentide.cli.services.extraction import run_extract
from opentide.cli.services.generation import run_generate, run_generate_docs
from opentide.cli.services.info import collect_info
from opentide.cli.services.validation import run_validate, validate_query_platform
from opentide.cli.setup_app import setup_app
from opentide.core.logging import LoggingConfig, init_logging, is_json_output
from opentide.core.logging import print_banner as print_banner  # noqa: F401
from opentide.core.logging.config import get_console, get_stdout_console
from opentide.core.root import get_repo_root

logger = structlog.get_logger("opentide.cli.__init__")
app = typer.Typer(
    name="opentide",
    help="OpenTide — DetectionOps Engine",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


def _deprecate(legacy: str, replacement: str) -> None:
    if is_json_output():
        logger.warning("cli_command_deprecated", legacy=legacy, use_instead=replacement)
        return
    get_console().print(f"[yellow]DEPRECATED[/] {legacy}; use {replacement}.")


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


app.add_typer(setup_app, name="setup")

generate_app = typer.Typer(help="Framework generation and documentation pipeline")
app.add_typer(generate_app, name="generate")

docs_app = typer.Typer(help="Generate markdown documentation for detection objects")
exports_app = typer.Typer(help="Export catalogue artefacts")
extract_app = typer.Typer(help="Import rules from external platforms")
generate_app.add_typer(docs_app, name="docs")
generate_app.add_typer(exports_app, name="exports")
generate_app.add_typer(extract_app, name="extract")


@generate_app.callback(invoke_without_command=True)
def generate_all(ctx: typer.Context) -> None:
    """Run full generation pipeline (docs, exports, then framework internals)."""
    if ctx.invoked_subcommand is not None:
        return
    cli = get_context(ctx)
    result = run_generate(cli)
    emit_success(cli, result)


@generate_app.command("schemas")
def generate_schemas_cmd(ctx: typer.Context) -> None:
    cli = get_context(ctx)
    emit_success(cli, run_generate(cli, phase="schemas"))


@generate_app.command("templates")
def generate_templates_cmd(ctx: typer.Context) -> None:
    cli = get_context(ctx)
    emit_success(cli, run_generate(cli, phase="templates"))


@generate_app.command("vocabs")
def generate_vocabs_cmd(ctx: typer.Context) -> None:
    cli = get_context(ctx)
    emit_success(cli, run_generate(cli, phase="vocabs"))


@generate_app.command("snippets")
def generate_snippets_cmd(ctx: typer.Context) -> None:
    cli = get_context(ctx)
    emit_success(cli, run_generate(cli, phase="snippets"))


inflight_app = typer.Typer(help="Inflight preview shard generation and prune")
generate_app.add_typer(inflight_app, name="inflight")


@inflight_app.callback(invoke_without_command=True)
def generate_inflight_cmd(ctx: typer.Context) -> None:
    """Write per-UUID preview shards under ``.opentide/inflight/`` for changed objects."""
    cli = get_context(ctx)
    emit_success(cli, run_generate(cli, phase="inflight"))


@inflight_app.command("prune")
def generate_inflight_prune_cmd(ctx: typer.Context) -> None:
    """Remove inflight shards superseded by committed objects on the default branch."""
    cli = get_context(ctx)
    emit_success(cli, run_generate(cli, phase="inflight-prune"))


def _emit_docs(
    ctx: typer.Context,
    *,
    output: str | None,
    flavor: str | None,
    scope: DocumentScope | None = None,
    rules: bool = False,
    threats: bool = False,
    objectives: bool = False,
    changed: bool = False,
) -> None:
    cli = get_context(ctx)
    cli.apply_environment()
    if changed and (scope is not None or rules or threats or objectives):
        emit_error(cli, "--changed cannot be combined with scoped docs generation")
    if scope is not None:
        emit_success(cli, run_document(cli, scope=scope, output=output, flavor=flavor))
        return
    result = run_generate_docs(
        output=output,
        flavor=flavor,
        rules=rules,
        threats=threats,
        objectives=objectives,
        changed=changed,
    )
    emit_success(cli, result)


@docs_app.callback(invoke_without_command=True)
def generate_docs_all(
    ctx: typer.Context,
    output: str | None = typer.Option(None, "--output"),
    flavor: str | None = typer.Option(None, "--flavor"),
    rules: bool = typer.Option(False, "--rules"),
    threats: bool = typer.Option(False, "--threats"),
    objectives: bool = typer.Option(False, "--objectives"),
    changed: bool = typer.Option(False, "--changed"),
) -> None:
    """Generate documentation (all scopes, then index)."""
    if ctx.invoked_subcommand is not None:
        return
    _emit_docs(
        ctx,
        output=output,
        flavor=flavor,
        rules=rules,
        threats=threats,
        objectives=objectives,
        changed=changed,
    )


@docs_app.command("rules")
def generate_docs_rules(
    ctx: typer.Context,
    output: str | None = typer.Option(None, "--output"),
    flavor: str | None = typer.Option(None, "--flavor"),
) -> None:
    _emit_docs(ctx, output=output, flavor=flavor, scope=DocumentScope.rules)


@docs_app.command("objectives")
def generate_docs_objectives(
    ctx: typer.Context,
    output: str | None = typer.Option(None, "--output"),
    flavor: str | None = typer.Option(None, "--flavor"),
) -> None:
    _emit_docs(ctx, output=output, flavor=flavor, scope=DocumentScope.objectives)


@docs_app.command("threats")
def generate_docs_threats(
    ctx: typer.Context,
    output: str | None = typer.Option(None, "--output"),
    flavor: str | None = typer.Option(None, "--flavor"),
) -> None:
    _emit_docs(ctx, output=output, flavor=flavor, scope=DocumentScope.threats)


@docs_app.command("index")
def generate_docs_index(
    ctx: typer.Context,
    output: str | None = typer.Option(None, "--output"),
    flavor: str | None = typer.Option(None, "--flavor"),
) -> None:
    _emit_docs(ctx, output=output, flavor=flavor, scope=DocumentScope.index)


@exports_app.callback(invoke_without_command=True)
def generate_exports_all(ctx: typer.Context) -> None:
    """Export navigator layer, objects dump, and revisions snapshot."""
    if ctx.invoked_subcommand is not None:
        return
    cli = get_context(ctx)
    emit_success(cli, run_generate(cli, phase="exports"))


@exports_app.command("navigator")
def generate_exports_navigator(ctx: typer.Context) -> None:
    cli = get_context(ctx)
    emit_success(cli, run_export(cli, target=ExportTarget.navigator))


@exports_app.command("objects")
def generate_exports_objects(ctx: typer.Context) -> None:
    cli = get_context(ctx)
    emit_success(cli, run_export(cli, target=ExportTarget.objects))


@exports_app.command("revisions")
def generate_exports_revisions(ctx: typer.Context) -> None:
    cli = get_context(ctx)
    emit_success(cli, run_export(cli, target=ExportTarget.revisions))


@extract_app.command("sentinel")
def generate_extract_sentinel(ctx: typer.Context) -> None:
    cli = get_context(ctx)
    try:
        result = run_extract(cli, import_target=ExtractImport.sentinel)
    except (FileNotFoundError, RuntimeError) as exc:
        emit_error(cli, str(exc))
    emit_success(cli, result)


@extract_app.command("defender")
def generate_extract_defender(ctx: typer.Context) -> None:
    cli = get_context(ctx)
    try:
        result = run_extract(cli, import_target=ExtractImport.defender)
    except (FileNotFoundError, RuntimeError) as exc:
        emit_error(cli, str(exc))
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
    valid_object_types = {"rule", "threat", "objective"}
    unknown_types = sorted(set(object_type or []) - valid_object_types)
    if unknown_types:
        emit_error(
            cli,
            "Unknown object type(s): "
            + ", ".join(unknown_types)
            + ". Choose rule, threat, or objective.",
        )
    result = run_validate(
        cli,
        check=check,
        strict=strict,
        file=file,
        uuids=uuid,
        object_types=object_type,
    )
    emit_result(cli, CommandResult.from_payload(result, default_message="Validation passed"))


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
    emit_result(cli, CommandResult.from_payload(result, default_message="Deployment completed"))


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
    )


# --- Deprecated top-level commands (delegate to generate) ---

document_app = typer.Typer(help="[deprecated] Use opentide generate docs", hidden=True)
export_legacy_app = typer.Typer(help="[deprecated] Use opentide generate exports", hidden=True)
extract_legacy_app = typer.Typer(help="[deprecated] Use opentide generate extract", hidden=True)
app.add_typer(document_app, name="document")
app.add_typer(export_legacy_app, name="export")
app.add_typer(extract_legacy_app, name="extract")


@document_app.callback(invoke_without_command=True)
def document_cmd(
    ctx: typer.Context,
    output: str | None = typer.Option(None, "--output"),
    flavor: str | None = typer.Option(None, "--flavor"),
) -> None:
    _deprecate("opentide document", "opentide generate docs")
    if ctx.invoked_subcommand is not None:
        return
    _emit_docs(ctx, output=output, flavor=flavor)


@document_app.command("rules")
def document_rules_cmd(
    ctx: typer.Context,
    output: str | None = typer.Option(None, "--output"),
    flavor: str | None = typer.Option(None, "--flavor"),
) -> None:
    _deprecate("opentide document rules", "opentide generate docs rules")
    _emit_docs(ctx, output=output, flavor=flavor, scope=DocumentScope.rules)


@document_app.command("objectives")
def document_objectives_cmd(
    ctx: typer.Context,
    output: str | None = typer.Option(None, "--output"),
    flavor: str | None = typer.Option(None, "--flavor"),
) -> None:
    _deprecate("opentide document objectives", "opentide generate docs objectives")
    _emit_docs(ctx, output=output, flavor=flavor, scope=DocumentScope.objectives)


@document_app.command("threats")
def document_threats_cmd(
    ctx: typer.Context,
    output: str | None = typer.Option(None, "--output"),
    flavor: str | None = typer.Option(None, "--flavor"),
) -> None:
    _deprecate("opentide document threats", "opentide generate docs threats")
    _emit_docs(ctx, output=output, flavor=flavor, scope=DocumentScope.threats)


@document_app.command("index")
def document_index_cmd(
    ctx: typer.Context,
    output: str | None = typer.Option(None, "--output"),
    flavor: str | None = typer.Option(None, "--flavor"),
) -> None:
    _deprecate("opentide document index", "opentide generate docs index")
    _emit_docs(ctx, output=output, flavor=flavor, scope=DocumentScope.index)


@export_legacy_app.command("navigator")
def export_navigator(ctx: typer.Context) -> None:
    _deprecate("opentide export navigator", "opentide generate exports navigator")
    cli = get_context(ctx)
    emit_success(cli, run_export(cli, target=ExportTarget.navigator))


@export_legacy_app.command("objects")
def export_objects(ctx: typer.Context) -> None:
    _deprecate("opentide export objects", "opentide generate exports objects")
    cli = get_context(ctx)
    emit_success(cli, run_export(cli, target=ExportTarget.objects))


@export_legacy_app.command("revisions")
def export_revisions(ctx: typer.Context) -> None:
    _deprecate("opentide export revisions", "opentide generate exports revisions")
    cli = get_context(ctx)
    emit_success(cli, run_export(cli, target=ExportTarget.revisions))


@export_legacy_app.command("playbook-map", hidden=True)
def export_playbook_map_legacy(ctx: typer.Context) -> None:
    _deprecate(
        "opentide export playbook-map",
        "removed from default generate — export module remains for one release",
    )
    cli = get_context(ctx)
    cli.apply_environment()
    from opentide.cli.services.export import run_playbook_map_export

    run_playbook_map_export()
    emit_success(cli, {"message": "Export playbook-map completed", "target": "playbook-map"})


@extract_legacy_app.command("sentinel")
def import_sentinel(ctx: typer.Context) -> None:
    _deprecate("opentide extract sentinel", "opentide generate extract sentinel")
    cli = get_context(ctx)
    try:
        result = run_extract(cli, import_target=ExtractImport.sentinel)
    except (FileNotFoundError, RuntimeError) as exc:
        emit_error(cli, str(exc))
    emit_success(cli, result)


@extract_legacy_app.command("defender")
def import_defender(ctx: typer.Context) -> None:
    _deprecate("opentide extract defender", "opentide generate extract defender")
    cli = get_context(ctx)
    try:
        result = run_extract(cli, import_target=ExtractImport.defender)
    except (FileNotFoundError, RuntimeError) as exc:
        emit_error(cli, str(exc))
    emit_success(cli, result)


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
    valid_sections = {None, "rules", "threats", "objectives", "coverage"}
    if section not in valid_sections:
        emit_error(cli, f"Unknown info section: {section}")
    if section == "coverage" and not technique:
        emit_error(cli, "The coverage section requires --technique")
    result = collect_info(cli, platform=platform, section=section, technique=technique)
    if cli.json_output:
        emit_success(cli, result)
    else:
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
            try:
                display_name = platform_label(DetectionPlatform(plat["name"]))
            except ValueError:
                display_name = plat["name"]
            table.add_row(
                display_name,
                f"enabled={plat['enabled']} [{', '.join(caps) or 'none'}]",
            )
        get_stdout_console().print(table)


def main() -> None:
    """Console script entry point."""
    app()


if __name__ == "__main__":
    main()
