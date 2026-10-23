"""Hidden ``document``, ``export`` and ``extract``: deprecated, delegate to ``generate``."""

from __future__ import annotations

import typer

from opentide.cli.commands.generate import _emit_docs
from opentide.cli.context import get_context
from opentide.cli.enums import DocumentScope, ExportTarget, ExtractImport
from opentide.cli.output import emit_deprecation, emit_error, emit_success
from opentide.cli.services.export import run_export
from opentide.cli.services.extraction import run_extract

_deprecate = emit_deprecation


# Help text is Rich markup: a bare `[deprecated]` renders as nothing.
document_app = typer.Typer(help="\\[deprecated] Use opentide generate docs", hidden=True)
export_legacy_app = typer.Typer(help="\\[deprecated] Use opentide generate exports", hidden=True)
extract_legacy_app = typer.Typer(help="\\[deprecated] Use opentide generate extract", hidden=True)


@document_app.callback(invoke_without_command=True)
def document_cmd(
    ctx: typer.Context,
    output: str | None = typer.Option(None, "--output"),
    flavor: str | None = typer.Option(None, "--flavor"),
) -> None:
    # Each `document <scope>` subcommand names its own replacement; warning here
    # too would print two DEPRECATED lines for one invocation.
    if ctx.invoked_subcommand is not None:
        return
    _deprecate("opentide document", "opentide generate docs")
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
