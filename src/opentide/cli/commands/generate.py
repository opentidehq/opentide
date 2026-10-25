"""``opentide generate``: framework generation, docs, exports and importers."""

from __future__ import annotations

from typing import Any

import typer
from typer.core import TyperGroup

from opentide.cli.context import get_context
from opentide.cli.enums import DocumentScope, ExportTarget, ExtractImport
from opentide.cli.output import emit_error, emit_success, emit_usage_error
from opentide.cli.services.document import run_document
from opentide.cli.services.export import run_export
from opentide.cli.services.extraction import run_extract
from opentide.cli.services.generation import run_generate, run_generate_docs
from opentide.cli.ui.contract import USAGE_ERROR


class GeneratePhaseGroup(TyperGroup):
    """Accept phase names on the group without hiding real subcommands.

    ``schemas``, ``templates``, ``vocabs``, and ``snippets`` are arguments of
    ``generate``. ``docs``, ``exports``, ``extract``, ``inflight``, and
    ``explorer`` stay commands. Click would otherwise treat the first token as
    a subcommand, or an argument list would swallow those commands.
    """

    def parse_args(self, ctx: Any, args: list[str]) -> list[str]:
        if args and not args[0].startswith("-") and self.get_command(ctx, args[0]) is None:
            phases: list[str] = []
            index = 0
            for token in args:
                if token.startswith("-"):
                    break
                phases.append(token)
                index += 1
            ctx.meta["generate_phases"] = phases
            return super().parse_args(ctx, args[index:])
        return super().parse_args(ctx, args)


generate_app = typer.Typer(
    cls=GeneratePhaseGroup,
    # Typer renders THIS string for `generate --help`, not the callback
    # docstring, so the positional phases have to be named here or they are
    # undiscoverable. Knowing they exist is what lets an instance regenerate
    # schemas without paying for the documentation phase.
    #
    # No square brackets: Rich parses them as console markup and silently
    # renders the contents as nothing.
    help=(
        "Generate schemas, templates, docs and exports\n\n"
        "Run with no argument for the full pipeline, or name one or more "
        "phases to run only those, in the order given: "
        "schemas, templates, vocabs, snippets.\n\n"
        "Regenerate editor schemas without paying for documentation: "
        "`opentide generate schemas templates vocabs snippets`."
    ),
)

docs_app = typer.Typer(help="Generate markdown documentation for detection objects")
exports_app = typer.Typer(help="Export catalogue artefacts")
extract_app = typer.Typer(help="Import rules from external platforms")
generate_app.add_typer(docs_app, name="docs")
generate_app.add_typer(exports_app, name="exports")
generate_app.add_typer(extract_app, name="extract")


_NAMED_GENERATE_PHASES = frozenset({"schemas", "templates", "vocabs", "snippets"})


@generate_app.callback(invoke_without_command=True)
def generate_all(ctx: typer.Context) -> None:
    """Run the full pipeline, or named phases in the order given.

    Pass ``schemas``, ``templates``, ``vocabs``, and ``snippets`` to run only
    those phases. ``docs``, ``exports``, ``extract``, ``inflight``, and
    ``explorer`` stay subcommands.
    """
    if ctx.invoked_subcommand is not None:
        return
    cli = get_context(ctx)
    phases = [str(name) for name in ctx.meta.get("generate_phases", [])]
    if not phases:
        emit_success(cli, run_generate(cli))
        return
    unknown = [name for name in phases if name not in _NAMED_GENERATE_PHASES]
    if unknown:
        names = ", ".join(unknown)
        known = sorted(_NAMED_GENERATE_PHASES)
        emit_usage_error(
            cli,
            f"Unknown generation phase {names}. Pass one or more of: {', '.join(known)}.",
            argument="phase",
            value=unknown[0],
            choices=known,
        )
    emit_success(cli, run_generate(cli, phases=phases))


@generate_app.command("explorer")
def generate_explorer_cmd(ctx: typer.Context) -> None:
    """Write explorer.bundle.json and explorer.search.json under .opentide/exports/."""
    cli = get_context(ctx)
    emit_success(cli, run_generate(cli, phase="explorer"))


inflight_app = typer.Typer(help="Inflight preview shard generation and prune")
generate_app.add_typer(inflight_app, name="inflight")


@inflight_app.callback(invoke_without_command=True)
def generate_inflight_cmd(ctx: typer.Context) -> None:
    """Write per-UUID preview shards under ``.opentide/inflight/`` for changed objects."""
    if ctx.invoked_subcommand is not None:
        return
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
        emit_usage_error(
            cli,
            "--changed cannot be combined with scoped docs generation",
            argument="--changed",
            code=USAGE_ERROR,
        )
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


def _run_extract_command(ctx: typer.Context, target: ExtractImport) -> None:
    """Run one importer, turning every failure into a single result document."""
    cli = get_context(ctx)
    try:
        result = run_extract(cli, import_target=target)
    except Exception as exc:  # noqa: BLE001 - one JSON document is the contract
        # Enumerating exception types is how #242 escaped: the importers reach
        # vendor SDKs and half-typed config, so anything they raise has to come
        # back as a result document rather than a Rich traceback. `str(exc)` is
        # empty for a bare KeyError and unhelpful for its key alone.
        detail = str(exc).strip()
        message = (
            f"{type(exc).__name__}: {detail}"
            if detail and not isinstance(exc, RuntimeError | FileNotFoundError)
            else detail or f"{type(exc).__name__} while importing {target.value}"
        )
        emit_error(cli, message)
        return
    emit_success(cli, result)


@extract_app.command("sentinel")
def generate_extract_sentinel(ctx: typer.Context) -> None:
    """Import Sentinel analytics rules (needs Sentinel tenant credentials)."""
    _run_extract_command(ctx, ExtractImport.sentinel)


@extract_app.command("defender")
def generate_extract_defender(ctx: typer.Context) -> None:
    """Import Defender custom detections (needs tenant credentials)."""
    _run_extract_command(ctx, ExtractImport.defender)


@extract_app.command("elastic")
def generate_extract_elastic(
    ctx: typer.Context,
    space: str = typer.Option("default", "--space", help="Kibana space ID"),
    include_prebuilt: bool = typer.Option(
        False,
        "--include-prebuilt/--custom-only",
        help="Include prebuilt rules converted to custom rules with derived UUIDs",
    ),
) -> None:
    """Import Elastic Security detection rules (needs tenant credentials)."""
    cli = get_context(ctx)
    try:
        from opentide.cli.services.extraction import run_extract

        result = run_extract(
            cli,
            import_target=ExtractImport.elastic,
            space=space,
            include_prebuilt=include_prebuilt,
        )
    except Exception as exc:
        detail = str(exc).strip()
        message = (
            f"{type(exc).__name__}: {detail}"
            if detail and not isinstance(exc, RuntimeError | FileNotFoundError)
            else detail or f"{type(exc).__name__} while importing elastic"
        )
        emit_error(cli, message)
        return
    emit_success(cli, result)
