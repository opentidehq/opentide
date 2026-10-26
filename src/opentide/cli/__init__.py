"""opentide Typer CLI application."""

from __future__ import annotations

import os
import sys
from typing import Any

import structlog
import typer
from typer.core import TyperGroup

from opentide.cli.context import CliContext, get_context, sync_typer_rendering
from opentide.cli.enums import (
    DetectionPlatform,
    DocumentScope,
    ExportTarget,
    ExtractImport,
    LintCheck,
    ValidateCheck,
)
from opentide.cli.group_options import hand_down, refuse_dropped
from opentide.cli.mcp_app import mcp_app
from opentide.cli.output import (
    CommandResult,
    emit_deprecation,
    emit_error,
    emit_result,
    emit_success,
)
from opentide.cli.rules_app import rules_app
from opentide.cli.services.deploy import run_deploy
from opentide.cli.services.document import run_document
from opentide.cli.services.export import run_export
from opentide.cli.services.extraction import run_extract
from opentide.cli.services.generation import run_generate, run_generate_docs
from opentide.cli.services.info import (
    InvalidVocabularyLifecycleError,
    UnknownVocabularyError,
    collect_info,
    render_info,
)
from opentide.cli.services.lint import render_findings, run_lint
from opentide.cli.services.validation import run_validate, validate_query_platform
from opentide.cli.setup_app import setup_app
from opentide.cli.share_app import share_app
from opentide.core.logging import LoggingConfig, init_logging
from opentide.core.logging import print_banner as print_banner
from opentide.core.root import get_repo_root

logger = structlog.get_logger("opentide.cli.__init__")
app = typer.Typer(
    name="opentide",
    help="opentide — DetectionOps Engine",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


def _no_color_before_help(value: bool) -> bool:
    """Eager, so ``opentide --no-color --help`` is plain: help exits before callbacks."""
    if value:
        sync_typer_rendering(no_color=True)
    return value


def _print_version(value: bool) -> bool:
    """Eager, so ``opentide --version`` answers before the workspace is resolved."""
    if value:
        from opentide import __version__

        typer.echo(f"opentide {__version__}")
        raise typer.Exit()
    return value


def _came_from_command_line(ctx: typer.Context, name: str) -> bool:
    """Whether *name* was typed as a flag rather than read from its envvar.

    Compared by name, not by enum identity: Typer bundles its own Click copy,
    so ``typer._click.core.ParameterSource`` is a different class from
    ``click.core.ParameterSource`` and ``==`` is always False.
    """
    source = ctx.get_parameter_source(name)
    return getattr(source, "name", "") == "COMMANDLINE"


_deprecate = emit_deprecation

#: Click's words for false; any other ``DEBUG`` value turns debug logging on.
_DEBUG_OFF = frozenset({"", "0", "f", "false", "n", "no", "off"})


def _debug_from_environment() -> bool:
    """Read ``DEBUG`` as a switch rather than a strict boolean.

    As the option's envvar, Click refused anything but a boolean word, so
    ``DEBUG=*`` or ``DEBUG=express:*`` (the Node ``debug`` package's
    convention, often exported shell-wide) failed every command with exit 2.
    """
    return os.environ.get("DEBUG", "").strip().lower() not in _DEBUG_OFF


@app.callback()
def main_callback(
    ctx: typer.Context,
    repo: str | None = typer.Option(
        None, "--repo", envvar="OPENTIDE_REPO_ROOT", help="Repository root"
    ),
    data: str | None = typer.Option(
        None, "--data", envvar="OPENTIDE_DATA_ROOT", help="Bundled data root"
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        help="Enable debug logging. DEBUG set to anything but 0, false, no or off does too",
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        is_eager=True,
        callback=_no_color_before_help,
        help="Disable Rich colour output",
    ),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON output"),
    proxy: str | None = typer.Option(
        None,
        "--proxy",
        envvar="OPENTIDE_PROXY",
        help=(
            "HTTP(S) proxy URL (http://\\[user:pass@\\]host:port) for platform and lookup "
            "calls. Overrides HTTP_PROXY and HTTPS_PROXY; hosts in NO_PROXY are still "
            "reached directly."
        ),
    ),
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        is_eager=True,
        callback=_print_version,
        help="Print the installed opentide version and exit",
    ),
) -> None:
    from pathlib import Path

    cli_ctx = CliContext(
        repo=Path(repo) if repo else get_repo_root(),
        data=Path(data) if data else None,
        json_output=json_output,
        debug=debug or _debug_from_environment(),
        no_color=no_color,
        repo_explicit=_came_from_command_line(ctx, "repo"),
        proxy=proxy,
    )
    ctx.obj = cli_ctx
    cli_ctx.activate()
    cli_ctx.apply_environment()
    init_logging(LoggingConfig.from_cli_context(cli_ctx), force=True)


app.add_typer(mcp_app, name="mcp")
app.add_typer(setup_app, name="setup")
app.add_typer(share_app, name="share")
app.add_typer(rules_app, name="rules")


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
        "Framework generation and documentation pipeline.\n\n"
        "Run with no argument for the full pipeline, or name one or more "
        "phases to run only those, in the order given: "
        "schemas, templates, vocabs, snippets.\n\n"
        "Regenerate editor schemas without paying for documentation: "
        "`opentide generate schemas templates vocabs snippets`."
    ),
)
app.add_typer(generate_app, name="generate")

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
        known = ", ".join(sorted(_NAMED_GENERATE_PHASES))
        emit_error(
            cli,
            f"Unknown generation phase {names}. Pass one or more of: {known}.",
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
    refuse_dropped(ctx)
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
        hand_down(ctx)
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
    except Exception as exc:
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


validate_app = typer.Typer(help="Object and query validation")
app.add_typer(validate_app, name="validate")

#: A status (DEVELOPMENT, STAGING, PRODUCTION, ... in the default configuration)
#: maps to a strategy; a run names the strategy it deploys, never a status.
DEPLOY_STRATEGY_HELP = (
    "Status strategy this run deploys (repeatable). PREVIEW: rules whose status maps to "
    "PREVIEW or UNIVERSAL. RELEASE: rules whose status maps to RELEASE or UNIVERSAL, and "
    "disables or deletes those mapping to DISABLEMENT or DELETION. Each rule goes to the "
    "tenants whose 'strategies' accept the run's strategy. Status names such as STAGING or "
    "PRODUCTION are not strategies"
)
QUERY_STRATEGY_HELP = (
    "Check only rules a run with this strategy deploys (repeatable), on the tenants that "
    "accept it. Default: PREVIEW and RELEASE"
)
REMOVED_PLAN_HELP = "Removed in 0.17.0; use --strategy"


def _refuse_removed_plan(cli: CliContext, plan: str | None) -> None:
    if plan is not None:
        from opentide.models.deployment_enums import removed_plan_message

        emit_error(cli, removed_plan_message(plan, option=True), exit_code=2)


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
) -> None:
    """Validate detection objects (schema, UUID, uniqueness)."""
    if ctx.invoked_subcommand is not None:
        hand_down(ctx)
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
        files=file,
        uuids=uuid,
        object_types=object_type,
    )
    emit_result(cli, CommandResult.from_payload(result, default_message="Validation passed"))


@app.command("lint")
def lint_cmd(
    ctx: typer.Context,
    fix: bool = typer.Option(False, "--fix", help="Apply safe filename renames"),
    strict: bool = typer.Option(
        False, "--strict", help="Exit non-zero when findings exist (CI gate)"
    ),
    check: list[LintCheck] = typer.Option(
        [], "--check", help="Limit to one check: filenames or metadata (repeatable)"
    ),
) -> None:
    """Catalogue hygiene: filename slugs and recommended metadata (not schema validation)."""
    cli = get_context(ctx)
    cli.apply_environment()
    result = run_lint(cli.repo, checks=check or None, fix=fix, strict=strict)
    findings = result["findings"]
    if not cli.json_output and isinstance(findings, list):
        render_findings(findings)
    emit_result(cli, CommandResult.from_payload(result, default_message="Catalogue lint passed"))


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
    refuse_dropped(ctx)
    cli = get_context(ctx)
    _refuse_removed_plan(cli, plan)
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


deploy_app = typer.Typer(help="Rule deployment")
app.add_typer(deploy_app, name="deploy")


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
        hand_down(ctx)
        return
    cli = get_context(ctx)
    _refuse_removed_plan(cli, plan)
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

    refuse_dropped(ctx)
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
    ctx: typer.Context,
    state_commit: str = typer.Argument(..., help="Commit whose deployment-state changes to replay"),
) -> None:
    """Replay one commit's deployment-state changes onto the checkout (CI write-back).

    Used by the generated production write-back when its rule files conflict
    with a concurrent merge. A subcommand rather than ``python -m`` so it runs
    in the interpreter that has opentide, whatever ``python`` is on PATH.
    """
    from opentide.ci.state_replay import main as replay_main

    refuse_dropped(ctx)
    raise typer.Exit(replay_main([state_commit]))


@deploy_app.command("metadata", hidden=True)
def deploy_metadata_cmd(
    ctx: typer.Context, platform: DetectionPlatform = typer.Option(..., "--platform")
) -> None:
    """Reserved for a future metadata deployment implementation."""
    refuse_dropped(ctx)
    cli = get_context(ctx)
    emit_error(
        cli,
        f"Metadata deployment is not implemented for {platform.value}",
        exit_code=2,
    )


# --- Deprecated top-level commands (delegate to generate) ---

# Help text is Rich markup: a bare `[deprecated]` renders as nothing.
document_app = typer.Typer(help="\\[deprecated] Use opentide generate docs", hidden=True)
export_legacy_app = typer.Typer(help="\\[deprecated] Use opentide generate exports", hidden=True)
extract_legacy_app = typer.Typer(help="\\[deprecated] Use opentide generate extract", hidden=True)
app.add_typer(document_app, name="document")
app.add_typer(export_legacy_app, name="export")
app.add_typer(extract_legacy_app, name="extract")


@document_app.callback(invoke_without_command=True)
def document_cmd(
    ctx: typer.Context,
    output: str | None = typer.Option(None, "--output"),
    flavor: str | None = typer.Option(None, "--flavor"),
) -> None:
    # Each `document <scope>` subcommand names its own replacement; warning here
    # too would print two DEPRECATED lines for one invocation.
    if ctx.invoked_subcommand is not None:
        hand_down(ctx)
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


migrate_app = typer.Typer(help="Migrate legacy client repository layouts")
app.add_typer(migrate_app, name="migrate")


@migrate_app.command("objects")
def migrate_objects_cmd(
    ctx: typer.Context,
    apply: bool = typer.Option(
        False, "--apply", help="Perform the planned moves (default: dry-run)"
    ),
    copy: bool = typer.Option(False, "--copy", help="Copy files instead of moving them"),
) -> None:
    """Move Configurations/, Objects/, and .opentide/framework into the greenfield layout."""
    from opentide.cli.services.migrate_objects import run_migrate_objects

    cli = get_context(ctx)
    cli.apply_environment()
    emit_success(cli, run_migrate_objects(cli.repo, apply=apply, copy=copy))


@migrate_app.command("vocab-scope")
def migrate_vocab_scope_cmd(
    ctx: typer.Context,
    apply: bool = typer.Option(
        False, "--apply", help="Rewrite the objects (default: dry-run report)"
    ),
    field: list[str] = typer.Option(
        None,
        "--field",
        help="Limit to one scoped field (repeatable). Default: every scoped field.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Exit 0 even when values need a human decision",
    ),
) -> None:
    """Re-prefix stage-scoped vocabulary values (`Process` -> `Host::Process`).

    Applies only mechanical outcomes: a key defined under exactly one stage,
    and a stage whose casing drifted. A key defined under several stages is
    reported, never guessed. Exits 2 when anything is left for a human.
    """
    from opentide.cli.services.migrate_vocab_scope import (
        SCOPED_FIELDS,
        load_scoped_vocabularies,
        run_migrate_vocab_scope,
    )

    cli = get_context(ctx)
    cli.apply_environment()

    fields = dict(SCOPED_FIELDS)
    if field:
        unknown = sorted(set(field) - set(fields))
        if unknown:
            known = ", ".join(sorted(fields))
            emit_error(
                cli,
                f"Unknown scoped field(s) {', '.join(unknown)}. Known scoped fields: {known}.",
            )
        fields = {name: fields[name] for name in field}

    try:
        report = run_migrate_vocab_scope(
            cli.repo,
            load_scoped_vocabularies(fields),
            apply=apply,
            fields=fields,
        )
    except (OSError, ValueError) as exc:
        emit_error(cli, str(exc))

    blocked = {
        name: entry["blocked"] for name, entry in report["fields"].items() if entry["blocked"]
    }
    warnings = [f"{name}: {detail}" for name, items in blocked.items() for detail in items.values()]
    warnings += [f"{path}: {reason}" for path, reason in report["failed_files"].items()]

    verb = "Rewrote" if apply else "Would rewrite"
    payload: dict[str, Any] = {
        **report,
        "message": (
            f"{verb} {len(report['changed_files'])} file(s) across {report['scanned']} scanned."
        ),
        "warnings": warnings,
    }
    if report["failed_files"]:
        payload["status"] = "issues"
        payload["message"] = (
            f"{len(report['failed_files'])} file(s) could not be migrated safely and "
            "were left unchanged."
        )
        payload["_exit_code"] = 1
    elif blocked and not force:
        count = sum(len(items) for items in blocked.values())
        payload["status"] = "issues"
        payload["message"] = (
            f"{verb} {len(report['changed_files'])} file(s); {count} value(s) "
            "are defined under several stages and cannot be inferred. Choose a stage "
            "for each by hand, then re-run. Pass --force to treat this as success."
        )
        payload["_exit_code"] = 2
    emit_success(cli, payload)


# ``info`` has no subcommands: registering it as a plain command keeps Click from
# treating options typed after the section (``info coverage --technique T1059``)
# as a subcommand name.
@app.command("info")
def info_cmd(
    ctx: typer.Context,
    platform: DetectionPlatform | None = typer.Option(None, "--platform"),
    section: str | None = typer.Argument(None),
    name: str | None = typer.Argument(
        None, help="Vocabulary to inspect, with the vocab section (e.g. surface)"
    ),
    technique: str | None = typer.Option(None, "--technique"),
    strict: bool = typer.Option(
        False, "--strict", help="Exit non-zero when any object failed to load"
    ),
) -> None:
    """Show repository and platform information."""
    cli = get_context(ctx)
    valid_sections = {None, "rules", "threats", "objectives", "coverage", "vocab"}
    if section not in valid_sections:
        emit_error(cli, f"Unknown info section: {section}")
    if section == "coverage" and not technique:
        emit_error(cli, "The coverage section requires --technique")
    if name is not None and section != "vocab":
        emit_error(cli, f"Only the vocab section takes a name; got {name!r} after {section!r}")
    try:
        result = collect_info(
            cli, platform=platform, section=section, technique=technique, vocab=name
        )
    except (UnknownVocabularyError, InvalidVocabularyLifecycleError) as exc:
        emit_error(cli, str(exc))
    strict_failure = strict and int(result.get("parse_error_count") or 0) > 0
    if strict_failure:
        result["status"] = "failed"
        result["message"] = "Repository has objects that failed to load"
        result["_exit_code"] = 1
    if cli.json_output:
        emit_success(cli, result)
    else:
        render_info(result, section=section)
        if strict_failure:
            raise typer.Exit(1)


def main() -> None:
    """Console script entry point."""
    # Here rather than at import: opentide.ci imports this package, and a host
    # Typer app must keep its own rendering settings. Click parses root
    # options, and exits on a bad one, before the eager callback runs.
    argv = sys.argv[1:]
    options = argv[: argv.index("--")] if "--" in argv else argv
    sync_typer_rendering(no_color="--no-color" in options or bool(os.getenv("NO_COLOR")))
    app()


if __name__ == "__main__":
    main()
