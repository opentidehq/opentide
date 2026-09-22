"""Typer application for ``opentide setup``."""

from __future__ import annotations

from pathlib import Path

import typer

from opentide.cli.context import CliContext, get_context
from opentide.cli.enums import CiPlatform, DetectionPlatform, McpHost, SkillTarget
from opentide.cli.output import emit, emit_deprecation, emit_error, emit_success
from opentide.cli.services.setup.ci import CiSetupOptions, run_ci_setup
from opentide.cli.services.setup.interactive import (
    InteractiveRequiredError,
    ask_confirm,
    require_interactive,
)
from opentide.cli.services.setup.mcp import (
    McpSetupOptions,
    run_interactive_mcp_setup,
    run_mcp_setup,
)
from opentide.cli.services.setup.orchestrator import SetupOptions, run_interactive_setup, run_setup
from opentide.cli.services.setup.platforms import PlatformsSetupOptions, run_platforms_setup
from opentide.cli.services.setup.repo import (
    RepoSetupOptions,
    run_interactive_repo_setup,
    run_repo_setup,
)
from opentide.cli.services.setup.skills import (
    SkillsDownloadError,
    SkillsSetupOptions,
    run_interactive_skills_setup,
    run_skills_setup,
)
from opentide.cli.services.setup.skills_registry import (
    SkillsManifestError,
    discover_skills,
    show_skill,
)
from opentide.cli.services.setup.vscode import run_vscode_setup
from opentide.core.logging.config import get_console, get_stdout_console

setup_app = typer.Typer(help="Repository and tooling setup")
skills_app = typer.Typer(help="Agent skills discovery and installation")
setup_app.add_typer(skills_app, name="skills")


def _resolve_setup_path(cli: CliContext, path: str | Path) -> Path:
    """Honor ``--repo`` when setup path is the default (``.``)."""
    target = Path(path)
    if target == Path(".") and cli.repo.resolve() != Path.cwd().resolve():
        return cli.repo
    return target


def _given_on_command_line(ctx: typer.Context, name: str) -> bool:
    # Compared by name: Typer vendors Click, so the ParameterSource enum lives in
    # a private module whose path is not part of Typer's API.
    source = ctx.get_parameter_source(name)
    return source is not None and source.name == "COMMANDLINE"


# `ctx.meta` is one dict shared by a group's context and its subcommand's.
_GROUP_PATH = "opentide.setup.path"
_GROUP_YES = "opentide.setup.yes"
_HANDED_DOWN = frozenset({"path", "yes"})


def _one_path(*given: str | None) -> str | None:
    """The single target named by a group and its subcommand, if any."""
    named = [path for path in given if path is not None]
    if len({Path(path).resolve() for path in named}) > 1:
        raise typer.BadParameter(
            f"Pass the repository path once: {' and '.join(named)} name different targets."
        )
    return named[-1] if named else None


def _hand_down(ctx: typer.Context) -> None:
    """Give the subcommand this group's ``--path`` and ``--yes``; refuse the rest.

    The group callback returned as soon as a subcommand was named, so
    ``setup --path ./repo hooks`` configured the current directory, and
    ``setup --ci github env`` dropped ``--ci`` without a word.
    """
    ignored = [
        "/".join([*param.opts, *param.secondary_opts])
        for param in ctx.command.params
        if param.name and param.name not in _HANDED_DOWN and _given_on_command_line(ctx, param.name)
    ]
    if ignored:
        verb = "configures" if len(ignored) == 1 else "configure"
        raise typer.BadParameter(
            f"{', '.join(ignored)} {verb} `{ctx.command_path}` itself and would be "
            f"ignored by `{ctx.command_path} {ctx.invoked_subcommand}`."
        )
    if _given_on_command_line(ctx, "path"):
        ctx.meta[_GROUP_PATH] = _one_path(ctx.meta.get(_GROUP_PATH), ctx.params["path"])
    if ctx.params.get("yes"):
        ctx.meta[_GROUP_YES] = True


def _consented(ctx: typer.Context, yes: bool) -> bool:
    return yes or bool(ctx.meta.get(_GROUP_YES))


def _option_path(ctx: typer.Context, cli: CliContext, option: str) -> Path:
    """Resolve a ``--path``-only command's target, inheriting the group's."""
    own = option if _given_on_command_line(ctx, "path") else None
    chosen = _one_path(ctx.meta.get(_GROUP_PATH), own)
    return _resolve_setup_path(cli, "." if chosen is None else chosen)


def _setup_path(
    ctx: typer.Context,
    cli: CliContext,
    positional: str,
    option: str,
    *,
    deprecate_positional: bool = False,
) -> Path:
    """Resolve a setup target from ``--path/-C`` or the legacy positional PATH.

    Explicitness comes from the parameter source, not from comparing against the
    ``"."`` default: ``setup repo ./other --path .`` names two different
    targets and must be rejected, not silently resolved to ``./other``.
    """
    flag_given = _given_on_command_line(ctx, "path_flag")
    positional_given = _given_on_command_line(ctx, "path")
    if flag_given and positional_given:
        raise typer.BadParameter(
            "Pass the repository path once: use --path/-C or the positional PATH, not both."
        )
    if positional_given and deprecate_positional:
        emit_deprecation(f"positional PATH ({ctx.command_path} {positional})", "--path/-C")
    own = option if flag_given else positional if positional_given else None
    chosen = _one_path(ctx.meta.get(_GROUP_PATH), own)
    return _resolve_setup_path(cli, "." if chosen is None else chosen)


PATH_OPTION = typer.Option(".", "--path", "-C", help="Repository path")
PATH_ARGUMENT = typer.Argument(".", help="Repository path (alias for --path)", hidden=True)


def _has_repo_flags(
    name: str | None,
    org: str | None,
    description: str | None,
    platform: list[DetectionPlatform],
) -> bool:
    return bool(name or org or description or platform)


def _should_run_repo(
    *,
    yes: bool,
    interactive: bool,
    has_repo_flags: bool,
    ci: CiPlatform | None,
    vscode_setup: bool,
) -> bool:
    if interactive or has_repo_flags:
        return True
    return yes and ci is None and not vscode_setup


def _require_scripted_for_json(cli: CliContext, command: str, flags: str) -> None:
    """Refuse to open a Rich/Questionary wizard while stdout is promised as JSON.

    ``--json`` lives on the root callback, so ``opentide --json setup`` used to
    print a setup panel, a prompt sequence, and *then* a JSON document, which no
    caller can parse.
    """
    if not cli.json_output:
        return
    emit_error(
        cli,
        f"--json cannot drive the interactive wizard. Run '{command}' with --yes "
        f"and explicit flags ({flags}), or drop --json to use the wizard.",
    )


def _confirm_write(cli: CliContext, target: Path, message: str, *, yes: bool) -> bool:
    """Confirm a scripted write unless explicit non-interactive consent was given."""
    if yes:
        return True
    if cli.json_output:
        emit_error(cli, f"--json cannot prompt for confirmation. Add --yes to write to {target}.")
    try:
        require_interactive()
    except InteractiveRequiredError as exc:
        emit_error(cli, f"{exc} Add --yes to confirm this write.")
    get_stdout_console().print(f"[bold]Target:[/] {target.resolve()}")
    return ask_confirm(message, default=True)


@setup_app.callback(invoke_without_command=True)
def setup_cmd(
    ctx: typer.Context,
    path: str = typer.Option(".", "--path", "-C", help="Repository path"),
    name: str | None = typer.Option(None, "--name"),
    org: str | None = typer.Option(None, "--org"),
    description: str | None = typer.Option(None, "--description"),
    platform: list[DetectionPlatform] = typer.Option(
        [],
        "--platform",
        help="Detection platforms — runs setup platforms step (repeatable)",
    ),
    ci: CiPlatform | None = typer.Option(None, "--ci"),
    staging: bool = typer.Option(True, "--staging/--no-staging"),
    inflight: bool = typer.Option(
        True,
        "--inflight/--no-inflight",
        help="Update .opentide/inflight/ preview shards on pull requests",
    ),
    promotion: bool = typer.Option(True, "--promotion/--no-promotion"),
    promotion_target: str = typer.Option("PRODUCTION", "--promotion-target"),
    python_version: str = typer.Option("3.12", "--python-version"),
    explorer_pages: bool = typer.Option(
        False,
        "--explorer-pages/--no-explorer-pages",
        help="Include GitHub Pages explorer build and deploy jobs",
    ),
    vscode_setup: bool = typer.Option(
        False, "--vscode-setup", help="Run deprecated VS Code settings + snippets"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Non-interactive mode"),
) -> None:
    """Interactive or scripted detection repository onboarding."""
    if ctx.invoked_subcommand is not None:
        _hand_down(ctx)
        return

    cli = get_context(ctx)
    base = _resolve_setup_path(cli, path)
    has_repo = _has_repo_flags(name, org, description, platform)
    only_ci_none = ci is CiPlatform.none and not yes and not has_repo and not vscode_setup
    scripted = not only_ci_none and (yes or has_repo or ci is not None or vscode_setup)

    if scripted:
        if not _confirm_write(cli, base, "Apply this setup?", yes=yes):
            emit_success(cli, {"message": "Setup cancelled", "status": "skipped"})
            return
        options = SetupOptions(
            path=base,
            name=name,
            org=org,
            description=description,
            platforms=platform,
            ci=ci,
            staging=staging,
            inflight=inflight,
            promotion=promotion,
            promotion_target=promotion_target,
            python_version=python_version,
            explorer_pages=explorer_pages,
            vscode_setup=vscode_setup,
            yes=yes,
            run_repo=_should_run_repo(
                yes=yes,
                interactive=False,
                has_repo_flags=has_repo,
                ci=ci,
                vscode_setup=vscode_setup,
            ),
            run_ci=ci is not None and ci is not CiPlatform.none,
            run_platforms=bool(platform),
        )
        cli.apply_environment()
        result = run_setup(options)
    else:
        _require_scripted_for_json(cli, "opentide setup", "--platform, --ci")
        try:
            result = run_interactive_setup(cli, base)
        except (InteractiveRequiredError, RuntimeError) as exc:
            emit_error(cli, str(exc))
    emit_success(cli, result)


@setup_app.command("repo")
def setup_repo_cmd(
    ctx: typer.Context,
    path: str = PATH_ARGUMENT,
    path_flag: str = PATH_OPTION,
    name: str | None = typer.Option(None, "--name"),
    org: str | None = typer.Option(None, "--org"),
    description: str | None = typer.Option(None, "--description"),
    platform: list[DetectionPlatform] = typer.Option(
        [],
        "--platform",
        help="Detection platforms — writes enabled platform TOML (repeatable)",
    ),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Scaffold a detection repository."""
    cli = get_context(ctx)
    base = _setup_path(ctx, cli, path, path_flag)
    yes = _consented(ctx, yes)
    if yes or _has_repo_flags(name, org, description, platform):
        if not _confirm_write(cli, base, "Create this repository scaffold?", yes=yes):
            emit_success(cli, {"message": "Repository setup cancelled", "status": "skipped"})
            return
        options = RepoSetupOptions(
            path=base,
            name=name,
            org=org,
            description=description,
            platforms=platform,
            yes=yes,
        )
        cli.apply_environment()
        result = run_repo_setup(options)
    else:
        _require_scripted_for_json(cli, "opentide setup repo", "--name, --platform")
        try:
            result = run_interactive_repo_setup(cli, base)
        except InteractiveRequiredError as exc:
            emit_error(cli, str(exc))
    emit_success(cli, result)


@setup_app.command("platforms")
def setup_platforms_cmd(
    ctx: typer.Context,
    path: str = PATH_ARGUMENT,
    path_flag: str = PATH_OPTION,
    sentinel: bool = typer.Option(False, "--sentinel"),
    splunk: bool = typer.Option(False, "--splunk"),
    crowdstrike: bool = typer.Option(False, "--crowdstrike"),
    defender_for_endpoint: bool = typer.Option(False, "--defender-for-endpoint"),
    sentinel_one: bool = typer.Option(False, "--sentinel-one"),
    carbon_black_cloud: bool = typer.Option(False, "--carbon-black-cloud"),
    harfanglab: bool = typer.Option(False, "--harfanglab"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Create and enable platform configuration files under ``.opentide/configurations/platforms/``."""
    cli = get_context(ctx)
    base = _setup_path(ctx, cli, path, path_flag)
    yes = _consented(ctx, yes)
    platforms: list[DetectionPlatform] = []
    if sentinel:
        platforms.append(DetectionPlatform.sentinel)
    if splunk:
        platforms.append(DetectionPlatform.splunk)
    if crowdstrike:
        platforms.append(DetectionPlatform.crowdstrike)
    if defender_for_endpoint:
        platforms.append(DetectionPlatform.defender)
    if sentinel_one:
        platforms.append(DetectionPlatform.sentinel_one)
    if carbon_black_cloud:
        platforms.append(DetectionPlatform.carbon_black)
    if harfanglab:
        platforms.append(DetectionPlatform.harfanglab)
    if not platforms:
        raise typer.BadParameter("Choose at least one platform flag (e.g. --sentinel --splunk)")
    if not _confirm_write(cli, base, "Write these platform configurations?", yes=yes):
        emit_success(cli, {"message": "Platform setup cancelled", "status": "skipped"})
        return
    cli.apply_environment()
    emit_success(
        cli,
        run_platforms_setup(PlatformsSetupOptions(path=base, platforms=platforms, yes=yes)),
    )


@setup_app.command("ci")
def setup_ci_cmd(
    ctx: typer.Context,
    ci_platform: CiPlatform = typer.Argument(..., help="github, gitlab, or azure"),
    path: str = PATH_OPTION,
    staging: bool = typer.Option(True, "--staging/--no-staging"),
    inflight: bool = typer.Option(
        True,
        "--inflight/--no-inflight",
        help="Update .opentide/inflight/ preview shards on pull requests",
    ),
    promotion: bool = typer.Option(True, "--promotion/--no-promotion"),
    promotion_target: str = typer.Option("PRODUCTION", "--promotion-target"),
    python_version: str = typer.Option("3.12", "--python-version"),
    explorer_pages: bool = typer.Option(
        False,
        "--explorer-pages/--no-explorer-pages",
        help="Include GitHub Pages explorer build and deploy jobs",
    ),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Generate CI/CD pipeline files (platforms discovered from repo config)."""
    cli = get_context(ctx)
    if ci_platform is CiPlatform.none:
        raise typer.BadParameter("Choose github, gitlab, or azure")
    target = _option_path(ctx, cli, path)
    yes = _consented(ctx, yes)
    if not _confirm_write(cli, target, "Write this CI/CD configuration?", yes=yes):
        emit_success(cli, {"message": "CI/CD setup cancelled", "status": "skipped"})
        return
    options = CiSetupOptions(
        path=target,
        ci=ci_platform,
        staging=staging,
        inflight=inflight,
        promotion=promotion,
        promotion_target=promotion_target,
        python_version=python_version,
        explorer_pages=explorer_pages,
        yes=yes,
    )
    cli.apply_environment()
    emit_success(cli, run_ci_setup(options))


@setup_app.command("env")
def setup_env_cmd(
    ctx: typer.Context,
    path: str = PATH_ARGUMENT,
    path_flag: str = PATH_OPTION,
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Write ``.env.example`` with ``OPENTIDE_REPO_ROOT`` and ignore ``.env``."""
    from opentide.cli.services.setup.env import EnvSetupOptions, run_env_setup

    cli = get_context(ctx)
    base = _setup_path(ctx, cli, path, path_flag)
    yes = _consented(ctx, yes)
    if not _confirm_write(cli, base, "Write .env.example with OPENTIDE_REPO_ROOT?", yes=yes):
        emit_success(cli, {"message": "Environment setup cancelled", "status": "skipped"})
        return
    cli.apply_environment()
    emit_success(cli, run_env_setup(EnvSetupOptions(path=base, yes=yes)))


@setup_app.command("hooks")
def setup_hooks_cmd(
    ctx: typer.Context,
    path: str = PATH_ARGUMENT,
    path_flag: str = PATH_OPTION,
    install: bool = typer.Option(
        True,
        "--install/--no-install",
        help="Install .git/hooks/pre-commit when this path is a Git repository",
    ),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Configure validate-on-commit hooks (pre-commit config + Git hook)."""
    from opentide.cli.services.setup.hooks import HooksSetupOptions, run_hooks_setup

    cli = get_context(ctx)
    base = _setup_path(ctx, cli, path, path_flag)
    yes = _consented(ctx, yes)
    if not _confirm_write(cli, base, "Configure validate-on-commit hooks?", yes=yes):
        emit_success(cli, {"message": "Hook setup cancelled", "status": "skipped"})
        return
    cli.apply_environment()
    emit_success(cli, run_hooks_setup(HooksSetupOptions(path=base, install=install, yes=yes)))


@setup_app.command("mcp")
def setup_mcp_cmd(
    ctx: typer.Context,
    path: str = PATH_ARGUMENT,
    path_flag: str = PATH_OPTION,
    vscode: bool = typer.Option(False, "--vscode"),
    cursor: bool = typer.Option(False, "--cursor"),
    claude_code: bool = typer.Option(False, "--claude-code"),
    generic: bool = typer.Option(False, "--generic"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Write OpenTide MCP configuration for editors and agents."""
    cli = get_context(ctx)
    base = _setup_path(ctx, cli, path, path_flag)
    yes = _consented(ctx, yes)
    hosts: list[McpHost] = []
    if vscode:
        hosts.append(McpHost.vscode)
    if cursor:
        hosts.append(McpHost.cursor)
    if claude_code:
        hosts.append(McpHost.claude_code)
    if generic:
        hosts.append(McpHost.generic)

    if yes and not hosts:
        emit_error(
            cli,
            "Choose at least one MCP host (--vscode, --cursor, --claude-code, --generic)",
            exit_code=2,
        )

    if yes or hosts:
        if not _confirm_write(cli, base, "Write these MCP configurations?", yes=yes):
            emit_success(cli, {"message": "MCP setup cancelled", "status": "skipped"})
            return
        options = McpSetupOptions(path=base, hosts=hosts, yes=yes)
        cli.apply_environment()
        result = run_mcp_setup(options)
    else:
        _require_scripted_for_json(cli, "opentide setup mcp", "--vscode, --cursor, --claude-code")
        try:
            result = run_interactive_mcp_setup(base)
        except InteractiveRequiredError as exc:
            emit_error(cli, str(exc))
    emit_success(cli, result)


@skills_app.callback(invoke_without_command=True)
def setup_skills_install_cmd(
    ctx: typer.Context,
    path: str = typer.Option(".", "--path", "-C", help="Repository path"),
    cursor: bool = typer.Option(False, "--cursor"),
    claude_code: bool = typer.Option(False, "--claude-code"),
    generic: bool = typer.Option(False, "--generic"),
    github_copilot: bool = typer.Option(False, "--github-copilot"),
    install: list[str] = typer.Option([], "--install", help="Skill slugs to install (repeatable)"),
    all_skills: bool = typer.Option(False, "--all", help="Install full skills catalogue"),
    name: str | None = typer.Option(None, "--name"),
    org: str | None = typer.Option(None, "--org"),
    description: str | None = typer.Option(None, "--description"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Install detection engineering agent skills from OpenTideHQ/skills.

    The group callback must not take a positional PATH: Click would consume
    ``discover`` / ``show`` as that argument and skip those subcommands.
    """
    if ctx.invoked_subcommand is not None:
        _hand_down(ctx)
        return
    cli = get_context(ctx)
    base = _option_path(ctx, cli, path)
    yes = _consented(ctx, yes)
    targets: list[SkillTarget] = []
    if cursor:
        targets.append(SkillTarget.cursor)
    if claude_code:
        targets.append(SkillTarget.claude_code)
    if generic:
        targets.append(SkillTarget.generic)
    if github_copilot:
        targets.append(SkillTarget.github_copilot)

    if yes and not targets:
        emit_error(
            cli,
            "Choose at least one skills target "
            "(--cursor, --claude-code, --generic, --github-copilot)",
            exit_code=2,
        )

    if yes or targets:
        if not _confirm_write(cli, base, "Install these agent skills?", yes=yes):
            emit_success(cli, {"message": "Agent skills setup cancelled", "status": "skipped"})
            return
        options = SkillsSetupOptions(
            path=base,
            targets=targets,
            skill_slugs=list(install),
            install_all=all_skills,
            name=name,
            org=org,
            description=description,
            yes=yes,
        )
        cli.apply_environment()
        try:
            result = run_skills_setup(options)
        except (SkillsDownloadError, SkillsManifestError) as exc:
            emit_error(cli, str(exc))
    else:
        _require_scripted_for_json(cli, "opentide setup skills", "--skill, --all")
        try:
            result = run_interactive_skills_setup(base)
        except (InteractiveRequiredError, RuntimeError, SkillsManifestError) as exc:
            emit_error(cli, str(exc))
    emit_success(cli, result)


@skills_app.command("discover")
def setup_skills_discover_cmd(
    ctx: typer.Context,
    path: str = PATH_ARGUMENT,
    path_flag: str = PATH_OPTION,
    query: str | None = typer.Option(None, "--query", "-q"),
    installed: bool = typer.Option(False, "--installed"),
    refresh: bool = typer.Option(False, "--refresh"),
) -> None:
    """List skills from the OpenTideHQ/skills catalogue."""
    cli = get_context(ctx)
    base = _setup_path(ctx, cli, path, path_flag, deprecate_positional=True)
    try:
        payload = discover_skills(base, query=query, installed_only=installed, refresh=refresh)
    except SkillsManifestError as exc:
        emit_error(cli, str(exc))
    if cli.json_output:
        emit_success(cli, payload)
        return
    from rich.table import Table

    table = Table(title="OpenTide Skills")
    table.add_column("Name")
    table.add_column("Installed")
    table.add_column("Description")
    for item in payload["skills"]:
        table.add_row(
            str(item["name"]),
            "yes" if item.get("installed") else "no",
            str(item.get("description", ""))[:80],
        )
    get_stdout_console().print(table)
    get_stdout_console().print(f"Source: {payload['source']} ({payload['count']} skills)")


@skills_app.command("show")
def setup_skills_show_cmd(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Skill slug or name"),
    path: str = typer.Option(".", "--path", "-C"),
    refresh: bool = typer.Option(False, "--refresh"),
) -> None:
    """Show details for one skill from the catalogue."""
    cli = get_context(ctx)
    base = _option_path(ctx, cli, path)
    try:
        payload = show_skill(base, name, refresh=refresh)
    except SkillsManifestError as exc:
        emit_error(cli, str(exc))
    if cli.json_output:
        if "error" in payload:
            emit(cli, {"ok": False, **payload}, exit_code=1)
        else:
            emit_success(cli, payload)
        return
    if "error" in payload:
        get_console().print(f"[red]{payload['error']}[/red]")
        raise typer.Exit(1)
    skill = payload["skill"]
    get_stdout_console().print(f"[bold]{skill['name']}[/bold] ({skill['slug']})")
    get_stdout_console().print(skill.get("description", ""))
    get_stdout_console().print(f"Installed: {'yes' if skill.get('installed') else 'no'}")
    get_stdout_console().print(payload.get("install_hint", ""))


@setup_app.command("vscode")
def setup_vscode_cmd(
    ctx: typer.Context,
    path: str = PATH_ARGUMENT,
    path_flag: str = PATH_OPTION,
    settings: bool = typer.Option(False, "--settings"),
    snippets: bool = typer.Option(False, "--snippets"),
    no_merge: bool = typer.Option(False, "--no-merge"),
    no_generate: bool = typer.Option(False, "--no-generate"),
    mcp: bool = typer.Option(
        False, "--mcp", help="Also write .vscode/mcp.json (same as setup mcp --vscode)"
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Accepted for symmetry with other setup subcommands; this command never prompts",
    ),
) -> None:
    """Write VS Code yaml.schemas and snippets (deprecated). Default: both."""
    cli = get_context(ctx)
    cli.apply_environment()
    target = _setup_path(ctx, cli, path, path_flag)
    run_settings_flag = settings or not snippets
    run_snippets_flag = snippets or not settings
    result = run_vscode_setup(
        target,
        settings=run_settings_flag,
        snippets=run_snippets_flag,
        generate=not no_generate,
        merge=not no_merge,
        mcp=mcp,
    )
    emit_success(cli, result)
