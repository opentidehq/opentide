"""Typer application for ``opentide setup``."""

from __future__ import annotations

from pathlib import Path

import typer

from opentide.cli.context import CliContext, get_context
from opentide.cli.enums import CiPlatform, DetectionPlatform, McpHost, SkillTarget
from opentide.cli.output import emit, emit_success
from opentide.cli.services.setup.ci import CiSetupOptions, run_ci_setup
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
    SkillsSetupOptions,
    run_interactive_skills_setup,
    run_skills_setup,
)
from opentide.cli.services.setup.skills_registry import discover_skills, show_skill
from opentide.cli.services.setup.vscode import (
    run_vscode_settings,
    run_vscode_snippets,
)

setup_app = typer.Typer(help="Repository and tooling setup")
skills_app = typer.Typer(help="Agent skills discovery and installation")
setup_app.add_typer(skills_app, name="skills")


def _resolve_setup_path(cli: CliContext, path: str | Path) -> Path:
    """Honor ``--repo`` when setup path is the default (``.``)."""
    target = Path(path)
    if target == Path(".") and cli.repo.resolve() != Path.cwd().resolve():
        return cli.repo
    return target


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
    vscode_setup: bool = typer.Option(
        False, "--vscode-setup", help="Run deprecated VS Code settings + snippets"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Non-interactive mode"),
) -> None:
    """Interactive or scripted detection repository onboarding."""
    if ctx.invoked_subcommand is not None:
        return

    cli = get_context(ctx)
    base = _resolve_setup_path(cli, path)
    has_repo = _has_repo_flags(name, org, description, platform)
    only_ci_none = ci is CiPlatform.none and not yes and not has_repo and not vscode_setup
    scripted = not only_ci_none and (yes or has_repo or ci is not None or vscode_setup)

    if scripted:
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
        result = run_interactive_setup(cli, base)
    emit_success(cli, result)


@setup_app.command("repo")
def setup_repo_cmd(
    ctx: typer.Context,
    path: str = typer.Argument(".", help="Repository path"),
    name: str | None = typer.Option(None, "--name"),
    org: str | None = typer.Option(None, "--org"),
    description: str | None = typer.Option(None, "--description"),
    platform: list[DetectionPlatform] = typer.Option(
        [], "--platform", help="Detection platforms (repeatable)"
    ),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Scaffold a detection repository."""
    cli = get_context(ctx)
    base = _resolve_setup_path(cli, path)
    if yes or _has_repo_flags(name, org, description, platform):
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
        result = run_interactive_repo_setup(cli, base)
    emit_success(cli, result)


@setup_app.command("platforms")
def setup_platforms_cmd(
    ctx: typer.Context,
    path: str = typer.Argument(".", help="Repository path"),
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
    base = _resolve_setup_path(cli, path)
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
    if yes and not platforms:
        platforms = [DetectionPlatform.sentinel]
    if not platforms:
        raise typer.BadParameter("Choose at least one platform flag (e.g. --sentinel --splunk)")
    cli.apply_environment()
    emit_success(
        cli,
        run_platforms_setup(PlatformsSetupOptions(path=base, platforms=platforms, yes=yes)),
    )


@setup_app.command("ci")
def setup_ci_cmd(
    ctx: typer.Context,
    ci_platform: CiPlatform = typer.Argument(..., help="github, gitlab, or azure"),
    path: str = typer.Option(".", "--path", "-C", help="Repository path"),
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
    options = CiSetupOptions(
        path=_resolve_setup_path(cli, path),
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


@setup_app.command("mcp")
def setup_mcp_cmd(
    ctx: typer.Context,
    path: str = typer.Argument(".", help="Repository path"),
    vscode: bool = typer.Option(False, "--vscode"),
    cursor: bool = typer.Option(False, "--cursor"),
    claude_code: bool = typer.Option(False, "--claude-code"),
    generic: bool = typer.Option(False, "--generic"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Write OpenTide MCP configuration for editors and agents."""
    cli = get_context(ctx)
    base = _resolve_setup_path(cli, path)
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
        hosts = [McpHost.vscode]

    if yes or hosts:
        options = McpSetupOptions(path=base, hosts=hosts, yes=yes)
        cli.apply_environment()
        result = run_mcp_setup(options)
    else:
        result = run_interactive_mcp_setup(base)
    emit_success(cli, result)


def _coalesce_setup_path(cli: CliContext, positional: str, option: str) -> Path:
    """Prefer ``--path`` when set; otherwise use the positional path."""
    if option != ".":
        return _resolve_setup_path(cli, option)
    return _resolve_setup_path(cli, positional)


@skills_app.callback(invoke_without_command=True)
def setup_skills_install_cmd(
    ctx: typer.Context,
    path: str = typer.Argument(".", help="Repository path"),
    path_flag: str = typer.Option(".", "--path", "-C", help="Repository path"),
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
    """Install detection engineering agent skills from OpenTideHQ/skills."""
    if ctx.invoked_subcommand is not None:
        return
    cli = get_context(ctx)
    base = _coalesce_setup_path(cli, path, path_flag)
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
        targets = [SkillTarget.generic]

    if yes or targets:
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
        result = run_skills_setup(options)
    else:
        result = run_interactive_skills_setup(base)
    emit_success(cli, result)


@skills_app.command("discover")
def setup_skills_discover_cmd(
    ctx: typer.Context,
    path: str = typer.Argument(".", help="Repository path"),
    path_flag: str = typer.Option(".", "--path", "-C", help="Repository path"),
    query: str | None = typer.Option(None, "--query", "-q"),
    installed: bool = typer.Option(False, "--installed"),
    refresh: bool = typer.Option(False, "--refresh"),
) -> None:
    """List skills from the OpenTideHQ/skills catalogue."""
    cli = get_context(ctx)
    base = _coalesce_setup_path(cli, path, path_flag)
    payload = discover_skills(base, query=query, installed_only=installed, refresh=refresh)
    if cli.json_output:
        emit_success(cli, payload)
        return
    from rich.console import Console
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
    Console().print(table)
    Console().print(f"Source: {payload['source']} ({payload['count']} skills)")


@skills_app.command("show")
def setup_skills_show_cmd(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Skill slug or name"),
    path: str = typer.Option(".", "--path", "-C"),
    refresh: bool = typer.Option(False, "--refresh"),
) -> None:
    """Show details for one skill from the catalogue."""
    cli = get_context(ctx)
    base = _resolve_setup_path(cli, path)
    payload = show_skill(base, name, refresh=refresh)
    if cli.json_output:
        if "error" in payload:
            emit(cli, {"ok": False, **payload}, exit_code=1)
        else:
            emit_success(cli, payload)
        return
    from rich.console import Console

    if "error" in payload:
        Console().print(f"[red]{payload['error']}[/red]")
        raise typer.Exit(1)
    skill = payload["skill"]
    Console().print(f"[bold]{skill['name']}[/bold] ({skill['slug']})")
    Console().print(skill.get("description", ""))
    Console().print(f"Installed: {'yes' if skill.get('installed') else 'no'}")
    Console().print(payload.get("install_hint", ""))


@setup_app.command("vscode")
def setup_vscode_cmd(
    ctx: typer.Context,
    path: str = typer.Argument(".", help="Repository path"),
    settings: bool = typer.Option(False, "--settings"),
    snippets: bool = typer.Option(False, "--snippets"),
    no_merge: bool = typer.Option(False, "--no-merge"),
) -> None:
    """Write VS Code yaml.schemas and snippets (deprecated). Default: both."""
    cli = get_context(ctx)
    cli.apply_environment()
    target = _resolve_setup_path(cli, path)
    run_settings_flag = settings or not snippets
    run_snippets_flag = snippets or not settings
    written: dict[str, object] = {"message": "VS Code setup complete (deprecated)", "files": []}
    files: list[str] = []
    if run_settings_flag:
        result = run_vscode_settings(target, merge=not no_merge)
        files.extend(result.get("files", []))  # type: ignore[arg-type]
    if run_snippets_flag:
        snippet_path = run_vscode_snippets(target)
        if snippet_path:
            files.append(snippet_path)
    written["files"] = files
    emit_success(cli, written)
