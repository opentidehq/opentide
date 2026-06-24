"""Typer application for ``opentide setup``."""

from __future__ import annotations

import typer

from opentide.cli.context import get_context
from opentide.cli.enums import CiPlatform, DetectionPlatform, McpHost, SkillTarget
from opentide.cli.output import emit_success
from opentide.cli.services.setup.ci import CiSetupOptions, run_ci_setup
from opentide.cli.services.setup.mcp import (
    McpSetupOptions,
    run_interactive_mcp_setup,
    run_mcp_setup,
)
from opentide.cli.services.setup.orchestrator import SetupOptions, run_interactive_setup, run_setup
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
from opentide.cli.services.setup.vscode import (
    run_vscode_all,
    run_vscode_settings,
    run_vscode_snippets,
)

setup_app = typer.Typer(help="Repository and tooling setup")
vscode_app = typer.Typer(help="VS Code configuration (deprecated)")
setup_app.add_typer(vscode_app, name="vscode")


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
    mcp: list[McpHost],
    skills: list[SkillTarget],
    vscode_setup: bool,
) -> bool:
    if interactive or has_repo_flags:
        return True
    return yes and not any([ci is not None, mcp, skills, vscode_setup])


@setup_app.callback(invoke_without_command=True)
def setup_cmd(
    ctx: typer.Context,
    path: str = typer.Option(".", "--path", "-C", help="Repository path"),
    name: str | None = typer.Option(None, "--name"),
    org: str | None = typer.Option(None, "--org"),
    description: str | None = typer.Option(None, "--description"),
    platform: list[DetectionPlatform] = typer.Option(
        [], "--platform", help="Detection platforms (repeatable)"
    ),
    ci: CiPlatform | None = typer.Option(None, "--ci"),
    staging: bool = typer.Option(True, "--staging/--no-staging"),
    promotion: bool = typer.Option(True, "--promotion/--no-promotion"),
    promotion_target: str = typer.Option("PRODUCTION", "--promotion-target"),
    python_version: str = typer.Option("3.12", "--python-version"),
    mcp: list[McpHost] = typer.Option([], "--mcp", help="MCP host targets (repeatable)"),
    skills: list[SkillTarget] = typer.Option([], "--skills", help="Agent targets (repeatable)"),
    vscode_setup: bool = typer.Option(
        False, "--vscode-setup", help="Run deprecated VS Code settings + snippets"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Non-interactive mode"),
) -> None:
    """Interactive or scripted detection repository onboarding."""
    if ctx.invoked_subcommand is not None:
        return
    from pathlib import Path

    cli = get_context(ctx)
    base = Path(path)
    has_repo = _has_repo_flags(name, org, description, platform)
    only_ci_none = (
        ci is CiPlatform.none
        and not yes
        and not has_repo
        and not mcp
        and not skills
        and not vscode_setup
    )
    scripted = not only_ci_none and (
        yes or has_repo or ci is not None or bool(mcp) or bool(skills) or vscode_setup
    )

    if scripted:
        options = SetupOptions(
            path=base,
            name=name,
            org=org,
            description=description,
            platforms=platform,
            ci=ci,
            staging=staging,
            promotion=promotion,
            promotion_target=promotion_target,
            python_version=python_version,
            mcp_hosts=list(mcp),
            skill_targets=list(skills),
            vscode_setup=vscode_setup,
            yes=yes,
            run_repo=_should_run_repo(
                yes=yes,
                interactive=False,
                has_repo_flags=has_repo,
                ci=ci,
                mcp=list(mcp),
                skills=list(skills),
                vscode_setup=vscode_setup,
            ),
            run_ci=ci is not None and ci is not CiPlatform.none,
            run_mcp=bool(mcp),
            run_skills=bool(skills),
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
    from pathlib import Path

    cli = get_context(ctx)
    base = Path(path)
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


@setup_app.command("ci")
def setup_ci_cmd(
    ctx: typer.Context,
    path: str = typer.Argument(".", help="Repository path"),
    ci: CiPlatform = typer.Option(CiPlatform.github, "--ci"),
    platform: list[DetectionPlatform] = typer.Option(
        [], "--platform", help="Detection platforms (repeatable)"
    ),
    staging: bool = typer.Option(True, "--staging/--no-staging"),
    promotion: bool = typer.Option(True, "--promotion/--no-promotion"),
    promotion_target: str = typer.Option("PRODUCTION", "--promotion-target"),
    python_version: str = typer.Option("3.12", "--python-version"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Generate CI/CD pipeline files."""
    from pathlib import Path

    cli = get_context(ctx)
    if ci is CiPlatform.none:
        raise typer.BadParameter("Choose --ci github, gitlab, or azure")
    options = CiSetupOptions(
        path=Path(path),
        ci=ci,
        platforms=platform,
        staging=staging,
        promotion=promotion,
        promotion_target=promotion_target,
        python_version=python_version,
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
    from pathlib import Path

    cli = get_context(ctx)
    base = Path(path)
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


@setup_app.command("skills")
def setup_skills_cmd(
    ctx: typer.Context,
    path: str = typer.Argument(".", help="Repository path"),
    cursor: bool = typer.Option(False, "--cursor"),
    claude_code: bool = typer.Option(False, "--claude-code"),
    generic: bool = typer.Option(False, "--generic"),
    github_copilot: bool = typer.Option(False, "--github-copilot"),
    name: str | None = typer.Option(None, "--name"),
    org: str | None = typer.Option(None, "--org"),
    description: str | None = typer.Option(None, "--description"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Install detection engineering agent skills and entrypoints."""
    from pathlib import Path

    cli = get_context(ctx)
    base = Path(path)
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


@vscode_app.command("settings")
def setup_vscode_settings_cmd(
    ctx: typer.Context,
    path: str = typer.Argument(".", help="Repository path"),
    no_merge: bool = typer.Option(False, "--no-merge"),
) -> None:
    """Write yaml.schemas to .vscode/settings.json (deprecated)."""
    from pathlib import Path

    cli = get_context(ctx)
    cli.apply_environment()
    emit_success(cli, run_vscode_settings(Path(path), merge=not no_merge))


@vscode_app.command("snippets")
def setup_vscode_snippets_cmd(
    ctx: typer.Context,
    path: str = typer.Argument(".", help="Repository path"),
) -> None:
    """Generate VS Code snippets from templates (deprecated)."""
    from pathlib import Path

    cli = get_context(ctx)
    cli.apply_environment()
    snippet_path = run_vscode_snippets(Path(path))
    emit_success(
        cli,
        {
            "message": "VS Code snippets generated (deprecated)"
            if snippet_path
            else "VS Code snippets skipped (no templates in Schemas/Templates)",
            "files": [snippet_path] if snippet_path else [],
        },
    )


@vscode_app.command("all")
def setup_vscode_all_cmd(
    ctx: typer.Context,
    path: str = typer.Argument(".", help="Repository path"),
    no_merge: bool = typer.Option(False, "--no-merge"),
) -> None:
    """Write settings and snippets (deprecated)."""
    from pathlib import Path

    cli = get_context(ctx)
    cli.apply_environment()
    emit_success(cli, run_vscode_all(Path(path), merge=not no_merge))
