"""Index of the root commands: what ``opentide --help`` and completion list.

Each entry names the module that defines a command and the help line the root
listing shows, so listing commands imports no command module and no engine
module. The command loads only when it runs, or when its own ``--help`` does.

``help`` is the first paragraph of the command's help text, exactly as the
command defines it. ``tests/test_cli/test_lazy_commands.py`` loads every entry
and fails when the two drift apart.
"""

from __future__ import annotations

from typing import NamedTuple


class CommandSpec(NamedTuple):
    """One root command, described without importing it."""

    name: str
    #: Module that defines the command.
    module: str
    #: A ``typer.Typer`` (mounted as a group) or a function (mounted as a command).
    attribute: str
    #: First paragraph of the command's help, as the root listing shows it.
    help: str
    hidden: bool = False
    rich_help_panel: str | None = None
    #: Text after the command's own ``--help``, such as its ``Examples`` block.
    epilog: str | None = None


#: Panels the root listing groups commands under (``opentide.cli.help``).
AUTHOR = "Author"
SHIP = "Ship"
WORKSPACE = "Workspace"
AGENTS = "Agents and integrations"

#: In the order ``opentide --help`` lists them, panel by panel.
ROOT_COMMANDS: tuple[CommandSpec, ...] = (
    CommandSpec(
        "validate",
        "opentide.cli.commands.validate",
        "validate_app",
        "Validate objects and queries",
        rich_help_panel=AUTHOR,
    ),
    CommandSpec(
        "lint",
        "opentide.cli.commands.lint",
        "lint_cmd",
        "Check file names and recommended metadata",
        rich_help_panel=AUTHOR,
    ),
    CommandSpec(
        "info",
        "opentide.cli.commands.info",
        "info_cmd",
        "Show repository and platform information",
        rich_help_panel=AUTHOR,
    ),
    CommandSpec(
        "new",
        "opentide.cli.commands.new",
        "new_app",
        "Scaffold a threat, objective or rule from its template",
        rich_help_panel=AUTHOR,
    ),
    CommandSpec(
        "generate",
        "opentide.cli.commands.generate",
        "generate_app",
        "Generate schemas, templates, docs and exports",
        rich_help_panel=AUTHOR,
    ),
    CommandSpec(
        "rules",
        "opentide.cli.rules_app",
        "rules_app",
        "Detection rule maintenance",
        rich_help_panel=AUTHOR,
    ),
    CommandSpec(
        "deploy",
        "opentide.cli.commands.deploy",
        "deploy_app",
        "Deploy rules to platform tenants",
        rich_help_panel=SHIP,
    ),
    CommandSpec(
        "share",
        "opentide.cli.share_app",
        "share_app",
        "Publish objects to intelligence platforms",
        rich_help_panel=SHIP,
    ),
    CommandSpec(
        "setup",
        "opentide.cli.setup_app",
        "setup_app",
        "Set up a detection repository and its tooling",
        rich_help_panel=WORKSPACE,
    ),
    CommandSpec(
        "doctor",
        "opentide.cli.commands.doctor",
        "doctor_cmd",
        "Check the installation, the workspace and its integrations",
        rich_help_panel=WORKSPACE,
    ),
    CommandSpec(
        "migrate",
        "opentide.cli.commands.migrate",
        "migrate_app",
        "Migrate legacy repository layouts",
        rich_help_panel=WORKSPACE,
    ),
    CommandSpec(
        "tui",
        "opentide.cli.commands.tui",
        "tui_cmd",
        "Browse the catalogue and its diagnostics in a terminal UI",
        rich_help_panel=WORKSPACE,
    ),
    CommandSpec(
        "explorer",
        "opentide.cli.explorer_app",
        "explorer_app",
        "Build or serve the corpus explorer",
        rich_help_panel=WORKSPACE,
    ),
    CommandSpec(
        "explain",
        "opentide.cli.commands.explain",
        "explain_cmd",
        "Explain a diagnostic code and how to fix it",
        rich_help_panel=AGENTS,
    ),
    CommandSpec(
        "commands",
        "opentide.cli.commands.introspect",
        "commands_cmd",
        "List every command and option, for agents",
        rich_help_panel=AGENTS,
        epilog=(
            "[dim]Examples[/dim]\n\n"
            "  [bold]$ opentide commands[/bold]\n\n"
            "  [bold]$ opentide --json commands[/bold]"
        ),
    ),
    CommandSpec(
        "mcp",
        "opentide.cli.mcp_app",
        "mcp_app",
        "Run the opentide MCP server for editors and agents",
        rich_help_panel=AGENTS,
    ),
    CommandSpec(
        "document",
        "opentide.cli.commands.legacy",
        "document_app",
        "\\[deprecated] Use opentide generate docs",
        hidden=True,
    ),
    CommandSpec(
        "export",
        "opentide.cli.commands.legacy",
        "export_legacy_app",
        "\\[deprecated] Use opentide generate exports",
        hidden=True,
    ),
    CommandSpec(
        "extract",
        "opentide.cli.commands.legacy",
        "extract_legacy_app",
        "\\[deprecated] Use opentide generate extract",
        hidden=True,
    ),
)
