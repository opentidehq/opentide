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


#: In the order ``opentide --help`` lists them.
ROOT_COMMANDS: tuple[CommandSpec, ...] = (
    CommandSpec(
        "lint",
        "opentide.cli.commands.lint",
        "lint_cmd",
        "Catalogue hygiene: filename slugs and recommended metadata (not schema validation).",
    ),
    CommandSpec(
        "info",
        "opentide.cli.commands.info",
        "info_cmd",
        "Show repository and platform information.",
    ),
    CommandSpec(
        "explain",
        "opentide.cli.commands.explain",
        "explain_cmd",
        "Explain a diagnostic code: what it means, an example, and how to fix it.",
    ),
    CommandSpec(
        "commands",
        "opentide.cli.commands.introspect",
        "commands_cmd",
        "List every command and option, for agents",
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
        "Run the opentide MCP server on stdio. The editor owns the process: "
        "stop is the host closing stdin, and reload is the host spawning this "
        "command again. There is no reload or stop subcommand.",
    ),
    CommandSpec("setup", "opentide.cli.setup_app", "setup_app", "Repository and tooling setup"),
    CommandSpec(
        "share",
        "opentide.cli.share_app",
        "share_app",
        "Publish Tide objects to intelligence platforms",
    ),
    CommandSpec("rules", "opentide.cli.rules_app", "rules_app", "Detection rule maintenance"),
    CommandSpec(
        "generate",
        "opentide.cli.commands.generate",
        "generate_app",
        "Framework generation and documentation pipeline.",
    ),
    CommandSpec(
        "validate",
        "opentide.cli.commands.validate",
        "validate_app",
        "Object and query validation",
    ),
    CommandSpec("deploy", "opentide.cli.commands.deploy", "deploy_app", "Rule deployment"),
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
    CommandSpec(
        "migrate",
        "opentide.cli.commands.migrate",
        "migrate_app",
        "Migrate legacy client repository layouts",
    ),
)
