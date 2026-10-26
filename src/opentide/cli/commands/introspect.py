"""``opentide commands``: every command, its options and an example, for people and agents."""

from __future__ import annotations

import typer

from opentide.cli.context import get_context
from opentide.cli.output import emit_success


def commands_cmd(ctx: typer.Context) -> None:
    """List every command and option, for agents

    Each command comes with its arguments, options (types, choices, defaults,
    environment variables) and an example. Add --json for the whole tree in one
    document.
    """
    from opentide.cli.services.introspect import command_tree, tree_lines

    cli = get_context(ctx)
    payload = command_tree(ctx.find_root().command, program="opentide")
    count = payload["_summary"]["commands"]
    payload["message"] = f"{count} commands"
    if not cli.json_output:
        _render_tree(tree_lines(payload))
    emit_success(cli, payload)


def _render_tree(lines: list[tuple[str, str]]) -> None:
    from rich.text import Text

    from opentide.core.logging.config import get_stdout_console

    console = get_stdout_console()
    width = max((len(name) for name, _ in lines), default=0)
    for name, summary in lines:
        line = Text(f"{name:<{width}}  ", style="bold")
        line.append(summary, style="")
        console.print(line, soft_wrap=True)
