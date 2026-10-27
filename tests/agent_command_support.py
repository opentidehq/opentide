"""The ``opentide …`` command lines agents are told to run, and a parser that checks them.

Agents paste these lines from the instruction files ``opentide setup skills``
writes, the bundled skills, the MCP server's ``next_actions`` and the docs. A
line that fails to parse is a usage error (exit 2) waiting for an agent, so
:func:`parse_error` parses each one the way Click would run it: options,
choices, extra arguments and required options all count.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterable, Iterator
from pathlib import Path

#: ``opentide …`` inside a code span.
_SPAN = re.compile(r"`(opentide [^`]+)`")
#: ``"command": "opentide …"`` in a JSON sample.
_JSON_COMMAND = re.compile(r'"command":\s*"(opentide [^"]+)"')
#: ``<rule file>``, ``<code>``, … and the ``…`` an example leaves to the reader.
_PLACEHOLDER = re.compile(r"<([^<>]+)>|…")

#: Values that stand in for placeholders, by the placeholder's words.
PLACEHOLDER_VALUES = {
    "command": "commands",
    "code": "vocab_unknown",
    "platform": "sentinel",
    "p": "sentinel",
    "id": "T1059",
    "technique": "T1059",
    "uuid": "00000000-0000-4000-8003-000000000001",
    "slug": "opentide-detection-rule",
}
_SHELL_TERMINATORS = frozenset({"|", "||", "&&", ";", "&"})
_REDIRECT = re.compile(r"^\d*[<>]")

#: A placeholder for a file, and the tutorial rule that fills it.
TUTORIAL_RULE = "objects/rules/sentinel-kql-rule.yaml"


def fill(command: str) -> str:
    """*command* with each placeholder replaced by a value that parses."""

    def value(match: re.Match[str]) -> str:
        name = (match.group(1) or "").strip()
        if name in PLACEHOLDER_VALUES:
            return PLACEHOLDER_VALUES[name]
        if "file" in name or name in {"rule", "path"}:
            return TUTORIAL_RULE
        return "x"

    filled = _PLACEHOLDER.sub(value, command)
    # ``objects/rules/<rule>.yaml`` becomes a whole path, not a path inside one.
    return filled.replace(f"objects/rules/{TUTORIAL_RULE}.yaml", TUTORIAL_RULE)


def commands_in_markdown(text: str) -> Iterator[str]:
    """``opentide …`` lines of fenced blocks (``\\`` continuations joined), code spans
    and JSON ``"command"`` values elsewhere."""
    in_fence = False
    pending = ""
    for line in text.splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
            pending = ""
            continue
        if in_fence:
            code = pending + line.split(" #", 1)[0].strip()
            pending = ""
            if code.endswith("\\"):
                pending = code[:-1].rstrip() + " "
                continue
            if code.startswith("opentide "):
                yield code
            yield from _JSON_COMMAND.findall(line)
            continue
        yield from (span.strip() for span in _SPAN.findall(line))
        yield from _JSON_COMMAND.findall(line)


def arguments(command: str) -> list[str]:
    """The arguments after ``opentide``, placeholders filled; a pipe or redirect ends them."""
    argv = shlex.split(fill(command))[1:]
    for index, token in enumerate(argv):
        if token in _SHELL_TERMINATORS or _REDIRECT.match(token):
            return argv[:index]
    return argv


def parse_error(root: object, command: str) -> str | None:
    """Why *command* would be a usage error, or ``None`` when Click accepts it.

    *command* starts with ``opentide``. Each group's context is made, then its
    subcommand's, until no arguments are left, as Click does before it runs
    a command; no callback runs.
    """
    import typer
    from typer import _click
    from typer.core import TyperGroup

    try:
        argv = arguments(command)
    except ValueError as error:
        return f"cannot split: {error}"
    try:
        ctx = root.make_context("opentide", argv)  # ty: ignore[unresolved-attribute]
        args = [*ctx._protected_args, *ctx.args]
        while args and isinstance(ctx.command, TyperGroup):
            name, sub, args = ctx.command.resolve_command(ctx, args)
            assert sub is not None
            ctx = sub.make_context(name, args, parent=ctx)
            args = [*ctx._protected_args, *ctx.args]
    except _click.exceptions.NoArgsIsHelpError:
        return None  # a group named on its own prints its help, exit 0
    except _click.exceptions.UsageError as error:
        return error.format_message()
    except (typer.Exit, SystemExit) as exit_:
        code = getattr(exit_, "exit_code", getattr(exit_, "code", 0))
        return f"usage error (exit {code})" if code else None
    if args:
        return f"unparsed arguments: {args}"
    return None


def unique(commands: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(commands))


def instruction_sources() -> dict[str, str]:
    """Every instruction file and skill ``opentide setup skills`` can write, rendered."""
    from opentide.cli.services.setup.templates import (
        ENTRYPOINT_TEMPLATES,
        render_agent_entrypoint,
        setup_data_root,
    )

    context = {"name": "SOC Detections", "org": "SecOps", "description": "Rules for SOC"}
    texts = {name: render_agent_entrypoint(name, context) for name in sorted(ENTRYPOINT_TEMPLATES)}
    root = setup_data_root() / "skills"
    for path in sorted(root.rglob("SKILL.md")):
        texts[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8")
    return texts


#: Docs pages that tell agents what to run.
AGENT_DOCS = (
    Path("docs/cli/index.md"),
    Path("docs/cli/json-output.md"),
    Path("docs/mcp/index.md"),
    Path("docs/mcp/tools.md"),
    Path("docs/usage/workflows/agentic-setup.md"),
)
