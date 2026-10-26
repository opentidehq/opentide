"""The command tree behind ``opentide commands``, read from Click.

Walks the root group the way Click would run it: each root command's module
is imported once, through :meth:`LazyTyperGroup.load`, and nothing else is.
Hidden commands and options are left out. Every entry carries an example:
the first one its ``--help`` shows, or a placeholder built from its required
arguments and options.
"""

from __future__ import annotations

import enum
import inspect
import re
from collections.abc import Iterator, Mapping
from pathlib import PurePath
from typing import Any

#: Options every command has, which say nothing about the command itself.
_PLUMBING_OPTIONS = frozenset({"--help", "--install-completion", "--show-completion"})

#: Environment variables a root option reads in its callback rather than through Click.
_CALLBACK_ENVVARS: dict[str, tuple[str, ...]] = {"--debug": ("OPENTIDE_DEBUG",)}

#: Click's type names, spelled the way JSON Schema spells them where it has one.
_TYPE_NAMES = {"str": "string", "text": "string", "int": "integer", "float": "number"}

#: ``$ opentide …`` lines in a help epilog, with or without Rich markup around them.
_EPILOG_EXAMPLE = re.compile(r"^\s*(?:\[[^\]]*\])*\$\s+(opentide\b.*?)(?:\[/[^\]]*\])*\s*$")


def _app_choices() -> dict[tuple[str, str], tuple[str, ...]]:
    """Values a command checks itself, for parameters Click types as plain strings.

    ``(command path, parameter name)`` → the values the command accepts.
    ``share --target`` is left out: its values are the configured targets.
    ``tests/test_cli/test_commands_introspect.py`` checks each against the command.
    """
    from opentide.models.deployment_enums import DEPLOYABLE_STRATEGIES

    return {
        ("validate", "object_type"): ("rule", "threat", "objective"),
        ("deploy", "strategy"): tuple(strategy.name for strategy in DEPLOYABLE_STRATEGIES),
        ("info", "section"): ("rules", "threats", "objectives", "coverage", "vocab"),
    }


def environment() -> list[dict[str, str]]:
    """Environment variables the CLI reads, the root options' own included.

    Every ``OPENTIDE_*`` name the code under ``src/`` reads is here;
    ``tests/test_cli/test_commands_introspect.py`` greps for them.
    """
    from opentide.cli.ui.codeframe import LINK_SCHEMES
    from opentide.cli.ui.mode import AGENT_VARIABLES, OUTPUT_ENV_VALUES

    modes = "|".join(sorted(OUTPUT_ENV_VALUES))
    links = "|".join(LINK_SCHEMES)
    return [
        {"name": "OPENTIDE_OUTPUT", "meaning": f"Output mode: {modes}"},
        {"name": "OPENTIDE_DEBUG", "meaning": "1 for debug logging, like --debug"},
        {"name": "NO_COLOR", "meaning": "Any value turns colour off, like --no-color"},
        {
            "name": "OPENTIDE_JSON_INDENT",
            "meaning": "0 for one-line JSON, 2 for indented; default: indented on a terminal",
        },
        {"name": "OPENTIDE_REPO_ROOT", "meaning": "Repository root, like --repo"},
        {"name": "OPENTIDE_DATA_ROOT", "meaning": "Bundled data root, like --data"},
        {"name": "OPENTIDE_PROXY", "meaning": "HTTP(S) proxy, like --proxy"},
        {
            "name": "OPENTIDE_TIDE_WORKSPACE",
            "meaning": "Folder whose objects are read, when not the repository root",
        },
        {
            "name": "OPENTIDE_LINKS",
            "meaning": f"Link scheme in code frames: {links}; default vscode in VS Code, else file",
        },
        {"name": "OPENTIDE_LOG_JSON", "meaning": "1 for one JSON object per log line on stderr"},
        {
            "name": "OPENTIDE_VALIDATE_WORKERS",
            "meaning": "Most threads validate uses: a number or auto",
        },
        {
            "name": "OPENTIDE_VALIDATE_PARALLEL_THRESHOLD",
            "meaning": "Fewest objects before validate runs in parallel",
        },
        {
            "name": "OPENTIDE_PROGRESS",
            "meaning": "0 turns terminal progress (OSC 9;4) off; 1 sends it to any terminal",
        },
        *(
            {"name": name, "meaning": "Set by a coding agent: selects agent output mode"}
            for name in AGENT_VARIABLES
        ),
    ]


def command_tree(root: Any, *, program: str = "opentide", schemas: bool = True) -> dict[str, Any]:
    """The payload of ``opentide commands``: global options and every visible command.

    *root* is the ``opentide`` group. ``commands`` is flat and depth-first, in
    the order ``--help`` lists them; ``path`` and ``subcommands`` give the tree.
    Each command's ``output_schema`` is the JSON Schema of its ``--json``
    document, a ``$ref`` into ``$defs``: ``CommandError`` for a group that
    only prints its help, ``null`` for ``mcp start`` or a command with no
    model yet. *schemas* false leaves both
    out, for the human tree.
    """
    from opentide import __version__

    choices = _app_choices()
    entries = list(_walk(root, (), choices))
    groups = sum(1 for entry in entries if entry["group"])
    payload: dict[str, Any] = {
        "program": program,
        "version": __version__,
        "global_options": [_option(param, root=True) for param in _visible_options(root)],
        "environment": environment(),
        "commands": entries,
        "_summary": {"commands": len(entries), "groups": groups},
    }
    if schemas:
        from opentide.cli.ui.results import output_schemas

        found, defs = output_schemas(
            [entry["path"] for entry in entries],
            help_only=frozenset(entry["path"] for entry in entries if not entry["runs_alone"]),
        )
        for entry in entries:
            entry["output_schema"] = found.get(entry["path"])
        payload["$defs"] = defs
    return payload


def _children(group: Any) -> Iterator[tuple[str, Any]]:
    """Visible subcommands of *group*, loading a lazy root command only here."""
    specs = getattr(group, "specs", None)
    if isinstance(specs, Mapping):
        for name, spec in specs.items():
            if not spec.hidden:
                yield name, group.load(spec)
        added = getattr(group.commands, "added", {})
        for name, command in added.items():
            if name not in specs and not getattr(command, "hidden", False):
                yield name, command
        return
    for name, command in (getattr(group, "commands", None) or {}).items():
        if not getattr(command, "hidden", False):
            yield name, command


_AppChoices = Mapping[tuple[str, str], tuple[str, ...]]


def _walk(group: Any, prefix: tuple[str, ...], choices: _AppChoices) -> Iterator[dict[str, Any]]:
    for name, command in _children(group):
        path = (*prefix, name)
        entry = _command(command, path, choices)
        yield entry
        if entry["group"]:
            yield from _walk(command, path, choices)


def _is_group(command: Any) -> bool:
    return isinstance(getattr(command, "commands", None), Mapping)


def _command(command: Any, path: tuple[str, ...], choices: _AppChoices) -> dict[str, Any]:
    group = _is_group(command)
    subcommands = [name for name, _ in _children(command)] if group else []
    help_text = inspect.cleandoc(command.help or "")
    key = " ".join(path)

    def checked(param: Any) -> tuple[str, ...] | None:
        return choices.get((key, str(param.name)))

    return {
        "path": " ".join(path),
        "name": path[-1],
        "summary": _summary(command, help_text),
        "help": help_text,
        "group": group,
        # A group runs on its own when it has a callback that does work
        # (``opentide validate``); otherwise it only prints its help.
        "runs_alone": not group or bool(getattr(command, "invoke_without_command", False)),
        "subcommands": subcommands,
        "deprecated": bool(getattr(command, "deprecated", False)),
        "arguments": [_argument(param, checked(param)) for param in _arguments(command)],
        "options": [
            _option(param, app_choices=checked(param)) for param in _visible_options(command)
        ],
        "example": example(command, path),
    }


def _summary(command: Any, help_text: str) -> str:
    short = getattr(command, "short_help", None)
    if short:
        return " ".join(str(short).split())
    return " ".join(help_text.split("\n\n")[0].split())


def _arguments(command: Any) -> list[Any]:
    return [
        param
        for param in getattr(command, "params", ())
        if getattr(param, "param_type_name", "") == "argument"
        and not getattr(param, "hidden", False)
    ]


def _visible_options(command: Any) -> list[Any]:
    return [
        param
        for param in getattr(command, "params", ())
        if getattr(param, "param_type_name", "") == "option"
        and not getattr(param, "hidden", False)
        and not _PLUMBING_OPTIONS.intersection(param.opts)
    ]


def _type_name(param: Any) -> str:
    if getattr(param, "is_flag", False) and not getattr(param, "count", False):
        return "boolean"
    if getattr(param, "count", False):
        return "count"
    name = str(getattr(param.type, "name", "text"))
    return _TYPE_NAMES.get(name, name)


def _choices(param: Any, app_choices: tuple[str, ...] | None = None) -> list[Any] | None:
    choices = getattr(param.type, "choices", None) or app_choices
    if not choices:
        return None
    return [_json_value(choice) for choice in choices]


def _help(param: Any) -> str | None:
    return _unescape(" ".join(str(getattr(param, "help", None) or "").split())) or None


def _json_value(value: Any) -> Any:
    """*value* as JSON: enums by value, paths as text, sequences as lists."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, enum.Enum):
        return _json_value(value.value)
    if isinstance(value, PurePath):
        return str(value)
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_value(item) for item in value]
    if callable(value):
        return None
    return str(value)


def _envvars(param: Any, *, root: bool) -> list[str]:
    envvar = getattr(param, "envvar", None)
    found: list[str] = [envvar] if isinstance(envvar, str) else list(envvar or ())
    if root:
        for flag in param.opts:
            found.extend(_CALLBACK_ENVVARS.get(flag, ()))
    return found


def _option(
    param: Any, *, root: bool = False, app_choices: tuple[str, ...] | None = None
) -> dict[str, Any]:
    flag = _type_name(param) == "boolean"
    return {
        "name": param.name,
        "flags": list(param.opts),
        "secondary_flags": list(param.secondary_opts),
        "type": _type_name(param),
        "choices": _choices(param, app_choices),
        "default": _json_value(param.default),
        "required": bool(param.required),
        "multiple": bool(getattr(param, "multiple", False)),
        "is_flag": flag,
        "envvars": _envvars(param, root=root),
        "help": _help(param),
    }


def _argument(param: Any, app_choices: tuple[str, ...] | None = None) -> dict[str, Any]:
    nargs = int(getattr(param, "nargs", 1))
    return {
        "name": param.name,
        "type": _type_name(param),
        "choices": _choices(param, app_choices),
        "default": _json_value(param.default),
        "required": bool(param.required),
        "multiple": nargs != 1,
        "envvars": _envvars(param, root=False),
        "help": _help(param),
    }


def example(command: Any, path: tuple[str, ...], *, program: str = "opentide") -> str:
    """The first example its help shows, or a placeholder built here.

    The placeholder is the command with each required argument and option
    filled with its first choice or ``<name>``. It names the command but may
    not run: options a command requires itself (``deploy --strategy``) are not
    filled. A group that only prints its help gives its first subcommand's.
    """
    for line in str(getattr(command, "epilog", None) or "").splitlines():
        match = _EPILOG_EXAMPLE.match(line)
        if match:
            return _unescape(match.group(1))
    if _is_group(command) and not getattr(command, "invoke_without_command", False):
        for name, child in _children(command):
            return example(child, (*path, name), program=program)
    words = [program, *path]
    for param in _arguments(command):
        if param.required:
            words.append(_placeholder(param))
    for param in _visible_options(command):
        if param.required:
            words.append(param.opts[0])
            if _type_name(param) != "boolean":
                words.append(_placeholder(param))
    return " ".join(words)


def _placeholder(param: Any) -> str:
    choices = _choices(param)
    if choices:
        return str(choices[0])
    return f"<{str(param.name).replace('_', '-')}>"


def _unescape(text: str) -> str:
    """Rich markup in an epilog escapes ``[`` as ``\\[``."""
    return text.replace("\\[", "[")


def tree_lines(payload: Mapping[str, Any]) -> list[tuple[str, str]]:
    """``(indented path word, summary)`` pairs for the compact human tree."""
    lines: list[tuple[str, str]] = []
    for entry in payload["commands"]:
        depth = entry["path"].count(" ")
        lines.append(("  " * depth + entry["name"], entry["summary"]))
    return lines
