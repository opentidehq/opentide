"""Extract and resolve the ``opentide`` invocations printed in ``docs/``.

The tutorial e2e suite copies **YAML** fences out of the docs and validates
them, which is why it caught quoted dates (#178). It never ran the **command**
fences, so every page could keep printing flags and subcommands the CLI had
stopped accepting: ``--path`` where the CLI wanted a positional, ``--json``
after the subcommand instead of before it, ``opentide explorer build`` which
was never registered at all (#247, #270).

Resolution here mirrors Click's own parse order rather than shelling out:
options bind to the command whose token span they appear in, so
``opentide --json validate`` and ``opentide validate --json`` are different
questions and only the first one has an answer.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from typer.main import get_command

from opentide.cli import app

if TYPE_CHECKING:  # pragma: no cover - import only for annotations
    import click

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

#: Fence languages that hold shell transcripts rather than output samples.
SHELL_LANGUAGES = frozenset({"bash", "sh", "shell", "console"})

#: Tokens that end the invocation being parsed; whatever follows is a separate
#: command or a redirect target, neither of which the CLI has to recognise.
TERMINATORS = frozenset({"|", "||", "&&", ";", ">", ">>", "<", "&"})

_FENCE = re.compile(r"^```([A-Za-z0-9_-]*)\s*$")
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
#: Shell keywords that may precede a command inside a documented snippet.
KEYWORDS = frozenset({"if", "then", "else", "elif", "fi", "while", "until", "do", "done", "!"})


@dataclass(frozen=True)
class DocCommand:
    """One ``opentide …`` invocation as printed in a documentation page."""

    page: str
    line: int
    source: str
    argv: tuple[str, ...]

    def __str__(self) -> str:
        return f"{self.page}:{self.line}: {self.source}"


def iter_shell_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield ``(line_number, command)`` for each line inside a shell fence.

    Backslash continuations are joined so a wrapped invocation is parsed as the
    single command the reader would paste.
    """
    language: str | None = None
    pending: list[str] = []
    pending_line = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        fence = _FENCE.match(raw.strip())
        if fence is not None:
            # A fence inside a pending continuation means the block was
            # malformed; drop it rather than swallowing the next fence.
            pending = []
            language = fence.group(1).lower() if language is None else None
            continue
        if language not in SHELL_LANGUAGES:
            continue
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if pending:
            pending.append(line)
        else:
            pending_line = number
            pending = [line]
        if line.endswith("\\"):
            continue
        joined = " ".join(part.rstrip("\\").strip() for part in pending)
        pending = []
        yield pending_line, joined


def split_invocations(line: str) -> Iterator[list[str]]:
    """Split a shell line into the argv lists it runs, dropping redirects."""
    try:
        tokens = shlex.split(line, comments=True)
    except ValueError:
        # Unbalanced quotes: a prose snippet, not something a reader pastes.
        return
    current: list[str] = []
    skip_target = False
    for token in tokens:
        if skip_target:
            skip_target = False
            continue
        if token in TERMINATORS:
            if token in {">", ">>", "<"}:
                skip_target = True
            if current:
                yield current
            current = []
            continue
        current.append(token)
    if current:
        yield current


def normalise(argv: list[str]) -> tuple[str, ...] | None:
    """Return the ``opentide`` argv in *argv*, or ``None`` when there is none."""
    tokens = list(argv)
    while tokens and (
        tokens[0] == "$" or tokens[0] in KEYWORDS or _ENV_ASSIGNMENT.match(tokens[0])
    ):
        tokens.pop(0)
    if not tokens or Path(tokens[0]).name != "opentide":
        return None
    return tuple(tokens[1:])


def documented_commands(paths: list[Path] | None = None) -> list[DocCommand]:
    """Every ``opentide`` invocation printed in the documentation tree."""
    pages = sorted(paths if paths is not None else DOCS.rglob("*.md"))
    found: list[DocCommand] = []
    for page in pages:
        relative = page.relative_to(ROOT).as_posix()
        text = page.read_text(encoding="utf-8")
        for number, line in iter_shell_lines(text):
            for argv in split_invocations(line):
                tokens = normalise(argv)
                if tokens is None:
                    continue
                found.append(DocCommand(relative, number, line, tokens))
    return found


def _is_group(command: click.Command) -> bool:
    """Whether *command* dispatches to subcommands.

    Checked structurally, not with ``isinstance``: Typer bundles its own Click
    copy, so the app's classes do not descend from the ``click`` package on
    ``sys.path`` — and that copy has folded ``Group`` into ``Command``.
    """
    return callable(getattr(command, "get_command", None))


def _is_argument(param: click.Parameter) -> bool:
    return getattr(param, "param_type_name", "") == "argument"


def fenced_blocks(page: Path, language: str) -> list[str]:
    """Every fenced block in *page* tagged with *language*, in document order."""
    blocks: list[str] = []
    current: list[str] | None = None
    for raw in page.read_text(encoding="utf-8").splitlines():
        fence = _FENCE.match(raw.strip())
        if fence is None:
            if current is not None:
                current.append(raw)
            continue
        if current is not None:
            blocks.append("\n".join(current))
            current = None
        elif fence.group(1).lower() == language:
            current = []
    return blocks


def _option_lookup(command: click.Command) -> dict[str, click.Parameter]:
    lookup: dict[str, click.Parameter] = {}
    for param in command.params:
        for opt in (*param.opts, *param.secondary_opts):
            if opt.startswith("-"):
                lookup[opt] = param
    return lookup


def _takes_value(param: click.Parameter) -> bool:
    if getattr(param, "is_flag", False) or getattr(param, "count", False):
        return False
    return param.nargs != 0


def _positional_limit(command: click.Command) -> int | None:
    """Maximum positional arguments, or ``None`` when unbounded."""
    total = 0
    for param in command.params:
        if not _is_argument(param):
            continue
        if param.nargs == -1:
            return None
        total += param.nargs
    return total


def resolve(argv: tuple[str, ...]) -> list[str]:
    """Return the reasons *argv* would not parse, empty when it is valid."""
    root = get_command(app)
    context = root.context_class(root, info_name="opentide")
    command: click.Command = root
    path = ["opentide"]
    problems: list[str] = []
    positionals = 0
    index = 0
    tokens = list(argv)
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if token == "--":
            break
        if token.startswith("-") and token != "-":
            if token in {"--help", "-h"}:
                continue
            name, separator, _ = token.partition("=")
            param = _option_lookup(command).get(name)
            if param is None:
                where = " ".join(path)
                problems.append(f"{where!r} has no option {name!r}")
                continue
            if _takes_value(param) and not separator:
                index += 1
            continue
        if _is_group(command):
            sub = command.get_command(context, token)
            if sub is None:
                where = " ".join(path)
                problems.append(f"{where!r} has no subcommand {token!r}")
                return problems
            command = sub
            path.append(token)
            continue
        positionals += 1
    limit = _positional_limit(command)
    if limit is not None and positionals > limit:
        where = " ".join(path)
        problems.append(f"{where!r} takes {limit} argument(s), documented with {positionals}")
    return problems
