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

#: CommonMark fence: three or more backticks or tildes, then an info string
#: whose first word is the language (Fumadocs adds ``title="…"`` after it).
_FENCE = re.compile(r"^(?P<marker>`{3,}|~{3,})\s*(?P<info>.*)$")
#: A file-descriptor number glued to a redirect (``2>/dev/null``, ``2>&1``).
_FD_REDIRECT = re.compile(r"(^|\s)\d+(?=[<>])")
#: Characters shlex treats as operators when ``punctuation_chars`` is on.
_OPERATOR_CHARS = frozenset("();<>|&")
#: ``<uuid>``-style placeholders, which an operator-aware lexer would otherwise
#: read as an input redirect and an output redirect.
_PLACEHOLDER = re.compile(r"<([^\s<>]+)>")
_OPEN, _CLOSE = "\x00", "\x01"
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


def _iter_fenced(text: str) -> Iterator[tuple[str, int, str]]:
    """Yield ``(language, line_number, raw_line)`` for every line inside a fence.

    Follows CommonMark closely enough for documentation: a fence closes only on
    the same character repeated at least as many times with no info string, so
    a ```` ```bash title="x" ```` opener or a four-backtick block that quotes a
    three-backtick one cannot flip the in/out state for the rest of the page.
    """
    marker: str | None = None
    language = ""
    for number, raw in enumerate(text.splitlines(), start=1):
        fence = _FENCE.match(raw.strip())
        if marker is None:
            if fence is not None:
                marker = fence.group("marker")
                info = fence.group("info").strip()
                language = info.split()[0].lower() if info else ""
            continue
        if (
            fence is not None
            and fence.group("marker")[0] == marker[0]
            and len(fence.group("marker")) >= len(marker)
            and not fence.group("info").strip()
        ):
            marker = None
            continue
        yield language, number, raw


def iter_shell_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield ``(line_number, command)`` for each line inside a shell fence.

    Backslash continuations are joined so a wrapped invocation is parsed as the
    single command the reader would paste.
    """
    pending: list[str] = []
    pending_line = 0
    previous = -1
    for language, number, raw in _iter_fenced(text):
        if number != previous + 1:
            # A new fence started; a continuation cannot cross it.
            pending = []
        previous = number
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
    """Split a shell line into the argv lists it runs, dropping redirects.

    Operators are recognised without surrounding spaces (``a|b``, ``a;b``,
    ``$(opentide info)``), and a redirect's file descriptor and target are
    dropped rather than read as positional arguments (``2>/dev/null``).
    """
    shielded = _PLACEHOLDER.sub(rf"{_OPEN}\1{_CLOSE}", _FD_REDIRECT.sub(r"\1", line))
    lexer = shlex.shlex(shielded, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        tokens = [token.replace(_OPEN, "<").replace(_CLOSE, ">") for token in lexer]
    except ValueError:
        # Unbalanced quotes: a prose snippet, not something a reader pastes.
        return
    current: list[str] = []
    skip_target = False
    for token in tokens:
        if skip_target:
            skip_target = False
            continue
        if token and set(token) <= _OPERATOR_CHARS:
            if "<" in token or ">" in token:
                skip_target = True
            if current:
                yield current
            current = []
            continue
        current.append(token)
    if current:
        yield current


#: ``uv run`` / ``uvx`` / ``pipx run`` options that consume the next token.
_LAUNCHER_VALUE_OPTIONS = frozenset(
    {"--from", "--with", "--python", "-p", "--spec", "--project", "--directory", "--package"}
)
_LAUNCHERS: tuple[tuple[str, ...], ...] = (("uv", "run"), ("uvx",), ("pipx", "run"))


def _strip_launcher(tokens: list[str]) -> list[str] | None:
    """Drop a ``uv run`` / ``uvx`` / ``pipx run`` prefix and its own options.

    Returns ``None`` when the launcher runs some other program, and the tokens
    unchanged when there is no launcher.
    """
    for launcher in _LAUNCHERS:
        if tuple(tokens[: len(launcher)]) != launcher:
            continue
        rest = tokens[len(launcher) :]
        index = 0
        while index < len(rest):
            token = rest[index]
            if not token.startswith("-"):
                return rest[index:]
            index += 2 if token in _LAUNCHER_VALUE_OPTIONS else 1
        return None
    return tokens


def normalise(argv: list[str]) -> tuple[str, ...] | None:
    """Return the ``opentide`` argv in *argv*, or ``None`` when there is none."""
    tokens = list(argv)
    while tokens and (
        tokens[0] == "$" or tokens[0] in KEYWORDS or _ENV_ASSIGNMENT.match(tokens[0])
    ):
        tokens.pop(0)
    launched = _strip_launcher(tokens)
    if not launched or Path(launched[0]).name != "opentide":
        return None
    return tuple(launched[1:])


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
    blocks: list[list[str]] = []
    previous = -1
    for block_language, number, raw in _iter_fenced(page.read_text(encoding="utf-8")):
        if number != previous + 1:
            blocks.append([])
        previous = number
        if block_language == language:
            blocks[-1].append(raw)
        elif blocks and not blocks[-1]:
            blocks.pop()
    return ["\n".join(block) for block in blocks if block]


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


def _arguments(command: click.Command) -> list[click.Parameter]:
    return [param for param in command.params if _is_argument(param)]


def _positional_limit(command: click.Command) -> int | None:
    """Maximum positional arguments, or ``None`` when unbounded."""
    total = 0
    for param in _arguments(command):
        if param.nargs == -1:
            return None
        total += param.nargs
    return total


def _is_placeholder(value: str) -> bool:
    return any(marker in value for marker in ("<", "$", "...", "/path/to/"))


def _choice_problem(param: click.Parameter, value: str, where: str) -> str | None:
    """Explain why *value* is not one of *param*'s choices, if it has any.

    Typer renders enum options as a Choice; checked structurally for the same
    vendored-Click reason as ``_is_group``.
    """
    choices = getattr(param.type, "choices", None)
    if not choices or _is_placeholder(value):
        return None
    names = [str(getattr(choice, "value", choice)) for choice in choices]
    if getattr(param.type, "case_sensitive", True):
        accepted = value in names
    else:
        accepted = value.lower() in {name.lower() for name in names}
    if accepted:
        return None
    label = param.opts[0] if param.opts and param.opts[0].startswith("-") else param.name
    return f"{where!r} {label} does not accept {value!r} (choose from {', '.join(names)})"


def resolve(argv: tuple[str, ...]) -> list[str]:
    """Return the reasons *argv* would not parse, empty when it is valid.

    Checks what Click would reject before running anything: unknown commands
    and options, an option missing its value, a flag given ``=value``, a value
    outside an enum's choices, and too few or too many positional arguments.
    """
    root = get_command(app)
    context = root.context_class(root, info_name="opentide")
    command: click.Command = root
    path = ["opentide"]
    problems: list[str] = []
    positionals: list[str] = []
    asked_for_help = False
    index = 0
    tokens = list(argv)
    while index < len(tokens):
        token = tokens[index]
        index += 1
        where = " ".join(path)
        if token == "--":
            positionals.extend(tokens[index:])
            break
        if token.startswith("-") and token != "-":
            if token in {"--help", "-h"}:
                asked_for_help = True
                continue
            name, separator, inline = token.partition("=")
            param = _option_lookup(command).get(name)
            if param is None:
                problems.append(f"{where!r} has no option {name!r}")
                continue
            if not _takes_value(param):
                if separator:
                    problems.append(f"{where!r} {name} is a flag and takes no value")
                continue
            if separator:
                value = inline
            elif index < len(tokens):
                value = tokens[index]
                index += 1
            else:
                problems.append(f"{where!r} {name} requires a value")
                continue
            if problem := _choice_problem(param, value, where):
                problems.append(problem)
            continue
        if _is_group(command):
            sub = command.get_command(context, token)
            if sub is None:
                problems.append(f"{where!r} has no subcommand {token!r}")
                return problems
            command = sub
            path.append(token)
            continue
        positionals.append(token)

    where = " ".join(path)
    arguments = _arguments(command)
    limit = _positional_limit(command)
    if limit is not None and len(positionals) > limit:
        problems.append(f"{where!r} takes {limit} argument(s), documented with {len(positionals)}")
    for param, value in zip(arguments, positionals, strict=False):
        if param.nargs == 1 and (problem := _choice_problem(param, value, where)):
            problems.append(problem)
    required = sum(1 for param in arguments if param.required and param.nargs > 0)
    if not asked_for_help and len(positionals) < required:
        missing = [param.name for param in arguments if param.required][len(positionals) :]
        problems.append(
            f"{where!r} is missing required argument(s): {', '.join(map(str, missing))}"
        )
    return problems
