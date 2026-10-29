"""Shell completion values, read from the workspace's files and the bundled data.

Completion runs on every Tab press, so nothing here builds the registry or
parses YAML: object UUIDs and names come from the first lines of each object
file, ATT&CK ids from a scan of the bundled vocabulary, platforms from the
``enabled = true`` line of each platform file, and diagnostic codes from the
names of the ``explain`` pages. Standard library only at import time; a
source that cannot be read completes nothing rather than failing.

:func:`attach` gives a command's parameters their completion when the lazy
group loads it (:meth:`opentide.cli.lazy.LazyTyperGroup.load`), by option
name, so ``--uuid`` completes the same way on ``validate``, ``share`` and
every ``share`` subcommand. Completing an option's value does not load the
command at all: :func:`complete_from_index` answers from
:data:`INDEXED_OPTIONS` before Click resolves the command line, since a
command's module imports the engine. ``tests/test_cli/test_completion.py``
checks the index against the loaded commands, and ``test_lazy_commands.py``
that completing each indexed option imports no engine module.

``--install-completion`` and ``--show-completion`` take the shell as the word
after them (:func:`install_completion`, :func:`show_completion`).
"""

from __future__ import annotations

import itertools
import json
import os
import re
import sys
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from typing import Any

#: The object kinds, in the order completion lists them, and their default folders.
OBJECT_FOLDERS: dict[str, str] = {
    "rule": "objects/rules/",
    "threat": "objects/threats/",
    "objective": "objects/objectives/",
}

#: The ATT&CK technique vocabulary, in the data root's ``vocabulary/`` folder.
ATTACK_VOCABULARY = "att&ck.vocab.toml"

#: How far into an object file its ``name`` and ``metadata.uuid`` are looked for.
HEADER_LINES = 200

#: ``--platform`` values, as :class:`opentide.cli.enums.DetectionPlatform` holds
#: them. A copy: importing that module loads the validation engine.
PLATFORMS = (
    "sentinel",
    "splunk",
    "crowdstrike",
    "defender_for_endpoint",
    "sentinel_one",
    "carbon_black_cloud",
    "harfanglab",
    "elastic",
)

#: ``--strategy`` values and what each deploys, as
#: ``opentide.models.deployment_enums.DEPLOYABLE_STRATEGIES`` holds them. A
#: copy: importing ``opentide.models`` loads pydantic and every model.
STRATEGIES: tuple[tuple[str, str], ...] = (
    ("PREVIEW", "Deployment from Pull/Merge Requests"),
    ("RELEASE", "Deployment from the default branch (also called trunk, or main branch)"),
)

_OBJECT_OPTIONS = frozenset({"--uuid", "--type", "--file"})

#: The options each command completes a value for, by command path. Completing
#: one of these answers from here, without importing the command's module.
#: ``test_completion.py`` checks it against what :func:`attach` gives the
#: loaded commands, so a new completed option fails a test until it is listed.
INDEXED_OPTIONS: dict[tuple[str, ...], frozenset[str]] = {
    ("validate",): _OBJECT_OPTIONS,
    ("validate", "query"): frozenset({"--uuid", "--file", "--platform", "--strategy"}),
    ("query",): frozenset({"--platform", "--file"}),
    ("info",): frozenset({"--platform", "--technique"}),
    ("deploy",): frozenset({"--platform", "--strategy"}),
    ("deploy", "metadata"): frozenset({"--platform"}),
    ("setup",): frozenset({"--platform"}),
    ("setup", "repo"): frozenset({"--platform"}),
    ("share",): _OBJECT_OPTIONS,
    ("share", "push"): _OBJECT_OPTIONS,
    ("share", "preview"): _OBJECT_OPTIONS,
    ("share", "status"): _OBJECT_OPTIONS,
    ("share", "retract"): _OBJECT_OPTIONS,
    # `opentide new rule` (#642): enabled platforms first, like every --platform.
    ("new", "rule"): frozenset({"--platform"}),
}

#: The shells Typer writes a completion script for.
SHELLS = ("bash", "zsh", "fish", "powershell", "pwsh")

#: What loads a freshly installed script into the running shell, and the alternative.
_RELOAD: dict[str, tuple[str, str]] = {
    "bash": ("source ~/.bashrc", "or restart your shell"),
    "zsh": ("source ~/.zshrc", "or restart your shell"),
    "fish": ("exec fish", "restart your shell"),
    "powershell": (". $PROFILE", "or restart your shell"),
    "pwsh": (". $PROFILE", "or restart your shell"),
}

#: A value and the help a shell shows beside it (``""`` for none).
Candidate = tuple[str, str]
Source = Callable[[Any, str], Iterable[Candidate]]

_TOP_KEY = re.compile(r"^([A-Za-z_][\w-]*)\s*:(.*)$")
_NESTED_UUID = re.compile(r"^\s+uuid\s*:(.*)$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
# YAML double-quoted escapes that stand for one character (``\x``, ``\u``, ``\U`` aside).
_YAML_ESCAPES = {
    "0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\v",
    "f": "\f", "r": "\r", "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\",
    "N": "\x85", "_": "\xa0", "L": "\u2028", "P": "\u2029",
}  # fmt: skip
_YAML_ESCAPE = re.compile(r"\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)", re.DOTALL)
# A character bash reads back unchanged without a backslash in front of it.
_BASH_PLAIN = re.compile(r"[\w./:@%+,=-]")
#: The variable Typer sets to ask for completions; ``complete_bash`` for bash.
COMPLETE_ENV = "_OPENTIDE_COMPLETE"
_PLATFORM_SECTION = re.compile(r"^\[platform\]\s*$", re.MULTILINE)
_ENABLED = re.compile(r"^enabled\s*=\s*true\s*$", re.MULTILINE | re.IGNORECASE)
# A ``[[keys]]`` entry of the vocabulary: ``id = "T1059.001"`` then ``name = "..."``.
_TECHNIQUE = re.compile(
    r'^id = "(T\d{4}(?:\.\d{3})?)"\s*\nname = ("(?:[^"\\\n]|\\.)*")', re.MULTILINE
)


@dataclass(frozen=True)
class ObjectEntry:
    """One object file, as completion sees it."""

    kind: str
    path: Path
    uuid: str | None
    name: str | None


# --------------------------------------------------------------------------- workspace


def workspace_root(ctx: Any = None) -> Path:
    """The workspace a command would use: ``--repo``, ``OPENTIDE_REPO_ROOT``, or the nearest one."""
    from opentide.core.root import find_workspace_root

    repo = _root_param(ctx, "repo") or os.environ.get("OPENTIDE_REPO_ROOT")
    return Path(repo) if repo else find_workspace_root()


def object_folders(root: Path) -> dict[str, Path]:
    """Each object kind's folder, from the workspace's ``paths.toml`` or the default."""
    folders = dict(OBJECT_FOLDERS)
    override = root / ".opentide" / "configurations" / "paths.toml"
    if override.is_file():
        try:
            configured = _load_toml(override).get("paths", {}).get("objects", {})
        except (OSError, ValueError):
            configured = {}
        if isinstance(configured, dict):
            for kind in folders:
                value = configured.get(kind)
                if isinstance(value, str) and value.strip():
                    folders[kind] = value
    return {kind: root / folder for kind, folder in folders.items()}


def iter_object_paths(
    root: Path, kinds: Sequence[str] = tuple(OBJECT_FOLDERS)
) -> Iterator[tuple[str, Path]]:
    """``(kind, path)`` for every object file of *kinds* under *root*, without reading it."""
    folders = object_folders(root)
    for kind in OBJECT_FOLDERS:
        if kind not in kinds or not folders[kind].is_dir():
            continue
        # Only files directly in the folder are objects (#584), as
        # ``opentide.registry.catalogue`` reads them; not imported, to keep
        # completion free of engine modules.
        paths = sorted(
            path
            for pattern in ("*.yaml", "*.yml")
            for path in folders[kind].glob(pattern)
            if not path.name.endswith((".debug.yaml", ".debug.yml"))
        )
        # A folder named like a YAML file is not an object.
        for path in paths:
            if path.is_file():
                yield kind, path


def iter_objects(root: Path, kinds: Sequence[str] = tuple(OBJECT_FOLDERS)) -> Iterator[ObjectEntry]:
    """Every object file of *kinds* under *root*, with the UUID and name from its first lines."""
    for kind, path in iter_object_paths(root, kinds):
        uuid, name = read_header(path)
        yield ObjectEntry(kind=kind, path=path, uuid=uuid, name=name)


def read_header(path: Path) -> tuple[str | None, str | None]:
    """``(uuid, name)`` from the top of an object file, without parsing the YAML.

    ``name`` is the top-level key; the UUID is ``metadata.uuid`` (or a
    top-level ``uuid``): a ``uuid`` key one level under ``metadata``, never a
    deeper one such as ``metadata.organisation.uuid``. Reading stops once both
    are found.
    """
    uuid: str | None = None
    name: str | None = None
    section: str | None = None
    # The indentation of metadata's own keys, taken from its first nested line.
    level: int | None = None
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            for number, line in enumerate(handle):
                if number >= HEADER_LINES or (uuid and name):
                    break
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                top = _TOP_KEY.match(line)
                if top is not None:
                    section, value = top.group(1), top.group(2)
                    level = None
                    if section == "name" and name is None:
                        name = _scalar(value)
                    elif section == "uuid" and uuid is None:
                        uuid = _scalar(value)
                    continue
                if section == "metadata" and uuid is None:
                    indent = len(line) - len(line.lstrip(" \t"))
                    if level is None:
                        level = indent
                    nested = _NESTED_UUID.match(line) if indent == level else None
                    if nested is not None:
                        uuid = _scalar(nested.group(1))
    except OSError:
        return None, None
    return uuid, name


def _scalar(raw: str) -> str | None:
    """A one-line YAML scalar: quotes and escapes decoded, a trailing ``# comment`` dropped."""
    value = raw.strip()
    if value[:1] == "'":
        value = _single_quoted(value)
    elif value[:1] == '"':
        value = _double_quoted(value)
    else:
        value = value.split(" #", 1)[0].strip()
    if value in {"", "|", ">", "|-", ">-"}:
        return None
    return value


def _single_quoted(value: str) -> str:
    """``'user''s'`` -> ``user's``: inside single quotes ``''`` is the only escape."""
    index = 1
    while index < len(value):
        if value[index] == "'":
            if value[index + 1 : index + 2] != "'":
                return value[1:index].replace("''", "'")
            index += 1
        index += 1
    return value[1:].replace("''", "'")


def _double_quoted(value: str) -> str:
    """``"a\\nb"`` -> ``a``, newline, ``b``: YAML escapes decoded up to the closing quote."""
    index = 1
    while index < len(value) and value[index] != '"':
        index += 2 if value[index] == "\\" else 1
    return _YAML_ESCAPE.sub(_unescape, value[1:index])


def _unescape(match: re.Match[str]) -> str:
    code = match.group(1)
    if code[0] in "xuU" and len(code) > 1:
        return chr(int(code[1:], 16))
    return _YAML_ESCAPES.get(code, match.group(0))


def _load_toml(path: Path) -> dict[str, Any]:
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        import tomli as tomllib

    with path.open("rb") as handle:
        return tomllib.load(handle)


def _root_param(ctx: Any, name: str) -> str | None:
    if ctx is None:
        return None
    value = ctx.find_root().params.get(name)
    return str(value) if value else None


def _selected_kinds(ctx: Any, kinds: Sequence[str]) -> list[str]:
    """*kinds*, narrowed to the ``--type`` values already on the command line."""
    chosen = (getattr(ctx, "params", None) or {}).get("object_type") or ()
    narrowed = [kind for kind in kinds if kind in chosen]
    return narrowed or list(kinds)


# --------------------------------------------------------------------------- sources


def object_uuids(kinds: Sequence[str] = tuple(OBJECT_FOLDERS)) -> Source:
    """``--uuid``: object UUIDs, the object's name and kind as help."""

    def source(ctx: Any, incomplete: str) -> Iterator[Candidate]:
        seen: set[str] = set()
        prefix = incomplete.lower()
        for entry in iter_objects(workspace_root(ctx), _selected_kinds(ctx, kinds)):
            uuid = entry.uuid
            # An unreadable or hand-mangled header is never offered as a UUID.
            if not uuid or not _UUID.match(uuid) or uuid in seen:
                continue
            if not uuid.lower().startswith(prefix):
                continue
            seen.add(uuid)
            yield uuid, f"{entry.name or entry.path.name} ({entry.kind})"

    return source


def object_files(kinds: Sequence[str] = tuple(OBJECT_FOLDERS)) -> Source:
    """``--file``: object files, relative to the current directory when inside it.

    A path outside the current directory is given relative to the workspace,
    which ``--file`` also accepts. When the typed text has no slash and no
    path starts with it, bare file names are matched instead, which
    ``--file`` accepts too. No match at all leaves the shell to complete
    file names itself. Paths are matched first, and only the matches' headers
    are read, for their names.
    """

    def source(ctx: Any, incomplete: str) -> list[Candidate]:
        # Resolved once: the object paths found under the root then need no resolving.
        root = workspace_root(ctx).resolve()
        cwd = Path.cwd().resolve()
        paths = [path for _, path in iter_object_paths(root, _selected_kinds(ctx, kinds))]
        found = [
            (shown, path)
            for path in paths
            if (shown := _shown_path(path, cwd, root)).startswith(incomplete)
        ]
        if not found and "/" not in incomplete and os.sep not in incomplete:
            found = [(path.name, path) for path in paths if path.name.startswith(incomplete)]
        return [(shown, read_header(path)[1] or "") for shown, path in found]

    return source


def _shown_path(path: Path, cwd: Path, root: Path) -> str:
    for base in (cwd, root):
        try:
            return path.relative_to(base).as_posix()
        except ValueError:
            continue
    return path.as_posix()


def object_types(ctx: Any, incomplete: str) -> list[Candidate]:
    """``--type``: ``rule``, ``threat``, ``objective``, each with its default folder."""
    return [
        (kind, folder) for kind, folder in OBJECT_FOLDERS.items() if kind.startswith(incomplete)
    ]


def techniques(ctx: Any, incomplete: str) -> list[Candidate]:
    """``--technique``: ATT&CK ids from the bundled vocabulary, with their titles."""
    data = _root_param(ctx, "data") or os.environ.get("OPENTIDE_DATA_ROOT")
    root = Path(data) if data else files("opentide.data")
    try:
        text = (root / "vocabulary" / ATTACK_VOCABULARY).read_text(encoding="utf-8")
    except OSError:
        return []
    prefix = incomplete.upper()
    found: dict[str, str] = {}
    for match in _TECHNIQUE.finditer(text):
        technique = match.group(1)
        if technique.startswith(prefix) and technique not in found:
            found[technique] = _toml_string(match.group(2))
    return sorted(found.items(), key=lambda item: _technique_key(item[0]))


def _toml_string(quoted: str) -> str:
    try:
        return str(json.loads(quoted))
    except ValueError:
        return quoted.strip('"')


def _technique_key(technique: str) -> tuple[int, int]:
    main, _, sub = technique[1:].partition(".")
    return int(main), int(sub or -1)


def platforms(ctx: Any, incomplete: str, *, choices: Sequence[str] = ()) -> list[Candidate]:
    """``--platform``: the platforms enabled in the workspace first, then the others."""
    names = list(choices) or list(PLATFORMS)
    found = enabled_platforms(workspace_root(ctx))
    enabled = [name for name in found if name in names]
    ordered = [*enabled, *(name for name in names if name not in enabled)]
    prefix = incomplete.lower()
    return [
        (name, "enabled" if name in enabled else "")
        for name in ordered
        if name.lower().startswith(prefix)
    ]


def enabled_platforms(root: Path) -> list[str]:
    """Platforms whose ``.opentide/configurations/platforms/<name>.toml`` says ``enabled = true``.

    The test :func:`opentide.ci.discovery.discover_enabled_platforms` makes,
    without importing the CI renderers that its package loads.
    """
    folder = root / ".opentide" / "configurations" / "platforms"
    enabled: list[str] = []
    for path in sorted(folder.glob("*.toml")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if _PLATFORM_SECTION.search(text) and _ENABLED.search(text):
            enabled.append(path.stem)
    return enabled


def strategies(ctx: Any, incomplete: str) -> list[Candidate]:
    """``--strategy``: the strategies a run deploys, ``PREVIEW`` and ``RELEASE``."""
    prefix = incomplete.upper()
    return [(name, meaning) for name, meaning in STRATEGIES if name.startswith(prefix)]


def diagnostic_codes(ctx: Any, incomplete: str) -> list[Candidate]:
    """``explain <code>``: the codes with a page in ``opentide/data/diagnostics/``.

    Empty when the package has no such folder.
    """
    folder = files("opentide.data") / "diagnostics"
    if not folder.is_dir():
        return []
    found: list[Candidate] = []
    for page in folder.iterdir():
        code, suffix = os.path.splitext(page.name)
        if suffix != ".md" or not code.startswith(incomplete):
            continue
        try:
            summary = _page_summary(page.read_text(encoding="utf-8"))
        except OSError:
            summary = ""
        found.append((code, summary))
    return sorted(found)


def _page_summary(markdown: str) -> str:
    """The first paragraph that is not a heading: what the code means."""
    for block in markdown.split("\n\n"):
        text = block.strip()
        if text and not text.startswith("#"):
            return " ".join(text.split())
    return ""


# --------------------------------------------------------------------------- wiring


def _source_for(path: tuple[str, ...], param: Any) -> Source | None:
    """The completion source for *param* of the command at *path*, if it has one."""
    if getattr(param, "param_type_name", "") == "argument":
        if path == ("explain",) and param.name == "code":
            return diagnostic_codes
        return None
    names = {*getattr(param, "opts", ()), *getattr(param, "secondary_opts", ())}
    choices = [str(getattr(choice, "value", choice)) for choice in _choices(param)]
    return _option_source(path, names, choices)


def _option_source(
    path: tuple[str, ...], names: set[str], choices: Sequence[str] = ()
) -> Source | None:
    """The source for an option called *names* of the command at *path*, if it has one."""
    # validate query --uuid / --file select rules only.
    kinds = ("rule",) if path == ("validate", "query") else tuple(OBJECT_FOLDERS)
    if "--uuid" in names:
        return object_uuids(kinds)
    if "--file" in names:
        return object_files(kinds)
    if "--type" in names:
        return object_types
    if "--technique" in names:
        return techniques
    if "--strategy" in names:
        return strategies
    if "--platform" in names:
        return lambda ctx, incomplete: platforms(ctx, incomplete, choices=choices)
    return None


def _choices(param: Any) -> Sequence[Any]:
    return tuple(getattr(getattr(param, "type", None), "choices", None) or ())


def _shell_complete(source: Source) -> Callable[[Any, Any, str], list[Any]]:
    """Wrap *source* as a Click ``shell_complete`` callback that never raises."""

    def complete(ctx: Any, param: Any, incomplete: str) -> list[Any]:
        from typer._click.shell_completion import CompletionItem

        bash = os.environ.get(COMPLETE_ENV) == "complete_bash"
        try:
            return [
                CompletionItem(bash_word(value) if bash else value, help=help_text or None)
                for value, help_text in source(ctx, incomplete or "")
                # A line break cannot be escaped: bash would split the candidate.
                if not (bash and "\n" in value)
            ]
        except Exception:
            return []

    complete.__doc__ = source.__doc__
    return complete


def bash_word(value: str) -> str:
    """*value* with a backslash before each space and shell metacharacter.

    Typer's bash script inserts candidates as they are, so a path with a
    space would otherwise reach the command as several arguments. zsh and
    fish quote candidates themselves.
    """
    return "".join(char if _BASH_PLAIN.fullmatch(char) else f"\\{char}" for char in value)


def attach(command: Any, path: str) -> Any:
    """Give the parameters of *command* and its subcommands their completion, once.

    A parameter that already has its own completion keeps it.
    """
    words = tuple(path.split())
    for param in getattr(command, "params", ()):
        if getattr(param, "_custom_shell_complete", None) is not None:
            continue
        source = _source_for(words, param)
        if source is not None:
            param._custom_shell_complete = _shell_complete(source)
    for name, child in (getattr(command, "commands", None) or {}).items():
        attach(child, f"{path} {name}".strip())
    return command


# --------------------------------------------------------------------------- index


def indexed_source(
    group: Any, args: Sequence[str], incomplete: str
) -> tuple[Source, Any, str] | None:
    """The source, context and typed text for completing *incomplete* after *args*.

    Answered from :data:`INDEXED_OPTIONS` alone: *args* must be the root's
    options, a command path the index holds, and then only that command's
    indexed options with their values (and the hoisted root flags), ending
    with the option being completed. ``None`` for anything else, which Click
    then completes by loading the command: an option name, an unindexed
    option, a positional argument, or ``--``.

    The context carries what the sources read: the root's ``--repo`` and
    ``--data``, and the ``--type`` values already typed.
    """
    if incomplete.startswith("-"):
        name, equals, value = incomplete.partition("=")
        if not equals:
            return None
        args, incomplete = [*args, name], value
    if "--" in args:
        return None
    from opentide.cli.lazy import HOISTED_FLAGS, split_root_options

    root, words = split_root_options(group, args)
    path = tuple(itertools.takewhile(lambda word: not word.startswith("-"), words))
    options = INDEXED_OPTIONS.get(path)
    rest = words[len(path) :]
    if options is None or not rest or rest[-1] not in options:
        return None
    typed: dict[str, list[str]] = {}
    index = 0
    while index < len(rest) - 1:
        token = rest[index]
        index += 1
        if token in HOISTED_FLAGS:
            continue
        name, equals, value = token.partition("=")
        if name not in options:
            return None
        if not equals:
            if index >= len(rest) - 1:
                return None
            value = rest[index]
            index += 1
        typed.setdefault(name, []).append(value)
    source = _option_source(path, {rest[-1]}, PLATFORMS)
    if source is None:  # pragma: no cover -- every indexed option has a source (tested)
        return None
    ctx = SimpleNamespace(
        params={"object_type": tuple(typed.get("--type", ()))},
        find_root=lambda: SimpleNamespace(params=root),
    )
    return source, ctx, incomplete


def complete_from_index(group: Any, prog_name: str, complete_var: str) -> None:
    """Answer a shell's request for an indexed option's value, and exit.

    Returns without printing when :func:`indexed_source` cannot answer, so
    Click completes as usual. The answer goes through the shell's own
    completion class, so it is formatted exactly as Click would format it.
    """
    action, _, shell = os.environ.get(complete_var, "").partition("_")
    if action != "complete":
        return
    from typer import _click
    from typer._click.shell_completion import get_completion_class
    from typer._completion_classes import completion_init

    completion_init()
    shell_class = get_completion_class(shell)
    if shell_class is None:
        return
    shell_completion = shell_class(group, {}, prog_name, complete_var)
    args, incomplete = shell_completion.get_completion_args()
    found = indexed_source(group, args, incomplete)
    if found is None:
        return
    source, ctx, incomplete = found
    items = _shell_complete(source)(ctx, None, incomplete)
    shell_completion.get_completions = lambda args, incomplete: items  # ty: ignore[invalid-assignment]
    _click.echo(shell_completion.complete())
    sys.exit(0)


# --------------------------------------------------------------------------- install and show


def install_completion(ctx: Any, param: Any, value: Any) -> Any:
    """``--install-completion [SHELL]``: write the script, then say where and how to load it."""
    if not value or ctx.resilient_parsing:
        return value
    from typer._completion_shared import install

    from opentide.cli.context import CliContext
    from opentide.cli.lazy import ROOT_ARGS_KEY
    from opentide.cli.output import CommandResult, emit_result
    from opentide.cli.ui.contract import NextAction
    from opentide.cli.ui.mode import OutputMode, get_mode
    from opentide.core.logging import LoggingConfig, init_logging

    shell = _shell_for(ctx, param, value)
    prog_name = ctx.find_root().info_name
    shell, path = install(
        shell=shell, prog_name=prog_name, complete_var=complete_var_for(prog_name)
    )
    command, reason = _RELOAD.get(shell, ("", "restart your shell"))
    flags = ctx.meta.get(ROOT_ARGS_KEY, ())
    cli = CliContext(
        repo=Path.cwd(),
        json_output=get_mode() is OutputMode.JSON,
        quiet="--quiet" in flags,
        no_color="--no-color" in flags,
    )
    # The root callback, which configures the consoles, has not run: this flag is eager.
    init_logging(LoggingConfig.from_cli_context(cli), force=True)
    emit_result(
        cli,
        CommandResult(
            message=f"Installed {shell} completion in {person_path(path)}",
            data={"shell": shell, "path": str(path)},
            next_actions=(NextAction(command or "restart your shell", reason if command else ""),),
        ),
    )
    ctx.exit(0)


def show_completion(ctx: Any, param: Any, value: Any) -> Any:
    """``--show-completion [SHELL]``: print the script for SHELL, or for the current shell."""
    if not value or ctx.resilient_parsing:
        return value
    from typer import _click
    from typer._completion_shared import get_completion_script

    shell = _shell_for(ctx, param, value)
    prog_name = ctx.find_root().info_name
    _click.echo(
        get_completion_script(
            prog_name=prog_name, complete_var=complete_var_for(prog_name), shell=shell
        )
    )
    ctx.exit(0)


def _shell_for(ctx: Any, param: Any, value: Any) -> str:
    """The shell named after the flag (``--show-completion zsh``), else the one running.

    A word that is not a shell, or no word when the running shell cannot be
    told, is a usage error that names the form to use. Under
    ``_TYPER_COMPLETE_TEST_DISABLE_SHELL_DETECTION`` Typer makes both options
    take the shell as their value, already checked against its shells.
    """
    if isinstance(value, str):
        return value
    from typer import _click

    from opentide.cli.lazy import COMMAND_WORDS_KEY

    option = param.opts[0]
    form = f"opentide {option} [{'|'.join(SHELLS)}]"
    words = ctx.meta.get(COMMAND_WORDS_KEY, ())
    if words:
        if len(words) == 1 and words[0] in SHELLS:
            return words[0]
        raise _click.exceptions.BadParameter(
            f"{' '.join(words)!r} is not a supported shell. Use: {form}",
            ctx=ctx,
            param=param,
        )
    from typer._completion_shared import _get_shell_name

    detected = _get_shell_name()
    if detected not in SHELLS:
        raise _click.exceptions.UsageError(
            f"Could not tell which shell this is. Name it: {form}", ctx=ctx
        )
    return str(detected)


def complete_var_for(prog_name: str) -> str:
    """The variable Typer's scripts set to ask *prog_name* for completions."""
    return f"_{prog_name}_COMPLETE".replace("-", "_").upper()


def person_path(path: Path) -> str:
    """*path* relative to the current directory when inside it, else to ``~``, else absolute."""
    from opentide.cli.ui.paths import display_path

    shown = display_path(path)
    if not Path(shown).is_absolute():
        return shown
    try:
        return "~/" + path.resolve().relative_to(Path.home().resolve()).as_posix()
    except (ValueError, RuntimeError, OSError):
        return shown
