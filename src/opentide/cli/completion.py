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
every ``share`` subcommand. ``tests/test_cli/test_completion.py`` covers each
source and checks that completing a value imports nothing new.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
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

#: A value and the help a shell shows beside it (``""`` for none).
Candidate = tuple[str, str]
Source = Callable[[Any, str], Iterable[Candidate]]

_TOP_KEY = re.compile(r"^([A-Za-z_][\w-]*)\s*:(.*)$")
_NESTED_UUID = re.compile(r"^\s+uuid\s*:(.*)$")
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


def iter_objects(root: Path, kinds: Sequence[str] = tuple(OBJECT_FOLDERS)) -> Iterator[ObjectEntry]:
    """Every object file of *kinds* under *root*, with the UUID and name from its first lines."""
    folders = object_folders(root)
    for kind in OBJECT_FOLDERS:
        if kind not in kinds or not folders[kind].is_dir():
            continue
        # A folder named like a YAML file reads as an empty header, not a crash.
        paths = sorted(
            path for pattern in ("*.yaml", "*.yml") for path in folders[kind].rglob(pattern)
        )
        for path in paths:
            uuid, name = read_header(path)
            yield ObjectEntry(kind=kind, path=path, uuid=uuid, name=name)


def read_header(path: Path) -> tuple[str | None, str | None]:
    """``(uuid, name)`` from the top of an object file, without parsing the YAML.

    ``name`` is the top-level key; the UUID is ``metadata.uuid`` (or a
    top-level ``uuid``). Reading stops once both are found.
    """
    uuid: str | None = None
    name: str | None = None
    section: str | None = None
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
                    if section == "name" and name is None:
                        name = _scalar(value)
                    elif section == "uuid" and uuid is None:
                        uuid = _scalar(value)
                    continue
                if section == "metadata" and uuid is None:
                    nested = _NESTED_UUID.match(line)
                    if nested is not None:
                        uuid = _scalar(nested.group(1))
    except OSError:
        return None, None
    return uuid, name


def _scalar(raw: str) -> str | None:
    """A one-line YAML scalar: quotes removed, a trailing ``# comment`` dropped."""
    value = raw.strip()
    if value[:1] in {'"', "'"}:
        quote = value[0]
        end = value.find(quote, 1)
        while quote == '"' and end > 0 and value[end - 1] == "\\":
            end = value.find(quote, end + 1)
        value = value[1:end] if end > 0 else value[1:]
    else:
        value = value.split(" #", 1)[0].strip()
    if value in {"", "|", ">", "|-", ">-"}:
        return None
    return value


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
            if not entry.uuid or entry.uuid in seen or not entry.uuid.lower().startswith(prefix):
                continue
            seen.add(entry.uuid)
            yield entry.uuid, f"{entry.name or entry.path.name} ({entry.kind})"

    return source


def object_files(kinds: Sequence[str] = tuple(OBJECT_FOLDERS)) -> Source:
    """``--file``: object files, relative to the current directory when inside it.

    A path outside the current directory is given relative to the workspace,
    which ``--file`` also accepts. When the typed text has no slash and no
    path starts with it, bare file names are matched instead, which
    ``--file`` accepts too. No match at all leaves the shell to complete
    file names itself.
    """

    def source(ctx: Any, incomplete: str) -> list[Candidate]:
        # Resolved once: the object paths found under the root then need no resolving.
        root = workspace_root(ctx).resolve()
        cwd = Path.cwd().resolve()
        entries = list(iter_objects(root, _selected_kinds(ctx, kinds)))
        paths = [(_shown_path(entry.path, cwd, root), entry) for entry in entries]
        found = [
            (shown, entry.name or "") for shown, entry in paths if shown.startswith(incomplete)
        ]
        if found or "/" in incomplete or os.sep in incomplete:
            return found
        return [
            (entry.path.name, entry.name or "")
            for entry in entries
            if entry.path.name.startswith(incomplete)
        ]

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
    names = list(choices) or [platform.value for platform in _detection_platforms()]
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


def _detection_platforms() -> Any:
    from opentide.cli.enums import DetectionPlatform

    return DetectionPlatform


def strategies(ctx: Any, incomplete: str) -> list[Candidate]:
    """``--strategy``: the strategies a run deploys, ``PREVIEW`` and ``RELEASE``."""
    from opentide.models.deployment_enums import DEPLOYABLE_STRATEGIES

    prefix = incomplete.upper()
    return [
        (strategy.name, str(strategy.value))
        for strategy in DEPLOYABLE_STRATEGIES
        if strategy.name.startswith(prefix)
    ]


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
        choices = [str(getattr(choice, "value", choice)) for choice in _choices(param)]
        return lambda ctx, incomplete: platforms(ctx, incomplete, choices=choices)
    return None


def _choices(param: Any) -> Sequence[Any]:
    return tuple(getattr(getattr(param, "type", None), "choices", None) or ())


def _shell_complete(source: Source) -> Callable[[Any, Any, str], list[Any]]:
    """Wrap *source* as a Click ``shell_complete`` callback that never raises."""

    def complete(ctx: Any, param: Any, incomplete: str) -> list[Any]:
        from typer._click.shell_completion import CompletionItem

        try:
            return [
                CompletionItem(value, help=help_text or None)
                for value, help_text in source(ctx, incomplete or "")
            ]
        except Exception:  # noqa: BLE001 -- a traceback in the shell helps nobody
            return []

    complete.__doc__ = source.__doc__
    return complete


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
