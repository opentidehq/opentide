"""Scaffolding for ``opentide new``: one object from the generated template.

The template (``.opentide/templates/<family>.<M>.<m>.template.yaml``) is the
starting text, so the comments that list every optional key stay in the new
file. Required keys are filled in place: the name, a fresh UUID v4, today's
date, the git author, the catalogue's organisation, and for every other
required value the first value its generated JSON schema allows (or ``...`` for
free text). Those stand-ins are returned as ``placeholders`` so neither a
person nor an agent mistakes them for decisions.

The result validates as soon as it is written; ``tests/test_cli/e2e`` checks
every family and every platform block.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import shutil
import subprocess
import types
import uuid as uuid_lib
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Literal, Union, get_args, get_origin

import yaml
from pydantic import BaseModel

from opentide.cli.ui.contract import NextAction
from opentide.core.io import parse_yaml
from opentide.documentation.markdown.links import slugify

#: The object families ``new`` scaffolds, in catalogue order.
FAMILIES = ("threat", "objective", "rule")

#: ``failure.code`` when the target file already exists. ``new`` never overwrites.
PATH_EXISTS = "path_exists"
#: ``failure.code`` when ``--objective`` or ``--threat`` names no object in the catalogue.
REFERENCE_NOT_FOUND = "reference_not_found"
#: ``failure.code`` when the template or schema is still missing after generating it.
TEMPLATE_MISSING = "template_missing"

#: Defaults that are a choice, not a stand-in: they are not reported as placeholders.
#: TLP starts at ``amber`` so a new object is never cleared for sharing by accident.
_DEFAULTS: dict[str, Any] = {"tlp": "amber", "version": 1}
#: What an empty free-text value becomes; a valid string nobody will mistake for content.
_TEXT_PLACEHOLDER = "..."

_LINE = re.compile(r"^(?P<indent> *)(?P<hash>#?)(?P<dash>- ?)?(?P<rest>.*)$")
_KEY = re.compile(r"^(?P<key>[A-Za-z_][\w.\-]*):(?:\s(?P<value>.*))?$")
_PLAIN_SCALAR = re.compile(r"^[A-Za-z0-9_./:+-][A-Za-z0-9_./:+ -]*$")
_YAML_RESERVED = frozenset({"true", "false", "null", "yes", "no", "on", "off", "y", "n", "~"})
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class NewError(Exception):
    """A scaffold that cannot be written. ``code`` is the ``failure.code``."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        argument: str | None = None,
        exit_code: int = 1,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.argument = argument
        self.exit_code = exit_code


@dataclass(frozen=True)
class NewOptions:
    """What to scaffold. ``platforms`` applies to rules, ``threats`` to objectives."""

    family: str
    name: str
    platforms: tuple[str, ...] = ()
    objective: str | None = None
    threats: tuple[str, ...] = ()
    path: Path | None = None
    today: dt.date | None = None


@dataclass(frozen=True)
class Organisation:
    uuid: str
    name: str


@dataclass(frozen=True)
class WorkspaceArtifacts:
    """Where the family's template, schema and objects live in a workspace."""

    template: Path
    schema: Path
    objects: Path


# --------------------------------------------------------------------------- inputs


def workspace_artifacts(workspace: Path, family: str) -> WorkspaceArtifacts:
    """Resolve the configured template, schema and object folder for *family*."""
    from opentide.core.files import resolve_configurations
    from opentide.registry.paths import resolve_workspace_paths

    configs = resolve_configurations(workspace)
    paths = resolve_workspace_paths(configs, workspace=workspace)
    artifacts = paths["_artifacts"]
    template_name = artifacts["templates"].get(family) or f"{family}.1.0.template.yaml"
    schema_name = artifacts["schemas"].get(family) or f"{family}.1.0.schema.json"
    objects = paths.get(family) or workspace / "objects" / f"{family}s"
    return WorkspaceArtifacts(
        template=Path(paths["templates"]) / template_name,
        schema=Path(paths["json_schemas"]) / schema_name,
        objects=Path(objects),
    )


def git_author(workspace: Path) -> str | None:
    """``git config user.name`` as seen from *workspace*, or ``None``."""
    git = shutil.which("git")
    if git is None:
        return None
    try:
        done = subprocess.run(
            [git, "config", "user.name"],
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    name = done.stdout.strip()
    return name or None


def _object_files(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    return sorted(
        path for path in root.rglob("*") if path.is_file() and path.suffix in (".yaml", ".yml")
    )


def _load(path: Path) -> dict[str, Any]:
    try:
        data = parse_yaml(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _metadata(data: Mapping[str, Any]) -> Mapping[str, Any]:
    metadata = data.get("metadata")
    return metadata if isinstance(metadata, Mapping) else {}


def catalogue_organisation(objects_root: Path) -> Organisation | None:
    """The organisation most objects in the catalogue carry, or ``None``.

    The workspace configuration has no organisation key; the catalogue is
    where a team's organisation is recorded. Ties go to the first seen in
    path order, so the answer is stable.
    """
    seen: Counter[Organisation] = Counter()
    for path in _object_files(objects_root):
        organisation = _metadata(_load(path)).get("organisation")
        if not isinstance(organisation, Mapping):
            continue
        org_uuid, org_name = organisation.get("uuid"), organisation.get("name")
        if isinstance(org_uuid, str) and isinstance(org_name, str) and org_uuid and org_name:
            seen[Organisation(org_uuid.strip(), org_name.strip())] += 1
    if not seen:
        return None
    return seen.most_common(1)[0][0]


def inert_status(workspace: Path) -> str | None:
    """The first configured deployment status whose strategy is ``INERT`` (``DESIGN``).

    A new platform block starts there, so it deploys nothing until someone
    moves it on.
    """
    from opentide.core.files import resolve_configurations

    statuses = resolve_configurations(workspace).get("deployment", {}).get("statuses")
    if not isinstance(statuses, list):
        return None
    for status in statuses:
        if isinstance(status, Mapping) and str(status.get("strategy", "")).upper() == "INERT":
            name = status.get("name")
            if isinstance(name, str) and name:
                return name
    return None


def catalogue_uuids(folder: Path) -> set[str]:
    """``metadata.uuid`` of every object under *folder*, lower-cased."""
    uuids: set[str] = set()
    for path in _object_files(folder):
        value = _metadata(_load(path)).get("uuid")
        if isinstance(value, str):
            uuids.add(value.strip().lower())
    return uuids


def target_path(objects: Path, name: str, object_uuid: str, path: Path | None) -> Path:
    """Where the new object goes, named the way ``opentide lint`` expects.

    ``slugify(name)``; when that stem is taken in the folder, ``-{uuid[:8]}`` is
    appended, as ``lint --fix`` does on a collision.
    """
    folder = objects
    if path is not None:
        if path.is_dir() or str(path).endswith(("/", "\\")):
            folder = path
        else:
            return path
    stem = slugify(name)
    taken = any((folder / f"{stem}{suffix}").exists() for suffix in (".yaml", ".yml"))
    if taken:
        stem = f"{stem}-{object_uuid[:8]}"
    return folder / f"{stem}.yaml"


# --------------------------------------------------------------------------- model walk


@dataclass(frozen=True)
class _FieldShape:
    """What a model field holds, with ``Optional`` and ``Annotated`` unwrapped."""

    kind: Literal["scalar", "list", "model"]
    model: type[BaseModel] | None = None
    item_model: type[BaseModel] | None = None
    choices: tuple[Any, ...] = ()
    is_bool: bool = False
    is_int: bool = False


def _unwrap(annotation: Any) -> Any:
    while True:
        origin = get_origin(annotation)
        if origin is Annotated:
            annotation = get_args(annotation)[0]
            continue
        if origin in (Union, types.UnionType):
            members = [arg for arg in get_args(annotation) if arg is not type(None)]
            if len(members) == 1:
                annotation = members[0]
                continue
        return annotation


def _model_class(annotation: Any) -> type[BaseModel] | None:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation
    return None


def _shape(annotation: Any) -> _FieldShape:
    annotation = _unwrap(annotation)
    origin = get_origin(annotation)
    if origin in (list, tuple, set, Sequence):
        args = get_args(annotation)
        item = _unwrap(args[0]) if args else str
        return _FieldShape("list", item_model=_model_class(item))
    if origin is Literal:
        return _FieldShape("scalar", choices=get_args(annotation))
    model = _model_class(annotation)
    if model is not None:
        return _FieldShape("model", model=model)
    return _FieldShape("scalar", is_bool=annotation is bool, is_int=annotation is int)


Path_ = tuple[str, ...]


def _field_key(name: str, info: Any) -> str:
    return str(info.alias or name)


def collect_fields(
    model: type[BaseModel],
    *,
    wanted: Iterable[Path_] = (),
    overrides: Mapping[Path_, type[BaseModel]] | None = None,
    prefix: Path_ = (),
) -> dict[Path_, _FieldShape]:
    """Every required field path of *model*, plus the *wanted* optional ones.

    A list of models contributes its items' fields under the list's own path
    (list indexes are not part of a path). *overrides* swaps in the model for
    a path (a rule's platform block, whose type the union does not name).
    """
    wanted = tuple(wanted)
    overrides = overrides or {}
    fields: dict[Path_, _FieldShape] = {}
    for name, info in model.model_fields.items():
        path = (*prefix, _field_key(name, info))
        is_wanted = any(item[: len(path)] == path for item in wanted)
        if not info.is_required() and not is_wanted:
            continue
        shape = _shape(info.annotation)
        if path in overrides:
            shape = _FieldShape("model", model=overrides[path])
        fields[path] = shape
        child = shape.model or shape.item_model
        if child is not None:
            fields.update(collect_fields(child, wanted=wanted, overrides=overrides, prefix=path))
    return fields


# --------------------------------------------------------------------------- schema lookup


def _resolve(node: Any, defs: Mapping[str, Any]) -> list[dict[str, Any]]:
    """*node* and every branch it composes (``$ref``, ``anyOf``, ``oneOf``, ``allOf``)."""
    found: list[dict[str, Any]] = []
    pending = [node]
    while pending:
        current = pending.pop(0)
        if not isinstance(current, dict):
            continue
        found.append(current)
        ref = current.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/$defs/"):
            pending.append(defs.get(ref.removeprefix("#/$defs/")))
        for keyword in ("anyOf", "oneOf", "allOf"):
            branches = current.get(keyword)
            if isinstance(branches, list):
                pending.extend(branches)
    return found


def schema_choices(schema: Mapping[str, Any], path: Path_) -> list[Any]:
    """The ``enum`` the generated JSON schema gives the field at *path*, items included."""
    defs = schema.get("$defs") if isinstance(schema.get("$defs"), dict) else {}
    nodes = _resolve(schema, defs)  # ty: ignore[invalid-argument-type]
    for key in path:
        children: list[dict[str, Any]] = []
        for node in nodes:
            for candidate in [node, *_resolve(node.get("items"), defs)]:  # ty: ignore[invalid-argument-type]
                properties = candidate.get("properties")
                if isinstance(properties, dict) and key in properties:
                    children.extend(_resolve(properties[key], defs))  # ty: ignore[invalid-argument-type]
        nodes = children
        if not nodes:
            return []
    for node in nodes:
        for candidate in [node, *_resolve(node.get("items"), defs)]:  # ty: ignore[invalid-argument-type]
            values = candidate.get("enum")
            if isinstance(values, list) and values:
                return values
    return []


# --------------------------------------------------------------------------- template text


@dataclass
class _Line:
    index: int
    indent: int
    commented: bool
    #: ``key`` for ``key: value``, ``item`` for a bare ``- value``, ``text`` otherwise.
    role: Literal["key", "item", "text"]
    path: Path_
    value: str = ""
    #: Column of the key or item text, after the ``#`` and the dash.
    column: int = 0


def index_template(lines: Sequence[str]) -> list[_Line]:
    """Give each non-blank template line its YAML path, commented or not.

    Template comments hug the key (``  #author:``), so a commented line has
    the indentation it would have uncommented.
    """
    entries: list[_Line] = []
    stack: list[tuple[int, str]] = []
    for index, raw in enumerate(lines):
        if not raw.strip():
            continue
        match = _LINE.match(raw)
        if match is None:  # pragma: no cover - the pattern matches any line
            continue
        indent = len(match["indent"])
        commented = bool(match["hash"])
        dash = match["dash"]
        rest = match["rest"]
        column = indent + len(match["hash"]) + len(dash or "")
        key = _KEY.match(rest)
        if key is not None:
            key_indent = indent + 2 if dash else indent
            while stack and stack[-1][0] >= key_indent:
                stack.pop()
            path = (*(name for _, name in stack), key["key"])
            stack.append((key_indent, key["key"]))
            entries.append(
                _Line(index, indent, commented, "key", path, (key["value"] or "").strip(), column)
            )
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()
        path = tuple(name for _, name in stack)
        role: Literal["item", "text"] = "item" if dash is not None else "text"
        entries.append(_Line(index, indent, commented, role, path, rest.strip(), column))
    return entries


def _scalar(value: Any) -> str:
    """*value* as a YAML scalar on one line."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dt.date):
        return value.isoformat()
    text = str(value)
    if (
        _PLAIN_SCALAR.match(text)
        and text.lower() not in _YAML_RESERVED
        and not text.endswith(" ")
        and not text.startswith(("- ", "-"))
    ):
        try:
            if parse_yaml(f"k: {text}") == {"k": text}:
                return text
        except yaml.YAMLError:
            pass
    return json.dumps(text, ensure_ascii=False)


@dataclass
class ScaffoldResult:
    text: str
    placeholders: list[str] = field(default_factory=list)


def fill_template(
    template: str,
    fields: Mapping[Path_, _FieldShape],
    *,
    values: Mapping[Path_, Any],
    schema: Mapping[str, Any],
    make_uuid: Any = None,
) -> ScaffoldResult:
    """Uncomment the keys in *fields*, fill their values, keep every other line.

    *values* are the known answers (name, UUID, dates, author, references). A
    required field with no answer and no template value gets a placeholder,
    reported by its dotted path.
    """
    make_uuid = make_uuid or (lambda: str(uuid_lib.uuid4()))
    lines = template.splitlines()
    entries = index_template(lines)
    live_keys = {entry.path for entry in entries if entry.role == "key"}
    placeholders: list[str] = []
    replacements: dict[int, str] = {}

    def live(entry: _Line) -> bool:
        if entry.role == "key":
            return entry.path in fields
        return entry.path in fields and entry.path in live_keys

    # Uncomment the keys this object needs, with their items and block text.
    for entry in entries:
        if entry.commented and live(entry):
            raw = lines[entry.index]
            lines[entry.index] = raw[: entry.indent] + raw[entry.indent + 1 :]
            entry.commented = False
            entry.column -= 1

    def set_value(entry: _Line, value: Any) -> None:
        raw = lines[entry.index]
        head = raw[: entry.column]
        if entry.role == "key":
            replacements[entry.index] = f"{head}{entry.path[-1]}: {_scalar(value)}"
        else:
            replacements[entry.index] = f"{head}{_scalar(value)}"

    def items_of(entry: _Line) -> list[_Line]:
        found: list[_Line] = []
        for other in entries:
            if other.index <= entry.index:
                continue
            if other.indent <= entry.indent and not (
                other.role == "item" and other.path == entry.path
            ):
                break
            if other.role == "item" and other.path == entry.path and not other.commented:
                found.append(other)
        return found

    def children(entry: _Line) -> list[_Line]:
        found: list[_Line] = []
        for other in entries:
            if other.index <= entry.index:
                continue
            if other.indent <= entry.indent:
                break
            if other.role == "key" and other.path[:-1] == entry.path:
                found.append(other)
        return found

    def choose(path: Path_, shape: _FieldShape) -> tuple[Any, bool]:
        leaf = path[-1]
        if leaf in _DEFAULTS:
            choices = schema_choices(schema, path)
            default = _DEFAULTS[leaf]
            if not choices or default in choices:
                return default, False
            return choices[0], True
        if leaf == "uuid":
            return make_uuid(), False
        if shape.choices:
            return shape.choices[0], True
        if shape.is_bool:
            return False, True
        if shape.is_int:
            return 1, True
        choices = schema_choices(schema, path)
        if choices:
            return choices[0], True
        return _TEXT_PLACEHOLDER, True

    for entry in entries:
        if entry.role != "key" or entry.commented or entry.path not in fields:
            continue
        shape = fields[entry.path]
        dotted = ".".join(entry.path)
        given = values.get(entry.path)
        if shape.kind == "model":
            if entry.value or any(path[:-1] == entry.path for path in fields):
                continue
            # A required block whose keys are all optional: keep the ones the
            # template shows with a value (their defaults), else write {}.
            defaults = [child for child in children(entry) if child.value and child.value != "|"]
            for child in defaults:
                raw = lines[child.index]
                if child.commented:
                    lines[child.index] = raw[: child.indent] + raw[child.indent + 1 :]
                    child.commented = False
            if not defaults:
                replacements[entry.index] = f"{lines[entry.index].rstrip()} {{}}"
            continue
        if shape.kind == "list":
            if shape.item_model is not None:
                continue
            items = items_of(entry)
            if given is not None:
                answers = list(given) if isinstance(given, (list, tuple)) else [given]
            else:
                if items and items[0].value:
                    continue
                answer, placeholder = choose(entry.path, shape)
                answers = [answer]
                if placeholder:
                    placeholders.append(dotted)
            indent = " " * (entry.indent + 2)
            rendered = "\n".join(f"{indent}- {_scalar(answer)}" for answer in answers)
            if items:
                replacements[items[0].index] = rendered
                for extra in items[1:]:
                    replacements[extra.index] = ""
            else:
                replacements[entry.index] = f"{lines[entry.index].rstrip()}\n{rendered}"
            continue
        if given is not None:
            set_value(entry, given)
            continue
        if entry.value == "|":
            text = [
                other
                for other in entries
                if other.role == "text" and other.path == entry.path and other.index > entry.index
            ]
            if all(other.value == _TEXT_PLACEHOLDER for other in text):
                placeholders.append(dotted)
            continue
        if entry.value and entry.path[-1] != "uuid":
            continue
        answer, placeholder = choose(entry.path, shape)
        set_value(entry, answer)
        if placeholder:
            placeholders.append(dotted)

    output: list[str] = []
    for index, raw in enumerate(lines):
        if index in replacements:
            if replacements[index]:
                output.append(replacements[index])
            continue
        output.append(raw)
    return ScaffoldResult("\n".join(output) + "\n", placeholders)


# --------------------------------------------------------------------------- command


def template_schema_id(template: str, family: str) -> str:
    """The ``metadata.schema`` the template carries (``rule::1.0``)."""
    match = re.search(r"^\s+schema:\s*([\w:.]+)\s*$", template, re.MULTILINE)
    if match:
        return match.group(1)
    from opentide.models.schema_registry import latest_identifier

    return latest_identifier(family)


def _relative(path: Path, workspace: Path) -> str:
    resolved = path.resolve()
    for base in (Path.cwd().resolve(), workspace.resolve()):
        try:
            return resolved.relative_to(base).as_posix()
        except ValueError:
            continue
    return resolved.as_posix()


def _check_references(options: NewOptions, workspace: Path) -> None:
    references: list[tuple[str, str, str]] = []
    if options.objective:
        references.append(("--objective", "objective", options.objective))
    references.extend(("--threat", "threat", value) for value in options.threats)
    known: dict[str, set[str]] = {}
    for argument, family, value in references:
        if not _UUID.match(value):
            raise NewError(
                f"{argument} takes a UUID, got {value!r}",
                code="usage_invalid_value",
                argument=argument,
                exit_code=2,
            )
        if family not in known:
            known[family] = catalogue_uuids(workspace_artifacts(workspace, family).objects)
        if value.lower() not in known[family]:
            folder = _relative(workspace_artifacts(workspace, family).objects, workspace)
            raise NewError(
                f"No {family} in {folder} has uuid {value}",
                code=REFERENCE_NOT_FOUND,
                argument=argument,
                exit_code=2,
            )


def scaffold_object(
    workspace: Path,
    options: NewOptions,
    *,
    author: str | None = None,
    organisation: Organisation | None = None,
) -> dict[str, Any]:
    """Write the new object and return the ``CommandResult`` payload.

    The template and schema must exist: :func:`missing_artifacts` names what
    to generate first.
    """
    from opentide.models.platform_schema import platform_model_for_key
    from opentide.models.schema_registry import resolve_model

    family = options.family
    _check_references(options, workspace)
    artifacts = workspace_artifacts(workspace, family)
    template = artifacts.template.read_text(encoding="utf-8")
    schema = json.loads(artifacts.schema.read_text(encoding="utf-8"))
    schema_id = template_schema_id(template, family)
    model = resolve_model(schema_id)

    object_uuid = str(uuid_lib.uuid4())
    destination = target_path(artifacts.objects, options.name, object_uuid, options.path)
    if destination.exists():
        raise NewError(
            f"{_relative(destination, workspace)} already exists; new never overwrites a file",
            code=PATH_EXISTS,
            argument="--path" if options.path is not None else "--name",
        )

    today = options.today or dt.date.today()
    values: dict[Path_, Any] = {
        ("name",): options.name,
        ("metadata", "uuid"): object_uuid,
        ("metadata", "schema"): schema_id,
        ("metadata", "created"): today,
        ("metadata", "modified"): today,
    }
    wanted: list[Path_] = []
    if author:
        values[("metadata", "author")] = author
        wanted.append(("metadata", "author"))
    if organisation is not None:
        values[("metadata", "organisation", "uuid")] = organisation.uuid
        values[("metadata", "organisation", "name")] = organisation.name
        wanted.append(("metadata", "organisation"))
    overrides: dict[Path_, type[BaseModel]] = {}
    if family == "rule":
        if options.objective:
            values[("detection_model",)] = options.objective
            wanted.append(("detection_model",))
        status = inert_status(workspace) if options.platforms else None
        for platform in options.platforms:
            block = ("configurations", platform)
            overrides[block] = platform_model_for_key(platform)
            values[(*block, "enabled")] = True
            if status:
                values[(*block, "status")] = status
            wanted.extend([block, (*block, "enabled")])
    if family == "objective" and options.threats:
        values[("objective", "threats")] = list(options.threats)
        wanted.append(("objective", "threats"))

    fields = collect_fields(model, wanted=wanted, overrides=overrides)
    filled = fill_template(template, fields, values=values, schema=schema)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(filled.text, encoding="utf-8")

    shown = _relative(destination, workspace)
    count = len(filled.placeholders)
    message = f"Created {shown}"
    if count:
        message += f" · {count} placeholder value{'s' if count != 1 else ''} to replace"
    payload: dict[str, Any] = {
        "message": message,
        "path": shown,
        "file_path": str(destination.resolve()),
        "uuid": object_uuid,
        "type": family,
        "schema": schema_id,
        "name": options.name,
        "author": author,
        "organisation": None
        if organisation is None
        else {"uuid": organisation.uuid, "name": organisation.name},
        "platforms": list(options.platforms),
        "placeholders": filled.placeholders,
        "_summary": {"created": 1, "placeholders": count},
        # Printed as a note under the outcome line in human output.
        "detail": f"replace the placeholder value of {', '.join(filled.placeholders)}"
        if count
        else None,
        "_next_actions": [
            NextAction(f"opentide validate --file {shown}", f"check the new {family}"),
        ],
    }
    return payload


def missing_artifacts(workspace: Path, family: str) -> list[str]:
    """The generation phases ``new`` needs before it can scaffold *family*."""
    artifacts = workspace_artifacts(workspace, family)
    phases: list[str] = []
    if not artifacts.template.is_file():
        phases.append("templates")
    if not artifacts.schema.is_file():
        phases.append("schemas")
    return phases
