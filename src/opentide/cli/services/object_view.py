"""An object as ``opentide tui`` shows it by default: a page, not a file (#776).

Each value is placed under the field its schema revision defines, with the
field's title and description, a vocabulary value's meaning, and the name of
the object or signal a UUID names. The fields the revision allows but the
object does not set are listed too, so an author sees what they could add.

Everything comes from :func:`opentide.generation.lsp_catalog.fields_catalog`,
the catalogue the models generate for the language server: the same fields,
descriptions and vocabularies that validation and the editor use, for the
revision in ``metadata.schema``. No Textual here; :mod:`opentide.cli.tui_app`
draws it.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "FieldRow",
    "LinkTarget",
    "ObjectView",
    "Section",
    "UnsetField",
    "build_object_view",
    "field_nodes",
]

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
#: The ``metadata`` keys the header shows; the others are rows of the Metadata section.
_HEADER_KEYS = ("uuid", "schema", "version", "created", "modified", "tlp")
#: Fields a severity badge colours, by their path without list indexes.
SEVERITY_FIELDS = frozenset(
    {"severity", "response.alert_severity", "threat.severity", "objective.signals.severity"}
)


@dataclass(frozen=True)
class LinkTarget:
    """What a UUID value names: an object of the catalogue, or a signal of one."""

    uuid: str
    name: str
    #: ``threat``, ``objective``, ``rule`` or ``signal``.
    kind: str
    #: The object to open: the signal's objective for a signal.
    opens: str


@dataclass(frozen=True)
class FieldRow:
    """One line of a section: a group heading, a list item heading or a value."""

    #: The field's path with list indexes (``objective.signals.0.severity``), as findings name it.
    path: str
    #: The path the schema defines it under, without list indexes.
    schema_path: str
    title: str
    depth: int
    #: ``group`` (a mapping or a list of them), ``item`` (one entry of such a list) or ``value``.
    kind: str
    description: str = ""
    #: The value as written: a scalar, or a list of scalars.
    value: Any = None
    #: What each vocabulary value means, in the order of :attr:`values`.
    meanings: tuple[str, ...] = ()
    #: The objects and signals the value's UUIDs name, in the order of :attr:`values`.
    links: tuple[LinkTarget | None, ...] = ()
    #: Whether the field holds a severity (a badge).
    severity: bool = False

    @property
    def values(self) -> tuple[Any, ...]:
        if isinstance(self.value, (list, tuple)):
            return tuple(self.value)
        return () if self.value is None else (self.value,)


@dataclass(frozen=True)
class Section:
    """A top-level field of the object, and what it holds."""

    title: str
    path: str
    description: str
    rows: tuple[FieldRow, ...]


@dataclass(frozen=True)
class UnsetField:
    """A field the object's revision allows that the object does not set."""

    path: str
    title: str
    description: str
    #: The values its vocabulary allows, when it has one.
    choices: tuple[str, ...] = ()
    recommended: bool = False


@dataclass(frozen=True)
class ObjectView:
    """What the object view shows for one object."""

    name: str
    kind: str
    schema: str
    #: ``uuid``, ``schema``, ``version``, ``created``, ``modified``, ``tlp`` as written.
    header: Mapping[str, str]
    #: What the object's TLP means, from the vocabulary.
    tlp_meaning: str
    sections: tuple[Section, ...]
    unset: tuple[UnsetField, ...]
    #: Every reference the object makes, in order, for following them from the keyboard.
    links: tuple[LinkTarget, ...] = field(default=())
    #: Why the schema's fields are not known, when they are not (an unknown revision).
    unknown_schema: str | None = None


@functools.cache
def field_nodes() -> Mapping[str, Mapping[str, Mapping[str, Any]]]:
    """Each schema revision's fields by path, from the language server's catalogue."""
    from opentide import __version__
    from opentide.generation.lsp_catalog import fields_catalog

    nodes: dict[str, dict[str, Mapping[str, Any]]] = {}
    for node in fields_catalog(__version__)["fields"]:
        nodes.setdefault(str(node["schema"]), {})[str(node["path"])] = node
    return nodes


def _schema_id(body: Mapping[str, Any]) -> str:
    metadata = body.get("metadata")
    schema = metadata.get("schema") if isinstance(metadata, Mapping) else None
    return str(schema or "")


def _resolve_schema(schema: str, nodes: Mapping[str, Mapping[str, Any]]) -> str | None:
    """The revision whose fields apply: *schema* itself, else a bare family's newest."""
    if schema in nodes:
        return schema
    if "::" not in schema:
        revisions = sorted(key for key in nodes if key.split("::", 1)[0] == schema)
        return revisions[-1] if revisions else None
    return None


def _title(node: Mapping[str, Any] | None, key: str) -> str:
    title = str(node.get("title") or "") if node else ""
    if not title or title.replace(" ", "").lower() == key.replace("_", "").lower():
        return key.replace("_", " ").capitalize()
    return title


def _description(node: Mapping[str, Any] | None) -> str:
    return " ".join(str(node.get("description") or "").split()) if node else ""


def _meaning(node: Mapping[str, Any] | None, value: Any) -> str:
    if not node or not isinstance(value, str):
        return ""
    choices = list(node.get("enum") or ())
    docs = list(node.get("enum_docs") or ())
    if value in choices:
        index = choices.index(value)
        return str(docs[index]) if index < len(docs) and docs[index] else ""
    return ""


def _strip_indexes(path: str) -> str:
    return ".".join(part for part in path.split(".") if not part.isdigit())


def _scalar(value: Any) -> bool:
    return not isinstance(value, (Mapping, list, tuple))


def build_object_view(
    body: Mapping[str, Any],
    kind: str,
    links: Mapping[str, LinkTarget],
    nodes: Mapping[str, Mapping[str, Mapping[str, Any]]] | None = None,
) -> ObjectView:
    """The :class:`ObjectView` of *body*, an object of *kind*.

    *links* maps each UUID of the catalogue (objects and signals) to what it
    names. *nodes* defaults to :func:`field_nodes`.
    """
    nodes = field_nodes() if nodes is None else nodes
    schema = _schema_id(body)
    resolved = _resolve_schema(schema or kind, nodes)
    fields: Mapping[str, Mapping[str, Any]] = nodes.get(resolved, {}) if resolved else {}
    raw_metadata = body.get("metadata")
    metadata: Mapping[str, Any] = raw_metadata if isinstance(raw_metadata, Mapping) else {}
    header = {key: str(metadata[key]) for key in _HEADER_KEYS if metadata.get(key) is not None}
    found_links: list[LinkTarget] = []

    def row(path: str, key: str, value: Any, depth: int) -> list[FieldRow]:
        schema_path = _strip_indexes(path)
        node = fields.get(schema_path)
        if isinstance(value, Mapping):
            rows = [
                FieldRow(path, schema_path, _title(node, key), depth, "group", _description(node))
            ]
            for child, item in value.items():
                rows.extend(row(f"{path}.{child}", str(child), item, depth + 1))
            return rows
        if isinstance(value, (list, tuple)) and not all(_scalar(item) for item in value):
            rows = [
                FieldRow(
                    path,
                    schema_path,
                    f"{_title(node, key)} ({len(value)})",
                    depth,
                    "group",
                    _description(node),
                )
            ]
            for index, item in enumerate(value):
                label = _item_label(item, index)
                rows.append(FieldRow(f"{path}.{index}", schema_path, label, depth + 1, "item"))
                if isinstance(item, Mapping):
                    for child, inner in item.items():
                        rows.extend(row(f"{path}.{index}.{child}", str(child), inner, depth + 2))
                else:
                    rows.extend(row(f"{path}.{index}", key, item, depth + 2))
            return rows
        values = list(value) if isinstance(value, (list, tuple)) else [value]
        targets = tuple(_link(item, links) for item in values)
        found_links.extend(target for target in targets if target is not None)
        return [
            FieldRow(
                path,
                schema_path,
                _title(node, key),
                depth,
                "value",
                _description(node),
                value=value,
                meanings=tuple(_meaning(node, item) for item in values),
                links=targets,
                severity=schema_path in SEVERITY_FIELDS,
            )
        ]

    sections: list[Section] = []
    other = {key: value for key, value in metadata.items() if key not in _HEADER_KEYS}
    if other:
        node = fields.get("metadata")
        rows = [r for key, value in other.items() for r in row(f"metadata.{key}", key, value, 0)]
        sections.append(
            Section(_title(node, "metadata"), "metadata", _description(node), tuple(rows))
        )
    # Top-level values (description, status, severity, …) read as one section;
    # each block (objective, threat, response, configurations) is its own.
    overview: list[FieldRow] = []
    blocks: list[Section] = []
    for key, value in body.items():
        if key in ("name", "metadata"):
            continue
        node = fields.get(str(key))
        if isinstance(value, Mapping):
            rows = [
                r
                for child, item in value.items()
                for r in row(f"{key}.{child}", str(child), item, 0)
            ]
            blocks.append(
                Section(_title(node, str(key)), str(key), _description(node), tuple(rows))
            )
        else:
            overview.extend(row(str(key), str(key), value, 0))
    if overview:
        sections.insert(0, Section("Overview", "", "", tuple(overview)))
    sections.extend(blocks)
    return ObjectView(
        name=str(body.get("name") or ""),
        kind=kind,
        schema=schema,
        header=header,
        tlp_meaning=_meaning(fields.get("metadata.tlp"), metadata.get("tlp")),
        sections=tuple(sections),
        unset=_unset(body, fields),
        links=tuple(dict.fromkeys(found_links)),
        unknown_schema=None
        if fields
        else f"opentide does not know the fields of {schema or kind!r}: they are shown as written",
    )


def _item_label(item: Any, index: int) -> str:
    if isinstance(item, Mapping):
        for key in ("name", "title", "relation", "vector", "link"):
            if isinstance(item.get(key), str) and item[key]:
                return f"{index + 1}. {item[key]}"
    return f"{index + 1}."


def _link(value: Any, links: Mapping[str, LinkTarget]) -> LinkTarget | None:
    if isinstance(value, str) and _UUID.match(value.strip()):
        return links.get(value.strip()) or links.get(value.strip().lower())
    return None


def _present(body: Any, prefix: str = "") -> set[str]:
    """Every path *body* sets, without list indexes."""
    found: set[str] = set()
    if isinstance(body, Mapping):
        for key, value in body.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if value is None:
                continue
            found.add(path)
            found |= _present(value, path)
    elif isinstance(body, (list, tuple)):
        for item in body:
            found |= _present(item, prefix)
    return found


def _unset(
    body: Mapping[str, Any], fields: Mapping[str, Mapping[str, Any]]
) -> tuple[UnsetField, ...]:
    """The optional fields the revision defines where *body* could add them.

    A field counts when its parent is set (or it is top-level), so a block the
    object leaves out is one entry, not one per field inside it. Required
    fields are not listed: leaving one out is a validation error, not an option.
    """
    present = _present(body)
    unset: list[UnsetField] = []
    for path, node in sorted(fields.items()):
        if path in present or node.get("required") or node.get("hidden") or node.get("legacy"):
            continue
        parent = path.rsplit(".", 1)[0] if "." in path else ""
        if parent and parent not in present:
            continue
        unset.append(
            UnsetField(
                path=path,
                title=_title(node, path.rsplit(".", 1)[-1]),
                description=_description(node),
                choices=tuple(str(choice) for choice in node.get("enum") or ()),
                recommended=bool(node.get("recommended")),
            )
        )
    return tuple(unset)


def catalogue_links(
    families: Mapping[str, Mapping[str, Any]], names: Mapping[str, tuple[str, str]]
) -> dict[str, LinkTarget]:
    """Every UUID a reference can name: each object's, and each signal's.

    *families* are the registry's ``threats``, ``objectives`` and ``rules``;
    *names* maps an object's UUID to ``(name, kind)``.
    """
    links = {
        uuid: LinkTarget(uuid=uuid, name=name, kind=kind, opens=uuid)
        for uuid, (name, kind) in names.items()
    }
    from opentide.core.object_fields import as_body

    for owner, objective in (families.get("objectives") or {}).items():
        section = as_body(objective).get("objective")
        signals: Sequence[Any] = (
            section.get("signals") or () if isinstance(section, Mapping) else ()
        )
        for signal in signals:
            if isinstance(signal, Mapping) and isinstance(signal.get("uuid"), str):
                uuid = signal["uuid"]
                links.setdefault(
                    uuid,
                    LinkTarget(
                        uuid=uuid, name=str(signal.get("name") or uuid), kind="signal", opens=owner
                    ),
                )
    return links
