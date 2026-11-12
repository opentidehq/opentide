"""Sections every object family shares.

Each function returns a section *body*: the page layout
(:mod:`opentide.documentation.markdown.page`) owns headings, order and the
contents list. An empty string means the section has nothing to say and is
left out.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.documentation.markdown.links import object_link
from opentide.documentation.markdown.page import key_value_table
from opentide.documentation.markdown.text import (
    first_sentence,
    inline_code,
    join_lines,
    stringify,
    table_cell,
)
from opentide.documentation.vocabulary import EnrichedEntry, enrich, enrich_technique
from opentide.models.metadata import ObjectMetadata, ObjectReferences

RelationsDirection = Literal["upstream", "downstream", "both"]


@dataclass(frozen=True)
class Links:
    """Everything a link from one page to another object needs."""

    formatter: MarkdownFormatter
    catalog: DocumentationCatalog
    folder: str
    uuid_permalinks: bool = False
    wiki: bool = False

    def to(self, uuid: str, *, with_uuid: bool = False) -> str:
        """A link to the page (or signal heading) of *uuid*."""
        return object_link(
            self.formatter,
            self.catalog,
            uuid,
            from_folder=self.folder,
            uuid_permalinks=self.uuid_permalinks,
            wiki=self.wiki,
            with_uuid=with_uuid,
        )


def prose(formatter: MarkdownFormatter, text: str | None) -> str:
    """Author text as written: its own paragraphs, lists and emphasis."""
    return formatter.paragraph(text) if text and text.strip() else ""


def metadata_table(metadata: ObjectMetadata, formatter: MarkdownFormatter) -> str:
    """Provenance of the object: identifiers, versions, dates, marking and authorship.

    The UUID row comes first: ``publish.prune`` recognises a generated page by it.
    """
    rows = [
        ("UUID", inline_code(metadata.uuid)),
        ("Schema", inline_code(metadata.schema_id)),
        ("Version", inline_code(metadata.version)),
        ("Created", inline_code(metadata.created)),
        ("Modified", inline_code(metadata.modified)),
        ("TLP", tlp_label(metadata.tlp)),
        ("Author", table_cell(metadata.author or "")),
        ("Contributors", ", ".join(metadata.contributors or [])),
    ]
    if metadata.organisation:
        organisation = metadata.organisation
        rows.append(("Organisation", f"{organisation.name} ({inline_code(organisation.uuid)})"))
    return key_value_table(formatter, rows, headers=("Field", "Value"))


def tlp_marking(tlp: str) -> str:
    """The marking id of *tlp* (``TLP:AMBER``), or the value as written when unknown."""
    entry = enrich("tlp", tlp)
    marking = entry.raw.get("id") if isinstance(entry.raw, dict) else ""
    return marking if isinstance(marking, str) and marking else tlp


def tlp_label(tlp: str) -> str:
    """``clear`` as ``clear (`TLP:CLEAR`)``: the vocabulary label and its marking id."""
    entry = enrich("tlp", tlp)
    marking = entry.raw.get("id") if isinstance(entry.raw, dict) else ""
    if isinstance(marking, str) and marking and marking != entry.label:
        return f"{entry.label} ({inline_code(marking)})"
    return entry.label


def references_body(references: ObjectReferences | None, formatter: MarkdownFormatter) -> str:
    """Public, internal and report references as one table."""
    if not references:
        return ""
    rows: list[list[str]] = []
    for key, value in sorted((references.public or {}).items()):
        rows.append(["Public", table_cell(str(key)), reference_value(value, formatter)])
    for key, value in sorted((references.internal or {}).items()):
        rows.append(["Internal", table_cell(str(key)), reference_value(value, formatter)])
    for value in references.reports or []:
        rows.append(["Report", "-", reference_value(value, formatter)])
    if not rows:
        return ""
    return formatter.table(["Kind", "Key", "Reference"], rows)


def reference_value(value: str, formatter: MarkdownFormatter) -> str:
    """A URL as a link, anything else as text."""
    if value.startswith(("http://", "https://")):
        return formatter.link(value, value)
    return table_cell(value)


def attack_table(techniques: Iterable[str], formatter: MarkdownFormatter) -> str:
    """ATT&CK techniques with their tactics and the opening sentence of their description."""
    rows: list[list[str]] = []
    for technique in dict.fromkeys(techniques):
        entry = enrich_technique(technique)
        tactics = stringify(entry.raw.get("tide.vocab.stages")) if entry.raw else ""
        rows.append(
            [
                entry_link(entry, technique, formatter, label=inline_code(technique)),
                table_cell(entry.label if entry.label != technique else ""),
                table_cell(tactics),
                table_cell(first_sentence(entry.description)),
            ]
        )
    if not rows:
        return ""
    return formatter.table(["Technique", "Name", "Tactics", "Summary"], rows)


def technique_links(techniques: Iterable[str], formatter: MarkdownFormatter) -> str:
    """Technique ids as links, one line each, for an overview cell."""
    lines = []
    for technique in dict.fromkeys(techniques):
        entry = enrich_technique(technique)
        name = f" {entry.label}" if entry.label != technique else ""
        lines.append(entry_link(entry, technique, formatter, label=inline_code(technique)) + name)
    return join_lines(lines)


def entry_link(
    entry: EnrichedEntry, fallback: str, formatter: MarkdownFormatter, *, label: str | None = None
) -> str:
    """The vocabulary entry's label, linked to its ``link`` when it has one."""
    text = label or table_cell(entry.label or fallback)
    link = entry.raw.get("link") if isinstance(entry.raw, dict) else None
    if isinstance(link, str) and link.startswith(("http://", "https://")):
        return formatter.link(text, link)
    return text


def vocab_label(vocab: str, key: str) -> str:
    """The vocabulary label of *key*, with the key itself when they differ."""
    entry = enrich(vocab, key)
    if entry.label != key:
        return f"{entry.label} ({inline_code(key)})"
    return key


def related_table(links: Links, uuid: str, *, direction: RelationsDirection) -> str:
    """Every object related to *uuid*, linked: Mermaid nodes are not clickable on GitHub."""
    entries = links.catalog.related_entries(uuid, direction=direction)
    if not isinstance(entries, list) or not entries:
        return ""
    order = {"threat": 0, "objective": 1, "signal": 2, "rule": 3}
    entries = sorted(
        entries,
        key=lambda entry: (
            order.get(entry.object_type or "", len(order)),
            (entry.name or links.catalog.resolve_name(entry.uuid)).lower(),
        ),
    )
    rows: list[list[str]] = []
    for entry in entries:
        rows.append(
            [
                (entry.object_type or "object").title(),
                links.to(entry.uuid),
                (entry.direction or "-").title(),
            ]
        )
    return links.formatter.table(["Type", "Object", "Direction"], rows)
