#!/usr/bin/env python3
"""Generate data/catalogs/bitdefender/criteria.toml, the GravityZone criteria catalogue.

`configurations.bitdefender.detection` (platform::bitdefender::1.0, #226) is a
GravityZone Basic detection rule: a target and a list of criteria. Which fields
a target has, what each field's value is, which relations it takes, whether
the EDR sensor, the XDR sensor or both evaluate it, and which fields may share
a rule are all on one Bitdefender page, "Detection and exclusion criteria for
Basic rules":

    https://www.bitdefender.com/business/support/en/77209-1486297-detection-and-exclusion-criteria.html

This script reads that page's criteria table and writes the catalogue. The
page is "all rights reserved", so the catalogue holds facts only: target and
field names, the Control Center label of each field, sensors, relations, value
kinds, enumerated values, ranges and the pairing rules, each rewritten as data.
No sentence of the page is copied. Every note in the table must match one of
the patterns below (`NOTE_RULES`), or be listed in `IGNORED_NOTES` with its
reason: a note the script does not know fails the run, so a change on the page
is read by a person before it reaches the engine.

Inputs (read as data, never executed):

- ``--cache DIR``: the page, as ``DIR/criteria.html``. It is fetched when
  missing, unless ``--offline`` or ``--check`` is given; ``--refresh`` fetches
  it again. The fetch date is kept in ``DIR/FETCHED`` and goes into the
  catalogue header. CI has no network: keep a cache to run ``--check``.

Usage:
    python -I scripts/engine/sync_bitdefender_criteria.py --cache ../bitdefender-cache [--offline] [--check]

``--check`` regenerates in memory, makes no network request, and exits 1 when
the committed file differs. Standard library only.
"""

from __future__ import annotations

import argparse
import re
import sys
import time
import urllib.request
from dataclasses import dataclass
from dataclasses import field as listed
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "catalogs" / "bitdefender" / "criteria.toml"
PAGE = "https://www.bitdefender.com/business/support/en/77209-1486297-detection-and-exclusion-criteria.html"
CACHE_NAME = "criteria.html"
USER_AGENT = "opentide-language-server catalog sync (https://github.com/opentidehq/language-server)"

# The targets whose field list bitdefender-1.0 states in its "Criteria
# catalogue" table (process, file, connection, registry). An unknown field of
# one of them is an error; any other target's list is the catalogue's alone,
# and an unknown field there is a warning until the spec covers it.
CLOSED_TARGETS = ("process", "file", "connection", "registry")

HEADER = [
    "Available for detection rules",
    "Available for exclusion rules",
    "Field name in GravityZone Control Center",
    "Target",
    "Field API name",
    "EDR or XDR support",
    "Relation API name",
    "Value validation rules",
]

FIELD_NAME = re.compile(r"^(?:[A-Z][A-Za-z0-9]*)(?:\.[A-Z][A-Za-z0-9]*)+$")
RELATIONS = ("is", "contains", "any")

# Notes the catalogue does not turn into data, with the reason.
IGNORED_NOTES = [
    # Registry.Key: full hive names never match. The abbreviations are read
    # into `[registry_hives]` (below); the engine's advisory
    # `bitdefender_registry_full_hive` (bitdefender-1.0, Advisories) uses them.
    (re.compile(r"^Registry key paths must use the supported root key abbreviations"), "hives"),
    (re.compile(r"^Additionally, for HKEY_USERS keys that do not start with a SID"), "hives"),
    (re.compile(r"^HKEY_[A-Z_]+: HK[A-Z]+$"), "hives"),
    # Registry.Data: base64 for binary types. The value's encoding is not
    # checked: the rule's data type may be any of several.
    (re.compile(r"^For the binary, resource_list, full_resource_descriptor, and resource_requirements_list registry types"), "base64"),
]


# --------------------------------------------------------------------------
# The page's table, with row and column spans resolved


@dataclass
class Block:
    """One paragraph or list item of a cell, and whether it sits in a note."""

    kind: str  # "p" or "li"
    text: str
    note: bool


@dataclass
class Cell:
    rowspan: int
    colspan: int
    blocks: list[Block] = listed(default_factory=list)

    def main(self) -> list[str]:
        return [b.text for b in self.blocks if not b.note]

    def notes(self) -> list[Block]:
        return [b for b in self.blocks if b.note]


class TableParser(HTMLParser):
    """The cells of every table on the page, as blocks of text."""

    NOTE_CLASSES = ("important", "tip", "note", "warning")

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[Cell]]] = []
        self.depth = 0
        self.cell: Cell | None = None
        self.buf: list[str] = []
        self.divs: list[bool] = []
        self.notes = 0
        self.lists = 0
        self.title = False

    def flush(self) -> None:
        text = re.sub(r"\s+", " ", "".join(self.buf)).strip()
        self.buf = []
        if text and self.cell is not None and not self.title:
            self.cell.blocks.append(Block("li" if self.lists else "p", text, self.notes > 0))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: v or "" for k, v in attrs}
        if tag == "table":
            self.depth += 1
            if self.depth == 1:
                self.tables.append([])
            return
        if not self.depth:
            return
        if tag == "tr":
            self.tables[-1].append([])
        elif tag in ("td", "th"):
            self.cell = Cell(int(a.get("rowspan") or 1), int(a.get("colspan") or 1))
            self.buf = []
        elif tag == "div":
            self.flush()
            note = any(c in a.get("class", "").split() for c in self.NOTE_CLASSES)
            self.divs.append(note)
            self.notes += note
        elif tag == "h3":
            self.flush()
            self.title = True
        elif tag in ("p", "li"):
            self.flush()
            if tag == "li":
                self.lists += 1
        elif tag == "br":
            self.flush()

    def handle_endtag(self, tag: str) -> None:
        if not self.depth:
            return
        if tag == "table":
            self.depth -= 1
        elif tag == "h3":
            self.buf = []
            self.title = False
        elif tag in ("p", "li"):
            self.flush()
            if tag == "li":
                self.lists -= 1
        elif tag == "div":
            self.flush()
            if self.divs and self.divs.pop():
                self.notes -= 1
        elif tag in ("td", "th") and self.cell is not None:
            self.flush()
            self.tables[-1][-1].append(self.cell)
            self.cell = None

    def handle_data(self, data: str) -> None:
        if self.depth and self.cell is not None:
            self.buf.append(data)


def grid(rows: list[list[Cell]]) -> list[list[Cell]]:
    """Rows of the same width: a cell spanning rows repeats in each."""
    out: list[list[Cell]] = []
    pending: dict[int, tuple[Cell, int]] = {}
    for row in rows:
        line: list[Cell] = []
        cells = list(row)
        col = 0
        while cells or col in pending:
            if col in pending:
                cell, left = pending.pop(col)
                if left > 1:
                    pending[col] = (cell, left - 1)
            else:
                cell = cells.pop(0)
                for offset in range(cell.colspan):
                    if cell.rowspan > 1:
                        pending[col + offset] = (cell, cell.rowspan - 1)
                line.extend([cell] * (cell.colspan - 1))
            line.append(cell)
            col = len(line)
        out.append(line)
    return out


def intro_hashes(html: str) -> list[str]:
    """The fields the page lists as taking no wildcards with `contains`."""
    head = html[: html.find("<table")]
    match = re.search(r"An exception applies to criteria where.*?</ul>", head, re.S)
    if not match:
        raise SystemExit("the page no longer lists the fields without wildcards")
    names = re.findall(r"<li[^>]*>(?:\s|<[^>]+>)*([A-Za-z.0-9]+)", match.group(0))
    if not names:
        raise SystemExit("the list of fields without wildcards is empty")
    return names


# --------------------------------------------------------------------------
# Reading the table into fields and rules


@dataclass
class Value:
    name: str
    availability: str
    incompatible: list[str] = listed(default_factory=list)


@dataclass
class Field:
    name: str
    target: str
    label: str
    availability: str
    detection: bool
    exclusion: bool
    relations: list[str]
    kind: str
    exclusion_availability: str | None = None
    values: list[Value] = listed(default_factory=list)
    minimum: int | None = None
    maximum: int | None = None
    requires_any: list[str] = listed(default_factory=list)
    detection_requires_any: list[str] = listed(default_factory=list)
    incompatible: list[str] = listed(default_factory=list)
    resource: str | None = None


@dataclass
class Rule:
    kind: str
    target: str | None = None
    field: str | None = None
    scope: str | None = None
    require: bool | None = None
    targets: list[str] = listed(default_factory=list)


@dataclass
class Catalogue:
    alert: Field | None = None
    fields: list[Field] = listed(default_factory=list)
    targets: dict[str, tuple[bool, bool]] = listed(default_factory=dict)
    rules: list[Rule] = listed(default_factory=list)
    hives: dict[str, str] = listed(default_factory=dict)


def yes(text: str) -> bool:
    if text not in ("Yes", "No"):
        raise SystemExit(f"availability {text!r} is not Yes or No")
    return text == "Yes"


def availability(texts: list[str]) -> tuple[str, str | None]:
    """The detection rule sensors, and the exclusion rule ones when they differ."""
    joined = " / ".join(texts)
    simple = {"EDR": "edr", "XDR": "xdr", "Both": "both"}
    if joined in simple:
        return simple[joined], None
    m = re.fullmatch(r"(EDR|XDR|Both) for exclusion rules / (EDR|XDR|Both) for detection rules", joined)
    if m:
        return simple[m.group(2)], simple[m.group(1)]
    raise SystemExit(f"sensor support {joined!r} is not EDR, XDR, Both or a per-rule-type pair")


def relations(text: str) -> list[str]:
    found = [part.strip() for part in text.split("|")]
    if not found or any(r not in RELATIONS for r in found):
        raise SystemExit(f"relations {text!r} are not among {RELATIONS}")
    return found


def kind_of(cell: Cell, name: str, hashes: list[str]) -> tuple[str, list[Value], int | None, int | None]:
    """The value kind, enumerated values, and range of a field."""
    texts = cell.main()
    first = texts[0] if texts else ""
    if first.startswith("Possible") or first.startswith("Possible values"):
        values: list[Value] = []
        sensor = ""
        for block in cell.blocks:
            if block.note:
                continue
            text = block.text
            group = re.fullmatch(r"Possible (EDR|XDR)-only values:", text)
            if group:
                sensor = group.group(1).lower()
                continue
            if re.fullmatch(r"Possible values for both EDR and XDR:", text):
                sensor = "both"
                continue
            if text == "Possible values:":
                sensor = ""  # the field's own sensors
                continue
            inline = re.fullmatch(r"Possible values: ([a-z_/]+)\.", text)
            if inline:
                values.append(Value(inline.group(1), ""))
                continue
            if block.kind == "li" and re.fullmatch(r"[a-z_/]+", text):
                values.append(Value(text, sensor))
                continue
            raise SystemExit(f"{name}: value line {text!r} is not understood")
        if not values:
            raise SystemExit(f"{name}: an enumeration without values")
        return "enum", values, None, None
    if name in hashes:
        if first != "string":
            raise SystemExit(f"{name}: a hash field whose values are {first!r}")
        return "hash", [], None, None
    if first == "string":
        return "string", [], None, None
    if first == "string containing a valid IP":
        return "ip", [], None, None
    if first == "string, valid email":
        return "email", [], None, None
    m = re.fullmatch(r"integer between (\d[\d,]*) and (\d[\d,]*)", first)
    if m:
        low, high = (int(g.replace(",", "")) for g in m.groups())
        if (low, high) != (0, 65535):
            raise SystemExit(f"{name}: an integer range {low}-{high} that is not a port")
        return "port", [], low, high
    raise SystemExit(f"{name}: value rule {first!r} is not understood")


def ignored(text: str) -> bool:
    return any(pattern.search(text) for pattern, _ in IGNORED_NOTES)


def read_field_notes(row: Field, blocks: list[Block], cat: Catalogue, pending_values: list[tuple[str, str, str]]) -> None:
    """Turn the notes under a field name into pairing data."""
    collecting = False
    for block in blocks:
        text = block.text
        if collecting and FIELD_NAME.fullmatch(text):
            row.incompatible.append(text)
            continue
        collecting = False
        if text == "Incompatible with the following fields in the same rule:":
            collecting = True
            continue
        m = re.fullmatch(r"Requires either ([\w.]+) or ([\w.]+) to be defined in the same rule\.", text)
        if m:
            row.requires_any.extend(m.groups())
            continue
        m = re.fullmatch(r"Requires ([\w.]+) to be defined in the same rule\.", text)
        if m:
            row.requires_any.append(m.group(1))
            continue
        m = re.fullmatch(r"This criterion can only be used together with ([\w.]+) in the same rule\.", text)
        if m:
            row.requires_any.append(m.group(1))
            continue
        m = re.fullmatch(r"This criterion must be used together with ([\w.]+)\.", text)
        if m:
            row.requires_any.append(m.group(1))
            continue
        m = re.fullmatch(
            r"This criterion can only be applied together with ([\w.]+) and is required when \1 is used without detection\.",
            text,
        )
        if m:
            row.requires_any.append(m.group(1))
            row.resource = resource_of(row.name)
            continue
        m = re.fullmatch(r"For detection rules, requires ([\w.]+) or detection to be defined in the same rule\.", text)
        if m:
            row.detection_requires_any.extend([m.group(1), "detection"])
            row.resource = resource_of(row.name)
            continue
        m = re.fullmatch(r"This criterion is incompatible with the (\w+) value of the ([\w.]+) field\.", text)
        if m:
            pending_values.append((m.group(2), m.group(1), row.name))
            continue
        m = re.fullmatch(
            r"If this criterion and ([\w.]+) are used, the ([\w.]+) criterion can have only the value ([a-z_/]+)\.", text
        )
        if m:
            # The other values of the protocol field cannot sit beside this one.
            pending_values.append((m.group(2), "!" + m.group(3), row.name))
            continue
        m = re.fullmatch(r"For any XDR detection rule that uses the (\w+) target, you must include either this criterion or a detection condition, but not both or neither\.", text)
        if m:
            cat.rules.append(Rule("alert_or_operation", target=m.group(1), field=row.name, scope="xdr", require=True))
            continue
        m = re.fullmatch(r"Any detection rule with the ([a-z ]+?) target(?: entity)? must use either this criterion or the detection field, but not both\.", text)
        if m:
            if m.group(1) != row.target:
                raise SystemExit(f"{row.name}: a note about target {m.group(1)!r} under {row.target!r}")
            cat.rules.append(Rule("alert_or_operation", target=row.target, field=row.name, scope="all", require=True))
            continue
        if ignored(text):
            continue
        raise SystemExit(f"{row.name}: note {text!r} is not understood")


def resource_of(name: str) -> str:
    parts = name.split(".")
    if len(parts) != 3:
        raise SystemExit(f"{name} is not <Target>.<Resource>.<Field>")
    return parts[1]


def read_value_notes(row: Field, cell: Cell, cat: Catalogue) -> None:
    """Notes beside enumerated values, and the registry hive tip."""
    current: Value | None = None
    for block in cell.blocks:
        if not block.note:
            current = next((v for v in row.values if v.name == block.text), current)
            continue
        text = block.text
        m = re.fullmatch(r"The (\w+) value is incompatible with ([\w.]+) or ([\w.]+) in the same rule\.", text)
        if m:
            value = next((v for v in row.values if v.name == m.group(1)), None)
            if value is None:
                raise SystemExit(f"{row.name}: a note on unknown value {m.group(1)!r}")
            value.incompatible.extend(m.group(2, 3))
            continue
        m = re.fullmatch(r"This value is not supported when the (.+) fields? (?:is|are) included in the same rule\.", text)
        if m:
            if current is None:
                raise SystemExit(f"{row.name}: a value note before any value")
            names = re.split(r",\s*(?:or\s+)?|\s+or\s+", m.group(1))
            if not all(FIELD_NAME.fullmatch(n) for n in names):
                raise SystemExit(f"{row.name}: value note fields {names!r} are not field names")
            current.incompatible.extend(names)
            continue
        m = re.fullmatch(r"(HKEY_[A-Z_]+): (HK[A-Z]+)", text)
        if m:
            cat.hives[m.group(1)] = m.group(2)
            continue
        if ignored(text):
            continue
        raise SystemExit(f"{row.name}: value note {text!r} is not understood")


def read_alert(line: list[Cell], cat: Catalogue) -> None:
    name = line[4].main()
    if name != ["detection"] or line[3].main() != ["All target entities"]:
        raise SystemExit("the first row is no longer the alert (detection) criterion")
    sensors, _ = availability(line[5].main())
    cat.alert = Field("detection", "*", " ".join(line[2].main()), sensors, yes(line[0].main()[0]),
                      yes(line[1].main()[0]), relations(line[6].main()[0]), "string")
    for block in line[4].notes():
        if re.fullmatch(r"For any XDR detection rule, you must use either this criterion or an operation criterion, but not both\.", block.text):
            cat.rules.append(Rule("alert_or_operation", scope="xdr", require=False))
            continue
        raise SystemExit(f"alert: note {block.text!r} is not understood")


def read_page(html: str) -> Catalogue:
    parser = TableParser()
    parser.feed(html)
    tables = [grid(t) for t in parser.tables if t]
    tables = [
        t
        for t in tables
        if len(t[0]) == len(HEADER) and all(" ".join(c.main()).startswith(h) for c, h in zip(t[0], HEADER))
    ]
    if len(tables) != 1:
        raise SystemExit(f"expected one criteria table with columns {HEADER}, found {len(tables)}")
    rows = tables[0][1:]
    hashes = intro_hashes(html)
    head = re.sub(r"<[^>]+>", "", html[: html.find("<table")])
    head = re.sub(r"\s+", " ", head)
    cat = Catalogue()
    if "EDR-only fields or values cannot be combined with XDR-only fields or values within the same rule" not in head:
        raise SystemExit("the page no longer says EDR-only and XDR-only criteria do not mix")
    cat.rules.append(Rule("no_sensor_mix"))
    m = re.search(r"Only one XDR resource can be defined as a criterion in a detection rule with the (\w+) or (\w+ \w+) target", head)
    if not m:
        raise SystemExit("the page no longer limits connection rules to one XDR resource")
    cat.rules.append(Rule("one_resource", targets=[m.group(1), m.group(2)]))
    read_alert(rows[0], cat)
    pending: list[tuple[str, str, str]] = []
    for line in rows[1:]:
        if len(line) != len(HEADER):
            raise SystemExit(f"a row of {len(line)} cells")
        target = " ".join(line[3].main())
        names = [t for t in line[4].main() if FIELD_NAME.fullmatch(t)]
        if len(names) != 1:
            raise SystemExit(f"field cell {line[4].main()!r} does not hold one API name")
        name = names[0]
        sensors, exclusion_sensors = availability(line[5].main())
        rel = relations(line[6].main()[0])
        kind, values, low, high = kind_of(line[7], name, hashes)
        row = Field(name, target, " ".join(line[2].main()), sensors, yes(line[0].main()[0]), yes(line[1].main()[0]),
                    rel, kind, exclusion_sensors, values, low, high)
        for value in row.values:
            value.availability = value.availability or sensors
        read_field_notes(row, line[4].notes(), cat, pending)
        read_value_notes(row, line[7], cat)
        if any(f.name == name for f in cat.fields):
            raise SystemExit(f"{name} appears twice")
        cat.fields.append(row)
        detection, exclusion = cat.targets.get(target, (False, False))
        cat.targets[target] = (detection or row.detection, exclusion or row.exclusion)
    by_name = {f.name: f for f in cat.fields}
    for target_field, value_name, other in pending:
        enum = by_name.get(target_field)
        if enum is None or not enum.values:
            raise SystemExit(f"{other}: a value note on {target_field!r}, which has no values")
        if value_name.startswith("!"):
            keep = value_name[1:]
            chosen = [v for v in enum.values if v.name != keep]
        else:
            chosen = [v for v in enum.values if v.name == value_name]
        if not chosen:
            raise SystemExit(f"{other}: no value {value_name!r} on {target_field}")
        for value in chosen:
            if other not in value.incompatible:
                value.incompatible.append(other)
    check(cat, by_name)
    return cat


def check(cat: Catalogue, by_name: dict[str, Field]) -> None:
    """Every name a rule mentions is a field of the catalogue."""
    for row in cat.fields:
        mentioned = row.requires_any + row.incompatible + [n for n in row.detection_requires_any if n != "detection"]
        mentioned += [n for v in row.values for n in v.incompatible]
        for name in mentioned:
            if name not in by_name:
                raise SystemExit(f"{row.name}: a pairing names {name!r}, which is not a field")
    for target in CLOSED_TARGETS:
        if target not in cat.targets:
            raise SystemExit(f"closed target {target!r} is not on the page")
    if set(cat.hives.values()) != {"HKLM", "HKCU", "HKU", "HKCR", "HKCC"}:
        raise SystemExit(f"registry hive abbreviations {cat.hives!r} changed")


# --------------------------------------------------------------------------
# Writing TOML


def q(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def qlist(items: list[str]) -> str:
    return "[" + ", ".join(q(i) for i in items) + "]"


def write(cat: Catalogue, fetched: str) -> str:
    out = [
        "# Bitdefender GravityZone criteria catalogue (#226), generated by",
        "# scripts/engine/sync_bitdefender_criteria.py. Do not edit.",
        f"# Source: {PAGE}",
        f"# (\"Detection and exclusion criteria for Basic rules\", fetched {fetched}).",
        "# Facts only: names, Control Center labels, sensors, relations, value kinds,",
        "# values, ranges and pairing rules, rewritten as data. See data/catalogs/bitdefender/NOTICE.",
        "#",
        "# availability: the sensor that evaluates a field or value in a detection rule",
        "#   (edr, xdr or both); exclusion_availability when exclusion rules differ.",
        "# kind: string, hash (no wildcards with contains), ip, email, port (an integer",
        "#   from minimum to maximum), or enum (one of `values`).",
        "# requires_any: one of these must also be a criterion of the rule;",
        "#   detection_requires_any the same in detection rules, where `detection` is the",
        "#   alert criterion (the block's `alert`).",
        "# incompatible: fields that may not be criteria of the same rule. On a value:",
        "#   fields that may not be criteria of a rule using that value.",
        "# resource: the XDR resource the field is about (one per connection rule).",
        "# closed: bitdefender-1.0 states the target's field list; an unknown field of",
        "#   another target is a warning.",
        "",
        f"source = {q(PAGE)}",
        f"fetched = {q(fetched)}",
        "",
        "[registry_hives]",
    ]
    for full, short in cat.hives.items():
        out.append(f"{full} = {q(short)}")
    alert = cat.alert
    assert alert is not None
    out += [
        "",
        "# The alert criterion, `alert` in the block (`detection` in criteriaList).",
        "[alert]",
        f"field = {q(alert.name)}",
        f"label = {q(alert.label)}",
        f"availability = {q(alert.availability)}",
        f"relations = {qlist(alert.relations)}",
        "",
    ]
    for rule in cat.rules:
        out.append("[[rules]]")
        out.append(f"kind = {q(rule.kind)}")
        if rule.target:
            out.append(f"target = {q(rule.target)}")
        if rule.field:
            out.append(f"field = {q(rule.field)}")
        if rule.scope:
            out.append(f"scope = {q(rule.scope)}")
        if rule.require is not None:
            out.append(f"require = {'true' if rule.require else 'false'}")
        if rule.targets:
            out.append(f"targets = {qlist(rule.targets)}")
        out.append("")
    for name, (detection, exclusion) in cat.targets.items():
        out += [
            "[[targets]]",
            f"name = {q(name)}",
            f"detection = {'true' if detection else 'false'}",
            f"exclusion = {'true' if exclusion else 'false'}",
            f"closed = {'true' if name in CLOSED_TARGETS else 'false'}",
            "",
        ]
    for row in cat.fields:
        out += [
            "[[fields]]",
            f"name = {q(row.name)}",
            f"target = {q(row.target)}",
            f"label = {q(row.label)}",
            f"availability = {q(row.availability)}",
        ]
        if row.exclusion_availability:
            out.append(f"exclusion_availability = {q(row.exclusion_availability)}")
        out += [
            f"detection = {'true' if row.detection else 'false'}",
            f"exclusion = {'true' if row.exclusion else 'false'}",
            f"relations = {qlist(row.relations)}",
            f"kind = {q(row.kind)}",
        ]
        if row.minimum is not None:
            out.append(f"minimum = {row.minimum}")
            out.append(f"maximum = {row.maximum}")
        if row.resource:
            out.append(f"resource = {q(row.resource)}")
        if row.requires_any:
            out.append(f"requires_any = {qlist(row.requires_any)}")
        if row.detection_requires_any:
            out.append(f"detection_requires_any = {qlist(row.detection_requires_any)}")
        if row.incompatible:
            out.append(f"incompatible = {qlist(row.incompatible)}")
        if row.values:
            out.append("values = [")
            for value in row.values:
                extra = f", incompatible = {qlist(value.incompatible)}" if value.incompatible else ""
                out.append(f"    {{ name = {q(value.name)}, availability = {q(value.availability)}{extra} }},")
            out.append("]")
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"


# --------------------------------------------------------------------------


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:  # fixed https host
        return response.read().decode("utf-8")


def fill_cache(cache: Path, offline: bool, refresh: bool) -> None:
    cache.mkdir(parents=True, exist_ok=True)
    page = cache / CACHE_NAME
    if page.is_file() and not refresh:
        return
    if offline:
        raise SystemExit(f"{page} is missing and --offline/--check forbids fetching")
    print(f"fetch {PAGE}", file=sys.stderr)
    page.write_text(fetch(PAGE), encoding="utf-8")
    (cache / "FETCHED").write_text(time.strftime("%Y-%m-%d") + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument("--cache", type=Path, required=True, help="directory holding criteria.html")
    parser.add_argument("--offline", action="store_true", help="never fetch; fail on a missing page")
    parser.add_argument("--refresh", action="store_true", help="fetch the page again")
    parser.add_argument("--check", action="store_true", help="exit 1 when the file would change (offline)")
    args = parser.parse_args()

    fill_cache(args.cache, offline=args.offline or args.check, refresh=args.refresh and not args.check)
    html = (args.cache / CACHE_NAME).read_text(encoding="utf-8")
    stamp = args.cache / "FETCHED"
    fetched = stamp.read_text(encoding="utf-8").strip() if stamp.is_file() else "unknown"
    text = write(read_page(html), fetched)
    if args.check:
        if not OUT.is_file() or OUT.read_text(encoding="utf-8") != text:
            print(f"stale: {OUT.relative_to(ROOT)}", file=sys.stderr)
            return 1
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(ROOT)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
