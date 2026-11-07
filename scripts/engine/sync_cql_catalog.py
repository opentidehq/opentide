#!/usr/bin/env python3
"""Generate catalogs/cql/*.toml, the CrowdStrike Query Language (CQL) catalogs.

CQL is the query language of Falcon LogScale and Falcon Next-Gen SIEM. This
script writes three catalogs, all facts only:

- ``functions.toml``: every function of the CQL function reference on
  library.humio.com (names, parameters, types, defaults, enumerated values,
  bounds, categories, lifecycle), plus the functions the release notes
  removed. CrowdStrike's documentation is "all rights reserved", so no
  sentence of it is copied: ``FUNCTION_SUMMARIES`` below is written for this
  catalog and must have an entry for every function. Next-Gen SIEM
  availability (``ngsiem``) is evidence only: a function is marked when
  CrowdStrike's own Next-Gen SIEM content calls it.
- ``events.toml``: Falcon ``#event_simpleName`` values with the platforms and
  fields public, redistributable sources show for each, and the field set of
  each Microsoft Sentinel FDR table (one per event category).
- ``fields.toml``: the LogScale built-in fields and tags, the Falcon platform
  tags and common sensor fields, the CrowdStrike Parsing Standard (CPS) tags
  and extras, and the ECS fields that Next-Gen SIEM parsers and dashboards
  use (types from catalogs/ecs/fields.json).

Inputs (all read as data, never executed):

- ``--cache DIR``: library.humio.com pages (``functions.html`` and every
  ``functions-*.html`` it links). Pages missing from the cache are fetched
  sequentially, one request per second, unless ``--offline`` or ``--check``
  is given; ``--refresh`` fetches them all again. The fetch date is kept in
  ``DIR/FETCHED`` and goes into the catalog header. CI has no network: keep a
  cache to run ``--check``.
- ``--lcc``: a CrowdStrike/logscale-community-content checkout (Unlicense;
  some sub-packages MIT or Apache-2.0, recorded per name).
  ``git clone --depth 1 https://github.com/CrowdStrike/logscale-community-content``
- ``--query-hub``: ByteRay-Labs/Query-Hub (MIT, stated in its README).
  ``git clone --depth 1 https://github.com/ByteRay-Labs/Query-Hub``
- ``--cql-queries``: cs-shadowbq/CQL-Queries (MIT).
  ``git clone --depth 1 https://github.com/cs-shadowbq/CQL-Queries``
- ``--sentinel``: Azure/Azure-Sentinel (MIT), only the CrowdStrike solution:
  ``git clone --depth 1 --filter=blob:none --sparse https://github.com/Azure/Azure-Sentinel``
  then ``git sparse-checkout set "Solutions/CrowdStrike Falcon Endpoint Protection"``.
- ``--pysigma``: SigmaHQ/pySigma-backend-crowdstrike (LGPL-2.1; event and
  field names only, read with ``ast``, never imported).
  ``git clone --depth 1 https://github.com/SigmaHQ/pySigma-backend-crowdstrike``

Elastic's crowdstrike integration (Elastic License 2.0) is deliberately not
an input: no name that only Elastic supplies may ship. The erickatwork
"events data dictionary" repository is never used: it republishes
CrowdStrike's login-gated event reference.

Usage:
    python -I scripts/sync_cql_catalog.py --cache ../cql-cache \
        --lcc ../logscale-community-content --query-hub ../Query-Hub \
        --cql-queries ../CQL-Queries --sentinel ../Azure-Sentinel \
        --pysigma ../pySigma-backend-crowdstrike [--offline] [--check]

``--check`` regenerates in memory, makes no network request, and exits 1
when a committed file differs. Requires PyYAML (scripts/requirements-cql.txt).
"""

from __future__ import annotations

import argparse
import ast
import collections
import json
import re
import subprocess
import sys
import time
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "catalogs" / "cql"
ECS_CATALOG = ROOT / "catalogs" / "ecs" / "fields.json"

SITE = "https://library.humio.com/crowdstrike-query-language/"
INDEX_PAGE = "functions.html"
RELEASE_NOTES = "https://library.humio.com/release-notes/release-notes-deprecated.html"
USER_AGENT = "opentide-language-server catalog sync (https://github.com/opentidehq/language-server)"

SENTINEL_SOLUTION = "Solutions/CrowdStrike Falcon Endpoint Protection/Data Connectors"
PYSIGMA_PIPELINE = "sigma/pipelines/crowdstrike/crowdstrike.py"

# --------------------------------------------------------------------------
# A small DOM over html.parser. The docs are generated XHTML-like HTML, so a
# stack that pops to the matching start tag is enough.

VOID = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
    "param", "source", "track", "wbr",
}
SKIP_TEXT = {"script", "style", "svg"}


class Element:
    __slots__ = ("attrs", "children", "parent", "tag")

    def __init__(self, tag: str, attrs: dict[str, str], parent: Element | None) -> None:
        self.tag = tag
        self.attrs = attrs
        self.children: list[Element | str] = []
        self.parent = parent

    def get(self, key: str) -> str:
        return self.attrs.get(key) or ""

    def has_class(self, name: str) -> bool:
        return name in self.get("class").split()

    def elements(self) -> list[Element]:
        return [c for c in self.children if isinstance(c, Element)]

    def iter(self) -> Iterator[Element]:
        for child in self.children:
            if isinstance(child, Element):
                yield child
                yield from child.iter()

    def find(self, tag: str | None = None, **attrs: str) -> Element | None:
        return next(self.find_all(tag, **attrs), None)

    def find_all(self, tag: str | None = None, **attrs: str) -> Iterator[Element]:
        """Descendants by tag and attribute; an attribute value ending in `*`
        matches as a prefix, `class_` matches one class."""
        for el in self.iter():
            if tag is not None and el.tag != tag:
                continue
            if all(_attr_match(el, k, v) for k, v in attrs.items()):
                yield el

    def text(self) -> str:
        parts: list[str] = []
        self._text(parts)
        return clean("".join(parts))

    def _text(self, parts: list[str]) -> None:
        if self.tag in SKIP_TEXT:
            return
        for child in self.children:
            if isinstance(child, str):
                parts.append(child)
            else:
                if child.tag in ("br", "p", "div", "td", "tr", "li"):
                    parts.append(" ")
                child._text(parts)


def _attr_match(el: Element, key: str, value: str) -> bool:
    if key == "class_":
        return el.has_class(value)
    actual = el.attrs.get(key)
    if actual is None:
        return False
    if value.endswith("*"):
        return actual.startswith(value[:-1])
    return actual == value


class TreeBuilder(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = Element("#document", {}, None)
        self.stack = [self.root]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        el = Element(tag, {k: v or "" for k, v in attrs}, self.stack[-1])
        self.stack[-1].children.append(el)
        if tag not in VOID:
            self.stack.append(el)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        el = Element(tag, {k: v or "" for k, v in attrs}, self.stack[-1])
        self.stack[-1].children.append(el)

    def handle_endtag(self, tag: str) -> None:
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                return

    def handle_data(self, data: str) -> None:
        self.stack[-1].children.append(data)


def parse_html(text: str) -> Element:
    builder = TreeBuilder()
    builder.feed(text)
    builder.close()
    return builder.root


def clean(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


# --------------------------------------------------------------------------
# Fetching library.humio.com


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:  # fixed https host
        return response.read().decode("utf-8")


def linked_pages(index_html: str) -> list[str]:
    return sorted(set(re.findall(r'href="(functions-[a-z0-9-]+\.html)', index_html)))


def fill_cache(cache: Path, offline: bool, refresh: bool) -> None:
    """Fetch the index and every page it links into *cache*, politely."""
    cache.mkdir(parents=True, exist_ok=True)
    index = cache / INDEX_PAGE
    fetched = False
    if refresh or not index.is_file():
        if offline:
            raise SystemExit(f"{index} is missing and --offline/--check forbids fetching")
        index.write_text(fetch(SITE + INDEX_PAGE), encoding="utf-8")
        fetched = True
    for page in linked_pages(index.read_text(encoding="utf-8")):
        path = cache / page
        if path.is_file() and not refresh:
            continue
        if offline:
            raise SystemExit(f"{path} is missing and --offline/--check forbids fetching")
        time.sleep(1.0)
        print(f"fetch {page}", file=sys.stderr)
        path.write_text(fetch(SITE + page), encoding="utf-8")
        fetched = True
    if fetched:
        (cache / "FETCHED").write_text(time.strftime("%Y-%m-%d") + "\n", encoding="utf-8")


# --------------------------------------------------------------------------
# The function reference

# Docs type (interpreted type first, else the base type) -> catalog type.
TYPE_MAP = {
    "fieldname": "field",
    "field": "field",
    "array of fieldnames": "array<field>",
    "string": "string",
    "hostname or ip address": "string",
    "array of strings": "array<string>",
    "array of arrays of strings": "array<array<string>>",
    "string or array": "string|array<string>",
    "boolean": "boolean",
    "integer": "integer",
    "long": "integer",
    "double": "number",
    "number": "number",
    "array of numbers": "array<number>",
    "expression": "expression",
    "non-aggregate expression": "expression",
    "non-aggregate exprssion": "expression",  # sic, on some pages
    "filter expression": "expression",
    "array of expressions": "array<expression>",
    "aggregate function": "function",
    "non-aggregate function": "function",
    "function": "function",
    "array of aggregate functions": "array<function>",
    "query": "query",
    "regex": "regex",
    "glob pattern": "glob",
    "relative time": "duration",
    "time value": "time",
    "timezone": "timezone",
    "fixed values": "enum",
    "array of fixed values": "array<enum>",
    "array name": "array_name",
    "arrayname": "array_name",
    "array": "array",
    "filename": "file",
    "array of file or table names": "array<file>",
}
QUERY_TYPES = {"function", "array<function>", "query"}
DEPRECATED_IN = re.compile(r"\(\s*deprecated in (\d+(?:\.\d+)*)\s*\)", re.I)
# Page "Compatible Context" names -> catalog spelling.
CONTEXTS = {
    "Query": "query",
    "Live Query": "live-query",
    "Aggregate Alert": "aggregate-alert",
    "Filter Alert": "filter-alert",
    "Legacy Alert": "legacy-alert",
    "Parser": "parser",
    "Non-aggregate Query": "non-aggregate-query",
    "Filter Query": "filter-query",
    "Must be used only on a stored event": "stored-event",
}
# Page "Incompatible" names -> catalog spelling. A context listed both ways
# (copyEvent, defineTable, ...) is taken as incompatible.
INCOMPATIBLE = {
    "Filter Alerts": "filter-alert",
    "Aggregate Alerts": "aggregate-alert",
    "Live Queries": "live-query",
    "Joins": "join",
}


def catalog_type(base: str, interpreted: str) -> str:
    low = (base + " " + interpreted).lower()
    if "fixed values" in (base.lower(), interpreted.lower()) and "array" not in low:
        return "enum"
    for key in (interpreted.lower().strip(), base.lower().strip()):
        if key in TYPE_MAP:
            return TYPE_MAP[key]
    raise SystemExit(f"unknown parameter type {base!r} / {interpreted!r}: extend TYPE_MAP")


def number(text: str) -> int | None:
    digits = text.replace(",", "").strip()
    return int(digits) if re.fullmatch(r"\d+", digits) else None


@dataclass
class Param:
    name: str
    type: str
    required: bool
    default: str | None
    unnamed: bool
    multi: bool
    deprecated_since: str | None = None
    deprecated: bool = False
    values: list[str] = field(default_factory=list)
    deprecated_values: list[str] = field(default_factory=list)
    values_open: bool = False
    minimum: int | None = None
    maximum: int | None = None
    query: bool = False
    aliases: list[str] = field(default_factory=list)


@dataclass
class Function:
    name: str
    page: str
    params: list[Param]
    function_type: list[str]
    contexts: list[str]
    incompatible: list[str]
    since: str | None
    deprecated: bool
    experimental: bool
    feature_flag: str | None
    ngsiem_only: bool
    category: list[str] = field(default_factory=list)
    aggregate: bool = False
    removed: bool = False
    removed_in: str | None = None
    replacement: str | None = None


DEFAULT_SPELLINGS = {"(space)": " "}


def literal_default(cell: Element, ptype: str) -> str | None:
    """The documented default when it is a literal value, else None: a bare
    token (`@rawstring`, `200`, `count(as=_count)`, `[50, 75, 99]`), never
    a description of where the value comes from."""
    code = cell.find("code")
    text = code.text() if code is not None else cell.text()
    if text in DEFAULT_SPELLINGS:
        return DEFAULT_SPELLINGS[text]
    if not text or (text.startswith("(") and text.endswith(")")):
        return None
    # `same as primary query`, `input field name`: a description, even in <code>.
    if " " in text and not re.search(r"^\[|[(=\"]", text):
        return None
    if ptype == "integer" and number(text) is not None:
        return str(number(text))
    return text


def parse_params(article: Element) -> list[Param]:
    wrap = article.find("div", id="table_table-functions*")
    if wrap is None:
        return []
    table = wrap.find("table")
    assert table is not None
    footnotes: dict[str, str] = {}
    for div in table.find_all("div", class_="footnote"):
        footnotes[div.get("id").removeprefix("ftn.")] = div.text()
    body = next(el for el in table.elements() if el.tag == "tbody" and not el.has_class("footnotes"))
    params: list[Param] = []
    current: Param | None = None
    mode = ""
    for tr in (el for el in body.elements() if el.tag == "tr"):
        tds = [el for el in tr.elements() if el.tag == "td"]
        if not tds:
            continue
        if tds[0].get("id").startswith("query-functions-") and len(tds) >= 6:
            name_cell = tds[0]
            code = name_cell.find("code")
            name = code.text() if code is not None else name_cell.text().split()[0]
            unnamed = False
            for link in name_cell.find_all("a", class_="footnote"):
                ref = link.get("href").split("#ftn.")[-1]
                unnamed = unnamed or "can be omitted" in footnotes.get(ref, "")
            for link in name_cell.find_all("a", class_="footnoteref"):
                ref = link.get("href").split("#ftn.")[-1]
                unnamed = unnamed or "can be omitted" in footnotes.get(ref, "")
            base, interpreted = tds[1].text(), tds[2].text()
            ptype = catalog_type(base, interpreted)
            description = tds[5].text()
            since = DEPRECATED_IN.search(description)
            current = Param(
                name=name,
                type=ptype,
                required=tds[3].text().lower().startswith("required"),
                default=literal_default(tds[4], ptype),
                unnamed=unnamed,
                multi=base.lower().startswith("array of") or ptype.startswith("array<"),
                deprecated="(deprecated)" in name_cell.text() or since is not None,
                deprecated_since=since.group(1) if since else None,
            )
            params.append(current)
            mode = ""
            continue
        if current is None:
            continue
        texts = [td.text() for td in tds]
        if len(texts) >= 5 and texts[4] == "Values":
            mode = "values"
        elif len(texts) >= 4 and texts[3] == "Controlling Variables":
            mode = "variables"
        elif len(texts) >= 5 and texts[3] in ("Maximum", "Minimum"):
            if texts[3] == "Maximum":
                current.maximum = number(texts[4])
            else:
                current.minimum = number(texts[4])
            mode = ""
        elif mode == "values" and len(texts) >= 5 and texts[4]:
            value = texts[4]
            notes = texts[5] if len(texts) > 5 else ""
            dep = DEPRECATED_IN.search(notes) or DEPRECATED_IN.search(value)
            value = clean(DEPRECATED_IN.sub("", value))
            current.values.append(value)
            if dep:
                current.deprecated_values.append(value)
    for p in params:
        if p.type == "boolean" and set(p.values) <= {"true", "false"}:
            p.values = []
        elif p.type in ("integer", "number"):
            # A keyword such as `max` accepted besides a number.
            keywords = [v for v in p.values if not re.fullmatch(r"[\d.,]+", v)]
            p.values = keywords
            p.values_open = bool(keywords)
    return params


def summary_rows(article: Element) -> dict[str, Element]:
    wrap = article.find("div", id="table_table-summary-functions*")
    rows: dict[str, Element] = {}
    if wrap is None:
        return rows
    for tr in wrap.find_all("tr"):
        tds = [el for el in tr.elements() if el.tag == "td"]
        if len(tds) >= 2:
            rows[tds[0].text()] = tds[1]
    return rows


def code_list(cell: Element | None) -> list[str]:
    if cell is None:
        return []
    codes = [c.text() for c in cell.find_all("code")]
    if codes:
        return list(dict.fromkeys(codes))
    return [clean(x) for x in cell.text().split(",") if clean(x)]


def parse_function_page(page: str, text: str) -> Function | None:
    doc = parse_html(text)
    article = doc.find("article", id="mainarticle")
    if article is None:
        return None
    rows = summary_rows(article)
    if "Signature" not in rows:
        return None
    heading = article.find("h2")
    name = (heading.text() if heading is not None else "").removesuffix("()").strip()
    # Admonitions between the title and the "Function Summary" heading.
    notes: list[str] = []
    title = article.find("div", class_="titlepage")
    if title is not None and title.parent is not None:
        siblings = title.parent.children
        for node in siblings[siblings.index(title) + 1:]:
            if not isinstance(node, Element):
                continue
            if node.has_class("bridgehead"):
                break
            if {"important", "note", "depnote", "warning", "caution", "tip"} & set(node.get("class").split()):
                notes.append(node.text())
    joined = " ".join(notes)
    page_text = article.text()
    flag = re.search(r"feature flag (\w+)|feature (\w+) must be enabled", joined + " " + page_text)
    badge = next((el for el in doc.find_all("span", class_="version-badge") if el.has_class("available")), None)
    params = parse_params(article)
    examples = "\n".join(c.text() for pre in article.find_all("pre") for c in pre.find_all("code"))
    for p in params:
        sub = re.search(r"\b" + re.escape(p.name) + r"\s*=\s*\[?\s*\{", examples)
        if not sub and p.unnamed:
            sub = re.search(re.escape(name) + r"\(\s*\[?\s*\{", examples)
        p.query = p.type in QUERY_TYPES or bool(sub)
    for alias, of in sorted(set(re.findall(r"\buse (\w+) as an alias of the (\w+) parameter", page_text))):
        for p in params:
            if p.name == of and alias not in p.aliases:
                p.aliases.append(alias)
    incompatible: list[str] = []
    for ctx in code_list(rows.get("Incompatible")):
        if ctx not in INCOMPATIBLE:
            raise SystemExit(f"{page}: unknown incompatible context {ctx!r}: extend INCOMPATIBLE")
        if INCOMPATIBLE[ctx] not in incompatible:
            incompatible.append(INCOMPATIBLE[ctx])
    contexts: list[str] = []
    for ctx in code_list(rows.get("Compatible Context")):
        if ctx not in CONTEXTS:
            raise SystemExit(f"{page}: unknown context {ctx!r}: extend CONTEXTS")
        if CONTEXTS[ctx] not in incompatible:
            contexts.append(CONTEXTS[ctx])
    return Function(
        name=name,
        page=page,
        params=params,
        function_type=[t.lower().replace(" ", "-") for t in code_list(rows.get("Function Type"))],
        contexts=contexts,
        incompatible=incompatible,
        since=badge.text() if badge is not None else None,
        deprecated=any(n.startswith("Deprecated:") for n in notes),
        experimental=bool(re.search(r"experimental|beta feature", joined, re.I)),
        feature_flag=(flag.group(1) or flag.group(2)) if flag else None,
        ngsiem_only=bool(re.search(r"only\s+available in Falcon NG-SIEM", page_text)),
    )


def parse_index(text: str) -> dict[str, list[str]]:
    """Function page -> categories, from the index table."""
    doc = parse_html(text)
    table = doc.find("table", summary="Query Functions")
    if table is None:
        raise SystemExit("functions.html has no Query Functions table")
    out: dict[str, list[str]] = {}
    for tr in table.find_all("tr", id="table_functions-functions-row-*"):
        tds = [el for el in tr.elements() if el.tag == "td"]
        link = tds[0].find("a")
        if link is None:
            continue
        cats = [c.strip().replace(" ", "-") for c in tds[1].text().split(",") if c.strip()]
        out[link.get("href").split("#")[0]] = cats
    return out


def parse_category_pages(cache: Path, pages: list[str]) -> dict[str, list[str]]:
    """Function page -> categories, from the row ids of the category pages
    (for the functions the index table does not list)."""
    out: dict[str, list[str]] = {}
    for page in pages:
        doc = parse_html((cache / page).read_text(encoding="utf-8"))
        for tr in doc.find_all("tr", id="table_functions-*"):
            m = re.match(r"table_functions-(.+?)(?:_summary)?-functions-row-", tr.get("id"))
            link = tr.find("a")
            if m and link is not None and link.get("href"):
                target = link.get("href").split("#")[0]
                cat = m.group(1).replace(" ", "-")
                if cat != "functions" and cat not in out.setdefault(target, []):
                    out[target].append(cat)
    return out


def docs_version(cache: Path) -> str:
    text = (cache / INDEX_PAGE).read_text(encoding="utf-8")
    m = re.search(r"CrowdStrike Query Language (\d[\d.]*(?:[-\u2013]\d[\d.]*)?)", text)
    return m.group(1).replace("\u2013", "-") if m else "unknown"


# Functions the release notes removed or replaced; they have no page any more.
# Facts from RELEASE_NOTES (and match()'s page for lookup()).
REMOVED_FUNCTIONS: list[dict[str, str | None]] = [
    # "holtwinters() is now deprecated and will be removed along with ... 1.73" (1.68.0).
    {"name": "holtwinters", "removed_in": "1.73", "replacement": None, "citation": RELEASE_NOTES},
    # match(strict=false) "works like the deprecated lookup()"; no page since.
    {"name": "lookup", "removed_in": None, "replacement": "match", "citation": SITE + "functions-match.html"},
    # "rdns() has been deprecated and will be removed in version 1.249" (1.193.0).
    {"name": "rdns", "removed_in": "1.249", "replacement": "reverseDns", "citation": RELEASE_NOTES},
]


# Documented facts that are wrong on the page, corrected here with the reason.
PARAM_FIXES: dict[tuple[str, str], dict[str, Any]] = {
    # Typed `long` on the page, but its values are unit names (ms, s, ...).
    ("formatDuration", "from"): {"type": "enum", "values_open": False},
    # The page gives now()'s output name `_now` as the default output array.
    ("matchAsArray", "asArray"): {"default": None},
    # The page no longer lists `any`, but CrowdStrike's own content still sorts
    # with it (logscale-community-content: the PAN-Firewall summary dashboard,
    # Helpful-CQL-Queries "Decode Base64"). Accepted, not offered.
    ("sort", "type"): {"deprecated_values": ["any"]},
    # The table has no "can be omitted" note, but the page's eight examples and
    # the Expressions page call getField("host-name") without the name.
    ("getField", "source"): {"unnamed": True},
    # Its own page's example is `math:cosh(x, as=result)`; every other math:
    # function marks `field` omittable.
    ("math:cosh", "field"): {"unnamed": True},
    # The page's prose gives two forms, `remoteTable(connection, [end], include,
    # name, query, [start])` and `remoteTable(connection, name, query)`.
    ("remoteTable", "include"): {"required": False},
    # "Deprecated: prefer order instead" in the parameter's description.
    ("table", "reverse"): {"deprecated": True},
    # CrowdStrike's own dashboards write these (logscale-community-content:
    # `order=des` six times, `ascending`, `descending`, `asce`). Accepted as
    # written there, not offered; anything else is refused.
    ("sort", "order"): {"deprecated_values": ["des", "asce", "ascending", "descending"]},
    ("table", "order"): {"deprecated_values": ["des", "asce", "ascending", "descending"]},
}
# Parameters a page's prose documents that its table leaves out.
EXTRA_PARAMS: dict[str, list[Param]] = {
    # Both forms on the remoteTable page take `query` (`query="show tables"`,
    # `query={*}`).
    "remoteTable": [
        Param(
            name="query", type="query", required=True, default=None, unnamed=False, multi=False, query=True
        )
    ],
}
FUNCTION_FIXES: dict[str, dict[str, Any]] = {
    # The page lists every context, but says it "can only be used within the
    # parser" and "cannot be used during a query".
    "copyEvent": {"contexts": ["parser"]},
}


def read_functions(cache: Path) -> list[Function]:
    index = parse_index((cache / INDEX_PAGE).read_text(encoding="utf-8"))
    pages = linked_pages((cache / INDEX_PAGE).read_text(encoding="utf-8"))
    by_category = parse_category_pages(cache, pages)
    functions: list[Function] = []
    for page in pages:
        fn = parse_function_page(page, (cache / page).read_text(encoding="utf-8"))
        if fn is None:
            continue
        fn.category = index.get(page) or by_category.get(page, [])
        fn.aggregate = "aggregate" in fn.function_type or (not fn.function_type and "aggregate" in fn.category)
        for key, value in FUNCTION_FIXES.get(fn.name, {}).items():
            setattr(fn, key, value)
        for p in fn.params:
            for key, value in PARAM_FIXES.get((fn.name, p.name), {}).items():
                setattr(p, key, value)
        for extra in EXTRA_PARAMS.get(fn.name, []):
            if any(p.name == extra.name for p in fn.params):
                raise SystemExit(f"EXTRA_PARAMS {fn.name}.{extra.name} is on the page now: drop it")
            fn.params.append(extra)
        fn.params.sort(key=lambda p: p.name.lower())
        functions.append(fn)
    unlisted = set(index) - {f.page for f in functions}
    if unlisted:
        raise SystemExit(f"index rows without a parsed page: {sorted(unlisted)}")
    for row in REMOVED_FUNCTIONS:
        functions.append(
            Function(
                name=str(row["name"]), page=str(row["citation"]), params=[], function_type=[],
                contexts=[], incompatible=[], since=None, deprecated=True, experimental=False, feature_flag=None,
                ngsiem_only=False, removed=True, removed_in=row["removed_in"],
                replacement=row["replacement"],
            )
        )
    return sorted(functions, key=lambda f: (f.name.lower(), f.name))


def signature(fn: Function) -> str:
    """`name(unnamed, required, [optional])`, parameters in that order."""
    ordered = sorted(fn.params, key=lambda p: (not p.unnamed, not p.required))
    parts = [p.name if p.required else f"[{p.name}]" for p in ordered if not p.deprecated]
    return f"{fn.name}({', '.join(parts)})"


# --------------------------------------------------------------------------
# Query corpora (logscale-community-content, Query-Hub, CQL-Queries)

FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.S)
QUERY_KEYS = {"queryString", "query", "search", "script", "filter", "cql"}


@dataclass
class Query:
    source: str  # catalog source key, e.g. "lcc", "lcc-mit", "queryhub"
    path: str
    text: str


def licence_of(path: Path, root: Path, cache: dict[Path, str]) -> str:
    """The licence of the nearest LICENSE file above *path* (up to *root*)."""
    for directory in [path.parent, *path.parent.parents]:
        if directory in cache:
            return cache[directory]
        found = ""
        for name in ("LICENSE", "LICENSE.txt", "LICENSE.md"):
            lic = directory / name
            if lic.is_file():
                head = lic.read_text(encoding="utf-8", errors="replace")[:600]
                if "MIT License" in head or "Permission is hereby granted" in head:
                    found = "mit"
                elif "Apache License" in head:
                    found = "apache"
                elif "unencumbered" in head:
                    found = "unlicense"
                break
        if found:
            cache[directory] = found
            return found
        if directory == root:
            break
    return "unlicense"


def yaml_queries(text: str) -> list[str]:
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        return []
    out: list[str] = []
    stack: list[Any] = list(docs)
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if key in QUERY_KEYS and isinstance(value, str):
                    out.append(value)
                else:
                    stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)
    return out


def read_corpus(root: Path, key: str, licences: bool) -> list[Query]:
    """Every query in a checkout: Markdown fences, `.logscale` files, and the
    query keys of YAML packages. Zip archives are not opened."""
    queries: list[Query] = []
    lic_cache: dict[Path, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.parts or "__MACOSX" in path.parts:
            continue
        suffix = path.suffix.lower()
        if suffix not in (".md", ".logscale", ".yaml", ".yml"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(root).as_posix()
        if suffix == ".md":
            texts = [m.group(1) for m in FENCE.finditer(text)]
        elif suffix == ".logscale":
            texts = [text]
        else:
            texts = yaml_queries(text)
        source = key
        if licences:
            lic = licence_of(path, root, lic_cache)
            source = key if lic == "unlicense" else f"{key}-{lic}"
        queries.extend(Query(source, rel, t) for t in texts)
    return queries


STRING = re.compile(r'"(?:[^"\\\n]|\\.)*"')
REGEX_LITERAL = re.compile(r"(?<=[=\s(,])/(?:[^/\\\n]|\\.)+/[a-zA-Z]*")


def strip_comments(q: str) -> str:
    q = re.sub(r"/\*.*?\*/", " ", q, flags=re.S)
    return re.sub(r"(?m)(?<!:)//.*$", " ", q)


# A query that reads Falcon-only data or packages runs in Falcon (Next-Gen
# SIEM), not in a plain LogScale cluster.
FALCON_ONLY = re.compile(r"\$falcon/|#repo\s*=\s*\"?(?:base_sensor|xdr_|fcs_)|\bNgsiem\.")


def ngsiem_evidence(queries: list[Query], names: list[str]) -> dict[str, str]:
    """Function -> where CrowdStrike's content calls it in a Next-Gen SIEM
    query: a file under Next-Gen-SIEM/ (preferred), else a query that reads
    Falcon-only data. Calls in strings and comments do not count."""
    patterns = {n: re.compile(r"(?<![\w$/.:@#])" + re.escape(n) + r"\s*\(") for n in names}
    strong: dict[str, str] = {}
    weak: dict[str, str] = {}
    for q in queries:
        text = strip_comments(q.text)
        if q.path.startswith("Next-Gen-SIEM/"):
            found = strong
        elif FALCON_ONLY.search(text):
            found = weak
        else:
            continue
        code = STRING.sub('""', text)
        for name, pattern in patterns.items():
            if name not in found and pattern.search(code):
                found[name] = q.path
    return {**weak, **strong}


EVENT_EQ = re.compile(r"#?event_simpleName\s*(?:=|!=)\s*\"?([A-Za-z][A-Za-z0-9_]*)\"?(?![*A-Za-z0-9_])")
EVENT_IN = re.compile(r"in\(\s*(?:field\s*=\s*)?\"?#?event_simpleName\"?\s*,\s*values\s*=\s*\[([^\]]*)\]", re.S)
EVENT_RX = re.compile(r"#?event_simpleName\s*=\s*/((?:[^/\\\n]|\\.)+)/")
IDENT = re.compile(r"(?<![A-Za-z0-9_.\-@#$])([@#]?[A-Za-z_][A-Za-z0-9_.\[\]]*)")
# Argument names and keywords that look like field names.
KEYWORDS = {
    "and", "or", "not", "true", "false", "as", "field", "function", "values", "limit",
    "max", "min", "distinct", "where", "include", "file", "column", "strict", "span",
    "unit", "format", "series", "sortby", "order", "desc", "asc", "type", "regex",
    "flags", "ignorecase", "mode", "prefilter", "buckets", "timezone", "query",
    "start", "end", "key", "repo", "glob", "within", "sequence", "maxperroot", "root",
    "jittertolerance", "globalconstraints", "maxdepth", "precision", "separator",
    "strip", "multiline", "with", "then", "case", "match", "in", "from", "to", "by",
    "default", "replace", "time", "timefield", "decimals", "n", "num", "percent",
    "infile", "template", "id", "minspan", "outputformat",
}
FIELD_ARGS = {"field", "fields", "key", "column", "sortby", "timefield", "keys"}


def event_names(q: str) -> tuple[set[str], set[str]]:
    """(names compared exactly, capitalised tokens of regex alternations)."""
    exact = {m.group(1) for m in EVENT_EQ.finditer(q)}
    for m in EVENT_IN.finditer(q):
        for value in re.split(r"[,\s]+", m.group(1)):
            value = value.strip().strip('"')
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", value):
                exact.add(value)
    regex: set[str] = set()
    for m in EVENT_RX.finditer(q):
        if "?<" not in m.group(1):
            regex.update(re.findall(r"[A-Z][A-Za-z0-9]+", m.group(1)))
    return exact, regex


def fields_in(q: str) -> tuple[set[str], set[str]]:
    """(names a query reads, names it creates)."""
    bare = REGEX_LITERAL.sub(" // ", STRING.sub(' "" ', q))
    created: set[str] = set()
    created.update(m.group(1) for m in re.finditer(r"([@#]?[A-Za-z_][A-Za-z0-9_.\[\]]*)\s*:=", bare))
    created.update(m.group(1) for m in re.finditer(r"\bas\s*=\s*\"?([A-Za-z_@#][A-Za-z0-9_.\[\]]*)", bare))
    created.update(m.group(1) for m in re.finditer(r"\?([A-Za-z_][A-Za-z0-9_]*)", bare))
    created.update(m.group(1) for m in re.finditer(r"\(\?<([A-Za-z_][A-Za-z0-9_.]*)>", q))
    created.update(m.group(1) for m in re.finditer(r"defineTable\(\s*name\s*=\s*\"?([A-Za-z_][A-Za-z0-9_]*)", q))
    bare = re.sub(r"values\s*=\s*\[[^\]]*\]", " ", bare)
    read: set[str] = set()
    for m in IDENT.finditer(bare):
        token = re.sub(r"\[\d*\]$", "", m.group(1).rstrip(".")).rstrip("[]")
        after = bare[m.end():m.end() + 3].lstrip()
        if after.startswith(("(", ":=")):
            continue
        before = bare[max(0, m.start() - 40):m.start()]
        if before.endswith("?"):
            continue
        lhs = re.search(r"([A-Za-z_@#][A-Za-z0-9_.]*)\s*(!=|=|<=|>=|<|>)\s*$", before)
        if lhs and lhs.group(1).lower() not in FIELD_ARGS:
            continue  # the value side of a comparison
        if token.lower() in KEYWORDS and not token.startswith(("#", "@")):
            continue
        if re.fullmatch(r"[a-z]+", token) and token not in {"aid", "cid", "aip"}:
            continue
        if re.search(r"\.(exe|dll|ps1|bat|cmd|sh|py|json|sys|vbs|js|msc|com|scr|hta|lnk)$", token, re.I):
            continue
        if re.fullmatch(r"[A-Z0-9_]+", token) and len(token) > 3:
            continue
        read.add(token)
    return read - created, created


def stages(q: str) -> list[str]:
    out: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in q:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "|" and depth <= 0:
            out.append("".join(current))
            current = []
        else:
            current.append(ch)
    out.append("".join(current))
    return out


def or_groups(stage: str) -> list[str]:
    groups: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(stage):
        if ch == "(":
            if depth == 0:
                start = i
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                groups.append(stage[start + 1:i])
    return groups


@dataclass
class EventEvidence:
    mentions: int = 0
    exact: int = 0
    fields: collections.Counter[str] = field(default_factory=collections.Counter)
    platforms: set[str] = field(default_factory=set)


@dataclass
class Mined:
    events: dict[str, EventEvidence] = field(default_factory=dict)
    created: collections.Counter[str] = field(default_factory=collections.Counter)
    read: collections.Counter[str] = field(default_factory=collections.Counter)
    tag_values: dict[str, collections.Counter[str]] = field(default_factory=dict)


VALUE_TAGS = [
    "#repo", "event_platform", "#Vendor", "#event.module", "#event.kind", "#kind",
    "#streamingApiEvent", "#data_source_name",
]


def mine(queries: list[Query]) -> dict[str, Mined]:
    """Per source key: event names, the fields queries pinning one event read,
    and tag values."""
    out: dict[str, Mined] = collections.defaultdict(Mined)
    for query in queries:
        mined = out[query.source]
        q = strip_comments(query.text)
        exact, regex = event_names(q)
        read, created = fields_in(q)
        mined.created.update(created)
        mined.read.update(read)
        for tag in VALUE_TAGS:
            pattern = re.escape(tag) + r"\s*=\s*\"?([A-Za-z0-9_][A-Za-z0-9_.\-]*)\"?(?![*\w])"
            for m in re.finditer(r"(?<![\w.#])" + pattern, q):
                mined.tag_values.setdefault(tag, collections.Counter())[m.group(1)] += 1
        names = exact | regex
        if not names:
            continue
        platforms = set(re.findall(r"event_platform\s*=\s*\"?([A-Za-z][A-Za-z0-9]*)", q))
        for m in re.finditer(r"event_platform\s*=\s*/([^/]+)/", q):
            platforms |= set(re.findall(r"[A-Z][A-Za-z0-9]+", m.group(1)))
        # Fields of a stage, or of a parenthesised OR group, that names one event.
        strong: dict[str, set[str]] = collections.defaultdict(set)
        for stage in stages(q):
            e, r = event_names(stage)
            units = or_groups(stage) if len(e | r) > 1 else [stage]
            for unit in units:
                e1, r1 = event_names(unit)
                if len(e1 | r1) == 1:
                    strong[next(iter(e1 | r1))] |= fields_in(unit)[0]
        for name in names:
            ev = mined.events.setdefault(name, EventEvidence())
            ev.mentions += 1
            if name in exact:
                ev.exact += 1
            if len(names) == 1:
                ev.fields.update(read)
                ev.platforms |= platforms
            else:
                ev.fields.update(strong.get(name, set()))
    return out


# --------------------------------------------------------------------------
# Microsoft Sentinel's CrowdStrike FDR connector (MIT)

SENTINEL_ONLY_COLUMNS = {
    "TimeGenerated", "CrowdStrikeId", "AdditionalFields", "eventDatetime", "_ItemId",
    "TenantId", "Type", "_ResourceId", "event_simpleName",
}


@dataclass
class Sentinel:
    tables: dict[str, list[tuple[str, str]]]  # table -> (column, type)
    event_table: dict[str, str]
    raw_columns: set[str]


def walk_json(node: Any, key: str) -> Iterator[Any]:
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key:
                yield v
            else:
                yield from walk_json(v, key)
    elif isinstance(node, list):
        for item in node:
            yield from walk_json(item, key)


def read_sentinel(checkout: Path) -> Sentinel:
    base = checkout / SENTINEL_SOLUTION
    fdr = base / "CrowdStrikeS3FDR_ccp"
    tables: dict[str, list[tuple[str, str]]] = {}
    for path in sorted(fdr.glob("CrowdStrike_*_CL.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        cols = data["properties"]["schema"]["columns"]
        tables[data["name"]] = [(c["name"], c["type"]) for c in cols if c["name"] not in SENTINEL_ONLY_COLUMNS]
    dcr = json.loads((fdr / "DCR.json").read_text(encoding="utf-8"))
    raw: set[str] = set()
    for decls in walk_json(dcr, "streamDeclarations"):
        for column in decls.get("Custom-CrowdstrikeStream", {}).get("columns", []):
            raw.add(column["name"])
    event_table: dict[str, str] = {}
    for flows in walk_json(dcr, "dataFlows"):
        for flow in flows:
            table = flow.get("outputStream", "").removeprefix("Custom-")
            for m in re.finditer(r"event_simpleName\s+in~?\s*\(([^)]*)\)", flow.get("transformKql") or ""):
                for name in re.findall(r"'([A-Za-z0-9_]+)'|\"([A-Za-z0-9_]+)\"", m.group(1)):
                    event_table[name[0] or name[1]] = table
    mapping = base / "CrowdstrikeReplicatorCLv2/CrowdstrikeFalconAPISentinelConn/QueueTriggerCS/EventsToTableMapping.json"
    for name, kind in json.loads(mapping.read_text(encoding="utf-8")).items():
        event_table.setdefault(name, f"CrowdStrike_{kind}_Events_CL")
    return Sentinel(tables, event_table, raw - SENTINEL_ONLY_COLUMNS)


def table_category(table: str) -> str:
    """`CrowdStrike_Process_Events_CL` -> `process`."""
    core = table.removeprefix("CrowdStrike_").removesuffix("_CL").removesuffix("_Events").removesuffix("_Data")
    return core.lower()


# --------------------------------------------------------------------------
# pySigma's CrowdStrike Falcon pipeline (LGPL-2.1): names only, via ast

OS_PLATFORM = {"windows": "Win", "linux": "Lin", "macos": "Mac"}


@dataclass
class SigmaCategory:
    events: set[str] = field(default_factory=set)
    fields: set[str] = field(default_factory=set)
    platforms: set[str] = field(default_factory=set)


def _strings(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple)):
        return [s for elt in node.elts for s in _strings(elt)]
    return []


def read_pysigma(checkout: Path) -> dict[str, SigmaCategory]:
    """Sigma category -> the `#event_simpleName` values of the Falcon (CQL)
    pipeline, the CQL fields its field mappings target, and the platforms of
    the log sources."""
    tree = ast.parse((checkout / PYSIGMA_PIPELINE).read_text(encoding="utf-8"))
    cats: dict[str, SigmaCategory] = collections.defaultdict(SigmaCategory)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "ProcessingItem"):
            continue
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        sources: list[tuple[str, str]] = []
        conditions = kw.get("rule_conditions")
        for call in ast.walk(conditions) if conditions is not None else []:
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
                m = re.fullmatch(r"logsource_(windows|linux|macos)_([a-z_]+)", call.func.id)
                if m and not m.group(2).endswith("initiated"):
                    category = re.sub(r"^registry_(add|set|delete)$", "registry_event", m.group(2))
                    sources.append((OS_PLATFORM[m.group(1)], category))
        transformation = kw.get("transformation")
        if not (isinstance(transformation, ast.Call) and isinstance(transformation.func, ast.Name)):
            continue
        kind = transformation.func.id
        arg = transformation.args[0] if transformation.args else None
        if not isinstance(arg, ast.Dict):
            continue
        events: list[str] = []
        targets: list[str] = []
        for k, v in zip(arg.keys, arg.values, strict=True):
            if kind == "AddConditionTransformation" and isinstance(k, ast.Constant) and k.value == "#event_simpleName":
                events += _strings(v)
            elif kind == "FieldMappingTransformation":
                targets += _strings(v)
        for platform, category in sources:
            cat = cats[category]
            cat.events.update(events)
            cat.fields.update(targets)
            cat.platforms.add(platform)
    return dict(cats)


# --------------------------------------------------------------------------
# Events

EVENT_NAME = re.compile(r"^[A-Z][A-Za-z0-9_]+$")
PLATFORMS = ["Win", "Mac", "Lin", "K8S"]
PLATFORM_SPELLINGS = {p.lower(): p for p in PLATFORMS}
# Tutorial placeholders in the community queries, not Falcon events.
PLACEHOLDER_EVENTS = {"EventTypeA", "EventTypeB", "MyDetection", "MyEvent", "NetworkConnect", "RegGenericValue"}
# Capitalised words that query mining picks up from prose-like queries.
NOISE_FIELDS = {
    "Chrome", "Edge", "Firefox", "Safari", "Explorer", "Help", "One", "Optional", "Environment",
    "Configure", "Domains", "Process", "Execution", "Graph", "Last", "Count", "Event", "Run",
    "System", "Search", "User", "Customer", "Endpoints", "Tenant", "Unverified", "Actor",
}
LOWERCASE_FIELDS = {"aid", "cid", "aip", "event_platform", "name", "id", "timestamp"}
# Fields on (nearly) every sensor event. Each must be confirmed by Sentinel's
# raw FDR stream or the community queries; `build_events` checks.
COMMON_SENSOR_FIELDS = [
    "aid", "aip", "cid", "event_platform", "timestamp", "ContextTimeStamp", "name", "id",
    "ConfigBuild", "ConfigStateHash", "EffectiveTransmissionClass", "Entitlements", "EventOrigin",
]
QUERY_SOURCES = ("lcc", "queryhub", "cqlqueries")


def build_events(
    mined: dict[str, Mined], sentinel: Sentinel, sigma: dict[str, SigmaCategory]
) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    sigma_events: dict[str, SigmaCategory] = collections.defaultdict(SigmaCategory)
    for cat in sigma.values():
        for name in cat.events:
            sigma_events[name].fields |= cat.fields
            sigma_events[name].platforms |= cat.platforms
    vocab = set(sentinel.raw_columns) | {c for cols in sentinel.tables.values() for c, _ in cols}
    vocab |= {f for cat in sigma.values() for f in cat.fields}
    created: collections.Counter[str] = collections.Counter()
    for m in mined.values():
        created.update(m.created)

    names: dict[str, set[str]] = collections.defaultdict(set)
    for name in sentinel.event_table:
        names[name].add("sentinel")
    for name in sigma_events:
        names[name].add("pysigma")
    for source, m in mined.items():
        for name, ev in m.events.items():
            if ev.exact:
                names[name].add(source)
    # A name seen only inside a regex alternation counts once it is confirmed.
    for source, m in mined.items():
        for name in m.events:
            if name in names:
                names[name].add(source)
    lower = collections.defaultdict(list)
    for name in names:
        lower[name.lower()].append(name)
    rows: list[dict[str, Any]] = []
    event_set = set(names)

    def accept(f: str, count: int) -> bool:
        if f.startswith(("#", "@", "_")) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", f):
            return False
        known = f in vocab
        if known:
            return True
        if f in NOISE_FIELDS or f in event_set or created.get(f) or len(f) <= 2:
            return False
        if (re.search(r"_[a-z]", f) or f[0].islower()) and f not in LOWERCASE_FIELDS:
            return False
        return count >= 2

    for name in sorted(names):
        sources = names[name]
        if not EVENT_NAME.match(name) or name in PLACEHOLDER_EVENTS:
            continue
        # pySigma-only spellings that differ only in case from a confirmed name.
        if sources == {"pysigma"} and any(alt != name for alt in lower[name.lower()]):
            continue
        fields: set[str] = set()
        platforms: set[str] = set()
        mentions = 0
        for m in mined.values():
            ev = m.events.get(name)
            if ev is None:
                continue
            mentions += ev.mentions
            fields |= {f for f, c in ev.fields.items() if accept(f, c)}
            platforms |= {PLATFORM_SPELLINGS[p.lower()] for p in ev.platforms if p.lower() in PLATFORM_SPELLINGS}
        if name in sigma_events:
            fields |= sigma_events[name].fields
            platforms |= sigma_events[name].platforms
        row: dict[str, Any] = {"name": name}
        table = sentinel.event_table.get(name)
        if table:
            row["category"] = table_category(table)
        row["platforms"] = [p for p in PLATFORMS if p in platforms]
        row["fields"] = sorted(fields - set(COMMON_SENSOR_FIELDS) - {"event_simpleName"}, key=lambda f: (f.lower(), f))
        row["sources"] = sorted(sources)
        row["mentions"] = mentions
        rows.append(row)
    for f in COMMON_SENSOR_FIELDS:
        if f not in vocab and not any(m.read.get(f) for m in mined.values()):
            raise SystemExit(f"common sensor field {f} has no redistributable source")
    categories = {
        table_category(t): sorted((c for c, _ in cols), key=lambda f: (f.lower(), f))
        for t, cols in sorted(sentinel.tables.items())
    }
    return rows, categories


# --------------------------------------------------------------------------
# Fields and tags

@dataclass
class FieldRow:
    name: str
    layer: str  # logscale | falcon | cps
    kind: str  # metadata | tag | field | namespace
    type: str
    docs: str
    sources: list[str]
    scope: str = ""  # collector | ngsiem | parser (narrower than the layer)
    values_from: str = ""  # tag whose mined values become `values`
    fixed_values: list[str] = field(default_factory=list)


# Names are facts from library.humio.com ("Field Naming and Standards",
# "Backfilling Data", the CPS pages) and the public queries; `docs` is
# written for this catalog. `sources` names where each was confirmed.
BUILTIN_FIELDS = [
    FieldRow("@timestamp", "logscale", "metadata", "timestamp",
             "When the event happened, in milliseconds since the Unix epoch (UTC). Searches filter on it.",
             ["library.humio.com"]),
    FieldRow("@timestamp.nanos", "logscale", "metadata", "integer",
             "Nanoseconds beyond the millisecond of `@timestamp`, when the source has them.",
             ["library.humio.com"]),
    FieldRow("@ingesttimestamp", "logscale", "metadata", "timestamp",
             "When LogScale received the event, in epoch milliseconds. Correlation rules can schedule on it.",
             ["library.humio.com", "developer.crowdstrike.com"]),
    FieldRow("@rawstring", "logscale", "metadata", "string",
             "The event as it arrived, before parsing. Free-text search and most parsers read it.",
             ["library.humio.com"]),
    FieldRow("@id", "logscale", "metadata", "string",
             "Identifier LogScale gives each stored event.",
             ["library.humio.com"]),
    FieldRow("@timezone", "logscale", "metadata", "string",
             "Time zone of the source timestamp, when the parser could tell.",
             ["library.humio.com"]),
    FieldRow("@error_msg", "logscale", "metadata", "string",
             "Why parsing the event failed; can be an array (`@error_msg[0]`).",
             ["lcc"], scope="parser"),
    FieldRow("@event_parsed", "logscale", "metadata", "string",
             "Parser flag recording whether the event was parsed.",
             ["lcc"], scope="parser"),
    FieldRow("@source", "logscale", "metadata", "string",
             "Ingest source label set on the way in (for example by a data connector).",
             ["cqlqueries"], scope="collector"),
    FieldRow("@sourcetype", "logscale", "metadata", "string",
             "Source type label set at ingest.",
             ["cqlqueries", "lcc"], scope="collector"),
    FieldRow("@host", "logscale", "metadata", "string",
             "Host the shipper or collector sent the event from.",
             ["lcc"], scope="collector"),
    FieldRow("@dataConnectionID", "logscale", "metadata", "string",
             "Next-Gen SIEM data connector that brought the event in.",
             ["cqlqueries", "lcc"], scope="ngsiem"),
    FieldRow("@collect.channel", "logscale", "metadata", "string",
             "LogScale Collector source (channel) the event was read from.",
             ["lcc"], scope="collector"),
    FieldRow("@collect.host", "logscale", "metadata", "string",
             "Host name the LogScale Collector reports for itself.",
             ["lcc"], scope="collector"),
    FieldRow("@collect.timestamp", "logscale", "metadata", "timestamp",
             "When the LogScale Collector read the event.",
             ["lcc"], scope="collector"),
    FieldRow("#repo", "logscale", "tag", "string",
             "Repository that stores the event. A view such as search-all spans several.",
             ["library.humio.com", "lcc"], values_from="#repo"),
    FieldRow("#type", "logscale", "tag", "string",
             "Parser that ingested the event.",
             ["library.humio.com", "lcc"]),
    FieldRow("#humioBackfill", "logscale", "tag", "string",
             "Set at ingest on events whose timestamp is more than about a day old.",
             ["library.humio.com"]),
    FieldRow("#repo.cid", "falcon", "tag", "string",
             "Falcon customer ID (CID) of the repository; filters a multi-CID (MSSP) tenant.",
             ["lcc", "cqlqueries"], scope="ngsiem"),
    FieldRow("#event_simpleName", "falcon", "tag", "string",
             "Falcon event type, such as ProcessRollup2. FDR exports carry it as the plain field `event_simpleName`.",
             ["lcc", "queryhub", "cqlqueries", "sentinel", "pysigma"]),
    FieldRow("#cid", "falcon", "tag", "string",
             "Falcon customer ID of a sensor event; the field `cid` holds the same value.",
             ["lcc"]),
    FieldRow("#streamingApiEvent", "falcon", "tag", "string",
             "Streaming API type of a record in the detections repository, such as Event_EppDetectionSummaryEvent.",
             ["lcc"], values_from="#streamingApiEvent"),
    FieldRow("#kind", "falcon", "tag", "string",
             "Primary for sensor events, Secondary for lookup data such as aidmaster.",
             ["lcc"], values_from="#kind"),
    FieldRow("#data_source_name", "falcon", "tag", "string",
             "Lookup data set in sensor_metadata, such as aidmaster or cid_name.",
             ["lcc"], values_from="#data_source_name"),
    FieldRow("#data_source_group", "falcon", "tag", "string",
             "Group a sensor_metadata data set belongs to.",
             ["lcc"]),
    FieldRow("aid", "falcon", "field", "string",
             "Falcon agent ID: the sensor (host) that sent the event.",
             ["lcc", "sentinel"]),
    FieldRow("cid", "falcon", "field", "string",
             "Falcon customer ID of the sensor's tenant.",
             ["lcc", "sentinel"]),
    FieldRow("aip", "falcon", "field", "string",
             "The host's external IP address as the Falcon cloud saw it.",
             ["lcc", "sentinel"]),
    FieldRow("event_platform", "falcon", "field", "string",
             "Operating system family of the sensor: Win, Mac, Lin or K8S.",
             ["lcc", "sentinel", "pysigma"], values_from="event_platform"),
    FieldRow("ComputerName", "falcon", "field", "string",
             "Host name of the sensor. Many queries join it from aidmaster.",
             ["lcc", "pysigma"]),
    FieldRow("timestamp", "falcon", "field", "timestamp",
             "When the Falcon cloud received the event, in epoch milliseconds.",
             ["sentinel"]),
    FieldRow("ContextTimeStamp", "falcon", "field", "number",
             "When the sensor saw the activity, in epoch seconds with a fraction.",
             ["lcc", "sentinel"]),
    FieldRow("name", "falcon", "field", "string",
             "Internal name of the sensor event record.",
             ["sentinel"]),
    FieldRow("id", "falcon", "field", "string",
             "Unique ID of the sensor event.",
             ["sentinel"]),
    FieldRow("ConfigBuild", "falcon", "field", "string",
             "Sensor build and configuration version that produced the event.",
             ["lcc", "sentinel"]),
    FieldRow("ConfigStateHash", "falcon", "field", "string",
             "Hash of the sensor's configuration state.",
             ["sentinel"]),
    FieldRow("EffectiveTransmissionClass", "falcon", "field", "string",
             "How the sensor prioritised sending the event.",
             ["sentinel"]),
    FieldRow("Entitlements", "falcon", "field", "string",
             "Falcon modules the sensor was licensed for when it sent the event.",
             ["sentinel"]),
    FieldRow("EventOrigin", "falcon", "field", "string",
             "Which part of the sensor produced the event.",
             ["sentinel"]),
    FieldRow("ExternalApiType", "falcon", "field", "string",
             "Streaming API record type in the detections repository, such as Event_UserActivityAuditEvent.",
             ["lcc", "cqlqueries"]),
    FieldRow("#Vendor", "cps", "tag", "string",
             "Vendor of the data source in lower case (aws, microsoft, zscaler). Required by CPS.",
             ["library.humio.com", "lcc"], values_from="#Vendor"),
    FieldRow("#event.module", "cps", "tag", "string",
             "Product or service of the vendor (cloudtrail, azure, zia). Required by CPS.",
             ["library.humio.com", "lcc"], values_from="#event.module"),
    FieldRow("#event.dataset", "cps", "tag", "string",
             "Data set within the module, written `module.dataset`. Required by CPS.",
             ["library.humio.com", "lcc"]),
    FieldRow("#event.kind", "cps", "tag", "string",
             "ECS `event.kind` kept as a tag; event or alert in practice. Required by CPS.",
             ["library.humio.com", "lcc"], values_from="#event.kind"),
    FieldRow("#event.outcome", "cps", "tag", "string",
             "ECS `event.outcome` kept as a tag: success, failure or unknown. Required by CPS.",
             ["library.humio.com", "lcc"], fixed_values=["failure", "success", "unknown"]),
    FieldRow("#ecs.version", "cps", "tag", "string",
             "ECS version the parser maps to. Required by CPS.",
             ["library.humio.com", "cqlqueries"]),
    FieldRow("#Cps.version", "cps", "tag", "string",
             "CPS version the parser follows, capital C. Required by CPS.",
             ["library.humio.com", "cqlqueries"]),
    FieldRow("#observer.type", "cps", "tag", "string",
             "ECS `observer.type` kept as a tag (firewall, proxy, ...). Required by CPS.",
             ["library.humio.com", "cqlqueries"]),
    FieldRow("#error", "cps", "tag", "string",
             "true when a CPS parser could not parse the whole event.",
             ["lcc"], scope="parser"),
    FieldRow("Parser.version", "cps", "field", "string",
             "Version of the parser that produced the event (semver).",
             ["library.humio.com", "cqlqueries"]),
    FieldRow("Vendor", "cps", "namespace", "namespace",
             "Prefix of the vendor's own fields that ECS has no name for (`Vendor.<name>`). Any name is valid.",
             ["library.humio.com", "lcc"]),
]
# CrowdStrike-managed repositories `#repo` is compared with in the public
# queries; tenants name their own third-party repositories freely.
KNOWN_REPOS = {
    "base_sensor", "detections", "xdr_indicatorsrepo", "xdr_eventsarchive", "sensor_metadata",
    "falcon_for_it", "fcs_csp_events", "fusion", "3pi_connection_errors", "humio", "humio-audit",
    "humio-usage", "humio-fleet", "humio-measurements", "humio-activity",
}
# CPS writes `#Vendor` and `#event.module` in lower case.
LOWERCASE_VALUES = {"#Vendor", "#event.module"}
# ECS arrays that CPS stores as LogScale arrays (`event.category[0]`).
CPS_ARRAYS = {"event.category", "event.type", "event.kind"}
ECS_TYPES = {
    "keyword": "string", "constant_keyword": "string", "wildcard": "string", "text": "string",
    "match_only_text": "string", "long": "integer", "integer": "integer", "short": "integer",
    "byte": "integer", "unsigned_long": "integer", "float": "number", "double": "number",
    "scaled_float": "number", "half_float": "number", "boolean": "boolean", "ip": "ip",
    "date": "date", "object": "object", "flattened": "object", "nested": "object",
    "geo_point": "object", "binary": "string",
}


def export_keys(root: Path) -> str:
    """Field names of the Next-Gen SIEM search exports (`*.ndjson`) in a
    checkout: CQL-Queries ships a real one with the ingest metadata and tags."""
    keys: set[str] = set()
    for path in sorted(root.rglob("*.ndjson")):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict):
                keys.update(k for k in record if isinstance(k, str))
    return " ".join(sorted(keys))


def check_sources(evidence: dict[str, str]) -> None:
    """Every corpus a BUILTIN_FIELDS row cites must contain the name."""
    for f in BUILTIN_FIELDS:
        for source in f.sources:
            # Sentinel and pySigma use the FDR spelling: no `#` on a tag.
            name = f.name.lstrip("#") if source in ("sentinel", "pysigma") else f.name
            pattern = re.compile(r"(?<![\w.@#])" + re.escape(name) + r"(?![\w])")
            if source in evidence and not pattern.search(evidence[source]):
                raise SystemExit(f"BUILTIN_FIELDS {f.name} cites {source}, which never mentions it")


def build_fields(mined: dict[str, Mined], queries: list[Query]) -> tuple[list[dict[str, Any]], str]:
    tag_values: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    for m in mined.values():
        for tag, counts in m.tag_values.items():
            tag_values[tag].update(counts)
    rows: list[dict[str, Any]] = []
    for f in BUILTIN_FIELDS:
        row: dict[str, Any] = {"name": f.name, "layer": f.layer, "kind": f.kind, "type": f.type}
        if f.scope:
            row["scope"] = f.scope
        row["docs"] = f.docs
        values = list(f.fixed_values)
        if f.values_from:
            counts = tag_values.get(f.values_from, collections.Counter())
            ranked = [v for v, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
            if f.values_from == "#repo":
                values = [v for v in ranked if v in KNOWN_REPOS]
            elif f.values_from == "event_platform":
                values = [p for p in PLATFORMS if p in ranked]
            else:
                values = [v for v in ranked if counts[v] >= 2]
            if f.values_from in LOWERCASE_VALUES:
                values = [v for v in values if v == v.lower()]
        if values:
            row["values"] = values
        row["sources"] = f.sources
        rows.append(row)
    ecs = json.loads(ECS_CATALOG.read_text(encoding="utf-8"))
    ecs_types = {r["name"]: r["type"] for r in ecs["fields"]}
    # ECS names in the Next-Gen SIEM parsers and dashboards of the community
    # content (Unlicense, or the sub-package's licence).
    used: dict[str, set[str]] = collections.defaultdict(set)
    for q in queries:
        if not q.path.startswith(("Next-Gen-SIEM/", "Log-Sources/")):
            continue
        read, created = fields_in(strip_comments(q.text))
        for name in read | created:
            name = re.sub(r"\[\d*\]$", "", name.lstrip("#"))
            if name in ecs_types:
                used[name].add(q.source)
    builtin = {f.name.lstrip("#") for f in BUILTIN_FIELDS}
    for name in sorted(used):
        if name in builtin or name == "@timestamp":
            continue
        row = {"name": name, "layer": "cps", "kind": "field", "type": ECS_TYPES.get(ecs_types[name], "string")}
        if name in CPS_ARRAYS:
            row["type"] = "array<string>"
        row["ecs"] = True
        row["sources"] = ["ecs", *sorted(used[name])]
        rows.append(row)
    return rows, f"{ecs['source']} ({ecs.get('tag', '')})"


# --------------------------------------------------------------------------
# TOML output


def toml_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return toml_str(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(v) for v in value) + "]"
    raise TypeError(value)


def toml_entry(key: str, value: Any) -> list[str]:
    """`key = value`; a long list is wrapped, a few items per line."""
    line = f"{key} = {toml_value(value)}"
    if len(line) <= 100 or not isinstance(value, list):
        return [line]
    out = [f"{key} = ["]
    current = ""
    for item in (toml_value(v) + "," for v in value):
        if current and len(current) + 1 + len(item) > 96:
            out.append("    " + current)
            current = item
        else:
            current = f"{current} {item}" if current else item
    out += ["    " + current, "]"]
    return out


def toml_table(header: str, row: dict[str, Any]) -> list[str]:
    lines = [header]
    for key, value in row.items():
        if value is not None:
            lines += toml_entry(key, value)
    return lines


def git_rev(path: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(path), "log", "-1", "--format=%H %cs"],
            check=True, capture_output=True, text=True,
        ).stdout.split()
        return f"{out[0]} ({out[1]})"
    except (OSError, subprocess.CalledProcessError, IndexError):
        return "unknown"


def check_text(functions: list[Function]) -> None:
    names = {f.name for f in functions}
    for table in (FUNCTION_SUMMARIES, DEPRECATION_NOTES):
        extra = sorted(set(table) - names)
        if extra:
            raise SystemExit(f"hand-written text for functions the reference lacks: {extra}")
    for name in [*FUNCTION_FIXES, *EXTRA_PARAMS]:
        if name not in names:
            raise SystemExit(f"FUNCTION_FIXES entry {name} matches no function: drop it")
    for fix in PARAM_FIXES:
        fn = next((f for f in functions if f.name == fix[0]), None)
        if fn is None or all(p.name != fix[1] for p in fn.params):
            raise SystemExit(f"PARAM_FIXES entry {fix} matches no parameter: drop it")


def function_row(fn: Function, ngsiem: dict[str, str]) -> dict[str, Any]:
    if fn.name not in FUNCTION_SUMMARIES:
        raise SystemExit(f"write a FUNCTION_SUMMARIES entry for `{fn.name}`")
    docs = FUNCTION_SUMMARIES[fn.name]
    if len(docs) > 140:
        raise SystemExit(f"FUNCTION_SUMMARIES[{fn.name!r}] is longer than 140 characters")
    row: dict[str, Any] = {
        "name": fn.name,
        "aliases": [],
        "category": fn.category,
        "kind": fn.function_type,
        "aggregate": fn.aggregate,
        "signature": None if fn.removed else signature(fn),
        "docs": docs,
        "citation": fn.page if fn.removed else SITE + fn.page,
        "contexts": fn.contexts,
        "incompatible": fn.incompatible or None,
        "since": fn.since,
    }
    if fn.deprecated:
        row["deprecated"] = True
        row["deprecated_note"] = DEPRECATION_NOTES[fn.name]
    if fn.removed:
        row["removed"] = True
        row["removed_in"] = fn.removed_in
        row["replacement"] = fn.replacement
    if fn.experimental:
        row["experimental"] = True
    if fn.feature_flag:
        row["feature_flag"] = fn.feature_flag
    if fn.ngsiem_only:
        row["ngsiem"] = True
        row["logscale"] = False
        row["ngsiem_evidence"] = "library.humio.com: available only in Falcon Next-Gen SIEM"
    elif fn.name in ngsiem:
        row["ngsiem"] = True
        row["ngsiem_evidence"] = f"CrowdStrike/logscale-community-content {ngsiem[fn.name]}"
    if fn.name in UNAVAILABLE:
        row["unavailable"] = True
    return row


def param_row(p: Param) -> dict[str, Any]:
    return {
        "name": p.name,
        "type": p.type,
        "required": p.required,
        "unnamed": p.unnamed,
        "multi": p.multi,
        "query": p.query,
        "default": p.default,
        "values": p.values or None,
        "values_open": True if p.values_open else None,
        "deprecated_values": p.deprecated_values or None,
        "min": p.minimum,
        "max": p.maximum,
        "aliases": p.aliases or None,
        "deprecated": True if p.deprecated else None,
        "deprecated_since": p.deprecated_since,
    }


def write_functions(functions: list[Function], ngsiem: dict[str, str], cache: Path, lcc: Path) -> str:
    fetched = (cache / "FETCHED").read_text(encoding="utf-8").strip() if (cache / "FETCHED").is_file() else "unknown"
    out = [
        "# CQL functions, generated by scripts/sync_cql_catalog.py. Do not edit.",
        "# Facts only (names, parameters, types, defaults, values, bounds, lifecycle);",
        "# `docs` and `deprecated_note` are written for this catalog. Hover links to `citation`.",
        f"# Source: {SITE}functions.html and the pages it links",
        f"# (CrowdStrike Query Language {docs_version(cache)}, fetched {fetched}),",
        f"# and {RELEASE_NOTES} for removed functions.",
        f"# Source: CrowdStrike/logscale-community-content@{git_rev(lcc)} Next-Gen-SIEM/ (Unlicense) for `ngsiem`.",
        "# `ngsiem = true` means CrowdStrike's own Next-Gen SIEM content calls the function;",
        "# omitted means no evidence either way, never that it is unavailable.",
        "",
        *toml_entry("types", sorted(set(TYPE_MAP.values()))),
    ]
    for fn in functions:
        out.append("")
        out += toml_table("[[functions]]", function_row(fn, ngsiem))
        for p in fn.params:
            out.append("")
            out += toml_table("[[functions.parameters]]", param_row(p))
    return "\n".join(out) + "\n"


def write_events(rows: list[dict[str, Any]], categories: dict[str, list[str]], heads: dict[str, str]) -> str:
    out = [
        "# Falcon events (#event_simpleName), generated by scripts/sync_cql_catalog.py. Do not edit.",
        "# Names, platforms and fields are facts from public, redistributable sources only",
        "# (catalogs/cql/NOTICE). Elastic's integration (ELv2) is not a source.",
    ]
    out += [f"# Source: {name}@{rev}" for name, rev in heads.items()]
    out += [
        "# `fields`: what queries pinning the event read, and pySigma's field mappings: \"seen with\",",
        "# not the event schema. `category`: the Sentinel FDR table the event is routed to;",
        "# `categories` lists each table's columns. `common_fields` apply to every sensor event.",
        "# `mentions`: query blocks naming the event (for ranking). No list here is closed.",
        "",
        *toml_entry("platforms", PLATFORMS),
        *toml_entry("common_fields", COMMON_SENSOR_FIELDS),
    ]
    for name, cols in categories.items():
        out.append("")
        out += toml_table("[[categories]]", {"name": name, "fields": cols})
    for row in rows:
        out.append("")
        out += toml_table("[[events]]", row)
    return "\n".join(out) + "\n"


def write_fields(rows: list[dict[str, Any]], heads: dict[str, str], ecs: str) -> str:
    out = [
        "# CQL fields and tags, generated by scripts/sync_cql_catalog.py. Do not edit.",
        "# Layers: `logscale` (on every event or ingest route), `falcon` (Falcon platform data),",
        "# `cps` (third-party data parsed to the CrowdStrike Parsing Standard, ECS names at the root).",
        "# Names are facts from library.humio.com and the sources below; `docs` is written",
        "# for this catalog. Rows with `ecs = true` take their description from catalogs/ecs.",
    ]
    out += [f"# Source: {name}@{rev}" for name, rev in heads.items()]
    out += [
        f"# Source: {ecs} via catalogs/ecs/fields.json (Apache-2.0) for ECS types.",
        "# `values`: values the public queries compare the tag with (twice or more; for `#repo`, the",
        "# CrowdStrike-managed repositories among them). Completion only.",
        "# LogScale is schemaless: this is never a closed list.",
    ]
    for row in rows:
        out.append("")
        out += toml_table("[[fields]]", row)
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# Hand-written text. Every function needs a summary; the script refuses to
# write a catalog with a missing or over-long one.

DEPRECATION_NOTES: dict[str, str] = {
    "holtwinters": "Deprecated in 1.68 and announced for removal in 1.73; no replacement.",
    "lookup": "Removed; match() replaces it (strict=false keeps unmatched events, as lookup() did).",
    "lowercase": "Deprecated in queries; meant for parsers. Use lower() in a query.",
    "rdns": "Deprecated in 1.193, announced for removal in 1.249; use reverseDns().",
}
# Documented, but the reference says they are not released yet.
UNAVAILABLE: set[str] = {"math:spherical2cartesian"}
FUNCTION_SUMMARIES: dict[str, str] = {
    "accumulate": "Running aggregate over an ordered sequence: each event gets the aggregate of itself and the events before it.",
    "appendAggregation": "Keeps the input events and adds the result of an aggregation as extra rows after them, such as a totals row.",
    "array:append": "Adds one or more values to the end of a flat array field, creating the array when it does not exist.",
    "array:contains": "Keeps events whose flat array has an element equal to the given value.",
    "array:dedup": "Removes repeated values from a flat array, keeping the first occurrence of each in order.",
    "array:drop": "Removes every element field (`a[0]`, `a[1]`, ...) of the named array.",
    "array:eval": "Runs a function on each element of a flat array and writes the results to a new or the same array.",
    "array:exists": "Keeps events whose flat array has at least one element for which a condition holds.",
    "array:filter": "Keeps the elements of a flat array for which a filter function passes; element order is kept.",
    "array:intersection": "Aggregate: the values present in the named array of every input event (behind the ArrayFunctions flag).",
    "array:length": "Number of elements in a flat array, written to a field.",
    "array:reduceAll": "Aggregate: folds all elements of the named array, across all events, into one value with a function.",
    "array:reduceColumn": "Aggregate: for each array index, combines the elements at that index across events (experimental).",
    "array:reduceRow": "Reduces each event's array to one value with an aggregate function (experimental).",
    "array:regex": "Keeps events whose flat array has an element that matches a regular expression.",
    "array:rename": "Gives every element field of an array a new array name.",
    "array:sort": "Sorts a flat array as strings or numbers, ascending or descending, in place or into a new array.",
    "array:union": "Aggregate: every distinct value of the named array across the input events (experimental).",
    "asn": "Adds the autonomous system number and organisation of an IP address (MaxMind GeoLite2 data).",
    "avg": "Aggregate: arithmetic mean of a numeric field.",
    "base64Decode": "Decodes a Base64 field into text in a chosen character set.",
    "base64Encode": "Encodes a field's value as Base64.",
    "beta:param": "Copies the value of a query parameter into a field of each event (beta).",
    "beta:repeating": "Turns a live query into one rerun as a historical query at an interval (beta).",
    "bitfield:extractFlags": "Reads an integer as bit flags and writes one field per named bit.",
    "bitfield:extractFlagsAsArray": "Reads an integer as bit flags and lists the names of the set bits in an array.",
    "bitfield:extractFlagsAsString": "Reads an integer as bit flags and joins the names of the set bits into one string.",
    "bucket": "Aggregate: groups events into time buckets (and optional fields) and runs aggregate functions per bucket.",
    "callFunction": "Runs an aggregate function chosen by name (for example from a dashboard parameter) on a field.",
    "cidr": "Keeps events whose IP field lies in the given IPv4 or IPv6 subnets, listed inline or in a lookup file.",
    "coalesce": "The first of several expressions that is not missing (or empty, by default).",
    "collect": "Aggregate: gathers the values of fields from many events into one event, as multi-line text or rows.",
    "communityId": "Computes the Community ID flow hash from addresses, ports and protocol.",
    "concat": "Joins the values of several fields into one string field.",
    "concatArray": "Joins the elements of an array (`f[0]`, `f[1]`, ...) into one string, with optional prefix, separator and suffix.",
    "copyEvent": "Parser only: duplicates the event so the copy can be routed or tagged separately.",
    "correlate": "Finds groups of events matching several named subqueries linked by shared field values, optionally in order and within a time span.",
    "count": "Aggregate: number of events, of events with a field, or of distinct values of a field.",
    "counterAsRate": "Aggregate: per-second rate of change of an increasing counter field.",
    "createEvents": "Replaces the input with new events made from the given raw strings; handy for test data.",
    "crypto:md5": "MD5 hash of a field's value.",
    "crypto:sha1": "SHA-1 hash of a field's value.",
    "crypto:sha256": "SHA-256 hash of a field's value.",
    "default": "Sets a field to a value on events that lack it (or, optionally, have it empty).",
    "defineTable": "Runs a subquery in the preamble and keeps its results as a named in-memory table for match() and readFile().",
    "drop": "Removes the listed fields from each event.",
    "dropEvent": "In a parser, discards the event so it is not stored; in a search it acts like `false` and drops every event.",
    "duration": "Converts a relative time such as `5m` or `2d` into milliseconds.",
    "end": "Writes the end of the search time range, in epoch milliseconds, to a field.",
    "eval": "Assigns the result of an arithmetic or comparison expression to a field: `eval(f = a + b)`.",
    "eventFieldCount": "Number of fields the event stores internally, written to a field.",
    "eventInternals": "Adds fields that describe where LogScale stores the event.",
    "eventSize": "Bytes the event's values take in uncompressed storage, written to a field.",
    "explain:asTable": "Replaces the result with per-step profiling of the query (time, event counts, prefilters); experimental.",
    "fieldset": "Aggregate: lists the field names present in the events searched.",
    "fieldstats": "Aggregate: for each field in the events, how many events have it and how many distinct values it takes.",
    "findTimestamp": "Looks for a timestamp near the start of a field in several known formats and parses the first one found.",
    "format": "Builds a string from fields with a printf-style pattern.",
    "formatDuration": "Turns a duration number into readable text such as `1h 2m 3s`.",
    "formatTime": "Formats an epoch-millisecond field as text with a strftime-style pattern, time zone and locale.",
    "geography:distance": "Great-circle distance in metres between two latitude/longitude points.",
    "geohash": "Geohash of a latitude/longitude pair at a given precision.",
    "getField": "Reads the field whose name an expression computes at run time.",
    "groupBy": "Aggregate: one row per distinct combination of the grouping fields, with aggregate functions (count() by default).",
    "hash": "Non-cryptographic 32-bit hash of one or more fields; useful to bucket values.",
    "hashMatch": "Filter: keeps events where a salted secure hash of the input equals a hash stored by hashRewrite().",
    "hashRewrite": "Replaces a field (and optionally its text in @rawstring) with a salted secure hash.",
    "head": "Aggregate: the first N events in time order (oldest first).",
    "holtwinters": "Removed time-series forecasting function.",
    "if": "Inline conditional: the value of `then` when the condition holds, else the value of `else`.",
    "in": "Keeps events where a field equals one of the listed values (wildcards allowed, case optional).",
    "ioc:lookup": "Annotates IPs, domains or URLs found in CrowdStrike's threat intelligence, optionally keeping only matches.",
    "ipLocation": "Adds country, city, latitude and longitude for an IP address (MaxMind GeoLite2 data).",
    "join": "Runs a subquery and merges its matching rows into the main query's events on key fields.",
    "json:prettyPrint": "Reformats a JSON field with indentation for reading.",
    "kvParse": "Extracts `key=value` pairs from a field into fields.",
    "length": "Length of a string field in UTF-16 code units (Java characters).",
    "linReg": "Aggregate: least-squares line through two numeric fields: slope, intercept, adjusted R² and point count.",
    "lookup": "Removed lookup-file join; replaced by match().",
    "lower": "Lower-cases a string field's value.",
    "lowercase": "Parser function: lower-cases field names, values or both.",
    "match": "Joins events with a lookup file or ad-hoc table on a key column; by default drops events without a match.",
    "matchAsArray": "Like match(), but puts all matching table rows into an array of objects on the event.",
    "math:abs": "Absolute value of a number.",
    "math:arccos": "Arc cosine, in radians.",
    "math:arcsin": "Arc sine, in radians.",
    "math:arctan": "Arc tangent, in radians.",
    "math:arctan2": "Angle in radians of the point (x, y) from the positive x axis.",
    "math:ceil": "Smallest integer greater than or equal to the number.",
    "math:cos": "Cosine of an angle in radians.",
    "math:cosh": "Hyperbolic cosine.",
    "math:deg2rad": "Converts degrees to radians.",
    "math:exp": "e raised to the number.",
    "math:expm1": "e raised to the number, minus 1 (precise near zero).",
    "math:floor": "Largest integer less than or equal to the number.",
    "math:log": "Natural logarithm.",
    "math:log10": "Base-10 logarithm.",
    "math:log1p": "Natural logarithm of 1 plus the number (precise near zero).",
    "math:log2": "Base-2 logarithm.",
    "math:mod": "Floor modulus of a number by a divisor.",
    "math:pow": "A number raised to an exponent.",
    "math:rad2deg": "Converts radians to degrees.",
    "math:sin": "Sine of an angle in radians.",
    "math:sinh": "Hyperbolic sine.",
    "math:spherical2cartesian": "Converts spherical coordinates (radius, polar and azimuth angles) to x, y, z. Documented, not yet released.",
    "math:sqrt": "Square root.",
    "math:tan": "Tangent of an angle in radians.",
    "math:tanh": "Hyperbolic tangent.",
    "max": "Aggregate: largest value of a numeric field.",
    "min": "Aggregate: smallest value of a numeric field.",
    "neighbor": "In an ordered sequence, copies fields from the event a given distance before or after.",
    "now": "Writes the current time, in epoch milliseconds, to a field.",
    "objectArray:eval": "Runs a function on each element of an array of objects (or of arrays) and collects the results in a flat array.",
    "objectArray:exists": "Keeps events whose array of objects has an element for which a condition holds.",
    "parseCEF": "Parses a CEF (ArcSight Common Event Format) message into fields.",
    "parseCsv": "Splits a delimited line into the named column fields.",
    "parseFixedWidth": "Cuts a field into named columns of fixed character widths.",
    "parseHexString": "Decodes hexadecimal bytes into text in a chosen character set.",
    "parseInt": "Converts an integer written in another base (hex, octal, ...) to decimal.",
    "parseJson": "Parses a JSON field into fields, with dotted names for nesting and `[n]` for arrays.",
    "parseLEEF": "Parses an IBM LEEF 1.0 or 2.0 message into fields.",
    "parseTimestamp": "Parses a date/time text field with a format into epoch milliseconds, by default into @timestamp.",
    "parseUri": "Splits a URI field into scheme, host, port, path, query and other parts.",
    "parseUrl": "Splits a URL field into scheme, host, port, path, query and other parts.",
    "parseXml": "Parses an XML field into fields named after its element paths.",
    "partition": "In an ordered sequence, starts a new partition wherever a condition holds and aggregates each partition.",
    "percentage": "Aggregate: share of events, from 0 to 100, for which a condition holds.",
    "percentile": "Aggregate: approximate percentiles of a numeric field (50th, 75th and 99th by default).",
    "range": "Aggregate: difference between the largest and smallest value of a numeric field.",
    "rdns": "Removed reverse DNS lookup; replaced by reverseDns().",
    "readFile": "Source: emits the rows of a lookup file or ad-hoc table as events.",
    "readPersistedAggregation": "Source: emits the stored results of a persisted aggregation as events.",
    "regex": "Matches a regular expression against a field; named groups become fields, and non-matching events drop.",
    "remoteTable": "Next-Gen SIEM: runs a federated search on an external source and keeps the result as an ad-hoc table.",
    "rename": "Renames one or more fields.",
    "replace": "Replaces every regular expression match in a field with replacement text.",
    "reverseDns": "Looks up host names for IP addresses after the first aggregation, up to a limit.",
    "round": "Rounds a number to an integer, to nearest by default or by floor or ceiling.",
    "sample": "Keeps a random percentage of events; events without the sampled field (@timestamp by default) are dropped.",
    "sankey": "Aggregate: source-to-target flow totals shaped for the Sankey widget.",
    "select": "Keeps only the listed fields on each event, without aggregating.",
    "selectFromMax": "Aggregate: the event with the largest value of a field, with the chosen fields.",
    "selectFromMin": "Aggregate: the event with the smallest value of a field, with the chosen fields.",
    "selectLast": "Aggregate: the most recent value of each listed field.",
    "selfJoin": "Two-pass join of events sharing a key field where each `where` filter is met by some event of the key.",
    "selfJoinFilter": "Two-pass filter: finds key values for which every `where` filter matches some event, then keeps all events of those keys.",
    "series": "Aggregate: collects field values from successive events into one event per series, split by pauses or start/end matches.",
    "session": "Aggregate: splits events into sessions separated by gaps longer than maxpause and aggregates each.",
    "setField": "Writes a value to a field whose name an expression computes at run time.",
    "setTimeInterval": "Preamble: sets the query's own time range and time zone, overriding the UI or API.",
    "shannonEntropy": "Shannon entropy of a string's characters; high values hint at random-looking text.",
    "slidingTimeWindow": "In an ordered sequence, aggregates over the events within a time span before each event.",
    "slidingWindow": "In an ordered sequence, aggregates over a fixed number of events before each event.",
    "sort": "Aggregate: orders events by one or more fields and keeps the first N (200 by default).",
    "split": "Turns each element of a JSON array field into its own event.",
    "splitString": "Splits a string on a regular expression into an array, or keeps one element by index.",
    "start": "Writes the start of the search time range, in epoch milliseconds, to a field.",
    "stats": "Aggregate: runs several aggregate functions over the whole input and returns one row.",
    "stdDev": "Aggregate: standard deviation of a numeric field.",
    "stripAnsiCodes": "Removes ANSI escape sequences (colours, cursor moves) from a field.",
    "subnet": "Masks an IPv4 address to a prefix length, giving its network address.",
    "sum": "Aggregate: total of a numeric field.",
    "table": "Aggregate: a table of the listed fields for up to N events, sorted by a field.",
    "tail": "Aggregate: the last N events in time order (newest).",
    "test": "Keeps events for which a boolean expression is true; bare words in it are field names.",
    "text:contains": "True when a string contains a substring.",
    "text:editDistance": "Levenshtein distance between two strings, capped at a maximum.",
    "text:editDistanceAsArray": "Levenshtein distance from one string to each string in a list, as an array of objects.",
    "text:endsWith": "True when a string ends with a substring.",
    "text:length": "Length of a string in grapheme clusters (what a reader counts as characters).",
    "text:positionOf": "Position of the n-th occurrence of a character or substring in a string.",
    "text:startsWith": "True when a string starts with a substring.",
    "text:substring": "Part of a string between a begin and an end position.",
    "text:trim": "Removes Unicode whitespace from the start, the end or both ends of a string.",
    "time:dayOfMonth": "Day of the month (1-31) of a timestamp.",
    "time:dayOfWeek": "Day of the week of a timestamp, Monday 1 to Sunday 7.",
    "time:dayOfWeekName": "English name of the weekday of a timestamp.",
    "time:dayOfYear": "Day of the year (1-366) of a timestamp.",
    "time:hour": "Hour (0-23) of a timestamp.",
    "time:millisecond": "Millisecond part (0-999) of a timestamp.",
    "time:minute": "Minute (0-59) of a timestamp.",
    "time:month": "Month (1-12) of a timestamp.",
    "time:monthName": "English name of the month of a timestamp.",
    "time:second": "Second (0-59) of a timestamp.",
    "time:weekOfYear": "Week of the year (1-53) of a timestamp.",
    "time:year": "Year of a timestamp.",
    "timeChart": "Aggregate: buckets events over time, optionally per series field, for a time chart.",
    "tokenHash": "Hash that is the same for strings of similar structure; groups log lines by shape.",
    "top": "Aggregate: the most frequent values of fields, or the values with the largest total of another field.",
    "transpose": "Aggregate: swaps rows and columns of a table result.",
    "unit:convert": "Converts a number between units, such as milliseconds to seconds or KiB to bytes.",
    "upper": "Upper-cases a string field's value.",
    "urlDecode": "Decodes percent-encoding in a field.",
    "urlEncode": "Percent-encodes a field for use in a URL.",
    "wildcard": "Filter on a `*` pattern, in one field or in the raw event, optionally ignoring case.",
    "window": "Inside timeChart() or bucket(): aggregates over a number of preceding buckets.",
    "worldMap": "Aggregate: points from IPs or coordinates, geohashed and counted, for the World Map widget.",
    "writeJson": "Writes the fields matching the given names or `*` patterns to one field as a JSON object.",
    "xml:prettyPrint": "Reformats an XML field with indentation for reading.",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument("--cache", type=Path, required=True, help="library.humio.com page cache")
    parser.add_argument("--lcc", type=Path, required=True, help="CrowdStrike/logscale-community-content")
    parser.add_argument("--query-hub", type=Path, required=True, help="ByteRay-Labs/Query-Hub")
    parser.add_argument("--cql-queries", type=Path, required=True, help="cs-shadowbq/CQL-Queries")
    parser.add_argument("--sentinel", type=Path, required=True, help="Azure/Azure-Sentinel (CrowdStrike solution)")
    parser.add_argument("--pysigma", type=Path, required=True, help="SigmaHQ/pySigma-backend-crowdstrike")
    parser.add_argument("--offline", action="store_true", help="never fetch; fail on a missing page")
    parser.add_argument("--refresh", action="store_true", help="fetch every page again")
    parser.add_argument("--check", action="store_true", help="exit 1 when a file would change (offline)")
    args = parser.parse_args()

    fill_cache(args.cache, offline=args.offline or args.check, refresh=args.refresh and not args.check)
    functions = read_functions(args.cache)
    check_text(functions)
    lcc = read_corpus(args.lcc, "lcc", licences=True)
    queries = lcc + read_corpus(args.query_hub, "queryhub", False) + read_corpus(args.cql_queries, "cqlqueries", False)
    ngsiem = ngsiem_evidence(lcc, [f.name for f in functions if not f.removed])
    mined = mine(queries)
    events, categories = build_events(mined, read_sentinel(args.sentinel), read_pysigma(args.pysigma))
    heads = {
        "CrowdStrike/logscale-community-content": git_rev(args.lcc),
        "ByteRay-Labs/Query-Hub": git_rev(args.query_hub),
        "cs-shadowbq/CQL-Queries": git_rev(args.cql_queries),
        "Azure/Azure-Sentinel": git_rev(args.sentinel),
        "SigmaHQ/pySigma-backend-crowdstrike": git_rev(args.pysigma),
    }
    evidence = {
        key: "\n".join(q.text for q in queries if q.source.split("-")[0] == key) for key in QUERY_SOURCES
    }
    evidence["cqlqueries"] += "\n" + export_keys(args.cql_queries)
    fdr = args.sentinel / SENTINEL_SOLUTION / "CrowdStrikeS3FDR_ccp"
    evidence["sentinel"] = "\n".join(p.read_text(encoding="utf-8") for p in sorted(fdr.glob("*.json")))
    evidence["pysigma"] = (args.pysigma / PYSIGMA_PIPELINE).read_text(encoding="utf-8")
    check_sources(evidence)
    field_rows, ecs = build_fields(mined, lcc)
    files = {
        OUT / "functions.toml": write_functions(functions, ngsiem, args.cache, args.lcc),
        OUT / "events.toml": write_events(events, categories, heads),
        OUT / "fields.toml": write_fields(field_rows, heads, ecs),
    }
    stale = []
    for path, text in files.items():
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != text:
                stale.append(path)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {path.relative_to(ROOT)}", file=sys.stderr)
    for path in stale:
        print(f"stale: {path.relative_to(ROOT)}", file=sys.stderr)
    return 1 if stale else 0


if __name__ == "__main__":
    raise SystemExit(main())
