#!/usr/bin/env python3
"""Generate data/catalogs/yaral/udm.toml and data/catalogs/yaral/functions.toml.

YARA-L 2.0 (yara-l-1.0, RFC 0019 section 7) checks field paths against
Google's Unified Data Model and calls against Google's function list. Both
come from Google's pages, never from memory:

- the UDM field list, as Markdown: every message of the event model, the
  entity model, and their enumerated types
  (https://cloud.google.com/chronicle/docs/reference/udm-field-list);
- the `Collection` resource of the Chronicle API: the detection model a
  composite rule reads under `detection`
  (https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/Collection);
- the YARA-L functions page, as HTML, because its "Supported in" chips
  (Rules, Search, Dashboards) are left out of the Markdown export
  (https://cloud.google.com/chronicle/docs/yara-l/functions);
- the metrics functions page, for the `metrics.*` names
  (https://cloud.google.com/chronicle/docs/detection/metrics-functions).

`cloud.google.com/chronicle/docs` redirects to `docs.cloud.google.com`;
appending `.md.txt` to a page gives its Markdown source. The pages are
CC BY 4.0 (code samples Apache-2.0): the catalogues keep names, types and
availability, and each function's and field's first sentence for hover, with
the attribution in data/catalogs/yaral/NOTICE.

The UDM catalogue is a type graph, not a list of paths: `Process.parent_process`
is a `Process`, so the paths are unbounded. Each message lists its fields
(name, type, repeated, deprecated); a field whose type is an enumerated type
names it, and `[[enums]]` lists its values. `[roots]` names the message each
data source starts at (`udm` and a bare path: the event; `graph`: the entity;
`detection`: the collection).

Inputs (read as data, never executed): ``--cache DIR`` holds the pages; each is
fetched when missing, unless ``--offline`` or ``--check`` is given;
``--refresh`` fetches them again. The fetch date is kept in ``DIR/FETCHED``.

Usage:
    python -I scripts/engine/sync_yaral_catalogs.py --cache ../yaral-cache [--offline] [--check]

``--check`` regenerates in memory, makes no network request, and exits 1 when
a committed file differs. Standard library only.
"""

from __future__ import annotations

import argparse
import html
import re
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_UDM = ROOT / "catalogs" / "yaral" / "udm.toml"
OUT_FUNCTIONS = ROOT / "catalogs" / "yaral" / "functions.toml"
USER_AGENT = "opentide-language-server catalog sync"

DOCS = "https://docs.cloud.google.com/chronicle/docs"
PAGES = {
    "udm.md": f"{DOCS}/reference/udm-field-list.md.txt",
    "collection.md": f"{DOCS}/reference/rest/v1alpha/Collection.md.txt",
    "functions.html": f"{DOCS}/yara-l/functions",
    "metrics.md": f"{DOCS}/detection/metrics-functions.md.txt",
}
# The pages as the catalogues cite them (cloud.google.com redirects there).
CITED = {
    "udm.md": "https://cloud.google.com/chronicle/docs/reference/udm-field-list",
    "collection.md": "https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/Collection",
    "functions.html": "https://cloud.google.com/chronicle/docs/yara-l/functions",
    "metrics.md": "https://cloud.google.com/chronicle/docs/detection/metrics-functions",
}

# Protobuf well-known types the UDM page names without a table of their own.
WELL_KNOWN = {
    "google.protobuf.Timestamp": [("seconds", "int64"), ("nanos", "int32")],
    "google.protobuf.Duration": [("seconds", "int64"), ("nanos", "int32")],
    "google.type.Interval": [
        ("start_time", "google.protobuf.Timestamp"),
        ("end_time", "google.protobuf.Timestamp"),
    ],
    "google.type.LatLng": [("latitude", "double"), ("longitude", "double")],
}
SCALARS = {"string", "bool", "bytes", "int32", "int64", "uint32", "uint64", "double", "float"}
# A Struct's keys are the log's: `additional.fields["k"]`, never checked.
FREE = {"google.protobuf.Struct", "google.protobuf.Value", "google.protobuf.Any"}

# The aggregations of `outcome`, which the functions page leaves to the
# outcome and statistics pages. Rules: outcome-syntax "Aggregations"; search
# adds avg, stddev, earliest, latest (statistics-aggregations-in-udm-search).
OUTCOME = "https://cloud.google.com/chronicle/docs/yara-l/outcome-syntax"
STATISTICS = (
    "https://cloud.google.com/chronicle/docs/investigation/statistics-aggregations-in-udm-search"
)
AGGREGATIONS = [
    (
        "count",
        "count(value)",
        1,
        1,
        "INT",
        ["rules", "search", "dashboards"],
        OUTCOME,
        "Number of values in the match window or group.",
    ),
    (
        "count_distinct",
        "count_distinct(value)",
        1,
        1,
        "INT",
        ["rules", "search", "dashboards"],
        OUTCOME,
        "Number of distinct values in the match window or group.",
    ),
    (
        "sum",
        "sum(numeric_value)",
        1,
        1,
        "NUMBER",
        ["rules", "search", "dashboards"],
        OUTCOME,
        "Sum of the numeric values in the match window or group.",
    ),
    (
        "max",
        "max(value)",
        1,
        1,
        "NUMBER",
        ["rules", "search", "dashboards"],
        OUTCOME,
        "Largest value in the match window or group.",
    ),
    (
        "min",
        "min(value)",
        1,
        1,
        "NUMBER",
        ["rules", "search", "dashboards"],
        OUTCOME,
        "Smallest value in the match window or group.",
    ),
    (
        "array",
        "array(value)",
        1,
        1,
        "ARRAY",
        ["rules", "search", "dashboards"],
        OUTCOME,
        "The values, as a list: 25 in a rule, 1,000 in a search.",
    ),
    (
        "array_distinct",
        "array_distinct(value)",
        1,
        1,
        "ARRAY",
        ["rules", "search", "dashboards"],
        OUTCOME,
        "The distinct values, as a list: 25 in a rule, 1,000 in a search.",
    ),
    (
        "avg",
        "avg(numeric_value)",
        1,
        1,
        "FLOAT",
        ["search", "dashboards"],
        STATISTICS,
        "Average of the numeric values; in a rule, window.avg.",
    ),
    (
        "stddev",
        "stddev(numeric_value)",
        1,
        1,
        "FLOAT",
        ["search", "dashboards"],
        STATISTICS,
        "Standard deviation of the numeric values; in a rule, window.stddev.",
    ),
    (
        "earliest",
        "earliest(timestamp)",
        1,
        1,
        "TIMESTAMP",
        ["search", "dashboards"],
        STATISTICS,
        "Earliest timestamp of the group, in microseconds.",
    ),
    (
        "latest",
        "latest(timestamp)",
        1,
        1,
        "TIMESTAMP",
        ["search", "dashboards"],
        STATISTICS,
        "Latest timestamp of the group, in microseconds.",
    ),
]
# Functions the syntax pages use that the functions page has no entry for,
# each with its evidence.
EXTRA_FUNCTIONS = [
    # condition-syntax: "a list outcome is tested with arrays.contains".
    (
        "arrays.contains",
        "arrays.contains(array, value)",
        2,
        2,
        "BOOL",
        ["rules", "search", "dashboards"],
        "https://cloud.google.com/chronicle/docs/yara-l/condition-syntax",
        "Whether the list holds the value.",
    ),
    # outcome-syntax and troubleshoot-rule-errors cast UINT64 fields with it.
    (
        "cast.as_uint",
        "cast.as_uint(value)",
        1,
        1,
        "UINT",
        ["rules", "search"],
        "https://cloud.google.com/chronicle/docs/yara-l/outcome-syntax",
        "Casts a value to an unsigned integer.",
    ),
]
# Corrections where a signature line disagrees with its own description.
ARITY_FIXES = {
    # "should_ignore_zero_values" is optional in the description and in
    # window.avg's and window.range's signatures.
    "window.median": (1, 2),
    # "The default delimiter is a comma", with an example that omits it.
    "strings.split": (1, 2),
    # "rounded to the nearest integer or to the specified number of decimal
    # places", with `math.round(10.7)` and `math.round(4)` as examples.
    "math.round": (1, 2),
}
# Functions the functions page marks "Rules" only that Google's own searches
# call (yara-l-1.0 1.1, "Function catalogue"): investigation/multi-stage-yaral
# (`window.avg`, `window.stddev`, `window.median`), yara-l/transition_spl_yaral
# (`window.first`, `window.last`), reference/sample-yaral-for-native-dashboard
# (`window.avg`). Every `window.*` function is offered in search.
SEARCH_TOO = ("window.",)
AVAILABILITY = {"Rules": "rules", "Search": "search", "Dashboards": "dashboards"}
# Field names the Markdown export mangles: it reads `_key_` in
# `registry_key` as emphasis. The HTML page and Google's rules spell them so.
NAME_FIXES = {"registry*key*": "registry_key"}


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode("utf-8")


def load_pages(cache: Path, offline: bool, refresh: bool) -> tuple[dict[str, str], str]:
    cache.mkdir(parents=True, exist_ok=True)
    stamp = cache / "FETCHED"
    pages: dict[str, str] = {}
    fetched = False
    for name, url in PAGES.items():
        path = cache / name
        if refresh or not path.exists():
            if offline:
                sys.exit(f"{path} is missing and --offline/--check makes no request")
            path.write_text(fetch(url), encoding="utf-8")
            fetched = True
        pages[name] = path.read_text(encoding="utf-8")
    if fetched or not stamp.exists():
        stamp.write_text(time.strftime("%Y-%m-%d", time.gmtime()) + "\n", encoding="utf-8")
    return pages, stamp.read_text(encoding="utf-8").strip()


# ── UDM ──────────────────────────────────────────────────────────────────


def link_text(cell: str) -> str:
    """`[name](url)` → `name`; plain text as it is; Markdown escapes (`registry\\_key`) undone."""
    cell = cell.strip()
    found = re.match(r"^\[([^\]]+)\]\([^)]*\)(.*)$", cell)
    if found:
        cell = (found.group(1) + found.group(2)).strip()
    return re.sub(r"\\(.)", r"\1", cell)


def first_sentence(text: str) -> str:
    text = re.sub(r"<br\s*/?>", " ", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\s+", " ", text).strip().replace("\\", "")
    found = re.match(r"^(.+?\.)(\s|$)", text)
    sentence = found.group(1) if found else text
    return sentence if len(sentence) <= 200 else sentence[:197].rstrip() + "..."


def is_deprecated(name: str, description: str) -> bool:
    lowered = description.strip().lower()
    return (
        name.startswith("DEPRECATED_")
        or lowered.startswith("deprecated")
        or "this field is deprecated" in lowered
        or "is deprecated." in lowered
    )


def parse_udm(text: str) -> tuple[dict[str, list[dict]], dict[str, list[str]], dict[str, str]]:
    """Messages (name → fields), enums (name → values), and type summaries."""
    messages: dict[str, list[dict]] = {}
    enums: dict[str, list[str]] = {}
    summaries: dict[str, str] = {}
    current: str | None = None
    kind: str | None = None
    prose: list[str] = []
    for line in text.splitlines():
        heading = re.match(r"^(#{2,3}) (.+?)\s*$", line)
        if heading:
            title = heading.group(2).strip()
            if heading.group(1) == "##" and title == "UDM Event data model":
                current = "Event"
            elif heading.group(1) == "###":
                current = title
            else:
                current = None
            kind = None
            prose = []
            continue
        if current is None:
            continue
        if line.startswith("| Field Name |"):
            kind = "message"
            messages.setdefault(current, [])
            summaries.setdefault(current, first_sentence(" ".join(prose)))
            continue
        if line.startswith("| Enum Value |"):
            kind = "enum"
            enums.setdefault(current, [])
            continue
        if line.startswith("|---"):
            continue
        if kind is None and line.strip() and not line.startswith("|"):
            prose.append(line)
            continue
        if not line.startswith("|") or kind is None:
            if line.strip() == "<br />":
                kind = None
            continue
        cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
        if kind == "enum":
            value = cells[0].strip()
            if re.match(r"^[A-Z0-9_]+$", value):
                enums[current].append(value)
            continue
        if len(cells) < 4:
            continue
        name = link_text(cells[0])
        name = NAME_FIXES.get(name, name)
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
            sys.exit(f"{current}: field name {name!r} is not an identifier; add it to NAME_FIXES")
        type_cell = cells[1]
        enum = "(Enumerated list)" in type_cell
        type_name = link_text(type_cell.replace("(Enumerated list)", "").strip())
        label = cells[2].strip()
        description = " | ".join(cells[3:])
        messages[current].append(
            {
                "name": name,
                "type": type_name,
                "enum": enum,
                "repeated": label == "repeated",
                "deprecated": is_deprecated(name, description),
                "doc": first_sentence(description),
            }
        )
    return messages, enums, summaries


def snake(name: str) -> str:
    return re.sub(r"(?<!^)([A-Z])", r"_\1", name).lower()


def parse_collection(text: str) -> tuple[dict[str, list[dict]], dict[str, list[str]]]:
    """The detection model: `Collection` and its local types, snake_case fields."""
    messages: dict[str, list[dict]] = {}
    enums: dict[str, list[str]] = {}
    current = "Collection"
    table: str | None = None
    for line in text.splitlines():
        heading = re.match(r"^## (\w+)\s*$", line)
        if heading:
            current = f"Collection.{heading.group(1)}"
            table = None
            continue
        if line.startswith("| Fields |"):
            table = "fields"
            messages.setdefault(current, [])
            continue
        if line.startswith("| Enums |"):
            table = "enums"
            enums.setdefault(current, [])
            continue
        row = re.match(r"^\| `([A-Za-z0-9_]+)(\[\])?` \| (.*) \|\s*$", line)
        if not row or table is None:
            continue
        if table == "enums":
            enums[current].append(row.group(1))
            continue
        name, repeated, rest = row.group(1), bool(row.group(2)), row.group(3)
        typed = re.match(r"^``(\w+) \(`([^`]+)`(?: format)?\)``(.*)$", rest)
        if typed:
            kind, url, doc = typed.groups()
        else:
            plain = re.match(r"^`(\w+)`(.*)$", rest)
            kind, url, doc = (plain.group(1), "", plain.group(2)) if plain else ("string", "", rest)
        enum = kind == "enum"
        if kind == "string":
            type_name = {
                "#timestamp": "google.protobuf.Timestamp",
                "#duration": "google.protobuf.Duration",
            }.get(url[url.rfind("#") :] if "#" in url else "", "string")
        elif kind == "object" and url.endswith("#struct"):
            type_name = "google.protobuf.Struct"
        elif kind in ("object", "enum"):
            target = url.split("/reference/rest/", 1)[-1]
            page, _, anchor = target.partition("#")
            if page.endswith("/Collection") and anchor:
                type_name = f"Collection.{anchor}"
            else:
                shared = {
                    "Shared.Types/UDM": "Event",
                    "Shared.Types/Entity": "Entity",
                    "Shared.Types/SecurityResult": "SecurityResult",
                    "Shared.Types/Interval": "google.type.Interval",
                }
                type_name = anchor or shared.get(page, page.rsplit("/", 1)[-1])
        else:
            type_name = {"boolean": "bool", "integer": "int32", "number": "double"}.get(
                kind, "string"
            )
        messages[current].append(
            {
                "name": snake(name),
                "type": type_name,
                "enum": enum,
                "repeated": repeated,
                "deprecated": False,
                "doc": first_sentence(doc),
            }
        )
    return messages, enums


# ── Functions ────────────────────────────────────────────────────────────


def parse_functions(page: str, metrics: str) -> list[dict]:
    headings = list(re.finditer(r'<h3[^>]*id="([^"]+)"[^>]*>(.*?)</h3>', page, re.DOTALL))
    out: list[dict] = []
    for k, heading in enumerate(headings):
        end = (
            headings[k + 1].start()
            if k + 1 < len(headings)
            else page.find("devsite-content-footer", heading.end())
        )
        section = page[heading.end() : end if end > 0 else len(page)]
        title = html.unescape(re.sub(r"<[^>]+>", "", heading.group(2))).strip()
        chips = []
        for chip in re.findall(r'track-name="([A-Za-z]+)"', section.split("<h4", 1)[0]):
            if chip in AVAILABILITY and AVAILABILITY[chip] not in chips:
                chips.append(AVAILABILITY[chip])
        if title == "metrics":
            continue
        blocks = [
            html.unescape(re.sub(r"<[^>]+>", "", b)).strip()
            for b in re.findall(r"<pre[^>]*><code[^>]*>(.*?)</code></pre>", section, re.DOTALL)
        ]
        signature = next(
            (
                line.strip()
                for b in blocks
                for line in b.splitlines()
                if re.match(r"^[a-z_0-9.]+\s*\(", line.strip())
            ),
            "",
        )
        name = re.match(r"^([a-z_0-9.]+)\s*\(", signature).group(1)

        # Google numbers repeated heading ids: description, description_1, ...
        def para(h4: str, section: str = section) -> re.Match[str] | None:
            return re.search(
                rf'<h4 id="{h4}(?:_[0-9]+)?"[^>]*>.*?</h4>\s*<p>(.*?)</p>', section, re.DOTALL
            )

        description = para("description")
        params = para("param_data_types")
        result = para("return_type")

        def clean(m: re.Match[str] | None) -> str:
            return html.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip() if m else ""

        param_types = [p.strip() for p in re.split(r"[,\n]", clean(params)) if p.strip()]
        args = (
            signature[signature.index("(") + 1 : signature.rindex(")")] if ")" in signature else ""
        )
        min_args, max_args = arity(args)
        if name in ARITY_FIXES:
            min_args, max_args = ARITY_FIXES[name]
        out.append(
            {
                "name": name,
                "signature": re.sub(r"\)\)$", ")", signature),
                "min_args": min_args,
                "max_args": max_args,
                "params": param_types,
                "result": clean(result).split(" ")[0] if result else "",
                "availability": chips
                + (["search"] if name.startswith(SEARCH_TOO) and "search" not in chips else []),
                "summary": first_sentence(clean(description)),
                "url": f"{CITED['functions.html']}#{heading.group(1)}",
            }
        )
    # Every function the page documents, under its "Functions" heading, not
    # only those an example happens to call.
    documented = metrics.split("\n## Functions", 1)[-1]
    for fn in sorted(set(re.findall(r"`metrics\.([a-z_]+)`", documented))):
        out.append(
            {
                "name": f"metrics.{fn}",
                "signature": f"metrics.{fn}(period: <duration>, window: <window>, "
                "metric: <metric>, agg: <aggregation>, <udm field>: <value>, ...)",
                "min_args": 1,
                "max_args": None,
                "params": [],
                "result": "NUMBER",
                "availability": ["rules"],
                "summary": "A Risk Analytics metric over the period and window, "
                "aggregated as `agg` (named arguments).",
                "url": CITED["metrics.md"],
            }
        )
    for name, signature, lo, hi, result, availability, url, summary in (
        AGGREGATIONS + EXTRA_FUNCTIONS
    ):
        out.append(
            {
                "name": name,
                "signature": signature,
                "min_args": lo,
                "max_args": hi,
                "params": [],
                "result": result,
                "availability": availability,
                "summary": summary,
                "url": url,
                "aggregation": (name, signature) in [(a[0], a[1]) for a in AGGREGATIONS],
            }
        )
    seen: set[str] = set()
    unique = []
    for fn in out:
        if fn["name"] not in seen:
            seen.add(fn["name"])
            unique.append(fn)
    return sorted(unique, key=lambda f: f["name"])


def arity(args: str) -> tuple[int, int | None]:
    """Required and maximum arguments of a signature's parameter list."""
    args = args.strip()
    if not args:
        return 0, 0
    if "..." in args:
        required = len([a for a in args.split(",") if a.strip() and "..." not in a])
        return min(required, 1), None
    optional = 0
    required = 0
    # `[, x]` and `[, x=false]`: optional.
    bracket = re.findall(r"\[\s*,([^\]]*)\]", args)
    optional += sum(len([p for p in b.split(",") if p.strip()]) for b in bracket)
    args = re.sub(r"\[\s*,[^\]]*\]", "", args)
    for part in [p.strip() for p in args.split(",") if p.strip()]:
        if part.startswith("optional"):
            optional += 1
        else:
            required += 1
    return required, required + optional


# ── TOML ─────────────────────────────────────────────────────────────────


def q(value: str) -> str:
    value = re.sub(r"\s+", " ", value)
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_udm(messages: dict, enums: dict, summaries: dict, fetched: str) -> str:
    lines = [
        "# The Unified Data Model of Google Security Operations: the event model,",
        "# the entity model (under `graph`) and the detection model (under",
        "# `detection`), as a type graph. Generated by scripts/engine/sync_yaral_catalogs.py;",
        "# do not edit. CC BY 4.0, Google LLC (data/catalogs/yaral/NOTICE).",
        f"# Sources: {CITED['udm.md']}",
        f"#          {CITED['collection.md']}",
        f"# Fetched: {fetched}",
        "",
        "[meta]",
        f"sources = [{q(CITED['udm.md'])}, {q(CITED['collection.md'])}]",
        f"fetched = {q(fetched)}",
        "",
        "# The message each data source starts at.",
        "[roots]",
        'event = "Event"',
        'entity = "Entity"',
        'detection = "Collection"',
        "",
        "# Well-known types the page names without a table; keys under them are free.",
        f"free = [{', '.join(q(t) for t in sorted(FREE))}]",
        "",
    ]
    for name in sorted(messages):
        lines.append("[[types]]")
        lines.append(f"name = {q(name)}")
        if summaries.get(name):
            lines.append(f"doc = {q(summaries[name])}")
        lines.append("fields = [")
        for f in messages[name]:
            parts = [f"name = {q(f['name'])}", f"type = {q(f['type'])}"]
            if f["enum"]:
                parts.append("enum = true")
            if f["repeated"]:
                parts.append("repeated = true")
            if f["deprecated"]:
                parts.append("deprecated = true")
            if f["doc"]:
                parts.append(f"doc = {q(f['doc'])}")
            lines.append("  { " + ", ".join(parts) + " },")
        lines.append("]")
        lines.append("")
    for name in sorted(enums):
        lines.append("[[enums]]")
        lines.append(f"name = {q(name)}")
        lines.append("values = [")
        for value in enums[name]:
            lines.append(f"  {q(value)},")
        lines.append("]")
        lines.append("")
    return "\n".join(lines)


def render_functions(functions: list[dict], fetched: str) -> str:
    lines = [
        "# The YARA-L 2.0 functions of Google Security Operations, with their",
        "# arity, types, and where they are available. Generated by",
        "# scripts/engine/sync_yaral_catalogs.py; do not edit. CC BY 4.0, Google LLC",
        "# (data/catalogs/yaral/NOTICE).",
        f"# Sources: {CITED['functions.html']}",
        f"#          {CITED['metrics.md']}",
        f"#          {OUTCOME}",
        f"#          {STATISTICS}",
        f"# Fetched: {fetched}",
        "",
        "[meta]",
        f"sources = [{q(CITED['functions.html'])}, {q(CITED['metrics.md'])}, "
        f"{q(OUTCOME)}, {q(STATISTICS)}]",
        f"fetched = {q(fetched)}",
        "",
    ]
    for fn in functions:
        namespace, _, _short = fn["name"].rpartition(".")
        lines.append("[[functions]]")
        lines.append(f"name = {q(fn['name'])}")
        if namespace:
            lines.append(f"namespace = {q(namespace)}")
        lines.append(f"signature = {q(fn['signature'])}")
        lines.append(f"min_args = {fn['min_args']}")
        if fn["max_args"] is not None:
            lines.append(f"max_args = {fn['max_args']}")
        if fn["params"]:
            lines.append(f"params = [{', '.join(q(p) for p in fn['params'])}]")
        if fn["result"]:
            lines.append(f"result = {q(fn['result'])}")
        lines.append(f"availability = [{', '.join(q(a) for a in fn['availability'])}]")
        if fn.get("aggregation"):
            lines.append("aggregation = true")
        lines.append(f"summary = {q(fn['summary'])}")
        lines.append(f"url = {q(fn['url'])}")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    pages, fetched = load_pages(
        args.cache, args.offline or args.check, args.refresh and not args.check
    )

    messages, enums, summaries = parse_udm(pages["udm.md"])
    detection, detection_enums = parse_collection(pages["collection.md"])
    for name, fields in WELL_KNOWN.items():
        messages.setdefault(
            name,
            [
                {
                    "name": n,
                    "type": t,
                    "enum": False,
                    "repeated": False,
                    "deprecated": False,
                    "doc": "",
                }
                for n, t in fields
            ],
        )
    messages.update(detection)
    enums.update(detection_enums)
    # The page labels some message types "(Enumerated list)" (`attribute` of
    # Asset, Group, Resource and User is an `Attribute` message with fields):
    # a type with a field table is a message, whatever its label says.
    for fields in messages.values():
        for f in fields:
            if f["enum"] and f["type"] in messages and f["type"] not in enums:
                f["enum"] = False
    # Every type a field names is a message, an enum, a scalar, or free;
    # anything else is reported, so a page change is read by a person.
    unknown = sorted(
        {
            f["type"]
            for fields in messages.values()
            for f in fields
            if f["type"] not in messages
            and f["type"] not in enums
            and f["type"] not in SCALARS
            and f["type"] not in FREE
        }
    )
    if unknown:
        print(
            f"note: types without a table (paths under them are not checked): {', '.join(unknown)}",
            file=sys.stderr,
        )
    for root in ("Event", "Entity", "Collection", "Noun", "Metadata", "SecurityResult"):
        if root not in messages:
            sys.exit(f"the pages lost the {root} message")
    if "Metadata.EventType" not in enums or "PROCESS_LAUNCH" not in enums["Metadata.EventType"]:
        sys.exit("the UDM page lost Metadata.EventType")

    functions = parse_functions(pages["functions.html"], pages["metrics.md"])
    names = {f["name"] for f in functions}
    for expected in ("strings.to_lower", "re.regex", "window.avg", "math.round", "group", "count"):
        if expected not in names:
            sys.exit(f"the functions page lost {expected}")

    outputs = {
        OUT_UDM: render_udm(messages, enums, summaries, fetched),
        OUT_FUNCTIONS: render_functions(functions, fetched),
    }
    if args.check:
        stale = [
            p
            for p, text in outputs.items()
            if not p.exists() or p.read_text(encoding="utf-8") != text
        ]
        for p in stale:
            print(
                f"{p.relative_to(ROOT)} is stale; run scripts/engine/sync_yaral_catalogs.py",
                file=sys.stderr,
            )
        return 1 if stale else 0
    for path, text in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
