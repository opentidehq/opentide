#!/usr/bin/env python3
"""Generate catalogs/esql/*.toml from an Elasticsearch checkout.

Elasticsearch generates one JSON definition per ES|QL function and operator
(docs/reference/query-languages/esql/kibana/generated/x-pack-esql/definition)
and one docs layout per command and function. The layouts carry the
`applies_to` lifecycle (`stack: preview 9.2.0, ga 9.4.0`). This script copies
facts only: names, signatures, parameter names and types, return types,
lifecycle, licence tier, and the elastic.co page.

The docs on `main` only describe 9.x, so they cannot say what 8.19 or 9.0
lacks. Each row therefore also carries `versions`: the release branches on
which the name works on a release (non-snapshot) build.

- Functions and cast types come from each release branch's own generated
  definitions (`--branches`). A function that a release branch defines but
  `main` no longer does (`multi_match`) gets a row from the newest branch that
  has it, so the engine can say which versions accept it.
- Commands come from `COMMAND_VERSIONS` below, read off each branch's lexer
  and parser grammar: a `DEV_` token or a snapshot-only gate means absent.

Elastic's prose is not copied. The definitions come from Elastic License 2.0
code and the docs are AGPL/SSPL/ELv2, none of which this EUPL-1.2 repository
can take. Command and operator summaries below are written for this catalog;
hover links to Elastic's page for the full text.

Usage:
    python scripts/sync_esql_catalog.py --elasticsearch ../elasticsearch \
        --branches ../es-branches

The checkout only needs `docs/reference/query-languages/esql`. `--branches`
holds one directory per release branch in `BRANCHES` (`8.19/`, `9.0/`, ...),
each a sparse checkout of that branch's `docs/reference` (for example
`git clone --filter=blob:none --sparse -b 9.1 elasticsearch 9.1` and
`git sparse-checkout set docs/reference`). Record the commit printed on stdout
in the catalog header; the files are committed.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

DOCS = Path("docs/reference/query-languages/esql")
DEFINITIONS = DOCS / "kibana/generated/x-pack-esql/definition"
# `abs` lives in its own module (x-pack-esql-function-math); read every module.
FUNCTION_DEFINITIONS = "kibana/generated/*/definition/functions/*.json"
FUNCTION_LAYOUTS = "_snippets/generated/*/functions/layout"
COMMAND_LAYOUTS = DOCS / "_snippets/commands/layout"
SITE = "https://www.elastic.co/docs/reference/query-languages/esql"

# Release branches the presence matrix covers, oldest first. elastic-1.0
# supports Kibana 8.19 and 9.x; 8.19 shipped beside 9.1 and is not a superset
# of 9.0, so every branch is listed.
BRANCHES = ["8.19", "9.0", "9.1", "9.2", "9.3", "9.4", "9.5", "9.6"]

# Where each branch keeps its generated definitions. 8.19 mixes functions and
# operators in one directory; 9.0-9.4 split them; 9.5 and later add a module
# level. Paths are relative to the branch checkout.
BRANCH_FUNCTION_GLOBS = [
    "docs/reference/esql/functions/kibana/definition/*.json",
    "docs/reference/query-languages/esql/kibana/definition/functions/*.json",
    "docs/reference/query-languages/esql/kibana/generated/*/definition/functions/*.json",
]
BRANCH_CAST_GLOBS = [
    "docs/reference/esql/functions/kibana/inline_cast.json",
    "docs/reference/query-languages/esql/kibana/definition/inline_cast.json",
    "docs/reference/query-languages/esql/kibana/generated/*/definition/inline_cast.json",
]

# 9.0-9.2 ship no inline_cast.json. These are the `::type` names their
# EsqlDataTypeConverter maps to a conversion function, plus the aliases
# DataType.fromNameOrAlias accepts (`bool`, `int`, `string`, `date`).
# 9.0 has no `date` alias: a 9.0.8 server answers `null::date` with
# "Unknown data type named [date]" (scripts/oracles/elasticsearch/esql_catalog.py).
CASTS_WITHOUT_JSON = {
    "9.0": [
        "bool", "boolean", "cartesian_point", "cartesian_shape", "date_nanos",
        "date_period", "datetime", "double", "geo_point", "geo_shape", "int", "integer",
        "ip", "keyword", "long", "string", "time_duration", "unsigned_long", "version",
    ],
    "9.1": [
        "aggregate_metric_double", "bool", "boolean", "cartesian_point", "cartesian_shape",
        "date", "date_nanos", "date_period", "datetime", "double", "geo_point", "geo_shape",
        "int", "integer", "ip", "keyword", "long", "string", "time_duration",
        "unsigned_long", "version",
    ],
    "9.2": [
        "aggregate_metric_double", "bool", "boolean", "cartesian_point", "cartesian_shape",
        "date", "date_nanos", "date_period", "datetime", "dense_vector", "double",
        "geo_point", "geo_shape", "geohash", "geohex", "geotile", "int", "integer", "ip",
        "keyword", "long", "string", "time_duration", "unsigned_long", "version",
    ],
}


def since(version: str) -> list[str]:
    """9.x branches from `version` on (8.19 is listed separately)."""
    key = tuple(int(p) for p in version.split("."))
    return [b for b in BRANCHES if b != "8.19" and tuple(int(p) for p in b.split(".")) >= key]


# Release branches where each command works on a release build. Evidence is
# each branch's x-pack/plugin/esql/src/main/antlr lexer (a `DEV_` token is
# snapshot-only) plus the runtime gates noted.
COMMAND_VERSIONS = {
    **{name: BRANCHES for name in [
        "from", "row", "show", "where", "eval", "stats", "keep", "drop", "rename",
        "sort", "limit", "dissect", "grok", "enrich", "mv_expand", "lookup join",
    ]},
    # 8.19 and 9.1 have ungated tokens; 9.0 has DEV_CHANGE_POINT and no
    # COMPLETION or SAMPLE token.
    "change_point": ["8.19"] + since("9.1"),
    "completion": ["8.19"] + since("9.1"),
    "sample": ["8.19"] + since("9.1"),
    "fork": since("9.1"),
    # TS: DEV_TIME_SERIES and a snapshot check in LogicalPlanBuilder on 9.1.
    "ts": since("9.2"),
    "inline stats": since("9.2"),
    "inlinestats": since("9.2"),
    "rerank": since("9.2"),
    "fuse": since("9.2"),
    # SET: the 9.2 parser accepts setCommand only on snapshot builds.
    "set": since("9.3"),
    # PROMQL: DEV_PROMQL on 9.3.
    "promql": since("9.4"),
    "uri_parts": since("9.4"),
    "user_agent": since("9.4"),
    "registered_domain": since("9.4"),
    "metrics_info": since("9.4"),
    "ts_info": since("9.4"),
    "mmr": since("9.4"),
    "ip_location": since("9.5"),
    "ts_collapse": since("9.5"),
    # DEDUP and HIGHLIGHT are DEV_ tokens on 9.5.
    "dedup": since("9.6"),
    "highlight": since("9.6"),
    "dense_vector": since("9.6"),
    # Snapshot builds only on every release.
    "explain": [],
    "fillnull": [],
    "left join": [],
    "right join": [],
    "full join": [],
}

# Command layout file -> (canonical name, kind, docs page, summary). The docs
# pages are the elastic.co URLs; layout files are named a little differently.
# Summaries are this catalog's own words.
COMMANDS = {
    "from.md": ("from", "source", "commands/from",
        "Reads rows from indices, data streams, or aliases. `METADATA` adds metadata fields such as `_id`."),
    "ts.md": ("ts", "source", "commands/ts",
        "Reads time series indices and enables the time series aggregation functions."),
    "row.md": ("row", "source", "commands/row",
        "Produces a single row from literal values."),
    "show.md": ("show", "source", "commands/show",
        "Returns information about the deployment (`SHOW INFO`)."),
    "promql.md": ("promql", "source", "commands/promql",
        "Runs a PromQL expression over time series indices."),
    "set.md": ("set", "directive", "directives/set",
        "Sets a query setting before the query: `SET name = value;`."),
    "change_point.md": ("change_point", "processing", "commands/change-point",
        "Finds spikes, dips, and change points in a numeric column."),
    "completion.md": ("completion", "processing", "commands/completion",
        "Sends a prompt to an inference endpoint and stores the reply in a column."),
    "dedup.md": ("dedup", "processing", "commands/dedup",
        "Removes duplicate rows, keeping one row per distinct combination of values."),
    "dense_vector.md": ("dense_vector", "processing", "commands/dense-vector",
        "Computes vector embeddings for text columns through an inference endpoint."),
    "dissect.md": ("dissect", "processing", "commands/dissect",
        "Extracts columns from a string with a delimiter pattern."),
    "drop.md": ("drop", "processing", "commands/drop",
        "Removes columns."),
    "enrich.md": ("enrich", "processing", "commands/enrich",
        "Adds columns from an enrich policy, matched on a field."),
    "eval.md": ("eval", "processing", "commands/eval",
        "Adds or replaces columns computed from expressions."),
    "fork.md": ("fork", "processing", "commands/fork",
        "Runs several processing branches over the same rows and combines their output, tagged by `_fork`."),
    "fuse.md": ("fuse", "processing", "commands/fuse",
        "Merges rows from several result sets and scores them again."),
    "grok.md": ("grok", "processing", "commands/grok",
        "Extracts columns from a string with a grok pattern."),
    "highlight.md": ("highlight", "processing", "commands/highlight",
        "Adds snippets of the text that matched a full-text query, with the matches tagged."),
    "inlinestats-by.md": ("inline stats", "processing", "commands/inlinestats-by",
        "Computes aggregates per group and appends them to every input row; the rows are kept."),
    "ip_location.md": ("ip_location", "processing", "commands/ip-location",
        "Adds geolocation columns for an IP address."),
    "keep.md": ("keep", "processing", "commands/keep",
        "Keeps only the named columns, in that order."),
    "limit.md": ("limit", "processing", "commands/limit",
        "Caps the number of rows returned."),
    "lookup-join.md": ("lookup join", "processing", "commands/lookup-join",
        "Adds columns from a lookup-mode index for rows where the join condition matches."),
    "metrics-info.md": ("metrics_info", "processing", "commands/metrics-info",
        "Lists the metrics in the time series data streams the query reads."),
    "mmr.md": ("mmr", "processing", "commands/mmr",
        "Keeps a diverse subset of rows by maximal marginal relevance."),
    "mv_expand.md": ("mv_expand", "processing", "commands/mv_expand",
        "Turns a multivalued column into one row per value."),
    "registered_domain.md": ("registered_domain", "processing", "commands/registered-domain",
        "Splits a domain name into registered domain, subdomain, and suffix columns."),
    "rename.md": ("rename", "processing", "commands/rename",
        "Renames columns."),
    "rerank.md": ("rerank", "processing", "commands/rerank",
        "Scores rows again with an inference model against a query text."),
    "sample.md": ("sample", "processing", "commands/sample",
        "Keeps a random fraction of the rows."),
    "sort.md": ("sort", "processing", "commands/sort",
        "Orders rows by one or more expressions."),
    "stats-by.md": ("stats", "processing", "commands/stats-by",
        "Aggregates rows, optionally per group (`BY`); the output has one row per group."),
    "ts-info.md": ("ts_info", "processing", "commands/ts-info",
        "Lists the individual time series in the data streams the query reads."),
    "ts_collapse.md": ("ts_collapse", "processing", "commands/ts_collapse",
        "Collapses the per-step rows of PROMQL into one row per time series."),
    "uri_parts.md": ("uri_parts", "processing", "commands/uri-parts",
        "Splits a URI into scheme, host, path, query, and other columns."),
    "user_agent.md": ("user_agent", "processing", "commands/user-agent",
        "Parses a user-agent string into browser, operating system, and device columns."),
    "where.md": ("where", "processing", "commands/where",
        "Keeps the rows where a boolean expression is true."),
}

# Commands the grammar accepts that have no docs page: snapshot builds only
# (the lexer token is gated by isDevVersion()), or a retired spelling.
UNDOCUMENTED = [
    {
        "name": "explain",
        "kind": "source",
        "syntax": "EXPLAIN (query)",
        "docs": "Development command. Release builds reject it.",
        "stack": "",
        "snapshot_only": True,
    },
    {
        "name": "fillnull",
        "kind": "processing",
        "syntax": "FILLNULL value ON fields",
        "docs": "Development command. Release builds reject it.",
        "stack": "",
        "snapshot_only": True,
    },
    {
        "name": "left join",
        "kind": "processing",
        "syntax": "LEFT JOIN index ON condition",
        "docs": "Development join type. Release builds accept only LOOKUP JOIN.",
        "stack": "",
        "snapshot_only": True,
    },
    {
        "name": "right join",
        "kind": "processing",
        "syntax": "RIGHT JOIN index ON condition",
        "docs": "Development join type. Release builds accept only LOOKUP JOIN.",
        "stack": "",
        "snapshot_only": True,
    },
    {
        "name": "full join",
        "kind": "processing",
        "syntax": "FULL JOIN index ON condition",
        "docs": "Development join type. Release builds accept only LOOKUP JOIN.",
        "stack": "",
        "snapshot_only": True,
    },
    {
        "name": "inlinestats",
        "kind": "processing",
        "syntax": "INLINESTATS aggregates [BY groups]",
        "docs": "Earlier spelling of INLINE STATS, accepted while INLINE STATS was in technical preview.",
        "stack": "preview 9.2",
        "snapshot_only": False,
        "alias_of": "inline stats",
    },
]

# Registered aliases are not in the definition JSON
# (x-pack/plugin/esql/.../function/EsqlFunctionRegistry.java on 8.19; each
# function's DEFINITION on main).
ALIASES = {
    "bucket": ["bin"],
    "to_aggregate_metric_double": ["to_aggregatemetricdouble"],
    "to_boolean": ["to_bool"],
    "to_datetime": ["to_dt"],
    "to_date_nanos": ["to_datenanos"],
    "to_double": ["to_dbl"],
    "to_integer": ["to_int"],
    "to_string": ["to_str"],
    "to_unsigned_long": ["to_ulong", "to_ul"],
    "to_version": ["to_ver"],
}

APPLIES = re.compile(r"```(?:yaml )?\{applies_to\}\n(.*?)```", re.S)


def toml_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def stack_lifecycle(text: str) -> str:
    match = APPLIES.search(text)
    if not match:
        return ""
    for line in match.group(1).splitlines():
        key, _, value = line.partition(":")
        if key.strip() == "stack":
            return value.strip()
    return ""


def syntax_block(text: str) -> str:
    match = re.search(r"## Syntax.*?```esql\n(.*?)```", text, re.S)
    return match.group(1).strip() if match else ""


def toml_list(values: list[str]) -> str:
    return json.dumps(values)


def branch_functions(branches: Path) -> dict[str, dict[str, dict]]:
    """Function definitions per release branch, keyed by name."""
    found: dict[str, dict[str, dict]] = {}
    for branch in BRANCHES:
        root = branches / branch
        if not root.is_dir():
            raise SystemExit(f"--branches has no {branch}/ checkout")
        rows: dict[str, dict] = {}
        for pattern in BRANCH_FUNCTION_GLOBS:
            for path in root.glob(pattern):
                data = json.loads(path.read_text())
                if data.get("type") == "operator":
                    continue
                rows[data["name"]] = {**data, "_path": path}
        if not rows:
            raise SystemExit(f"no function definitions under {root}")
        found[branch] = rows
    return found


# Release lines where a live server accepts a function its branch's
# definitions omit or mark snapshot-only (scripts/oracles/elasticsearch/
# esql_catalog.py against the latest patch of each line): TO_TDIGEST is a
# 9.3 preview, WITHOUT ships in 9.4 time-series queries.
LIVE_FUNCTION_RELEASES = {
    "to_tdigest": ["9.3"],
    "without": ["9.4"],
}


def released_on(per_branch: dict[str, dict[str, dict]], name: str) -> list[str]:
    live = LIVE_FUNCTION_RELEASES.get(name, [])
    return [
        b for b in BRANCHES
        if b in live or (name in per_branch[b] and not per_branch[b][name].get("snapshot_only"))
    ]


def branch_casts(branches: Path) -> dict[str, dict[str, str]]:
    """`::type` name -> conversion function, per release branch."""
    found: dict[str, dict[str, str]] = {}
    for branch in BRANCHES:
        casts: dict[str, str] = {}
        for pattern in BRANCH_CAST_GLOBS:
            for path in (branches / branch).glob(pattern):
                casts.update({k: v.lower() for k, v in json.loads(path.read_text()).items()})
        if not casts:
            if branch not in CASTS_WITHOUT_JSON:
                raise SystemExit(f"no inline_cast.json for {branch} and no fallback list")
            casts = {name: "" for name in CASTS_WITHOUT_JSON[branch]}
        found[branch] = casts
    return found


def function_pages(es: Path) -> dict[str, str]:
    pages = {}
    root = es / DOCS / "functions-operators"
    for path in root.glob("*/*.md"):
        pages[path.stem] = f"{SITE}/functions-operators/{path.parent.name}/{path.stem}"
    return pages


def signature_label(name: str, params: list[dict], variadic: bool) -> str:
    parts = []
    for i, param in enumerate(params):
        label = param["name"]
        if variadic and i == len(params) - 1:
            label += ", ..."
        parts.append(f"[{label}]" if param.get("optional") else label)
    return f"{name.upper()}({', '.join(parts)})"


def merge_parameters(signatures: list[dict]) -> list[dict]:
    """One row per parameter name, in first-seen order, with the union of types."""
    rows: dict[str, dict] = {}
    for signature in signatures:
        for param in signature["params"]:
            row = rows.setdefault(
                param["name"],
                {
                    "name": param["name"],
                    "types": [],
                    "required": not param.get("optional", False),
                },
            )
            if param["type"] not in row["types"]:
                row["types"].append(param["type"])
            if param.get("optional"):
                row["required"] = False
    return list(rows.values())


def longest_signature(signatures: list[dict]) -> dict:
    return max(signatures, key=lambda s: len(s["params"]), default={"params": [], "variadic": False})


def write_functions(es: Path, branches: Path, out: Path, commit: str) -> int:
    pages = function_pages(es)
    per_branch = branch_functions(branches)
    lines = [
        "# ES|QL functions, generated by scripts/sync_esql_catalog.py. Do not edit.",
        "# Facts only (names, signatures, types, lifecycle); hover links to Elastic's page.",
        f"# Source: elastic/elasticsearch@{commit} {DOCS}/{FUNCTION_DEFINITIONS}",
        "# and the `applies_to` lifecycle in the function layout snippets.",
        "# `versions`: release branches whose own definitions list the function",
        "# (not snapshot-only). `docs` is written for this catalog.",
        "",
        f"branches = {toml_list(BRANCHES)}",
        "",
    ]
    definitions: dict[str, tuple[dict, str, Path | None]] = {}
    for path in (es / DOCS).glob(FUNCTION_DEFINITIONS):
        data = json.loads(path.read_text())
        layouts = list((es / DOCS).glob(f"{FUNCTION_LAYOUTS}/{data['name']}.md"))
        stack = stack_lifecycle(layouts[0].read_text()) if layouts else ""
        definitions[data["name"]] = (data, stack, path)
    # Functions a release accepts that main has dropped: newest branch's definition.
    for branch in reversed(BRANCHES):
        for name, data in per_branch[branch].items():
            if name not in definitions and released_on(per_branch, name):
                definitions[name] = (data, "", None)
    count = 0
    for name in sorted(definitions):
        data, stack, path = definitions[name]
        if name not in FUNCTION_SUMMARIES:
            raise SystemExit(f"write a FUNCTION_SUMMARIES entry for `{name}`")
        signatures = data.get("signatures", [])
        widest = longest_signature(signatures)
        returns = sorted({s.get("returnType", "") for s in signatures if s.get("returnType")})
        kind = "scalar" if data["type"] == "eval" else data["type"]
        lines += [
            "[[functions]]",
            f"name = {toml_str(name)}",
            f"kind = {toml_str(kind)}",
            f"signature = {toml_str(signature_label(name, widest['params'], widest.get('variadic', False)))}",
            f"docs = {toml_str(FUNCTION_SUMMARIES[name])}",
            f"returns = {json.dumps(returns)}",
            f"aliases = {json.dumps(ALIASES.get(name, []))}",
            f"stack = {toml_str(stack)}",
            f"versions = {toml_list(released_on(per_branch, name))}",
            f"preview = {str(bool(data.get('preview'))).lower()}",
            f"snapshot_only = {str(bool(data.get('snapshot_only'))).lower()}",
        ]
        if data.get("license"):
            lines.append(f"license = {toml_str(data['license'])}")
        if path is not None and name in pages:
            lines.append(f"citation = {toml_str(pages[name])}")
        lines.append("")
        for param in merge_parameters(signatures):
            lines += [
                "[[functions.parameters]]",
                f"name = {toml_str(param['name'])}",
                f"types = {json.dumps(param['types'])}",
                f"required = {str(param['required']).lower()}",
                "",
            ]
        count += 1
    out.write_text("\n".join(lines).rstrip() + "\n")
    return count


# Function summaries, written for this catalog (not Elastic's wording).
FUNCTION_SUMMARIES = {
    "abs": "Absolute value of a number.",
    "absent": "True when the expression has no non-null value in the current group.",
    "absent_over_time": "Per time series, true when a field has no value in the time window.",
    "acos": "Arc cosine, in radians.",
    "acosh": "Inverse hyperbolic cosine.",
    "asin": "Arc sine, in radians.",
    "asinh": "Inverse hyperbolic sine.",
    "atan": "Arc tangent, in radians.",
    "atan2": "Angle in radians of the point (x, y) from the positive x axis; takes y first.",
    "atanh": "Inverse hyperbolic tangent.",
    "avg": "Mean of a numeric expression.",
    "avg_over_time": "Per time series, the mean of a numeric field over the time window.",
    "bit_length": "Length of a string in bits.",
    "bucket": "Groups dates or numbers into fixed-size buckets, given a size or a target count and range.",
    "byte_length": "Length of a string in bytes (UTF-8).",
    "case": "Returns the value paired with the first true condition, or the trailing default.",
    "categorize": "Groups text values into categories of similar messages.",
    "cbrt": "Cube root; always returns a double.",
    "ceil": "Rounds a number up to the next whole number.",
    "chunk": "Splits text into smaller pieces, for example for embedding.",
    "cidr_match": "True when an IP address falls in any of the given CIDR blocks.",
    "clamp": "Limits each value to the range between a minimum and a maximum.",
    "clamp_max": "Caps each value at an upper bound.",
    "clamp_min": "Raises each value to at least a lower bound.",
    "coalesce": "First argument that is not null; null when all are.",
    "concat": "Joins two or more strings.",
    "contains": "True when a string contains a substring.",
    "copy_sign": "First argument's magnitude with the second argument's sign.",
    "cos": "Cosine of an angle in radians.",
    "cosh": "Hyperbolic cosine.",
    "count": "Number of non-null values; `COUNT(*)` or `COUNT()` counts rows.",
    "count_distinct": "Approximate number of distinct values, with optional precision.",
    "count_distinct_over_time": "Per time series, approximate distinct values of a field over the time window.",
    "count_over_time": "Per time series, number of values of a field over the time window.",
    "date_diff": "Difference between two dates in a given unit (end minus start).",
    "date_extract": "One component of a date, such as the year or the hour of day.",
    "date_format": "Formats a date as a string with a pattern.",
    "date_parse": "Parses a string into a date with a pattern.",
    "date_trunc": "Rounds a date down to a time interval.",
    "date_unit_count": "How many of one calendar unit fit in the enclosing larger unit for a date.",
    "day": "Day of the month (1-31) of a date, in the query time zone.",
    "day_name": "Weekday name of a date.",
    "decay": "Score that falls off with distance from an origin value, using a decay function.",
    "delta": "Per time series, the change of a gauge over the time window.",
    "deriv": "Per time series, the rate of change of a numeric field, by linear regression.",
    "e": "Euler's number.",
    "earliest": "Value of a field at the earliest `@timestamp` in the group.",
    "embedding": "Dense vector embedding of the input from an inference endpoint.",
    "ends_with": "True when a string ends with a suffix.",
    "exp": "e raised to a power.",
    "field_extract": "One sub-field of a `flattened` field, as a keyword.",
    "first": "Value of a field on the row where a sort field is lowest.",
    "first_over_time": "Per time series, the earliest value of a field in the time window.",
    "floor": "Rounds a number down to the previous whole number.",
    "from_base64": "Decodes a base64 string.",
    "greatest": "Largest of several values, compared across columns.",
    "hash": "Hash of a string with a named algorithm (MD5, SHA-1, SHA-256, ...).",
    "hour": "Hour of the day (0-23) of a date, in the query time zone.",
    "hypot": "Length of the hypotenuse for two sides.",
    "idelta": "Per time series, the change of a gauge between its last two samples in the window.",
    "increase": "Per time series, how much a counter grew over the time window.",
    "ip_prefix": "Truncates an IP address to a prefix length (separate IPv4 and IPv6 lengths).",
    "irate": "Per time series, the per-second rate of a counter from its last two samples.",
    "json_extract": "Value at a JSONPath-style path in a JSON string.",
    "json_string": "Builds a JSON object string from key/value pairs.",
    "knn": "Nearest-neighbour vector search on a dense vector field; true for matching rows.",
    "kql": "True when the row matches a Kibana KQL query string.",
    "last": "Value of a field on the row where a sort field is highest.",
    "last_over_time": "Per time series, the latest value of a field in the time window.",
    "latest": "Value of a field at the latest `@timestamp` in the group.",
    "least": "Smallest of several values, compared across columns.",
    "left": "First N characters of a string.",
    "length": "Number of characters in a string.",
    "locate": "1-based position of a substring in a string, or 0 when absent.",
    "log": "Logarithm of a number in a given base (natural log with one argument).",
    "log10": "Base-10 logarithm.",
    "ltrim": "Removes leading whitespace.",
    "match": "Full-text match query on a field; true for matching rows.",
    "match_phrase": "Phrase query on a field; true for matching rows.",
    "max": "Largest value.",
    "max_over_time": "Per time series, the largest value of a field over the time window.",
    "md5": "MD5 hash of a string, as hex.",
    "median": "Median (50th percentile) of a numeric expression, approximate.",
    "median_absolute_deviation": "Median absolute deviation, a spread measure robust to outliers.",
    "min": "Smallest value.",
    "min_over_time": "Per time series, the smallest value of a field over the time window.",
    "month": "Month (1-12) of a date, in the query time zone.",
    "month_name": "Month name of a date.",
    "multi_match": "Full-text match of one query across several fields (removed after 9.3).",
    "mv_append": "Joins the values of two multivalued expressions into one.",
    "mv_avg": "Mean of the values of a multivalued number.",
    "mv_concat": "Joins the values of a multivalued string with a separator.",
    "mv_contains": "True when every value of the second expression appears in the first.",
    "mv_count": "Number of values in a multivalued expression.",
    "mv_dedupe": "Removes duplicate values from a multivalued expression.",
    "mv_difference": "Values of the first multivalued expression that are not in the second.",
    "mv_first": "First value of a multivalued expression.",
    "mv_greater": "True when any value is greater than a bound.",
    "mv_in_range": "True when any value lies between a lower and an upper bound.",
    "mv_intersection": "Values present in both multivalued expressions.",
    "mv_intersects": "True when the two multivalued expressions share any value.",
    "mv_last": "Last value of a multivalued expression.",
    "mv_less": "True when any value is less than a bound.",
    "mv_like": "True when any value matches a LIKE wildcard pattern.",
    "mv_max": "Largest value of a multivalued expression.",
    "mv_median": "Median of the values of a multivalued number.",
    "mv_median_absolute_deviation": "Median absolute deviation of the values of a multivalued number.",
    "mv_min": "Smallest value of a multivalued expression.",
    "mv_percentile": "Percentile of the values of a multivalued number.",
    "mv_pseries_weighted_sum": "Sum of the values weighted by a p-series (value i divided by i^p).",
    "mv_rlike": "True when any value matches an RLIKE regular expression.",
    "mv_slice": "Values between a start and an end index (0-based) of a multivalued expression.",
    "mv_sort": "Sorts the values of a multivalued expression, ascending or descending.",
    "mv_sum": "Sum of the values of a multivalued number.",
    "mv_union": "Distinct values from either multivalued expression.",
    "mv_zip": "Pairs the values of two multivalued strings, joining each pair with a separator.",
    "network_direction": "Traffic direction (inbound, outbound, internal, external) from two IPs and the internal networks.",
    "now": "Current date and time.",
    "percentile": "Value below which a given percentage of values fall, approximate.",
    "percentile_over_time": "Per time series, a percentile of a field over the time window.",
    "pi": "The constant pi.",
    "pow": "A base raised to an exponent.",
    "present": "True when the expression has a non-null value in the current group.",
    "present_over_time": "Per time series, true when a field has a value in the time window.",
    "qstr": "True when the row matches a Lucene query string.",
    "range_contains": "True when the first range contains the second value or range.",
    "range_intersects": "True when two ranges, or a range and a value, overlap.",
    "range_max": "Upper (exclusive) bound of a range.",
    "range_min": "Lower (inclusive) bound of a range.",
    "range_within": "True when the first value or range lies inside the second range.",
    "rate": "Per time series, the per-second rate of a counter over the time window, allowing for resets.",
    "repeat": "A string repeated N times.",
    "replace": "Replaces every match of a regular expression in a string.",
    "reverse": "A string with its characters in reverse order.",
    "right": "Last N characters of a string.",
    "round": "Rounds a number to a number of decimal places (0 by default).",
    "round_to": "Rounds down to the nearest of a list of fixed points.",
    "rtrim": "Removes trailing whitespace.",
    "sample": "A random sample of up to N values.",
    "scalb": "A number multiplied by 2 raised to an integer power.",
    "score": "Relevance score of the full-text functions in an expression.",
    "sha1": "SHA-1 hash of a string, as hex.",
    "sha256": "SHA-256 hash of a string, as hex.",
    "signum": "Sign of a number: -1, 0, or 1.",
    "sin": "Sine of an angle in radians.",
    "sinh": "Hyperbolic sine.",
    "space": "A string of N spaces.",
    "sparkline": "Series of an aggregation over time buckets, for a sparkline chart.",
    "split": "Splits a string on a delimiter into a multivalued string.",
    "sqrt": "Square root; always returns a double.",
    "st_buffer": "Geometry grown (or shrunk) by a distance around the input.",
    "st_centroid_agg": "Centroid of all spatial values in the group.",
    "st_contains": "True when the first geometry contains the second.",
    "st_difference": "Part of the first geometry not covered by the second.",
    "st_dimension": "Topological dimension of a geometry: 0 points, 1 lines, 2 areas.",
    "st_disjoint": "True when two geometries share no point.",
    "st_distance": "Distance between two points (metres for geo, units for cartesian).",
    "st_envelope": "Bounding box of a geometry.",
    "st_extent_agg": "Bounding box of all spatial values in the group.",
    "st_geohash": "Geohash cell of a geo point (or the cells a geo shape covers) at a precision.",
    "st_geohex": "H3 cell of a geo point (or the cells a geo shape covers) at a precision.",
    "st_geometrytype": "Geometry type name, such as `ST_Point` or `ST_Polygon`.",
    "st_geotile": "Map tile of a geo point (or the tiles a geo shape covers) at a zoom precision.",
    "st_intersection": "Shared part of two geometries.",
    "st_intersects": "True when two geometries share any point.",
    "st_isempty": "True when a geometry has no points.",
    "st_npoints": "Number of points in a geometry.",
    "st_simplify": "Geometry simplified with the Douglas-Peucker algorithm at a tolerance.",
    "st_simplifypreservetopology": "Geometry simplified at a tolerance without breaking its topology.",
    "st_symdifference": "Parts of two geometries that are not shared.",
    "st_union": "Geometry covering both inputs.",
    "st_within": "True when the first geometry lies within the second.",
    "st_x": "x coordinate (longitude for geo) of a point.",
    "st_xmax": "Largest x coordinate (longitude for geo) of a geometry.",
    "st_xmin": "Smallest x coordinate (longitude for geo) of a geometry.",
    "st_y": "y coordinate (latitude for geo) of a point.",
    "st_ymax": "Largest y coordinate (latitude for geo) of a geometry.",
    "st_ymin": "Smallest y coordinate (latitude for geo) of a geometry.",
    "starts_with": "True when a string starts with a prefix.",
    "std_dev": "Population standard deviation of a numeric expression.",
    "stddev_over_time": "Per time series, the population standard deviation of a field over the time window.",
    "substring": "Part of a string from a 1-based start position, with an optional length.",
    "sum": "Sum of a numeric expression.",
    "sum_over_time": "Per time series, the sum of a field over the time window.",
    "tan": "Tangent of an angle in radians.",
    "tanh": "Hyperbolic tangent.",
    "tau": "The constant tau (2 pi).",
    "tbucket": "Groups `@timestamp` into buckets of a fixed span or a target count.",
    "text_embedding": "Dense vector embedding of text from an inference endpoint.",
    "to_aggregate_metric_double": "Converts a number to an `aggregate_metric_double`.",
    "to_base64": "Encodes a string as base64.",
    "to_boolean": "Converts a value to a boolean; the string `true` in any case is true.",
    "to_cartesianpoint": "Converts a value (such as WKT text) to a `cartesian_point`.",
    "to_cartesianshape": "Converts a value (such as WKT text) to a `cartesian_shape`.",
    "to_counter": "Converts a number to the matching counter type.",
    "to_date_nanos": "Converts a value to a nanosecond-precision date.",
    "to_date_range": "Converts a value (such as `start..end` text) to a `date_range`.",
    "to_dateperiod": "Converts a value to a `date_period` (calendar span).",
    "to_datetime": "Converts a value (ISO 8601 text or epoch milliseconds) to a date.",
    "to_degrees": "Converts radians to degrees.",
    "to_dense_vector": "Converts numbers or a hex string to a `dense_vector`.",
    "to_double": "Converts a value to a double; dates become epoch milliseconds.",
    "to_double_range": "Converts a value (such as `start..end` text) to a `double_range`.",
    "to_exponential_histogram": "Converts histogram-like values to an exponential histogram.",
    "to_gauge": "Converts a counter to its plain numeric type.",
    "to_geohash": "Converts a value to a `geohash` cell.",
    "to_geohex": "Converts a value to a `geohex` (H3) cell.",
    "to_geopoint": "Converts a value (such as WKT text) to a `geo_point`.",
    "to_geoshape": "Converts a value (such as WKT text) to a `geo_shape`.",
    "to_geotile": "Converts a value to a `geotile` cell.",
    "to_integer": "Converts a value to an integer, with an optional base for strings.",
    "to_ip": "Converts a string to an IP address.",
    "to_long": "Converts a value to a long, with an optional base for strings.",
    "to_lower": "Lower-cases a string.",
    "to_radians": "Converts degrees to radians.",
    "to_range": "Builds a range from an inclusive lower and an exclusive upper bound.",
    "to_string": "Converts a value to a keyword string.",
    "to_tdigest": "Converts histogram values to a t-digest.",
    "to_text": "Converts a value to `text`.",
    "to_timeduration": "Converts a value to a `time_duration` (fixed span).",
    "to_unsigned_long": "Converts a value to an unsigned long.",
    "to_upper": "Upper-cases a string.",
    "to_version": "Converts a string to a `version`, which sorts by semantic version.",
    "top": "The top N values of a field, in ascending or descending order.",
    "top_snippets": "Best-matching snippets of a text field for a query.",
    "trange": "True when `@timestamp` lies in a time range (absolute, or an offset from now).",
    "trim": "Removes leading and trailing whitespace.",
    "tstep": "Groups `@timestamp` into fixed-step buckets aligned to a range.",
    "url_decode": "Decodes a percent-encoded URL string.",
    "url_encode": "Percent-encodes a string for a URL, with spaces as `+`.",
    "url_encode_component": "Percent-encodes a string for a URL component, with spaces as `%20`.",
    "v_cosine": "Cosine similarity of two dense vectors.",
    "v_dot_product": "Dot product of two dense vectors.",
    "v_hamming": "Hamming distance between two dense vectors.",
    "v_l1_norm": "L1 (Manhattan) distance between two dense vectors.",
    "v_l2_norm": "L2 (Euclidean) distance between two dense vectors.",
    "v_magnitude": "Magnitude (length) of a dense vector.",
    "values": "All distinct values in the group, as a multivalued field in no fixed order.",
    "variance": "Population variance of a numeric expression.",
    "variance_over_time": "Per time series, the population variance of a field over the time window.",
    "weighted_avg": "Weighted mean of a numeric expression.",
    "without": "Groups time series by every dimension except the named ones.",
    "year": "Year of a date, in the query time zone.",
}


OPERATOR_SUMMARIES = {
    "add": "Addition. Also adds a time span to a date.",
    "cast": "Converts a value to the named type: `value::type`.",
    "div": "Division. Integer division truncates.",
    "equals": "Equality.",
    "greater_than": "Greater than.",
    "greater_than_or_equal": "Greater than or equal.",
    "in": "True when the value equals any value in the list.",
    "is_not_null": "True when the value is not null.",
    "is_null": "True when the value is null.",
    "less_than": "Less than.",
    "less_than_or_equal": "Less than or equal.",
    "like": "Wildcard match: `*` is any characters, `?` is one character.",
    "match_operator": "Full-text match of a field against a query string: `field:\"text\"`.",
    "mod": "Remainder of a division.",
    "mul": "Multiplication.",
    "neg": "Negation.",
    "not_in": "True when the value equals none of the values in the list.",
    "not_like": "Negated wildcard match.",
    "not_rlike": "Negated regular expression match.",
    "not_equals": "Inequality.",
    "rlike": "Regular expression match over the whole value.",
    "sub": "Subtraction. Also subtracts a time span from a date.",
}


def write_operators(es: Path, out: Path, commit: str) -> int:
    lines = [
        "# ES|QL operators, generated by scripts/sync_esql_catalog.py. Do not edit.",
        f"# Source: elastic/elasticsearch@{commit} {DEFINITIONS}/operators/*.json",
        "",
    ]
    count = 0
    for path in sorted((es / DEFINITIONS / "operators").glob("*.json")):
        data = json.loads(path.read_text())
        lines += [
            "[[operators]]",
            f"name = {toml_str(data['name'])}",
            f"operator = {toml_str(data.get('operator', data['name']))}",
            f"docs = {toml_str(OPERATOR_SUMMARIES.get(data['name'], ''))}",
            f"preview = {str(bool(data.get('preview'))).lower()}",
            f"citation = {toml_str(SITE + '/functions-operators/operators')}",
            "",
        ]
        count += 1
    out.write_text("\n".join(lines).rstrip() + "\n")
    return count


def write_commands(es: Path, out: Path, commit: str) -> int:
    lines = [
        "# ES|QL commands, generated by scripts/sync_esql_catalog.py. Do not edit.",
        f"# Source: elastic/elasticsearch@{commit} {COMMAND_LAYOUTS}/*.md",
        "# Rows without a citation are snapshot-only or retired spellings the grammar still parses.",
        "# `versions`: release branches whose grammar accepts the command on a release build.",
        "",
        f"branches = {toml_list(BRANCHES)}",
        "",
    ]
    rows = []
    for layout, (name, kind, page, summary) in sorted(COMMANDS.items(), key=lambda kv: kv[1][0]):
        path = es / COMMAND_LAYOUTS / layout
        text = path.read_text()
        rows.append(
            {
                "name": name,
                "kind": kind,
                "syntax": syntax_block(text),
                "docs": summary,
                "stack": stack_lifecycle(text),
                "snapshot_only": False,
                "citation": f"{SITE}/{page}",
            }
        )
    rows += UNDOCUMENTED
    for row in rows:
        lines += [
            "[[commands]]",
            f"name = {toml_str(row['name'])}",
            f"kind = {toml_str(row['kind'])}",
            f"syntax = {toml_str(row['syntax'])}",
            f"docs = {toml_str(row['docs'])}",
            f"stack = {toml_str(row['stack'])}",
            f"versions = {toml_list(COMMAND_VERSIONS[row['name']])}",
            f"snapshot_only = {str(row['snapshot_only']).lower()}",
        ]
        if row.get("citation"):
            lines.append(f"citation = {toml_str(row['citation'])}")
        if row.get("alias_of"):
            lines.append(f"alias_of = {toml_str(row['alias_of'])}")
        lines.append("")
    out.write_text("\n".join(lines).rstrip() + "\n")
    return len(rows)


def write_types(es: Path, branches: Path, out: Path, commit: str) -> int:
    per_branch = branch_casts(branches)
    main_casts: dict[str, str] = {}
    for path in (es / DEFINITIONS).glob("inline_cast.json"):
        main_casts.update({k: v.lower() for k, v in json.loads(path.read_text()).items()})
    names = sorted(set(main_casts).union(*per_branch.values()))
    lines = [
        "# ES|QL `::type` cast targets, generated by scripts/sync_esql_catalog.py. Do not edit.",
        f"# Source: elastic/elasticsearch@{commit} {DEFINITIONS}/inline_cast.json and each",
        "# release branch's inline_cast.json (9.0-9.2: EsqlDataTypeConverter, see the script).",
        "# `function` is the conversion function the cast calls.",
        "",
        f"branches = {toml_list(BRANCHES)}",
        "",
    ]
    for name in names:
        function = main_casts.get(name) or next(
            (per_branch[b][name] for b in reversed(BRANCHES) if per_branch[b].get(name)), ""
        )
        lines += [
            "[[types]]",
            f"name = {toml_str(name)}",
            f"function = {toml_str(function)}",
            f"versions = {toml_list([b for b in BRANCHES if name in per_branch[b]])}",
            "",
        ]
    out.write_text("\n".join(lines).rstrip() + "\n")
    return len(names)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elasticsearch", type=Path, required=True)
    parser.add_argument(
        "--branches", type=Path, required=True,
        help="directory with one docs checkout per release branch (8.19/, 9.0/, ...)",
    )
    parser.add_argument(
        "--out", type=Path, default=Path(__file__).resolve().parent.parent / "catalogs/esql"
    )
    args = parser.parse_args()
    es = args.elasticsearch.resolve()
    commit = subprocess.run(
        ["git", "-C", str(es), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    args.out.mkdir(parents=True, exist_ok=True)
    branches = args.branches.resolve()
    functions = write_functions(es, branches, args.out / "functions.toml", commit)
    operators = write_operators(es, args.out / "operators.toml", commit)
    commands = write_commands(es, args.out / "commands.toml", commit)
    types = write_types(es, branches, args.out / "types.toml", commit)
    print(
        f"elastic/elasticsearch@{commit}: {commands} commands, {functions} functions, "
        f"{operators} operators, {types} cast types; branches {', '.join(BRANCHES)}"
    )


if __name__ == "__main__":
    main()
