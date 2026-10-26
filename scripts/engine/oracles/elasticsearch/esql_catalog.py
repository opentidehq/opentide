#!/usr/bin/env python3
"""Check the `versions` lists in catalogs/esql/*.toml against a live server.

Usage: python3 scripts/oracles/elasticsearch/esql_catalog.py [--url URL] [--all]

Asks the server (ES_URL, default http://127.0.0.1:9200) for its version,
then sends one minimal query per command, function (and alias), and `::type`
cast in the catalog, and compares what the server accepts with whether the
catalog lists that release line (`8.19`, `9.0`, ...) in the row's `versions`.

What counts as "absent" on a release build:
- a function: the response names it in `Unknown function [name]`;
  or a grammar error at the call (8.19 lexes FIRST and LAST as keywords);
- a cast: `Unknown data type named [name]` or `Unsupported conversion to
  type [name]`;
- a command: a `parsing_exception` at or before the command keyword (the
  grammar does not know it, the builder refuses it outside snapshot builds,
  or a command the probe needs first is missing), or 8.19's 500 for a
  command missing from telemetry. A probe the lexer refuses after the
  keyword defers to the command's next form, if it has one. Any other response,
  including errors about the fixture or about argument types, means the
  name exists.

Prints a TSV line `kind name catalog observed detail` for every
disagreement (all rows with `--all`), and exits 1 when there is one.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run  # noqa: E402  (sibling module)

ROOT = Path(__file__).resolve().parents[3]

# A literal for each parameter type, most common first.
LITERALS = [
    ("keyword", '"a"'),
    ("text", '"a"'),
    ("integer", "1"),
    ("long", "1"),
    ("double", "1.5"),
    ("boolean", "true"),
    ("date", 'TO_DATETIME("2024-01-01T00:00:00Z")'),
    ("ip", 'TO_IP("1.1.1.1")'),
    ("version", 'TO_VERSION("1.0")'),
    ("unsigned_long", "1"),
    ("date_period", "1 day"),
    ("time_duration", "1 hour"),
    ("geo_point", 'TO_GEOPOINT("POINT(1 1)")'),
    ("geo_shape", 'TO_GEOSHAPE("POINT(1 1)")'),
    ("cartesian_point", 'TO_CARTESIANPOINT("POINT(1 1)")'),
    ("cartesian_shape", 'TO_CARTESIANSHAPE("POINT(1 1)")'),
    ("date_nanos", 'TO_DATE_NANOS("2024-01-01T00:00:00Z")'),
]

# One or more queries per command; the command keyword is the text after the
# last `| ` (or the start for a source command). The first query that does
# not fail at that keyword decides.
COMMANDS: dict[str, list[str]] = {
    "change_point": ["ROW t = NOW(), v = 1 | CHANGE_POINT v ON t"],
    "completion": [
        'ROW p = "x" | COMPLETION c = p WITH {"inference_id": "e"}',
        'ROW p = "x" | COMPLETION c = p WITH e',
    ],
    "dedup": ["ROW a = 1 | DEDUP"],
    "dense_vector": ['ROW a = "x" | DENSE_VECTOR a'],
    "dissect": ['ROW a = "x" | DISSECT a "%{b}"'],
    "drop": ["ROW a = 1, b = 2 | DROP a"],
    "enrich": ['ROW a = "x" | ENRICH p ON a'],
    "eval": ["ROW a = 1 | EVAL b = a"],
    "fork": ["FROM logs-* | FORK (WHERE true) (WHERE false)"],
    "from": ["FROM logs-*"],
    "fuse": ["FROM logs-* METADATA _id, _index, _score | FORK (WHERE true) (WHERE false) | FUSE"],
    "grok": ['ROW a = "x" | GROK a "%{WORD:b}"'],
    "highlight": ['FROM logs-* | WHERE MATCH(process.name, "a") | HIGHLIGHT ON process.name'],
    "inline stats": ["ROW a = 1 | INLINE STATS c = COUNT(*)"],
    "ip_location": ['ROW ip = TO_IP("1.1.1.1") | IP_LOCATION g = ip'],
    "keep": ["ROW a = 1 | KEEP a"],
    "limit": ["ROW a = 1 | LIMIT 1"],
    "lookup join": ["FROM logs-* | LOOKUP JOIN lookup_idx ON host.name"],
    "metrics_info": ["TS logs-* | METRICS_INFO"],
    "mmr": ["FROM logs-* | MMR ON process.name LIMIT 1"],
    "mv_expand": ["ROW a = [1, 2] | MV_EXPAND a"],
    "promql": ["PROMQL up"],
    "registered_domain": ['ROW d = "a.example.com" | REGISTERED_DOMAIN r = d'],
    "rename": ["ROW a = 1 | RENAME a AS b"],
    "rerank": [
        'FROM logs-* | RERANK "q" ON process.name WITH {"inference_id": "e"}',
        'FROM logs-* | RERANK "q" ON process.name WITH e',
    ],
    "row": ["ROW a = 1"],
    "sample": ["ROW a = 1 | SAMPLE 0.5"],
    "set": ['SET unmapped_fields = "fail"; ROW a = 1', 'SET a = "b"; ROW a = 1'],
    "show": ["SHOW INFO"],
    "sort": ["ROW a = 1 | SORT a"],
    "stats": ["ROW a = 1 | STATS c = COUNT(*)"],
    "ts": ["TS logs-* | LIMIT 1"],
    "ts_collapse": ["TS logs-* | TS_COLLAPSE"],
    "ts_info": ["TS logs-* | TS_INFO"],
    "uri_parts": ['ROW u = "http://a.example.com/b" | URI_PARTS p = u'],
    "user_agent": ['ROW u = "x" | USER_AGENT p = u'],
    "where": ["ROW a = 1 | WHERE a > 0"],
    "explain": ["EXPLAIN (ROW a = 1)", "EXPLAIN [ROW a = 1]"],
    "fillnull": ["ROW a = 1 | FILLNULL 0 ON a"],
    "left join": ["FROM logs-* | LEFT JOIN lookup_idx ON host.name"],
    "right join": ["FROM logs-* | RIGHT JOIN lookup_idx ON host.name"],
    "full join": ["FROM logs-* | FULL JOIN lookup_idx ON host.name"],
    "inlinestats": ["ROW a = 1 | INLINESTATS c = COUNT(*)"],
}


def server_line(url: str) -> str:
    status, body = run.request(url)
    number = body["version"]["number"]
    return ".".join(number.split(".")[:2])


def ask(url: str, query: str, mapped: set[str]) -> tuple[int, dict]:
    return run.request(f"{url}/_query", "POST", {"query": run.rewrite_sources(query, run.ECS_ALIAS)})


def error_text(body: dict) -> str:
    error = body.get("error") or {}
    return run.describe(error) if isinstance(error, dict) else str(body)


def function_query(row: dict, name: str) -> str:
    args = []
    for p in row.get("parameters", []):
        if not p.get("required", True):
            continue
        types = p.get("types") or []
        lit = next((v for t, v in LITERALS if t in types), '"a"')
        args.append(lit)
    call = f"{name.upper()}({', '.join(args)})"
    kind = row.get("kind")
    if kind in ("agg", "time_series_agg"):
        return f"ROW a = 1 | STATS x = {call}"
    if kind == "grouping":
        return f"ROW a = 1 | STATS c = COUNT(*) BY g = {call}"
    return f"ROW x = {call}"


def parse_error_at_or_before(status: int, body: dict, offset: int) -> bool:
    """A grammar error at or before `offset` (0-based, first line)."""
    if status == 200:
        return False
    error = body.get("error") or {}
    if not isinstance(error, dict) or error.get("type") != "parsing_exception":
        return False
    reason = error.get("reason", "")
    m = re.match(r"line (\d+):(\d+): (.*)", reason, re.S)
    syntax = r"mismatched input|extraneous input|no viable alternative|token recognition error|missing |.*snapshot"
    if not m or not re.match(syntax, m.group(3)):
        return False
    return int(m.group(1)) == 1 and int(m.group(2)) <= offset + 1


def command_absent(query: str, status: int, body: dict) -> bool:
    keyword_at = query.rfind("| ") + 2 if "| " in query else 0
    # 8.19 parses `EXPLAIN [...]`, then fails every run with a 500: the
    # command exists only in snapshot builds' telemetry.
    if status == 500 and re.search(r"Command not mapped for telemetry", error_text(body)):
        return True
    return parse_error_at_or_before(status, body, keyword_at)


def lexer_refused(status: int, body: dict) -> bool:
    """The lexer has no token for some part of this probe's form (8.19 lexes
    `EXPLAIN (` with no rule for `(`), so the command's next form decides.
    The last form falls back to the keyword-position rule."""
    return status == 400 and "token recognition error" in error_text(body)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default=os.environ.get("ES_URL", "http://127.0.0.1:9200"))
    parser.add_argument("--all", action="store_true", help="print agreeing rows too")
    args = parser.parse_args()
    url = args.url.rstrip("/")
    mapped = run.setup(url, {}, False)
    line = server_line(url)
    rows: list[tuple[str, str, bool, bool, str]] = []

    functions = tomllib.loads((ROOT / "catalogs/esql/functions.toml").read_text())["functions"]
    for f in functions:
        for name in [f["name"], *f.get("aliases", [])]:
            query = function_query(f, name)
            status, body = ask(url, query, mapped)
            text = error_text(body) if status != 200 else "OK"
            absent = re.search(rf"Unknown function \[{re.escape(name)}\]", text, re.I) is not None
            # A name the lexer takes as a keyword (8.19's FIRST) cannot be called.
            absent = absent or parse_error_at_or_before(status, body, query.index(name.upper() + "("))
            rows.append(("function", name, line in f.get("versions", []), not absent, f"{query} => {text}"))

    for t in tomllib.loads((ROOT / "catalogs/esql/types.toml").read_text())["types"]:
        query = f"ROW x = null::{t['name']}"
        status, body = ask(url, query, mapped)
        text = error_text(body) if status != 200 else "OK"
        absent = re.search(
            rf"(Unknown data type named|Unsupported conversion to type) \[{re.escape(t['name'])}\]", text, re.I
        ) is not None
        rows.append(("cast", t["name"], line in t.get("versions", []), not absent, f"{query} => {text}"))

    commands = {c["name"]: c for c in tomllib.loads((ROOT / "catalogs/esql/commands.toml").read_text())["commands"]}
    for name, row in commands.items():
        queries = COMMANDS.get(name)
        if not queries:
            rows.append(("command", name, line in row.get("versions", []), False, "no probe"))
            continue
        present, detail = False, ""
        for i, query in enumerate(queries):
            status, body = ask(url, query, mapped)
            text = error_text(body) if status != 200 else "OK"
            detail = f"{query} => {text}"
            if lexer_refused(status, body) and i + 1 < len(queries):
                continue
            if not command_absent(query, status, body):
                present = True
                break
        rows.append(("command", name, line in row.get("versions", []), present, detail))

    bad = 0
    for kind, name, listed, seen, detail in rows:
        if listed != seen:
            bad += 1
        if args.all or listed != seen:
            yn = lambda b: "yes" if b else "no"  # noqa: E731
            print(f"{line}\t{kind}\t{name}\tcatalog:{yn(listed)}\tobserved:{yn(seen)}\t{run.one_line(detail)[:400]}")
    print(f"# {line}: {len(rows)} names, {bad} disagree with the catalog", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
