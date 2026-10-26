#!/usr/bin/env python3
"""Run EQL, ES|QL, or Lucene queries against a live Elasticsearch.

Usage:
  python3 scripts/oracles/elasticsearch/run.py --language eql|esql|lucene DIR
      [--url URL] [--extra-mapping FILE] [--assume-unmapped] [--jobs N]
      [--skip-larger BYTES] [--lucene-verdict both|strict|lenient]

Reads every `*.eql`, `*.esql`, or `*.lucene` file in DIR and prints one line
per file, sorted by name, in the format of `scripts/oracles/elastic/*.cjs`:

  <file>\tOK\t[<note>]
  <file>\tERR\t<error type>: <reason>

An ES|QL file `x.esql` with a sibling `x.esql.params.json` is sent with that
JSON as the request's `params`.

Lucene lines carry a fourth column, `lenient:OK` or `lenient:ERR <reason>`:
the verdict with `lenient: true`, which is how detection rules run. The
second and third columns are the strict (`lenient: false`) verdict.
`--lucene-verdict strict` or `lenient` prints that verdict alone, in three
columns.

The server is ES_URL (default http://127.0.0.1:9200); `start.sh` starts one.
The script waits for cluster health yellow and creates the fixture indices
(reused while their mapping is unchanged):

- `opentide-ecs`, alias `o`: every ECS field in `catalogs/ecs/fields.json`
  with its type, plus `--extra-mapping` (a JSON object `{"field": "type"}`).
  Skipped: `object` entries (their children create the object) and `nested`
  entries (their children are mapped as plain object fields, so a query on
  them is checked as if the parent were an object). A `match_only_text` field
  under a keyword or wildcard field is mapped as its multi-field, as ECS
  does. `scaled_float` gets `scaling_factor: 1000`.
- `opentide-unmapped`, alias `u`: no mapping. A file whose name contains
  `.unmapped.` runs against it.

What counts as an error is documented in scripts/oracles/README.md ("Live
Elasticsearch"). In short: parse and verification errors are ERR; problems
that only exist because the fixture is not a real cluster (a field the
fixture does not map, an index, enrich policy, or inference endpoint that
does not exist) are OK with an `unverified:` note.

`--assume-unmapped` is for corpora written against non-ECS field names. EQL
and ES|QL retry a query whose only problems are unmapped fields: EQL marks
those fields optional (`?field`, which reads as null), ES|QL maps them as
`keyword` in `opentide-assumed-esql` (alias `a`, over both indices). Lucene
maps every unmapped `field:` of the query as `keyword` in
`opentide-assumed-lucene` before it runs, because Elasticsearch builds, and
so checks, nothing for a field it does not map. The note then starts with
`assumed:` and names them, on OK and ERR lines alike. A problem that rests on
the assumption (it names an assumed ES|QL field, or an assumed EQL field's
own value) stays `unverified`.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
ECS_INDEX, ECS_ALIAS = "opentide-ecs", "o"
UNMAPPED_INDEX, UNMAPPED_ALIAS = "opentide-unmapped", "u"
ASSUMED_INDEX, ASSUMED_ALIAS = "opentide-assumed-esql", "a"
ASSUMED_LUCENE_INDEX = "opentide-assumed-lucene"
EXT = {"eql": ".eql", "esql": ".esql", "lucene": ".lucene"}
_types: dict[str, str] = {}  # mapped ECS leaf -> type, filled by ecs_mapping


def request(url: str, method: str = "GET", body: object | None = None, timeout: float = 120):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"error": {"type": f"http_{e.code}", "reason": raw.decode(errors="replace")}}


def wait_for_yellow(url: str, deadline_s: float = 300) -> None:
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            status, body = request(f"{url}/_cluster/health?wait_for_status=yellow&timeout=30s", timeout=40)
            if status == 200 and body.get("status") in ("yellow", "green"):
                return
        except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
            pass
        if time.monotonic() > deadline:
            sys.exit(f"{url} did not reach cluster health yellow")
        time.sleep(2)


# --- fixture indices ---------------------------------------------------------


def _multi_field(name: str, t: str, types: dict[str, str]) -> bool:
    parent = name.rsplit(".", 1)[0]
    return parent != name and t == "match_only_text" and types.get(parent) in ("keyword", "wildcard")


def ecs_mapping(extra: dict[str, str]) -> tuple[dict, set[str]]:
    """Index properties for the ECS catalog, and the set of mapped names."""
    fields = json.loads((ROOT / "catalogs/ecs/fields.json").read_text())["fields"]
    types = {f["name"]: f["type"] for f in fields}
    types.update(extra)
    props: dict = {}
    mapped: set[str] = set()

    def spec(t: str) -> dict:
        return {"type": t, "scaling_factor": 1000} if t == "scaled_float" else {"type": t}

    for name, t in sorted(types.items()):
        if t in ("object", "nested") or _multi_field(name, t, types):
            continue
        node = props
        parts = name.split(".")
        for p in parts[:-1]:
            node = node.setdefault(p, {"properties": {}})
            if "properties" not in node:
                break  # under a leaf: not mappable as an object field
            node = node["properties"]
        else:
            node[parts[-1]] = spec(t)
            mapped.add(name)
            _types[name] = t
    for name, t in sorted(types.items()):
        if _multi_field(name, t, types):
            parent = name.rsplit(".", 1)[0]
            node = props
            for p in parent.split(".")[:-1]:
                node = node[p]["properties"]
            node[parent.split(".")[-1]].setdefault("fields", {})[name.rsplit(".", 1)[1]] = spec(t)
            mapped.add(name)
    return props, mapped


def ensure_index(url: str, index: str, aliases: dict, mappings: dict, fresh: bool = False) -> None:
    digest = hashlib.sha256(json.dumps([mappings, aliases], sort_keys=True).encode()).hexdigest()
    status, body = request(f"{url}/{index}/_mapping")
    if status == 200:
        meta = body.get(index, {}).get("mappings", {}).get("_meta", {})
        if meta.get("opentide") == digest and not fresh:
            return
        request(f"{url}/{index}", "DELETE")
    status, body = request(
        f"{url}/{index}?wait_for_active_shards=1",
        "PUT",
        {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "index.mapping.total_fields.limit": 100000,
            },
            "mappings": {**mappings, "_meta": {"opentide": digest}},
            "aliases": aliases,
        },
    )
    if status != 200:
        sys.exit(f"cannot create {index}: {json.dumps(body)[:2000]}")


def setup(url: str, extra: dict[str, str], assume: str | None = None) -> set[str]:
    """Create the fixture indices; `assume` names the language whose
    side index for assumed fields is recreated empty."""
    wait_for_yellow(url)
    props, mapped = ecs_mapping(extra)
    ensure_index(url, ECS_INDEX, {ECS_ALIAS: {}, ASSUMED_ALIAS: {}}, {"properties": props})
    ensure_index(url, UNMAPPED_INDEX, {UNMAPPED_ALIAS: {}}, {})
    if assume == "esql":
        ensure_index(url, ASSUMED_INDEX, {ASSUMED_ALIAS: {}}, {"dynamic": False}, fresh=True)
    if assume == "lucene":
        ensure_index(url, ASSUMED_LUCENE_INDEX, {}, {"dynamic": False}, fresh=True)
    wait_for_yellow(url)
    return mapped


# --- verdicts ------------------------------------------------------------------


def one_line(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def describe(error: dict) -> str:
    """`type: reason`, descending into the shard failure that caused it."""
    if error.get("type") == "search_phase_execution_exception":
        shards = error.get("failed_shards") or []
        if shards and isinstance(shards[0].get("reason"), dict):
            error = shards[0]["reason"]
        elif error.get("caused_by"):
            error = error["caused_by"]
    text = f"{error.get('type', '?')}: {error.get('reason', '')}"
    cause = error.get("caused_by")
    depth = 0
    while isinstance(cause, dict) and depth < 3:
        if cause.get("reason"):
            text += f" | caused by {cause.get('type', '?')}: {cause['reason']}"
        cause = cause.get("caused_by")
        depth += 1
    return one_line(text)


PROBLEM = re.compile(r"line (-?\d+):(-?\d+): ")
UNKNOWN_COLUMN = re.compile(r"^Unknown column \[([^\]]+)\]")
NO_MATCH = re.compile(r"^No matches found for pattern \[([^\]]+)\]")
FIXTURE_PROBLEM = re.compile(
    r"^(Unknown index"
    r"|cannot find enrich policy"
    r"|unresolved enrich policy"
    r"|Inference endpoint not found"
    r"|current license is non-compliant"  # CHANGE_POINT and others need more than basic
    r"|.*\bin lookup mode\b"
    r"|.*requires a lookup index"
    r"|.*\bTS\b.*time.series)",
    re.I,
)


def _glob_matches(pattern: str, names: set[str]) -> bool:
    rx = re.compile("^" + ".*".join(re.escape(p) for p in pattern.split("*")) + "$")
    return any(rx.match(n) for n in names)


def unmapped_field(problem: str, mapped: set[str]) -> str | None:
    """The field name when the problem is a column the fixture does not map.

    `Unknown column [x]` blames the fixture only when x is not mapped: a
    mapped x means the query itself dropped or never produced the column
    (KEEP, STATS, a misspelt EVAL name), which fails on any cluster.
    """
    m = UNKNOWN_COLUMN.match(problem)
    if m and m.group(1).strip("`") not in mapped:
        return m.group(1).strip("`")
    return None


def fixture_problem(problem: str, mapped: set[str]) -> bool:
    if unmapped_field(problem, mapped):
        return True
    m = NO_MATCH.match(problem)
    if m:
        return not _glob_matches(m.group(1).strip("`"), mapped)
    return bool(FIXTURE_PROBLEM.match(problem))


def problems_of(reason: str) -> list[tuple[int, int, str]]:
    """`Found N problems\\nline L:C: text...` as (line, column, text)."""
    parts = PROBLEM.split(reason)
    out = []
    for i in range(1, len(parts) - 2, 3):
        out.append((int(parts[i]), int(parts[i + 1]), parts[i + 2].strip()))
    return out


class Verdict:
    def __init__(self, ok: bool, detail: str, unmapped: list[tuple[int, int, str]] | None = None):
        self.ok, self.detail, self.unmapped = ok, one_line(detail), unmapped or []

    @property
    def cells(self) -> tuple[str, str]:
        return ("OK" if self.ok else "ERR"), self.detail


FIXTURE_TYPES = {
    "index_not_found_exception",
    "resource_not_found_exception",  # inference endpoints, enrich policies
    "circuit_breaking_exception",  # the fixture's 1 GB heap, not the language
}


def mentions(text: str, names: set[str]) -> bool:
    text = text.replace("`", "")
    return any(re.search(r"(?<![\w.])" + re.escape(n) + r"(?![\w])", text) for n in names)


def judge(status: int, body: dict, mapped: set[str], depends=None) -> Verdict:
    """The verdict for one response. A problem for which `depends(text)` is
    true rests on an assumed field, so it counts as unverified, not as an error."""
    depends = depends or (lambda text: False)
    shards = body.get("_shards") or {}
    if status == 200 and shards.get("failed"):
        # A search over several indices answers 200 when only some shards fail.
        failure = (shards.get("failures") or [{}])[0].get("reason") or {}
        return Verdict(False, describe(failure) if isinstance(failure, dict) else str(failure))
    if status == 200:
        return Verdict(True, "")
    error = body.get("error")
    if not isinstance(error, dict):
        return Verdict(False, f"http_{status}: {json.dumps(body)[:500]}")
    # ES|QL wraps an unknown index in index_not_found_exception whose cause
    # is the verification problem list.
    verification = error if error.get("type") == "verification_exception" else None
    if verification is None and isinstance(error.get("caused_by"), dict):
        if error["caused_by"].get("type") == "verification_exception":
            verification = error["caused_by"]
    if verification is not None:
        reason = verification.get("reason", "")
        # 9.4 and later report a lone unknown index without the
        # `Found 1 problem\nline L:C:` frame.
        problems = problems_of(reason) or [(0, 0, reason.strip())]
        real = [p for p in problems if not fixture_problem(p[2], mapped)]
        if real and all(depends(p[2]) for p in real):
            return Verdict(True, "unverified: " + "; ".join(p[2] for p in real))
        real = [p for p in real if not depends(p[2])]
        if real:
            return Verdict(False, "verification_exception: " + "; ".join(p[2] for p in real))
        unmapped = [p for p in problems if unmapped_field(p[2], mapped)]
        others = len(unmapped) < len(problems)
        return Verdict(
            True,
            "unverified: " + "; ".join(p[2] for p in problems),
            [] if others else unmapped,
        )
    # Cross-cluster search needs a licence the fixture cluster does not have.
    licence = error.get("type") == "status_exception" and "license is required" in error.get("reason", "")
    if error.get("type") in FIXTURE_TYPES or licence or depends(describe(error)):
        return Verdict(True, "unverified: " + describe(error))
    return Verdict(False, describe(error))


# --- EQL -----------------------------------------------------------------------


def target(name: str, mapped: set[str]) -> tuple[str, set[str]]:
    """The alias a file runs against, and the fields mapped there."""
    return (UNMAPPED_ALIAS, set()) if ".unmapped." in name else (ECS_ALIAS, mapped)


EQL_TOKEN = re.compile(r'"""(?:.|\n)*?"""|"(?:\\.|[^"\\\n])*"|`(?:``|[^`])*`|[A-Za-z_@][\w.@]*', re.S)


def make_optional(text: str, names: set[str]) -> str:
    """Prefix every reference to one of `names` with `?`. Elasticsearch
    reports an unknown column once, so every occurrence is found here."""
    out, last = [], 0
    for m in EQL_TOKEN.finditer(text):
        token = m.group(0)
        if token.startswith('"'):
            continue
        name = token[1:-1].replace("``", "`") if token.startswith("`") else token
        if name in names and (m.start() == 0 or text[m.start() - 1] != "?"):
            out.append(text[last : m.start()] + "?")
            last = m.start()
    out.append(text[last:])
    return "".join(out)


def run_eql(url: str, name: str, text: str, mapped: set[str], assume: bool) -> str:
    alias, mapped = target(name, mapped)

    def ask(query: str, depends=None) -> Verdict:
        # `size: 0` lets the planner return an empty result before it
        # translates the filter, which hides translation errors such as a
        # field-to-field comparison; the index is empty, so `size: 1` is free.
        status, body = request(f"{url}/{alias}/_eql/search", "POST", {"query": query, "size": 1})
        return judge(status, body, mapped, depends)

    v = ask(text)
    if assume and v.ok and v.unmapped:
        names = sorted({p[2].split("[", 1)[1].split("]", 1)[0] for p in v.unmapped})
        query = make_optional(text, set(names))
        # A null optional field passes every type check, so only a problem
        # about the field's own value, or a script over it, rests on it.
        alt = "|".join(re.escape(n) for n in names)
        rx = re.compile(rf"found value \[\??`?({alt})\b|Cannot evaluate script for expression \??`?({alt})\b")
        retry = ask(query, lambda text: rx.search(text) is not None)
        retry.detail = one_line(f"assumed: optional {', '.join(names)}" + (f"; {retry.detail}" if retry.detail else ""))
        v = retry
    ok, detail = v.cells
    return f"{name}\t{ok}\t{detail}"


# --- Lucene --------------------------------------------------------------------


LUCENE_STRIP = re.compile(r'"(?:\\.|[^"\\])*"|/(?:\\.|[^/\\])*/')
LUCENE_FIELD = re.compile(r"(?<![\\\w.@*?])((?:[\w.@]|\\.)+)\s*:")


def lucene_fields(text: str) -> set[str]:
    """Field names before `:` outside phrases and regexps, unescaped."""
    bare = LUCENE_STRIP.sub(" ", text)
    return {re.sub(r"\\(.)", r"\1", m.group(1)) for m in LUCENE_FIELD.finditer(bare)}


def run_lucene(url: str, name: str, text: str, mapped: set[str], assume: bool) -> str:
    alias, fields = target(name, mapped)
    note = ""
    if assume and alias == ECS_ALIAS:
        # Elasticsearch builds no query, so checks nothing, for a field it
        # does not map: map the query's unmapped fields as keyword first.
        unmapped = {f for f in lucene_fields(text) if f not in mapped and "*" not in f and not f.startswith("_")}
        if unmapped:
            assume_keywords(url, ASSUMED_LUCENE_INDEX, unmapped)
            alias = f"{ECS_INDEX},{ASSUMED_LUCENE_INDEX}"
            note = "assumed: keyword " + ", ".join(sorted(unmapped))
    cells = []
    for lenient in (False, True):
        body = {
            "size": 0,
            "query": {
                "query_string": {
                    "query": text,
                    "default_field": "*",
                    "allow_leading_wildcard": True,
                    "lenient": lenient,
                }
            },
        }
        status, resp = request(f"{url}/{alias}/_search", "POST", body)
        cells.append(judge(status, resp, fields).cells)
    (v, d), (lv, ld) = cells
    if note:
        d = f"{note}; {d}" if d else note
    lenient_cell = f"lenient:{lv}" + (f" {ld}" if lv == "ERR" else "")
    return f"{name}\t{v}\t{d}\t{lenient_cell}"


# --- ES|QL ---------------------------------------------------------------------

TOKEN = re.compile(
    r'(?P<comment>//[^\n]*|/\*.*?(?:\*/|\Z))'
    r'|(?P<string>"""(?:.|\n)*?(?:"""|\Z)|"(?:\\.|[^"\\\n])*(?:"|$))'
    r"|(?P<punct>[|()\[\],])"
    r"|(?P<space>\s+)"
    r"|(?P<word>[^\s|()\[\],\"/]+|/)",
    re.S | re.M,
)


def _tokens(text: str) -> list[tuple[str, int, int]]:
    out = []
    for m in TOKEN.finditer(text):
        kind = m.lastgroup
        if kind != "space":
            out.append((kind, m.start(), m.end()))
    return out


def rewrite_sources(text: str, alias: str) -> str:
    """Point every FROM / TS source list at the fixture alias.

    The index pattern list (the tokens between the command keyword and
    METADATA, `[`, `|`, `(`, `)`, or the end; a comma that leads into a
    subquery is kept) is blanked to spaces and its first characters become
    the alias, so every later offset, and every line and column
    Elasticsearch reports, is unchanged. A `::selector` on the first pattern
    and a `cluster:` prefix on the first pattern are kept, so the grammar
    still sees them. Newlines and comments inside the list are kept.
    """
    toks = _tokens(text)
    code = [t for t in toks if t[0] != "comment"]
    out = list(text)
    for i, (kind, start, end) in enumerate(code):
        if kind != "word" or text[start:end].lower() not in ("from", "ts"):
            continue
        prev = code[i - 1] if i else None
        if prev is not None and text[prev[1] : prev[2]] not in ("|", "("):
            continue
        j = i + 1
        span: list[tuple[int, int]] = []
        while j < len(code):
            k, s, e = code[j]
            word = text[s:e]
            if word in ("|", "(", ")", "[") or (k == "word" and word.lower() == "metadata"):
                break
            span.append((s, e))
            j += 1
        while span and text[span[-1][0] : span[-1][1]] == ",":
            span.pop()
        if not span:
            continue
        first = text[span[0][0] : span[0][1]].strip('"')
        sm = re.search(r"::\w+$", first)
        cm = re.match(r"([^:,\s]+):(?!:)", first)
        replacement = (cm.group(0) if cm else "") + alias + (sm.group(0) if sm else "")
        lo, hi = span[0][0], span[-1][1]
        comments = [(s, e) for kd, s, e in toks if kd == "comment" and lo <= s < hi]
        filled = 0
        for pos in range(lo, hi):
            if text[pos] in "\r\n" or any(s <= pos < e for s, e in comments):
                continue
            if filled < len(replacement):
                out[pos] = replacement[filled]
                filled += 1
            else:
                out[pos] = " "
        if filled < len(replacement):
            # A pattern shorter than the alias (`*`): offsets after it shift.
            out[hi - 1] += replacement[filled:]
    return "".join(out)


_assumed_lock = threading.Lock()
_assumed: set[str] = set()


def assumed_properties(names: list[str]) -> dict:
    """`keyword` mappings for unmapped names. Under a mapped leaf (`x.caseless`
    under keyword `x`) the name becomes a multi-field of a copy of that leaf,
    since an object there would conflict with the ECS index."""
    props: dict = {}
    for name in names:
        parts = name.split(".")
        leaf = next((i for i in range(len(parts) - 1, 0, -1) if ".".join(parts[:i]) in _types), None)
        if leaf is None:
            props[name] = {"type": "keyword"}
        else:
            parent = ".".join(parts[:leaf])
            entry = props.setdefault(parent, {"type": _types[parent]})
            entry.setdefault("fields", {})[".".join(parts[leaf:])] = {"type": "keyword"}
    return props


def assume_keywords(url: str, index: str, names: set[str]) -> set[str]:
    """Map the not yet assumed `names` as keyword in `index`; returns every
    name assumed so far."""
    with _assumed_lock:
        missing = sorted(names - _assumed)
        if missing:
            status, _ = request(f"{url}/{index}/_mapping", "PUT", {"properties": assumed_properties(missing)})
            if status == 200:
                _assumed.update(missing)
        return set(_assumed)


def run_esql(url: str, name: str, text: str, mapped: set[str], assume: bool, params: object = None) -> str:
    alias, mapped = target(name, mapped)
    request_body: dict = {} if params is None else {"params": params}

    def ask(alias: str, fields: set[str], assumed: set[str] = frozenset()) -> Verdict:
        body = {**request_body, "query": rewrite_sources(text, alias)}
        status, body = request(f"{url}/_query", "POST", body)
        return judge(status, body, fields, lambda text: mentions(text, assumed))

    v = ask(alias, mapped)
    if assume and alias == ECS_ALIAS and v.ok and v.unmapped:
        names: set[str] = set()
        for _ in range(3):
            new = {p[2].split("[", 1)[1].split("]", 1)[0].strip("`") for p in v.unmapped}
            names |= new
            known = assume_keywords(url, ASSUMED_INDEX, new)
            if not new <= known:
                break
            v = ask(ASSUMED_ALIAS, mapped | known, known)
            if not (v.ok and v.unmapped):
                break
        v.detail = one_line(f"assumed: keyword {', '.join(sorted(names))}" + (f"; {v.detail}" if v.detail else ""))
    ok, detail = v.cells
    return f"{name}\t{ok}\t{detail}"


RUNNERS = {"eql": run_eql, "esql": run_esql, "lucene": run_lucene}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--language", required=True, choices=sorted(RUNNERS))
    parser.add_argument("--url", default=os.environ.get("ES_URL", "http://127.0.0.1:9200"))
    parser.add_argument("--extra-mapping", type=Path, help="JSON object {field: type} added to the ECS index")
    parser.add_argument("--assume-unmapped", action="store_true", help="retry with unmapped fields assumed (see above)")
    parser.add_argument(
        "--lucene-verdict",
        choices=["both", "strict", "lenient"],
        default="both",
        help="Lucene: `both` adds the lenient fourth column; `strict` or `lenient` print three columns",
    )
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument(
        "--skip-larger",
        type=int,
        metavar="BYTES",
        help="do not send files larger than this (9.3 with a 1 GB heap dies on a 250 KB Lucene query)",
    )
    parser.add_argument("dir", type=Path)
    args = parser.parse_args()
    url = args.url.rstrip("/")
    extra = json.loads(args.extra_mapping.read_text()) if args.extra_mapping else {}
    mapped = setup(url, extra, args.language if args.assume_unmapped else None)
    files = sorted(p for p in args.dir.iterdir() if p.name.endswith(EXT[args.language]) and p.is_file())
    run = RUNNERS[args.language]

    def one(path: Path) -> str:
        text = path.read_text(encoding="utf-8")
        if args.skip_larger and len(text.encode()) > args.skip_larger:
            skipped = f"{path.name}\tOK\tunverified: skipped, {len(text.encode())} bytes"
            return skipped + ("\tlenient:OK" if args.language == "lucene" else "")
        sidecar = path.with_name(path.name + ".params.json")
        if args.language == "esql" and sidecar.exists():
            return run_esql(url, path.name, text, mapped, args.assume_unmapped, json.loads(sidecar.read_text()))
        return run(url, path.name, text, mapped, args.assume_unmapped)

    def shaped(path: Path) -> str:
        line = one(path)
        if args.language != "lucene" or args.lucene_verdict == "both":
            return line
        name, verdict, detail, lenient = line.split("\t", 3)
        if args.lucene_verdict == "strict":
            return f"{name}\t{verdict}\t{detail}"
        lv, _, ld = lenient.removeprefix("lenient:").partition(" ")
        note = detail if detail.startswith(("assumed", "unverified")) else ""
        return f"{name}\t{lv}\t{ld or note}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        lines = pool.map(shaped, files)
        for line in lines:
            print(line, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
