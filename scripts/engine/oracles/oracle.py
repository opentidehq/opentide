#!/usr/bin/env python3
"""Differential oracles: the opentide engine against the reference parser.

    oracle.py kql     Microsoft Kusto.Language (scripts/oracles/kusto, needs dotnet)
    oracle.py spl     Splunk's search/parser REST endpoint (needs SPLUNK_PASSWORD)
    oracle.py esql    @elastic/esql's parser (scripts/oracles/elastic, needs node)
    oracle.py eql     Elasticsearch's EqlBase.g4, generated with antlr-ng (needs node)
    oracle.py kuery   Kibana's kuery grammar.peggy, compiled with peggy (needs node)
    oracle.py lucene  Lucene's classic QueryParser, the jar Elasticsearch pins (needs java)

Each runs every query in the corpus through `opentide-lsp analyze` and through
the reference, then compare two things:

- Verdicts. A query is rejected when ours reports a syntax diagnostic, or when
  the reference reports an error. Each query where the verdicts differ must be
  listed by `paths` in testdata/oracles/exceptions.toml. A `.broken.` fixture
  the reference accepts is always an error: its injected fault breaks nothing.
- Names. KQL functions and plugins, or SPL commands, that one side knows and
  the other does not, plus names ours flags as unknown that the reference
  knows. Each must be listed by `names`.
- KQL columns and types. Kusto.Language analyzes each query against a
  database built from the engine's own table, column and ASIM catalogs; every
  `kql_unknown_column` or `kql_type_mismatch` ours reports must be an error
  the reference reports too (the name it does not know, or an operator it does
  not define for the types). Each fixture in testdata/conformance/columns/
  must make ours report one. A query where they differ is listed by `paths`.

A listed path or name that no longer disagrees is stale and also fails, so the
exceptions file is the exact ledger of known disagreements.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import dataclasses
import ipaddress
import json
import os
import pathlib
import re
import ssl
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXCEPTIONS = ROOT / "testdata/oracles/exceptions.toml"
KUSTO = ROOT / "scripts/oracles/kusto"
ELASTIC = ROOT / "scripts/oracles/elastic"
ELASTIC_CACHE = ELASTIC / ".cache"
MACROS = ROOT / "scripts/oracles/splunk/macros.toml"

# Diagnostics that mean ours rejects the query's syntax.
REJECT = {
    "kql": {"kql_parse_error", "kql_unknown_operator"},
    "spl": {"spl_parse_error", "spl_unknown_command"},
    # Elastic: error-severity syntax diagnostics only. Checks Elasticsearch
    # makes after parsing (unknown functions, types, versions) are not in
    # the parser references, so they are not compared here.
    "esql": {"esql_parse_error", "esql_unknown_command"},
    "eql": {"eql_parse_error"},
    "kuery": {"kuery_parse_error"},
    # Elasticsearch parses fuzziness itself and fails the query string on a
    # value Lucene's plain parser would clamp (`~3`, `~0.5`).
    "lucene": {"lucene_parse_error", "lucene_regexp", "lucene_escape", "lucene_fuzzy"},
}
ELASTIC_LANGUAGES = ("esql", "eql", "kuery", "lucene")
UNKNOWN_NAME = {
    "kql": ("kql_unknown_function", re.compile(r"unknown function '([^']+)'")),
    "spl": ("spl_unknown_command", re.compile(r"unknown SPL command '([^']+)'")),
}
REFERENCE = {
    "kql": "Kusto.Language",
    "spl": "Splunk",
    "esql": "@elastic/esql",
    "eql": "EqlBase.g4",
    "kuery": "Kibana grammar.peggy",
    "lucene": "Lucene QueryParser",
}

# Pinned Elastic references, fetched at CI time and never committed: the
# grammars are ELv2/AGPL/SSPL. Each download is checked against its SHA-256.
ES_COMMIT = "2c85bbdf4cc32de876c2bb31f009caa3a184c329"
KIBANA_COMMIT = "ea2712af211782c2dfd1bc8a81c5d68fec975284"
LUCENE = "10.5.2"
MAVEN = "https://repo1.maven.org/maven2/org/apache/lucene"
FETCH = {
    "EqlBase.g4": (
        f"https://raw.githubusercontent.com/elastic/elasticsearch/{ES_COMMIT}/x-pack/plugin/eql/src/main/antlr/EqlBase.g4",
        "489354eb66e70ee7eafa4c54a8bd67a917e66bd16f129838d258aa8924c60267",
    ),
    "grammar.peggy": (
        f"https://raw.githubusercontent.com/elastic/kibana/{KIBANA_COMMIT}/src/platform/packages/shared/kbn-es-query/src/kuery/grammar/grammar.peggy",
        "ab15ddc4cbd67e3d89215284a5bbc91019475489b75cc13418aa03c024ff328d",
    ),
    "lucene-core.jar": (
        f"{MAVEN}/lucene-core/{LUCENE}/lucene-core-{LUCENE}.jar",
        "39210e1024da5c31d1ad7571d622ebb122a8c4e23ff42e9bc380124973d8c635",
    ),
    "lucene-queryparser.jar": (
        f"{MAVEN}/lucene-queryparser/{LUCENE}/lucene-queryparser-{LUCENE}.jar",
        "ae7d20d735e61c2e0a9bd4b6893eb3d460dea58b0c4b73bafcf136da6f61f3ca",
    ),
}

# Tide configuration fields the engine injects (opentide-tide language_for_field_path).
PLATFORMS = {
    "sentinel": ("kql", ("query",)),
    "defender_for_endpoint": ("kql", ("query",)),
    "splunk": ("spl", ("query", "search")),
}
# A corpus fixture's tag line. SPL comments need a closing ```, so the line is
# not SPL; corpus_gate.rs strips it the same way.
FIXTURE_TAG = re.compile(r"\A(//|```|#) prod:[^\n]*\n")


@dataclasses.dataclass
class Query:
    id: str
    text: str
    broken: bool

    @property
    def probe(self) -> bool:
        return self.id.startswith("testdata/oracles/")


def corpus(language: str) -> list[Query]:
    files = sorted(
        [
            *ROOT.glob(f"testdata/corpus/{language}/*.{language}"),
            *ROOT.glob(f"testdata/conformance/external/{language}/*.{language}"),
            *ROOT.glob(f"testdata/conformance/perf/*.{language}"),
            *ROOT.glob(f"testdata/oracles/{language}/*.{language}"),
            *ROOT.glob(f"testdata/conformance/columns/*.{language}"),
        ]
    )
    queries = [
        Query(rel(p), FIXTURE_TAG.sub("", p.read_text(), count=1), ".broken." in p.name)
        for p in files
    ]
    if language in ELASTIC_LANGUAGES:
        return queries + verdict_tables(language) + elastic_embedded(language) + detection_rules(language)
    return queries + embedded(language)


def verdict_tables(language: str) -> list[Query]:
    """Queries from the upstream test suites kept as verdict tables."""
    tables = {
        "lucene": ("testdata/conformance/external/lucene-queryparser/cases.tsv", unescape_tsv),
        "kuery": ("testdata/conformance/external/kuery-opensearch-dashboards/cases.tsv", json.loads),
    }
    if language not in tables:
        return []
    path, decode = tables[language]
    queries = []
    for n, line in enumerate((ROOT / path).read_text().splitlines(), 1):
        if line.startswith("#") or not line.strip():
            continue
        query = decode(line.split("\t")[1])
        queries.append(Query(f"{path}:{n}", query, False))
    return queries


def unescape_tsv(text: str) -> str:
    return re.sub(r"\\([tnr\\])", lambda m: {"t": "\t", "n": "\n", "r": "\r", "\\": "\\"}[m.group(1)], text)


def elastic_language(rule_type: object, language: object) -> str | None:
    """Mirror of opentide_tide::elastic_query_language."""
    if rule_type in ("esql", "eql"):
        return str(rule_type)
    if rule_type in ("query", "threshold", "new_terms", "threat_match"):
        return {None: "kuery", "kuery": "kuery", "lucene": "lucene"}.get(language)  # type: ignore[arg-type]
    return None


def elastic_embedded(language: str) -> list[Query]:
    """Elastic queries in Tide rules: the block query, `threat.query`, and
    `response.procedure.searches[]` entries that declare their language."""
    import yaml

    queries = []
    for path in sorted(ROOT.glob("testdata/**/*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        block = (doc.get("configurations") or {}).get("elastic")
        if isinstance(block, dict):
            if elastic_language(block.get("type"), block.get("language")) == language and isinstance(block.get("query"), str):
                queries.append(Query(f"{rel(path)}#configurations.elastic.query", block["query"], False))
            threat = block.get("threat")
            if (
                block.get("type") == "threat_match"
                and isinstance(threat, dict)
                and elastic_language("threat_match", threat.get("language")) == language
                and isinstance(threat.get("query"), str)
            ):
                queries.append(Query(f"{rel(path)}#configurations.elastic.threat.query", threat["query"], False))
        searches = ((doc.get("response") or {}).get("procedure") or {}).get("searches") or []
        for n, search in enumerate(searches if isinstance(searches, list) else []):
            if (
                isinstance(search, dict)
                and search.get("system") == "elastic"
                and search.get("language") == language
                and isinstance(search.get("query"), str)
            ):
                queries.append(Query(f"{rel(path)}#response.procedure.searches.{n}.query", search["query"], False))
    return queries


def detection_rules(language: str) -> list[Query]:
    """Elastic's public rules from an elastic/detection-rules checkout named
    by OPENTIDE_DETECTION_RULES (ELv2: read at CI time, never vendored).
    Elasticsearch accepts every one of them."""
    root = os.environ.get("OPENTIDE_DETECTION_RULES")
    if not root:
        return []
    base = pathlib.Path(root)
    queries = []
    files = sorted(p for d in ("rules", "rules_building_block", "hunting") for p in (base / d).rglob("*.toml"))
    for path in files:
        try:
            doc = tomllib.loads(path.read_text())
        except (tomllib.TOMLDecodeError, UnicodeDecodeError):
            continue
        ident = f"detection-rules:{path.relative_to(base).as_posix()}"
        rule = doc.get("rule") or {}
        if elastic_language(rule.get("type"), rule.get("language")) == language and isinstance(rule.get("query"), str):
            queries.append(Query(f"{ident}#query", rule["query"].rstrip(), False))
        if (
            rule.get("type") == "threat_match"
            and elastic_language("threat_match", rule.get("threat_language")) == language
            and isinstance(rule.get("threat_query"), str)
        ):
            queries.append(Query(f"{ident}#threat_query", rule["threat_query"].rstrip(), False))
        hunt = doc.get("hunt") or {}
        hunt_language = {("ES|QL",): "esql", ("EQL",): "eql"}.get(tuple(hunt.get("language") or []))
        if hunt_language == language:
            for n, query in enumerate(hunt.get("query") or []):
                if isinstance(query, str):
                    queries.append(Query(f"{ident}#hunt.query.{n}", query.strip(), False))
    return queries


def embedded(language: str) -> list[Query]:
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML is required to read Tide rules (pip install pyyaml)")
    queries = []
    for path in sorted(ROOT.glob("testdata/**/*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError:
            continue
        configurations = doc.get("configurations") if isinstance(doc, dict) else None
        if not isinstance(configurations, dict):
            continue
        for platform, (lang, fields) in PLATFORMS.items():
            config = configurations.get(platform)
            if lang != language or not isinstance(config, dict):
                continue
            for field in fields:
                if isinstance(config.get(field), str):
                    ident = f"{rel(path)}#configurations.{platform}.{field}"
                    queries.append(Query(ident, config[field], False))
    return queries


def rel(path: pathlib.Path) -> str:
    return path.relative_to(ROOT).as_posix()


def ours(language: str, queries: list[Query], scratch: pathlib.Path) -> dict[str, list[dict]]:
    subprocess.run(
        ["cargo", "build", "--quiet", "-p", "opentide-lsp"],
        cwd=ROOT,
        check=True,
        stdout=sys.stderr,
    )
    exe = ROOT / "target/debug" / ("opentide-lsp.exe" if os.name == "nt" else "opentide-lsp")
    # Without an `objects/` above it, `analyze` loads every YAML file under the
    # file's grandparent (the system temp directory). An empty one keeps each
    # query a standalone document, as the reference sees it.
    (scratch / "objects").mkdir(exist_ok=True)

    def analyze(item: tuple[int, Query]) -> tuple[str, list[dict]]:
        n, query = item
        path = scratch / f"ours-{n}.{language}"
        path.write_text(query.text)
        run = subprocess.run(
            [str(exe), "analyze", "--language", language, str(path)],
            capture_output=True,
            text=True,
        )
        if run.returncode != 0:
            sys.exit(f"opentide-lsp analyze failed on {query.id}: {run.stderr.strip()}")
        return query.id, json.loads(run.stdout)

    with concurrent.futures.ThreadPoolExecutor() as pool:
        return dict(pool.map(analyze, enumerate(queries)))


def rejected_by_ours(language: str, diagnostics: list[dict]) -> list[str]:
    return [
        f"{d['code']}: {d['message']}"
        for d in diagnostics
        if d["code"] in REJECT[language]
        and (language not in ELASTIC_LANGUAGES or d["severity"] == "error")
    ]


def unknown_names(language: str, diagnostics: dict[str, list[dict]]) -> dict[str, str]:
    if language not in UNKNOWN_NAME:
        return {}
    code, pattern = UNKNOWN_NAME[language]
    names: dict[str, str] = {}
    for ident, diags in diagnostics.items():
        if ".broken." in ident:
            continue  # the injected fault is not a name
        for d in diags:
            match = pattern.search(d["message"]) if d["code"] == code else None
            if match:
                names.setdefault(match.group(1), ident)
    return names


# --- Kusto.Language ---------------------------------------------------------


def kusto(*args: str) -> str:
    out = KUSTO / "bin/oracle"
    if not kusto.built:
        subprocess.run(
            ["dotnet", "build", str(KUSTO), "-c", "Release", "-o", str(out), "--nologo", "-v", "q"],
            check=True,
            stdout=sys.stderr,
        )
        kusto.built = True
    run = subprocess.run(
        ["dotnet", str(out / "KustoOracle.dll"), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return run.stdout


kusto.built = False


def kql_reference(queries: list[Query], scratch: pathlib.Path) -> dict[str, list[str]]:
    paths = {}
    for n, query in enumerate(queries):
        path = scratch / f"kusto-{n}.kql"
        path.write_text(query.text)
        paths[str(path)] = query.id
    verdicts = {}
    for line in kusto("parse", *paths).splitlines():
        result = json.loads(line)
        verdicts[paths[result["path"]]] = [
            f"{e['code']} at {e['start']}: {e['message']}" for e in result["errors"]
        ]
    return verdicts


# Ours reports these only where Kusto rejects the query; the reference must agree.
SEMANTIC = {"kql_unknown_column", "kql_type_mismatch"}
COLUMN_FIXTURES = "testdata/conformance/columns/"


def kql_schema() -> dict:
    """The engine's `sentinel` view of tables, columns and ASIM parsers, as a
    Kusto.Language database: the Azure Monitor reference, the hand-written
    columns, the standard Log Analytics columns, `Timestamp` on the advanced
    hunting tables, and each ASIM parser returning its schema."""
    reference = json.loads((ROOT / "catalogs/kql/azure-monitor/tables.json").read_text())
    tables: dict[str, list[list[str]]] = {
        t["name"]: [list(c) for c in t["columns"]] for t in reference["tables"] if t.get("columns")
    }
    standard = [
        ["TenantId", "string"], ["TimeGenerated", "datetime"], ["Type", "string"],
        ["SourceSystem", "string"], ["_ResourceId", "string"], ["_SubscriptionId", "string"],
        ["_BilledSize", "real"], ["_IsBillable", "string"], ["_ItemId", "string"],
        ["_TimeReceived", "datetime"],
    ]
    for columns in tables.values():
        have = {c[0] for c in columns}
        columns.extend(c for c in standard if c[0] not in have)
    for path in ("catalogs/kql/sentinel/columns.toml", "catalogs/kql/defender/columns.toml"):
        for column in load_toml(path)["columns"]:
            listed = tables.setdefault(column["table"], [])
            if column["name"] not in {c[0] for c in listed}:
                listed.append([column["name"], column.get("type") or "dynamic"])
    for table in load_toml("catalogs/kql/defender/tables.toml")["tables"]:
        listed = tables.setdefault(table["name"], [])
        if "Timestamp" not in {c[0] for c in listed}:
            listed.append(["Timestamp", "datetime"])
    asim = json.loads((ROOT / "catalogs/kql/asim/asim.json").read_text())
    functions = {
        p["name"]: {
            "columns": [[c[0], c[1]] for c in asim["schemas"][p["schema"]]["columns"]],
            "params": [[q["name"], q["type"]] for q in p["params"]],
        }
        for p in asim["parsers"]
    }
    return {"tables": tables, "functions": functions}


def kql_semantic(queries: list[Query], scratch: pathlib.Path) -> dict[str, list[dict]]:
    schema = scratch / "kusto-schema.json"
    schema.write_text(json.dumps(kql_schema()))
    paths = {}
    for n, query in enumerate(queries):
        path = scratch / f"kusto-semantic-{n}.kql"
        path.write_text(query.text)
        paths[str(path)] = query.id
    found = {}
    for line in kusto("semantic", str(schema), *paths).splitlines():
        result = json.loads(line)
        found[paths[result["path"]]] = result["errors"]
    return found


def kql_columns(
    queries: list[Query],
    diagnostics: dict[str, list[dict]],
    semantic: dict[str, list[dict]],
    known: Ledger,
    errors: list[str],
) -> None:
    """Every column or type error ours reports, Kusto.Language reports too."""
    checked = confirmed = listed = 0
    for query in queries:
        reported = [
            d for d in diagnostics[query.id] if d["code"] in SEMANTIC and d["severity"] == "error"
        ]
        if query.id.startswith(COLUMN_FIXTURES) and not reported:
            errors.append(f"{query.id}: ours reports no kql_unknown_column or kql_type_mismatch on this fixture")
        theirs = semantic.get(query.id, [])
        for d in reported:
            checked += 1
            if d["code"] == "kql_unknown_column":
                name = d["message"].split("'")[1]
                agrees = any(e["text"] == name for e in theirs)
            else:
                agrees = any(e["code"] in ("KS106", "KS107") for e in theirs)
            if agrees:
                confirmed += 1
                continue
            ident = known.paths.get(query.id)
            side = f"ours reports {d['code']} ({d['message']}), Kusto.Language accepts it"
            if ident:
                listed += 1
                print(f"known  {query.id} [{ident}]: {side}")
            else:
                errors.append(f"{query.id}: {side}")
    print(f"Kusto.Language semantics: {checked} column and type errors from ours, {confirmed} confirmed, {listed} listed")


def kql_names(flagged: dict[str, str]) -> dict[str, str]:
    """Function and plugin names the two sides disagree on, with the reason."""
    reference = {
        s["name"]: s
        for s in json.loads(kusto("symbols"))
        if not s["name"].startswith("__")  # Kusto.Language internals
    }
    catalog = {f["name"] for f in load_toml("catalogs/kql/core/functions.toml")["functions"]}
    plugins = {p["name"] for p in load_toml("catalogs/kql/core/evaluate-plugins.toml")["plugins"]}
    ours_known = catalog | plugins
    disagree = {}
    for name in sorted(ours_known - reference.keys()):
        where = "evaluate-plugins.toml" if name in plugins else "functions.toml"
        disagree[name] = f"in catalogs/kql/core/{where}, unknown to Kusto.Language"
    for name in sorted(reference.keys() - ours_known):
        s = reference[name]
        status = "obsolete " if s["obsolete"] else "hidden " if s["hidden"] else ""
        disagree[name] = f"Kusto.Language {status}{s['kind']}, missing from catalogs/kql/core"
    for name, ident in flagged.items():
        if name in reference and name in ours_known:
            disagree[name] = f"in both catalogs, but ours reports kql_unknown_function in {ident}"
    return disagree


# --- Splunk -----------------------------------------------------------------


class Splunk:
    def __init__(self) -> None:
        self.url = os.environ.get("SPLUNK_URL", "https://localhost:8089").rstrip("/")
        user = os.environ.get("SPLUNK_USERNAME", "admin")
        password = os.environ.get("SPLUNK_PASSWORD")
        if not password:
            sys.exit("SPLUNK_PASSWORD is not set")
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        host = urllib.parse.urlsplit(self.url).hostname or ""
        self.context = ssl.create_default_context(cafile=os.environ.get("SPLUNK_CA"))
        if not os.environ.get("SPLUNK_CA") and is_loopback(host):
            # The oracle container's management port uses Splunk's self-signed certificate.
            self.context = ssl._create_unverified_context()

    def request(self, method: str, path: str, data: dict | None = None) -> tuple[int, dict]:
        body = urllib.parse.urlencode({**(data or {}), "output_mode": "json"}).encode()
        url = f"{self.url}{path}"
        if method in ("GET", "DELETE"):
            url, body = f"{url}?{body.decode()}", None
        req = urllib.request.Request(url, body, {"Authorization": self.auth}, method=method)
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, context=self.context, timeout=60) as resp:
                    return resp.status, json.loads(resp.read() or b"{}")
            except urllib.error.HTTPError as err:
                raw = err.read()
                try:
                    return err.code, json.loads(raw or b"{}")
                except json.JSONDecodeError:
                    return err.code, {"messages": [{"type": "ERROR", "text": raw.decode(errors="replace")}]}
            except (urllib.error.URLError, OSError):
                # splunkd restarts once while the container finishes provisioning.
                if attempt == 2:
                    raise
                time.sleep(10)
        raise AssertionError("unreachable")

    def wait(self, seconds: int) -> dict:
        deadline = time.monotonic() + seconds
        while True:
            try:
                status, body = self.request("GET", "/services/server/info")
                if status == 200:
                    return body["entry"][0]["content"]
                if status == 401:
                    sys.exit(f"Splunk at {self.url} rejected SPLUNK_USERNAME/SPLUNK_PASSWORD")
            except (urllib.error.URLError, OSError):
                pass
            if time.monotonic() > deadline:
                sys.exit(f"Splunk at {self.url} did not answer within {seconds}s")
            time.sleep(5)

    def define_macro(self, name: str, args: list[str], definition: str) -> None:
        stanza = f"{name}({len(args)})" if args else name
        data = {"definition": definition, "args": ",".join(args)} if args else {"definition": definition}
        base = "/servicesNS/nobody/search/configs/conf-macros"
        status, body = self.request("POST", base, {"name": stanza, **data})
        if status == 409:
            status, body = self.request("POST", f"{base}/{urllib.parse.quote(stanza, safe='')}", data)
        if status >= 300:
            sys.exit(f"could not define macro {stanza}: {status} {body}")

    def define_datamodel(self, model: str, datasets: dict[str, list[str]]) -> None:
        objects = [
            {
                "objectName": name,
                "displayName": name,
                "parentName": "BaseEvent",
                "comment": "",
                "lineage": name,
                "calculations": [],
                "constraints": [{"search": "index=*", "owner": name}],
                "fields": [
                    {
                        "fieldName": field,
                        "displayName": field,
                        "owner": name,
                        "type": "string",
                        "fieldSearch": "",
                        "required": False,
                        "multivalue": False,
                        "hidden": False,
                        "editable": True,
                        "comment": "",
                    }
                    for field in fields
                ],
            }
            for name, fields in datasets.items()
        ]
        description = {
            "modelName": model,
            "displayName": model,
            "description": "opentide oracle stand-in built from catalogs/spl/datamodels.toml",
            "editable": True,
            "objectNameList": list(datasets),
            "objects": objects,
        }
        base = "/servicesNS/nobody/search/datamodel/model"
        self.request("DELETE", f"{base}/{model}")
        status, body = self.request("POST", base, {"name": model, "description": json.dumps(description)})
        if status >= 300:
            sys.exit(f"could not define data model {model}: {status} {body}")

    def parse(self, query: str) -> list[str]:
        status, body = self.request(
            "POST", "/services/search/parser", {"q": query, "parse_only": "t"}
        )
        messages = [
            m["text"] for m in body.get("messages", []) if m.get("type") in ("FATAL", "ERROR")
        ]
        if status >= 300 and not messages:
            messages = [f"HTTP {status}"]
        return messages

    def commands(self) -> set[str]:
        status, body = self.request("GET", "/services/configs/conf-searchbnf", {"count": "0"})
        if status != 200:
            sys.exit(f"could not list searchbnf: {status}")
        names = set()
        for entry in body["entry"]:
            if entry["name"].endswith("-command"):
                names.add(entry["name"].removesuffix("-command"))
                aliases = entry["content"].get("alias") or entry["content"].get("aliases") or ""
                names.update(a for a in re.split(r"[\s,]+", aliases) if a)
        return names


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


MISSING_MACRO = re.compile(r"macro '([^']+)' that cannot be found")


def spl_reference(splunk: Splunk, queries: list[Query]) -> dict[str, list[str]]:
    macros = load_toml(MACROS.relative_to(ROOT).as_posix())["macros"]
    for macro in macros:
        splunk.define_macro(macro["name"], macro.get("args", []), macro["definition"])
    defined = {m["name"] for m in macros}
    for query in queries:
        for name in re.findall(r"`([A-Za-z0-9_]+_filter)`", query.text):
            if name not in defined:
                splunk.define_macro(name, [], "search *")
                defined.add(name)

    models: dict[str, dict[str, list[str]]] = {}
    for dm in load_toml("catalogs/spl/datamodels.toml")["datamodels"]:
        # One row per dataset; a root's stand-in carries its children's fields too.
        fields = models.setdefault(dm["model"], {}).setdefault(dm["prefix"], [])
        fields += [f for f in dm.get("fields", []) if f not in fields]
    for model, datasets in models.items():
        splunk.define_datamodel(model, datasets)

    def verdict(query: Query) -> tuple[str, list[str]]:
        text = query.text.strip()
        # Splunk runs authored text as if it began with `search` (docs/spl/README.md).
        return query.id, splunk.parse(text if text.startswith("|") else f"search {text}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        verdicts = dict(pool.map(verdict, queries))
    missing = sorted({m for errors in verdicts.values() for e in errors for m in MISSING_MACRO.findall(e)})
    if missing:
        sys.exit(f"define these macros in {rel(MACROS)}: {', '.join(missing)}")
    return verdicts


def spl_names(splunk: Splunk, flagged: dict[str, str]) -> dict[str, str]:
    reference = splunk.commands()
    catalog = {c["name"] for c in load_toml("catalogs/spl/commands.toml")["commands"]}
    disagree = {}
    for name in sorted(catalog - reference):
        # searchbnf does not list every alias; the parser is the authority.
        errors = splunk.parse(f"| makeresults | {name}")
        if any(e.startswith("Unknown search command") for e in errors):
            disagree[name] = "in catalogs/spl/commands.toml, unknown to Splunk"
    for name in sorted(reference - catalog):
        disagree[name] = "Splunk searchbnf command, missing from catalogs/spl/commands.toml"
    for name, ident in flagged.items():
        if name in reference and name in catalog:
            disagree[name] = f"in both catalogs, but ours reports spl_unknown_command in {ident}"
    return disagree


# --- Elastic -----------------------------------------------------------------


def fetch(name: str) -> pathlib.Path:
    """A pinned reference file, downloaded once and checked by SHA-256."""
    import hashlib

    url, digest = FETCH[name]
    path = ELASTIC_CACHE / name
    if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() == digest:
        return path
    ELASTIC_CACHE.mkdir(exist_ok=True)
    with urllib.request.urlopen(url, timeout=120) as resp:
        data = resp.read()
    got = hashlib.sha256(data).hexdigest()
    if got != digest:
        sys.exit(f"{name}: {url} has SHA-256 {got}, expected {digest}")
    path.write_bytes(data)
    return path


def node_sandbox() -> pathlib.Path:
    """scripts/oracles/elastic/node_modules from its lock file, without install scripts."""
    if not (ELASTIC / "node_modules/.package-lock.json").exists():
        subprocess.run(
            ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            cwd=ELASTIC,
            check=True,
            stdout=sys.stderr,
        )
    return ELASTIC / "node_modules"


def elastic_runner(language: str) -> list[str]:
    """The command that prints `<file>\tOK|ERR\t<message>` for a directory."""
    if language == "lucene":
        jars = os.pathsep.join(str(fetch(j)) for j in ("lucene-core.jar", "lucene-queryparser.jar"))
        return ["java", "-cp", jars, str(ELASTIC / "LuceneOracle.java")]
    modules = node_sandbox()
    if language == "esql":
        return ["node", str(ELASTIC / "esql.cjs"), str(ELASTIC)]
    if language == "eql":
        gen = ELASTIC_CACHE / "eql"
        if not (gen / "EqlBaseParser.js").exists():
            subprocess.run(
                [str(modules / ".bin/antlr-ng"), "-Dlanguage=JavaScript", "-o", str(gen), str(fetch("EqlBase.g4"))],
                check=True,
                stdout=sys.stderr,
            )
            (gen / "package.json").write_text('{"type": "module"}\n')
        return ["node", str(ELASTIC / "eql.mjs"), str(gen), str(modules / "antlr4")]
    parser = ELASTIC_CACHE / "kuery.cjs"
    if not parser.exists():
        subprocess.run(
            [str(modules / ".bin/peggy"), "--format", "commonjs", "--allowed-start-rules", "start",
             "-o", str(parser), str(fetch("grammar.peggy"))],
            check=True,
            stdout=sys.stderr,
        )
    return ["node", str(ELASTIC / "kuery.cjs"), str(parser)]


def elastic_reference(language: str, queries: list[Query], scratch: pathlib.Path) -> dict[str, list[str]]:
    folder = scratch / f"reference-{language}"
    folder.mkdir()
    files = {}
    for n, query in enumerate(queries):
        name = f"q{n:06}.{language}"
        (folder / name).write_text(query.text)
        files[name] = query.id
    run = subprocess.run([*elastic_runner(language), str(folder)], capture_output=True, text=True)
    if run.returncode != 0:
        sys.exit(f"{REFERENCE[language]} runner failed: {run.stderr.strip()[-2000:]}")
    verdicts = {}
    for line in run.stdout.splitlines():
        name, verdict, message = (line.split("\t", 2) + ["", ""])[:3]
        if name in files:
            verdicts[files[name]] = [message or "error"] if verdict == "ERR" else []
    return verdicts


# --- comparison -------------------------------------------------------------


def load_toml(path: str) -> dict:
    return tomllib.loads((ROOT / path).read_text())


@dataclasses.dataclass
class Ledger:
    paths: dict[str, str]
    names: dict[str, str]


def ledger(language: str, ids: set[str], errors: list[str]) -> Ledger:
    paths: dict[str, str] = {}
    names: dict[str, str] = {}
    for entry in load_toml(rel(EXCEPTIONS)).get(language, []):
        ident = entry.get("id")
        if not ident or not entry.get("reason"):
            errors.append(f"[[{language}]] exception {ident!r} needs an id and a reason")
            continue
        if ("paths" in entry) == ("names" in entry):
            errors.append(f"[[{language}]] exception {ident}: give exactly one of `paths` or `names`")
            continue
        for path in entry.get("paths", []):
            if path not in ids:
                errors.append(f"[[{language}]] exception {ident}: {path} is not in the {language} corpus")
            elif path in paths:
                errors.append(f"[[{language}]] exception {ident}: {path} is already listed by {paths[path]}")
            else:
                paths[path] = ident
        for name in entry.get("names", []):
            if name in names:
                errors.append(f"[[{language}]] exception {ident}: {name} is already listed by {names[name]}")
            else:
                names[name] = ident
    return Ledger(paths, names)


def compare(
    language: str,
    queries: list[Query],
    diagnostics: dict[str, list[dict]],
    reference: dict[str, list[str]],
    names: dict[str, str],
    known: Ledger,
    errors: list[str],
) -> None:
    oracle = REFERENCE[language]
    unlisted_paths, unlisted_names = [], []
    differ = listed = 0
    for query in queries:
        ours_errors = rejected_by_ours(language, diagnostics[query.id])
        theirs = reference.get(query.id)
        if theirs is None:
            errors.append(f"{query.id}: {oracle} returned no verdict")
            continue
        if query.broken and not theirs:
            errors.append(f"{query.id}: {oracle} accepts this .broken. fixture; move its fault out of comments and strings")
        if query.probe:
            # A probe is a valid detection form: no error from ours at all, not
            # only no syntax error (unknown table, unknown function, ...).
            for d in diagnostics[query.id]:
                if d["severity"] == "error" and d["code"] not in REJECT[language]:
                    errors.append(f"{query.id}: ours reports {d['code']} on a probe: {d['message']}")
        ident = known.paths.get(query.id)
        if bool(ours_errors) == bool(theirs):
            if ident:
                errors.append(f"{query.id}: ours and {oracle} now agree; remove it from exception {ident}")
            continue
        differ += 1
        side = (
            f"ours rejects ({ours_errors[0]}), {oracle} accepts"
            if ours_errors
            else f"ours accepts, {oracle} rejects ({theirs[0]})"
        )
        if ident:
            listed += 1
            print(f"known  {query.id} [{ident}]: {side}")
        else:
            errors.append(f"{query.id}: {side}")
            unlisted_paths.append(query.id)

    for name, why in sorted(names.items()):
        ident = known.names.get(name)
        if ident:
            listed += 1
            print(f"known  name {name} [{ident}]: {why}")
        else:
            errors.append(f"name {name}: {why}")
            unlisted_names.append(name)
    for name, ident in sorted(known.names.items()):
        if name not in names:
            errors.append(f"name {name}: ours and {oracle} now agree; remove it from exception {ident}")

    print(
        f"{oracle}: {len(queries)} {language} queries, {differ} verdicts differ; "
        f"{len(names)} names differ; {listed} listed in {rel(EXCEPTIONS)}"
    )
    if unlisted_paths or unlisted_names:
        print(f"\nunlisted disagreements, as a starting point for {rel(EXCEPTIONS)}:")
        for key, values in (("paths", unlisted_paths), ("names", unlisted_names)):
            if values:
                body = ",\n".join(f'  "{v}"' for v in values)
                print(f'\n[[{language}]]\nid = "TODO"\nreason = "TODO"\n{key} = [\n{body},\n]')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("language", choices=sorted(REFERENCE))
    parser.add_argument("--splunk-wait", type=int, default=600, help="seconds to wait for splunkd")
    args = parser.parse_args()
    language = args.language

    queries = corpus(language)
    errors: list[str] = []
    known = ledger(language, {q.id for q in queries}, errors)
    with tempfile.TemporaryDirectory() as tmp:
        scratch = pathlib.Path(tmp)
        diagnostics = ours(language, queries, scratch)
        flagged = unknown_names(language, diagnostics)
        if language == "kql":
            reference = kql_reference(queries, scratch)
            names = kql_names(flagged)
            kql_columns(queries, diagnostics, kql_semantic(queries, scratch), known, errors)
        elif language in ELASTIC_LANGUAGES:
            # Catalog names come from the pinned Elasticsearch docs through
            # the sync scripts; the parser references carry no catalog.
            reference = elastic_reference(language, queries, scratch)
            names = {}
        else:
            splunk = Splunk()
            info = splunk.wait(args.splunk_wait)
            print(f"Splunk {info.get('version')} at {splunk.url}")
            reference = spl_reference(splunk, queries)
            names = spl_names(splunk, flagged)
    compare(language, queries, diagnostics, reference, names, known, errors)
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
