#!/usr/bin/env python3
"""Differential oracles: the opentide engine against the reference parser.

    oracle.py kql   Microsoft Kusto.Language (scripts/oracles/kusto, needs dotnet)
    oracle.py spl   Splunk's search/parser REST endpoint (needs SPLUNK_PASSWORD)

Both run every query in the corpus through `opentide-lsp analyze` and through
the reference, then compare two things:

- Verdicts. A query is rejected when ours reports a syntax diagnostic, or when
  the reference reports an error. Each query where the verdicts differ must be
  listed by `paths` in testdata/oracles/exceptions.toml. A `.broken.` fixture
  the reference accepts is always an error: its injected fault breaks nothing.
- Names. KQL functions and plugins, or SPL commands, that one side knows and
  the other does not, plus names ours flags as unknown that the reference
  knows. Each must be listed by `names`.

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
MACROS = ROOT / "scripts/oracles/splunk/macros.toml"

# Diagnostics that mean ours rejects the query's syntax.
REJECT = {
    "kql": {"kql_parse_error", "kql_unknown_operator"},
    "spl": {"spl_parse_error", "spl_unknown_command"},
}
UNKNOWN_NAME = {
    "kql": ("kql_unknown_function", re.compile(r"unknown function '([^']+)'")),
    "spl": ("spl_unknown_command", re.compile(r"unknown SPL command '([^']+)'")),
}
REFERENCE = {"kql": "Kusto.Language", "spl": "Splunk"}

# Tide configuration fields the engine injects (opentide-tide language_for_field_path).
PLATFORMS = {
    "sentinel": ("kql", ("query",)),
    "defender_for_endpoint": ("kql", ("query",)),
    "splunk": ("spl", ("query", "search")),
}
# A corpus fixture's tag line. SPL comments need a closing ```, so the line is
# not SPL; corpus_gate.rs strips it the same way.
FIXTURE_TAG = re.compile(r"\A(//|```) prod:[^\n]*\n")


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
        ]
    )
    queries = [
        Query(rel(p), FIXTURE_TAG.sub("", p.read_text(), count=1), ".broken." in p.name)
        for p in files
    ]
    return queries + embedded(language)


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
    return [f"{d['code']}: {d['message']}" for d in diagnostics if d["code"] in REJECT[language]]


def unknown_names(language: str, diagnostics: dict[str, list[dict]]) -> dict[str, str]:
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
        models.setdefault(dm["model"], {})[dm["prefix"]] = dm.get("fields", [])
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
