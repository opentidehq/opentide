#!/usr/bin/env python3
"""Generate the Falco catalogs (catalogs/falco/) from public Falco sources.

Reads three checkouts:

- falcosecurity/falco-website (CC BY 4.0):
  ``content/en/docs/reference/rules/supported-fields/supported-fields.md`` for
  the libsinsp field classes of the ``syscall`` source, and
  ``reference/rules/supported-events/supported-events.md`` for event names;
- falcosecurity/plugins (Apache-2.0): each plugin README's field table
  (``k8saudit``, ``k8saudit-eks``, ``cloudtrail``, ``okta``, ``github``,
  ``gcpaudit``, ``json``, ``k8smeta``, ``container``) and the plugins' default
  rules files;
- falcosecurity/rules (Apache-2.0): ``rules/*.yaml``.

and writes:

- ``catalogs/falco/fields.toml``: event sources, then one row per field with
  its type, the sources it applies to, whether it takes an argument
  (``proc.aname[2]``, ``evt.arg.flags``) and its description;
- ``catalogs/falco/defaults.toml``: the macros and lists of the Falco default
  rules, with the condition or items and the file that defines them (a later
  file overrides an earlier one, as Falco loads them);
- ``catalogs/falco/events.toml``: event names ``evt.type`` compares with.

With ``--corpus``, it also writes ``testdata/conformance/external/falco/``:
each default rule's condition, unmodified, as ``<slug>.falco``, plus a
``.broken.falco`` twin with one injected fault.

The catalogs are never a closed list for the engine: an unknown field or
reference is a warning, because plugins add fields and Sysdig manages macros
of its own (sysdig-1.0, "Falco language").

Usage:
    python scripts/sync_falco_catalog.py --website ../falco-website \
        --plugins ../plugins --rules ../rules [--corpus] [--check]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "catalogs" / "falco"
CORPUS = ROOT / "testdata" / "conformance" / "external" / "falco"

FIELDS_MD = "content/en/docs/reference/rules/supported-fields/supported-fields.md"
EVENTS_MD = "content/en/docs/reference/rules/supported-events/supported-events.md"

# Plugin -> the event sources its fields apply to. An extractor plugin
# (json, k8smeta, container) has no source of its own.
PLUGIN_SOURCES: dict[str, list[str]] = {
    "k8saudit": ["k8s_audit"],
    "k8saudit-eks": ["k8s_audit"],
    "cloudtrail": ["aws_cloudtrail"],
    "okta": ["okta"],
    "github": ["github"],
    "gcpaudit": ["gcp_auditlog"],
    "k8smeta": ["syscall"],
    "container": ["syscall"],
    "json": ["k8s_audit", "aws_cloudtrail", "okta", "github", "gcp_auditlog"],
}

SOURCES: list[tuple[str, str, str]] = [
    ("syscall", "libsinsp", "Linux system calls, captured by the Falco kernel driver or eBPF probe."),
    ("k8s_audit", "k8saudit", "Kubernetes audit events (k8saudit and k8saudit-eks plugins)."),
    ("aws_cloudtrail", "cloudtrail", "AWS CloudTrail events (cloudtrail plugin)."),
    ("okta", "okta", "Okta System Log events (okta plugin)."),
    ("github", "github", "GitHub webhook events (github plugin)."),
    ("gcp_auditlog", "gcpaudit", "Google Cloud audit logs (gcpaudit plugin)."),
]

# Default rules files, in the order Falco loads them: a later definition of a
# macro or list replaces an earlier one.
RULE_FILES: list[tuple[str, str, str]] = [
    ("rules", "rules/falco_rules.yaml", "syscall"),
    ("rules", "rules/falco-incubating_rules.yaml", "syscall"),
    ("rules", "rules/falco-sandbox_rules.yaml", "syscall"),
    ("plugins", "plugins/k8saudit/rules/k8s_audit_rules.yaml", "k8s_audit"),
    ("plugins", "plugins/cloudtrail/rules/aws_cloudtrail_rules.yaml", "aws_cloudtrail"),
    ("plugins", "plugins/okta/rules/okta_rules.yaml", "okta"),
    ("plugins", "plugins/github/rules/github.yaml", "github"),
    ("plugins", "plugins/gcpaudit/rules/gcp_auditlog_rules.yaml", "gcp_auditlog"),
]

# Fields current libsinsp no longer documents that rules written for older
# Falco releases and for Sysdig agents still use. Without them every such rule
# would warn; each is kept with the reason.
LEGACY_FIELDS: list[dict] = [
    {
        "name": "evt.dir",
        "type": "CHARBUF",
        "kind": "string",
        "class": "evt (legacy)",
        "sources": ["syscall"],
        "arg": False,
        "description": (
            "Event direction: '>' for enter events, '<' for exit events. Removed from "
            "libsinsp when enter events were dropped; Sysdig agents and older Falco "
            "releases still read it, and `evt.dir = <` is common in their rules."
        ),
    },
]

STRING_TYPES = {"CHARBUF", "FSPATH", "FSRELPATH", "string", "BYTEBUF", "DYNAMIC"}
NUMBER_TYPES = {
    "UINT8", "UINT16", "UINT32", "UINT64", "INT8", "INT16", "INT32", "INT64",
    "RELTIME", "ABSTIME", "DOUBLE", "PORT", "ERRNO", "PID", "FD", "SYSCALLID",
    "SIGTYPE", "uint64", "reltime", "abstime", "MODE", "UID", "GID",
}
BOOL_TYPES = {"BOOL", "bool"}
IP_TYPES = {"IPV4ADDR", "IPV6ADDR", "IPADDR", "IPNET", "IPV4NET", "IPV6NET", "ipaddr", "ipnet"}


def kind(field_type: str) -> str:
    if field_type in STRING_TYPES:
        return "string"
    if field_type in NUMBER_TYPES:
        return "number"
    if field_type in BOOL_TYPES:
        return "bool"
    if field_type in IP_TYPES:
        return "ip"
    return "other"


def clean(text: str) -> str:
    text = " ".join((text or "").split())
    return text.replace("\\|", "|")


def website_fields(website: Path) -> list[dict]:
    rows: list[dict] = []
    current_class = ""
    common = False
    for line in (website / FIELDS_MD).read_text(encoding="utf-8").splitlines():
        heading = re.match(r"### Field Class: (.+)", line)
        if heading:
            current_class = heading.group(1).strip()
            # The first class, `evt`, applies to every event source.
            common = current_class == "evt"
            continue
        m = re.match(r"`([A-Za-z0-9_.]+)` \| ([A-Za-z0-9_]+) \| (.*)$", line)
        if not m:
            continue
        name, field_type, desc = m.group(1), m.group(2), clean(m.group(3))
        rows.append(
            {
                "name": name,
                "type": field_type,
                "kind": kind(field_type),
                "class": current_class,
                "sources": ["*"] if common else ["syscall"],
                "arg": f"{name}[" in desc or f"{name}." in desc,
                "description": desc,
            }
        )
    return rows


def plugin_fields(plugins: Path, plugin: str) -> list[dict]:
    readme = plugins / "plugins" / plugin / "README.md"
    rows = []
    for line in readme.read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))]
        if len(cells) < 4 or not re.fullmatch(r"`[A-Za-z0-9_.]+`", cells[0]):
            continue
        name = cells[0].strip("`")
        field_type = cells[1].strip("`")
        arg = cells[2] if cells[2] != "None" else ""
        rows.append(
            {
                "name": name,
                "type": field_type,
                "kind": kind(field_type),
                "class": plugin,
                "sources": PLUGIN_SOURCES[plugin],
                "arg": bool(arg),
                "description": clean(cells[3]),
            }
        )
    return rows


def merge_fields(rows: list[dict]) -> list[dict]:
    """One row per field name; sources are united, the first description kept."""
    merged: dict[str, dict] = {}
    for row in rows:
        seen = merged.get(row["name"])
        if seen is None:
            merged[row["name"]] = dict(row, sources=list(row["sources"]))
            continue
        for source in row["sources"]:
            if source not in seen["sources"]:
                seen["sources"].append(source)
        seen["arg"] = seen["arg"] or row["arg"]
    return sorted(merged.values(), key=lambda r: r["name"])


def events(website: Path) -> list[dict]:
    out: dict[str, str] = {}
    section = ""
    for line in (website / EVENTS_MD).read_text(encoding="utf-8").splitlines():
        heading = re.match(r"## (.+) events", line)
        if heading:
            section = heading.group(1).strip().lower()
            continue
        m = re.match(r"(?:Yes|No) \| `[<>]` \| `([a-z0-9_]+)` \|", line)
        if m and section:
            out.setdefault(m.group(1), section)
    return [{"name": name, "kind": kind_} for name, kind_ in sorted(out.items())]


def defaults(rules: Path, plugins: Path) -> tuple[list[dict], list[dict], list[dict]]:
    macros: dict[str, dict] = {}
    lists: dict[str, dict] = {}
    rule_rows: list[dict] = []
    roots = {"rules": rules, "plugins": plugins}
    for root, rel, source in RULE_FILES:
        path = roots[root] / rel
        origin = f"falcosecurity/{root}/{rel}"
        for item in yaml.safe_load(path.read_text(encoding="utf-8")) or []:
            if not isinstance(item, dict):
                continue
            if "macro" in item and "condition" in item:
                macros[item["macro"]] = {
                    "name": item["macro"],
                    "condition": " ".join(str(item["condition"]).split()),
                    "source": source,
                    "origin": origin,
                }
            elif "list" in item and "items" in item:
                lists[item["list"]] = {
                    "name": item["list"],
                    "items": [str(i) for i in item.get("items") or []],
                    "origin": origin,
                }
            elif "rule" in item and "condition" in item:
                rule_rows.append(
                    {
                        "name": item["rule"],
                        "condition": str(item["condition"]),
                        "source": item.get("source", source),
                        "origin": origin,
                    }
                )
    return (
        sorted(macros.values(), key=lambda r: r["name"]),
        sorted(lists.values(), key=lambda r: r["name"]),
        rule_rows,
    )


def toml_str(value: str) -> str:
    # JSON string escapes are valid TOML basic-string escapes.
    return json.dumps(value, ensure_ascii=False)


def toml_list(values: list[str]) -> str:
    return "[" + ", ".join(toml_str(v) for v in values) + "]"


def head(sources: dict[str, str]) -> str:
    lines = ["# Generated by scripts/sync_falco_catalog.py. Do not edit."]
    for name, rev in sources.items():
        lines.append(f"# Source: {name}@{rev}")
    return "\n".join(lines) + "\n"


def write_fields(rows: list[dict], header: str) -> str:
    out = [header, "# libsinsp field reference: CC BY 4.0 (falco-website); plugin READMEs: Apache-2.0.\n"]
    for name, plugin, desc in SOURCES:
        out.append(
            f"[[sources]]\nname = {toml_str(name)}\nplugin = {toml_str(plugin)}\n"
            f"description = {toml_str(desc)}\n"
        )
    for row in rows:
        out.append(
            "[[fields]]\n"
            f"name = {toml_str(row['name'])}\n"
            f"type = {toml_str(row['type'])}\n"
            f"kind = {toml_str(row['kind'])}\n"
            f"class = {toml_str(row['class'])}\n"
            f"sources = {toml_list(row['sources'])}\n"
            f"arg = {'true' if row['arg'] else 'false'}\n"
            f"description = {toml_str(row['description'])}\n"
        )
    return "\n".join(out)


def write_defaults(macros: list[dict], lists: list[dict], header: str) -> str:
    out = [header, "# Falco default rules (falcosecurity/rules, falcosecurity/plugins): Apache-2.0.\n"]
    for row in macros:
        out.append(
            "[[macros]]\n"
            f"name = {toml_str(row['name'])}\n"
            f"condition = {toml_str(row['condition'])}\n"
            f"source = {toml_str(row['source'])}\n"
            f"origin = {toml_str(row['origin'])}\n"
        )
    for row in lists:
        out.append(
            "[[lists]]\n"
            f"name = {toml_str(row['name'])}\n"
            f"items = {toml_list(row['items'])}\n"
            f"origin = {toml_str(row['origin'])}\n"
        )
    return "\n".join(out)


def write_events(rows: list[dict], header: str) -> str:
    out = [header, "# Falco supported events (falco-website): CC BY 4.0.\n"]
    for row in rows:
        out.append(f"[[events]]\nname = {toml_str(row['name'])}\nkind = {toml_str(row['kind'])}\n")
    return "\n".join(out)


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def corpus(rule_rows: list[dict]) -> dict[str, str]:
    """`<slug>.falco` and its `.broken.falco` twin for every default rule."""
    files: dict[str, str] = {}
    for row in rule_rows:
        name = slug(row["name"])
        text = row["condition"].rstrip("\n") + "\n"
        files[f"{row['source']}/{name}.falco"] = text
        # One injected fault: an unclosed value list after the first `and`.
        broken = text.replace(" and ", " and proc.name in (oops and ", 1)
        if broken == text:
            broken = "(" + text
        files[f"{row['source']}/{name}.broken.falco"] = broken
    return files


def git_rev(path: Path) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--website", type=Path, required=True)
    parser.add_argument("--plugins", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--corpus", action="store_true", help="also write the external corpus")
    parser.add_argument("--check", action="store_true", help="exit 1 when a file would change")
    args = parser.parse_args()

    header = head(
        {
            "falcosecurity/falco-website": git_rev(args.website),
            "falcosecurity/plugins": git_rev(args.plugins),
            "falcosecurity/rules": git_rev(args.rules),
        }
    )
    field_rows = website_fields(args.website)
    for plugin in PLUGIN_SOURCES:
        field_rows += plugin_fields(args.plugins, plugin)
    field_rows += LEGACY_FIELDS
    macros, lists, rule_rows = defaults(args.rules, args.plugins)
    files = {
        OUT / "fields.toml": write_fields(merge_fields(field_rows), header),
        OUT / "defaults.toml": write_defaults(macros, lists, header),
        OUT / "events.toml": write_events(events(args.website), header),
    }
    if args.corpus:
        for rel, text in corpus(rule_rows).items():
            files[CORPUS / rel] = text

    stale = []
    for path, text in files.items():
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != text:
                stale.append(path)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    for path in stale:
        print(f"stale: {path.relative_to(ROOT)}", file=sys.stderr)
    return 1 if stale else 0


if __name__ == "__main__":
    raise SystemExit(main())
