#!/usr/bin/env python3
"""Generate the Falco catalogs (catalogs/falco/) from public Falco sources.

Reads three checkouts:

- falcosecurity/libs (Apache-2.0): the libsinsp field tables
  (``userspace/libsinsp/sinsp_filtercheck_*.cpp``), each field with its type
  and flags (argument required or allowed, index or key, list, no
  transformer, no right-hand side field, filter or print only), in the order
  libsinsp's filter check list tries the classes; the event table
  (``driver/event_table.c``) for event names and argument names, and the
  syscall codes (``driver/ppm_events_public.h``) that ``evt.type`` also
  accepts;
- falcosecurity/plugins (Apache-2.0): each plugin README's field table
  (``k8saudit``, ``k8saudit-eks``, ``cloudtrail``, ``okta``, ``github``,
  ``gcpaudit``, ``json``, ``k8smeta``, ``container``), with its argument
  column, and the plugins' default rules files;
- falcosecurity/rules (Apache-2.0): ``rules/*.yaml``.

and writes:

- ``catalogs/falco/fields.toml``: event sources, then one row per field;
- ``catalogs/falco/defaults.toml``: the macros and lists of the Falco default
  rules, with the condition or items and the file that defines them (a later
  file overrides an earlier one, as Falco loads them);
- ``catalogs/falco/events.toml``: event names, event argument names with
  their types (``evt.arg.<name>``, ``evt.rawarg.<name>``), and syscall names.

With ``--corpus``, it also writes ``testdata/conformance/external/falco/``:
each default rule's condition, unmodified, as ``<slug>.falco``, plus a
``.broken.falco`` twin with one injected fault.

Usage:
    python scripts/sync_falco_catalog.py --libs ../libs --falco ../falco \
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

# libsinsp's filter check classes, in the order `sinsp_filter_check_list`
# tries them (`filter_check_list.cpp`): a name is resolved by the first class
# that knows a prefix of it. `gen_event` is the one generic class: its fields
# apply to every event source.
LIBS_CLASSES: list[tuple[str, str]] = [
    ("gen_event", "sinsp_filtercheck_gen_event.cpp"),
    ("event", "sinsp_filtercheck_event.cpp"),
    ("thread", "sinsp_filtercheck_thread.cpp"),
    ("user", "sinsp_filtercheck_user.cpp"),
    ("group", "sinsp_filtercheck_group.cpp"),
    ("fd", "sinsp_filtercheck_fd.cpp"),
    ("fspath", "sinsp_filtercheck_fspath.cpp"),
    ("utils", "sinsp_filtercheck_utils.cpp"),
    ("fdlist", "sinsp_filtercheck_fdlist.cpp"),
]
LIBSINSP = "userspace/libsinsp"
EVENT_TABLE = "driver/event_table.c"
PPM_EVENTS = "driver/ppm_events_public.h"
FALCO_LOAD_RESULT = "userspace/engine/falco_load_result.cpp"

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


FLAG_NAMES = {
    "EPF_ARG_REQUIRED", "EPF_ARG_ALLOWED", "EPF_ARG_INDEX", "EPF_ARG_KEY", "EPF_IS_LIST",
    "EPF_NO_TRANSFORMER", "EPF_NO_RHS", "EPF_FILTER_ONLY", "EPF_PRINT_ONLY", "EPF_DEPRECATED",
    "EPF_TABLE_ONLY", "EPF_INFO", "EPF_CONVERSATION", "EPF_NO_PTR_STABILITY",
    "EPF_FORMAT_SUGGESTED", "EPF_NONE",
}


def c_strings(text: str) -> str:
    """Adjacent C string literals in *text*, concatenated and unescaped."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', text)
    return "".join(json.loads(f'"{p}"') for p in parts)


def split_top(text: str, sep: str = ",") -> list[str]:
    """Split *text* at *sep* outside braces, parentheses and string literals."""
    out, depth, cur, i = [], 0, [], 0
    while i < len(text):
        c = text[i]
        if c == '"':
            j = i + 1
            while text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            cur.append(text[i : j + 1])
            i = j + 1
            continue
        if c in "{(":
            depth += 1
        elif c in "})":
            depth -= 1
        if c == sep and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    if "".join(cur).strip():
        out.append("".join(cur))
    return out


def field_entries(source: str) -> list[list[str]]:
    """The `{type, flags, format, name, display, description}` entries of the
    first `filtercheck_field_info ...[] = {...}` array in *source*."""
    m = re.search(r"filtercheck_field_info\s+\w+\[\]\s*=\s*\{", source)
    if not m:
        return []
    depth, i = 1, m.end()
    start = i
    while depth:
        c = source[i]
        if c == '"':
            i += 1
            while source[i] != '"':
                i += 2 if source[i] == "\\" else 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        i += 1
    body = source[start : i - 1]
    entries = []
    for entry in split_top(body):
        entry = entry.strip()
        if not entry.startswith("{"):
            continue
        entries.append([e.strip() for e in split_top(entry.strip()[1:-1])])
    return entries


def libs_fields(libs: Path, deprecated: set[str]) -> list[dict]:
    rows: list[dict] = []
    for cls, filename in LIBS_CLASSES:
        source = (libs / LIBSINSP / filename).read_text(encoding="utf-8")
        for order, entry in enumerate(field_entries(source)):
            ptype = entry[0].removeprefix("PT_")
            flags = set(re.findall(r"EPF_[A-Z_]+", entry[1])) & FLAG_NAMES
            name = c_strings(entry[3])
            arg = (
                "required" if "EPF_ARG_REQUIRED" in flags
                else "allowed" if "EPF_ARG_ALLOWED" in flags
                else "none"
            )
            rows.append(
                {
                    "name": name,
                    "type": ptype,
                    "list": "EPF_IS_LIST" in flags,
                    "kind": kind(ptype),
                    "class": cls,
                    "order": order,
                    "origin": "libsinsp",
                    "sources": ["*"] if cls == "gen_event" else ["syscall"],
                    "arg": arg,
                    "arg_index": "EPF_ARG_INDEX" in flags,
                    "arg_key": "EPF_ARG_KEY" in flags,
                    "no_rhs": "EPF_NO_RHS" in flags,
                    "no_transformer": "EPF_NO_TRANSFORMER" in flags,
                    "filter_only": "EPF_FILTER_ONLY" in flags,
                    "print_only": "EPF_PRINT_ONLY" in flags,
                    "deprecated": "EPF_DEPRECATED" in flags or name in deprecated,
                    "description": clean(c_strings(entry[5]) if len(entry) > 5 else ""),
                }
            )
    return rows


def falco_deprecated(falco: Path) -> set[str]:
    """`deprecated_fields[]` of Falco's rule loader (`falco_load_result.cpp`)."""
    text = (falco / FALCO_LOAD_RESULT).read_text(encoding="utf-8")
    m = re.search(r"deprecated_fields\[\]\s*=\s*\{(.*?)\};", text, re.S)
    return set(re.findall(r'"([^"]+)"', m.group(1))) if m else set()


PLUGIN_TYPES = {
    "string": "CHARBUF", "uint64": "UINT64", "bool": "BOOL", "reltime": "RELTIME",
    "abstime": "ABSTIME", "ipaddr": "IPADDR", "ipnet": "IPNET",
}


def plugin_fields(plugins: Path, plugin: str) -> list[dict]:
    readme = plugins / "plugins" / plugin / "README.md"
    rows = []
    for order, line in enumerate(readme.read_text(encoding="utf-8").splitlines()):
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))]
        if len(cells) < 4 or not re.fullmatch(r"`[A-Za-z0-9_.]+`", cells[0]):
            continue
        name = cells[0].strip("`")
        raw_type = cells[1].strip("`")
        is_list = raw_type.endswith("(list)")
        ptype = PLUGIN_TYPES[raw_type.removesuffix("(list)").strip()]
        arg_cell = {a.strip() for a in cells[2].split(",")} - {"None", ""}
        rows.append(
            {
                "name": name,
                "type": ptype,
                "list": is_list,
                "kind": kind(ptype),
                "class": plugin,
                "order": order,
                "origin": "plugin",
                "sources": PLUGIN_SOURCES[plugin],
                "arg": "required" if "Required" in arg_cell else "allowed" if arg_cell else "none",
                "arg_index": "Index" in arg_cell,
                "arg_key": "Key" in arg_cell,
                "no_rhs": False,
                "no_transformer": False,
                "filter_only": False,
                "print_only": False,
                "deprecated": False,
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
    return sorted(merged.values(), key=lambda r: r["name"])


def events(libs: Path) -> tuple[list[dict], list[dict], list[str]]:
    """Event names (and category), event arguments (name, type: first seen,
    as `find_longest_matching_evt_param` walks the table), syscall names."""
    table = (libs / EVENT_TABLE).read_text(encoding="utf-8")
    names: dict[str, str] = {}
    codes: dict[str, list[str]] = {}
    params: dict[str, str] = {}
    for m in re.finditer(r"\[(PPME_\w+)\]\s*=\s*\{\s*\"([^\"]*)\",\s*([^,]+),", table):
        code, name, cats = m.group(1), m.group(2), m.group(3)
        category = (re.findall(r"EC_([A-Z_]+)", cats) or ["OTHER"])[0].lower()
        if name:
            names.setdefault(name, category)
            codes.setdefault(name, []).append(code)
        end = table.find("\n        [PPME_", m.end())
        body = table[m.end() : end if end != -1 else len(table)]
        for pm in re.finditer(r"\{\s*\"([A-Za-z0-9_]+)\",\s*PT_([A-Z0-9_]+)", body):
            params.setdefault(pm.group(1), pm.group(2))
    header = (libs / PPM_EVENTS).read_text(encoding="utf-8")
    block = header[header.index("#define PPM_SC_FIELDS") :]
    block = block[: block.index("\n\n")]
    syscalls = sorted({n.lower() for n in re.findall(r"PPM_SC_X\((\w+),", block)})
    return (
        [{"name": n, "kind": k, "codes": codes[n]} for n, k in sorted(names.items())],
        [{"name": n, "type": tp} for n, tp in params.items()],
        syscalls,
    )


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
    out = [header, "# libsinsp field tables and plugin READMEs: Apache-2.0.\n"]
    out.append("# libsinsp's filter check classes, in the order it tries them.")
    out.append(f"classes = {toml_list([c for c, _ in LIBS_CLASSES])}\n")
    for name, plugin, desc in SOURCES:
        out.append(
            f"[[sources]]\nname = {toml_str(name)}\nplugin = {toml_str(plugin)}\n"
            f"description = {toml_str(desc)}\n"
        )
    for row in rows:
        b = lambda k: "true" if row[k] else "false"  # noqa: E731
        out.append(
            "[[fields]]\n"
            f"name = {toml_str(row['name'])}\n"
            f"type = {toml_str(row['type'])}\n"
            f"list = {b('list')}\n"
            f"kind = {toml_str(row['kind'])}\n"
            f"class = {toml_str(row['class'])}\n"
            f"origin = {toml_str(row['origin'])}\n"
            f"sources = {toml_list(row['sources'])}\n"
            f"arg = {toml_str(row['arg'])}\n"
            f"arg_index = {b('arg_index')}\n"
            f"arg_key = {b('arg_key')}\n"
            f"no_rhs = {b('no_rhs')}\n"
            f"no_transformer = {b('no_transformer')}\n"
            f"filter_only = {b('filter_only')}\n"
            f"print_only = {b('print_only')}\n"
            f"deprecated = {b('deprecated')}\n"
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


def write_events(events_: list[dict], params: list[dict], syscalls: list[str], header: str) -> str:
    out = [header, "# libs driver event table and syscall codes: Apache-2.0 / GPL-2.0 / MIT.\n"]
    out.append(f"syscalls = {toml_list(syscalls)}\n")
    for row in events_:
        out.append(
            f"[[events]]\nname = {toml_str(row['name'])}\nkind = {toml_str(row['kind'])}\n"
            f"codes = {toml_list(row['codes'])}\n"
        )
    for row in params:
        out.append(f"[[params]]\nname = {toml_str(row['name'])}\ntype = {toml_str(row['type'])}\n")
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
    parser.add_argument("--libs", type=Path, required=True)
    parser.add_argument("--falco", type=Path, required=True)
    parser.add_argument("--plugins", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--corpus", action="store_true", help="also write the external corpus")
    parser.add_argument("--check", action="store_true", help="exit 1 when a file would change")
    args = parser.parse_args()

    header = head(
        {
            "falcosecurity/libs": git_rev(args.libs),
            "falcosecurity/falco": git_rev(args.falco),
            "falcosecurity/plugins": git_rev(args.plugins),
            "falcosecurity/rules": git_rev(args.rules),
        }
    )
    field_rows = libs_fields(args.libs, falco_deprecated(args.falco))
    for plugin in PLUGIN_SOURCES:
        field_rows += plugin_fields(args.plugins, plugin)
    macros, lists, rule_rows = defaults(args.rules, args.plugins)
    files = {
        OUT / "fields.toml": write_fields(merge_fields(field_rows), header),
        OUT / "defaults.toml": write_defaults(macros, lists, header),
        OUT / "events.toml": write_events(*events(args.libs), header),
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
