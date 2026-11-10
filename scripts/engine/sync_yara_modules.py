#!/usr/bin/env python3
"""Generate the YARA module catalogue (catalogs/yara/modules.toml) for #165.

Reads two sources:

- a libyara checkout at the pinned tag (BSD-3-Clause): each module's
  ``begin_declarations`` block in ``libyara/modules/<name>/<name>.c``. Those
  declarations are what libyara 4.5 compiles against, so they decide
  ``libyara = true`` and the libyara argument signatures (``"si"``: a string,
  then an integer);
- YARA-X's module reflection, as JSON from ``scripts/yara-modules`` (a
  separate Cargo project: the ``yara-x`` crate never enters the workspace).
  It decides ``yara_x = true``, and gives the types and documentation.

and writes one row per module member, path first. A member in one engine
only is kept with the other flag false: ``yara_unknown_module_member`` under
libyara, ``yara_x_incompatible`` for what only libyara has.

Usage:
    cargo run --release --manifest-path scripts/yara-modules/Cargo.toml > /tmp/yara-x-modules.json
    python scripts/sync_yara_modules.py --libyara ../yara --yara-x-json /tmp/yara-x-modules.json [--check]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "catalogs" / "yara" / "modules.toml"

LIBYARA_TAG = "v4.5.4"
YARA_X_VERSION = "1.23.0"

# yara-1.0 "Modules": the modules the engine knows.
MODULES = [
    "pe", "elf", "math", "hash", "time", "dotnet", "macho", "magic",
    "cuckoo", "console", "string", "lnk", "dex",
]

# libyara's one-letter types (libyara/include/yara/modules.h).
LIBYARA_TYPES = {"i": "integer", "f": "float", "s": "string", "r": "regexp", "b": "boolean"}

DECL = re.compile(
    r"\b(begin_struct_array|begin_struct_dictionary|begin_struct|"
    r"end_struct_array|end_struct_dictionary|end_struct|"
    r"declare_integer_array|declare_integer_dictionary|declare_integer|"
    r"declare_float_array|declare_float_dictionary|declare_float|"
    r"declare_string_array|declare_string_dictionary|declare_string|"
    r"declare_function)\s*\(([^()]*)\)"
)
ARGS = re.compile(r'"([^"]*)"')


def libyara_members(source: str) -> dict[str, dict]:
    """Every member a module's begin_declarations block declares, by path.

    A path uses `[]` for an array element and `{}` for a dictionary value:
    `sections[].name`, `version_info{}`.
    """
    start = source.index("begin_declarations")
    end = source.index("end_declarations", start)
    body = source[start:end]
    out: dict[str, dict] = {}
    stack: list[str] = []

    def path(name: str) -> str:
        return ".".join(stack + [name]) if stack else name

    for m in DECL.finditer(body):
        macro, raw = m.group(1), m.group(2)
        strings = ARGS.findall(raw)
        if macro.startswith("end_struct"):
            stack.pop()
            continue
        name = strings[0]
        if macro.startswith("begin_struct"):
            kind = {"begin_struct": "struct", "begin_struct_array": "array",
                    "begin_struct_dictionary": "dict"}[macro]
            p = path(name)
            out[p] = {"kind": kind, "element": "struct" if kind != "struct" else None}
            stack.append(name + {"struct": "", "array": "[]", "dict": "{}"}[kind])
            continue
        if macro == "declare_function":
            args, ret = strings[1], strings[2]
            entry = out.setdefault(path(name), {"kind": "function", "overloads": []})
            entry["overloads"].append({"args": args, "ret": LIBYARA_TYPES[ret]})
            continue
        base = macro.removeprefix("declare_")
        scalar, _, shape = base.partition("_")
        if shape == "array":
            out[path(name)] = {"kind": "array", "element": scalar}
        elif shape == "dictionary":
            out[path(name)] = {"kind": "dict", "element": scalar}
        else:
            out[path(name)] = {"kind": scalar}
    return out


def yara_x_type_letter(t) -> str:
    if isinstance(t, str):
        return {"integer": "i", "float": "f", "string": "s", "regexp": "r", "boolean": "b"}[t]
    return "?"


def yara_x_members(fields: list, prefix: str = "", out: dict | None = None) -> dict[str, dict]:
    out = {} if out is None else out
    for f in fields:
        p = f"{prefix}.{f['name']}" if prefix else f["name"]
        t = f["type"]
        doc = f.get("doc")
        if isinstance(t, str):
            out[p] = {"kind": t, "doc": doc}
        elif "struct" in t:
            out[p] = {"kind": "struct", "doc": doc, "enum": f.get("enum", False)}
            yara_x_members(t["struct"], p, out)
        elif "array" in t or "map" in t:
            kind, inner, mark = ("array", t["array"], "[]") if "array" in t else ("dict", t["map"][1], "{}")
            element = inner if isinstance(inner, str) else "struct"
            out[p] = {"kind": kind, "element": element, "doc": doc}
            if isinstance(inner, dict) and "struct" in inner:
                yara_x_members(inner["struct"], p + mark, out)
        elif "function" in t:
            overloads = []
            for sig in t["function"]:
                overloads.append({
                    "args": "".join(yara_x_type_letter(a[1]) for a in sig["args"]),
                    "ret": sig["ret"] if isinstance(sig["ret"], str) else "struct",
                    "doc": sig.get("doc"),
                })
            out[p] = {"kind": "function", "overloads": overloads, "doc": doc}
    return out


def toml_str(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def render(rows: list[dict]) -> str:
    lines = [
        "# Generated by scripts/sync_yara_modules.py; do not edit.",
        f"# libyara {LIBYARA_TAG} module declarations (BSD-3-Clause) and YARA-X",
        f"# {YARA_X_VERSION} module reflection (BSD-3-Clause): see NOTICE in this directory.",
        "# A path uses `[]` for an array element and `{}` for a dictionary value.",
        "",
        "[meta]",
        f"libyara = {toml_str(LIBYARA_TAG)}",
        f"yara_x = {toml_str(YARA_X_VERSION)}",
        "modules = [" + ", ".join(toml_str(m) for m in MODULES) + "]",
        "",
    ]
    for row in rows:
        lines.append("[[member]]")
        for key in ("module", "path", "kind", "element"):
            if row.get(key):
                lines.append(f"{key} = {toml_str(row[key])}")
        lines.append(f"libyara = {'true' if row['libyara'] else 'false'}")
        lines.append(f"yara_x = {'true' if row['yara_x'] else 'false'}")
        if row.get("doc"):
            lines.append(f"doc = {toml_str(row['doc'].strip())}")
        for o in row.get("overloads", []):
            lines.append("[[member.overload]]")
            lines.append(f"args = {toml_str(o['args'])}")
            lines.append(f"ret = {toml_str(o['ret'])}")
            lines.append(f"libyara = {'true' if o['libyara'] else 'false'}")
            lines.append(f"yara_x = {'true' if o['yara_x'] else 'false'}")
            if o.get("doc"):
                lines.append(f"doc = {toml_str(o['doc'].strip())}")
        lines.append("")
    return "\n".join(lines)


def merge(module: str, ly: dict[str, dict], yx: dict[str, dict]) -> list[dict]:
    rows = []
    for path in sorted(set(ly) | set(yx)):
        a, b = ly.get(path), yx.get(path)
        base = a or b
        row = {
            "module": module,
            "path": path,
            "kind": base["kind"],
            "element": base.get("element"),
            "libyara": a is not None,
            "yara_x": b is not None,
            "doc": (b or {}).get("doc"),
        }
        if base["kind"] == "function":
            overloads: dict[str, dict] = {}
            for o in (a or {}).get("overloads", []):
                overloads[o["args"]] = {**o, "libyara": True, "yara_x": False}
            for o in (b or {}).get("overloads", []):
                if o["args"] in overloads:
                    overloads[o["args"]]["yara_x"] = True
                    overloads[o["args"]]["doc"] = o.get("doc")
                else:
                    overloads[o["args"]] = {**o, "libyara": False, "yara_x": True}
            row["overloads"] = sorted(overloads.values(), key=lambda o: o["args"])
        rows.append(row)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--libyara", type=Path, required=True)
    ap.add_argument("--yara-x-json", type=Path, required=True)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    tag = subprocess.run(
        ["git", "-C", str(args.libyara), "describe", "--tags", "--exact-match"],
        capture_output=True, text=True,
    ).stdout.strip()
    if tag != LIBYARA_TAG:
        print(f"libyara checkout is {tag or 'not a tag'}, want {LIBYARA_TAG}", file=sys.stderr)
        return 2
    reflection = json.loads(args.yara_x_json.read_text())
    rows: list[dict] = []
    for module in MODULES:
        src = args.libyara / "libyara" / "modules" / module / f"{module}.c"
        ly = libyara_members(src.read_text()) if src.exists() else {}
        yx = yara_x_members(reflection.get(module, []))
        if not ly and not yx:
            print(f"module {module}: in neither engine", file=sys.stderr)
            return 1
        rows.extend(merge(module, ly, yx))
    text = render(rows)
    if args.check:
        if OUT.read_text() != text:
            print(f"{OUT.relative_to(ROOT)} is stale; rerun without --check", file=sys.stderr)
            return 1
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(ROOT)}: {len(rows)} members")
    return 0


if __name__ == "__main__":
    sys.exit(main())
