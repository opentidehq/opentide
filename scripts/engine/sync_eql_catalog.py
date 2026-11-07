#!/usr/bin/env python3
"""Generate catalogs/eql/*.toml from an Elasticsearch checkout.

Reads the EQL function and pipe references
(docs/reference/query-languages/eql/eql-function-ref.md, eql-pipe-ref.md)
and writes one row per function and pipe: the syntax line, each parameter
with its required flag and types, the return types, whether the docs show a
case-insensitive `name~(` form, the argument counts Elasticsearch's function
registry enforces, and the elastic.co anchor.

Facts only. Elastic's prose is not copied (the docs are AGPL/SSPL/ELv2); the
function, parameter, and pipe summaries below are this catalog's own words.

Usage:
    python scripts/sync_eql_catalog.py --elasticsearch ../elasticsearch
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

DOCS = Path("docs/reference/query-languages/eql")
SITE = "https://www.elastic.co/docs/reference/query-languages/eql"

SUMMARIES = {
    "add": "Sum of two numbers. Same as `+`.",
    "between": "The substring between `left` and `right`; shortest match unless `greedy` is true.",
    "cidrMatch": "True when an IP address falls in any of the given CIDR blocks.",
    "concat": "Joins the string form of its arguments; null if any argument is null.",
    "divide": "Quotient of two numbers. Same as `/`; integer division truncates.",
    "endsWith": "True when the source string ends with the substring.",
    "indexOf": "Zero-based position of the substring at or after `start_pos`; null when absent.",
    "length": "Number of characters in a string.",
    "modulo": "Remainder of a division. Same as `%`.",
    "multiply": "Product of two numbers. Same as `*`.",
    "number": "Parses a string as a number, in an optional base.",
    "startsWith": "True when the source string starts with the substring.",
    "string": "The string form of a value.",
    "stringContains": "True when the source string contains the substring.",
    "substring": "Characters from `start_pos` up to `end_pos`; negative offsets count from the end.",
    "subtract": "Difference of two numbers. Same as binary `-`.",
}

# One line per parameter, keyed by (function, parameter) as the docs name
# them. Our own wording, like SUMMARIES.
PARAM_SUMMARIES = {
    ("add", "addend"): "A number; `add` takes exactly two.",
    ("between", "source"): "Text to search in.",
    ("between", "left"): "Marker that precedes the wanted text; it is not part of the result.",
    ("between", "right"): "Marker that follows the wanted text; it is not part of the result.",
    ("between", "greedy_matching"): "`true` extends the match to the last `right`; `false` (the default) stops at the first.",
    ("cidrMatch", "ip_address"): "An `ip`-typed field; a string literal is rejected.",
    ("cidrMatch", "cidr_block"): "A CIDR range written as a string constant, for example `\"10.0.0.0/8\"`; list as many as needed.",
    ("concat", "value"): "Any value, converted to text; list as many as needed.",
    ("divide", "dividend"): "The number being divided.",
    ("divide", "divisor"): "The number to divide by; must not be zero.",
    ("endsWith", "source"): "Text to test.",
    ("endsWith", "substring"): "Suffix to look for at the end of `source`.",
    ("indexOf", "source"): "Text to search in.",
    ("indexOf", "substring"): "Text to find.",
    ("indexOf", "start_pos"): "Integer offset (from 0) where the search begins; 0 when omitted.",
    ("length", "string"): "Text whose characters are counted.",
    ("modulo", "dividend"): "The number being divided.",
    ("modulo", "divisor"): "The number to divide by; the remainder is returned.",
    ("multiply", "factor"): "A number; `multiply` takes exactly two.",
    ("number", "string"): "Text that holds an integer or decimal number.",
    ("number", "base_num"): "Integer radix to read the text in; 16 for a `0x` prefix, otherwise 10.",
    ("startsWith", "source"): "Text to test.",
    ("startsWith", "substring"): "Prefix to look for at the start of `source`.",
    ("string", "value"): "Any value to turn into text.",
    ("stringContains", "source"): "Text to search in.",
    ("stringContains", "substring"): "Text to look for anywhere in `source`.",
    ("substring", "source"): "Text to take a slice of.",
    ("substring", "start_pos"): "Integer offset (from 0) of the first character kept; negative counts back from the end.",
    ("substring", "end_pos"): "Integer offset where the slice stops, exclusive; the rest of the text when omitted.",
    ("subtract", "minuend"): "The number to subtract from.",
    ("subtract", "subtrahend"): "The number taken away; required, despite the docs.",
}

PIPE_SUMMARIES = {
    "head": "Keeps the first N events or sequences, earliest first.",
    "tail": "Keeps the last N events or sequences, most recent first.",
}

# (min, max) argument counts from EqlFunctionRegistry; None is unbounded.
ARITY = {
    "add": (2, 2), "between": (3, 4), "cidrMatch": (2, None), "concat": (0, None),
    "divide": (2, 2), "endsWith": (2, 2), "indexOf": (2, 3), "length": (1, 1),
    "modulo": (2, 2), "multiply": (2, 2), "number": (1, 2), "startsWith": (2, 2),
    "string": (1, 1), "stringContains": (2, 2), "substring": (2, 3), "subtract": (2, 2),
}

# Parameters the docs mark wrongly; the registry is the authority.
REQUIRED_OVERRIDES = {("subtract", "subtrahend"): True}

SECTION = re.compile(r"^## `([^`]+)` \[([^\]]+)\]\s*$", re.M)
PARAM = re.compile(
    r"^[ \t]*`<([^>]+)>`\s*\n[ \t]*:\s+\((Required|Optional)(?:,\s*([^)]*))?\)\s*(.*)$", re.M
)


def toml_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def sections(text: str) -> list[tuple[str, str, str]]:
    found = list(SECTION.finditer(text))
    out = []
    for i, match in enumerate(found):
        end = found[i + 1].start() if i + 1 < len(found) else len(text)
        out.append((match.group(1), match.group(2), text[match.end() : end]))
    return out


def syntax_line(body: str) -> str:
    match = re.search(r"\*\*Syntax\*\*\s*```txt\n(.*?)```", body, re.S)
    return match.group(1).strip().strip("`") if match else ""


def returns(body: str) -> list[str]:
    match = re.search(r"\*\*Returns:\*\*\s*(.*)", body)
    if not match:
        return []
    parts = re.split(r",\s*(?:or\s+)?|\s+or\s+", match.group(1).replace("`", ""))
    return [p.strip() for p in parts if p.strip()]


def write_functions(es: Path, out: Path, commit: str) -> int:
    text = (es / DOCS / "eql-function-ref.md").read_text()
    lines = [
        "# EQL functions, generated by scripts/sync_eql_catalog.py. Do not edit.",
        f"# Source: elastic/elasticsearch@{commit} {DOCS}/eql-function-ref.md",
        "",
    ]
    count = 0
    for name, anchor, body in sections(text):
        case_insensitive = f"{name}~(" in body
        low, high = ARITY[name]
        lines += [
            "[[functions]]",
            f"name = {toml_str(name)}",
            f"signature = {toml_str(syntax_line(body).replace('<factor, <factor>', '<factor>, <factor>'))}",
            f"docs = {toml_str(SUMMARIES[name])}",
            f"returns = {json.dumps(returns(body))}",
            f"case_insensitive = {str(case_insensitive).lower()}",
            f"min_args = {low}",
        ]
        if high is not None:
            lines.append(f"max_args = {high}")
        lines += [
            f"citation = {toml_str(f'{SITE}/eql-function-ref#{anchor}')}",
            "",
        ]
        for param in PARAM.finditer(body):
            types = [t.strip() for t in re.split(r",|\bor\b", (param.group(3) or "").replace("`", "")) if t.strip()]
            required = REQUIRED_OVERRIDES.get((name, param.group(1)), param.group(2) == "Required")
            lines += [
                "[[functions.parameters]]",
                f"name = {toml_str(param.group(1))}",
                f"docs = {toml_str(PARAM_SUMMARIES[(name, param.group(1))])}",
                f"types = {json.dumps(types)}",
                f"required = {str(required).lower()}",
                "",
            ]
        count += 1
    out.write_text("\n".join(lines).rstrip() + "\n")
    return count


def write_pipes(es: Path, out: Path, commit: str) -> int:
    text = (es / DOCS / "eql-pipe-ref.md").read_text()
    lines = [
        "# EQL pipes, generated by scripts/sync_eql_catalog.py. Do not edit.",
        f"# Source: elastic/elasticsearch@{commit} {DOCS}/eql-pipe-ref.md",
        "# Elasticsearch supports only these pipes; Endgame pipes such as unique or count are rejected.",
        "",
    ]
    count = 0
    for name, anchor, body in sections(text):
        lines += [
            "[[pipes]]",
            f"name = {toml_str(name)}",
            f"signature = {toml_str(syntax_line(body))}",
            f"docs = {toml_str(PIPE_SUMMARIES[name])}",
            f"citation = {toml_str(f'{SITE}/eql-pipe-ref#{anchor}')}",
            "",
        ]
        count += 1
    out.write_text("\n".join(lines).rstrip() + "\n")
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elasticsearch", type=Path, required=True)
    parser.add_argument(
        "--out", type=Path, default=Path(__file__).resolve().parent.parent / "catalogs/eql"
    )
    args = parser.parse_args()
    es = args.elasticsearch.resolve()
    commit = subprocess.run(
        ["git", "-C", str(es), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    args.out.mkdir(parents=True, exist_ok=True)
    functions = write_functions(es, args.out / "functions.toml", commit)
    pipes = write_pipes(es, args.out / "pipes.toml", commit)
    print(f"elastic/elasticsearch@{commit}: {functions} functions, {pipes} pipes")


if __name__ == "__main__":
    main()
