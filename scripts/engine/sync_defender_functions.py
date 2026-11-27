#!/usr/bin/env python3
"""Generate the Defender dialect's KQL functions (data/catalogs/kql/defender/functions.toml).

Advanced hunting has functions of its own that Kusto's reference does not list: `FileProfile`,
`DeviceFromIP` and `SeenBy` (each `invoke`d on the rows before it) and `AssignedIPAddresses`
(a tabular source). Microsoft documents each on its own Learn page (ADR 0015, section 5.1). This
script reads those pages and writes one row per function in ADR 0013's form:

- ``name``, ``signature`` (the page's Syntax block, verbatim), ``docs`` (the page's first
  sentence about the function), ``citation`` (the page), ``kind = "tabular"``;
- ``profile = "defender"``: the dialect the function exists in. Under the Sentinel dialect the
  engine reports a call to one as ``kql_function_unavailable``;
- ``[[functions.parameters]]``: each argument the page lists, with its text and whether the
  page says what happens when it is left out (``required = false``).

The pages' source repository is not public, so the script reads the published pages: from
learn.microsoft.com by default, or from ``--pages DIR`` holding each page saved as
``<slug>.html`` (``advanced-hunting-fileprofile-function.html``). A page whose structure the
script does not recognise fails the run, naming the page, rather than writing a partial row.

Usage:
    python scripts/engine/sync_defender_functions.py [--pages DIR] [--check]
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "data" / "catalogs" / "kql" / "defender" / "functions.toml"
LEARN = "https://learn.microsoft.com/defender-xdr"

# The functions, in the order the catalog lists them, by their page's slug.
FUNCTIONS = (
    ("FileProfile", "advanced-hunting-fileprofile-function"),
    ("DeviceFromIP", "advanced-hunting-devicefromip-function"),
    ("SeenBy", "advanced-hunting-seenby-function"),
    ("AssignedIPAddresses", "advanced-hunting-assignedipaddresses-function"),
)

# What an argument's text says when the argument may be left out.
OPTIONAL = re.compile(r"if (?:unspecified|not specified)|\boptional\b", re.IGNORECASE)


@dataclass(frozen=True)
class Parameter:
    name: str
    docs: str
    required: bool


@dataclass(frozen=True)
class Function:
    name: str
    signature: str
    docs: str
    citation: str
    parameters: tuple[Parameter, ...]


class PageError(ValueError):
    """A page the script does not recognise."""


def text_of(fragment: str) -> str:
    """The text of an HTML fragment: tags dropped, entities decoded, blanks collapsed."""
    text = re.sub(r"<[^>]+>", "", fragment)
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def first_sentence(text: str) -> str:
    match = re.match(r".+?[.!?](?=\s|$)", text)
    return match.group(0) if match else text


def article(page: str, slug: str) -> str:
    """The article's body: from the first paragraph after the outline to the examples."""
    start = page.find('id="ms--in-this-article"')
    if start < 0:
        raise PageError(f"{slug}: no article outline")
    end = page.find('<h2 id="related', start)
    return page[start : end if end > 0 else len(page)]


def parse(name: str, slug: str, page: str) -> Function:
    body = article(page, slug)
    syntax = body.find('<h2 id="syntax"')
    if syntax < 0:
        raise PageError(f"{slug}: no Syntax section")
    intro = [text_of(p) for p in re.findall(r"<p>(.*?)</p>", body[:syntax], re.DOTALL)]
    about = next((p for p in intro if f"{name}()" in p), None)
    if about is None:
        raise PageError(f"{slug}: no paragraph about {name}()")
    block = re.search(r"<pre><code[^>]*>(.*?)</code></pre>", body[syntax:], re.DOTALL)
    if block is None:
        raise PageError(f"{slug}: no Syntax block")
    signature = text_of(block.group(1))
    if name not in signature or "(" not in signature:
        raise PageError(f"{slug}: the Syntax block {signature!r} does not call {name}")
    # The arguments: the first list after the Syntax block (under an Arguments heading, or
    # directly), before the next heading.
    after = body[syntax + block.end() :]
    heading = re.match(r'\s*<h2 id="(?:arguments|parameters)"[^>]*>.*?</h2>', after, re.DOTALL)
    if heading:
        after = after[heading.end() :]
    stop = re.search(r"<h[23] ", after)
    section = after[: stop.start() if stop else len(after)]
    items = re.search(r"<ul>(.*?)</ul>", section, re.DOTALL)
    parameters: list[Parameter] = []
    for item in re.findall(r"<li>(.*?)</li>", items.group(1) if items else "", re.DOTALL):
        label = re.search(r"<strong>(.*?)</strong>", item, re.DOTALL)
        if label is None:
            raise PageError(f"{slug}: an argument without a name: {text_of(item)!r}")
        argument = text_of(label.group(1))
        docs = text_of(item[label.end() :]).lstrip("—-: ").strip()
        if text_of(item[: label.start()]):
            # "where **x** is the device ID of interest"
            docs = text_of(item)
        parameters.append(Parameter(argument, docs, not OPTIONAL.search(docs)))
    if not parameters and "()" not in signature:
        raise PageError(f"{slug}: the Syntax block takes arguments the page does not list")
    return Function(
        name=name,
        signature=signature,
        docs=first_sentence(about),
        citation=f"{LEARN}/{slug}",
        parameters=tuple(parameters),
    )


def fetch(slug: str, pages: Path | None) -> str:
    if pages is not None:
        return (pages / f"{slug}.html").read_text(encoding="utf-8")
    url = f"https://learn.microsoft.com/en-us/defender-xdr/{slug}"
    request = urllib.request.Request(url, headers={"User-Agent": "opentide-catalog-sync"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def render(functions: list[Function]) -> str:
    lines = [
        "# Microsoft Defender advanced hunting functions, the Defender dialect's own (ADR 0015).",
        "# Generated by scripts/engine/sync_defender_functions.py from each function's Learn page;",
        "# do not edit by hand. Signatures are the pages' Syntax blocks, verbatim.",
    ]
    for function in functions:
        lines += [
            "",
            "[[functions]]",
            f"name = {toml_string(function.name)}",
            f"signature = {toml_string(function.signature)}",
            f"docs = {toml_string(function.docs)}",
            f"citation = {toml_string(function.citation)}",
            'kind = "tabular"',
            'profile = "defender"',
        ]
        for parameter in function.parameters:
            lines += [
                "",
                "[[functions.parameters]]",
                f"name = {toml_string(parameter.name)}",
                f"docs = {toml_string(parameter.docs)}",
                f"required = {'true' if parameter.required else 'false'}",
            ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pages", type=Path, help="read <slug>.html from this directory")
    parser.add_argument("--check", action="store_true", help="fail if the output would change")
    args = parser.parse_args()
    try:
        functions = [parse(name, slug, fetch(slug, args.pages)) for name, slug in FUNCTIONS]
    except PageError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    text = render(functions)
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print(f"{OUT.relative_to(ROOT)} is out of date: run the script", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(functions)} functions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
