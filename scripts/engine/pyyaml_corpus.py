"""Write the PyYAML differential corpus of ``crates/opentide-cli/src/pyyaml.rs`` (#834).

The Rust CLI writes YAML byte for byte as PyYAML 6 does (``generate extract
elastic``'s ``IndentedYamlDumper``, ``generate extract sentinel``'s scalars).
This script draws documents and scalars from a fixed seed and records what
PyYAML writes for each; the Rust test ``the_corpus_is_written_as_pyyaml_wrote_it``
checks every one.

Usage: ``uv run python scripts/engine/pyyaml_corpus.py
crates/opentide-cli/tests/fixtures/pyyaml/corpus.json``
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path
from typing import Any

import yaml


class _IndentedDumper(yaml.SafeDumper):
    """``elastic_importer.IndentedYamlDumper``: sequences indented under their key."""

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        return super().increase_indent(flow, False)


def _represent_str(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_IndentedDumper.add_representer(str, _represent_str)

#: Texts that exercise the emitter's analysis, quoting, folding and escapes.
ATOMS = [
    "",
    " ",
    "a",
    "yes",
    "No",
    "null",
    "~",
    "12",
    "0x1F",
    "1.5",
    ".inf",
    "2026-01-01",
    "2026-1-2 3:04:05",
    "<<",
    "=",
    "!",
    "&a",
    "*b",
    "- x",
    "-x",
    "? x",
    "?x",
    ": x",
    "a: b",
    "a:b",
    "a #b",
    "a#b",
    "#x",
    "[x]",
    "{x}",
    "x, y",
    "'q'",
    '"d"',
    "it's",
    "@at",
    "`tick`",
    "%p",
    "|p",
    ">p",
    "---",
    "...",
    "a\tb",
    "é",
    "日本",
    "\U0001f600",
    "\x07",
    "\u00a0",
    "\u2028",
    "trailing ",
    " leading",
    "a\nb",
    "a\n",
    "\na",
    "a\n\n",
    "a \nb",
    "a\n b",
    "line\r\nwin",
    "\\back",
    "x" * 90,
    "word " * 25,
    "a" * 40 + " " + "b" * 50,
    'process.name : "cmd.exe" and user.name : x',
    "https://example.org/a?b=c#d",
]


def _text(rng: random.Random) -> str:
    return "".join(rng.choice(ATOMS) for _ in range(rng.choice([1, 1, 1, 2, 3])))


def _value(rng: random.Random, depth: int) -> Any:
    draw = rng.random()
    if depth > 3 or draw < 0.55:
        kind = rng.random()
        if kind < 0.75:
            return _text(rng)
        if kind < 0.85:
            return rng.choice([0, 1, -5, 100, 2**40])
        if kind < 0.92:
            return rng.choice([True, False])
        if kind < 0.96:
            return None
        return rng.choice([0.5, 1.0, -2.25])
    if draw < 0.78:
        return {_text(rng) or "k": _value(rng, depth + 1) for _ in range(rng.randint(0, 4))}
    return [_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]


def corpus() -> list[dict[str, Any]]:
    """The documents and scalars, each with what PyYAML writes for it."""
    rng = random.Random(7)
    cases: list[dict[str, Any]] = []
    for _ in range(400):
        doc = {_text(rng) or "k": _value(rng, 1) for _ in range(rng.randint(1, 5))}
        cases.append(
            {"input": doc, "indented": yaml.dump(doc, Dumper=_IndentedDumper, sort_keys=False)}
        )
    for atom in ATOMS:
        out = yaml.safe_dump(atom, allow_unicode=True, width=sys.maxsize)
        cases.append({"scalar": atom, "out": out.removesuffix("\n...\n").removesuffix("\n")})
    return cases


def main() -> None:
    """Write the corpus to the path the command line names."""
    Path(sys.argv[1]).write_text(
        json.dumps(corpus(), ensure_ascii=True, indent=0), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
