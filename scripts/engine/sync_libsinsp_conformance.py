#!/usr/bin/env python3
"""Port falcosecurity/libs' filter parser and compiler unit tests to fixtures.

Reads a falcosecurity/libs checkout (Apache-2.0) and writes, under
``crates/testdata/conformance/libsinsp/``:

- ``parser.json``: every expression ``userspace/libsinsp/test/filter_parser.ut.cpp``
  hands to the parser, with libs' verdict: ``accept`` (``test_accept``,
  ``test_equal_ast``, a ``parser p(...)`` whose ``parse()`` must succeed),
  ``reject`` (``test_reject``, ``EXPECT_THROW``/``ANY_THROW`` on ``parse()``),
  or ``reject`` with the exact ``message`` (``test_reject_msg``). Where the test
  compares ``as_string()`` of the parsed AST, ``ast`` holds the expected string.
  ``variants`` is true for ``test_accept`` with one argument: libs also parses
  the input padded with spaces, with every space a line break, and with every
  line break a tab.
- ``compiler.json``: every ``test_filter_compile`` and ``test_filter_compile_msg``
  call of ``filter_compiler.ut.cpp``: the filter, whether compilation must
  fail, the expected warning count, and the message when one is given. Fields
  the test factory mocks (``c.true``, ``c.buffer``, ...) are flagged ``mock``.

Usage:
    python scripts/engine/sync_libsinsp_conformance.py --libs ../libs [--check]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "crates" / "testdata" / "conformance" / "libsinsp"
PARSER_TESTS = "userspace/libsinsp/test/filter_parser.ut.cpp"
COMPILER_TESTS = "userspace/libsinsp/test/filter_compiler.ut.cpp"

SIMPLE_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "b": "\b",
    "f": "\f",
    "v": "\v",
    "a": "\a",
    "\\": "\\",
    '"': '"',
    "'": "'",
    "?": "?",
    "0": "\0",
}


class Lit:
    """A C++ expression made only of string literals, or ``None``."""


def read_literal(src: str, i: int) -> tuple[str, int] | None:
    """One C++ string literal at *i* (after whitespace), or None."""
    j = skip_ws(src, i)
    if src.startswith('R"', j):
        k = src.index("(", j)
        delim = src[j + 2 : k]
        end = src.index(")" + delim + '"', k)
        return src[k + 1 : end], end + len(delim) + 2
    if j < len(src) and src[j] == '"':
        out = []
        k = j + 1
        while src[k] != '"':
            c = src[k]
            if c == "\\":
                n = src[k + 1]
                if n == "x":
                    m = re.match(r"[0-9a-fA-F]+", src[k + 2 :])
                    out.append(chr(int(m.group(0), 16)))
                    k += 2 + len(m.group(0))
                    continue
                if (n in "01234567" and n != "0") or (n == "0" and src[k + 2] in "01234567"):
                    m = re.match(r"[0-7]{1,3}", src[k + 1 :])
                    out.append(chr(int(m.group(0), 8)))
                    k += 1 + len(m.group(0))
                    continue
                out.append(SIMPLE_ESCAPES[n])
                k += 2
                continue
            out.append(c)
            k += 1
        return "".join(out), k + 1
    return None


def skip_ws(src: str, i: int) -> int:
    while True:
        while i < len(src) and src[i] in " \t\r\n":
            i += 1
        if src.startswith("//", i):
            i = src.index("\n", i)
            continue
        if src.startswith("/*", i):
            i = src.index("*/", i) + 2
            continue
        return i


def read_string_expr(src: str, i: int) -> tuple[str | None, int]:
    """Adjacent literals concatenated, ending at ``,`` or ``)``; None if not literal."""
    parts = []
    while (lit := read_literal(src, i)) is not None:
        parts.append(lit[0])
        i = lit[1]
    j = skip_ws(src, i)
    if parts and j < len(src) and src[j] in ",)":
        return "".join(parts), j
    return None, i


def matching_paren(src: str, i: int) -> int:
    """Index of the ``)`` closing the ``(`` at *i*, skipping literals."""
    depth = 0
    k = i
    while k < len(src):
        c = src[k]
        if c == '"' or src.startswith('R"', k):
            lit = read_literal(src, k)
            assert lit is not None
            k = lit[1]
            continue
        if c == "'":
            k = src.index("'", k + 2 if src[k + 1] == "\\" else k + 1) + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return k
        k += 1
    raise ValueError("unbalanced")


def tests(src: str) -> list[tuple[str, int, int]]:
    """(name, body start, body end) of each TEST/TEST_F."""
    out = []
    for m in re.finditer(r"^TEST(?:_F)?\(\s*(\w+),\s*(\w+)\)\s*\{", src, re.MULTILINE):
        start = m.end()
        depth, k = 1, start
        while depth:
            c = src[k]
            if c == '"' or src.startswith('R"', k):
                lit = read_literal(src, k)
                k = lit[1] if lit else k + 1
                continue
            depth += {"{": 1, "}": -1}.get(c, 0)
            k += 1
        out.append((f"{m.group(1)}.{m.group(2)}", start, k))
    return out


def line_of(src: str, i: int) -> int:
    return src.count("\n", 0, i) + 1


def parser_fixtures(src: str) -> tuple[list[dict], list[str]]:
    fixtures: list[dict] = []
    skipped: list[str] = []
    for name, start, end in tests(src):
        body = src[start:end]
        # Direct parsers: `parser <var>(<literal>);`, judged by how <var>.parse() is used.
        direct: dict[str, dict] = {}
        for m in re.finditer(r"\bparser\s+(\w+)\((?=[R\"])", body):
            text, _ = read_string_expr(body, m.end())
            if text is None:
                skipped.append(f"{name}: parser {m.group(1)}(...) is not a literal")
                continue
            var = m.group(1)
            rest = body[m.end() :]
            nxt = re.search(r"\bparser\s+\w+\(", rest)
            scope = rest[: nxt.start()] if nxt else rest
            throws = re.search(rf"(EXPECT|ASSERT)_(ANY_)?THROW\(\s*{var}\.parse\(\)", scope)
            fx = {
                "test": name,
                "line": line_of(src, start + m.start()),
                "input": text,
                "verdict": "reject" if throws else "accept",
                "variants": False,
            }
            res = re.search(rf"auto\s+(\w+)\s*=\s*{var}\.parse\(\)", scope)
            if res:
                asm = re.search(rf"as_string\(\s*{res.group(1)}\.get\(\)\)\s*,", scope)
                if asm:
                    expected, _ = read_string_expr(scope, asm.end())
                    if expected is not None:
                        fx["ast"] = expected
            direct[var] = fx
            fixtures.append(fx)
        for m in re.finditer(r"\b(test_accept|test_reject|test_reject_msg|test_equal_ast)\(", body):
            fn = m.group(1)
            text, j = read_string_expr(body, m.end())
            if text is None:
                call = body[m.start() : matching_paren(body, m.end() - 1) + 1]
                skipped.append(
                    f"{name}:{line_of(src, start + m.start())}: {' '.join(call.split())[:90]}"
                )
                continue
            fx = {
                "test": name,
                "line": line_of(src, start + m.start()),
                "input": text,
                "verdict": "reject" if fn.startswith("test_reject") else "accept",
                "variants": fn == "test_accept" and body[j] == ")",
            }
            if fn == "test_reject_msg":
                msg, _ = read_string_expr(body, j + 1)
                fx["message"] = msg
            fixtures.append(fx)
    return fixtures, skipped


MOCK_FIELDS = ("c.true", "c.false", "c.buffer", "c.doublequote", "c.singlequote")


def compiler_fixtures(src: str) -> tuple[list[dict], list[str]]:
    fixtures: list[dict] = []
    skipped: list[str] = []
    for name, start, end in tests(src):
        body = src[start:end]
        for m in re.finditer(r"\btest_filter_compile(_msg)?\(\s*\w+\s*,", body):
            text, j = read_string_expr(body, m.end())
            line = line_of(src, start + m.start())
            if text is None:
                skipped.append(f"{name}:{line}: filter is not a literal")
                continue
            fx: dict = {"test": name, "line": line, "filter": text}
            if m.group(1):
                msg, _ = read_string_expr(body, j + 1)
                fx.update(fail=True, warnings=0, message=msg)
            else:
                close = matching_paren(body, body.index("(", m.start()))
                rest = [a.strip() for a in body[j:close].strip(", ").split(",") if a.strip()]
                fx["fail"] = bool(rest) and rest[0] == "true"
                fx["warnings"] = int(rest[1]) if len(rest) > 1 else 0
            fx["mock"] = any(f in text for f in MOCK_FIELDS)
            fixtures.append(fx)
    return fixtures, skipped


def head(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--libs", type=Path, required=True)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    sha = head(args.libs)
    parser, pskip = parser_fixtures((args.libs / PARSER_TESTS).read_text(encoding="utf-8"))
    compiler, cskip = compiler_fixtures((args.libs / COMPILER_TESTS).read_text(encoding="utf-8"))
    outputs = {
        "parser.json": {
            "source": f"falcosecurity/libs@{sha}",
            "file": PARSER_TESTS,
            "license": "Apache-2.0",
            "skipped": pskip,
            "fixtures": parser,
        },
        "compiler.json": {
            "source": f"falcosecurity/libs@{sha}",
            "file": COMPILER_TESTS,
            "license": "Apache-2.0",
            "skipped": cskip,
            "fixtures": compiler,
        },
    }
    stale = []
    for name, data in outputs.items():
        text = json.dumps(data, indent=1, ensure_ascii=True) + "\n"
        path = OUT / name
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                stale.append(name)
        else:
            OUT.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            print(
                f"wrote {path.relative_to(ROOT)}: {len(data['fixtures'])} fixtures, "
                f"{len(data['skipped'])} skipped"
            )
    if stale:
        print("stale: " + ", ".join(stale), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
