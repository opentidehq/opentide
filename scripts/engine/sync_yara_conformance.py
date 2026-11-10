#!/usr/bin/env python3
"""Extract the YARA conformance cases (#165) and record each engine's verdict.

Reads two checkouts, both BSD-3-Clause:

- VirusTotal/yara-x at the pinned tag: every `condition_true!`,
  `condition_false!`, `rule_true!`, `rule_false!`, `pattern_true!`,
  `pattern_false!` and `pattern_match!` of ``lib/src/tests/mod.rs`` whose
  first argument is a string literal, expanded as the macro expands it; and
  each ``lib/src/compiler/tests/testdata/{errors,warnings}/*.in``;
- VirusTotal/yara at the pinned tag: every ``assert_true_rule*``,
  ``assert_false_rule*``, ``assert_error`` and ``assert_warning*`` of
  ``tests/test-rules.c`` whose rule is a C string literal.

and writes ``testdata/conformance/yara/cases.json``: one row per case with
its source, where it comes from, and the verdict of `yara-python` 4.5.4
(libyara: ``ok``, ``warning`` or ``error``) and of the ``yara-x`` wheel
(``ok`` or ``error``). The verdicts are what the engine is held to
(``crates/opentide-yara/tests/conformance.rs``); ``scripts/oracles`` checks
them again against the engines in CI. Neither package ships.

Usage:
    python -I scripts/sync_yara_conformance.py --yara-x ../yara-x --libyara ../yara [--check]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "testdata" / "conformance" / "yara" / "cases.json"

YARA_X_TAG = "v1.23.0"
LIBYARA_TAG = "v4.5.4"

RUST_MACROS = {
    "condition_true": "rule t {{condition: {} }}",
    "condition_false": "rule t {{condition: {} }}",
    "rule_true": "{}",
    "rule_false": "{}",
    "pattern_true": "rule test {{ strings: $a = {} condition: $a}}",
    "pattern_false": "rule test {{ strings: $a = {} condition: $a}}",
    "pattern_match": "rule test {{ strings: $a = {} condition: $a}}",
}


def rust_literal(text: str, i: int) -> tuple[str, int] | None:
    """The Rust string literal at `text[i:]` (after blanks), and its end."""
    while i < len(text) and text[i] in " \t\r\n":
        i += 1
    m = re.match(r'r(#*)"', text[i:])
    if m:
        hashes = m.group(1)
        start = i + m.end()
        end = text.find('"' + hashes, start)
        return (text[start:end], end + 1 + len(hashes)) if end >= 0 else None
    if text.startswith('"', i):
        out, j = [], i + 1
        while j < len(text):
            c = text[j]
            if c == '"':
                return "".join(out), j + 1
            if c == "\\":
                n = text[j + 1]
                if n == "\n":
                    j += 2
                    while j < len(text) and text[j] in " \t\r\n":
                        j += 1
                    continue
                simple = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"', "'": "'"}
                if n in simple:
                    out.append(simple[n])
                    j += 2
                    continue
                if n == "x":
                    out.append(chr(int(text[j + 2 : j + 4], 16)))
                    j += 4
                    continue
                if n == "u":
                    close = text.index("}", j)
                    out.append(chr(int(text[j + 3 : close], 16)))
                    j = close + 1
                    continue
            out.append(c)
            j += 1
    return None


def yara_x_cases(root: Path) -> list[dict]:
    cases = []
    tests = (root / "lib/src/tests/mod.rs").read_text()
    pattern = re.compile(r"\b(" + "|".join(RUST_MACROS) + r")!\s*\(")
    for m in pattern.finditer(tests):
        lit = rust_literal(tests, m.end())
        if lit is None:
            continue
        body, _ = lit
        source = RUST_MACROS[m.group(1)].format(body)
        line = tests.count("\n", 0, m.start()) + 1
        cases.append({"origin": f"yara-x:lib/src/tests/mod.rs:{line}", "kind": m.group(1), "source": source})
    for kind in ["errors", "warnings"]:
        folder = root / "lib/src/compiler/tests/testdata" / kind
        for path in sorted(folder.glob("*.in"), key=lambda p: (len(p.stem), p.stem)):
            cases.append({
                "origin": f"yara-x:{path.relative_to(root)}",
                "kind": f"compiler_{kind}",
                "source": path.read_text(encoding="utf-8", errors="replace"),
            })
    return cases


def c_literals(text: str, i: int) -> tuple[str, int] | None:
    """Adjacent C string literals at `text[i:]`, concatenated, and their end."""
    out, found = [], False
    while True:
        while i < len(text) and text[i] in " \t\r\n":
            i += 1
        if text.startswith("//", i):
            i = text.index("\n", i)
            continue
        if not text.startswith('"', i):
            break
        found = True
        j = i + 1
        while text[j] != '"':
            c = text[j]
            if c == "\\":
                n = text[j + 1]
                simple = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'", "0": "\0"}
                if n in simple:
                    out.append(simple[n])
                    j += 2
                    continue
                if n == "x":
                    k = j + 2
                    while k < len(text) and text[k] in "0123456789abcdefABCDEF":
                        k += 1
                    out.append(chr(int(text[j + 2 : k], 16)))
                    j = k
                    continue
            out.append(c)
            j += 1
        i = j + 1
    return ("".join(out), i) if found else None


def libyara_cases(root: Path) -> list[dict]:
    cases = []
    text = (root / "tests/test-rules.c").read_text()
    call = re.compile(r"\b(assert_true_rule\w*|assert_false_rule\w*|assert_error|assert_warning\w*)\s*\(")
    for m in call.finditer(text):
        lit = c_literals(text, m.end())
        if lit is None:
            continue
        source, end = lit
        if not text[end:].lstrip().startswith((",", ")")):
            continue
        line = text.count("\n", 0, m.start()) + 1
        cases.append({"origin": f"libyara:tests/test-rules.c:{line}", "kind": m.group(1), "source": source})
    return cases


def libyara_verdict(source: str) -> tuple[str, str]:
    """libyara's verdict and its first message."""
    import yara

    try:
        yara.compile(source=source)
    except Exception as e:
        return "error", str(e)
    try:
        yara.compile(source=source, error_on_warning=True)
    except yara.WarningError as e:
        return "warning", "; ".join(getattr(e, "warnings", []) or [str(e)])
    except Exception as e:
        return "error", str(e)
    return "ok", ""


def yara_x_verdict(source: str) -> tuple[str, str]:
    """YARA-X's verdict and the first line of its message."""
    import yara_x

    try:
        c = yara_x.Compiler()
        c.add_source(source)
        c.build()
    except Exception as e:
        return "error", str(e).splitlines()[0] if str(e) else ""
    return "ok", ""


def verdicts(source: str) -> dict:
    """Both verdicts, from a child process with 2 GB and 20 seconds: a case
    that makes an engine blow up is recorded, not fatal."""
    import resource

    def limit() -> None:
        resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))

    try:
        done = subprocess.run(
            [sys.executable, "-I", __file__, "--verdict"],
            input=source.encode("utf-8", "surrogatepass"),
            capture_output=True,
            timeout=20,
            preexec_fn=limit,
        )
    except subprocess.TimeoutExpired:
        return {"libyara": "timeout", "yara_x": "timeout"}
    try:
        return json.loads(done.stdout.decode())
    except ValueError:
        return {"libyara": "crash", "yara_x": "crash"}


def tags(path: Path) -> list[str]:
    """The tags on the checkout's commit (YARA-X tags `v1.23.0` and `go/v1.23.0` alike)."""
    return subprocess.run(
        ["git", "-C", str(path), "tag", "--points-at", "HEAD"], capture_output=True, text=True
    ).stdout.split()


def main() -> int:
    if sys.argv[1:] == ["--verdict"]:
        source = sys.stdin.buffer.read().decode("utf-8", "surrogatepass")
        (ly, ly_msg), (yx, yx_msg) = libyara_verdict(source), yara_x_verdict(source)
        out = {"libyara": ly, "yara_x": yx}
        if ly_msg:
            out["libyara_message"] = ly_msg
        if yx_msg:
            out["yara_x_message"] = yx_msg
        print(json.dumps(out))
        return 0
    ap = argparse.ArgumentParser()
    ap.add_argument("--yara-x", type=Path, required=True)
    ap.add_argument("--libyara", type=Path, required=True)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    for path, want in [(args.yara_x, YARA_X_TAG), (args.libyara, LIBYARA_TAG)]:
        if want not in tags(path):
            print(f"{path} is not at {want}", file=sys.stderr)
            return 2
    cases = yara_x_cases(args.yara_x) + libyara_cases(args.libyara)
    seen, rows = set(), []
    for case in cases:
        if case["source"] in seen:
            continue
        seen.add(case["source"])
        case.update(verdicts(case["source"]))
        rows.append(case)
    text = json.dumps(
        {"yara_x": YARA_X_TAG, "libyara": LIBYARA_TAG, "cases": rows}, indent=1, ensure_ascii=False
    ) + "\n"
    if args.check:
        if OUT.read_text() != text:
            print(f"{OUT.relative_to(ROOT)} is stale", file=sys.stderr)
            return 1
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    from collections import Counter

    print(f"wrote {OUT.relative_to(ROOT)}: {len(rows)} cases;",
          dict(Counter((r["libyara"], r["yara_x"]) for r in rows)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
