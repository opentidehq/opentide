#!/usr/bin/env python3
"""YARA oracle (#165, #1225): the engine against YARA-X 1.23.0.

YARA-X is the language (#1225). The reference is the ``yara-x`` 1.23.0
wheel, installed in CI only (``oracle.yml``); it never ships, and must not
appear in a Rust or npm manifest (``scripts/engine/ci-oracle.sh``). libyara is
no oracle any more: the ``libyara`` verdicts in ``cases.json`` are what
``scripts/engine/sync_yara_conformance.py`` recorded, read only by the
portability check's test.

Two checks:

1. Every YARA-X verdict recorded in ``crates/testdata/conformance/yara/cases.json``
   is what the live wheel says. ``crates/opentide-yara/tests/conformance.rs``
   holds the engine to those verdicts on every ``cargo test``; this keeps them
   honest without the YARA-X checkout.
2. Every YARA file in the repository (``crates/testdata/corpus/yara``, the external
   corpus with its ``.broken.`` twins, YARA-X's parser suite) goes through the
   engine (``opentide-lsp analyze``) and the wheel. They agree when the engine
   reports an error exactly when YARA-X refuses the file.

A disagreement fails unless a ``[[yara]]`` entry of
``crates/testdata/oracles/exceptions.toml`` with ``check = "yara_x"`` lists its
path, and a listed file that agrees fails too. ``conformance.rs`` reads the
same entries for the cases.

Usage:
    python3 scripts/engine/oracles/yara/oracle.py \
        [--binary target/debug/opentide-lsp] [--report report.json]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys

import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[4]
CASES = ROOT / "crates/testdata/conformance/yara/cases.json"
EXCEPTIONS = ROOT / "crates/testdata/oracles/exceptions.toml"
CORPORA = [
    ("crates/testdata/corpus/yara", "*.yar"),
    ("crates/testdata/conformance/external/yara", "**/*.yar"),
    ("crates/testdata/conformance/external/yara", "**/*.yara"),
    ("crates/testdata/conformance/yara-x/parser", "*.in"),
]
YARA_X = "1.23.0"  # the yara-x wheel

sys.path.insert(0, str(ROOT / "scripts" / "engine"))
from sync_yara_conformance import verdicts  # noqa: E402


def check_pins() -> None:
    from importlib.metadata import version

    found = version("yara-x")
    if found != YARA_X:
        sys.exit(f"yara-x {found} installed; the oracle pins {YARA_X}")


def ledger() -> dict[str, dict]:
    """Path → its `[[yara]]` entry."""
    out = {}
    for entry in tomllib.loads(EXCEPTIONS.read_text()).get("yara", []):
        if (
            not entry.get("id")
            or not entry.get("reason")
            or entry.get("check") not in ("yara_x", "portable")
        ):
            sys.exit(
                f"[[yara]] {entry.get('id')}: needs an id, a reason, and check = yara_x or portable"
            )
        for path in entry.get("paths", []):
            out[path] = entry
    return out


def engine(binary: pathlib.Path, path: pathlib.Path) -> tuple[bool, set[str]]:
    """Whether the engine reports an error, and the codes it reports."""
    done = subprocess.run(
        [str(binary), "analyze", "--language", "yara", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    found = json.loads(done.stdout or "[]")
    # `yara_empty_signature` is yara-1.0's rule for a signature; YARA-X
    # compiles a file of private rules.
    error = any(d["severity"] == "error" and d["code"] != "yara_empty_signature" for d in found)
    return error, {d["code"] for d in found}


def disagreement(verdict: str, error: bool) -> str | None:
    if verdict not in ("ok", "error"):
        return None
    return "yara_x" if error != (verdict == "error") else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", type=pathlib.Path, default=ROOT / "target/debug/opentide-lsp")
    ap.add_argument("--report", type=pathlib.Path)
    args = ap.parse_args()
    check_pins()
    known = ledger()
    failures: list[str] = []
    report: dict[str, dict] = {}

    # 1. The recorded verdicts.
    recorded = json.loads(CASES.read_text())["cases"]
    for case in recorded:
        live = verdicts(case["source"])["yara_x"]
        if live != case["yara_x"]:
            failures.append(
                f"{case['origin']}: recorded {case['yara_x']}, YARA-X says {live} "
                "(re-run scripts/engine/sync_yara_conformance.py)"
            )

    # 2. The files.
    files = sorted({p for folder, glob in CORPORA for p in (ROOT / folder).glob(glob)})
    if not files:
        sys.exit("no YARA file found")
    for path in files:
        rel = path.relative_to(ROOT).as_posix()
        theirs = verdicts(path.read_text(encoding="utf-8", errors="surrogateescape"))
        verdict, message = theirs["yara_x"], theirs.get("yara_x_message", "")
        error, codes = engine(args.binary, path)
        kind = disagreement(verdict, error)
        entry = known.get(rel)
        report[rel] = {
            "yara_x": verdict,
            "yara_x_message": message,
            "engine_error": error,
            "engine_codes": sorted(codes),
            "disagreement": kind,
        }
        if kind and not (entry and entry["check"] == kind):
            failures.append(
                f"{rel}: YARA-X {verdict}, "
                f"engine {'error' if error else 'no error'} {sorted(codes)} [{message}]"
            )
        if entry and not kind:
            failures.append(f"{rel}: listed by [[yara]] {entry['id']} but agrees now; delete it")

    if args.report:
        args.report.write_text(json.dumps(report, indent=1) + "\n")
    print(
        f"yara: {len(recorded)} recorded verdicts, {len(files)} files, {len(failures)} failure(s)"
    )
    for f in failures:
        print(f"  {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
