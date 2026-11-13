#!/usr/bin/env python3
"""YARA oracle (#165): the engine against libyara 4.5.4 and YARA-X 1.23.0.

The references are the ``yara-python`` 4.5.4 and ``yara-x`` 1.23.0 wheels,
installed in CI only (``oracle.yml``); neither ships, and neither may appear
in a Rust or npm manifest (``scripts/engine/ci-oracle.sh``).

Two checks:

1. Every verdict recorded in ``crates/testdata/conformance/yara/cases.json`` is what
   the live engines say. ``crates/opentide-yara/tests/conformance.rs`` holds
   the engine to those verdicts on every ``cargo test``; this keeps them
   honest without the YARA-X and libyara checkouts.
2. Every YARA file in the repository (``crates/testdata/corpus/yara``, the external
   corpus with its ``.broken.`` twins, YARA-X's parser suite) goes through the
   engine (``opentide-lsp analyze``) and both references. They agree when:
   - the engine reports an error exactly when libyara refuses the file;
   - when libyara compiles it and YARA-X refuses it, the engine warns
     ``yara_x_incompatible`` (or ``yara_entrypoint_deprecated``);
   - when YARA-X compiles it too, the engine does not warn
     ``yara_x_incompatible``.

A disagreement fails unless a ``[[yara]]`` entry of
``crates/testdata/oracles/exceptions.toml`` lists its path, and a listed file that
agrees fails too. ``conformance.rs`` reads the same entries for the cases.

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
PINS = {"yara": "4.5.4", "yara_x": "1.23.0"}  # yara-python, yara-x

sys.path.insert(0, str(ROOT / "scripts"))
from sync_yara_conformance import verdicts  # noqa: E402


def check_pins() -> None:
    from importlib.metadata import version

    found = {"yara": version("yara-python"), "yara_x": version("yara-x")}
    for name, want in PINS.items():
        if found[name] != want:
            sys.exit(f"{name} {found[name]} installed; the oracle pins {want}")


def ledger() -> dict[str, dict]:
    """Path → its `[[yara]]` entry."""
    out = {}
    for entry in tomllib.loads(EXCEPTIONS.read_text()).get("yara", []):
        if (
            not entry.get("id")
            or not entry.get("reason")
            or entry.get("check") not in ("libyara", "yara_x", "both")
        ):
            sys.exit(
                f"[[yara]] {entry.get('id')}: needs an id, a reason, "
                "and check = libyara, yara_x or both"
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
    # `yara_empty_signature` is yara-1.0's rule for a signature; libyara
    # compiles a file of private rules.
    error = any(d["severity"] == "error" and d["code"] != "yara_empty_signature" for d in found)
    return error, {d["code"] for d in found}


def disagreement(theirs: dict, error: bool, codes: set[str]) -> str | None:
    if theirs["libyara"] not in ("ok", "warning", "error"):
        return None
    if error != (theirs["libyara"] == "error"):
        return "libyara"
    flagged = bool(codes & {"yara_x_incompatible", "yara_entrypoint_deprecated"})
    if theirs["libyara"] != "error" and (theirs["yara_x"] == "error") != flagged:
        return "yara_x"
    return None


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
        live = verdicts(case["source"])
        if (live["libyara"], live["yara_x"]) != (case["libyara"], case["yara_x"]):
            failures.append(
                f"{case['origin']}: recorded {case['libyara']}/{case['yara_x']}, the engines say "
                f"{live['libyara']}/{live['yara_x']} "
                "(re-run scripts/engine/sync_yara_conformance.py)"
            )

    # 2. The files.
    files = sorted({p for folder, glob in CORPORA for p in (ROOT / folder).glob(glob)})
    if not files:
        sys.exit("no YARA file found")
    for path in files:
        rel = path.relative_to(ROOT).as_posix()
        theirs = verdicts(path.read_text(encoding="utf-8", errors="surrogateescape"))
        error, codes = engine(args.binary, path)
        kind = disagreement(theirs, error, codes)
        entry = known.get(rel)
        report[rel] = {
            **theirs,
            "engine_error": error,
            "engine_codes": sorted(codes),
            "disagreement": kind,
        }
        if kind and not (entry and entry["check"] in (kind, "both")):
            failures.append(
                f"{rel}: {kind} disagreement: libyara {theirs['libyara']}, "
                f"YARA-X {theirs['yara_x']}, "
                f"engine {'error' if error else 'no error'} {sorted(codes)}"
                f" [{theirs.get('libyara_message') or theirs.get('yara_x_message') or ''}]"
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
