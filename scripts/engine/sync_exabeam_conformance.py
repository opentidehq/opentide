#!/usr/bin/env python3
"""Record the reference checker's verdicts on the Exabeam conformance queries.

specifications `specs/languages/exabeam-1.0.md` comes with a reference checker,
`scripts/exabeam_language.py` in opentidehq/specifications. Exabeam publishes
no grammar and no parser, so that checker is the reference the engine
(`crates/opentide-exabeam`) is held to. This script runs it over

- `crates/testdata/conformance/exabeam/{valid,invalid,highlight}/*.exabeam` (the
  spec's fixtures, copied unchanged),
- `crates/testdata/conformance/external/exabeam/*.exabeam` (queries written for
  opentide, and their `.broken.` twins),
- `crates/testdata/conformance/exabeam/probes.tsv` (more queries written for
  opentide, one per line),

and writes `crates/testdata/conformance/exabeam/reference.json`: for each query, its
profile and the checker's diagnostics (code, byte range) and highlight tokens
(byte range, capture). `crates/opentide-exabeam/tests/reference.rs` compares
the engine with it. Byte offsets: the checker counts characters.

It also runs the block checker, `validate_exabeam_block` and
`validate_exabeam_searches` of the specifications' `scripts/object_fixtures.py`,
over `crates/testdata/conformance/exabeam/blocks/*.yaml` (block cases written for
opentide) and `objects/{valid,invalid}/*.yaml` (the spec's fixtures), and
records each error's code and field path under `blocks`
(`crates/opentide-tide/tests/exabeam_spec.rs` compares them). Unknown keys
(`unknown_field`, `external_id_in_rule`) are left out: the Tide catalogue
reports those.

Inputs (read as data; the checker is imported from the checkout given):

- ``--specifications DIR``: an opentidehq/specifications checkout.

Usage:
    python -I scripts/engine/sync_exabeam_conformance.py --specifications ../specifications [--check]

``--check`` compares with the committed file and exits 1 when it differs.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFORMANCE = ROOT / "testdata" / "conformance" / "exabeam"
EXTERNAL = ROOT / "testdata" / "conformance" / "external" / "exabeam"
OUT = CONFORMANCE / "reference.json"


def load_module(specifications: Path, name: str):  # noqa: ANN201 -- a module
    path = specifications / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def block_cases() -> list[Path]:
    paths = sorted((CONFORMANCE / "blocks").glob("*.yaml"))
    for sub in ("valid", "invalid"):
        paths += sorted((CONFORMANCE / "objects" / sub).glob("*.yaml"))
    return paths


def record_block(fixtures, path: Path) -> dict[str, object]:  # noqa: ANN001
    doc = fixtures.load_yaml(path)
    errors = []
    configurations = doc.get("configurations") if isinstance(doc, dict) else None
    if isinstance(configurations, dict) and isinstance(configurations.get("exabeam"), dict):
        errors += fixtures.validate_exabeam_block(configurations["exabeam"], doc.get("name"))
    errors += fixtures.validate_exabeam_searches(doc)
    found = sorted(
        {
            (e.code, e.path.replace("[", ".").replace("]", ""))
            for e in errors
            if e.code not in ("unknown_field", "external_id_in_rule")
        }
    )
    return {"file": str(path.relative_to(CONFORMANCE)), "errors": [list(e) for e in found]}


def commit(specifications: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(specifications), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return out.stdout.strip()


def queries() -> list[tuple[str, str, str]]:
    """(name, profile, text) for every conformance query."""
    out: list[tuple[str, str, str]] = []
    for sub in ("valid", "invalid", "highlight"):
        for path in sorted((CONFORMANCE / sub).glob("*.exabeam")):
            out.append((f"{sub}/{path.name}", path.name.split(".")[-2], path.read_text(encoding="utf-8")))
    for path in sorted(EXTERNAL.glob("*.exabeam")):
        out.append((f"external/{path.name}", path.name.split(".")[-2], path.read_text(encoding="utf-8")))
    lines = (CONFORMANCE / "probes.tsv").read_text(encoding="utf-8").splitlines()
    for number, line in enumerate(lines, start=1):
        if line.startswith("#"):
            continue
        profile, _, text = line.partition("\t")
        out.append((f"probes.tsv:{number}", profile, text.replace("⏎", "\n").replace("⇥", "\t")))
    return out


def byte_offsets(text: str) -> list[int]:
    offsets = [0]
    for ch in text:
        offsets.append(offsets[-1] + len(ch.encode("utf-8")))
    return offsets


def record(checker, name: str, profile: str, text: str) -> dict[str, object]:  # noqa: ANN001
    result = checker.analyze(text, profile)
    b = byte_offsets(text)

    def at(i: int) -> int:
        return b[min(i, len(text))] + max(0, i - len(text))

    return {
        "name": name,
        "profile": profile,
        "text": text,
        "diagnostics": [[d.code, at(d.start), at(d.end)] for d in result.diagnostics],
        "tokens": [[at(t.start), at(t.end), t.capture] for t in result.tokens],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--specifications", type=Path, required=True)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    checker = load_module(args.specifications, "exabeam_language")
    fixtures = load_module(args.specifications, "object_fixtures")
    doc = {
        "generated_by": "scripts/engine/sync_exabeam_conformance.py",
        "reference": f"opentidehq/specifications@{commit(args.specifications)} scripts/exabeam_language.py, scripts/object_fixtures.py",
        "queries": [record(checker, *q) for q in queries()],
        "blocks": [record_block(fixtures, p) for p in block_cases()],
    }
    text = json.dumps(doc, indent=1, ensure_ascii=False) + "\n"
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print(f"{OUT.relative_to(ROOT)} is out of date", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(doc['queries'])} queries, {len(doc['blocks'])} blocks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
