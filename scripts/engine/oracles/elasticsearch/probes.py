#!/usr/bin/env python3
"""Run the live-Elasticsearch probes and compare them with recorded verdicts.

Usage: python3 scripts/oracles/elasticsearch/probes.py [--url URL] [--update] [--show]

Every file under testdata/oracles/elasticsearch/<topic>/ is one probe
(`.eql`, `.esql`, `.lucene`; see run.py for `.unmapped.` and
`.params.json`). `expected.tsv` beside the topics holds one row per probe
and one column per release line (8.19, 9.0, ...): `OK` or `ERR`, and for
Lucene `<strict>/<lenient>` (`ERR/OK`). An empty cell was not recorded.

The script asks the server (ES_URL) for its version, runs every probe, and
fails when a verdict differs from the recorded one for that line, when a
probe or the line has no recorded verdict, or when a recorded probe is gone. With
`--update` it writes the column for that line instead. `--show` prints every
probe's verdict and Elasticsearch's message.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run  # noqa: E402  (sibling module)

ROOT = Path(__file__).resolve().parents[3]
PROBES = ROOT / "testdata/oracles/elasticsearch"
EXPECTED = PROBES / "expected.tsv"


def read_expected() -> tuple[list[str], dict[str, dict[str, str]]]:
    if not EXPECTED.exists():
        return [], {}
    lines = EXPECTED.read_text().splitlines()
    header = lines[0].split("\t")[1:]
    rows = {}
    for line in lines[1:]:
        cells = line.split("\t")
        rows[cells[0]] = {v: c for v, c in zip(header, cells[1:]) if c}
    return header, rows


def write_expected(header: list[str], rows: dict[str, dict[str, str]]) -> None:
    key = lambda v: tuple(int(x) for x in v.split("."))  # noqa: E731
    header = sorted(set(header), key=key)
    out = ["probe\t" + "\t".join(header)]
    for path in sorted(rows):
        out.append(path + "\t" + "\t".join(rows[path].get(v, "") for v in header))
    EXPECTED.write_text("\n".join(out) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default=os.environ.get("ES_URL", "http://127.0.0.1:9200"))
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--show", action="store_true")
    args = parser.parse_args()
    url = args.url.rstrip("/")
    mapped = run.setup(url, {}, False)
    _, body = run.request(url)
    line = ".".join(body["version"]["number"].split(".")[:2])

    header, rows = read_expected()
    if not args.update and line not in header:
        print(f"expected.tsv records no verdicts for {line}; run with --update to add them", file=sys.stderr)
        return 1
    seen: set[str] = set()
    failures = 0
    for path in sorted(PROBES.glob("*/*")):
        lang = path.suffix.lstrip(".")
        if lang not in run.RUNNERS:
            continue
        rel = str(path.relative_to(PROBES))
        seen.add(rel)
        text = path.read_text(encoding="utf-8")
        if lang == "esql":
            sidecar = path.with_name(path.name + ".params.json")
            params = json.loads(sidecar.read_text()) if sidecar.exists() else None
            out = run.run_esql(url, path.name, text, mapped, False, params)
        else:
            out = run.RUNNERS[lang](url, path.name, text, mapped, False)
        cells = out.split("\t")
        verdict = cells[1]
        if lang == "lucene":
            verdict += "/" + cells[3].split(" ", 1)[0].removeprefix("lenient:")
        if args.show:
            print(f"{line}\t{rel}\t{verdict}\t{cells[2]}")
        recorded = rows.get(rel, {}).get(line)
        if args.update:
            rows.setdefault(rel, {})[line] = verdict
        elif recorded is None:
            failures += 1
            print(f"{rel}: no verdict recorded for {line} | Elasticsearch says {verdict}")
        elif recorded != verdict:
            failures += 1
            print(f"{rel}: Elasticsearch {line} says {verdict}, expected.tsv says {recorded} | {cells[2]}")
    if args.update:
        for stale in set(rows) - seen:
            del rows[stale]
        write_expected(header + [line], rows)
        print(f"recorded {len(seen)} verdicts for {line}", file=sys.stderr)
        return 0
    for stale in sorted(set(rows) - seen):
        failures += 1
        print(f"{stale}: recorded in expected.tsv but the probe file is gone")
    print(f"{line}: {len(seen)} probes, {failures} differ from expected.tsv", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
