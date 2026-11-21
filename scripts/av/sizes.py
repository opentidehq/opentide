#!/usr/bin/env python3
"""Hold the release artifacts to their size budgets (tests/bench/sizes.toml, #1743).

    sizes.py [--budgets FILE] DIR

DIR holds the artifacts as the release build names them (the GitHub Release's assets, the wheels,
the sdist). Each `[[artifact]]` of the budgets file names a glob and the most bytes a matching file
may have; a file over its budget fails. A budget no file matches is reported and passes (a run
checks the artifacts it has: the release assets and the wheels are separate downloads).

Compressing the embedded datasets (opentide-dataset) took about a fifth off each binary; a dataset
stored loose again, or a decoder that grew, shows here. Exit status: 0 within budget, 1 over, 2 no
budget file or nothing matched at all.
"""

from __future__ import annotations

import argparse
import fnmatch
import sys
from pathlib import Path

import tomllib

DEFAULT_BUDGETS = Path(__file__).resolve().parents[2] / "tests" / "bench" / "sizes.toml"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--budgets", type=Path, default=DEFAULT_BUDGETS)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    if not args.budgets.is_file() or not args.directory.is_dir():
        print("sizes: no budget file, or DIR is not a directory", file=sys.stderr)
        return 2
    with args.budgets.open("rb") as handle:
        budgets = tomllib.load(handle).get("artifact", [])
    files = sorted(p for p in args.directory.rglob("*") if p.is_file())
    matched = 0
    over = 0
    print(f"{'artifact':<62} {'bytes':>12} {'budget':>12}  verdict")
    for budget in budgets:
        glob, limit = budget["glob"], int(budget["max_bytes"])
        found = [p for p in files if fnmatch.fnmatch(p.name, glob)]
        if not found:
            print(f"{glob:<62} {'-':>12} {limit:>12}  no such artifact in this run")
            continue
        for path in found:
            matched += 1
            size = path.stat().st_size
            verdict = "ok" if size <= limit else "OVER"
            over += size > limit
            print(f"{path.name:<62} {size:>12} {limit:>12}  {verdict}")
    if matched == 0:
        print("sizes: no artifact matched a budget", file=sys.stderr)
        return 2
    return 1 if over else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
