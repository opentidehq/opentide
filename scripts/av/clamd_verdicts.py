#!/usr/bin/env python3
"""Check that clamd gave a verdict for every file of the trees it scanned (#1743).

    clamd_verdicts.py --log LOG TREE...

LOG is clamd's log, written with `LogClean yes` and `LogTime no`: one line `PATH: OK` for a clean
file and `PATH: SIGNATURE FOUND` for a detection, a file found clean before (a cache hit) included.
`clamdscan --multiscan` has the daemon walk each TREE itself, so a file it never reached (a
directory deeper than MaxDirectoryRecursion, a file it could not read) would otherwise pass in
silence. Here every regular file of each TREE (symbolic links are not followed, as clamd follows
none) must have a line; a file without one is listed and fails. The detections themselves are
clamdscan's to report (scripts/av/clamav-scan.sh).

Exit status: 0 every file has a verdict, 2 a file has none or the log cannot be read.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

CLEAN = ": OK"
FOUND = " FOUND"


def verdicts(log: str) -> set[str]:
    """The paths the log gives a verdict for: clean, or a signature found."""
    paths: set[str] = set()
    for line in log.splitlines():
        if line.endswith(CLEAN):
            paths.add(line[: -len(CLEAN)])
        elif line.endswith(FOUND):
            # `PATH: SIGNATURE FOUND`: a signature name holds no ": ", a path may.
            path, separator, _ = line.rpartition(": ")
            if separator:
                paths.add(path)
    return paths


def regular_files(tree: Path) -> list[str]:
    """Every regular file under `tree`, by its absolute path, as `find TREE -type f` lists them."""
    files: list[str] = []
    for directory, _, names in os.walk(tree, followlinks=False):
        for name in names:
            path = os.path.join(directory, name)
            if os.path.isfile(path) and not os.path.islink(path):
                files.append(path)
    return sorted(files)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--log", type=Path, required=True, help="clamd's log (LogClean yes)")
    parser.add_argument("trees", type=Path, nargs="+", metavar="TREE")
    args = parser.parse_args(argv)
    try:
        # Paths are bytes on Linux: decode them as Python decodes file names.
        seen = verdicts(args.log.read_text(encoding="utf-8", errors="surrogateescape"))
    except OSError as error:
        print(f"clamd verdicts: cannot read the log {args.log}: {error}", file=sys.stderr)
        return 2
    missing_any = False
    for tree in args.trees:
        root = tree.resolve()
        if not root.is_dir():
            print(f"clamd verdicts: no such directory: {tree}", file=sys.stderr)
            return 2
        files = regular_files(root)
        missing = [path for path in files if path not in seen]
        found = len(files) - len(missing)
        print(f"clamd verdicts: {tree}: {len(files)} files, {found} with a verdict")
        for path in missing:
            print(f"clamd verdicts: no verdict for {path}", file=sys.stderr)
        missing_any = missing_any or bool(missing)
    return 2 if missing_any else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
