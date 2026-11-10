#!/usr/bin/env python3
"""Rebuild tests.json: Python vs Rust test functions over the integration history.

Points: development baseline f41fe5e5, then each first-parent merge of
origin/integration/unified-core. Counts are static (parametrized cases count once).
Idempotent: rebuilds the whole file from git every run.
"""
import json
import re
import subprocess
from pathlib import Path

REPO = "/home/user/opentide"
BASE = "f41fe5e5"
BRANCH = "origin/integration/unified-core"
OUT = Path(__file__).resolve().parent / "tests.json"


def git(*args: str, check: bool = True) -> str:
    r = subprocess.run(["git", "-C", REPO, *args], capture_output=True, text=True)
    if check and r.returncode not in (0, 1):  # git grep exits 1 on no match
        raise SystemExit(r.stderr)
    return r.stdout


def grep_count(rev: str, pattern: str, *paths: str) -> int:
    out = git("grep", "-c", "-E", pattern, rev, "--", *paths)
    return sum(int(line.rsplit(":", 1)[1]) for line in out.splitlines() if line)


def point(rev: str, label: str) -> dict:
    sha, at = git("show", "-s", "--format=%h %cI", rev).split()
    return {
        "at": at,
        "rev": sha,
        "label": label,
        "python": grep_count(rev, r"^\s*(async\s+)?def test_", "tests/**/*.py", "tests/*.py"),
        "rust": grep_count(rev, r"#\[(tokio::)?test\]|#\[rstest", "*.rs"),
    }


def main() -> None:
    git("fetch", "-q", "origin", "integration/unified-core", "development")
    rows = [point(BASE, "development baseline")]
    log = git("log", "--first-parent", "--reverse", "--format=%H %s", BRANCH, f"{BASE}..")
    for line in log.splitlines():
        sha, subject = line.split(" ", 1)
        m = re.search(r"#(\d+)", subject)
        rows.append(point(sha, f"#{m.group(1)}" if m else sha[:8]))
    OUT.write_text(json.dumps({"rows": rows}, indent=1) + "\n")
    last = rows[-1]
    print(f"{len(rows)} rows; latest {last['label']}: python {last['python']}, rust {last['rust']}")


if __name__ == "__main__":
    main()
