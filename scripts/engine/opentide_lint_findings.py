#!/usr/bin/env python3
"""Record what `opentide lint` reports for a workspace, in the engine's codes (#214).

    python3 scripts/opentide_lint_findings.py DIR            # print the findings
    python3 scripts/opentide_lint_findings.py DIR --write    # update DIR/opentide-lint.json
    python3 scripts/opentide_lint_findings.py DIR --check    # fail if it differs

Each record is `{file, code}` with the file relative to DIR. The CLI's codes are
mapped to the language server's: `filename_mismatch` is `filename_slug`, and a
`metadata_recommended` finding is one `missing_<key>` per missing `author` or
`organisation`. Other findings are left out: the engine's Tide checks have no
counterpart for them. `crates/opentide-analysis/tests/lint_settings.rs` checks
the engine against the recorded file, so `lint.toml` cannot be read two ways.

Needs an opentide that reads `[filenames] style` and `pattern` (0.20.0 or later),
on PATH as `opentide`: CI's pinned opentide is older, so the file is recorded
and the Rust test reads it.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ORACLE = "opentide-lint.json"
_MISSING = re.compile(r"missing: (.+)$")


def findings(root: Path) -> dict:
    run = subprocess.run(
        ["opentide", "--json", "--repo", str(root), "lint"],
        capture_output=True,
        text=True,
        check=False,
        cwd=root,
    )
    document = json.loads(run.stdout)
    rows: set[tuple[str, str]] = set()
    for finding in document.get("findings", []):
        code, path = finding.get("code"), finding.get("path")
        if code in ("filename_mismatch", "filename_pattern"):
            rows.add((path, "filename_slug" if code == "filename_mismatch" else code))
        elif code == "metadata_recommended":
            match = _MISSING.search(finding.get("message", ""))
            keys = [k.strip() for k in match.group(1).split(",")] if match else []
            rows.update((path, f"missing_{k}") for k in keys if k in ("author", "organisation"))
    version = subprocess.run(
        ["opentide", "--version"], capture_output=True, text=True, check=False
    ).stdout.strip()
    return {
        "opentide": version,
        "findings": [{"file": f, "code": c} for f, c in sorted(rows)],
    }


def main() -> int:
    root = Path(sys.argv[1]).resolve()
    recorded = findings(root)
    oracle = root / ORACLE
    if "--write" in sys.argv:
        oracle.write_text(json.dumps(recorded, indent=2) + "\n", encoding="utf-8")
        return 0
    if "--check" in sys.argv:
        stored = json.loads(oracle.read_text(encoding="utf-8"))
        if stored["findings"] != recorded["findings"]:
            print(f"{oracle} is out of date; run with --write", file=sys.stderr)
            return 1
        return 0
    json.dump(recorded, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
