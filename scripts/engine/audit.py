#!/usr/bin/env python3
"""The scheduled `cargo audit` run's helpers (#843, `rust-audit.yml`).

    audit.py ignores            print `--ignore <ID>` for each advisory deny.toml excepts
    audit.py report JSON...     print the issue body for cargo audit's JSON reports

cargo-deny gates every pull request; `cargo audit` runs on a schedule as well,
so an advisory published after a change merged reaches the maintainers as an
issue without anyone opening a pull request. The two read one list of
exceptions: deny.toml's `[advisories] ignore`, each with its reason there.

`report` reads the JSON `cargo audit --json` writes for each lock file and
prints a Markdown issue body: every vulnerability and every warning (an
unmaintained, unsound or yanked crate), with its advisory, the crate and
version, and the fix when RustSec names one. A file that is not cargo audit's
JSON stops the script: a failed audit must fail the run, not open an issue.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import tomllib

ROOT = Path(__file__).resolve().parents[2]

ISSUE_TITLE = "cargo audit: RustSec advisories in the Rust lock files"


def ignored_advisories(deny_toml: str) -> list[str]:
    """The advisory ids deny.toml's ``[advisories] ignore`` excepts."""
    ignore = tomllib.loads(deny_toml).get("advisories", {}).get("ignore", [])
    ids = [entry["id"] if isinstance(entry, dict) else entry for entry in ignore]
    return [str(advisory) for advisory in ids]


def findings(report: dict[str, Any]) -> list[dict[str, str]]:
    """Each vulnerability and warning in one ``cargo audit --json`` report."""
    if "vulnerabilities" not in report or "warnings" not in report:
        raise ValueError("not a cargo audit JSON report")
    found: list[dict[str, str]] = []
    entries = [("vulnerability", v) for v in report["vulnerabilities"].get("list", [])]
    for kind, warnings in (report.get("warnings") or {}).items():
        entries += [(kind, w) for w in warnings or []]
    for kind, entry in entries:
        advisory = entry.get("advisory") or {}
        package = entry.get("package") or {}
        patched = (entry.get("versions") or {}).get("patched") or []
        found.append(
            {
                "kind": kind,
                "id": str(advisory.get("id", "")),
                "title": str(advisory.get("title", "")),
                "crate": str(package.get("name", "")),
                "version": str(package.get("version", "")),
                "fix": ", ".join(patched) if patched else "none published",
                "url": str(advisory.get("url") or ""),
            }
        )
    return found


# GitHub's limit on an issue body is 65536 characters; stay well under it.
BODY_LIMIT = 60000


def _cell(text: str) -> str:
    """``text`` inert in a Markdown table cell: advisory titles are external
    text, so no table break, HTML, link, image, code span or @-mention
    (which would notify someone) survives."""
    text = text.replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")
    for char in "\\|[]()!`*_~#":
        text = text.replace(char, f"\\{char}")
    # A zero-width joiner after `@` keeps a name from becoming a mention.
    return text.replace("@", "@\u200d")


def _link(advisory: str, url: str) -> str:
    """The advisory id, linked to its page when the URL is a plain https one."""
    if url.startswith("https://") and not any(c in url for c in " ()[]<>\"'`"):
        return f"[{_cell(advisory)}]({url})"
    return _cell(advisory)


def render(reports: dict[str, dict[str, Any]], run_url: str = "") -> str:
    """The issue body for ``reports`` (lock file → its cargo audit report)."""
    lines = [
        "The scheduled `cargo audit` (`.github/workflows/rust-audit.yml`) found RustSec "
        "advisories in the Rust lock files. Fix each (update or replace the crate), or "
        "except it in `deny.toml`'s `[advisories] ignore` with its reason and a follow-up "
        "issue; `cargo deny check` on pull requests reads the same list.",
        "",
    ]
    total = 0
    for lock, report in sorted(reports.items()):
        rows = findings(report)
        total += len(rows)
        lines += [f"### `{lock}`", ""]
        if not rows:
            lines += ["Nothing found.", ""]
            continue
        lines += ["| Kind | Advisory | Crate | Fix | Title |", "| --- | --- | --- | --- | --- |"]
        for row in rows:
            lines.append(
                f"| {_cell(row['kind'])} | {_link(row['id'], row['url'])} | {_cell(row['crate'])} "
                f"{_cell(row['version'])} | {_cell(row['fix'])} | {_cell(row['title'])} |"
            )
        lines.append("")
    if run_url:
        lines += [f"Run: {run_url}", ""]
    lines.insert(0, f"**{total} advisories.**\n")
    body = "\n".join(lines)
    if len(body) > BODY_LIMIT:
        cut = body.rfind("\n", 0, BODY_LIMIT)
        body = body[:cut] + "\n\n(Cut to fit an issue: the run's summary has every row.)\n"
    return body


def main(argv: list[str]) -> int:
    if argv[:1] == ["ignores"]:
        for advisory in ignored_advisories((ROOT / "deny.toml").read_text(encoding="utf-8")):
            print(f"--ignore\n{advisory}")
        return 0
    if argv[:1] == ["report"] and len(argv) > 1:
        reports: dict[str, dict[str, Any]] = {}
        for name in argv[1:]:
            path = Path(name)
            try:
                report = json.loads(path.read_text(encoding="utf-8"))
                findings(report)
            except (OSError, ValueError) as error:
                print(f"audit.py: {path}: {error}", file=sys.stderr)
                return 2
            reports[report.get("lockfile", {}).get("path", path.name)] = report
        run_url = ""
        if os.environ.get("GITHUB_RUN_ID"):
            server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
            run_url = (
                f"{server}/{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/"
                f"{os.environ['GITHUB_RUN_ID']}"
            )
        print(render(reports, run_url))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
