#!/usr/bin/env python3
"""Post or update a stack-navigation comment on a GitHub pull request.

Used by .github/workflows/stack-comment.yml so every PR in a jj stack shows
position, merge order, and links to sibling PRs.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any

MARKER = "<!-- opentide-stack-comment -->"
TRUNK_BRANCHES = frozenset(
    b.strip()
    for b in os.environ.get("STACK_TRUNK_BRANCHES", "development,main").split(",")
    if b.strip()
)


def _run_gh(args: list[str]) -> str:
    result = subprocess.run(
        ["gh", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _pr_fields() -> str:
    return "number,title,url,state,baseRefName,headRefName,isDraft"


def get_pr(pr_number: int) -> dict[str, Any]:
    return json.loads(_run_gh(["pr", "view", str(pr_number), "--json", _pr_fields()]))


def list_open_prs() -> list[dict[str, Any]]:
    raw = _run_gh(["pr", "list", "--state", "open", "--limit", "200", "--json", _pr_fields()])
    return json.loads(raw)


def _find_parent_pr(pr: dict[str, Any], open_prs: list[dict[str, Any]]) -> dict[str, Any] | None:
    base = pr["baseRefName"]
    if base in TRUNK_BRANCHES:
        return None
    matches = [p for p in open_prs if p["headRefName"] == base]
    if not matches:
        return None
    return min(matches, key=lambda p: p["number"])


def _find_child_pr(pr: dict[str, Any], open_prs: list[dict[str, Any]]) -> dict[str, Any] | None:
    head = pr["headRefName"]
    matches = [p for p in open_prs if p["baseRefName"] == head]
    if not matches:
        return None
    return min(matches, key=lambda p: p["number"])


def build_stack_chain(
    current: dict[str, Any], open_prs: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    chain = [current]

    while True:
        parent = _find_parent_pr(chain[0], open_prs)
        if parent is None:
            break
        if parent["number"] in {p["number"] for p in chain}:
            break
        chain.insert(0, parent)

    while True:
        child = _find_child_pr(chain[-1], open_prs)
        if child is None:
            break
        if child["number"] in {p["number"] for p in chain}:
            break
        chain.append(child)

    return chain


def render_comment(chain: list[dict[str, Any]], current_number: int) -> str:
    lines = [
        MARKER,
        "## Stack navigation (Jujutsu)",
        "",
        "This PR is part of a **stacked** change set. Merge **bottom → top**.",
        "",
        "| # | Branch | PR | Base | Status |",
        "|---|--------|-----|------|--------|",
    ]
    for idx, pr in enumerate(chain, start=1):
        marker = " **← this PR**" if pr["number"] == current_number else ""
        draft = " (draft)" if pr.get("isDraft") else ""
        lines.append(
            f"| {idx} | `{pr['headRefName']}` | [#{pr['number']}]({pr['url']}) | "
            f"`{pr['baseRefName']}` | {pr['state']}{draft}{marker} |"
        )

    bottom = chain[0]
    top = chain[-1]
    merge_hint = f"#{bottom['number']}" if len(chain) > 1 else f"#{current_number}"
    depth = (
        f"**Stack depth:** {len(chain)} PR(s) · bottom `{bottom['headRefName']}` "
        f"→ top `{top['headRefName']}`"
    )
    lines.extend(
        [
            "",
            f"**Merge order:** start at {merge_hint}, then work upward.",
            depth,
            "",
            "**Local (jj):** `scripts/jj-stack-status.sh` · "
            "submit: `scripts/jj-stack-submit.sh <top-bookmark>`",
            "",
            "_Updated automatically by "
            "[stack-comment workflow](.github/workflows/stack-comment.yml)._",
        ]
    )
    return "\n".join(lines)


def find_existing_comment_id(pr_number: int, repo: str) -> int | None:
    raw = _run_gh(["api", f"repos/{repo}/issues/{pr_number}/comments", "--paginate"])
    for comment in json.loads(raw):
        if MARKER in comment.get("body", ""):
            return int(comment["id"])
    return None


def upsert_comment(pr_number: int, body: str, repo: str) -> None:
    comment_id = find_existing_comment_id(pr_number, repo)
    if comment_id is None:
        _run_gh(["pr", "comment", str(pr_number), "--body", body])
        return
    _run_gh(
        [
            "api",
            "--method",
            "PATCH",
            f"repos/{repo}/issues/comments/{comment_id}",
            "-f",
            f"body={body}",
        ]
    )


def main() -> int:
    pr_number = int(os.environ.get("PR_NUMBER", "0"))
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not pr_number or not repo:
        print("PR_NUMBER and GITHUB_REPOSITORY are required", file=sys.stderr)
        return 1

    current = get_pr(pr_number)
    open_prs = list_open_prs()
    chain = build_stack_chain(current, open_prs)

    if len(chain) == 1 and current["baseRefName"] in TRUNK_BRANCHES:
        body = "\n".join(
            [
                MARKER,
                "## Stack navigation (Jujutsu)",
                "",
                "Standalone PR (base is trunk — not stacked on another open PR).",
                "",
                "| Branch | PR | Base |",
                "|--------|-----|------|",
                (
                    f"| `{current['headRefName']}` | [#{current['number']}]({current['url']}) "
                    f"| `{current['baseRefName']}` |"
                ),
                "",
                "**Local (jj):** `scripts/jj-stack-status.sh`",
            ]
        )
    else:
        body = render_comment(chain, pr_number)

    upsert_comment(pr_number, body, repo)
    print(f"Stack comment updated on PR #{pr_number} ({len(chain)} in chain)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
