"""The matrices of ci.yml, as the contract tests read them.

A job whose cells differ between a pull request and the full set names its
`include` as one expression: the full set's cells, else the pull request's.

    include: ${{ fromJSON((<full set>) && '[...]' || '[...]') }}

``cells`` returns the cells of either scope; a static matrix is the same in
both.
"""

from __future__ import annotations

import json
import re
from typing import Any

# The condition under which a job runs in the full set (test_ci_scope.FULL_SET).
FULL_SET = (
    "github.event_name != 'pull_request' || "
    "contains(github.event.pull_request.labels.*.name, 'full-ci')"
)
DYNAMIC = re.compile(
    r"\$\{\{\s*fromJSON\(\((?P<condition>.+)\)"
    r" && '(?P<full>\[.*\])' \|\| '(?P<pull>\[.*\])'\)\s*\}\}",
    re.DOTALL,
)


def dynamic_include(include: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The (full set, pull request) cells of a scope-dependent `include`."""
    match = DYNAMIC.fullmatch(include.strip())
    assert match, f"not a scope-dependent include: {include}"
    assert match.group("condition") == FULL_SET, match.group("condition")
    return json.loads(match.group("full")), json.loads(match.group("pull"))


def cells(job: dict[str, Any], scope: str = "full") -> list[dict[str, str]]:
    """The job's matrix cells in *scope* (``full`` or ``pull``): the product of
    its axes, or its `include` entries when it has no axes; one empty cell
    without a matrix."""
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    if isinstance(matrix, str):
        return [{}]
    include = matrix.get("include")
    if isinstance(include, str):
        full, pull = dynamic_include(include)
        include = full if scope == "full" else pull
    axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
    found: list[dict[str, str]] = [{}]
    for name, values in axes.items():
        found = [{**cell, name: str(value)} for cell in found for value in values]
    if not axes and include:
        found = [{str(k): str(v) for k, v in entry.items()} for entry in include]
    return found


def selection(packages: str) -> tuple[list[str], list[str]]:
    """An engine-test cell's `packages`: the packages its `-p` name, and the
    `--features` it enables (`pkg/feature`)."""
    words = packages.split()
    names: list[str] = []
    features: list[str] = []
    at = 0
    while at < len(words):
        flag, value = words[at], words[at + 1] if at + 1 < len(words) else ""
        assert flag in ("-p", "--features") and value, packages
        if flag == "-p":
            names.append(value)
        else:
            features.extend(value.split(","))
        at += 2
    return names, features
