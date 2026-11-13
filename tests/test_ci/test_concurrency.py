"""The workflows' concurrency: a push to a base branch is never cancelled.

GitHub runs one workflow run per concurrency group at a time: with
``cancel-in-progress: true`` a new run cancels the running one, and even
without it a newer queued run cancels an older *pending* one. A group of
``<workflow>-<event>-<ref>`` therefore cancelled every push to
``integration/unified-core`` when the next merge landed, and a busy day left
the branch with no complete run at all.

So every run that is not a pull request's gets a group of its own (its run
id), and only a pull request's runs share one, keyed on its ref, so that a new
push to it still cancels the stale run. The expressions are evaluated here for
each event, the way GitHub reads them.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
BASE_BRANCHES = ("development", "integration/unified-core")
# The workflows a push to a base branch runs that hold a concurrency group (the
# guard against this list going stale is below).
EXPECTED = {
    "bench.yml",
    "ci.yml",
    "codeql.yml",
    "coverage.yml",
    "docs.yml",
    "golden.yml",
    "publish-dry-run.yml",
    "schema.yml",
}

EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}")
NAME = re.compile(r"\b(?:github|matrix)\.[A-Za-z_.]+")


def _load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    # PyYAML reads the key `on` as True.
    return dict(workflow.get("on", workflow.get(True)) or {})


def _evaluate(expression: str, context: dict[str, str]) -> Any:
    """One `${{ }}` expression: names of `context`, string literals, `==`,
    `!=`, `&&` and `||`, which Python's operators read the same way (`&&` and
    `||` return an operand, and bind looser than the comparisons)."""
    unknown = {name for name in NAME.findall(expression) if name not in context}
    assert not unknown, f"the test does not know {unknown}"
    python = NAME.sub(lambda m: repr(context[m.group(0)]), expression)
    python = python.replace("&&", " and ").replace("||", " or ")
    # Only literals and operators are left: the workflow's own text.
    assert re.fullmatch(r"[\sA-Za-z0-9_'/=!.()-]*", python), python
    return eval(python, {"__builtins__": {}})


def _render(value: Any, context: dict[str, str]) -> Any:
    """A concurrency value as GitHub reads it: a lone expression keeps its
    type (`cancel-in-progress`), anything else is a string."""
    if not isinstance(value, str):
        return value
    lone = EXPRESSION.fullmatch(value.strip())
    if lone:
        return _evaluate(lone.group(1), context)
    return EXPRESSION.sub(lambda m: str(_evaluate(m.group(1), context)), value)


def _context(event: str, ref: str, run_id: str) -> dict[str, str]:
    return {
        "github.event_name": event,
        "github.ref": ref,
        "github.run_id": run_id,
        "github.workflow": "Workflow",
        # bench.yml's jobs: one group per engine of the matrix.
        "matrix.engine": "rust",
    }


def _groups(workflow: dict[str, Any]) -> list[dict[str, Any]]:
    """The workflow's concurrency, and every job's that sets its own."""
    found = [workflow["concurrency"]] if "concurrency" in workflow else []
    for job in (workflow.get("jobs") or {}).values():
        if "concurrency" in job:
            found.append(job["concurrency"])
    return [{"group": c} if isinstance(c, str) else c for c in found]


def _runs(concurrency: dict[str, Any], context: dict[str, str]) -> tuple[str, bool]:
    group = str(_render(concurrency["group"], context))
    cancel = _render(concurrency.get("cancel-in-progress", False), context)
    return group, bool(cancel)


def _workflows() -> list[str]:
    """The workflows a push to a base branch starts, with a group."""
    names = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        workflow = _load(path)
        triggers = _triggers(workflow)
        branches = (triggers.get("push") or {}).get("branches") or []
        if set(BASE_BRANCHES) & set(branches) and _groups(workflow):
            names.append(path.name)
    return names


def test_the_list_of_workflows_is_current() -> None:
    assert set(_workflows()) == EXPECTED


@pytest.mark.parametrize("name", sorted(EXPECTED))
@pytest.mark.parametrize("branch", BASE_BRANCHES)
def test_two_pushes_to_a_base_branch_never_share_a_group(name: str, branch: str) -> None:
    workflow = _load(WORKFLOWS / name)
    assert branch in _triggers(workflow)["push"]["branches"], name
    ref = f"refs/heads/{branch}"
    for concurrency in _groups(workflow):
        first, _ = _runs(concurrency, _context("push", ref, "1001"))
        second, _ = _runs(concurrency, _context("push", ref, "1002"))
        # One group would cancel the first push's run (or, pending, queue it to be cancelled).
        assert first != second, f"{name}: two pushes to {branch} share {first}"


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_a_new_push_to_a_pull_request_cancels_its_stale_run(name: str) -> None:
    workflow = _load(WORKFLOWS / name)
    if "pull_request" not in _triggers(workflow):
        pytest.skip(f"{name} has no pull_request trigger")
    ref = "refs/pull/42/merge"
    for concurrency in _groups(workflow):
        first, cancels = _runs(concurrency, _context("pull_request", ref, "1001"))
        second, _ = _runs(concurrency, _context("pull_request", ref, "1002"))
        assert first == second, f"{name}: a pull request's runs share a group"
        assert cancels, f"{name}: a pull request's new run cancels the stale one"
        other, _ = _runs(concurrency, _context("pull_request", "refs/pull/43/merge", "1003"))
        assert other != first, f"{name}: two pull requests never cancel each other"


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_no_other_run_shares_a_group_with_a_push(name: str) -> None:
    """The nightly run, Run workflow and a pull request never cancel a push's run."""
    workflow = _load(WORKFLOWS / name)
    ref = "refs/heads/development"
    for concurrency in _groups(workflow):
        push, _ = _runs(concurrency, _context("push", ref, "1001"))
        for event in ("schedule", "workflow_dispatch", "pull_request"):
            other, _ = _runs(concurrency, _context(event, ref, "1002"))
            assert other != push, (name, event)


def test_the_evaluator_reads_the_old_groups_as_github_did() -> None:
    """The group this file replaced put two pushes in one group."""
    old = {"group": "ci-${{ github.event_name }}-${{ github.ref }}", "cancel-in-progress": True}
    ref = "refs/heads/integration/unified-core"
    first = _runs(old, _context("push", ref, "1"))
    second = _runs(old, _context("push", ref, "2"))
    assert first == second == ("ci-push-refs/heads/integration/unified-core", True)


def test_the_evaluator_reads_and_or_as_github_does() -> None:
    expression = "github.event_name == 'pull_request' && github.ref || github.run_id"
    assert _evaluate(expression, _context("pull_request", "refs/pull/1/merge", "7")) == (
        "refs/pull/1/merge"
    )
    assert _evaluate(expression, _context("push", "refs/heads/development", "7")) == "7"
    assert _evaluate("github.event_name == 'pull_request'", _context("push", "x", "7")) is False
