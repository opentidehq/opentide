"""Which jobs GitLab adds to a generated pipeline, and whether it can start.

A small evaluator of the ``rules:`` the generator writes: ``&&``-joined
``==``, ``!=``, ``=~`` and ``!~`` comparisons, the first matching rule decides,
``when: never`` leaves the job out, and a rule with no ``if`` always matches.
GitLab compares an unset variable as null, and a regex never matches it.
"""

from __future__ import annotations

import re
from typing import Any

#: Top-level keys that are not jobs.
GLOBAL_KEYS = frozenset({"workflow", "variables", "stages", "default", "include"})

_OPERATOR = re.compile(r"\s(==|!=|=~|!~)\s")


def _operand(token: str, variables: dict[str, str]) -> str | None:
    token = token.strip()
    if token.startswith("$"):
        return variables.get(token[1:])
    return token.strip('"')


def _clause(clause: str, variables: dict[str, str]) -> bool:
    found = _OPERATOR.search(clause)
    if found is None:
        # A bare ``$VAR``: true when it is set and not empty.
        return bool(_operand(clause, variables))
    operator = found.group(1)
    left = _operand(clause[: found.start()], variables)
    right_text = clause[found.end() :].strip()
    if operator in ("=~", "!~"):
        assert right_text.startswith("/") and right_text.endswith("/"), right_text
        matched = left is not None and re.search(right_text[1:-1], left) is not None
        return matched if operator == "=~" else not matched
    equal = left == _operand(right_text, variables)
    return equal if operator == "==" else not equal


def matches(expression: str, variables: dict[str, str]) -> bool:
    """Evaluate an ``&&``-joined rule expression (the generator writes no ``||``)."""
    assert "||" not in expression, expression
    return all(_clause(clause, variables) for clause in expression.split("&&"))


def rule_outcome(rules: list[dict[str, Any]], variables: dict[str, str]) -> str | None:
    """The ``when`` of the first rule that matches, or ``None`` when none does."""
    for rule in rules:
        condition = rule.get("if")
        if condition is None or matches(condition, variables):
            return str(rule.get("when", "on_success"))
    return None


def pipeline_jobs(parsed: dict[str, Any], variables: dict[str, str]) -> set[str] | None:
    """The jobs GitLab adds for *variables*, or ``None`` when no pipeline is created.

    A job without ``rules`` is added to every pipeline ``workflow:rules``
    allows (GitLab drops its ``except: merge_requests`` default then).
    """
    workflow = parsed.get("workflow")
    if isinstance(workflow, dict) and rule_outcome(workflow["rules"], variables) in (
        None,
        "never",
    ):
        return None
    merge_request = variables.get("CI_PIPELINE_SOURCE") == "merge_request_event"
    jobs: set[str] = set()
    for name, job in parsed.items():
        if name in GLOBAL_KEYS or not isinstance(job, dict):
            continue
        rules = job.get("rules")
        if rules:
            if rule_outcome(rules, variables) not in (None, "never"):
                jobs.add(name)
        elif workflow is not None or not merge_request:
            jobs.add(name)
    return jobs


def needs_of(job: dict[str, Any]) -> list[tuple[str, bool]]:
    """``(job, optional)`` for each entry of a job's ``needs``."""
    out: list[tuple[str, bool]] = []
    for need in job.get("needs") or []:
        if isinstance(need, str):
            out.append((need, False))
        else:
            out.append((need["job"], bool(need.get("optional"))))
    return out


def unmet_needs(parsed: dict[str, Any], jobs: set[str]) -> dict[str, list[str]]:
    """Per added job, the non-optional needs that were not added: GitLab refuses those."""
    unmet: dict[str, list[str]] = {}
    for name in sorted(jobs):
        missing = [need for need, optional in needs_of(parsed[name]) if not optional]
        missing = [need for need in missing if need not in jobs]
        if missing:
            unmet[name] = missing
    return unmet


#: The pipelines a project sees. ``CI_COMMIT_BRANCH`` is unset in merge request
#: pipelines, and GitLab compares an unset variable as null.
PIPELINES: dict[str, dict[str, str]] = {
    "merge request into the default branch": {
        "CI_PIPELINE_SOURCE": "merge_request_event",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main",
        "CI_DEFAULT_BRANCH": "main",
        "CI_COMMIT_MESSAGE": "feat: add a rule",
        "CI_MERGE_REQUEST_TITLE": "Add a rule",
        "CI_MERGE_REQUEST_LABELS": "detection,review",
    },
    "merge request into another branch": {
        "CI_PIPELINE_SOURCE": "merge_request_event",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "release",
        "CI_DEFAULT_BRANCH": "main",
        "CI_COMMIT_MESSAGE": "feat: add a rule",
        "CI_MERGE_REQUEST_TITLE": "Add a rule",
    },
    "push to the default branch": {
        "CI_PIPELINE_SOURCE": "push",
        "CI_COMMIT_BRANCH": "main",
        "CI_DEFAULT_BRANCH": "main",
        "CI_COMMIT_MESSAGE": "Merge branch 'rule' into 'main'\n\nAdd a rule",
    },
    "push to a feature branch": {
        "CI_PIPELINE_SOURCE": "push",
        "CI_COMMIT_BRANCH": "feature",
        "CI_DEFAULT_BRANCH": "main",
        "CI_COMMIT_MESSAGE": "wip",
    },
}
