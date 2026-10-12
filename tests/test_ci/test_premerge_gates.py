"""Every generated job that writes outside its pipeline must be branch-gated.

The invariant these tests protect: a job that deploys to a tenant, pushes to
the default branch, or shares objects must never be gated on the *event* alone.
``$CI_PIPELINE_SOURCE == "merge_request_event"`` and
``github.event_name == 'pull_request'`` are true for a pull request between two
feature branches, so an event-only gate let such a review deploy to a live
staging tenant and land a commit on the default branch.

Rather than asserting fixed condition strings, these tests *discover* the
writing jobs from the rendered pipeline and require each one's gate to mention
a branch variable. A new writing job added later with an event-only gate fails
here without anyone remembering to update a list.
"""

from __future__ import annotations

import re

import pytest
import yaml

from opentide.ci.azure import render_azure
from opentide.ci.gates import (
    azure_premerge_condition,
    github_premerge_if,
    gitlab_premerge_rule,
)
from opentide.ci.github import render_github
from opentide.ci.gitlab import render_gitlab
from opentide.ci.models import CiRenderOptions

#: Branch-aware variables. A gate naming one of these constrains *where* the
#: change is headed; an event variable alone does not.
BRANCH_TERMS = (
    # GitLab
    "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
    "CI_COMMIT_BRANCH",
    # GitHub Actions
    "github.base_ref",
    "github.ref",
    # Azure Pipelines
    "System.PullRequest.TargetBranch",
    "Build.SourceBranch",
)


def _options(ci: str) -> CiRenderOptions:
    return CiRenderOptions(
        ci=ci,
        platforms=["sentinel", "splunk"],
        staging=True,
        inflight=True,
        sharing=True,
        default_branch="main",
    )


def _writes_externally(commands: list[str]) -> bool:
    """Whether any command deploys, shares, or pushes to the default branch."""
    for raw in commands:
        command = str(raw)
        for line in command.splitlines():
            if re.search(r"\bopentide deploy\b", line) and "--dry-run" not in line:
                return True
            if re.search(r"\bopentide share push\b", line):
                return True
            if re.search(r"\bgit push\b", line):
                return True
    return False


def _is_branch_gated(gate: str | None) -> bool:
    return bool(gate) and any(term in str(gate) for term in BRANCH_TERMS)


# --- GitLab ---------------------------------------------------------------


def _gitlab_writing_jobs() -> dict[str, str | None]:
    parsed = yaml.safe_load(render_gitlab(_options("gitlab")))
    found: dict[str, str | None] = {}
    for name, body in parsed.items():
        if not isinstance(body, dict) or "script" not in body:
            continue
        if not _writes_externally(list(body.get("script") or [])):
            continue
        rules = body.get("rules") or []
        conditions = [
            str(rule.get("if")) for rule in rules if isinstance(rule, dict) and rule.get("if")
        ]
        found[name] = " ".join(conditions) if conditions else None
    return found


def test_gitlab_writing_jobs_are_branch_gated() -> None:
    jobs = _gitlab_writing_jobs()
    assert jobs, "no writing jobs discovered — the detector or the renderer changed"
    ungated = {name: gate for name, gate in jobs.items() if not _is_branch_gated(gate)}
    assert not ungated, f"GitLab jobs write externally without a branch gate: {ungated}"


def test_gitlab_premerge_rule_requires_the_default_branch_as_target() -> None:
    rule = gitlab_premerge_rule()
    assert "merge_request_event" in rule
    assert "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME == $CI_DEFAULT_BRANCH" in rule


def test_gitlab_staging_and_inflight_use_the_shared_premerge_rule() -> None:
    parsed = yaml.safe_load(render_gitlab(_options("gitlab")))
    expected = gitlab_premerge_rule()
    for job in ("deploy_staging", "inflight_shards"):
        rules = parsed[job]["rules"]
        assert any(rule.get("if") == expected for rule in rules), (
            f"{job} does not carry the shared pre-merge rule: {rules}"
        )


# --- GitHub ---------------------------------------------------------------


def _github_writing_jobs() -> dict[str, str | None]:
    parsed = yaml.safe_load(render_github(_options("github")))
    found: dict[str, str | None] = {}
    for name, body in parsed.get("jobs", {}).items():
        commands = [step["run"] for step in body.get("steps", []) or [] if step.get("run")]
        if not _writes_externally(commands):
            continue
        found[name] = body.get("if")
    return found


def test_github_writing_jobs_are_branch_gated() -> None:
    jobs = _github_writing_jobs()
    assert jobs, "no writing jobs discovered — the detector or the renderer changed"
    ungated = {name: gate for name, gate in jobs.items() if not _is_branch_gated(gate)}
    assert not ungated, f"GitHub jobs write externally without a branch gate: {ungated}"


def test_github_premerge_if_pins_the_base_ref() -> None:
    gate = github_premerge_if("development")
    assert gate == ("github.event_name == 'pull_request' && github.base_ref == 'development'")


def test_github_staging_and_inflight_use_the_shared_premerge_if() -> None:
    parsed = yaml.safe_load(render_github(_options("github")))
    expected = github_premerge_if("main")
    for job in ("deploy_staging", "inflight_shards"):
        assert parsed["jobs"][job]["if"] == expected


# --- Azure ----------------------------------------------------------------


def _azure_writing_jobs() -> dict[str, str | None]:
    parsed = yaml.safe_load(render_azure(_options("azure")))
    found: dict[str, str | None] = {}
    for stage in parsed.get("stages", []) or []:
        stage_condition = stage.get("condition")
        for job in stage.get("jobs", []) or []:
            commands: list[str] = []
            for step in job.get("steps", []) or []:
                script = step.get("script") or step.get("bash")
                if script:
                    commands.append(str(script))
            if not _writes_externally(commands):
                continue
            # A job inherits its stage's condition, so either may carry the gate.
            gate = " ".join(str(part) for part in (stage_condition, job.get("condition")) if part)
            found[job.get("job")] = gate or None
    return found


def test_azure_writing_jobs_are_branch_gated() -> None:
    jobs = _azure_writing_jobs()
    assert jobs, "no writing jobs discovered — the detector or the renderer changed"
    ungated = {name: gate for name, gate in jobs.items() if not _is_branch_gated(gate)}
    assert not ungated, f"Azure jobs write externally without a branch gate: {ungated}"


def test_azure_premerge_condition_pins_the_target_branch() -> None:
    condition = azure_premerge_condition("main")
    assert "eq(variables['Build.Reason'], 'PullRequest')" in condition
    assert "eq(variables['System.PullRequest.TargetBranch'], 'refs/heads/main')" in condition


def test_azure_staging_and_inflight_use_the_shared_premerge_condition() -> None:
    parsed = yaml.safe_load(render_azure(_options("azure")))
    expected = azure_premerge_condition("main")
    seen = {}
    for stage in parsed.get("stages", []) or []:
        for job in stage.get("jobs", []) or []:
            seen[job.get("job")] = job.get("condition")
    for job in ("deploy_staging", "inflight_shards"):
        assert seen[job] == expected, f"{job} condition is {seen[job]!r}"


# --- The regression itself -------------------------------------------------


@pytest.mark.parametrize(
    ("renderer", "ci", "event_only"),
    [
        (render_gitlab, "gitlab", '$CI_PIPELINE_SOURCE == "merge_request_event"'),
        (render_github, "github", "github.event_name == 'pull_request'"),
        (render_azure, "azure", "eq(variables['Build.Reason'], 'PullRequest')"),
    ],
)
def test_no_writing_job_carries_an_event_only_gate(renderer, ci: str, event_only: str) -> None:
    """The exact shape of the original defect, per provider.

    An event-only expression must never appear as a complete gate. It may still
    appear as one *term* of a gate that also pins the branch, which is why this
    compares whole conditions rather than searching the document.
    """
    rendered = renderer(_options(ci))
    parsed = yaml.safe_load(rendered)

    gates: list[str] = []
    if ci == "gitlab":
        for body in parsed.values():
            if isinstance(body, dict):
                for rule in body.get("rules") or []:
                    if isinstance(rule, dict) and rule.get("if"):
                        gates.append(str(rule["if"]))
    elif ci == "github":
        for body in parsed.get("jobs", {}).values():
            if body.get("if"):
                gates.append(str(body["if"]))
    else:
        for stage in parsed.get("stages", []) or []:
            if stage.get("condition"):
                gates.append(str(stage["condition"]))
            for job in stage.get("jobs", []) or []:
                if job.get("condition"):
                    gates.append(str(job["condition"]))

    assert event_only not in gates, (
        f"{ci}: a job is gated on the event alone, so a pull request between two "
        f"feature branches would run it"
    )
