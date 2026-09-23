"""GitHub Actions expression contexts that make a workflow file unparseable.

GitHub rejects the whole workflow when ``secrets`` appears in a job-level or
step-level ``if``. Nothing reports that on the pull request: every push records
a 0-second failed run and the file's ``schedule``/``workflow_dispatch``/
``release`` triggers never register. ``publish-pypi.yml`` documents the same
trap; ``vocab-upstream.yml`` fell into it and never ran its weekly ingest (#287).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from opentide.ci.github import render_github
from opentide.ci.models import CiRenderOptions

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))

_SECRETS = re.compile(r"\bsecrets\s*(?:\.|\[)")


def _secrets_in_conditions(workflow: dict[str, Any]) -> list[str]:
    offenders: list[str] = []
    for job_id, job in (workflow.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        condition = job.get("if")
        if isinstance(condition, str) and _SECRETS.search(condition):
            offenders.append(f"jobs.{job_id}.if: {condition}")
        for index, step in enumerate(job.get("steps") or []):
            condition = step.get("if") if isinstance(step, dict) else None
            if isinstance(condition, str) and _SECRETS.search(condition):
                label = step.get("name") or step.get("id") or index
                offenders.append(f"jobs.{job_id}.steps[{label}].if: {condition}")
    return offenders


def test_repository_has_workflows() -> None:
    assert WORKFLOWS, "no workflow files found; the guard below would pass vacuously"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_repository_workflow_conditions_do_not_read_secrets(path: Path) -> None:
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert _secrets_in_conditions(workflow) == [], (
        f"{path.name}: promote the secret to job-level env "
        "(HAS_X: ${{ secrets.X != '' }}) and test env.HAS_X in the if"
    )


def test_generated_github_workflow_conditions_do_not_read_secrets() -> None:
    options = CiRenderOptions(
        ci="github",
        platforms=["sentinel", "defender", "splunk", "crowdstrike"],
        staging=True,
        promotion=True,
        explorer_pages=True,
        inflight=True,
        docs_enabled=True,
    )
    workflow = yaml.safe_load(render_github(options))
    assert _secrets_in_conditions(workflow) == []


@pytest.mark.parametrize(
    "condition",
    [
        "${{ secrets.TOKEN != '' }}",
        "secrets.TOKEN != ''",
        "${{ secrets['TOKEN'] }}",
        "github.event_name == 'push' && secrets.A != ''",
    ],
)
def test_detects_secrets_in_step_and_job_conditions(condition: str) -> None:
    workflow = {
        "jobs": {
            "build": {
                "if": condition,
                "steps": [{"name": "token", "if": condition, "run": "true"}],
            }
        }
    }
    assert _secrets_in_conditions(workflow) == [
        f"jobs.build.if: {condition}",
        f"jobs.build.steps[token].if: {condition}",
    ]


def test_allows_env_promoted_secret_presence() -> None:
    workflow = {
        "jobs": {
            "build": {
                "env": {"HAS_APP": "${{ secrets.GH_APP_ID != '' }}"},
                "steps": [
                    {
                        "if": "env.HAS_APP == 'true'",
                        "with": {"token": "${{ secrets.GH_APP_ID }}"},
                    }
                ],
            }
        }
    }
    assert _secrets_in_conditions(workflow) == []
