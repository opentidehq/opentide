"""Generated pipelines keep the findings reports and job summaries opentide writes (#621)."""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from opentide.ci.azure import SARIF_ARTIFACT, render_azure
from opentide.ci.github import VALIDATE_PERMISSIONS, render_github
from opentide.ci.gitlab import render_gitlab
from opentide.ci.models import CiRenderOptions
from opentide.ci.stages import object_validate_commands, report_path
from opentide.cli.ui.ci import GITLAB_SUMMARY, REPORTS_DIR


def test_gate_commands_write_a_report_only_when_asked() -> None:
    assert object_validate_commands() == ["opentide validate --strict", "opentide lint --strict"]
    assert object_validate_commands("sarif") == [
        "opentide validate --strict --format sarif --output opentide-reports/validate.sarif",
        "opentide lint --strict --format sarif --output opentide-reports/lint.sarif",
    ]
    assert report_path("lint", "codequality") == "opentide-reports/lint.codequality.json"
    assert GITLAB_SUMMARY.startswith(f"{REPORTS_DIR}/")


def _github(**options: Any) -> dict[str, Any]:
    text = render_github(CiRenderOptions(ci="github", platforms=["sentinel"], **options))
    return yaml.safe_load(text)["jobs"]


def _step(steps: list[dict[str, Any]], name: str) -> dict[str, Any]:
    return next(step for step in steps if step.get("name") == name)


def test_github_validate_job_writes_and_uploads_sarif() -> None:
    validate = _github()["validate"]
    assert validate["permissions"] == yaml.safe_load(VALIDATE_PERMISSIONS)
    assert validate["permissions"]["security-events"] == "write"
    runs = [step["run"] for step in validate["steps"] if "run" in step]
    assert object_validate_commands("sarif")[0] in runs
    assert object_validate_commands("sarif")[1] in runs
    artifact = _step(validate["steps"], "Upload opentide reports")
    assert artifact["if"] == "${{ !cancelled() }}"
    assert artifact["uses"] == "actions/upload-artifact@v4"
    assert artifact["with"] == {
        "name": "opentide-reports",
        "path": "opentide-reports/",
        "if-no-files-found": "ignore",
    }
    for command in ("validate", "lint"):
        upload = _step(validate["steps"], f"Upload {command} findings to code scanning")
        sarif = report_path(command, "sarif")
        assert upload["uses"] == "github/codeql-action/upload-sarif@v3"
        assert upload["continue-on-error"] is True
        assert upload["with"] == {"sarif_file": sarif, "category": f"opentide-{command}"}
        assert upload["if"] == (
            "${{ !cancelled() && !github.event.repository.private && "
            f"hashFiles('{sarif}') != '' }}}}"
        )


def test_github_uploads_come_after_every_check() -> None:
    names = [
        step.get("name") or step.get("run") or step.get("uses")
        for step in _github()["validate"]["steps"]
    ]
    assert names.index("Validate queries on reviewed tenants") < names.index(
        "Upload opentide reports"
    )


def test_github_other_jobs_keep_their_permissions() -> None:
    jobs = _github()
    assert "permissions" not in jobs["generate"]
    assert jobs["deploy_production"]["permissions"] == {"contents": "write"}


def _gitlab(**options: Any) -> dict[str, Any]:
    text = render_gitlab(CiRenderOptions(ci="gitlab", platforms=["sentinel", "splunk"], **options))
    return yaml.safe_load(text)


def test_gitlab_validate_job_keeps_code_quality_reports() -> None:
    validate = _gitlab()["validate"]
    assert validate["script"] == object_validate_commands("codequality")
    assert validate["artifacts"] == {
        "when": "always",
        "expose_as": "opentide reports",
        "paths": ["opentide-reports/"],
        "reports": {
            "codequality": [
                "opentide-reports/validate.codequality.json",
                "opentide-reports/lint.codequality.json",
            ]
        },
    }


@pytest.mark.parametrize(
    ("job", "expose_as"),
    [
        ("validate_query_sentinel", "opentide query sentinel"),
        ("validate_query_splunk", "opentide query splunk"),
        ("deploy_staging", "opentide staging plan"),
        ("deploy_production", None),
    ],
)
def test_gitlab_jobs_keep_their_summary(job: str, expose_as: str | None) -> None:
    artifacts = _gitlab()[job]["artifacts"]
    assert artifacts["when"] == "always"
    assert artifacts["paths"] == [GITLAB_SUMMARY]
    assert artifacts.get("expose_as") == expose_as


def test_gitlab_jobs_without_opentide_output_keep_no_artifact() -> None:
    pipeline = _gitlab()
    assert "artifacts" not in pipeline["generate"]
    assert "artifacts" not in pipeline["document"]


def test_gitlab_expose_as_names_are_valid() -> None:
    """GitLab accepts letters, digits, spaces, ``-`` and ``_`` there."""
    pipeline = _gitlab()
    names = [
        job["artifacts"]["expose_as"]
        for job in pipeline.values()
        if isinstance(job, dict) and "expose_as" in job.get("artifacts", {})
    ]
    assert names
    assert all(name.replace(" ", "").replace("-", "").replace("_", "").isalnum() for name in names)


def test_azure_validate_job_publishes_sarif() -> None:
    parsed = yaml.safe_load(render_azure(CiRenderOptions(ci="azure", platforms=["sentinel"])))
    validate = parsed["stages"][0]["jobs"][0]
    assert validate["job"] == "validate"
    script = next(
        step["script"] for step in validate["steps"] if "set -e" in step.get("script", "")
    )
    assert script.splitlines() == [
        "set -e",
        f"mkdir -p {REPORTS_DIR}",
        *object_validate_commands("sarif"),
    ]
    publish = validate["steps"][-1]
    assert publish == {
        "task": "PublishBuildArtifacts@1",
        "displayName": "Publish opentide reports",
        "condition": "succeededOrFailed()",
        "inputs": {
            "PathtoPublish": f"$(Build.SourcesDirectory)/{REPORTS_DIR}",
            "ArtifactName": SARIF_ARTIFACT,
        },
    }
