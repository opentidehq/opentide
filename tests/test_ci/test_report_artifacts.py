"""Generated pipelines keep the findings reports and job summaries opentide writes (#621)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from opentide.ci.azure import SARIF_ARTIFACT, render_azure
from opentide.ci.github import CODE_SCANNING_IF, render_github
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


def test_github_validate_job_writes_sarif_and_keeps_it() -> None:
    validate = _github()["validate"]
    # The validate job holds the platform secrets, so it gets no write scope.
    assert "permissions" not in validate
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
    assert not any("upload-sarif" in str(step.get("uses")) for step in validate["steps"])


def test_github_code_scanning_job_uploads_the_sarif() -> None:
    job = _github()["code_scanning"]
    assert job["needs"] == "validate"
    assert job["if"] == CODE_SCANNING_IF
    assert "!cancelled()" in job["if"]
    assert "!github.event.repository.private" in job["if"]
    assert job["permissions"] == {"security-events": "write"}
    assert "env" not in job
    download = _step(job["steps"], "Download opentide reports")
    assert download["uses"] == "actions/download-artifact@v4"
    assert download["with"] == {"name": "opentide-reports", "path": "opentide-reports/"}
    for command in ("validate", "lint"):
        upload = _step(job["steps"], f"Upload {command} findings to code scanning")
        sarif = report_path(command, "sarif")
        assert upload["uses"] == "github/codeql-action/upload-sarif@v4"
        assert upload["continue-on-error"] is True
        # The category comes from the run's automationDetails.id (opentide/<command>/).
        assert upload["with"] == {"sarif_file": sarif}
        assert upload["if"] == f"${{{{ hashFiles('{sarif}') != '' }}}}"


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
    # One file: GitLab Runner 18.9 failed the job on two ("only one file can
    # be sent as raw"), after both commands had passed.
    assert validate["artifacts"] == {
        "when": "always",
        "expose_as": "opentide reports",
        "paths": ["opentide-reports/"],
        "reports": {"codequality": "opentide-reports/codequality.json"},
    }
    # Merged in after_script, which also runs when a gate command failed.
    assert validate["after_script"] == [
        "python -m opentide.ci.codequality --output opentide-reports/codequality.json"
        " opentide-reports/validate.codequality.json opentide-reports/lint.codequality.json"
    ]


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


def test_every_document_job_keeps_the_pages_it_renders() -> None:
    """The document job rendered the docs (minutes per default-branch run) and dropped them."""
    gitlab = _gitlab()["document"]
    assert gitlab["script"] == ["opentide generate docs --output docs"]
    assert gitlab["artifacts"] == {"name": "opentide-docs", "paths": ["docs/"]}

    github = _github()["document"]["steps"]
    runs = [step.get("run") for step in github]
    upload = _step(github, "Upload documentation")
    assert runs.index("opentide generate docs --output docs") < github.index(upload)
    assert upload["uses"] == "actions/upload-artifact@v4"
    assert upload["with"] == {"name": "opentide-docs", "path": "docs/"}

    parsed = yaml.safe_load(render_azure(CiRenderOptions(ci="azure", platforms=["sentinel"])))
    document = next(stage for stage in parsed["stages"] if stage["stage"] == "Document")
    steps = document["jobs"][0]["steps"]
    assert "opentide generate docs --output docs" in steps[-2]["script"]
    assert steps[-1] == {
        "task": "PublishBuildArtifacts@1",
        "displayName": "Publish documentation",
        "inputs": {
            "PathtoPublish": "$(Build.SourcesDirectory)/docs",
            "ArtifactName": "opentide-docs",
        },
    }


@pytest.mark.parametrize("ci", ["github", "gitlab", "azure"])
def test_no_docs_artifact_without_docs(ci: str) -> None:
    from opentide.ci.render import render_ci

    options = CiRenderOptions(ci=ci, platforms=["sentinel"], docs_enabled=False)
    assert "opentide-docs" not in next(iter(render_ci(options).values()))


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


def test_setup_ignores_the_reports_folder(tmp_path: Path) -> None:
    from opentide.cli.services.setup.repo import _write_gitignore

    _write_gitignore(tmp_path)
    lines = (tmp_path / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert f"{REPORTS_DIR}/" in lines
