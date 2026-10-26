"""CLI E2E: CI annotations, job summaries and report files on the tutorial workspace (#621).

The tutorial rule gets a vocabulary typo. Under a simulated GitHub Actions,
GitLab CI or Azure Pipelines job, ``validate`` and ``lint`` print annotations
and write the job summary; ``--format`` writes the SARIF or Code Quality
report. Output is read with ANSI stripped, since CI forces colour.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.corpus_support import clear_runtime_caches
from tests.test_cli.e2e.helpers import write_tutorial_objects
from typer.testing import CliRunner, Result

from opentide.cli import app
from opentide.cli.enums import DetectionPlatform
from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup

pytestmark = pytest.mark.cli_e2e

_LEAKY_ENV = (
    "OPENTIDE_REPO_ROOT",
    "OPENTIDE_TIDE_WORKSPACE",
    "OPENTIDE_OUTPUT",
    "DEPLOYMENT_PLAN",
    "CI",
    "GITHUB_ACTIONS",
    "GITHUB_STEP_SUMMARY",
    "GITHUB_WORKSPACE",
    "GITLAB_CI",
    "CI_PROJECT_DIR",
    "TF_BUILD",
    "AGENT_TEMPDIRECTORY",
    "NO_COLOR",
    "FORCE_COLOR",
    "AI_AGENT",
    "CLAUDECODE",
)
_RULE_FILE = "objects/rules/sentinel-kql-rule.yaml"
_SCHEMA = Path(__file__).resolve().parents[2] / "fixtures" / "sarif" / "sarif-schema-2.1.0.json"
_ANSI = re.compile(r"\x1b\[[0-9;]*m|\x1b\]8;[^\x1b]*\x1b\\")
_ANNOTATION = (
    f"::error file={_RULE_FILE},line=8,endLine=8,col=8,endColumn=13,title=vocab_unknown::"
    "'clearr' is not a TLP value%0Ahelp: did you mean 'clear'?"
)


@pytest.fixture(scope="module")
def _pristine(tmp_path_factory: pytest.TempPathFactory) -> Path:
    repo = tmp_path_factory.mktemp("ci-sinks") / "tutorial"
    run_repo_setup(
        RepoSetupOptions(
            path=repo,
            name="Tutorial Detections",
            org="Example Corp",
            platforms=[DetectionPlatform.sentinel],
            yes=True,
        )
    )
    write_tutorial_objects(repo)
    path = repo / _RULE_FILE
    text = path.read_text(encoding="utf-8")
    assert "  tlp: clear\n" in text
    path.write_text(text.replace("  tlp: clear\n", "  tlp: clearr\n", 1), encoding="utf-8")
    return repo


@pytest.fixture
def tutorial(_pristine: Path, tmp_path: Path) -> Iterator[Path]:
    repo = tmp_path / "tutorial"
    shutil.copytree(_pristine, repo)
    yield repo
    clear_runtime_caches()


def _env(repo: Path, **extra: str) -> dict[str, str | None]:
    return (
        dict.fromkeys(_LEAKY_ENV)
        | {"OPENTIDE_REPO_ROOT": str(repo), "OPENTIDE_TIDE_WORKSPACE": str(repo)}
        | extra
    )


def _run(repo: Path, *argv: str, **env: str) -> Result:
    clear_runtime_caches()
    return CliRunner().invoke(app, ["--repo", str(repo), *argv], env=_env(repo, **env))


def _lines(result: Result) -> list[str]:
    return _ANSI.sub("", result.stdout).splitlines()


def test_github_actions_gets_annotations_a_summary_and_sarif(
    tutorial: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A relative --output is read from the current directory, the checkout in CI.
    monkeypatch.chdir(tutorial)
    step_summary = tutorial / "step-summary.md"
    github = {
        "GITHUB_ACTIONS": "true",
        "CI": "true",
        "GITHUB_WORKSPACE": str(tutorial),
        "GITHUB_STEP_SUMMARY": str(step_summary),
    }
    result = _run(
        tutorial,
        "validate",
        "--strict",
        "--format",
        "sarif",
        "--output",
        "opentide-reports/validate.sarif",
        **github,
    )
    assert result.exit_code == 1, result.output
    assert _ANNOTATION in _lines(result)
    assert "error[vocab_unknown]" in result.stdout

    summary = step_summary.read_text(encoding="utf-8")
    assert summary.startswith("### ✗ opentide validate\n\n1 error in 1 file · 3 objects checked")
    assert f"| `{_RULE_FILE}:8:8` |" in summary

    jsonschema = pytest.importorskip("jsonschema")
    sarif = json.loads((tutorial / "opentide-reports" / "validate.sarif").read_text("utf-8"))
    jsonschema.Draft4Validator(json.loads(_SCHEMA.read_text("utf-8"))).validate(sarif)
    (finding,) = sarif["runs"][0]["results"]
    assert finding["ruleId"] == "vocab_unknown"
    assert finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == _RULE_FILE
    assert finding["fixes"][0]["artifactChanges"][0]["replacements"][0]["insertedContent"] == {
        "text": "clear"
    }

    clean = _run(tutorial, "lint", **github)
    assert clean.exit_code == 0, clean.output
    assert not any(line.startswith("::") for line in _lines(clean))
    assert "### ✓ opentide lint\n\n3 files clean\n" in step_summary.read_text("utf-8")


def test_json_mode_writes_no_sink_even_in_ci(tutorial: Path) -> None:
    step_summary = tutorial / "step-summary.md"
    result = _run(
        tutorial,
        "--json",
        "validate",
        GITHUB_ACTIONS="true",
        GITHUB_STEP_SUMMARY=str(step_summary),
    )
    assert result.exit_code == 1, result.output
    assert json.loads(result.stdout)["status"] == "failed"
    assert not step_summary.exists()


def test_gitlab_gets_a_code_quality_report_and_a_summary_file(tutorial: Path) -> None:
    gitlab = {"GITLAB_CI": "true", "CI": "true", "CI_PROJECT_DIR": str(tutorial)}
    report = tutorial / "opentide-reports" / "validate.codequality.json"
    result = _run(
        tutorial, "validate", "--format", "codequality", "--output", str(report), **gitlab
    )
    assert result.exit_code == 1, result.output
    assert not any(line.startswith("::") for line in _lines(result))
    (issue,) = json.loads(report.read_text("utf-8"))
    assert issue["check_name"] == "vocab_unknown"
    assert issue["location"] == {"path": _RULE_FILE, "lines": {"begin": 8}}
    summary = (tutorial / "opentide-reports" / "summary.md").read_text("utf-8")
    assert summary.startswith("### ✗ opentide validate\n")


def test_azure_gets_logissue_and_an_uploaded_summary(tutorial: Path) -> None:
    agent = tutorial / "agent-temp"
    result = _run(tutorial, "validate", TF_BUILD="True", AGENT_TEMPDIRECTORY=str(agent))
    assert result.exit_code == 1, result.output
    lines = _lines(result)
    assert (
        f"##vso[task.logissue type=error;sourcepath={_RULE_FILE};linenumber=8;columnnumber=8;"
        "code=vocab_unknown;]'clearr' is not a TLP value"
        "%0Ahelp: did you mean 'clear'?"
    ) in lines
    assert f"##vso[task.uploadsummary]{agent / 'opentide-validate.md'}" in lines


def test_the_console_script_never_wraps_an_annotation(tutorial: Path) -> None:
    """A real process on a narrow terminal: the workflow command stays on one line."""
    executable = Path(sys.executable).with_name("opentide")
    env = {key: value for key, value in os.environ.items() if key not in _LEAKY_ENV}
    env |= {
        "PATH": f"{executable.parent}{os.pathsep}{env.get('PATH', '')}",
        "GITHUB_ACTIONS": "true",
        "GITHUB_WORKSPACE": str(tutorial),
        "COLUMNS": "40",
    }
    done = subprocess.run(
        [str(executable), "--repo", str(tutorial), "validate"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        check=False,
    )
    assert done.returncode == 1, done.stdout + done.stderr
    assert _ANNOTATION in _ANSI.sub("", done.stdout).splitlines()
