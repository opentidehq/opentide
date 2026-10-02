"""``generate`` names a missing detection model instead of an empty JSON document (#352)."""

from __future__ import annotations

import json
import shutil
import textwrap
from pathlib import Path

from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup

runner = CliRunner()

# Click deletes a variable when its overlay value is None. On a pull request,
# GitHub Actions sets these, and `generate inflight` then fetches origin of the
# Actions checkout. That fetch is not this temp repo and does not return before
# the runner shuts down. The assertion only needs inflight to exit 0.
_CI_ENV = (
    "CI",
    "GITHUB_ACTIONS",
    "GITHUB_HEAD_REF",
    "GITHUB_BASE_REF",
    "GITHUB_SHA",
    "GITHUB_WORKSPACE",
    "GITLAB_CI",
    "CI_PROJECT_DIR",
    "TF_BUILD",
    "BUILD_SOURCEVERSION",
    "BUILD_SOURCESDIRECTORY",
    "SYSTEM_PULLREQUEST_SOURCEBRANCH",
    "SYSTEM_PULLREQUEST_TARGETBRANCHNAME",
    "DEPLOYMENT_PLAN",
    "INFLIGHT_PATHS",
)

_MISSING = "00000000-0000-4000-8002-000000000099"
_OBJECTIVE = "00000000-0000-4000-8002-000000000001"

_RULE = textwrap.dedent(
    """\
    name: Dangling Rule

    metadata:
      uuid: 00000000-0000-4000-8003-000000000099
      schema: rule::1.0
      version: 1
      created: 2026-01-01
      modified: 2026-01-02
      tlp: clear

    description: A rule whose detection model is not in the catalogue.
    status: STAGING
    severity: Substantial incident
    techniques:
      - T1059
    detection_model: {model}

    response:
      alert_severity: High

    configurations:
      sentinel:
        enabled: true
        name: Dangling Rule
        status: STAGING
        query: |
          SecurityEvent
          | take 1
        scheduling:
          frequency: PT1H
          lookback: PT2H
        alert:
          title: Dangling Rule
          suppression: false
        grouping:
          event: SingleAlert
          alert:
            enabled: false
    """
)

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "tide_corpus" / "current" / "Objects"


def _repo(tmp_path: Path, model: str) -> Path:
    target = tmp_path / "detections"
    run_repo_setup(RepoSetupOptions(path=target, name="Detections", yes=True))
    rules = target / "objects" / "rules"
    rules.mkdir(parents=True, exist_ok=True)
    (rules / "dangling.yaml").write_text(_RULE.format(model=model), encoding="utf-8")
    return target


def _invoke(repo: Path, *args: str):
    env = dict.fromkeys(_CI_ENV)
    env["OPENTIDE_REPO_ROOT"] = str(repo)
    env["OPENTIDE_TIDE_WORKSPACE"] = str(repo)
    return runner.invoke(app, ["--json", "--repo", str(repo), *args], env=env)


def test_generate_names_a_missing_detection_model(tmp_path: Path) -> None:
    repo = _repo(tmp_path, _MISSING)
    result = _invoke(repo, "generate")
    rendered = result.stdout + result.stderr
    assert result.exit_code == 1, rendered
    assert "Traceback" not in rendered
    assert not rendered.rstrip().endswith("Exception")
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert _MISSING in payload["message"]
    assert "detection_model" in payload["message"]
    inflight = _invoke(repo, "generate", "inflight")
    assert inflight.exit_code == 0, inflight.stdout + inflight.stderr


def test_generate_completes_when_the_detection_model_exists(tmp_path: Path) -> None:
    repo = _repo(tmp_path, _OBJECTIVE)
    shutil.copy(
        _FIXTURES / "Detection Objectives" / "objective-0001-credential-access.yaml",
        repo / "objects" / "objectives" / "credential-access.yaml",
    )
    shutil.copy(
        _FIXTURES / "Threat Vectors" / "threat-0001-simulated-actor.yaml",
        repo / "objects" / "threats" / "simulated-actor.yaml",
    )
    result = _invoke(repo, "generate")
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
