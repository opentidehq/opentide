"""Real ``opentide`` console-script chain for the published first-user path.

``test_workflow_e2e.py`` drives the same sequence in-process via CliRunner.
This module launches the installed ``opentide`` entry point as a child process
and requires every happy-path command to exit 0. Query/deploy stay in the
in-process test because they mock HTTP.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from pathlib import Path

import pytest
from pytest_console_scripts import RunResult, ScriptRunner
from tests.test_cli.e2e.helpers import write_tutorial_objects

pytestmark = [
    pytest.mark.cli_smoke,
    pytest.mark.script_launch_mode("subprocess"),
]

_HAPPY_PATH: tuple[tuple[str, ...], ...] = (
    ("generate",),
    ("validate", "--strict"),
    ("lint", "--strict"),
    ("info",),
    ("info", "--technique", "T1059", "coverage"),
)


def _repo_env(repo: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["OPENTIDE_REPO_ROOT"] = str(repo)
    env["OPENTIDE_TIDE_WORKSPACE"] = str(repo)
    env.pop("DEPLOYMENT_PLAN", None)
    env.pop("CI", None)
    env.pop("GITHUB_ACTIONS", None)
    env.pop("TF_BUILD", None)
    return env


def _run(
    script_runner: ScriptRunner,
    repo: Path,
    args: Sequence[str],
) -> RunResult:
    command = ["opentide", "--json", "--repo", str(repo), *args]
    return script_runner.run(command, env=_repo_env(repo), print_result=False)


def _payload(result: RunResult) -> dict[str, object]:
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout.strip())
    assert isinstance(payload, dict)
    if "ok" in payload:
        assert payload["ok"] is True, payload
    return payload


def test_first_user_console_script_workflow(script_runner: ScriptRunner, tmp_path: Path) -> None:
    parent = tmp_path / "workspace"
    parent.mkdir()
    fresh = parent / "tutorial-detections"

    setup = script_runner.run(
        [
            "opentide",
            "--json",
            "--repo",
            str(parent),
            "setup",
            "--yes",
            "--name",
            "Tutorial Detections",
            "--org",
            "Example Corp",
            "--platform",
            "sentinel",
            "--path",
            str(fresh),
        ],
        env=_repo_env(parent),
        print_result=False,
    )
    _payload(setup)
    assert (fresh / "objects" / "threats").is_dir()
    sentinel_toml = fresh / ".opentide" / "configurations" / "platforms" / "sentinel.toml"
    assert sentinel_toml.is_file()
    assert "enabled = true" in sentinel_toml.read_text(encoding="utf-8")

    empty = _run(script_runner, fresh, ("generate",))
    _payload(empty)
    assert (fresh / ".opentide" / "schemas" / "rule.1.0.schema.json").is_file()
    rule_template = (fresh / ".opentide" / "templates" / "rule.1.0.template.yaml").read_text(
        encoding="utf-8"
    )
    assert "configurations: {}" not in rule_template
    assert "#sentinel:" in rule_template
    assert "null" not in rule_template

    write_tutorial_objects(fresh)
    threat_yaml = (fresh / "objects" / "threats" / "simulated-actor.yaml").read_text(
        encoding="utf-8"
    )
    assert "name: att&ck::G0006" in threat_yaml

    for args in _HAPPY_PATH:
        payload = _payload(_run(script_runner, fresh, args))
        if args == ("validate", "--strict"):
            assert payload["report"]["ok"] is True
        if args == ("lint", "--strict"):
            assert payload["count"] == 0
        if args == ("info",):
            assert payload["counts"]["threats"] == 1
            assert payload["counts"]["objectives"] == 1
            assert payload["counts"]["rules"] == 1
        if args[-1] == "coverage":
            assert payload["coverage"]["count"] >= 1
