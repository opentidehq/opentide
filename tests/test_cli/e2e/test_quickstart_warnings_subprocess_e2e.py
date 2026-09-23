"""Console-script guard: the quickstart path logs nothing for an unused platform (#295).

Every command runs in a fresh ``opentide`` process, so no client an earlier
command built can hide one that logs when it is constructed. With ``--json``
each log line on stderr is a record that names its logger, which separates
platform output from unrelated generation messages.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from pytest_console_scripts import ScriptRunner
from tests.test_cli.e2e.helpers import write_tutorial_objects

pytestmark = [
    pytest.mark.cli_smoke,
    pytest.mark.script_launch_mode("subprocess"),
]

_QUICKSTART: tuple[tuple[str, ...], ...] = (
    ("info",),
    ("validate", "--strict"),
    ("lint", "--strict"),
    ("generate",),
)
_NOISY = frozenset({"warning", "error", "critical"})
#: Platform clients, plus the ``$VAR`` secret resolution their tenant configs trigger.
_PLATFORM_LOGGERS = ("opentide.platforms.", "opentide.core.environment")

_DISABLED_SPLUNK = """\
[platform]
enabled = false
identifier = "splunk"
name = "Splunk Enterprise"
subschema = "Splunk Sub Schema"
description = "Splunk"
flags = []

[[tenants]]
name = "Default"
description = "Default Splunk deployment target"
deployment = "ALWAYS"
[tenants.setup]
url = "$SPLUNK_URL"
port = "$SPLUNK_PORT"
token = "$SPLUNK_TOKEN"
app = "search"
frequency_scheduling = "bogus"
"""


def _env(repo: Path) -> dict[str, str]:
    """A plain terminal: the root conftest's ``TERM_PROGRAM=vscode`` switches on debug mode."""
    env = os.environ.copy()
    env["OPENTIDE_REPO_ROOT"] = str(repo)
    env["OPENTIDE_TIDE_WORKSPACE"] = str(repo)
    for name in (
        "TERM_PROGRAM",
        "DEBUG",
        "DEPLOYMENT_PLAN",
        "CI",
        "GITHUB_ACTIONS",
        "TF_BUILD",
        "SPLUNK_URL",
        "SPLUNK_PORT",
        "SPLUNK_TOKEN",
    ):
        env.pop(name, None)
    return env


def _tutorial(script_runner: ScriptRunner, parent: Path) -> Path:
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
        env=_env(parent),
        print_result=False,
    )
    assert setup.returncode == 0, setup.stdout + setup.stderr
    write_tutorial_objects(fresh)
    return fresh


def _platform_warnings(stderr: str) -> list[tuple[object, object, object]]:
    found: list[tuple[object, object, object]] = []
    for line in stderr.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict) or record.get("level") not in _NOISY:
            continue
        if str(record.get("logger", "")).startswith(_PLATFORM_LOGGERS):
            found.append((record["logger"], record["level"], record.get("event")))
    return found


@pytest.mark.parametrize("layout", ["sentinel-tutorial", "empty-directory", "disabled-splunk"])
def test_quickstart_commands_log_nothing_for_unused_platforms(
    script_runner: ScriptRunner, tmp_path: Path, layout: str
) -> None:
    if layout == "empty-directory":
        repo = tmp_path / "empty"
        repo.mkdir()
    else:
        repo = _tutorial(script_runner, tmp_path)
    if layout == "disabled-splunk":
        platforms = repo / ".opentide" / "configurations" / "platforms"
        (platforms / "splunk.toml").write_text(_DISABLED_SPLUNK, encoding="utf-8")

    failures: dict[str, object] = {}
    for args in _QUICKSTART:
        result = script_runner.run(
            ["opentide", "--json", "--repo", str(repo), *args],
            env=_env(repo),
            print_result=False,
        )
        assert result.returncode == 0, (args, result.stdout, result.stderr)
        if warnings := _platform_warnings(result.stderr):
            failures[" ".join(args)] = warnings
    assert failures == {}
