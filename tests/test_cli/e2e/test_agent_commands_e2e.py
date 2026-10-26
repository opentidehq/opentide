"""CLI E2E: the read-only commands agents are told to run never end in a usage error.

``tests/test_cli/test_agent_instructions.py`` parses every quoted command;
this runs the read-only ones (``validate``, ``lint``, ``info``, ``explain``,
``commands`` and ``deploy --dry-run``) on the tutorial workspace, which also
catches what a command requires itself, such as ``deploy --strategy``.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.agent_command_support import (
    AGENT_DOCS,
    arguments,
    commands_in_markdown,
    instruction_sources,
    unique,
)
from tests.corpus_support import clear_runtime_caches
from tests.test_cli.e2e.helpers import write_tutorial_objects
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.enums import DetectionPlatform
from opentide.cli.lazy import HOISTED_FLAGS
from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup

pytestmark = pytest.mark.cli_e2e

ROOT = Path(__file__).resolve().parents[3]
_LEAKY_ENV = (
    "OPENTIDE_REPO_ROOT",
    "OPENTIDE_TIDE_WORKSPACE",
    "OPENTIDE_OUTPUT",
    "DEPLOYMENT_PLAN",
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "TF_BUILD",
    "AI_AGENT",
    "CLAUDECODE",
)
_READ_ONLY = frozenset({"validate", "lint", "info", "explain", "commands", "deploy"})


def _read_only(command: str) -> bool:
    words = [word for word in arguments(command) if word not in HOISTED_FLAGS]
    if not words or words[0] not in _READ_ONLY:
        return False
    if words[0] == "validate" and words[1:2] == ["query"]:
        return False  # contacts the tenant
    if words[0] == "lint" and "--fix" in words:
        return False  # renames files
    return words[0] != "deploy" or "--dry-run" in words


def _quoted_read_only_commands() -> list[str]:
    texts = list(instruction_sources().values())
    # json-output.md shows usage errors on purpose (`opentide --json info rulez`).
    texts += [
        (ROOT / path).read_text(encoding="utf-8")
        for path in AGENT_DOCS
        if path.name != "json-output.md"
    ]
    found = unique(command for text in texts for command in commands_in_markdown(text))
    return [command for command in found if _read_only(command)]


@pytest.fixture(scope="module")
def tutorial(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    repo = tmp_path_factory.mktemp("agent-commands") / "tutorial"
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
    env = dict.fromkeys(_LEAKY_ENV)
    result = CliRunner().invoke(app, ["--repo", str(repo), "--json", "generate"], env=env)
    assert result.exit_code == 0, result.output
    yield repo
    clear_runtime_caches()


def test_there_are_read_only_commands_to_run() -> None:
    commands = _quoted_read_only_commands()
    assert any(" deploy " in f" {command} " for command in commands)
    assert len(commands) > 10


@pytest.mark.parametrize("command", _quoted_read_only_commands())
def test_quoted_read_only_command_is_not_a_usage_error(
    command: str, tutorial: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tutorial)
    clear_runtime_caches()
    env = dict.fromkeys(_LEAKY_ENV) | {
        "OPENTIDE_REPO_ROOT": str(tutorial),
        "OPENTIDE_TIDE_WORKSPACE": str(tutorial),
    }
    argv = arguments(command)
    result = CliRunner().invoke(app, ["--repo", str(tutorial), *argv], env=env)
    assert result.exit_code != 2, f"{command}\n{result.output}"
