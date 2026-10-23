"""The instruction files ``opentide setup skills`` writes teach the agent output contract.

Every ``opentide`` command line they quote must exist, with options the
command really has, so an agent that pastes one never meets a usage error.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.services.setup.templates import (
    ENTRYPOINT_TEMPLATES,
    render_agent_entrypoint,
    setup_data_root,
)

_CONTEXT = {"name": "SOC Detections", "org": "SecOps", "description": "Rules for SOC"}
#: What every entrypoint must teach, in the words the JSON output uses.
_CONTRACT = ("opentide --json", "failure.code", "fix", "next_actions", "opentide explain")
_TAGLINE = "spec-driven development for agentic detection engineering"
#: ``opentide …`` inside a code span.
_SPAN = re.compile(r"`(opentide [^`]+)`")
#: Root options a quoted command may carry before its words.
_ROOT_FLAGS = frozenset({"--json", "--quiet", "--debug", "--no-color"})


def _skill_files() -> list[Path]:
    root = setup_data_root() / "skills"
    return sorted(root.rglob("SKILL.md"))


def _instruction_texts() -> dict[str, str]:
    texts = {name: render_agent_entrypoint(name, _CONTEXT) for name in ENTRYPOINT_TEMPLATES}
    root = setup_data_root() / "skills"
    for path in _skill_files():
        texts[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8")
    return texts


@pytest.fixture(scope="module")
def tree() -> dict:
    result = CliRunner().invoke(app, ["--json", "commands"], env={"NO_COLOR": "1"})
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)


@pytest.mark.parametrize("name", sorted(ENTRYPOINT_TEMPLATES))
def test_entrypoint_renders_every_placeholder(name: str) -> None:
    text = render_agent_entrypoint(name, _CONTEXT)
    assert "SOC Detections" in text
    assert "SecOps" in text
    assert "opentide deploy --dry-run" in text
    assert not re.search(r"\{[a-z_]+\}", text), "an unrendered placeholder is left"


@pytest.mark.parametrize("name", sorted(ENTRYPOINT_TEMPLATES))
def test_entrypoint_teaches_the_agent_output_contract(name: str) -> None:
    text = render_agent_entrypoint(name, _CONTEXT)
    for phrase in _CONTRACT:
        assert phrase in text, phrase
    assert _TAGLINE in text
    assert "MDR" not in text
    # People own merges and real deployments.
    assert "--dry-run" in text
    assert "merge" in text


def test_skill_pack_teaches_the_agent_output_contract() -> None:
    text = (setup_data_root() / "skills" / "detection-ops" / "SKILL.md").read_text(encoding="utf-8")
    for phrase in _CONTRACT:
        assert phrase in text, phrase


@pytest.mark.parametrize("path", _skill_files(), ids=lambda path: path.parent.name)
def test_authoring_skills_check_with_json(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert "opentide --json validate" in text
    assert "fix" in text
    assert "opentide explain" in text


def _quoted_commands(text: str) -> list[str]:
    """``opentide …`` lines of fenced blocks, and ``opentide …`` code spans elsewhere."""
    commands: list[str] = []
    in_fence = False
    for line in text.splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            if line.startswith("opentide "):
                commands.append(line.split("#", 1)[0].strip())
            continue
        commands.extend(span.strip() for span in _SPAN.findall(line))
    return commands


def test_quoted_commands_exist_with_their_options(tree: dict) -> None:
    by_path = {entry["path"]: entry for entry in tree["commands"]}
    root_flags = {flag for option in tree["global_options"] for flag in option["flags"]}
    checked = 0
    for name, text in _instruction_texts().items():
        for command in _quoted_commands(text):
            tokens = [token for token in command.split()[1:] if token not in _ROOT_FLAGS]
            if tokens and tokens[0].startswith("<"):
                continue  # ``opentide --json <command>``: any command
            words: list[str] = []
            for token in tokens:
                if token.startswith(("-", "<", "{")) or " ".join([*words, token]) not in by_path:
                    break
                words.append(token)
            path = " ".join(words)
            assert path in by_path, f"{name}: {command!r} names no command"
            entry = by_path[path]
            flags = {flag for option in entry["options"] for flag in option["flags"]}
            for token in tokens[len(words) :]:
                if token.startswith("--"):
                    assert token in flags | root_flags, f"{name}: {command!r} has no {token}"
            checked += 1
    assert checked > 20
