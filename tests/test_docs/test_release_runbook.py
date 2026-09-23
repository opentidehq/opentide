"""The release runbook's commands must match what ``publish-pypi.yml`` accepts.

Agents follow ``.agents/skills/release-management/SKILL.md`` literally. The
0.4.0 release was cut with ``--latest=false`` and the repo kept showing 0.3.0
as Latest; its PyPI 502 was recovered only through the documented
``repository_dispatch`` retry (#290). If the documented dispatch event or
payload key drifts from the workflow, that recovery path silently stops working.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "publish-pypi.yml"
SKILL = ROOT / ".agents" / "skills" / "release-management" / "SKILL.md"
RUNBOOKS = [SKILL, ROOT / "docs" / "internal" / "pypi-trusted-publishing.md"]

_DISPATCH = re.compile(r"repos/OpenTideHQ/opentide/dispatches((?:\s+-f\s+[^\s`]+)+)")
_FIELD = re.compile(r"-f\s+(\S+?)=")


def _text(path: Path) -> str:
    # Join shell line continuations so multi-line commands match as one.
    return re.sub(r"\\\s*\n\s*", " ", path.read_text(encoding="utf-8"))


def _release_create_commands(path: Path) -> list[str]:
    commands: list[str] = []
    in_fence = False
    for line in _text(path).splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
        elif in_fence and stripped.startswith("gh release create "):
            commands.append(" ".join(stripped.split()))
    return commands


def _workflow() -> dict[Any, Any]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _dispatch_fields(path: Path) -> list[list[str]]:
    return [_FIELD.findall(match.group(1)) for match in _DISPATCH.finditer(_text(path))]


def _dispatch_values(path: Path, field: str) -> list[str]:
    pattern = re.compile(rf"-f\s+{re.escape(field)}=(\S+)")
    return [
        value for match in _DISPATCH.finditer(_text(path)) for value in pattern.findall(match[1])
    ]


@pytest.mark.parametrize("path", RUNBOOKS, ids=lambda path: path.name)
def test_documented_retry_uses_the_workflow_dispatch_event(path: Path) -> None:
    workflow = _workflow()
    # PyYAML (YAML 1.1) reads the bare `on` key as boolean True.
    triggers = workflow.get("on", workflow.get(True))
    events = _dispatch_values(path, "event_type")
    assert events, f"{path.name} no longer documents the repository_dispatch retry"
    assert set(events) <= set(triggers["repository_dispatch"]["types"])


@pytest.mark.parametrize("path", RUNBOOKS, ids=lambda path: path.name)
def test_documented_retry_payload_keys_reach_the_checkout(path: Path) -> None:
    checkout_ref = next(
        step["with"]["ref"]
        for step in _workflow()["jobs"]["publish"]["steps"]
        if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    for fields in _dispatch_fields(path):
        for key in re.findall(r"client_payload\[(\w+)\]", " ".join(fields)):
            assert f"github.event.client_payload.{key}" in checkout_ref, (
                f"{path.name}: client_payload[{key}] is ignored by publish-pypi.yml"
            )


@pytest.mark.parametrize("path", RUNBOOKS, ids=lambda path: path.name)
def test_documented_release_create_marks_the_new_tag_latest(path: Path) -> None:
    commands = _release_create_commands(path)
    assert commands, f"{path.name} no longer documents gh release create"
    for command in commands:
        assert "--target development" in command
        assert "--notes-file .github/release-notes/" in command
        assert "--latest=false" not in command


def test_release_create_parser_reads_fenced_multiline_commands(tmp_path: Path) -> None:
    runbook = tmp_path / "runbook.md"
    runbook.write_text(
        "Run `gh release create` after merge.\n\n"
        "```markdown\n[0.x.y]: link\n```\n\n"
        "```bash\ngh release create v0.4.0 \\\n  --target development \\\n  --latest=false\n```\n",
        encoding="utf-8",
    )
    assert _release_create_commands(runbook) == [
        "gh release create v0.4.0 --target development --latest=false"
    ]


def test_skill_verifies_the_latest_flag_and_both_pypi_files() -> None:
    text = _text(SKILL)
    assert "gh release list --repo OpenTideHQ/opentide" in text
    assert "https://pypi.org/pypi/opentide/0.x.y/json" in text
    assert "bdist_wheel" in text and "sdist" in text
