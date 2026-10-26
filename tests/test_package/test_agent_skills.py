"""Agent skills under .agents/skills stay discoverable and every pointer to them resolves.

Skill-aware agents find a skill through its YAML frontmatter: an unparseable header
(an unquoted ``description`` containing ``": "``) or a ``name`` that differs from the
directory silently hides the skill. ``release-management`` shipped that way.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SKILLS = ROOT / ".agents" / "skills"
SKILL_FILES = sorted(SKILLS.glob("*/SKILL.md"))
FRONTMATTER = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
SKILL_LINK = re.compile(r"\.agents/skills/([^/)\s`]+)/SKILL\.md")


def _frontmatter(path: Path) -> dict[str, object]:
    match = FRONTMATTER.match(path.read_text(encoding="utf-8"))
    assert match, f"{path.relative_to(ROOT)} has no YAML frontmatter"
    data = yaml.safe_load(match.group(1))
    assert isinstance(data, dict)
    return data


def test_there_are_skills() -> None:
    assert len(SKILL_FILES) >= 10


@pytest.mark.parametrize("path", SKILL_FILES, ids=lambda p: p.parent.name)
def test_skill_frontmatter_names_the_directory_and_describes_when_to_use_it(path: Path) -> None:
    data = _frontmatter(path)
    assert data.get("name") == path.parent.name
    description = data.get("description")
    assert isinstance(description, str)
    assert 50 <= len(description) <= 1024


@pytest.mark.parametrize(
    "pointer", ["AGENTS.md", ".github/copilot-instructions.md"], ids=lambda p: p
)
def test_every_skill_link_resolves(pointer: str) -> None:
    text = (ROOT / pointer).read_text(encoding="utf-8")
    linked = set(SKILL_LINK.findall(text))
    assert linked, f"{pointer} links no skills"
    missing = sorted(name for name in linked if not (SKILLS / name / "SKILL.md").is_file())
    assert missing == []


def test_agents_md_lists_every_skill() -> None:
    linked = set(SKILL_LINK.findall((ROOT / "AGENTS.md").read_text(encoding="utf-8")))
    assert {path.parent.name for path in SKILL_FILES} <= linked


def test_skills_lock_points_at_existing_skills() -> None:
    lock = json.loads((ROOT / "skills-lock.json").read_text(encoding="utf-8"))
    for name, entry in lock["skills"].items():
        assert (SKILLS / name / "SKILL.md").is_file(), name
        if entry["sourceType"] == "project":
            assert entry["skillPath"] == f".agents/skills/{name}/SKILL.md"
