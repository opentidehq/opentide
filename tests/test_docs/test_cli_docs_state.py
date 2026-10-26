"""The CLI docs describe the merged CLI, not a branch of it."""

from __future__ import annotations

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.ui.results import PENDING_MODELS

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "docs" / "internal" / "cli-experience.md"
INDEX = ROOT / "docs" / "cli" / "index.md"
CHANGELOG = ROOT / "CHANGELOG.md"

#: Wording a stacked PR wrote about work that had not merged yet.
_STALE = (
    "not on this branch",
    "is not built yet",
    "until their PRs",
    "at merge it takes",
    "Until #641 and #643 land",
    "come later (PR",
)


def test_the_spec_has_no_wording_about_unmerged_work() -> None:
    text = SPEC.read_text(encoding="utf-8")
    assert [phrase for phrase in _STALE if phrase in text] == []


def test_the_spec_says_what_pending_models_holds() -> None:
    text = SPEC.read_text(encoding="utf-8")
    row = next(line for line in text.splitlines() if line.startswith("| Typed results |"))
    assert ("`PENDING_MODELS` is empty" in row) is (PENDING_MODELS == {})


def test_the_spec_names_the_renamed_skill_pack() -> None:
    """#634 renamed `detection-ops` to `detection-workflow`; the old name is only an alias."""
    text = SPEC.read_text(encoding="utf-8")
    for line in text.splitlines():
        if "`detection-ops`" in line:
            assert "detection-workflow" in line or "alias" in line, line


def test_the_brand_rule_agrees_with_the_no_color_rule() -> None:
    """`NO_COLOR` selects `plain`, where no mark prints; the Brand rules must say so."""
    text = SPEC.read_text(encoding="utf-8")
    rules = next(line for line in text.splitlines() if line.startswith("Rules: only in `human`"))
    assert "`NO_COLOR` keeps the shapes." not in rules
    assert "`NO_COLOR` on its own selects `plain`" in rules


def test_the_command_index_counts_match_the_cli() -> None:
    result = CliRunner().invoke(app, ["--json", "commands"])
    summary = json.loads(result.stdout)["summary"]
    text = INDEX.read_text(encoding="utf-8")
    documented = re.search(r'"summary": \{ "commands": (\d+), "groups": (\d+) \}', text)
    assert documented is not None
    assert (int(documented[1]), int(documented[2])) == (summary["commands"], summary["groups"])
    assert f'"message": "{summary["commands"]} commands"' in text
    assert f"ends with `✓ {summary['commands']} commands`" in text


def test_the_unreleased_lists_hold_no_blank_lines() -> None:
    """Auto-merged CHANGELOG sections must not split a list in two."""
    text = CHANGELOG.read_text(encoding="utf-8")
    unreleased = text.split("## [Unreleased]", 1)[1].split("\n## [", 1)[0]
    for section in re.split(r"\n### ", unreleased)[1:]:
        body = section.split("\n", 1)[1].strip("\n")
        assert "\n\n- " not in body, section.split("\n", 1)[0]
