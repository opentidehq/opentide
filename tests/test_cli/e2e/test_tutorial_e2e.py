"""CLI E2E: tutorial objects from docs/usage/tutorial.md (issue #165)."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.test_cli.conftest import assert_json_ok

from opentide.cli.enums import DetectionPlatform
from opentide.cli.services.setup.platforms import PlatformsSetupOptions, run_platforms_setup
from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup

pytestmark = pytest.mark.cli_e2e

ROOT = Path(__file__).resolve().parents[3]
TUTORIAL = ROOT / "docs" / "usage" / "tutorial.md"

_TUTORIAL_FILES = (
    ("objects/threats/simulated-actor.yaml", "Create `objects/threats/simulated-actor.yaml`:"),
    (
        "objects/objectives/credential-access-objective.yaml",
        "Create `objects/objectives/credential-access-objective.yaml`:",
    ),
    ("objects/rules/sentinel-kql-rule.yaml", "Create `objects/rules/sentinel-kql-rule.yaml`:"),
)


def _yaml_fence_after(markdown: str, heading: str) -> str:
    idx = markdown.index(heading)
    start = markdown.index("```yaml", idx)
    end = markdown.index("```", start + 7)
    return markdown[start + 7 : end].lstrip("\n")


def test_tutorial_objects_validate_and_lint(invoke_cli, tmp_path: Path) -> None:
    fresh = tmp_path / "tutorial-detections"
    run_repo_setup(
        RepoSetupOptions(
            path=fresh,
            name="Tutorial Detections",
            org="Example Corp",
            yes=True,
            platforms=[DetectionPlatform.sentinel],
        )
    )
    run_platforms_setup(
        PlatformsSetupOptions(path=fresh, platforms=[DetectionPlatform.sentinel], yes=True)
    )
    markdown = TUTORIAL.read_text(encoding="utf-8")
    for relpath, heading in _TUTORIAL_FILES:
        dest = fresh / relpath
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(_yaml_fence_after(markdown, heading), encoding="utf-8")

    generate = invoke_cli("generate", repo=fresh)
    assert_json_ok(generate)
    threat_template = (fresh / ".opentide" / "templates" / "threat.1.0.template.yaml").read_text(
        encoding="utf-8"
    )
    assert "created: YYYY-MM-DD" in threat_template
    assert "modified: YYYY-MM-DD" in threat_template

    validate = invoke_cli("validate", "--strict", repo=fresh)
    payload = assert_json_ok(validate)
    assert payload["report"]["ok"] is True

    lint = invoke_cli("lint", "--strict", repo=fresh)
    lint_payload = assert_json_ok(lint)
    assert lint_payload["count"] == 0

    docs = invoke_cli("generate", "docs", repo=fresh)
    assert_json_ok(docs)
    # Flavor follows CI env (GitLab locally via CI=true, GitHub Actions in CI),
    # so filenames are either UUIDs or slugs. Assert object pages exist either way.
    def _object_pages(folder: str) -> list[str]:
        return sorted(
            p.name
            for p in (fresh / "docs" / folder).glob("*.md")
            if p.name.lower() != "readme.md"
        )

    assert _object_pages("Rules"), "expected generated rule documentation"
    assert _object_pages("Objectives"), "expected generated objective documentation"
    assert _object_pages("Threats"), "expected generated threat documentation"
    rule_text = (fresh / "docs" / "Rules" / _object_pages("Rules")[0]).read_text(encoding="utf-8")
    assert "00000000-0000-4000-8003-000000000001" in rule_text
