"""CLI E2E: tutorial objects from docs/usage/tutorial.md (issue #165)."""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.test_cli.conftest import assert_json_ok
from tests.test_cli.e2e.helpers import TUTORIAL, write_tutorial_objects

pytestmark = pytest.mark.cli_e2e


def test_tutorial_objects_validate_and_lint(invoke_cli, tmp_path: Path) -> None:
    fresh = tmp_path / "tutorial-detections"
    setup = invoke_cli(
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
        repo=tmp_path,
    )
    assert_json_ok(setup)
    write_tutorial_objects(fresh, markdown=TUTORIAL.read_text(encoding="utf-8"))

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

    def _object_pages(folder: str) -> list[str]:
        return sorted(
            p.name for p in (fresh / "docs" / folder).glob("*.md") if p.name.lower() != "readme.md"
        )

    assert _object_pages("Rules"), "expected generated rule documentation"
    assert _object_pages("Objectives"), "expected generated objective documentation"
    assert _object_pages("Threats"), "expected generated threat documentation"
    rule_text = (fresh / "docs" / "Rules" / _object_pages("Rules")[0]).read_text(encoding="utf-8")
    assert "00000000-0000-4000-8003-000000000001" in rule_text
    threat_text = (fresh / "docs" / "Threats" / _object_pages("Threats")[0]).read_text(
        encoding="utf-8"
    )
    assert "G0006" in threat_text
