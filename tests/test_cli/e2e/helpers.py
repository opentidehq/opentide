"""Shared helpers for CLI E2E tests that author objects from docs."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TUTORIAL = ROOT / "docs" / "usage" / "tutorial.md"

TUTORIAL_FILES = (
    ("objects/threats/simulated-actor.yaml", "Create `objects/threats/simulated-actor.yaml`:"),
    (
        "objects/objectives/credential-access-objective.yaml",
        "Create `objects/objectives/credential-access-objective.yaml`:",
    ),
    ("objects/rules/sentinel-kql-rule.yaml", "Create `objects/rules/sentinel-kql-rule.yaml`:"),
)


def yaml_fence_after(markdown: str, heading: str) -> str:
    idx = markdown.index(heading)
    start = markdown.index("```yaml", idx)
    end = markdown.index("```", start + 7)
    return markdown[start + 7 : end].lstrip("\n")


def write_tutorial_objects(repo: Path, *, markdown: str | None = None) -> None:
    text = TUTORIAL.read_text(encoding="utf-8") if markdown is None else markdown
    for relpath, heading in TUTORIAL_FILES:
        dest = repo / relpath
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(yaml_fence_after(text, heading), encoding="utf-8")
