"""Guards so first-user simulations keep author-shaped YAML (issue #178).

Quoted ``created: "2026-01-01"`` scalars never become ``datetime.date``, so
generate/export can pass in CI while unquoted tutorial YAML crashes for users.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests.test_cli.e2e.helpers import TUTORIAL, TUTORIAL_FILES, yaml_fence_after

ROOT = Path(__file__).resolve().parents[2]
CORPUS_OBJECTS = ROOT / "tests" / "fixtures" / "tide_corpus" / "current" / "Objects"
QUOTED_DATE = re.compile(r"^[ \t]*(created|modified): \"\d{4}-\d{2}-\d{2}\"", re.M)


def test_tutorial_object_fences_use_unquoted_dates() -> None:
    markdown = TUTORIAL.read_text(encoding="utf-8")
    for relpath, heading in TUTORIAL_FILES:
        fence = yaml_fence_after(markdown, heading)
        quoted = QUOTED_DATE.findall(fence)
        assert not quoted, f"{relpath} quotes metadata dates: {quoted}"
        assert re.search(r"^[ \t]*created: \d{4}-\d{2}-\d{2}$", fence, re.M)
        assert re.search(r"^[ \t]*modified: \d{4}-\d{2}-\d{2}$", fence, re.M)


def test_tide_corpus_objects_use_unquoted_dates() -> None:
    offenders: list[str] = []
    for path in sorted(CORPUS_OBJECTS.rglob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        if QUOTED_DATE.search(text):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []
