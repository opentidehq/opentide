"""The ADRs are all in the navigation, and the contributor docs' relative links resolve (#845).

``scripts/validate-docs.sh`` checks links under ``docs/`` only, and a page left out of a
``meta.json`` is silently missing from the site's sidebar.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ADR = ROOT / "docs" / "internal" / "adr"
#: The contributor docs written with the ADRs (UC-X.3). Other skills keep their own links.
CONTRIBUTOR_DOCS = [
    ROOT / "CONTRIBUTING.md",
    ROOT / "AGENTS.md",
    ROOT / ".agents" / "skills" / "rust" / "SKILL.md",
    ROOT / ".agents" / "skills" / "golden" / "SKILL.md",
    ROOT / ".agents" / "skills" / "review-checklist" / "SKILL.md",
]
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
FENCE = re.compile(r"^(`{3,})[^\n]*\n.*?^\1[ \t]*$", re.MULTILINE | re.DOTALL)


def _pages(meta: Path) -> list[str]:
    data = json.loads(meta.read_text(encoding="utf-8"))
    pages = data["pages"]
    assert isinstance(pages, list)
    return [str(page) for page in pages]


def test_internal_navigation_lists_the_adr_folder() -> None:
    assert "adr" in _pages(ROOT / "docs" / "internal" / "meta.json")


def test_every_adr_page_is_in_the_adr_navigation_and_nothing_else_is() -> None:
    on_disk = {page.stem for page in ADR.glob("*.md")}
    listed = _pages(ADR / "meta.json")
    assert len(listed) == len(set(listed)), "a page is listed twice"
    assert set(listed) == on_disk


def test_adr_file_names_are_numbered() -> None:
    names = [page.name for page in ADR.glob("*.md") if page.name != "index.md"]
    assert names
    bad = [name for name in names if not re.fullmatch(r"\d{4}-[a-z0-9]+(?:-[a-z0-9]+)*\.md", name)]
    assert bad == []


@pytest.mark.parametrize("path", CONTRIBUTOR_DOCS, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_relative_links_resolve(path: Path) -> None:
    text = FENCE.sub("", path.read_text(encoding="utf-8"))
    broken = []
    for target in LINK.findall(text):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        relative = target.split("#", 1)[0]
        if relative and not (path.parent / relative).exists():
            broken.append(target)
    assert broken == []
