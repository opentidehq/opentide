"""Removal of object pages that no catalogue record writes any more."""

from __future__ import annotations

import os
from pathlib import Path

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.context import DocumentationContext
from opentide.documentation.format.factory import formatter_for
from opentide.documentation.publish.prune import is_generated_page, prune_stale_pages
from opentide.documentation.types import DocumentFlavor, DocumentRecord, DocumentScope

PAGE = "# {name}\n\n## Metadata\n| Field | Value |\n| --- | --- |\n| UUID | `{uuid}` |\n"


def _ctx(output: Path) -> DocumentationContext:
    return DocumentationContext(
        flavor=DocumentFlavor.github,
        output_dir=output,
        formatter=formatter_for(DocumentFlavor.github),
    )


def _catalog(*rules: tuple[str, str]) -> DocumentationCatalog:
    return DocumentationCatalog(
        rules=[DocumentRecord(DocumentScope.rules, uuid, name, object()) for uuid, name in rules],
        objectives=[],
        threats=[],
    )


def test_prune_removes_only_stale_generated_pages(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "live-rule.md").write_text(PAGE.format(name="Live rule", uuid="u1"), encoding="utf-8")
    (rules / "old-name.md").write_text(PAGE.format(name="Old name", uuid="u1"), encoding="utf-8")
    (rules / "README.md").write_text(PAGE.format(name="Index", uuid="x"), encoding="utf-8")
    (rules / "guide.md").write_text("# Writing rules\n\n| UUID | `u1` |\n", encoding="utf-8")
    (rules / "notes.txt").write_text(PAGE.format(name="Notes", uuid="u9"), encoding="utf-8")

    removed = prune_stale_pages(_ctx(tmp_path), _catalog(("u1", "Live rule")))

    assert removed == [rules / "old-name.md"]
    assert sorted(path.name for path in rules.iterdir()) == [
        "README.md",
        "guide.md",
        "live-rule.md",
        "notes.txt",
    ]


def test_prune_keeps_a_live_page_under_another_spelling(tmp_path: Path) -> None:
    """A case-insensitive filesystem can list a live page under an older spelling."""
    rules = tmp_path / "rules"
    rules.mkdir()
    live = rules / "live-rule.md"
    live.write_text(PAGE.format(name="Live rule", uuid="u1"), encoding="utf-8")
    alias = rules / "Live-Rule.md"
    if not alias.exists():  # a case-sensitive file system: give the page a second spelling
        os.link(live, alias)

    assert prune_stale_pages(_ctx(tmp_path), _catalog(("u1", "Live rule"))) == []
    assert (rules / "Live-Rule.md").exists()


def test_prune_skips_scopes_and_missing_folders(tmp_path: Path) -> None:
    stale = tmp_path / "rules" / "gone.md"
    stale.parent.mkdir()
    stale.write_text(PAGE.format(name="Gone", uuid="u2"), encoding="utf-8")

    assert prune_stale_pages(_ctx(tmp_path), _catalog(), [DocumentScope.threats]) == []
    assert stale.exists()
    assert prune_stale_pages(_ctx(tmp_path), _catalog()) == [stale]


def test_is_generated_page_needs_the_metadata_uuid_row(tmp_path: Path) -> None:
    page = tmp_path / "page.md"
    page.write_text(PAGE.format(name="Rule", uuid="u1"), encoding="utf-8")
    assert is_generated_page(page)
    page.write_text("## Metadata\n| UUID | not code |\n", encoding="utf-8")
    assert not is_generated_page(page)
    page.write_bytes(b"\xff\xfe")
    assert not is_generated_page(page)
    assert not is_generated_page(tmp_path / "missing.md")
