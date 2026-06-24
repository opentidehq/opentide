"""Documentation index page rendering."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from opentide.documentation.context import DocumentationContext
from opentide.documentation.format.factory import formatter_for
from opentide.documentation.publish.index import render_index, write_index
from opentide.documentation.types import DocumentFlavor, DocumentRecord, DocumentScope


def test_render_index_builds_table() -> None:
    formatter = formatter_for(DocumentFlavor.github)
    ctx = DocumentationContext(
        flavor=DocumentFlavor.github,
        output_dir=MagicMock(),
        formatter=formatter,
        folder_index_pages=True,
        uuid_permalinks=False,
    )
    records = [
        DocumentRecord(
            object_type=DocumentScope.rules,
            uuid="u1",
            name="Rule A",
            model=MagicMock(),
        ),
    ]
    content = render_index(
        formatter,
        title="Detection Rules",
        folder="rules",
        records=records,
        ctx=ctx,
    )
    assert "Detection Rules" in content
    assert "Rule A" in content
    assert "u1" in content


def test_write_index_skips_when_disabled() -> None:
    ctx = DocumentationContext(
        flavor=DocumentFlavor.github,
        output_dir=MagicMock(),
        formatter=formatter_for(DocumentFlavor.github),
        folder_index_pages=False,
        uuid_permalinks=False,
    )
    pub = MagicMock()
    write_index(ctx, pub, rules=[], objectives=[], threats=[])
    # No exception and no write when folder_index_pages is False


def test_write_index_writes_folder_pages(tmp_path: Path) -> None:
    formatter = formatter_for(DocumentFlavor.github)
    ctx = DocumentationContext(
        flavor=DocumentFlavor.github,
        output_dir=tmp_path,
        formatter=formatter,
        folder_index_pages=True,
        uuid_permalinks=False,
    )
    pub = MagicMock()
    pub.rules_dir = tmp_path / "Rules"
    pub.objectives_dir = tmp_path / "Objectives"
    pub.threats_dir = tmp_path / "Threats"
    pub.output_root = tmp_path
    for folder in (pub.rules_dir, pub.objectives_dir, pub.threats_dir):
        folder.mkdir(parents=True)
    record = DocumentRecord(
        object_type=DocumentScope.rules,
        uuid="u1",
        name="Rule A",
        model=MagicMock(),
    )
    write_index(ctx, pub, rules=[record], objectives=[], threats=[])
    assert (pub.rules_dir / "README.md").is_file()
    assert (pub.output_root / "README.md").is_file()
