"""Documentation index page rendering."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

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
    with patch("opentide.documentation.publish.index.fw.relations_list", return_value={}):
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
    assert "Related" in content
    assert "0" in content


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
        index_relation_counts=False,
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


def test_write_index_writes_gitlab_order_file(tmp_path: Path) -> None:
    formatter = formatter_for(DocumentFlavor.gitlab)
    ctx = DocumentationContext(
        flavor=DocumentFlavor.gitlab,
        output_dir=tmp_path,
        formatter=formatter,
        folder_index_pages=True,
        uuid_permalinks=True,
        index_relation_counts=False,
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
        uuid="rule-uuid",
        name="Rule A",
        model=MagicMock(),
    )
    write_index(ctx, pub, rules=[record], objectives=[], threats=[])
    assert (pub.rules_dir / ".order").read_text(encoding="utf-8") == "README\nrule-uuid\n"


def test_render_index_includes_icons_when_enabled() -> None:
    formatter = formatter_for(DocumentFlavor.github)
    ctx = DocumentationContext(
        flavor=DocumentFlavor.github,
        output_dir=MagicMock(),
        formatter=formatter,
        folder_index_pages=True,
        uuid_permalinks=False,
        index_icons=True,
    )
    records = [
        DocumentRecord(
            object_type=DocumentScope.rules,
            uuid="u1",
            name="Rule A",
            model=MagicMock(),
        ),
    ]
    with patch("opentide.documentation.publish.index.fw.relations_list", return_value={}):
        content = render_index(
            formatter,
            title="Detection Rules",
            folder="rules",
            records=records,
            ctx=ctx,
        )
    assert ":shield: Rule A" in content
