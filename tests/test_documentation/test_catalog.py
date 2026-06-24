"""Documentation catalog behaviour."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.documentation.catalog import DocumentationCatalog, build_catalog


def test_catalog_resolve_name_fallback_to_uuid() -> None:
    catalog = DocumentationCatalog(rules=[], objectives=[], threats=[])
    with patch("opentide.documentation.catalog.OpenTide.lookup", return_value=None):
        assert catalog.resolve_name("missing") == "missing"


def test_catalog_related_uuids() -> None:
    catalog = DocumentationCatalog(rules=[], objectives=[], threats=[])
    with patch(
        "opentide.documentation.catalog.fw.relations_list",
        return_value={"rule": ["u2", "u3"]},
    ):
        assert catalog.related_uuids("u1") == ["u2", "u3"]


def test_build_catalog_collects_records() -> None:
    rule = MagicMock(metadata=MagicMock(uuid="r1"), name="Rule")
    with patch("opentide.documentation.catalog.OpenTide") as mock_ot:
        mock_ot.Rules.values.return_value = [rule]
        mock_ot.Objectives.values.return_value = []
        mock_ot.Threats.values.return_value = []
        catalog = build_catalog()
    assert len(catalog.rules) == 1
    assert catalog.rules[0].uuid == "r1"
