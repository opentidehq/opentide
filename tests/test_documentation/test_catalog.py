"""Documentation catalog behaviour."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.documentation.catalog import DocumentationCatalog, build_catalog


def test_catalog_resolve_name_fallback_to_uuid() -> None:
    catalog = DocumentationCatalog(rules=[], objectives=[], threats=[])
    with patch("opentide.documentation.catalog.OpenTide.lookup", return_value=None):
        assert catalog.resolve_name("missing") == "missing"


def test_catalog_resolve_record_returns_catalog_entry() -> None:
    record = MagicMock(uuid="u1")
    catalog = DocumentationCatalog(rules=[record], objectives=[], threats=[])
    assert catalog.resolve_record("u1") is record
    assert catalog.resolve_record("missing") is None


def test_catalog_related_uuids() -> None:
    catalog = DocumentationCatalog(rules=[], objectives=[], threats=[])
    with patch(
        "opentide.documentation.catalog.fw.relations_list",
        return_value={"rule": ["u2", "u3"]},
    ):
        assert catalog.related_uuids("u1") == ["u2", "u3"]


def test_catalog_related_entries_include_relation_metadata() -> None:
    catalog = DocumentationCatalog(rules=[], objectives=[], threats=[])
    with patch(
        "opentide.documentation.catalog.fw.relations_list",
        return_value={"objective": ["u2"]},
    ):
        entries = catalog.related_entries("u1")
    assert len(entries) == 1
    assert entries[0].uuid == "u2"
    assert entries[0].relation == "objective"
    assert entries[0].description == "Related objective"


def test_catalog_chaining_entries_enrich_description_from_vocab() -> None:
    catalog = DocumentationCatalog(rules=[], objectives=[], threats=[])
    threat = MagicMock()
    threat.threat.chaining = [{"vector": "u2", "relation": "preceeds"}]
    with (
        patch("opentide.documentation.catalog.OpenTide") as mock_ot,
        patch(
            "opentide.documentation.catalog.fw.get_vocab_entry",
            return_value="The following TVM occurs after this TVM.",
        ),
    ):
        mock_ot.Threats.get.return_value = threat
        entries = catalog.chaining_entries("u1")
    assert len(entries) == 1
    assert entries[0].uuid == "u2"
    assert entries[0].relation == "preceeds"
    assert entries[0].description == "The following TVM occurs after this TVM."


def test_build_catalog_collects_records() -> None:
    rule = MagicMock(metadata=MagicMock(uuid="r1"), name="Rule")
    with patch("opentide.documentation.catalog.OpenTide") as mock_ot:
        mock_ot.Rules.values.return_value = [rule]
        mock_ot.Objectives.values.return_value = []
        mock_ot.Threats.values.return_value = []
        catalog = build_catalog()
    assert len(catalog.rules) == 1
    assert catalog.rules[0].uuid == "r1"
