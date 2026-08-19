"""Documentation catalog behaviour."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from tests.test_documentation._snapshot_helpers import (
    FOLLOW_UP_THREAT_UUID,
    load_documentation_bundle,
)

from opentide.documentation.catalog import DocumentationCatalog, SignalRecord, build_catalog
from opentide.documentation.types import DocumentRecord, DocumentScope


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


def test_catalog_related_entries_merge_upstream_and_downstream_without_clobber() -> None:
    catalog = DocumentationCatalog(rules=[], objectives=[], threats=[])

    def _relations(uuid, mode="flat", direction="downstream"):
        _ = uuid, mode
        if direction == "downstream":
            return {"rule": ["down-1"]}
        return {"rule": ["up-1"]}

    with patch("opentide.documentation.catalog.fw.relations_list", side_effect=_relations):
        entries = catalog.related_entries("u1", direction="both")
    uuids = {entry.uuid for entry in entries}
    assert uuids == {"down-1", "up-1"}
    directions = {entry.uuid: entry.direction for entry in entries}
    assert directions["down-1"] == "downstream"
    assert directions["up-1"] == "upstream"


def test_coverage_graph_unknown_uuid_is_empty() -> None:
    catalog = DocumentationCatalog(rules=[], objectives=[], threats=[])
    assert catalog.coverage_graph("missing").is_empty()


def test_coverage_graph_links_threat_objective_signal_and_rule() -> None:
    bundle = load_documentation_bundle()
    catalog = DocumentationCatalog(
        rules=bundle.catalog.rules,
        objectives=bundle.catalog.objectives,
        threats=bundle.catalog.threats,
        signals=bundle.catalog.signals,
    )
    with patch.object(
        DocumentationCatalog,
        "rules_for_signal",
        return_value=[bundle.rule.metadata.uuid],
    ):
        from_objective = catalog.coverage_graph(bundle.objective.metadata.uuid)
        from_threat = catalog.coverage_graph(bundle.threat.metadata.uuid)
        from_rule = catalog.coverage_graph(bundle.rule.metadata.uuid)
    assert {node.object_type for node in from_objective.nodes} == {
        "threat",
        "objective",
        "signal",
        "rule",
    }
    assert any(edge.label == "covers" for edge in from_threat.edges)
    assert any(node.uuid == bundle.rule.metadata.uuid for node in from_rule.nodes)


def test_chaining_network_walks_inbound_index() -> None:
    bundle = load_documentation_bundle()
    follow = DocumentRecord(
        DocumentScope.threats,
        FOLLOW_UP_THREAT_UUID,
        "Cloud Discovery Follow-up",
        MagicMock(threat=MagicMock(killchain=["Impact"])),
    )
    catalog = DocumentationCatalog(
        rules=[],
        objectives=[],
        threats=[bundle.catalog.threats[0], follow],
        signals=[],
    )
    inbound = {"other-threat": {"succeeds": [bundle.threat.metadata.uuid]}}
    other = DocumentRecord(
        DocumentScope.threats,
        "other-threat",
        "Other Threat",
        MagicMock(threat=MagicMock(killchain=None)),
    )
    catalog = DocumentationCatalog(
        rules=[],
        objectives=[],
        threats=[bundle.catalog.threats[0], follow, other],
        signals=[],
    )
    with (
        patch("opentide.documentation.catalog.OpenTide") as mock_ot,
        patch(
            "opentide.documentation.catalog.fw.chain_resolver",
            side_effect=lambda _vector, chain: chain,
        ),
        patch(
            "opentide.documentation.catalog.fw.get_vocab_entry",
            return_value="bidirectional",
        ),
    ):
        mock_ot.Models.chaining = inbound
        mock_ot.Threats.get.return_value = bundle.threat
        graph = catalog.chaining_network(bundle.threat.metadata.uuid)
        chained = catalog.chaining_uuids(bundle.threat.metadata.uuid)
    assert not graph.is_empty()
    assert any(edge.arrow == "bidirectional" for edge in graph.edges)
    assert chained == [FOLLOW_UP_THREAT_UUID]


def test_chaining_network_keeps_unresolved_chain_targets() -> None:
    bundle = load_documentation_bundle()
    follow = DocumentRecord(
        DocumentScope.threats,
        FOLLOW_UP_THREAT_UUID,
        "Cloud Discovery Follow-up",
        MagicMock(threat=MagicMock(killchain=None)),
    )
    catalog = DocumentationCatalog(
        rules=[],
        objectives=[],
        threats=[bundle.catalog.threats[0], follow],
        signals=[],
    )
    threat = MagicMock()
    threat.threat.chaining = [
        {"vector": FOLLOW_UP_THREAT_UUID, "relation": "preceeds"},
        {"vector": "ghost-threat", "relation": "succeeds"},
    ]
    with (
        patch("opentide.documentation.catalog.OpenTide") as mock_ot,
        patch(
            "opentide.documentation.catalog.fw.chain_resolver",
            side_effect=lambda _vector, chain: chain,
        ),
        patch("opentide.documentation.catalog.fw.get_vocab_entry", return_value="forward"),
    ):
        mock_ot.Models.chaining = {}
        mock_ot.Threats.get.return_value = threat
        mock_ot.lookup.return_value = None
        graph = catalog.chaining_network(bundle.threat.metadata.uuid)
    node_ids = {node.uuid for node in graph.nodes}
    assert FOLLOW_UP_THREAT_UUID in node_ids
    assert "ghost-threat" in node_ids
    assert any(edge.target == "ghost-threat" for edge in graph.edges)


def test_rules_for_signal_filters_to_catalog_rules() -> None:
    rule = MagicMock(uuid="rule-1")
    catalog = DocumentationCatalog(rules=[rule], objectives=[], threats=[])
    with (
        patch(
            "opentide.documentation.catalog.fw.get_type",
            side_effect=lambda uuid, mute=True: "signal" if uuid == "sig" else "rule",
        ),
        patch("opentide.documentation.catalog.fw.childs", return_value=["rule-1", "rule-missing"]),
        patch(
            "opentide.documentation.catalog.fw.relations_list",
            return_value={"rule": ["rule-1"]},
        ),
    ):
        assert catalog.rules_for_signal("sig") == ["rule-1"]


def test_rules_for_signal_returns_empty_for_non_signal() -> None:
    catalog = DocumentationCatalog(rules=[], objectives=[], threats=[])
    with patch("opentide.documentation.catalog.fw.get_type", return_value="rule"):
        assert catalog.rules_for_signal("not-a-signal") == []


def test_resolve_name_uses_signal_and_lookup() -> None:
    catalog = DocumentationCatalog(
        rules=[],
        objectives=[],
        threats=[],
        signals=[SignalRecord("s1", "Signal One", "obj", "Objective")],
    )
    assert catalog.resolve_name("s1") == "Signal One"
    named = MagicMock()
    named.name = "Looked Up"
    with patch("opentide.documentation.catalog.OpenTide.lookup", return_value=named):
        assert catalog.resolve_name("other") == "Looked Up"


def test_related_entries_skips_self_and_non_dict_relations() -> None:
    catalog = DocumentationCatalog(rules=[], objectives=[], threats=[])
    with patch(
        "opentide.documentation.catalog.fw.relations_list",
        return_value={"rule": ["u1", "u2"]},
    ):
        entries = catalog.related_entries("u1")
    assert [entry.uuid for entry in entries] == ["u2"]


def test_related_entries_tolerate_relation_lookup_errors() -> None:
    catalog = DocumentationCatalog(rules=[], objectives=[], threats=[])
    with patch(
        "opentide.documentation.catalog.fw.relations_list",
        side_effect=RuntimeError("index missing"),
    ):
        assert catalog.related_entries("u1") == []


def test_chaining_entries_skip_blank_targets() -> None:
    catalog = DocumentationCatalog(rules=[], objectives=[], threats=[])
    threat = MagicMock()
    threat.threat.chaining = [{"relation": "preceeds"}]
    with patch("opentide.documentation.catalog.OpenTide") as mock_ot:
        mock_ot.Threats.get.return_value = threat
        assert catalog.chaining_entries("u1") == []


def test_build_catalog_indexes_nested_signals() -> None:
    bundle = load_documentation_bundle()
    with patch("opentide.documentation.catalog.OpenTide") as mock_ot:
        mock_ot.Rules.values.return_value = [bundle.rule]
        mock_ot.Objectives.values.return_value = [bundle.objective]
        mock_ot.Threats.values.return_value = [bundle.threat]
        catalog = build_catalog()
    assert catalog.signals
    assert catalog.resolve_signal(catalog.signals[0].uuid) is not None


def test_build_catalog_collects_records() -> None:
    rule = MagicMock(metadata=MagicMock(uuid="r1"), name="Rule")
    with patch("opentide.documentation.catalog.OpenTide") as mock_ot:
        mock_ot.Rules.values.return_value = [rule]
        mock_ot.Objectives.values.return_value = []
        mock_ot.Threats.values.return_value = []
        catalog = build_catalog()
    assert len(catalog.rules) == 1
    assert catalog.rules[0].uuid == "r1"
