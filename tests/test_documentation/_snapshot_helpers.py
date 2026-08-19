from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock

from opentide.core.io import load_yaml
from opentide.documentation.catalog import (
    CoverageEdge,
    CoverageGraph,
    CoverageNode,
    DiagramEntry,
    DocumentationCatalog,
    SignalRecord,
)
from opentide.documentation.context import DocumentationContext
from opentide.documentation.format.factory import formatter_for
from opentide.documentation.types import DocumentFlavor, DocumentRecord, DocumentScope
from opentide.loading.objective_loader import load_objective_from_dict
from opentide.models.objective import DetectionObjective
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatVector

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "documentation"
THREAT_FIXTURE = FIXTURES_DIR / "threat-azure-gather-victim-data.yaml"
OBJECTIVE_FIXTURE = FIXTURES_DIR / "objective-shai-hulud.yaml"
RULE_FIXTURE = FIXTURES_DIR / "rule-shai-hulud-sentinel.yaml"

FOLLOW_UP_THREAT_UUID = "00000000-0000-4000-8101-000000000099"
SIGNAL_UUID = "00000000-0000-4000-8199-000000000001"


@dataclass(frozen=True)
class DocumentationBundle:
    threat: ThreatVector
    objective: DetectionObjective
    rule: DetectionRule
    catalog: DocumentationCatalog


def load_documentation_bundle() -> DocumentationBundle:
    threat = ThreatVector.from_yaml_dict(load_yaml(THREAT_FIXTURE))
    objective = load_objective_from_dict(load_yaml(OBJECTIVE_FIXTURE))
    rule = DetectionRule.from_yaml_dict(load_yaml(RULE_FIXTURE))
    signal_name = objective.objective.signals[0].name

    names = {
        threat.metadata.uuid: threat.name,
        objective.metadata.uuid: objective.name,
        rule.metadata.uuid: rule.name,
        FOLLOW_UP_THREAT_UUID: "Cloud Discovery Follow-up",
        SIGNAL_UUID: signal_name,
    }
    records_by_uuid = {
        threat.metadata.uuid: DocumentRecord(
            object_type=DocumentScope.threats,
            uuid=threat.metadata.uuid,
            name=threat.name,
            model=threat,
        ),
        objective.metadata.uuid: DocumentRecord(
            object_type=DocumentScope.objectives,
            uuid=objective.metadata.uuid,
            name=objective.name,
            model=objective,
        ),
        rule.metadata.uuid: DocumentRecord(
            object_type=DocumentScope.rules,
            uuid=rule.metadata.uuid,
            name=rule.name,
            model=rule,
        ),
    }
    signal = SignalRecord(
        uuid=SIGNAL_UUID,
        name=signal_name,
        parent_uuid=objective.metadata.uuid,
        parent_name=objective.name,
    )
    related_map = {
        threat.metadata.uuid: [
            DiagramEntry(
                uuid=objective.metadata.uuid,
                relation="objective",
                object_type="objective",
                direction="downstream",
                name=objective.name,
            )
        ],
        objective.metadata.uuid: [
            DiagramEntry(
                uuid=rule.metadata.uuid,
                relation="rule",
                object_type="rule",
                direction="downstream",
                name=rule.name,
            )
        ],
        rule.metadata.uuid: [
            DiagramEntry(
                uuid=objective.metadata.uuid,
                relation="objective",
                object_type="objective",
                direction="upstream",
                name=objective.name,
            )
        ],
    }
    chain_map = {
        threat.metadata.uuid: [
            DiagramEntry(
                uuid=FOLLOW_UP_THREAT_UUID,
                relation="preceeds",
                description="The following TVM is occuring AFTER this TVM.",
                object_type="threat",
                direction="downstream",
                name="Cloud Discovery Follow-up",
            )
        ],
        objective.metadata.uuid: [],
        rule.metadata.uuid: [],
    }
    coverage_map = {
        threat.metadata.uuid: CoverageGraph(
            nodes=[
                CoverageNode(
                    threat.metadata.uuid, threat.name, "threat", killchain="Reconnaissance"
                ),
                CoverageNode(objective.metadata.uuid, objective.name, "objective"),
                CoverageNode(SIGNAL_UUID, signal_name, "signal"),
                CoverageNode(rule.metadata.uuid, rule.name, "rule"),
            ],
            edges=[
                CoverageEdge(threat.metadata.uuid, objective.metadata.uuid, "covers"),
                CoverageEdge(objective.metadata.uuid, SIGNAL_UUID, None),
                CoverageEdge(SIGNAL_UUID, rule.metadata.uuid, "implements"),
            ],
        ),
        objective.metadata.uuid: CoverageGraph(
            nodes=[
                CoverageNode(threat.metadata.uuid, threat.name, "threat"),
                CoverageNode(objective.metadata.uuid, objective.name, "objective"),
                CoverageNode(SIGNAL_UUID, signal_name, "signal"),
                CoverageNode(rule.metadata.uuid, rule.name, "rule"),
            ],
            edges=[
                CoverageEdge(threat.metadata.uuid, objective.metadata.uuid, "covers"),
                CoverageEdge(objective.metadata.uuid, SIGNAL_UUID, None),
                CoverageEdge(SIGNAL_UUID, rule.metadata.uuid, "implements"),
            ],
        ),
        rule.metadata.uuid: CoverageGraph(
            nodes=[
                CoverageNode(threat.metadata.uuid, threat.name, "threat"),
                CoverageNode(objective.metadata.uuid, objective.name, "objective"),
                CoverageNode(rule.metadata.uuid, rule.name, "rule"),
            ],
            edges=[
                CoverageEdge(threat.metadata.uuid, objective.metadata.uuid, "covers"),
                CoverageEdge(objective.metadata.uuid, rule.metadata.uuid, "implements"),
            ],
        ),
    }
    network_map = {
        threat.metadata.uuid: CoverageGraph(
            nodes=[
                CoverageNode(
                    threat.metadata.uuid, threat.name, "threat", killchain="Reconnaissance"
                ),
                CoverageNode(FOLLOW_UP_THREAT_UUID, "Cloud Discovery Follow-up", "threat"),
            ],
            edges=[CoverageEdge(threat.metadata.uuid, FOLLOW_UP_THREAT_UUID, "preceeds")],
        ),
        objective.metadata.uuid: CoverageGraph(),
        rule.metadata.uuid: CoverageGraph(),
    }

    catalog = MagicMock(spec=DocumentationCatalog)
    catalog.rules = [records_by_uuid[rule.metadata.uuid]]
    catalog.objectives = [records_by_uuid[objective.metadata.uuid]]
    catalog.threats = [records_by_uuid[threat.metadata.uuid]]
    catalog.signals = [signal]
    catalog.resolve_name.side_effect = lambda uuid: names.get(uuid, uuid)
    catalog.resolve_record.side_effect = lambda uuid: records_by_uuid.get(uuid)
    catalog.resolve_signal.side_effect = lambda uuid: signal if uuid == SIGNAL_UUID else None
    catalog.related_entries.side_effect = lambda uuid, direction="both": related_map.get(uuid, [])
    catalog.related_uuids.side_effect = lambda uuid, direction="both": [
        entry.uuid for entry in related_map.get(uuid, [])
    ]
    catalog.chaining_entries.side_effect = lambda uuid: chain_map.get(uuid, [])
    catalog.chaining_network.side_effect = lambda uuid: network_map.get(uuid, CoverageGraph())
    catalog.coverage_graph.side_effect = lambda uuid: coverage_map.get(uuid, CoverageGraph())
    catalog.rules_for_signal.side_effect = lambda uuid: (
        [rule.metadata.uuid] if uuid == SIGNAL_UUID else []
    )

    return DocumentationBundle(
        threat=threat,
        objective=objective,
        rule=rule,
        catalog=catalog,
    )


def github_context(tmp_path: Path) -> DocumentationContext:
    flavor = DocumentFlavor.github
    return DocumentationContext(
        flavor=flavor,
        output_dir=tmp_path / "docs-output",
        formatter=formatter_for(flavor),
    )
