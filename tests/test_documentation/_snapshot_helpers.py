from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock

from opentide.core.io import load_yaml
from opentide.documentation.catalog import DiagramEntry, DocumentationCatalog
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

    names = {
        threat.metadata.uuid: threat.name,
        objective.metadata.uuid: objective.name,
        rule.metadata.uuid: rule.name,
        "00000000-0000-4000-8101-000000000099": "Cloud Discovery Follow-up",
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
    related_map = {
        threat.metadata.uuid: [DiagramEntry(uuid=objective.metadata.uuid, relation="objective")],
        objective.metadata.uuid: [DiagramEntry(uuid=rule.metadata.uuid, relation="rule")],
        rule.metadata.uuid: [],
    }
    chain_map = {
        threat.metadata.uuid: [
            DiagramEntry(
                uuid="00000000-0000-4000-8101-000000000099",
                relation="preceeds",
                description="The following TVM is occuring AFTER this TVM.",
            )
        ],
        objective.metadata.uuid: [],
        rule.metadata.uuid: [],
    }

    catalog = MagicMock(spec=DocumentationCatalog)
    catalog.resolve_name.side_effect = lambda uuid: names.get(uuid, uuid)
    catalog.resolve_record.side_effect = lambda uuid: records_by_uuid.get(uuid)
    catalog.related_entries.side_effect = lambda uuid, direction="both": related_map.get(uuid, [])
    catalog.chaining_entries.side_effect = lambda uuid: chain_map.get(uuid, [])

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
