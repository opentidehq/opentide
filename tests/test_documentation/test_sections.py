"""Documentation section renderers."""

from __future__ import annotations

from typing import Any

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.format.factory import formatter_for
from opentide.documentation.parts.sections import (
    render_actors,
    render_attack_techniques,
    render_criticality,
    render_description,
    render_detection_model_link,
    render_metadata,
    render_objective_meta,
    render_references,
    render_rule_queries,
    render_rule_response,
    render_rule_status,
    render_signal_mdr_coverage,
    render_signals,
    render_techniques,
    render_terrain,
    render_threat_assessment,
    render_threat_body,
)
from opentide.documentation.types import DocumentFlavor, DocumentRecord, DocumentScope
from opentide.loading.objective_loader import load_objective_from_dict
from opentide.models.metadata import ObjectMetadata, ObjectReferences
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatVector


def _objective_payload(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "Objective",
        "metadata": {**metadata, "schema": "objective::1.0"},
        "composition": {"strategy": "synergetic", "description": "compose"},
        "objective": {
            "priority": "High",
            "type": "Threat",
            "investment": "Medium",
            "description": "Track execution",
            "composition": {"strategy": "synergetic", "description": "compose"},
            "signals": [
                {
                    "name": "Exec signal",
                    "uuid": "00000000-0000-4000-8000-000000000021",
                    "description": "Suspicious execution",
                    "severity": "High",
                    "effort": 3,
                    "methodology": "Monitor process creation",
                    "entities": ["host"],
                    "data": {
                        "availability": "Complete",
                        "requirements": "logs",
                        "logsources": ["MDE DeviceProcessEvents"],
                    },
                    "detectors": [
                        {
                            "name": "Sentinel KQL baseline",
                            "technology": "Microsoft Sentinel",
                            "description": "Initial tuned baseline query.",
                            "link": "https://example.com/detector",
                        }
                    ],
                    "examples": [
                        {
                            "description": "Baseline suspicious process lineage query.",
                            "link": "https://example.com/example",
                            "language": "sql",
                            "query": "DeviceProcessEvents\n| take 1",
                        }
                    ],
                }
            ],
        },
    }


def test_render_metadata_includes_uuid_and_schema(metadata: dict[str, Any]) -> None:
    formatter = formatter_for(DocumentFlavor.github)
    obj_metadata = ObjectMetadata.model_validate({**metadata, "schema": "rule::1.0"})
    rendered = render_metadata(obj_metadata, formatter)
    assert "Metadata" in rendered
    assert metadata["uuid"] in rendered
    assert "rule::1.0" in rendered
    assert "**Version**: `1`" in rendered
    assert "**Created**: `2026-01-01`" in rendered
    assert "**Modified**: `2026-01-02`" in rendered
    assert "TLP:CLEAR" in rendered


def test_render_metadata_includes_optional_authoring_fields() -> None:
    formatter = formatter_for(DocumentFlavor.github)
    metadata = ObjectMetadata.model_validate(
        {
            "uuid": "00000000-0000-4000-8000-000000000001",
            "schema": "rule::1.0",
            "version": "2.1.0",
            "created": "2026-01-01",
            "modified": "2026-01-03",
            "tlp": "amber",
            "author": "OpenTide Team",
            "contributors": ["Alice", "Bob"],
            "organisation": {
                "uuid": "00000000-0000-4000-8000-000000000123",
                "name": "OpenTideHQ",
            },
        }
    )
    rendered = render_metadata(metadata, formatter)

    assert "**Author**: OpenTide Team" in rendered
    assert "**Contributors**: Alice, Bob" in rendered
    assert "**Organisation**: OpenTideHQ (`00000000-0000-4000-8000-000000000123`)" in rendered


def test_render_references_renders_all_reference_groups() -> None:
    formatter = formatter_for(DocumentFlavor.github)
    references = ObjectReferences.model_validate(
        {
            "public": {1: "https://example.com/advisory"},
            "internal": {"IR-123": "https://wiki.example.test/ir-123"},
            "reports": ["https://example.com/report"],
        }
    )
    rendered = render_references(references, formatter)

    assert "## References" in rendered
    assert "### Public" in rendered
    assert "### Internal" in rendered
    assert "### Reports" in rendered
    assert "[https://example.com/advisory](https://example.com/advisory)" in rendered


def test_render_references_returns_empty_for_none() -> None:
    formatter = formatter_for(DocumentFlavor.github)
    assert render_references(None, formatter) == ""


def test_render_description_and_techniques() -> None:
    formatter = formatter_for(DocumentFlavor.github)
    assert "Description" in render_description("Detect malware", formatter)
    assert render_techniques([], formatter) == ""
    assert "T1059" in render_techniques(["T1059"], formatter)


def test_render_rule_queries_with_platform_config(rule_payload: dict) -> None:
    rule = DetectionRule.from_yaml_dict(rule_payload)
    formatter = formatter_for(DocumentFlavor.github)
    rendered = render_rule_queries(rule, formatter)
    assert rendered == ""


def test_render_rule_sections_include_status_response_and_model_link(
    metadata: dict[str, Any],
) -> None:
    rule = DetectionRule.from_yaml_dict(
        {
            "name": "Rule with response",
            "metadata": {**metadata, "schema": "rule::1.0"},
            "description": "Detect suspicious cloud list operations",
            "status": "STAGING",
            "severity": "High",
            "techniques": ["T1589"],
            "platforms": {},
            "detection_model": "00000000-0000-4000-8102-000000000001",
            "response": {
                "alert_severity": "High",
                "playbook": "PB-IR-001",
                "responders": "soc_l1",
                "procedure": {
                    "analysis": "Review contextual indicators and user baselines.",
                    "containment": "Disable tokens and force account reauthentication.",
                },
            },
        }
    )
    formatter = formatter_for(DocumentFlavor.github)
    catalog = DocumentationCatalog(
        rules=[],
        objectives=[
            DocumentRecord(
                object_type=DocumentScope.objectives,
                uuid="00000000-0000-4000-8102-000000000001",
                name="Shai-Hulud Objective",
                model=object(),
            )
        ],
        threats=[],
    )

    status = render_rule_status(rule, formatter)
    response = render_rule_response(rule, formatter)
    detection_model = render_detection_model_link(rule, formatter, catalog)

    assert "## Status" in status
    assert "**Status**: `STAGING`" in status
    assert "**Severity**: `High`" in status
    assert "## Response" in response
    assert "**Alert severity**:" in response
    assert "**Playbook**: PB-IR-001" in response
    assert "**Responders**:" in response
    assert "### Procedure" in response
    assert "## Detection model" in detection_model
    assert "[Shai-Hulud Objective](Objectives/shai-hulud-objective.md)" in detection_model
    assert "`00000000-0000-4000-8102-000000000001`" in detection_model


def test_render_rule_queries_include_platform_metadata(metadata: dict[str, Any]) -> None:
    formatter = formatter_for(DocumentFlavor.github)
    rule = DetectionRule.from_yaml_dict(
        {
            "name": "Rule with sentinel config",
            "metadata": {**metadata, "schema": "rule::1.0"},
            "description": "desc",
            "status": "STAGING",
            "severity": "High",
            "techniques": [],
            "platforms": {},
            "configurations": {
                "sentinel": {
                    "enabled": True,
                    "name": "Rule with sentinel config",
                    "status": "STAGING",
                    "query": "SecurityEvent | take 1",
                    "scheduling": {"frequency": "PT1H", "lookback": "PT2H"},
                    "alert": {"title": "Sentinel alert", "suppression": False},
                    "grouping": {"event": "SingleAlert"},
                    "entities": [
                        {
                            "entity": "Account",
                            "mappings": [{"identifier": "Name", "column": "AccountName"}],
                        }
                    ],
                }
            },
        }
    )

    rendered = render_rule_queries(rule, formatter)

    assert "## Platform configurations" in rendered
    assert "**Enabled**: `True`" in rendered
    assert "**Status**: `STAGING`" in rendered
    assert "**Alert title**: Sentinel alert" in rendered
    assert "**Entity mapping**: Account: Name -> AccountName" in rendered
    assert "```sql" in rendered
    assert "SecurityEvent | take 1" in rendered


def test_render_signals_and_threat_body(metadata: dict[str, Any]) -> None:
    formatter = formatter_for(DocumentFlavor.github)
    objective = load_objective_from_dict(_objective_payload(metadata))
    signals = render_signals(objective, formatter)
    objective_meta = render_objective_meta(objective, formatter)

    assert "## Objective metadata" in objective_meta
    assert "**Priority**: High" in objective_meta
    assert "**Type**: Threat" in objective_meta
    assert "**Investment**: Medium" in objective_meta
    assert "**Composition rationale**: compose" in objective_meta

    assert "## Signals" in signals
    assert "Exec signal" in signals
    assert "**Severity**: High" in signals
    assert "**Effort**: 3" in signals
    assert "#### Data" in signals
    assert "**Log sources**: MDE DeviceProcessEvents" in signals
    assert "#### Detectors" in signals
    assert "Sentinel KQL baseline" in signals
    assert "#### Examples" in signals
    assert "```sql" in signals

    threat = ThreatVector.from_yaml_dict(
        {
            "name": "Threat",
            "criticality": "High",
            "metadata": {**metadata, "schema": "threat::1.0"},
            "threat": {
                "description": "Ransomware",
                "severity": "High",
                "impact": "Data Breach",
                "leverage": "High",
                "viability": "High",
                "terrain": "Endpoint",
                "att&ck": ["T1486"],
            },
        }
    )
    body = render_threat_body(threat, formatter)
    assert "Ransomware" in body
    assert "## Criticality" in body
    assert "## Terrain" in body
    assert "## Threat Assessment" in body
    assert "## ATT&CK Techniques" in body
    assert "[Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486)" in body


def test_render_threat_sections_with_enrichment(metadata: dict[str, Any]) -> None:
    formatter = formatter_for(DocumentFlavor.github)
    threat = ThreatVector.from_yaml_dict(
        {
            "name": "Threat",
            "criticality": "High",
            "metadata": {**metadata, "schema": "threat::1.0"},
            "threat": {
                "description": "Ransomware",
                "severity": "High",
                "impact": "Data Breach",
                "leverage": "High",
                "viability": "High",
                "terrain": "Cloud",
                "actors": ["G1028"],
                "killchain": ["Reconnaissance"],
                "att&ck": ["T1589"],
            },
        }
    )

    criticality = render_criticality(threat, formatter)
    terrain = render_terrain(threat.threat, formatter)
    assessment = render_threat_assessment(threat.threat, formatter)
    actors = render_actors(threat.threat, formatter)
    techniques = render_attack_techniques(threat.threat.att_ck, formatter)

    assert "## Criticality" in criticality
    assert "## Terrain" in terrain
    assert "> **Cloud Services**" in terrain or "> **Cloud**" in terrain
    assert "## Threat Assessment" in assessment
    assert "Kill Chain" in assessment
    assert "## Actors" in actors
    assert "G1028" in actors
    assert "## ATT&CK Techniques" in techniques
    assert "Gather Victim Identity Information" in techniques


def test_render_signal_mdr_coverage_uses_fw_relations(
    monkeypatch, metadata: dict[str, Any]
) -> None:
    formatter = formatter_for(DocumentFlavor.github)
    objective = load_objective_from_dict(_objective_payload(metadata))

    monkeypatch.setattr(
        "opentide.documentation.parts.sections.fw.childs",
        lambda _signal_uuid: ["00000000-0000-4000-8000-000000000031"],
    )
    monkeypatch.setattr(
        "opentide.documentation.parts.sections.fw.get_type",
        lambda uuid, mute=True: (
            "signal" if uuid == "00000000-0000-4000-8000-000000000021" else "rule"
        ),
    )
    monkeypatch.setattr(
        "opentide.documentation.parts.sections.fw.relations_list",
        lambda _signal_uuid, mode="flat", direction="downstream": {
            "rule": [
                "00000000-0000-4000-8000-000000000031",
                "00000000-0000-4000-8000-000000000032",
            ]
        },
    )

    coverage = render_signal_mdr_coverage(
        objective,
        formatter,
        resolve_name=lambda uuid: f"Rule {uuid[-4:]}",
    )

    assert "## Signal MDR coverage" in coverage
    assert "| Signal | Downstream MDR rules |" in coverage
    assert "Rule 0031" in coverage
    assert "Rule 0032" in coverage
