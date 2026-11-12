"""Section bodies of the three object pages (``documentation.parts``)."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from opentide.documentation.catalog import DocumentationCatalog
from opentide.documentation.format.factory import formatter_for
from opentide.documentation.parts.common import (
    Links,
    attack_table,
    metadata_table,
    references_body,
)
from opentide.documentation.parts.objective import (
    overview as objective_overview,
)
from opentide.documentation.parts.objective import (
    signal_sections,
    signals_summary,
)
from opentide.documentation.parts.rule import (
    configuration_sections,
    response_body,
)
from opentide.documentation.parts.threat import (
    actors_table,
    assessment_table,
    chaining_table,
    cve_body,
    surface_table,
)
from opentide.documentation.types import DocumentFlavor, DocumentRecord, DocumentScope
from opentide.documentation.vocabulary import EnrichedEntry
from opentide.documentation.vocabulary import enrich as enrich_vocab
from opentide.generation import framework as fw
from opentide.loading.objective_loader import load_objective_from_dict
from opentide.models.metadata import ObjectMetadata, ObjectReferences
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatVector
from opentide.vulnerability_lookup import CveSettings, VulnerabilityLookupError, VulnerabilityRecord

GITHUB = formatter_for(DocumentFlavor.github)


def _links(catalog: DocumentationCatalog | None = None, folder: str = "rules") -> Links:
    return Links(GITHUB, catalog or DocumentationCatalog([], [], []), folder)


def _threat(metadata: dict[str, Any], **body: Any) -> ThreatVector:
    return ThreatVector.from_yaml_dict(
        {
            "name": "Threat",
            "criticality": "High",
            "metadata": {**metadata, "schema": "threat::1.0"},
            "threat": {
                "description": "Ransomware",
                "severity": "High",
                "impact": ["Data Breach"],
                "leverage": ["High"],
                "viability": "High",
                "terrain": "Endpoint workstations.",
                "surface": ["OS::Windows::Desktop"],
                "mitre_attack": ["T1486"],
                **body,
            },
        }
    )


def _objective_payload(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": "Objective",
        "metadata": {**metadata, "schema": "objective::1.0"},
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


def test_metadata_table_starts_with_the_uuid_row(metadata: dict[str, Any]) -> None:
    rendered = metadata_table(ObjectMetadata.model_validate(metadata), GITHUB)
    # publish.prune recognises a generated page by this exact row.
    assert rendered.splitlines()[2] == f"| UUID | `{metadata['uuid']}` |"
    assert "| TLP | clear (`TLP:CLEAR`) |" in rendered
    assert "Author" not in rendered


def test_metadata_table_includes_optional_authoring_fields() -> None:
    metadata = ObjectMetadata.model_validate(
        {
            "uuid": "00000000-0000-4000-8000-000000000001",
            "schema": "rule::1.0",
            "version": "2.1.0",
            "created": "2026-01-01",
            "modified": "2026-01-03",
            "tlp": "amber",
            "author": "opentide Team",
            "contributors": ["Alice", "Bob"],
            "organisation": {"uuid": "00000000-0000-4000-8000-000000000123", "name": "opentidehq"},
        }
    )
    rendered = metadata_table(metadata, GITHUB)
    assert "| Author | opentide Team |" in rendered
    assert "| Contributors | Alice, Bob |" in rendered
    assert "opentidehq (`00000000-0000-4000-8000-000000000123`)" in rendered


def test_references_are_one_table_of_every_group() -> None:
    references = ObjectReferences.model_validate(
        {
            "public": {1: "https://example.com/advisory"},
            "internal": {"IR-123": "wiki page | draft"},
            "reports": ["https://example.com/report"],
        }
    )
    rendered = references_body(references, GITHUB)
    assert rendered.splitlines()[0] == "| Kind | Key | Reference |"
    assert (
        "| Public | 1 | [https://example.com/advisory](https://example.com/advisory) |" in rendered
    )
    assert "| Internal | IR-123 | wiki page \\| draft |" in rendered
    assert "| Report | - | [https://example.com/report]" in rendered
    assert references_body(None, GITHUB) == ""


def test_attack_table_shows_tactics_and_a_one_sentence_summary() -> None:
    rendered = attack_table(["T1059", "T1059"], GITHUB)
    assert rendered.count("T1059") == 2  # link text and URL, the duplicate dropped
    row = rendered.splitlines()[2]
    assert "Command and Scripting Interpreter" in row
    assert "| Execution |" in row
    assert "(Citation:" not in rendered
    assert attack_table([], GITHUB) == ""


def _sentinel_rule(metadata: dict[str, Any], **extra: Any) -> DetectionRule:
    return DetectionRule.from_yaml_dict(
        {
            "name": "Rule on two platforms",
            "metadata": {**metadata, "schema": "rule::1.0"},
            "description": "desc",
            "configurations": {
                "elastic": {
                    "enabled": True,
                    "schema": "platform::elastic::1.0",
                    "status": "STAGING",
                    "type": "eql",
                    "query": 'process where process.name == "powershell.exe"',
                    "index": ["logs-*"],
                },
                "sentinel": {
                    "enabled": True,
                    "name": "Rule on two platforms",
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
                },
            },
            **extra,
        }
    )


def test_platform_sections_document_every_setting_in_model_order(
    metadata: dict[str, Any],
) -> None:
    """Elastic was missing from every rule page, and most block settings from all of them."""
    sections = configuration_sections(_sentinel_rule(metadata), GITHUB)
    assert [section.title for section in sections] == ["Microsoft Sentinel", "Elastic Security"]
    sentinel, elastic = (section.body for section in sections)
    assert "**`query`** (KQL)\n\n```kql\nSecurityEvent | take 1\n```" in sentinel
    assert sentinel.startswith("Status `STAGING`\n")
    assert "| `alert.title` | Sentinel alert |" in sentinel
    assert "| `scheduling.lookback` | `PT2H` |" in sentinel
    assert "| `grouping.event` | `SingleAlert` |" in sentinel
    assert "**`entities[0].mappings`**" in sentinel
    assert "| `Name` | `AccountName` |" in sentinel
    assert "`status`" not in sentinel  # in the deployment table instead
    assert "```eql\nprocess where" in elastic
    assert "| `index` | `logs-*` |" in elastic


def test_response_body_lists_procedure_and_searches(metadata: dict[str, Any]) -> None:
    rule = DetectionRule.from_yaml_dict(
        {
            "name": "Rule with response",
            "metadata": {**metadata, "schema": "rule::1.0"},
            "description": "d",
            "response": {
                "alert_severity": "High",
                "playbook": "PB-IR-001",
                "procedure": {
                    "analysis": "Review contextual indicators.",
                    "containment": "Disable tokens.",
                    "searches": [
                        {"purpose": "Corroborate", "system": "Sentinel", "query": "AuditLogs"}
                    ],
                },
            },
        }
    )
    rendered = response_body(rule, GITHUB)
    assert "| Alert severity | High |" in rendered
    assert "| Playbook | PB-IR-001 |" in rendered
    assert "**Analysis**\n\nReview contextual indicators." in rendered
    assert "**Containment**\n\nDisable tokens." in rendered
    assert "**Search: Corroborate** (Sentinel, KQL)\n\n```kql\nAuditLogs\n```" in rendered
    bare = DetectionRule.from_yaml_dict({**rule.model_dump(by_alias=True), "response": None})
    assert response_body(bare, GITHUB) == ""


def test_objective_priority_is_not_looked_up_as_criticality(
    metadata: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Alert-style priority (Critical) is not a criticality::1.0 token (#204)."""
    lookups: list[tuple[str, str]] = []

    def _spy(vocab: str, key: str) -> EnrichedEntry:
        lookups.append((vocab, key))
        return enrich_vocab(vocab, key)

    monkeypatch.setattr("opentide.documentation.parts.objective.enrich", _spy)
    payload = _objective_payload(metadata)
    payload["objective"]["priority"] = "Critical"
    objective = load_objective_from_dict(payload)
    catalog = MagicMock(spec=DocumentationCatalog)
    catalog.rules = []
    catalog.rules_for_signal.return_value = []
    rendered = objective_overview(objective, _links(catalog, "objectives"))
    assert "| Priority | Critical |" in rendered
    assert "| Investment | Medium |" in rendered
    assert ("criticality", "Critical") not in lookups


def test_signal_sections_keep_the_signal_name_as_their_heading(metadata: dict[str, Any]) -> None:
    objective = load_objective_from_dict(_objective_payload(metadata))
    catalog = MagicMock(spec=DocumentationCatalog)
    catalog.rules_for_signal.return_value = []
    (signal,) = signal_sections(objective, _links(catalog, "objectives"))
    # Rule pages link to this heading's anchor.
    assert signal.title == "Exec signal"
    assert "- **Data:** Complete. logs\n" in signal.body
    assert "- **Log sources:** `MDE DeviceProcessEvents`\n" in signal.body
    assert "- **Implemented by:** *no rule yet*\n" in signal.body
    assert "- **UUID:** `00000000-0000-4000-8000-000000000021`" in signal.body
    assert "| Sentinel KQL baseline | Microsoft Sentinel |" in signal.body
    assert "1. Baseline suspicious process lineage query." in signal.body
    assert "```sql\nDeviceProcessEvents\n| take 1\n```" in signal.body


def test_signals_summary_lists_each_signal_its_rules_and_platforms(
    metadata: dict[str, Any],
) -> None:
    objective = load_objective_from_dict(_objective_payload(metadata))
    rule = _sentinel_rule(metadata)
    record = DocumentRecord(DocumentScope.rules, "rule-1", rule.name, rule)
    catalog = MagicMock(spec=DocumentationCatalog)
    catalog.rules = [record]
    catalog.rules_for_signal.return_value = ["rule-1", "unknown-rule"]
    catalog.resolve_record.side_effect = lambda uuid: record if uuid == "rule-1" else None
    catalog.resolve_signal.return_value = None
    catalog.resolve_name.side_effect = lambda uuid: uuid
    rendered = signals_summary(objective, _links(catalog, "objectives"))
    assert rendered.splitlines()[0] == (
        "| Signal | Severity | Methodology | Effort | Rules | Platforms and status |"
    )
    # The signal links to its own heading below the table.
    assert "| [Exec signal](#exec-signal) | High |" in rendered
    assert "| 3 |" in rendered
    assert (
        "[Rule on two platforms](../rules/rule-on-two-platforms.md)<br>`unknown-rule`" in rendered
    )
    assert "Microsoft Sentinel `STAGING`<br>Elastic Security `STAGING`<br>-" in rendered


def test_surface_table_and_chaining_table(metadata: dict[str, Any]) -> None:
    threat = _threat(
        metadata,
        surface=["Azure"],
        chaining=[
            {"vector": "00000000-0000-4000-8101-000000000099", "relation": "succeeds"},
            {"relation": "preceeds"},
        ],
    )
    assert "| Azure | Microsoft Azure cloud platform |" in surface_table(threat.threat, GITHUB)
    catalog = MagicMock(spec=DocumentationCatalog)
    catalog.resolve_signal.return_value = None
    catalog.resolve_record.return_value = None
    catalog.resolve_name.side_effect = lambda uuid: "Follow-up"
    rendered = chaining_table(threat, _links(catalog, "threats"))
    assert rendered.splitlines()[0] == "| Relation | Threat vector | Family | Meaning |"
    assert (
        "| `succeeds` | Follow-up (`00000000-0000-4000-8101-000000000099`) | sequence |" in rendered
    )
    assert len(rendered.splitlines()) == 3  # the entry without a target is skipped


def test_render_threat_assessment_keeps_impact_vocab_spelling(
    metadata: dict[str, Any],
) -> None:
    """Catalogue tokens match impact::1.0, including the historical Impairement spelling."""
    threat = ThreatVector.from_yaml_dict(
        {
            "name": "Threat",
            "criticality": "High",
            "metadata": {**metadata, "schema": "threat::1.0"},
            "threat": {
                "description": "Service disruption",
                "severity": "High",
                "impact": ["Impairement"],
                "leverage": ["High"],
                "viability": "High",
                "terrain": "Endpoint workstations.",
                "surface": ["OS::Windows::Desktop"],
                "mitre_attack": ["T1486"],
            },
        }
    )
    rendered = assessment_table(threat.threat, formatter_for(DocumentFlavor.github))
    assert "Impairement" in rendered
    assert "Impairment" not in rendered


def test_render_threat_assessment_lists_every_impact_and_leverage_name(
    metadata: dict[str, Any],
) -> None:
    threat = ThreatVector.from_yaml_dict(
        {
            "name": "Threat",
            "criticality": "High",
            "metadata": {**metadata, "schema": "threat::1.0"},
            "threat": {
                "description": "Credential theft",
                "severity": "Significant incident",
                "impact": ["Data Breach", "Identity Theft"],
                "leverage": ["Elevation of privilege", "Repudiation"],
                "viability": "Likely",
                "terrain": "Endpoint workstations.",
                "surface": ["OS::Windows::Desktop"],
                "mitre_attack": ["T1059"],
            },
        }
    )
    rows = {
        line.split(" | ")[0].lstrip("| "): line
        for line in assessment_table(
            threat.threat, formatter_for(DocumentFlavor.github)
        ).splitlines()
        if line.startswith("| ")
    }
    assert "| Data Breach<br>Identity Theft | Non-public information" in rows["Impact"]
    assert rows["Impact"].count("<br>") == 2
    assert "| Elevation of privilege<br>Repudiation | Capacity to augment" in rows["Leverage"]
    assert rows["Leverage"].count("<br>") == 2


def _actor_source_cells(metadata: dict[str, Any], *actors: str) -> dict[str, str]:
    threat = ThreatVector.from_yaml_dict(
        {
            "name": "Threat",
            "criticality": "High",
            "metadata": {**metadata, "schema": "threat::1.0"},
            "threat": {
                "description": "Credential theft",
                "severity": "Significant incident",
                "impact": ["Data Breach"],
                "leverage": ["Elevation of privilege"],
                "viability": "Likely",
                "terrain": "Endpoint workstations.",
                "surface": ["OS::Windows::Desktop"],
                "actors": [{"name": actor} for actor in actors],
                "mitre_attack": ["T1059"],
            },
        }
    )
    rendered = actors_table(threat.threat, formatter_for(DocumentFlavor.github))
    rows = [
        [cell.strip() for cell in re.split(r"(?<!\\)\|", line)[1:-1]]
        for line in rendered.splitlines()
        if line.startswith("| ")
    ]
    assert rows[0] == ["Actor", "ID", "Source", "Description"]
    return {actor_id.strip("`"): source for _, actor_id, source, _ in rows[2:]}


@pytest.mark.parametrize(
    ("actor", "source"),
    [
        ("att&ck::G0006", "att&ck"),
        ("misp::1cb7e1cc-d695-42b1-92f4-fd0112a3c9be", "misp"),
    ],
)
def test_render_actors_source_is_the_actor_stage(
    metadata: dict[str, Any], actor: str, source: str
) -> None:
    """The vocabulary stores ``tide.vocab.stages`` as a tuple; the cell is its text (#296)."""
    assert _actor_source_cells(metadata, actor) == {actor: source}


@pytest.mark.parametrize(
    ("make_stages", "source"),
    [
        (lambda: ("att&ck",), "att&ck"),
        (lambda: ("att&ck", "misp"), "att&ck, misp"),
        (lambda: ["misp"], "misp"),
        (lambda: {"misp", "att&ck"}, "att&ck, misp"),
        (lambda: frozenset({"misp", "att&ck"}), "att&ck, misp"),
        (lambda: (stage for stage in ("att&ck", "misp")), "att&ck, misp"),
        (lambda: ("att&ck", None, ""), "att&ck"),
        (lambda: (), "-"),
        (lambda: "", "-"),
        (lambda: None, "-"),
    ],
    ids=[
        "tuple",
        "tuple-of-two",
        "list",
        "set",
        "frozenset",
        "generator",
        "blank-items",
        "empty-tuple",
        "empty-string",
        "none",
    ],
)
def test_render_actors_source_joins_any_stages_collection(
    metadata: dict[str, Any], make_stages: Callable[[], object], source: str
) -> None:
    with patch.object(fw, "get_vocab_entry", side_effect=lambda *_, **__: make_stages()):
        cells = _actor_source_cells(metadata, "att&ck::G0006")
    assert cells == {"att&ck::G0006": source}


def test_render_cve_links_to_vulnerability_lookup() -> None:
    formatter = formatter_for(DocumentFlavor.github)
    settings = CveSettings(retrieve_details=False)
    with patch(
        "opentide.documentation.parts.threat.load_cve_settings",
        return_value=settings,
    ):
        rendered = cve_body(["CVE-2024-3094"], formatter, retrieve_details=False)
    assert "[CVE-2024-3094](https://vulnerability.circl.lu/vuln/CVE-2024-3094)" in rendered
    assert "CIRCL Vulnerability-Lookup" in rendered


def test_render_cve_enriches_from_lookup_client() -> None:
    formatter = formatter_for(DocumentFlavor.github)
    client = MagicMock()
    client.get.return_value = VulnerabilityRecord(
        identifier="CVE-2024-3094",
        title="Xz: malicious code in distributed source",
        description="Malicious code was discovered in xz.",
        published="2024-03-29",
        severity="CRITICAL (10)",
        aliases=("GHSA-rxwq-x6h5-x525",),
        page_url="https://vulnerability.circl.lu/vuln/CVE-2024-3094",
    )
    with (
        patch(
            "opentide.documentation.parts.threat.load_cve_settings",
            return_value=CveSettings(retrieve_details=True),
        ),
        patch("opentide.documentation.parts.threat.apply_cve_proxy_settings"),
    ):
        rendered = cve_body(["CVE-2024-3094"], formatter, client=client, retrieve_details=True)
    assert "| Identifier | Published | Severity | Summary |" in rendered
    assert "Xz: malicious code" in rendered
    assert "2024-03-29" in rendered
    assert "CRITICAL (10)" in rendered
    assert "GHSA-rxwq-x6h5-x525" in rendered
    assert "https://vulnerability.circl.lu/vuln/CVE-2024-3094" in rendered


def test_render_cve_maps_gcve0_link_to_cve_page() -> None:
    formatter = formatter_for(DocumentFlavor.github)
    settings = CveSettings(retrieve_details=False)
    with patch(
        "opentide.documentation.parts.threat.load_cve_settings",
        return_value=settings,
    ):
        rendered = cve_body(["GCVE-0-2024-3094"], formatter, retrieve_details=False)
    assert "[GCVE-0-2024-3094](https://vulnerability.circl.lu/vuln/CVE-2024-3094)" in rendered


def test_render_cve_dedupes_gcve0_and_cve_aliases() -> None:
    formatter = formatter_for(DocumentFlavor.github)
    settings = CveSettings(retrieve_details=False)
    with patch(
        "opentide.documentation.parts.threat.load_cve_settings",
        return_value=settings,
    ):
        rendered = cve_body(
            ["CVE-2024-3094", "GCVE-0-2024-3094"],
            formatter,
            retrieve_details=False,
        )
    assert rendered.count("[CVE-2024-3094]") == 1
    assert "GCVE-0-2024-3094" not in rendered


def test_render_cve_marks_missing_and_unreachable_identifiers() -> None:
    formatter = formatter_for(DocumentFlavor.github)
    client = MagicMock()
    client.get.side_effect = [
        None,
        VulnerabilityLookupError("offline"),
    ]
    with (
        patch(
            "opentide.documentation.parts.threat.load_cve_settings",
            return_value=CveSettings(retrieve_details=True),
        ),
        patch("opentide.documentation.parts.threat.apply_cve_proxy_settings"),
    ):
        rendered = cve_body(
            ["CVE-2024-BAD", "CVE-2024-3094"],
            formatter,
            client=client,
            retrieve_details=True,
        )
    assert "Not found in Vulnerability-Lookup." in rendered
    assert "Could not resolve: `CVE-2024-BAD`" in rendered
    assert "Details unavailable from Vulnerability-Lookup." in rendered
    assert "was unreachable" in rendered


def test_render_cve_empty_returns_nothing() -> None:
    formatter = formatter_for(DocumentFlavor.github)
    assert cve_body([], formatter) == ""
    assert cve_body(None, formatter) == ""
