"""The graph tool: the catalogue as threats, objectives and rules, and the gaps between them."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.corpus_support import (
    CORPUS_ACTOR,
    CORPUS_OBJECTIVE_UUID,
    CORPUS_RULE_UUIDS,
    CORPUS_THREAT_UUID,
    clear_runtime_caches,
)

from opentide.mcp_server import tools

# Objects added to tide_corpus to give the graph a chain and some gaps.
LATER_THREAT = "00000000-0000-4000-8001-0000000000a2"
ORPHAN_THREAT = "00000000-0000-4000-8001-0000000000a3"
IDLE_OBJECTIVE = "00000000-0000-4000-8002-0000000000a2"
SIGNAL = "00000000-0000-4000-8099-000000000001"  # the corpus objective's signal
SIGNAL_RULE = "00000000-0000-4000-8003-0000000000a2"

META = (
    "metadata:\n  uuid: {uuid}\n  schema: {schema}\n  version: 1\n"
    "  created: 2026-01-01\n  modified: 2026-01-02\n  tlp: clear\n"
)


def _threat(uuid: str, name: str, extra: str = "") -> str:
    return (
        f"name: {name}\ncriticality: High\n\n"
        + META.format(uuid=uuid, schema="threat::1.0")
        + "\nthreat:\n  description: Graph test threat.\n  severity: Substantial incident\n"
        "  viability: Likely\n  mitre_attack:\n    - T1003\n" + extra
    )


@pytest.fixture
def graph_repo(tide_corpus_repo: Path) -> Iterator[Path]:
    objects = tide_corpus_repo / "objects"
    # The corpus threat now precedes LATER_THREAT, which only IDLE_OBJECTIVE covers.
    corpus_threat = next((objects / "threats").glob("*.yaml"))
    corpus_threat.write_text(
        corpus_threat.read_text(encoding="utf-8")
        + f"  chaining:\n    - vector: {LATER_THREAT}\n      relation: sequence::preceeds\n",
        encoding="utf-8",
    )
    (objects / "threats" / "threat-a2.yaml").write_text(
        _threat(LATER_THREAT, "Credential dumping after the intrusion"), encoding="utf-8"
    )
    (objects / "threats" / "threat-a3.yaml").write_text(
        _threat(ORPHAN_THREAT, "Threat no objective covers"), encoding="utf-8"
    )
    (objects / "objectives" / "objective-a2.yaml").write_text(
        "name: Objective without rules\n\n"
        + META.format(uuid=IDLE_OBJECTIVE, schema="objective::1.0")
        + f"\nobjective:\n  priority: High\n  type: Threat\n  description: Idle.\n"
        f"  threats:\n    - {LATER_THREAT}\n",
        encoding="utf-8",
    )
    # A rule whose detection_model names a signal: it belongs to the signal's objective.
    (objects / "rules" / "rule-a2.yaml").write_text(
        "name: Rule on a signal\n\n"
        + META.format(uuid=SIGNAL_RULE, schema="rule::1.0")
        + f"\ndescription: Signal rule.\nseverity: High\ndetection_model: {SIGNAL}\n"
        "configurations:\n  splunk:\n    enabled: true\n    name: Rule on a signal\n"
        "    status: PRODUCTION\n",
        encoding="utf-8",
    )
    clear_runtime_caches()
    yield tide_corpus_repo
    clear_runtime_caches()


def test_full_graph_links_threats_objectives_and_rules(graph_repo: Path) -> None:
    full = tools.tool_graph("full")
    threats = {threat["uuid"]: threat for threat in full["threats"]}
    rules = {rule["uuid"]: rule for rule in full["rules"]}
    objectives = {objective["uuid"]: objective for objective in full["objectives"]}

    # As written: the view reads the family-scoped form and the bare one alike.
    assert threats[CORPUS_THREAT_UUID]["chaining"] == [
        {"to": LATER_THREAT, "relation": "sequence::preceeds"}
    ]
    assert {"name": "PRODUCTION", "strategy": "RELEASE"} in full["statuses"]
    # Actors as the threat writes them, with the vocabulary's name beside them.
    assert threats[CORPUS_THREAT_UUID]["actors"] == [CORPUS_ACTOR]
    assert full["actor_names"][CORPUS_ACTOR]
    assert objectives[CORPUS_OBJECTIVE_UUID]["threats"] == [CORPUS_THREAT_UUID]
    sentinel = rules[CORPUS_RULE_UUIDS["sentinel"]]
    assert sentinel["objective"] == CORPUS_OBJECTIVE_UUID
    assert sentinel["platforms"] == {"sentinel": "STAGING"}
    assert "T1059" in sentinel["techniques"]
    signal_rule = rules[SIGNAL_RULE]
    assert (signal_rule["objective"], signal_rule["signal"]) == (CORPUS_OBJECTIVE_UUID, SIGNAL)


def test_summary_names_every_kind_of_gap(graph_repo: Path) -> None:
    summary = tools.tool_graph()
    assert summary["counts"]["threats"] == 3
    assert summary["counts"]["chained_threats"] == 2

    def gap(key: str) -> list[str]:
        return [item["uuid"] for item in summary[key]["items"]]

    assert gap("threats_without_objectives") == [ORPHAN_THREAT]
    assert gap("threats_without_rules") == [LATER_THREAT]
    assert gap("objectives_without_rules") == [IDLE_OBJECTIVE]
    # Only SIGNAL_RULE is in production, and it covers the corpus threat.
    assert gap("threats_without_production_rules") == []
    assert summary["rule_blocks_by_platform"]["splunk"]["PRODUCTION"] == 1
    assert "threats" not in summary


def test_production_means_a_release_status_of_the_workspace(
    graph_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A workspace that releases from LIVE: PRODUCTION is then just a name, not production.
    monkeypatch.setattr(
        "opentide.mcp_server.catalog._configured_statuses",
        lambda: [{"name": "LIVE", "strategy": "RELEASE"}],
    )
    gaps = tools.tool_graph()["threats_without_production_rules"]
    assert [item["uuid"] for item in gaps["items"]] == [CORPUS_THREAT_UUID]


def test_summary_lists_are_capped_but_counted(
    graph_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("opentide.mcp_server.catalog.SUMMARY_LIST_LIMIT", 0)
    gaps = tools.tool_graph()["threats_without_objectives"]
    assert gaps == {"count": 1, "items": []}


def test_unknown_detail_is_an_error_not_an_exception(tide_corpus_repo: Path) -> None:
    assert tools.tool_graph("everything") == {
        "error": "Unknown detail 'everything'",
        "supported": ["summary", "full"],
    }
