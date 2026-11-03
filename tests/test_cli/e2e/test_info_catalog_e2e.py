"""CLI E2E: ``opentide --json info catalog`` on the tide_corpus workspace (#749)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from tests.corpus_support import (
    CORPUS_OBJECTIVE_UUID,
    CORPUS_RULE_UUIDS,
    CORPUS_THREAT_UUID,
    TIDE_CORPUS_ROOT,
)
from tests.test_cli.conftest import assert_json_ok, parse_cli_json

pytestmark = pytest.mark.cli_e2e

SECOND_THREAT = "00000000-0000-4000-8001-000000000749"
MISSING_THREAT = "00000000-0000-4000-8001-0000000dead1"
CHILD_SIGNAL = "00000000-0000-4000-8099-000000000749"
SIGNAL_RULE = "00000000-0000-4000-8003-000000000749"
DANGLING_RULE = "00000000-0000-4000-8003-000000000750"
MISSING_OBJECTIVE = "00000000-0000-4000-8002-0000000dead2"
BROKEN_UUID = "00000000-0000-4000-8003-000000000751"
DEFENDER_RULE = CORPUS_RULE_UUIDS["defender_for_endpoint"]

THREAT_DIR = "Objects/Threat Vectors"
OBJECTIVE_DIR = "Objects/Detection Objectives"
RULE_DIR = "Objects/Detection Rules"


def _rule_text(uuid: str, name: str, detection_model: str) -> str:
    source = TIDE_CORPUS_ROOT / RULE_DIR / "rule-0001-sentinel-kql.yaml"
    return (
        source.read_text(encoding="utf-8")
        .replace(CORPUS_RULE_UUIDS["sentinel"], uuid)
        .replace("name: Sentinel KQL Rule", f"name: {name}")
        .replace(f"detection_model: {CORPUS_OBJECTIVE_UUID}", f"detection_model: {detection_model}")
        .replace("  - T1059\n", "  - T1003.001\n")
    )


def _extend_corpus(repo: Path) -> None:
    """Add one object per edge kind the corpus lacks, a load error and a deployment binding."""
    threat = (repo / THREAT_DIR / "threat-0001-simulated-actor.yaml").read_text(encoding="utf-8")
    second = (
        threat.replace(CORPUS_THREAT_UUID, SECOND_THREAT)
        .replace("name: Simulated Actor", "name: Follow-up Actor")
        .replace("    - T1059\n", "    - T1003\n")
    )
    second += (
        "  chaining:\n"
        f"    - relation: sequence::preceeds\n      vector: {CORPUS_THREAT_UUID}\n"
        f"    - relation: sequence::succeeds\n      vector: {MISSING_THREAT}\n"
    )
    (repo / THREAT_DIR / "threat-0749-follow-up-actor.yaml").write_text(second, encoding="utf-8")

    objective_path = repo / OBJECTIVE_DIR / "objective-0001-credential-access.yaml"
    objective = objective_path.read_text(encoding="utf-8")
    objective = objective.replace(
        "        requirements: Security event logs\n",
        "        requirements: Security event logs\n"
        "        logsources:\n"
        "          - Windows Security Events\n"
        f"    - name: Child signal\n"
        f"      uuid: {CHILD_SIGNAL}\n"
        "      description: Narrower authentication activity\n"
        "      severity: Medium\n"
        "      methodology: Statistical\n"
        "      parent: 00000000-0000-4000-8099-000000000001\n"
        "      entities:\n"
        "        - Host::Hostname\n"
        "      data:\n"
        "        availability: Complete\n"
        "        requirements: Security event logs\n",
    )
    objective_path.write_text(objective, encoding="utf-8")

    rules = repo / RULE_DIR
    (rules / "rule-0749-signal.yaml").write_text(
        _rule_text(SIGNAL_RULE, "Signal Rule", CHILD_SIGNAL), encoding="utf-8"
    )
    (rules / "rule-0750-dangling.yaml").write_text(
        _rule_text(DANGLING_RULE, "Dangling Rule", MISSING_OBJECTIVE), encoding="utf-8"
    )
    (rules / "rule-0751-broken.yaml").write_text(
        f"name: Broken Rule\n\nmetadata:\n  uuid: {BROKEN_UUID}\n  schema: rule::1.0\n"
        "techniques: [T1059\n",
        encoding="utf-8",
    )
    shards = repo / ".opentide" / "states" / "deployment"
    shards.mkdir(parents=True)
    shard = {
        "schema": "deployment.state::1.0",
        "object_uuid": DEFENDER_RULE,
        "platforms": {"defender_for_endpoint": {"prod": "4242"}},
    }
    (shards / f"{DEFENDER_RULE}.json").write_text(json.dumps(shard), encoding="utf-8")


@pytest.fixture
def catalog(invoke_cli, tide_corpus_repo: Path) -> dict[str, Any]:
    _extend_corpus(tide_corpus_repo)
    return assert_json_ok(invoke_cli("info", "catalog"))


def _edges(document: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [edge for edge in document["edges"] if edge["kind"] == kind]


def _object(document: dict[str, Any], uuid: str) -> dict[str, Any]:
    return next(row for row in document["objects"] if row["uuid"] == uuid)


def test_catalog_lists_every_object_with_its_location(
    catalog: dict[str, Any], tide_corpus_repo: Path
) -> None:
    rule = _object(catalog, CORPUS_RULE_UUIDS["sentinel"])
    assert rule["type"] == "rule"
    assert rule["schema"] == "rule::1.0"
    assert rule["name"] == "Sentinel KQL Rule"
    assert rule["path"] == f"{RULE_DIR}/rule-0001-sentinel-kql.yaml"
    assert Path(rule["file_path"]).is_absolute()
    assert Path(rule["file_path"]).read_text(encoding="utf-8").splitlines()[rule["line"] - 1] == (
        "name: Sentinel KQL Rule"
    )
    assert rule["tlp"] == "clear"
    assert rule["created"] == "2026-01-01"
    assert rule["platforms"] == [
        {"id": "sentinel", "enabled": True, "status": "STAGING", "strategy": "PREVIEW"}
    ]
    assert rule["techniques"] == {"own": ["T1059"], "inherited": []}
    assert rule["tactics"] == ["execution"]
    assert rule["actors"] == ["att&ck::G0006"]
    assert rule["load_error"] is None
    summary = catalog["summary"]
    assert summary["threats"] == 2 and summary["objectives"] == 1
    assert summary["rules"] == 12  # the corpus ten, and two added here
    assert summary["signals"] == 2
    assert summary["edges"] == len(catalog["edges"])
    assert summary["objects"] == len(catalog["objects"])


def test_catalog_has_every_edge_kind(catalog: dict[str, Any]) -> None:
    covers = _edges(catalog, "covers")
    assert {
        "from": CORPUS_OBJECTIVE_UUID,
        "to": CORPUS_THREAT_UUID,
        "kind": "covers",
        "field_path": "objective.threats",
        "relation": None,
        "missing": False,
    } in covers
    implements = {
        (edge["from"], edge["to"], edge["missing"]) for edge in _edges(catalog, "implements")
    }
    assert (CORPUS_RULE_UUIDS["sentinel"], CORPUS_OBJECTIVE_UUID, False) in implements
    assert (SIGNAL_RULE, CHILD_SIGNAL, False) in implements
    assert (DANGLING_RULE, MISSING_OBJECTIVE, True) in implements
    [parent] = _edges(catalog, "parent")
    assert parent["from"] == CHILD_SIGNAL
    assert parent["to"] == "00000000-0000-4000-8099-000000000001"
    assert parent["field_path"] == "objective.signals.1.parent"
    assert parent["missing"] is False
    chains = {
        (edge["from"], edge["to"], edge["relation"], edge["missing"])
        for edge in _edges(catalog, "chains")
    }
    assert chains == {
        (SECOND_THREAT, CORPUS_THREAT_UUID, "sequence::preceeds", False),
        (SECOND_THREAT, MISSING_THREAT, "sequence::succeeds", True),
    }
    techniques = {
        (edge["from"], edge["to"], edge["field_path"]) for edge in _edges(catalog, "technique")
    }
    assert (CORPUS_THREAT_UUID, "T1059", "threat.mitre_attack") in techniques
    assert (SIGNAL_RULE, "T1003.001", "techniques") in techniques
    [logsource] = _edges(catalog, "logsource")
    assert logsource["from"] == "00000000-0000-4000-8099-000000000001"
    assert logsource["to"] == "Windows Security Events"
    assert logsource["field_path"] == "objective.signals.0.data.logsources"
    # Only object references can dangle.
    assert not any(edge["missing"] for edge in _edges(catalog, "technique"))


def test_catalog_signals_and_inherited_techniques(catalog: dict[str, Any]) -> None:
    signals = {row["uuid"]: row for row in catalog["signals"]}
    assert signals[CHILD_SIGNAL] == {
        "uuid": CHILD_SIGNAL,
        "name": "Child signal",
        "objective": CORPUS_OBJECTIVE_UUID,
        "parent": "00000000-0000-4000-8099-000000000001",
    }
    # Signals are edge endpoints, not object rows.
    assert CHILD_SIGNAL not in {row["uuid"] for row in catalog["objects"]}
    rule = _object(catalog, SIGNAL_RULE)
    assert rule["techniques"] == {"own": ["T1003.001"], "inherited": ["T1059"]}
    assert rule["tactics"] == ["execution", "credential-access"]
    objective = _object(catalog, CORPUS_OBJECTIVE_UUID)
    assert objective["techniques"] == {"own": [], "inherited": ["T1059"]}
    dangling = _object(catalog, DANGLING_RULE)
    assert dangling["techniques"]["inherited"] == []


def test_catalog_reports_deployment_state(catalog: dict[str, Any]) -> None:
    assert _object(catalog, DEFENDER_RULE)["deployment"] == [
        {"platform": "defender_for_endpoint", "tenant": "prod", "deployed": True, "rule_id": "4242"}
    ]
    assert _object(catalog, CORPUS_RULE_UUIDS["sentinel"])["deployment"] == []


def test_catalog_keeps_a_file_that_failed_to_load(catalog: dict[str, Any]) -> None:
    broken = _object(catalog, BROKEN_UUID)
    assert broken["path"] == f"{RULE_DIR}/rule-0751-broken.yaml"
    assert broken["name"] == "Broken Rule"
    assert broken["type"] == "rule"
    assert broken["schema"] == "rule::1.0"
    assert broken["line"] == 1
    error = broken["load_error"]
    assert error["code"] == "yaml_parse"
    assert error["message"]
    assert error["line"] == 7
    assert catalog["summary"]["load_errors"] == 1
    assert catalog["status"] == "issues"


def test_catalog_attack_skeleton(catalog: dict[str, Any]) -> None:
    attack = catalog["attack"]
    tactics = attack["tactics"]
    assert [tactic["shortname"] for tactic in tactics][:3] == [
        "reconnaissance",
        "resource-development",
        "initial-access",
    ]
    credential = next(tactic for tactic in tactics if tactic["id"] == "TA0006")
    assert credential["shortname"] == "credential-access"
    assert credential["name"] == "Credential Access"
    assert "T1003" in credential["techniques"]
    assert "T1003.001" not in credential["techniques"]
    techniques = attack["techniques"]
    assert techniques["T1003"]["name"] == "OS Credential Dumping"
    assert techniques["T1003"]["parent"] is None
    assert "T1003.001" in techniques["T1003"]["subtechniques"]
    assert techniques["T1003.001"] == {
        "name": "LSASS Memory",
        "parent": "T1003",
        "subtechniques": [],
    }
    # Enterprise only.
    assert not any(row["name"].startswith("Mobile : ") for row in techniques.values())


def test_info_catalog_human_summary(cli_runner, tide_corpus_repo: Path) -> None:
    from opentide.cli import app

    _extend_corpus(tide_corpus_repo)
    result = cli_runner.invoke(
        app, ["--no-color", "--repo", str(tide_corpus_repo), "info", "catalog"]
    )
    assert result.exit_code == 0, result.stdout
    rows = [" ".join(line.split()) for line in result.stdout.splitlines()]
    assert any(row.startswith("objects ") and "2 threats" in row for row in rows)
    assert "edges 31" in rows
    assert "2 chains" in rows
    assert "2 missing: name no object" in rows
    assert "load errors 1" in rows


def test_info_catalog_is_listed_as_a_section(invoke_cli) -> None:
    """The extension finds the catalogue in ``opentide --json commands``."""
    document = parse_cli_json(invoke_cli("commands"))
    info = next(command for command in document["commands"] if command["path"] == "info")
    section = next(argument for argument in info["arguments"] if argument["name"] == "section")
    assert "catalog" in section["choices"]


TWO_THREATS = "00000000-0000-4000-8002-000000000752"
SCALAR_OBJECTIVE = "00000000-0000-4000-8002-000000000753"
SCALAR_THREAT = "00000000-0000-4000-8001-000000000753"
TWO_THREATS_RULE = "00000000-0000-4000-8003-000000000752"
SCALAR_RULE = "00000000-0000-4000-8003-000000000753"
SCALAR_SIGNAL = "00000000-0000-4000-8099-000000000753"


def _objective_text(uuid: str, name: str, threats: str, signal: str) -> str:
    source = TIDE_CORPUS_ROOT / OBJECTIVE_DIR / "objective-0001-credential-access.yaml"
    return (
        source.read_text(encoding="utf-8")
        .replace(CORPUS_OBJECTIVE_UUID, uuid)
        .replace("name: Credential Access Objective", f"name: {name}")
        .replace(f"  threats:\n    - {CORPUS_THREAT_UUID}\n", threats)
        .replace("00000000-0000-4000-8099-000000000001", signal)
    )


def _add_inheritance_objects(repo: Path) -> None:
    """An objective over one live and one dangling threat, and one written with scalars."""
    threat = (repo / THREAT_DIR / "threat-0001-simulated-actor.yaml").read_text(encoding="utf-8")
    scalar_threat = (
        threat.replace(CORPUS_THREAT_UUID, SCALAR_THREAT)
        .replace("name: Simulated Actor", "name: Scalar Actor")
        .replace("  mitre_attack:\n    - T1059\n", "  mitre_attack: T1003\n")
    )
    (repo / THREAT_DIR / "threat-0753-scalar.yaml").write_text(scalar_threat, encoding="utf-8")
    objectives = repo / OBJECTIVE_DIR
    (objectives / "objective-0752-two-threats.yaml").write_text(
        _objective_text(
            TWO_THREATS,
            "Two threats",
            f"  threats:\n    - {CORPUS_THREAT_UUID}\n    - {MISSING_THREAT}\n"
            f"    - {SCALAR_THREAT}\n",
            "00000000-0000-4000-8099-000000000752",
        ),
        encoding="utf-8",
    )
    scalar = _objective_text(
        SCALAR_OBJECTIVE, "Scalar objective", f"  threats: {SCALAR_THREAT}\n", SCALAR_SIGNAL
    ).replace(
        "        requirements: Security event logs\n",
        "        requirements: Security event logs\n        logsources: Windows\n",
    )
    (objectives / "objective-0753-scalar.yaml").write_text(scalar, encoding="utf-8")
    rules = repo / RULE_DIR
    (rules / "rule-0752-two-threats.yaml").write_text(
        _rule_text(TWO_THREATS_RULE, "Two threats rule", TWO_THREATS), encoding="utf-8"
    )
    (rules / "rule-0753-scalar.yaml").write_text(
        _rule_text(SCALAR_RULE, "Scalar rule", SCALAR_SIGNAL), encoding="utf-8"
    )


def test_a_dangling_threat_keeps_the_other_threats_techniques(
    invoke_cli, tide_corpus_repo: Path
) -> None:
    _add_inheritance_objects(tide_corpus_repo)
    catalog = assert_json_ok(invoke_cli("info", "catalog"))
    objective = _object(catalog, TWO_THREATS)
    assert objective["techniques"] == {"own": [], "inherited": ["T1059", "T1003"]}
    assert set(objective["tactics"]) >= {"execution", "credential-access"}
    rule = _object(catalog, TWO_THREATS_RULE)
    assert rule["techniques"]["inherited"] == ["T1059", "T1003"]
    covers = {(edge["to"], edge["missing"]) for edge in _edges(catalog, "covers")}
    assert (MISSING_THREAT, True) in covers


def test_a_scalar_where_a_list_belongs_is_one_item(invoke_cli, tide_corpus_repo: Path) -> None:
    _add_inheritance_objects(tide_corpus_repo)
    catalog = assert_json_ok(invoke_cli("info", "catalog"))
    covers = [edge for edge in _edges(catalog, "covers") if edge["from"] == SCALAR_OBJECTIVE]
    assert [(edge["to"], edge["missing"]) for edge in covers] == [(SCALAR_THREAT, False)]
    logsources = [edge for edge in _edges(catalog, "logsource") if edge["from"] == SCALAR_SIGNAL]
    assert [edge["to"] for edge in logsources] == ["Windows"]
    assert _object(catalog, SCALAR_OBJECTIVE)["techniques"]["inherited"] == ["T1003"]
    assert _object(catalog, SCALAR_RULE)["techniques"]["inherited"] == ["T1003"]
    assert _object(catalog, SCALAR_THREAT)["techniques"]["own"] == ["T1003"]


def test_a_file_whose_uuid_another_uses_keeps_a_row(invoke_cli, tide_corpus_repo: Path) -> None:
    rules = tide_corpus_repo / RULE_DIR
    original = rules / "rule-0002-defender-kql.yaml"
    copy = rules / "rule-zz-copy.yaml"
    copy.write_text(
        original.read_text(encoding="utf-8").replace("name: ", "name: Copied ", 1),
        encoding="utf-8",
    )
    result = invoke_cli("info", "catalog")
    catalog = parse_cli_json(result)
    paths = {row["path"] for row in catalog["objects"]}
    assert f"{RULE_DIR}/rule-0002-defender-kql.yaml" in paths
    assert f"{RULE_DIR}/rule-zz-copy.yaml" in paths
    [duplicate] = [
        row for row in catalog["objects"] if row["load_error"] and row["uuid"] == DEFENDER_RULE
    ]
    assert duplicate["load_error"]["code"] == "duplicate_id"
    assert "rule-zz-copy.yaml" in duplicate["load_error"]["message"]
    assert catalog["summary"]["load_errors"] == 1
    assert catalog["status"] == "issues"


def test_a_signal_parent_that_is_not_a_string_is_null_and_the_document_valid(
    invoke_cli, tide_corpus_repo: Path
) -> None:
    import jsonschema

    objective_path = tide_corpus_repo / OBJECTIVE_DIR / "objective-0001-credential-access.yaml"
    text = objective_path.read_text(encoding="utf-8")
    objective_path.write_text(
        text.replace(
            "      methodology: Statistical\n",
            "      methodology: Statistical\n"
            "      parent:\n        - 00000000-0000-4000-8099-000000000009\n",
            1,
        ),
        encoding="utf-8",
    )
    catalog = parse_cli_json(invoke_cli("info", "catalog"))
    [signal] = catalog["signals"]
    assert signal["parent"] is None
    commands = parse_cli_json(invoke_cli("commands"))
    entry = next(command for command in commands["commands"] if command["path"] == "info")
    jsonschema.validate(catalog, {**entry["output_schema"], "$defs": commands["$defs"]})
