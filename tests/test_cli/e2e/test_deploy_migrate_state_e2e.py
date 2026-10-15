"""CLI E2E: ``validate`` refuses vendor ids on rules; ``deploy migrate-state`` moves them."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS
from tests.test_cli.conftest import assert_json_ok, parse_cli_json

pytestmark = pytest.mark.cli_e2e

DEFENDER = CORPUS_RULE_UUIDS["defender_for_endpoint"]
CROWDSTRIKE = CORPUS_RULE_UUIDS["crowdstrike"]


def _rule(repo: Path, uuid: str) -> Path:
    for path in (repo / "objects" / "rules").glob("*.yaml"):
        if uuid in path.read_text(encoding="utf-8"):
            return path
    raise AssertionError(uuid)


def _splice(repo: Path, uuid: str, platform: str, line: str) -> tuple[Path, str]:
    path = _rule(repo, uuid)
    before = path.read_text(encoding="utf-8")
    path.write_text(before.replace(f"  {platform}:\n", f"  {platform}:\n    {line}\n", 1))
    return path, before


def test_migrate_state_end_to_end(invoke_cli, tide_corpus_repo: Path) -> None:
    defender, defender_before = _splice(
        tide_corpus_repo, DEFENDER, "defender_for_endpoint", "rule_id::IIG::Production: 7590"
    )
    crowdstrike, crowdstrike_before = _splice(
        tide_corpus_repo, CROWDSTRIKE, "crowdstrike", "rule_id_bundle:\n      falcon: 0abc"
    )
    (tide_corpus_repo / ".gitignore").write_text(".opentide/states/\n", encoding="utf-8")

    invalid = invoke_cli("validate", "--strict")
    assert invalid.exit_code == 1
    issues = parse_cli_json(invalid)["report"]["issues"]
    flagged = {(i["object_uuid"], i["code"]) for i in issues}
    assert flagged == {(DEFENDER, "external_id_in_rule"), (CROWDSTRIKE, "external_id_in_rule")}

    refused = invoke_cli("deploy", "migrate-state")
    assert refused.exit_code == 1
    body = parse_cli_json(refused)
    assert body["code"] == "deployment_state_ignored"
    assert "rule_id::IIG::Production" in defender.read_text(encoding="utf-8")

    (tide_corpus_repo / ".gitignore").write_text(
        ".opentide/states/sharing.jsonl\n", encoding="utf-8"
    )
    migrated = assert_json_ok(invoke_cli("deploy", "migrate-state"))
    assert migrated["rules_edited"] == 2
    assert defender.read_text(encoding="utf-8") == defender_before
    assert crowdstrike.read_text(encoding="utf-8") == crowdstrike_before
    shard = tide_corpus_repo / ".opentide" / "states" / "deployment" / f"{DEFENDER}.json"
    assert json.loads(shard.read_text())["platforms"] == {
        "defender_for_endpoint": {"IIG::Production": "7590"}
    }

    again = assert_json_ok(invoke_cli("deploy", "migrate-state"))
    assert again["migrated"] == []
    assert again["message"] == "No vendor rule ids left on rules"

    assert_json_ok(invoke_cli("validate", "--strict"))


def test_migrate_state_exits_0_when_it_only_drops_unused_ids(
    invoke_cli, tide_corpus_repo: Path
) -> None:
    """Sentinel never stored an id: dropping one is a warning, not a failure."""
    sentinel, before = _splice(
        tide_corpus_repo, CORPUS_RULE_UUIDS["sentinel"], "sentinel", "rule_id::contoso: 7590"
    )

    result = invoke_cli("deploy", "migrate-state")

    assert result.exit_code == 0, result.stdout + result.stderr
    body = parse_cli_json(result)
    assert body["status"] == "completed"
    assert [(u["platform"], u["tenant"], u["external_id"]) for u in body["unused"]] == [
        ("sentinel", "contoso", "7590")
    ]
    assert body["warnings"][0].startswith("external_id_unused: sentinel tenant contoso")
    assert sentinel.read_text(encoding="utf-8") == before
    assert not (tide_corpus_repo / ".opentide" / "states" / "deployment").exists()


def test_validate_reports_a_broken_shard(invoke_cli, tide_corpus_repo: Path) -> None:
    shard = tide_corpus_repo / ".opentide" / "states" / "deployment" / f"{DEFENDER}.json"
    shard.parent.mkdir(parents=True)
    shard.write_text(
        json.dumps(
            {
                "schema": "deployment.state::1.0",
                "object_uuid": DEFENDER,
                "platforms": {"sentinel": {"t": "1"}},
            }
        ),
        encoding="utf-8",
    )
    result = invoke_cli("validate")
    assert result.exit_code == 1
    codes = [i["code"] for i in parse_cli_json(result)["report"]["issues"]]
    assert codes == ["deployment_state_platform"]
