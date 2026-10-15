"""``external_id_in_rule`` and shard checks during object validation (RFC 0010)."""

from __future__ import annotations

import json
from pathlib import Path

from opentide.states.deployment import record_external_id, shard_path
from opentide.validation.external_ids import external_id_issues, is_superseded_extra_key
from opentide.validation.issues import ValidationIssue

UUID = "00000000-0000-4000-8003-000000000021"


def _rule(**blocks: object) -> dict:
    return {"metadata": {"uuid": UUID}, "configurations": blocks}


def test_every_legacy_spelling_on_every_block_is_reported(tmp_path: Path) -> None:
    body = _rule(
        defender_for_endpoint={"rule_id": {"a": 1}, "status": "PRODUCTION"},
        sentinel_one={"rule_id::b": 2},
        carbon_black_cloud={"rule_id_bundle": {"c": "3"}},
    )
    issues = external_id_issues(body, object_uuid=UUID, object_type="rule", workspace=tmp_path)
    assert [(i.code, i.field_path) for i in issues] == [
        ("external_id_in_rule", ("configurations", "defender_for_endpoint", "rule_id")),
        ("external_id_in_rule", ("configurations", "sentinel_one", "rule_id::b")),
        ("external_id_in_rule", ("configurations", "carbon_black_cloud", "rule_id_bundle")),
    ]
    assert all("migrate-state" in (i.suggestion or "") for i in issues)


def test_objects_other_than_rules_are_not_checked(tmp_path: Path) -> None:
    body = _rule(defender_for_endpoint={"rule_id": {"a": 1}})
    assert (
        external_id_issues(body, object_uuid=UUID, object_type="threat", workspace=tmp_path) == []
    )


def test_a_valid_or_missing_shard_is_not_an_issue(tmp_path: Path) -> None:
    body = _rule(defender_for_endpoint={"status": "PRODUCTION"})
    assert external_id_issues(body, object_uuid=UUID, object_type="rule", workspace=tmp_path) == []
    record_external_id(UUID, "defender_for_endpoint", "contoso", 1, tmp_path)
    assert external_id_issues(body, object_uuid=UUID, object_type="rule", workspace=tmp_path) == []


def test_a_broken_shard_is_reported_with_its_code(tmp_path: Path) -> None:
    path = shard_path(UUID, tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text('{"schema": "deployment.state::1.0"}', encoding="utf-8")
    issues = external_id_issues(_rule(), object_uuid=UUID, object_type="rule", workspace=tmp_path)
    assert [i.code for i in issues] == ["deployment_state_shape"]
    assert issues[0].context == {"shard": str(path)}


def test_the_extra_key_schema_error_is_superseded() -> None:
    legacy = ValidationIssue(
        code="schema_validation",
        field_path=("configurations", "crowdstrike", "rule_id::x"),
        message="Extra inputs are not permitted",
    )
    other = legacy.model_copy(update={"field_path": ("configurations", "crowdstrike", "query")})
    assert is_superseded_extra_key(legacy)
    assert not is_superseded_extra_key(other)


def test_a_misspelt_shard_beside_the_rule_is_reported_on_a_narrow_run(tmp_path: Path) -> None:
    hex_uuid = "0000abcd-0000-4000-8003-0000000000ef"
    path = shard_path(hex_uuid, tmp_path)
    path.parent.mkdir(parents=True)
    misspelt = path.with_name(f"{hex_uuid.upper()}.json")
    misspelt.write_text(
        json.dumps(
            {"schema": "deployment.state::1.0", "object_uuid": hex_uuid.upper(), "platforms": {}}
        ),
        encoding="utf-8",
    )
    body = {"metadata": {"uuid": hex_uuid}, "configurations": {}}
    issues = external_id_issues(body, object_uuid=hex_uuid, object_type="rule", workspace=tmp_path)
    assert [i.code for i in issues] == ["deployment_state_uuid_mismatch"]
    assert (
        external_id_issues(
            body, object_uuid=hex_uuid, object_type="rule", workspace=tmp_path, check_shard=False
        )
        == []
    )


def test_full_validation_checks_orphan_shards(tide_corpus_repo: Path) -> None:
    """A shard whose rule is gone is still the only handle on a remote rule."""
    from opentide.validation.scope import ValidationScope
    from opentide.validation.session import run_validation

    orphan = "00000000-0000-4000-8003-0000000000aa"
    path = shard_path(orphan, tide_corpus_repo)
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "schema": "deployment.state::1.0",
                "object_uuid": orphan,
                "platforms": {"defender_for_endpoint": {" contoso ": "1"}},
            }
        ),
        encoding="utf-8",
    )

    report = run_validation(ValidationScope.full())

    shard_issues = [i for i in report.issues if i.code.startswith("deployment_state_")]
    assert [(i.code, i.file_path) for i in shard_issues] == [("deployment_state_shape", path)]
    assert not report.ok
    narrow = run_validation(ValidationScope.narrow(types=frozenset({"rule"})))
    assert not [i for i in narrow.issues if i.code.startswith("deployment_state_")]
