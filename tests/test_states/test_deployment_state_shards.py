"""Deployment state shards: ``.opentide/states/deployment/<uuid>.json`` (RFC 0010)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from opentide.states.deployment import (
    SCHEMA_ID,
    DeploymentState,
    DeploymentStateError,
    deployment_state_ignore,
    forget_external_id,
    ignored_message,
    legacy_external_id_keys,
    normalise_external_id,
    record_external_id,
    scan_deployment_states,
    shard_path,
)

UUID = "00000000-0000-4000-8003-000000000010"
OTHER_UUID = "00000000-0000-4000-8003-000000000099"
#: Has letters, so its uppercase spelling is a different file name.
HEX_UUID = "0000abcd-0000-4000-8003-0000000000ef"


def _write(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _shard(platforms: object, *, object_uuid: str = UUID, schema: str = SCHEMA_ID) -> dict:
    return {"schema": schema, "object_uuid": object_uuid, "platforms": platforms}


def test_shard_path_is_lowercase_canonical_uuid(tmp_path: Path) -> None:
    path = shard_path(UUID.upper(), tmp_path)
    assert path == tmp_path / ".opentide" / "states" / "deployment" / f"{UUID}.json"


def test_shard_path_refuses_a_value_that_is_not_a_uuid(tmp_path: Path) -> None:
    with pytest.raises(DeploymentStateError) as caught:
        shard_path("../escape", tmp_path)
    assert caught.value.code == "deployment_state_shape"


def test_rfc_example_shard_is_rendered_byte_for_byte(tmp_path: Path) -> None:
    record_external_id(UUID, "sentinel_one", "s1-prod", 4242, tmp_path)
    record_external_id(UUID, "defender_for_endpoint", "fabrikam", "67890", tmp_path)
    record_external_id(UUID, "defender_for_endpoint", "contoso", 12345, tmp_path)
    record_external_id(
        UUID, "crowdstrike", "falcon-prod", "c5e1b2a0e4c84f0a9d3b7e6a1c8f0d22", tmp_path
    )
    text = shard_path(UUID, tmp_path).read_text(encoding="utf-8")
    assert text == (
        "{\n"
        '  "object_uuid": "00000000-0000-4000-8003-000000000010",\n'
        '  "platforms": {\n'
        '    "crowdstrike": {\n'
        '      "falcon-prod": "c5e1b2a0e4c84f0a9d3b7e6a1c8f0d22"\n'
        "    },\n"
        '    "defender_for_endpoint": {\n'
        '      "contoso": "12345",\n'
        '      "fabrikam": "67890"\n'
        "    },\n"
        '    "sentinel_one": {\n'
        '      "s1-prod": "4242"\n'
        "    }\n"
        "  },\n"
        '  "schema": "deployment.state::1.0"\n'
        "}\n"
    )


def test_writer_changes_one_tenant_and_keeps_the_rest(tmp_path: Path) -> None:
    payload = _shard(
        {
            "defender_for_endpoint": {"contoso": "1", "fabrikam": "2"},
            "crowdstrike": {"falcon": "abc"},
        }
    )
    payload["future_field"] = {"kept": True}
    path = _write(shard_path(UUID, tmp_path), payload)
    record_external_id(UUID, "defender_for_endpoint", "  contoso  ", 99, tmp_path)
    written = json.loads(path.read_text(encoding="utf-8"))
    assert written["future_field"] == {"kept": True}
    assert written["platforms"] == {
        "crowdstrike": {"falcon": "abc"},
        "defender_for_endpoint": {"contoso": "99", "fabrikam": "2"},
    }


def test_delete_removes_entry_then_platform_then_file(tmp_path: Path) -> None:
    record_external_id(UUID, "defender_for_endpoint", "contoso", 1, tmp_path)
    record_external_id(UUID, "defender_for_endpoint", "fabrikam", 2, tmp_path)
    record_external_id(UUID, "sentinel_one", "s1", 3, tmp_path)
    path = shard_path(UUID, tmp_path)

    assert forget_external_id(UUID, "defender_for_endpoint", "contoso", tmp_path) == "1"
    assert json.loads(path.read_text())["platforms"]["defender_for_endpoint"] == {"fabrikam": "2"}

    forget_external_id(UUID, "defender_for_endpoint", "fabrikam", tmp_path)
    assert "defender_for_endpoint" not in json.loads(path.read_text())["platforms"]

    forget_external_id(UUID, "sentinel_one", "s1", tmp_path)
    assert not path.exists()
    assert forget_external_id(UUID, "sentinel_one", "s1", tmp_path) is None


def test_missing_shard_is_an_empty_state(tmp_path: Path) -> None:
    state = DeploymentState.load(UUID, tmp_path)
    assert state.exists is False
    assert state.get("defender_for_endpoint", "contoso") is None


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ([], "deployment_state_shape"),
        (_shard({}, schema="deployment.state::2.0"), "deployment_state_shape"),
        (_shard([]), "deployment_state_shape"),
        (_shard({}, object_uuid=OTHER_UUID), "deployment_state_uuid_mismatch"),
        (_shard({"sentinel": {"t": "1"}}), "deployment_state_platform"),
        (_shard({"defender_for_endpoint": {"t": 1}}), "deployment_state_shape"),
        (_shard({"defender_for_endpoint": {"t": "0123"}}), "deployment_state_shape"),
        (_shard({"crowdstrike": {"t": ""}}), "deployment_state_shape"),
        (_shard({"crowdstrike": {" ": "x"}}), "deployment_state_shape"),
        (_shard({"defender_for_endpoint": {" contoso ": "1"}}), "deployment_state_shape"),
        (_shard({"crowdstrike": {"contoso\t": "x"}}), "deployment_state_shape"),
        (_shard({}, object_uuid="{" + UUID + "}"), "deployment_state_uuid_mismatch"),
        (_shard({}, object_uuid=HEX_UUID.upper()), "deployment_state_uuid_mismatch"),
    ],
)
def test_broken_shards_fail_with_their_code(tmp_path: Path, payload: object, code: str) -> None:
    uuid = HEX_UUID if HEX_UUID.upper() in json.dumps(payload) else UUID
    _write(shard_path(uuid, tmp_path), payload)
    with pytest.raises(DeploymentStateError) as caught:
        DeploymentState.load(uuid, tmp_path)
    assert caught.value.code == code


def test_a_tenant_key_with_surrounding_whitespace_is_never_matched_or_rewritten(
    tmp_path: Path,
) -> None:
    """``" contoso "`` would miss the stripped lookup and create a second remote rule."""
    _write(shard_path(UUID, tmp_path), _shard({"defender_for_endpoint": {" contoso ": "7"}}))
    with pytest.raises(DeploymentStateError) as caught:
        record_external_id(UUID, "defender_for_endpoint", "contoso", 8, tmp_path)
    assert caught.value.code == "deployment_state_shape"
    assert "' contoso '" in caught.value.message


def _variant_names() -> list[str]:
    return [f"{HEX_UUID.upper()}.json", f"{HEX_UUID.replace('-', '')}.json", f"{HEX_UUID}.JSON"]


@pytest.mark.parametrize("name", _variant_names())
def test_a_non_canonical_file_name_is_a_uuid_mismatch_not_an_empty_state(
    tmp_path: Path, name: str
) -> None:
    """A case-sensitive checkout would not find it, and deploy would create a duplicate."""
    directory = shard_path(HEX_UUID, tmp_path).parent
    payload = _shard({"defender_for_endpoint": {"contoso": "7"}}, object_uuid=HEX_UUID)
    _write(directory / name, payload)
    with pytest.raises(DeploymentStateError) as caught:
        DeploymentState.load(HEX_UUID, tmp_path)
    assert caught.value.code == "deployment_state_uuid_mismatch"
    assert name in caught.value.message
    with pytest.raises(DeploymentStateError):
        record_external_id(HEX_UUID, "defender_for_endpoint", "contoso", 8, tmp_path)
    assert sorted(path.name for path in directory.iterdir()) == [name]


def test_a_duplicate_beside_the_canonical_shard_fails_closed(tmp_path: Path) -> None:
    canonical = _write(shard_path(UUID, tmp_path), _shard({"defender_for_endpoint": {"a": "1"}}))
    duplicate = canonical.with_name(f"{UUID.replace('-', '')}.json")
    _write(duplicate, _shard({"defender_for_endpoint": {"b": "2"}}))
    with pytest.raises(DeploymentStateError) as caught:
        DeploymentState.load(UUID, tmp_path)
    assert caught.value.code == "deployment_state_uuid_mismatch"
    codes = sorted(
        (error.code, Path(error.context["path"]).name) for error in scan_deployment_states(tmp_path)
    )
    assert codes == [
        ("deployment_state_uuid_mismatch", canonical.name),
        ("deployment_state_uuid_mismatch", duplicate.name),
    ]


def test_scan_checks_every_shard_including_orphans(tmp_path: Path) -> None:
    record_external_id(UUID, "defender_for_endpoint", "contoso", 1, tmp_path)
    directory = shard_path(UUID, tmp_path).parent
    _write(
        directory / f"{OTHER_UUID}.json", _shard({"sentinel": {"t": "1"}}, object_uuid=OTHER_UUID)
    )
    _write(directory / "nested" / f"{OTHER_UUID}.json", _shard({}, object_uuid=OTHER_UUID))
    (directory / "notes.txt").write_text("not a shard\n", encoding="utf-8")
    errors = sorted(
        (error.code, Path(error.context["path"]).relative_to(directory).as_posix())
        for error in scan_deployment_states(tmp_path)
    )
    assert errors == [
        ("deployment_state_platform", f"{OTHER_UUID}.json"),
        ("deployment_state_uuid_mismatch", f"nested/{OTHER_UUID}.json"),
    ]
    assert scan_deployment_states(tmp_path / "elsewhere") == []


def test_unparseable_shard_is_a_shape_failure(tmp_path: Path) -> None:
    path = shard_path(UUID, tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text("{", encoding="utf-8")
    with pytest.raises(DeploymentStateError) as caught:
        DeploymentState.load(UUID, tmp_path)
    assert caught.value.code == "deployment_state_shape"


@pytest.mark.parametrize(
    ("platform", "value", "stored"),
    [
        ("defender_for_endpoint", 12345, "12345"),
        ("defender_for_endpoint", "12345", "12345"),
        ("sentinel_one", 0, "0"),
        ("crowdstrike", "00ab", "00ab"),
        ("crowdstrike", 7, "7"),
    ],
)
def test_external_ids_are_canonical_strings(platform: str, value: object, stored: str) -> None:
    assert normalise_external_id(platform, value) == stored


@pytest.mark.parametrize(
    ("platform", "value"),
    [
        ("defender_for_endpoint", "012"),
        ("sentinel_one", "+1"),
        ("sentinel_one", -1),
        ("defender_for_endpoint", True),
        ("defender_for_endpoint", 1.5),
        ("crowdstrike", ""),
        ("crowdstrike", None),
        ("crowdstrike", ["a"]),
    ],
)
def test_bad_external_ids_fail_shape(platform: str, value: object) -> None:
    with pytest.raises(DeploymentStateError) as caught:
        normalise_external_id(platform, value)
    assert caught.value.code == "external_id_shape"


def test_only_vendor_id_platforms_get_a_shard(tmp_path: Path) -> None:
    with pytest.raises(DeploymentStateError) as caught:
        record_external_id(UUID, "harfanglab", "hl", "1", tmp_path)
    assert caught.value.code == "deployment_state_platform"
    assert not shard_path(UUID, tmp_path).exists()


def test_legacy_keys_are_found_at_block_roots_only() -> None:
    rule = {
        "configurations": {
            "defender_for_endpoint": {"rule_id": {"a": 1}, "rule_id::b": 2, "query": "x"},
            "crowdstrike": {"rule_id_bundle": {"c": "z"}},
            "sentinel": {"alert": {"rule_id": "nested is fine"}},
        }
    }
    assert legacy_external_id_keys(rule) == [
        ("defender_for_endpoint", "rule_id"),
        ("defender_for_endpoint", "rule_id::b"),
        ("crowdstrike", "rule_id_bundle"),
    ]


@pytest.mark.parametrize(
    ("ignore", "pattern"),
    [
        (".opentide/states/\n", ".opentide/states/"),
        ("dist/\n.opentide/\n", ".opentide/"),
        (".opentide/states/deployment/\n", ".opentide/states/deployment/"),
        (".opentide/states/\n!.opentide/states/deployment/\n", ".opentide/states/"),
        ("*.json\n", "*.json"),
    ],
)
def test_ignored_deployment_state_names_the_line(tmp_path: Path, ignore: str, pattern: str) -> None:
    (tmp_path / ".gitignore").write_text(ignore, encoding="utf-8")
    rule = deployment_state_ignore(tmp_path)
    assert rule is not None
    assert rule.pattern == pattern
    assert rule.source == ".gitignore"
    message = ignored_message(rule)
    assert ".opentide/states/sharing.jsonl" in message
    assert f".gitignore:{ignore.splitlines().index(pattern) + 1}" in message


@pytest.mark.parametrize(
    "ignore",
    ["", ".opentide/states/sharing.jsonl\n", ".opentide/states/*\n!.opentide/states/deployment/\n"],
)
def test_deployment_state_not_ignored(tmp_path: Path, ignore: str) -> None:
    (tmp_path / ".gitignore").write_text(ignore, encoding="utf-8")
    assert deployment_state_ignore(tmp_path) is None


def test_ignore_check_agrees_with_git_for_a_nested_workspace(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text("team/.opentide/states/\n", encoding="utf-8")
    workspace = tmp_path / "team"
    workspace.mkdir()
    rule = deployment_state_ignore(workspace)
    assert rule is not None
    assert rule.pattern == "team/.opentide/states/"
    probe = workspace / ".opentide" / "states" / "deployment" / f"{UUID}.json"
    probe.parent.mkdir(parents=True)
    probe.write_text("{}", encoding="utf-8")
    checked = subprocess.run(
        ["git", "-C", str(tmp_path), "check-ignore", "-q", str(probe)], check=False
    )
    assert checked.returncode == 0


def test_writes_leave_no_temporary_file(tmp_path: Path) -> None:
    record_external_id(UUID, "defender_for_endpoint", "contoso", 1, tmp_path)
    record_external_id(UUID, "defender_for_endpoint", "contoso", 2, tmp_path)
    leftovers = [p.name for p in shard_path(UUID, tmp_path).parent.iterdir()]
    assert leftovers == [f"{UUID}.json"]
