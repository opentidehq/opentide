"""``opentide deploy migrate-state`` moves vendor ids from rules into shards (RFC 0010 §3)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from opentide.cli.services.migrate_state import run_migrate_state
from opentide.states.deployment import record_external_id, shard_path

U1 = "00000000-0000-4000-8003-000000000011"
U2 = "00000000-0000-4000-8003-000000000012"
U3 = "00000000-0000-4000-8003-000000000013"

SPLICED = f"""\
name: Spliced Defender rule
metadata:
  uuid: {U1}
  schema: rule::1.0
configurations:
  # deployed once by the old splice
  defender_for_endpoint: 
    rule_id::IIG::Production: 7590
    enabled: true
    schema: platform::defender_for_endpoint::1.0
    status: PRODUCTION
    query: |
      DeviceProcessEvents
      | where FileName =~ "cmd.exe"
"""

MAP_FORM = f"""\
name: Map form
metadata:
  uuid: {U2}
configurations:
  defender_for_endpoint:
    enabled: true   # keep me
    rule_id:
      # one per tenant
      Contoso: 12345
      Fabrikam: "67890"  # quoted
    query: |
      DeviceProcessEvents

      | take 1
    status: PRODUCTION
  sentinel_one:
    rule_id_bundle: {{s1-prod: 4242}}
    status: PRODUCTION
  crowdstrike:
    status: PRODUCTION
    rule_id_bundle:
      falcon-prod: 00c5e1b2
"""

UNUSED = f"""\
metadata:
  uuid: {U3}
configurations:
  harfanglab:
    status: PRODUCTION
    rule_id_bundle:
      hl-prod: abc
  carbon_black_cloud:
    rule_id::org-a: 123
    status: PRODUCTION
"""


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "objects" / "rules").mkdir(parents=True)
    (tmp_path / ".gitignore").write_text(".opentide/states/sharing.jsonl\n", encoding="utf-8")
    return tmp_path


def _rules(workspace: Path) -> Path:
    return workspace / "objects" / "rules"


def _write(workspace: Path, name: str, text: str, *, newline: str = "\n") -> Path:
    path = _rules(workspace) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.replace("\n", newline).encode("utf-8"))
    return path


def _migrate(workspace: Path) -> dict:
    return run_migrate_state(workspace, _rules(workspace))


def _shard(workspace: Path, uuid: str) -> dict:
    return json.loads(shard_path(uuid, workspace).read_text(encoding="utf-8"))


def _removed_lines(before: str, after: str) -> list[str]:
    """Lines present before and gone after, asserting nothing else changed or moved."""
    old, new = before.splitlines(keepends=True), after.splitlines(keepends=True)
    removed: list[str] = []
    cursor = 0
    for line in old:
        if cursor < len(new) and new[cursor] == line:
            cursor += 1
        else:
            removed.append(line)
    assert cursor == len(new), "the edit added or reordered lines"
    return removed


def test_splice_form_moves_to_a_shard_and_only_that_line_goes(workspace: Path) -> None:
    path = _write(workspace, "spliced.yaml", SPLICED)

    result = _migrate(workspace)

    assert result["status"] == "completed"
    assert "_exit_code" not in result
    assert _removed_lines(SPLICED, path.read_text(encoding="utf-8")) == [
        "    rule_id::IIG::Production: 7590\n"
    ]
    assert _shard(workspace, U1)["platforms"] == {
        "defender_for_endpoint": {"IIG::Production": "7590"}
    }
    text = shard_path(U1, workspace).read_text(encoding="utf-8")
    assert text.endswith("}\n") and '  "object_uuid"' in text


def test_map_forms_keep_comments_order_and_blank_lines(workspace: Path) -> None:
    path = _write(workspace, "map.yaml", MAP_FORM)

    result = _migrate(workspace)

    after = path.read_text(encoding="utf-8")
    assert _removed_lines(MAP_FORM, after) == [
        "    rule_id:\n",
        "      # one per tenant\n",
        "      Contoso: 12345\n",
        '      Fabrikam: "67890"  # quoted\n',
        "    rule_id_bundle: {s1-prod: 4242}\n",
        "    rule_id_bundle:\n",
        "      falcon-prod: 00c5e1b2\n",
    ]
    assert "enabled: true   # keep me" in after
    assert "DeviceProcessEvents\n\n      | take 1" in after
    assert _shard(workspace, U2)["platforms"] == {
        "crowdstrike": {"falcon-prod": "00c5e1b2"},
        "defender_for_endpoint": {"Contoso": "12345", "Fabrikam": "67890"},
        "sentinel_one": {"s1-prod": "4242"},
    }
    assert result["migrated"][0]["shard"] == f".opentide/states/deployment/{U2}.json"


def test_crlf_rule_keeps_its_line_endings(workspace: Path) -> None:
    path = _write(workspace, "crlf.yaml", SPLICED, newline="\r\n")

    _migrate(workspace)

    raw = path.read_bytes()
    assert b"rule_id" not in raw
    assert raw == SPLICED.replace("    rule_id::IIG::Production: 7590\n", "").replace(
        "\n", "\r\n"
    ).encode("utf-8")


def test_nested_rule_files_are_migrated(workspace: Path) -> None:
    path = _write(workspace, "team-a/deeper/spliced.yml", SPLICED)

    result = _migrate(workspace)

    assert "rule_id" not in path.read_text(encoding="utf-8")
    assert result["migrated"][0]["file"] == "objects/rules/team-a/deeper/spliced.yml"


def test_harfanglab_and_carbon_black_bundles_are_dropped_loudly(workspace: Path) -> None:
    path = _write(workspace, "unused.yaml", UNUSED)

    result = _migrate(workspace)

    assert not shard_path(U3, workspace).exists()
    assert "rule_id" not in path.read_text(encoding="utf-8")
    assert {(u["platform"], u["tenant"], u["external_id"]) for u in result["unused"]} == {
        ("harfanglab", "hl-prod", "abc"),
        ("carbon_black_cloud", "org-a", "123"),
    }
    assert any("external_id_unused" in warning for warning in result["warnings"])
    assert result["status"] == "completed"


U4 = "00000000-0000-4000-8003-000000000014"

SENTINEL_AND_SPLUNK = f"""\
metadata:
  uuid: {U4}
configurations:
  sentinel:
    rule_id::IIG::Production: 7590
    status: PRODUCTION
  splunk:
    status: PRODUCTION
    rule_id:
      search-head: "saved/search 1"
"""


def test_sentinel_and_splunk_ids_are_removed_and_never_stored(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only Defender, SentinelOne and CrowdStrike store ids; every other platform drops them."""
    from unittest.mock import MagicMock

    from opentide.cli.services import migrate_state

    spy = MagicMock(wraps=migrate_state.logger)
    monkeypatch.setattr(migrate_state, "logger", spy)
    path = _write(workspace, "sentinel-splunk.yaml", SENTINEL_AND_SPLUNK)

    result = _migrate(workspace)

    assert result["status"] == "completed"
    assert "_exit_code" not in result
    assert not shard_path(U4, workspace).exists()
    assert _removed_lines(SENTINEL_AND_SPLUNK, path.read_text(encoding="utf-8")) == [
        "    rule_id::IIG::Production: 7590\n",
        "    rule_id:\n",
        '      search-head: "saved/search 1"\n',
    ]
    expected = [
        ("sentinel", "IIG::Production", "7590", "objects/rules/sentinel-splunk.yaml"),
        ("splunk", "search-head", "saved/search 1", "objects/rules/sentinel-splunk.yaml"),
    ]
    assert [
        (u["platform"], u["tenant"], u["external_id"], u["file"]) for u in result["unused"]
    ] == expected
    logged = [
        (c.kwargs["platform"], c.kwargs["tenant"], c.kwargs["value"], c.kwargs["file"])
        for c in spy.warning.call_args_list
        if c.args[0] == "external_id_unused"
    ]
    assert logged == expected
    assert len(result["warnings"]) == 2
    assert all(w.startswith("external_id_unused: ") for w in result["warnings"])


def test_second_run_is_a_clean_success(workspace: Path) -> None:
    _write(workspace, "spliced.yaml", SPLICED)
    _write(workspace, "map.yaml", MAP_FORM)
    _migrate(workspace)
    shard_before = shard_path(U2, workspace).read_bytes()

    again = _migrate(workspace)

    assert again["status"] == "completed"
    assert again["migrated"] == []
    assert "_exit_code" not in again
    assert shard_path(U2, workspace).read_bytes() == shard_before


def test_crash_after_shard_write_is_completed_by_the_next_run(workspace: Path) -> None:
    path = _write(workspace, "spliced.yaml", SPLICED)
    record_external_id(U1, "defender_for_endpoint", "IIG::Production", 7590, workspace)

    result = _migrate(workspace)

    assert result["status"] == "completed"
    assert result["shards_written"] == 0
    assert "rule_id" not in path.read_text(encoding="utf-8")


def test_gitignored_destination_refuses_and_edits_nothing(workspace: Path) -> None:
    (workspace / ".gitignore").write_text("dist/\n.opentide/states/\n", encoding="utf-8")
    path = _write(workspace, "spliced.yaml", SPLICED)

    result = _migrate(workspace)

    assert result["_exit_code"] == 1
    assert result["code"] == "deployment_state_ignored"
    assert result["ignore"] == {"pattern": ".opentide/states/", "source": ".gitignore", "line": 2}
    assert ".opentide/states/sharing.jsonl" in str(result["message"])
    assert path.read_text(encoding="utf-8") == SPLICED
    assert not (workspace / ".opentide" / "states").exists()


def test_conflict_leaves_that_rule_alone_and_migrates_the_rest(workspace: Path) -> None:
    twice = SPLICED.replace(
        "    rule_id::IIG::Production: 7590\n",
        "    rule_id::IIG::Production: 7590\n    rule_id:\n      IIG::Production: 7591\n",
    )
    conflicted = _write(workspace, "twice.yaml", twice)
    clean = _write(workspace, "map.yaml", MAP_FORM)

    result = _migrate(workspace)

    assert result["_exit_code"] == 1
    assert [e["code"] for e in result["errors"]] == ["external_id_conflict"]
    assert conflicted.read_text(encoding="utf-8") == twice
    assert not shard_path(U1, workspace).exists()
    assert "rule_id" not in clean.read_text(encoding="utf-8")
    assert shard_path(U2, workspace).exists()


def test_disagreeing_shard_is_a_conflict(workspace: Path) -> None:
    path = _write(workspace, "spliced.yaml", SPLICED)
    record_external_id(U1, "defender_for_endpoint", "IIG::Production", 1, workspace)
    before = shard_path(U1, workspace).read_bytes()

    result = _migrate(workspace)

    assert [e["code"] for e in result["errors"]] == ["external_id_conflict"]
    assert path.read_text(encoding="utf-8") == SPLICED
    assert shard_path(U1, workspace).read_bytes() == before


@pytest.mark.parametrize(
    "replacement",
    [
        '    rule_id::IIG::Production: "07590"\n',
        "    rule_id::IIG::Production: -1\n",
        "    rule_id::IIG::Production: [1]\n",
        "    rule_id::IIG::Production: true\n",
        '    rule_id::IIG::Production: ""\n',
        "    rule_id::: 1\n",
        "    rule_id: 7590\n",
        "    rule_id_bundle:\n      - 7590\n",
    ],
)
def test_bad_shapes_fail_external_id_shape_and_are_left_untouched(
    workspace: Path, replacement: str
) -> None:
    text = SPLICED.replace("    rule_id::IIG::Production: 7590\n", replacement)
    path = _write(workspace, "bad.yaml", text)

    result = _migrate(workspace)

    assert result["_exit_code"] == 1
    assert {e["code"] for e in result["errors"]} == {"external_id_shape"}
    assert path.read_text(encoding="utf-8") == text
    assert not shard_path(U1, workspace).exists()


def test_flow_style_block_is_refused_rather_than_rewritten(workspace: Path) -> None:
    text = f"""\
metadata:
  uuid: {U1}
configurations:
  defender_for_endpoint: {{rule_id::IIG: 1, status: PRODUCTION}}
"""
    path = _write(workspace, "flow.yaml", text)

    result = _migrate(workspace)

    assert [e["code"] for e in result["errors"]] == ["external_id_shape"]
    assert path.read_text(encoding="utf-8") == text


def test_nested_rule_id_keys_are_not_external_ids(workspace: Path) -> None:
    text = f"""\
metadata:
  uuid: {U1}
configurations:
  defender_for_endpoint:
    status: PRODUCTION
    alert:
      rule_id: not-a-binding
"""
    path = _write(workspace, "nested.yaml", text)

    result = _migrate(workspace)

    assert result["migrated"] == []
    assert path.read_text(encoding="utf-8") == text


def test_unparseable_file_is_reported_and_others_continue(workspace: Path) -> None:
    _write(workspace, "broken.yaml", "rule_id: [\n")
    clean = _write(workspace, "spliced.yaml", SPLICED)

    result = _migrate(workspace)

    assert [e["code"] for e in result["errors"]] == ["yaml_parse"]
    assert "rule_id" not in clean.read_text(encoding="utf-8")


def test_stripped_rule_still_parses_to_the_same_document(workspace: Path) -> None:
    path = _write(workspace, "map.yaml", MAP_FORM)
    original = yaml.safe_load(MAP_FORM)

    _migrate(workspace)

    for block in original["configurations"].values():
        for key in [k for k in block if k.startswith("rule_id")]:
            del block[key]
    assert yaml.safe_load(path.read_text(encoding="utf-8")) == original
