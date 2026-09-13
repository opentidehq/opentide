"""Per-key vocabulary lifecycle merge."""

from __future__ import annotations

from opentide.vocabulary.lifecycle import entry_identity, format_version, merge_vocab_keys


def test_first_fill_assigns_version_1_0_without_pin_contract() -> None:
    result = merge_vocab_keys(
        [],
        [{"id": "T1001", "name": "Alpha", "description": "one"}],
        key_field="id",
    )
    assert len(result.keys) == 1
    assert result.keys[0]["version"] == "1.0"
    assert result.added == ("T1001",)
    assert result.pin_contract is None
    assert result.dirty


def test_new_keys_on_populated_vocab_open_next_minor() -> None:
    existing = [{"id": "T1001", "name": "Alpha", "version": "1.0"}]
    upstream = [
        {"id": "T1001", "name": "Alpha"},
        {"id": "T1002", "name": "Beta"},
    ]
    result = merge_vocab_keys(existing, upstream, key_field="id")
    assert result.added == ("T1002",)
    assert result.introducing_version == "1.1"
    assert result.pin_contract == "1.1"
    by_id = {str(entry["id"]): entry for entry in result.keys}
    assert by_id["T1001"]["version"] == "1.0"
    assert by_id["T1002"]["version"] == "1.1"


def test_description_only_edit_keeps_version() -> None:
    existing = [{"id": "T1001", "name": "Alpha", "description": "old", "version": "1.0"}]
    upstream = [{"id": "T1001", "name": "Alpha", "description": "new"}]
    result = merge_vocab_keys(existing, upstream, key_field="id")
    assert result.added == ()
    assert result.updated == ("T1001",)
    assert result.keys[0]["version"] == "1.0"
    assert result.keys[0]["description"] == "new"
    assert result.pin_contract is None


def test_missing_upstream_key_sets_removed_at_next_major() -> None:
    existing = [
        {"id": "T1001", "name": "Alpha", "version": "1.0"},
        {"id": "T1002", "name": "Beta", "version": "1.1"},
    ]
    upstream = [{"id": "T1001", "name": "Alpha"}]
    result = merge_vocab_keys(existing, upstream, key_field="id")
    assert result.removed == ("T1002",)
    by_id = {str(entry["id"]): entry for entry in result.keys}
    assert by_id["T1002"]["removed"] == "2.0"
    assert by_id["T1002"]["version"] == "1.1"
    assert result.pin_contract is None


def test_already_removed_key_stays_removed_without_new_event() -> None:
    existing = [
        {"id": "T1001", "name": "Alpha", "version": "1.0"},
        {"id": "T1002", "name": "Gone", "version": "1.0", "removed": "2.0"},
    ]
    upstream = [{"id": "T1001", "name": "Alpha"}]
    result = merge_vocab_keys(existing, upstream, key_field="id")
    assert result.removed == ()
    by_id = {str(entry["id"]): entry for entry in result.keys}
    assert by_id["T1002"]["removed"] == "2.0"


def test_revived_key_clears_removed() -> None:
    existing = [{"id": "T1001", "name": "Alpha", "version": "1.0", "removed": "2.0"}]
    upstream = [{"id": "T1001", "name": "Alpha", "description": "back"}]
    result = merge_vocab_keys(existing, upstream, key_field="id")
    assert result.updated == ("T1001",)
    assert "removed" not in result.keys[0]
    assert result.keys[0]["version"] == "1.0"


def test_backfill_missing_version_without_treating_as_add() -> None:
    existing = [{"id": "T1001", "name": "Alpha"}]
    upstream = [{"id": "T1001", "name": "Alpha"}]
    result = merge_vocab_keys(existing, upstream, key_field="id")
    assert result.backfilled == ("T1001",)
    assert result.added == ()
    assert result.keys[0]["version"] == "1.0"
    assert result.pin_contract is None


def test_one_minor_per_cycle_for_multiple_adds() -> None:
    existing = [{"id": "T1001", "name": "Alpha", "version": "1.0"}]
    upstream = [
        {"id": "T1001", "name": "Alpha"},
        {"id": "T1002", "name": "Beta"},
        {"id": "T1003", "name": "Gamma"},
    ]
    result = merge_vocab_keys(existing, upstream, key_field="id")
    versions = {str(entry["id"]): entry["version"] for entry in result.keys}
    assert versions["T1002"] == "1.1"
    assert versions["T1003"] == "1.1"
    assert result.pin_contract == "1.1"


def test_name_keyed_identity() -> None:
    existing = [{"name": "Process", "description": "a", "version": "1.0"}]
    upstream = [{"name": "Process", "description": "a"}, {"name": "File"}]
    result = merge_vocab_keys(existing, upstream, key_field="name")
    assert result.added == ("File",)
    assert result.pin_contract == "1.1"


def test_merge_skips_blank_and_missing_identity() -> None:
    result = merge_vocab_keys(
        [],
        [{"id": "", "name": "Nope"}, {"name": "No id"}, {"id": "  "}],
        key_field="id",
    )
    assert result.keys == ()
    assert result.added == ()


def test_format_version_and_entry_identity() -> None:
    assert format_version(1, 2) == "1.2"
    assert entry_identity({"id": "  "}, "id") is None
    assert entry_identity({"uuid": None}, "uuid") is None
    assert entry_identity({"id": "T1001"}, "id") == "T1001"


def test_add_and_remove_same_cycle_still_pins_minor() -> None:
    existing = [{"id": "T1001", "name": "Alpha", "version": "1.0"}]
    upstream = [{"id": "T1002", "name": "Beta"}]
    result = merge_vocab_keys(existing, upstream, key_field="id")
    assert result.added == ("T1002",)
    assert result.removed == ("T1001",)
    assert result.pin_contract == "1.1"
    by_id = {str(entry["id"]): entry for entry in result.keys}
    assert by_id["T1001"]["removed"] == "2.0"
    assert by_id["T1002"]["version"] == "1.1"
