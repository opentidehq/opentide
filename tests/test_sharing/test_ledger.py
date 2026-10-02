"""Current-state sharing ledger."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.sharing.ledger import ShareLedger, ledger_path


def _synced(uuid: str = "00000000-0000-4000-8003-000000000001", **extra: object) -> dict:
    record: dict[str, object] = {
        "state": "synced",
        "object_uuid": uuid,
        "object_schema": "rule::1.0",
        "object_version": 1,
        "content_hash": "abc",
        "integration": "misp",
        "target": "misp-internal",
        "organisation_uuid": "00000000-0000-4000-8aaa-000000000001",
        "remote_event_uuid": "11111111-1111-4111-8111-111111111111",
        "remote_event_id": 42,
        "published": False,
        "shared_at": "2026-09-28T11:00:00Z",
    }
    record.update(extra)
    return record


def test_missing_file_is_empty(tmp_path: Path) -> None:
    ledger = ShareLedger.load(tmp_path / "states" / "sharing.jsonl")
    assert ledger.get("any", "misp", "misp-internal") is None
    assert len(ledger) == 0


def test_put_replaces_the_triple_and_round_trips(tmp_path: Path) -> None:
    path = tmp_path / ".opentide" / "states" / "sharing.jsonl"
    ledger = ShareLedger.load(path)
    ledger.put(_synced())
    ledger.put(_synced(content_hash="def", object_version=2))
    ledger.save()

    loaded = ShareLedger.load(path)
    current = loaded.get(
        "00000000-0000-4000-8003-000000000001",
        "misp",
        "misp-internal",
    )
    assert current is not None
    assert current["content_hash"] == "def"
    assert current["object_version"] == 2
    assert len(loaded) == 1
    assert path.read_text(encoding="utf-8").count("\n") == 1


def test_duplicate_triples_keep_the_last_line(tmp_path: Path) -> None:
    path = tmp_path / "sharing.jsonl"
    path.write_text(
        "\n".join(
            [
                '{"state":"synced","object_uuid":"u","integration":"misp","target":"a","content_hash":"1"}',
                '{"state":"retracted","object_uuid":"u","integration":"misp","target":"a","content_hash":"2"}',
                '{"state":"synced","object_uuid":"other","integration":"misp","target":"a","content_hash":"3"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    ledger = ShareLedger.load(path)
    assert ledger.get("u", "misp", "a")["state"] == "retracted"
    assert ledger.get("u", "misp", "a")["content_hash"] == "2"
    assert len(ledger) == 2


def test_unknown_state_and_raw_lines_survive_a_rewrite(tmp_path: Path) -> None:
    path = tmp_path / "sharing.jsonl"
    path.write_text(
        "\n".join(
            [
                "not json",
                '{"state":"observed","object_uuid":"u","integration":"misp","target":"a","note":"keep"}',
                '{"hello":"no triple"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    ledger = ShareLedger.load(path)
    ledger.put(_synced())
    ledger.save()
    text = path.read_text(encoding="utf-8")
    assert "not json" in text
    assert '"state":"observed"' in text
    assert '"hello":"no triple"' in text
    assert ledger.get("u", "misp", "a")["state"] == "observed"
    reloaded = ShareLedger.load(path)
    assert reloaded.get("u", "misp", "a")["note"] == "keep"
    assert (
        reloaded.get(
            "00000000-0000-4000-8003-000000000001",
            "misp",
            "misp-internal",
        )["state"]
        == "synced"
    )


def test_discard_removes_only_the_triple(tmp_path: Path) -> None:
    path = tmp_path / "sharing.jsonl"
    ledger = ShareLedger.load(path)
    ledger.put(_synced())
    ledger.put(_synced(target="misp-isac"))
    assert ledger.discard(
        "00000000-0000-4000-8003-000000000001",
        "misp",
        "misp-internal",
    )
    ledger.save()
    loaded = ShareLedger.load(path)
    assert (
        loaded.get(
            "00000000-0000-4000-8003-000000000001",
            "misp",
            "misp-internal",
        )
        is None
    )
    assert (
        loaded.get(
            "00000000-0000-4000-8003-000000000001",
            "misp",
            "misp-isac",
        )["target"]
        == "misp-isac"
    )


def test_unchanged_read_does_not_create_the_file(tmp_path: Path) -> None:
    path = ledger_path(tmp_path)
    ShareLedger.load(workspace=tmp_path)
    assert path == tmp_path / ".opentide" / "states" / "sharing.jsonl"
    assert not path.exists()


def test_records_lists_identity_lines_only(tmp_path: Path) -> None:
    path = tmp_path / "sharing.jsonl"
    path.write_text('not json\n{"hello":"no triple"}\n', encoding="utf-8")
    ledger = ShareLedger.load(path)
    ledger.put(_synced())
    assert len(ledger.records()) == 1
    assert ledger.records()[0]["state"] == "synced"


def test_put_refuses_a_line_without_identity() -> None:
    ledger = ShareLedger(Path("unused"))
    with pytest.raises(ValueError, match="object_uuid"):
        ledger.put({"state": "synced"})


def test_empty_and_blank_lines_are_an_empty_ledger(tmp_path: Path) -> None:
    blank = tmp_path / "blank.jsonl"
    blank.write_text("\n\n  \n", encoding="utf-8")
    assert len(ShareLedger.load(blank)) == 0

    mixed = tmp_path / "mixed.jsonl"
    mixed.write_text(
        '\n{"state":"synced","object_uuid":"u","integration":"misp","target":"a"}\n\n',
        encoding="utf-8",
    )
    ledger = ShareLedger.load(mixed)
    assert ledger.get("u", "misp", "a") is not None
    assert len(ledger) == 1
    assert not ledger.discard("missing", "misp", "a")


def test_non_object_json_is_preserved(tmp_path: Path) -> None:
    path = tmp_path / "sharing.jsonl"
    path.write_text('["not", "an", "object"]\n', encoding="utf-8")
    ledger = ShareLedger.load(path)
    ledger.put(_synced())
    ledger.save()
    text = path.read_text(encoding="utf-8")
    assert '["not", "an", "object"]' in text
    assert len(ledger) == 1
