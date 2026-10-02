"""Edge paths for the MISP connector: failures, filters, and edit preservation."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest
from tests.test_sharing.test_engine import CLOCK, FIXTURES, ORG, FakeMisp, _block, _load

from opentide.sharing.client import MispCallError, RemoteEvent, TemplateView
from opentide.sharing.config import MispBlock
from opentide.sharing.constants import OPENTIDE_TEMPLATE_UUID, REQUIRED_TEMPLATE_RELATIONS
from opentide.sharing.document import TideDocument, load_document
from opentide.sharing.engine import (
    ShareFilters,
    _default_client,
    _edit_body,
    _failure,
    _ledger_uuids,
    run_misp,
)
from opentide.sharing.ledger import ShareLedger
from opentide.sharing.payload import BuiltEvent

REMOTE = "44444444-4444-4444-8444-444444444444"


class Recording(FakeMisp):
    def __init__(self) -> None:
        super().__init__()
        self.fail_search: MispCallError | None = None
        self.fail_edit: MispCallError | None = None
        self.fail_publish: MispCallError | None = None
        self.fail_delete: MispCallError | None = None
        self.edited_id: str | None = None
        self.edited: dict[str, object] | None = None
        self.extra: list[RemoteEvent] = []

    def search_opentide_events(self, object_uuid: str) -> list[RemoteEvent]:
        if self.fail_search is not None:
            raise self.fail_search
        return self.extra + super().search_opentide_events(object_uuid)

    def edit_event(self, event_id: str, event: dict[str, object]) -> RemoteEvent:
        self.edited_id = event_id
        self.edited = event
        if self.fail_edit is not None:
            raise self.fail_edit
        if not event_id.isdigit():
            body = event["Event"]
            assert isinstance(body, dict)
            return RemoteEvent(None, str(body["uuid"]), self.org, False, (), 0, ())
        return super().edit_event(event_id, event)

    def publish_event(self, event_id: str) -> None:
        if self.fail_publish is not None:
            raise self.fail_publish
        super().publish_event(event_id)

    def delete_event(self, event_id: str) -> None:
        if self.fail_delete is not None:
            raise self.fail_delete
        super().delete_event(event_id)


def test_preflight_guards(tmp_path: Path) -> None:
    ledger = ShareLedger.load(tmp_path / "sharing.jsonl")
    with pytest.raises(ValueError, match="workers"):
        run_misp([_load("objective.yaml")], [_block()], mode="push", ledger=ledger, workers=0)
    disabled = run_misp(
        [_load("objective.yaml")],
        [_block(enabled=False)],
        mode="preview",
        ledger=ledger,
    )
    assert disabled.preflight == "scope_no_match"
    empty = run_misp([], [_block()], mode="retract", ledger=ledger)
    assert empty.preflight == "scope_no_match"


def test_push_rejects_a_missing_or_invalid_organisation(tmp_path: Path) -> None:
    missing = run_misp(
        [_load("objective.yaml")],
        [_block(max_tlp="red", organisation_uuid=None)],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "missing.jsonl"),
        client_for=lambda _block: FakeMisp(),
        clock=lambda: CLOCK,
    )
    assert missing.records[0].reason == "organisation_uuid_missing"
    text = (FIXTURES / "objective.yaml").read_text(encoding="utf-8")
    text = text.replace(
        "tlp: clear\n",
        "tlp: clear\n  organisation:\n    uuid: not-a-uuid\n",
    )
    invalid = run_misp(
        [load_document(text)],
        [_block(max_tlp="red", organisation_uuid=None)],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "invalid.jsonl"),
        client_for=lambda _block: FakeMisp(),
        clock=lambda: CLOCK,
    )
    assert invalid.records[0].reason == "organisation_uuid_invalid"


def test_unmapped_tlp_and_non_string_status_fail_or_skip(tmp_path: Path) -> None:
    source = (FIXTURES / "objective.yaml").read_text(encoding="utf-8")
    mauve = load_document(source.replace("tlp: clear", "tlp: mauve"))
    failed = run_misp(
        [mauve],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "tlp.jsonl"),
        client_for=lambda _block: FakeMisp(),
        clock=lambda: CLOCK,
    )
    assert failed.records[0].reason == "unmapped_tlp"
    rule = load_document(
        (FIXTURES / "rule.yaml").read_text(encoding="utf-8").replace("status: STAGING", "status: 1")
    )
    skipped = run_misp(
        [rule],
        [_block(max_tlp="red", rule_statuses=("STAGING",))],
        mode="preview",
        ledger=ShareLedger.load(tmp_path / "status.jsonl"),
    )
    assert skipped.records[0].action == "skipped_status"
    ceiling = run_misp(
        [_load("objective.yaml")],
        [_block(max_tlp="nope")],
        mode="preview",
        ledger=ShareLedger.load(tmp_path / "ceiling.jsonl"),
    )
    assert ceiling.records[0].action == "skipped_tlp"


def test_publish_and_lookup_failures_leave_the_ledger_unchanged(tmp_path: Path) -> None:
    fake = Recording()
    fake.fail_publish = MispCallError("connectivity", "connectivity_failed", status=503)
    document = _load("objective.yaml")
    assert document.uuid is not None
    ledger = ShareLedger.load(tmp_path / "sharing.jsonl")
    created = run_misp(
        [document],
        [_block(max_tlp="red", publish=True)],
        mode="push",
        ledger=ledger,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert created.records[0].reason == "publish_failed"
    assert ledger.get(document.uuid, "misp", "misp-internal") is None

    fake.fail_publish = None
    fake.fail_search = MispCallError("authentication", "authentication_failed", status=401)
    looked = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ledger,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert looked.records[0].reason == "remote_lookup_failed"
    assert looked.exit_code == 2


def test_update_keeps_foreign_objects_and_records_extra_content(tmp_path: Path) -> None:
    fake = Recording()
    document = _load("objective.yaml")
    assert document.uuid is not None
    ledger = ShareLedger.load(tmp_path / "sharing.jsonl")
    run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ledger,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    stored = fake.events[0]
    fake.events[0] = RemoteEvent(
        None,
        stored.event_uuid,
        stored.orgc_uuid,
        False,
        stored.opentide_uuids,
        2,
        (
            {"name": "ip-dst"},
            {"name": "opentide", "Attribute": "nope"},
            {
                "name": "opentide",
                "template_uuid": OPENTIDE_TEMPLATE_UUID,
                "Attribute": ["skip", {"object_relation": "uuid", "value": "other"}],
            },
            {
                "name": "opentide",
                "Attribute": [{"object_relation": "uuid", "value": document.uuid}],
            },
        ),
    )
    changed = load_document(
        (FIXTURES / "objective.yaml")
        .read_text(encoding="utf-8")
        .replace(
            "name: Credential Access Objective",
            "name: Credential Access Objective revised",
        )
    )
    fake.extra.append(
        RemoteEvent(8, "55555555-5555-4555-8555-555555555555", ORG, False, ("other",), 0, ())
    )
    updated = run_misp(
        [changed],
        [_block(max_tlp="red", publish=True)],
        mode="push",
        ledger=ledger,
        publish=False,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert updated.records[0].action == "updated"
    assert "remote_extra_content" in updated.records[0].notes
    assert fake.edited_id == stored.event_uuid
    assert fake.edited is not None
    event = fake.edited["Event"]
    assert isinstance(event, dict)
    assert "Attribute" not in event
    names = [obj["name"] for obj in event["Object"] if isinstance(obj, dict)]
    assert names[0] == "ip-dst"
    assert not any(call.startswith("publish:") for call in fake.calls)


def test_edit_and_publish_failures_on_update(tmp_path: Path) -> None:
    fake = Recording()
    document = _load("objective.yaml")
    assert document.uuid is not None
    ledger = ShareLedger.load(tmp_path / "sharing.jsonl")
    run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ledger,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    revised = (FIXTURES / "objective.yaml").read_text(encoding="utf-8")
    changed = load_document(revised.replace("version: 1", "version: 2"))
    fake.fail_edit = MispCallError("rejected", "nope", status=400)
    rejected = run_misp(
        [changed],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ledger,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert rejected.records[0].reason == "remote_update_rejected"
    fake.fail_edit = None
    fake.fail_publish = MispCallError("authentication", "authentication_failed", status=401)
    unpublished = run_misp(
        [changed],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ledger,
        publish=True,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert unpublished.records[0].reason == "publish_failed"
    stored = ledger.get(document.uuid, "misp", "misp-internal")
    assert stored is not None
    assert stored["content_hash"] == document.content_hash


def test_add_failure_reasons(tmp_path: Path) -> None:
    for error, reason, code in (
        (
            MispCallError("authentication", "authentication_failed", status=401),
            "authentication_failed",
            2,
        ),
        (MispCallError("rejected", "remote_rejected", status=422), "remote_rejected", 1),
    ):
        fake = Recording()
        fake.fail_add = error
        result = run_misp(
            [_load("objective.yaml")],
            [_block(max_tlp="red")],
            mode="push",
            ledger=ShareLedger.load(tmp_path / f"{reason}.jsonl"),
            client_for=lambda _block, client=fake: client,
            clock=lambda: CLOCK,
        )
        assert result.records[0].reason == reason
        assert result.exit_code == code


def test_template_version_note_and_missing_relation(tmp_path: Path) -> None:
    noted = FakeMisp()
    noted.template = TemplateView(True, 4, frozenset(REQUIRED_TEMPLATE_RELATIONS), None)
    noted_result = run_misp(
        [_load("objective.yaml")],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "note.jsonl"),
        client_for=lambda _block: noted,
        clock=lambda: CLOCK,
    )
    assert noted_result.records[0].action == "created"
    assert "template_version:4" in noted_result.records[0].notes
    incomplete = FakeMisp()
    incomplete.template = TemplateView(True, 5, frozenset({"name"}), frozenset({"threat"}))
    missing = run_misp(
        [_load("objective.yaml")],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "relation.jsonl"),
        client_for=lambda _block: incomplete,
        clock=lambda: CLOCK,
    )
    assert missing.records[0].reason == "template_relation_missing"


def test_retract_paths(tmp_path: Path) -> None:
    document = _load("objective.yaml")
    assert document.uuid is not None
    fake = Recording()
    ledger = ShareLedger.load(tmp_path / "sharing.jsonl")
    run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ledger,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    quiet = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="retract",
        ledger=ledger,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert quiet.records[0].action == "retracted"
    assert not any(call.startswith("unpublish:") for call in fake.calls)
    assert ledger.get(document.uuid, "misp", "misp-internal")["state"] == "retracted"

    fake.fail_delete = MispCallError("connectivity", "connectivity_failed", status=503)
    failed = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="retract",
        ledger=ledger,
        delete=True,
        confirmed=True,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert failed.records[0].reason == "connectivity_failed"
    fake.fail_delete = None

    ambiguous = Recording()
    ambiguous.events = [
        RemoteEvent(1, f"33333333-3333-4333-8333-{index:012d}", ORG, False, (document.uuid,), 0, ())
        for index in (1, 2)
    ]
    many = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="retract",
        ledger=ShareLedger.load(tmp_path / "ambiguous.jsonl"),
        client_for=lambda _block: ambiguous,
        clock=lambda: CLOCK,
    )
    assert many.records[0].reason == "ambiguous_remote_event"

    absent = ShareLedger.load(tmp_path / "absent.jsonl")
    absent.put(
        {
            "state": "synced",
            "object_uuid": document.uuid,
            "integration": "misp",
            "target": "misp-internal",
            "organisation_uuid": ORG,
        }
    )
    gone = run_misp(
        [],
        [_block(max_tlp="red", organisation_uuid=None)],
        mode="retract",
        ledger=absent,
        client_for=lambda _block: Recording(),
        clock=lambda: CLOCK,
    )
    assert gone.records[0].action == "retracted"
    assert gone.records[0].notes == ("remote_absent",)
    assert absent.get(document.uuid, "misp", "misp-internal") is None


def test_retract_lookup_and_probe_failures(tmp_path: Path) -> None:
    document = _load("objective.yaml")
    assert document.uuid is not None
    lookup = Recording()
    lookup.fail_search = MispCallError("connectivity", "connectivity_failed", status=503)
    failed = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="retract",
        ledger=ShareLedger.load(tmp_path / "lookup.jsonl"),
        client_for=lambda _block: lookup,
        clock=lambda: CLOCK,
    )
    assert failed.records[0].reason == "remote_lookup_failed"

    class Denied(FakeMisp):
        def get_version(self) -> str:
            raise MispCallError("other", "organisation_uuid_unverified")

    probed = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="retract",
        ledger=ShareLedger.load(tmp_path / "probe.jsonl"),
        client_for=lambda _block: Denied(),
        clock=lambda: CLOCK,
    )
    assert probed.records[0].reason == "organisation_uuid_unverified"

    class Offline(FakeMisp):
        def get_version(self) -> str:
            raise MispCallError("connectivity", "timed out")

    offline = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "offline.jsonl"),
        client_for=lambda _block: Offline(),
        clock=lambda: CLOCK,
    )
    assert offline.records[0].reason == "connectivity_failed"

    class Odd(FakeMisp):
        def current_organisation_uuid(self) -> str:
            raise MispCallError("rejected", "weird")

    odd = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "odd.jsonl"),
        client_for=lambda _block: Odd(),
        clock=lambda: CLOCK,
    )
    assert odd.records[0].reason == "weird"


def test_retract_without_an_organisation_uuid(tmp_path: Path) -> None:
    document = _load("objective.yaml")
    assert document.uuid is not None
    found = Recording()
    found.events.append(RemoteEvent(3, REMOTE, ORG, False, (document.uuid,), 0, ()))
    missing = run_misp(
        [document],
        [_block(max_tlp="red", organisation_uuid=None)],
        mode="retract",
        ledger=ShareLedger.load(tmp_path / "missing.jsonl"),
        client_for=lambda _block: found,
        clock=lambda: CLOCK,
    )
    assert missing.records[0].reason == "organisation_uuid_missing"
    nowhere = run_misp(
        [document],
        [_block(max_tlp="red", organisation_uuid=None)],
        mode="retract",
        ledger=ShareLedger.load(tmp_path / "nowhere.jsonl"),
        client_for=lambda _block: Recording(),
        clock=lambda: CLOCK,
    )
    assert nowhere.records == ()
    assert nowhere.exit_code == 0


def test_preview_field_errors_and_filters(tmp_path: Path) -> None:
    ledger = ShareLedger.load(tmp_path / "sharing.jsonl")
    text = (FIXTURES / "objective.yaml").read_text(encoding="utf-8")
    missing = run_misp(
        [_load("objective.yaml")],
        [_block(max_tlp="red", organisation_uuid=None)],
        mode="preview",
        ledger=ledger,
    )
    assert missing.records[0].reason == "organisation_uuid_missing"
    invalid = load_document(
        text.replace("tlp: clear\n", "tlp: clear\n  organisation:\n    uuid: nope\n")
    )
    bad_org = run_misp(
        [invalid],
        [_block(max_tlp="red", organisation_uuid=None)],
        mode="preview",
        ledger=ledger,
    )
    assert bad_org.records[0].reason == "organisation_uuid_invalid"
    broken = TideDocument(":\n", {}, parse_error="yaml")
    invalid_document = run_misp(
        [broken, load_document(text.replace('created: "2026-01-01"', 'created: "yesterday"'))],
        [_block(max_tlp="red")],
        mode="preview",
        ledger=ledger,
    )
    assert [record.reason for record in invalid_document.records] == [
        "invalid_document",
        "metadata.created",
    ]
    objective = _load("objective.yaml")
    threat = _load("threat.yaml")
    pathed = replace(objective, path=Path("/tmp/objective.yaml"))
    filtered = run_misp(
        [pathed, threat, objective],
        [_block(max_tlp="red")],
        mode="preview",
        ledger=ledger,
        filters=ShareFilters(
            types=frozenset({"objective"}),
            files=frozenset({Path("/tmp/objective.yaml").resolve()}),
        ),
    )
    assert [record.object_uuid for record in filtered.records] == [objective.uuid]


def test_status_predictions(tmp_path: Path) -> None:
    document = _load("objective.yaml")
    assert document.uuid is not None
    ledger = ShareLedger.load(tmp_path / "sharing.jsonl")
    ledger.put(
        {
            "state": "retracted",
            "object_uuid": document.uuid,
            "integration": "misp",
            "target": "misp-internal",
            "content_hash": "different",
            "remote_event_uuid": 4,
            "remote_event_id": True,
        }
    )
    retracted = run_misp(
        [document],
        [_block(max_tlp="red", api_key=None, api_key_unset=True)],
        mode="status",
        ledger=ledger,
        clock=lambda: datetime(2026, 9, 28, 11, 0),
    )
    assert retracted.records[0].action == "updated"
    assert retracted.records[0].remote_event_uuid is None
    assert retracted.records[0].remote_event_id is None
    fresh = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="status",
        ledger=ShareLedger.load(tmp_path / "empty.jsonl"),
    )
    assert fresh.records[0].action == "created"
    assert fresh.records[0].remote_event_uuid is None


def test_one_mismatched_block_does_not_hide_the_other(tmp_path: Path) -> None:
    good = FakeMisp()
    bad = FakeMisp()
    bad.org = "00000000-0000-4000-8aaa-000000000099"

    def factory(block: MispBlock) -> FakeMisp:
        return good if block.name == "good" else bad

    result = run_misp(
        [_load("objective.yaml")],
        [_block(name="good", max_tlp="red"), _block(name="bad", max_tlp="red")],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "sharing.jsonl"),
        client_for=factory,
        clock=lambda: CLOCK,
    )
    assert result.preflight == "organisation_uuid_mismatch"
    assert {record.target for record in result.records} == {"bad"}
    assert "add" not in good.calls


def test_relation_note_when_the_parent_is_not_selected(tmp_path: Path) -> None:
    result = run_misp(
        [_load("rule.yaml")],
        [_block(max_tlp="red", rule_statuses=("STAGING",))],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "sharing.jsonl"),
        client_for=lambda _block: FakeMisp(),
        clock=lambda: CLOCK,
    )
    assert result.records[0].action == "created"
    assert any(note.startswith("relation_not_shared:") for note in result.records[0].notes)


def test_second_build_and_lookup_exceptions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"count": 0}
    real = __import__("opentide.sharing.engine", fromlist=["build_event"]).build_event

    def wrapped(document: TideDocument, tags: tuple[str, ...] = ()) -> BuiltEvent:
        calls["count"] += 1
        if calls["count"] >= 2:
            return BuiltEvent(None, "name")
        return real(document, tags)

    monkeypatch.setattr("opentide.sharing.engine.build_event", wrapped)
    failed = run_misp(
        [_load("objective.yaml")],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "build.jsonl"),
        client_for=lambda _block: FakeMisp(),
        clock=lambda: CLOCK,
    )
    assert failed.records[0].reason == "name"

    def boom(_client: object, _sources: tuple[str, ...]) -> object:
        raise MispCallError("connectivity", "connectivity_failed")

    monkeypatch.setattr("opentide.sharing.engine.resolve_clusters", boom)
    monkeypatch.setattr("opentide.sharing.engine.build_event", real)
    raised = run_misp(
        [_load("threat.yaml")],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "galaxy.jsonl"),
        client_for=lambda _block: FakeMisp(),
        clock=lambda: CLOCK,
    )
    assert raised.records[0].reason == "galaxy_lookup_failed"


def test_malformed_edit_body_is_a_recorded_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeMisp()
    document = _load("objective.yaml")
    assert document.uuid is not None
    fake.events.append(RemoteEvent(1, REMOTE, ORG, False, (document.uuid,), 0, ()))

    def wrapped(_document: TideDocument, _tags: tuple[str, ...] = ()) -> BuiltEvent:
        return BuiltEvent({"Event": "nope"})

    monkeypatch.setattr("opentide.sharing.engine.build_event", wrapped)
    result = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "sharing.jsonl"),
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert result.records[0].reason == "remote_update_rejected"


def test_helpers_for_unreachable_ledger_shapes(tmp_path: Path) -> None:
    block = _block()
    with pytest.raises(MispCallError, match="api_key_unset"):
        _default_client(_block(api_key=None, api_key_unset=True))
    opened = _default_client(_block(verify_ssl=False))
    assert opened._api.ssl is False
    assert opened._api.timeout == 30
    assert _failure(None) == ("connectivity_failed", "connectivity")
    with pytest.raises(MispCallError, match="remote_update_rejected"):
        _edit_body({"Event": []}, RemoteEvent(1, REMOTE, ORG, False, (), 0, ()), "tide")
    remote = RemoteEvent(1, REMOTE, ORG, False, (), 0, ())
    kept = _edit_body({"Event": {"info": "x"}}, remote, "tide")
    assert kept["Event"]["Object"] == []

    class Stub:
        def records(self) -> tuple[dict[str, object], ...]:
            return (
                {"integration": "misp", "target": "misp-internal", "object_uuid": 1},
                {"integration": "misp", "target": "misp-internal", "object_uuid": "abc"},
            )

    assert _ledger_uuids(Stub(), (block,), None) == ["abc"]  # type: ignore[arg-type]

    ledger = ShareLedger.load(tmp_path / "sharing.jsonl")
    ledger.put(
        {
            "state": "synced",
            "object_uuid": "00000000-0000-4000-8002-000000000001",
            "integration": "opencti",
            "target": "misp-internal",
        }
    )
    assert run_misp([], [_block()], mode="retract", ledger=ledger).preflight == "scope_no_match"
    ledger.put(
        {
            "state": "synced",
            "object_uuid": "00000000-0000-4000-8002-000000000009",
            "integration": "misp",
            "target": "misp-internal",
        }
    )
    filtered = run_misp(
        [],
        [_block()],
        mode="retract",
        ledger=ledger,
        filters=ShareFilters(uuids=frozenset({"00000000-0000-4000-8002-000000000001"})),
    )
    assert filtered.preflight == "scope_no_match"


def test_update_can_publish_and_retract_uses_the_object_organisation(tmp_path: Path) -> None:
    fake = Recording()
    document = _load("objective.yaml")
    assert document.uuid is not None
    ledger = ShareLedger.load(tmp_path / "sharing.jsonl")
    run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ledger,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    changed = load_document(
        (FIXTURES / "objective.yaml")
        .read_text(encoding="utf-8")
        .replace("name: Credential Access Objective", "name: Revised objective")
    )
    published = run_misp(
        [changed],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ledger,
        publish=True,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert published.records[0].action == "updated"
    assert any(call.startswith("publish:") for call in fake.calls)
    stored = ledger.get(document.uuid, "misp", "misp-internal")
    assert stored is not None
    assert stored["published"] is True

    owned = load_document(
        (FIXTURES / "objective.yaml")
        .read_text(encoding="utf-8")
        .replace("tlp: clear\n", f"tlp: clear\n  organisation:\n    uuid: {ORG}\n")
    )
    quiet = run_misp(
        [owned],
        [_block(max_tlp="red", organisation_uuid=None)],
        mode="retract",
        ledger=ShareLedger.load(tmp_path / "empty.jsonl"),
        client_for=lambda _block: Recording(),
        clock=lambda: CLOCK,
    )
    assert quiet.records == ()
    assert quiet.exit_code == 0


def test_status_reports_a_changed_synced_object_as_updated(tmp_path: Path) -> None:
    document = _load("objective.yaml")
    assert document.uuid is not None
    ledger = ShareLedger.load(tmp_path / "sharing.jsonl")
    ledger.put(
        {
            "state": "synced",
            "object_uuid": document.uuid,
            "integration": "misp",
            "target": "misp-internal",
            "content_hash": "stale",
        }
    )
    result = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="status",
        ledger=ledger,
    )
    assert result.records[0].action == "updated"
