"""MISP connector behaviour against a fake transport. No instance is contacted."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from opentide.sharing.client import GalaxyCluster, MispCallError, RemoteEvent, TemplateView
from opentide.sharing.config import MispBlock
from opentide.sharing.constants import OPENTIDE_TEMPLATE_VERSION, REQUIRED_TEMPLATE_RELATIONS
from opentide.sharing.document import TideDocument, load_document
from opentide.sharing.engine import ShareFilters, run_misp
from opentide.sharing.ledger import ShareLedger

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "sharing"
ORG = "00000000-0000-4000-8aaa-000000000001"
CLOCK = datetime(2026, 9, 28, 11, 0, tzinfo=timezone.utc)


def _block(**overrides: object) -> MispBlock:
    values: dict[str, object] = {
        "name": "misp-internal",
        "url": "https://misp.example",
        "max_tlp": "amber",
        "api_key": "secret",
        "api_key_env": "MISP_KEY",
        "api_key_literal": False,
        "api_key_unset": False,
        "enabled": True,
        "organisation_uuid": ORG,
        "publish": False,
        "verify_ssl": True,
    }
    values.update(overrides)
    return MispBlock(**values)  # type: ignore[arg-type]


def _template(version: int = OPENTIDE_TEMPLATE_VERSION, found: bool = True) -> TemplateView:
    return TemplateView(
        found=found,
        version=version,
        relations=frozenset(REQUIRED_TEMPLATE_RELATIONS),
        type_values=frozenset({"threat", "objective", "rule"}),
    )


class FakeMisp:
    def __init__(self) -> None:
        self.org = ORG
        self.events: list[RemoteEvent] = []
        self.calls: list[str] = []
        self.template = _template()
        self.clusters: dict[str, tuple[GalaxyCluster, ...]] = {}
        self.fail_galaxy: MispCallError | None = None
        self.fail_add: MispCallError | None = None
        self._next = 1

    def get_version(self) -> str:
        self.calls.append("version")
        return "2.4.214"

    def current_organisation_uuid(self) -> str:
        self.calls.append("me")
        return self.org

    def object_template(self) -> TemplateView:
        self.calls.append("template")
        return self.template

    def search_opentide_events(self, object_uuid: str) -> list[RemoteEvent]:
        self.calls.append(f"search:{object_uuid}")
        return [event for event in self.events if object_uuid in event.opentide_uuids]

    def add_event(self, event: dict[str, object]) -> RemoteEvent:
        self.calls.append("add")
        if self.fail_add is not None:
            raise self.fail_add
        remote = _from_payload(event, self._next, self.org)
        self._next += 1
        self.events.append(remote)
        return remote

    def edit_event(self, event_id: str, event: dict[str, object]) -> RemoteEvent:
        self.calls.append(f"edit:{event_id}")
        remote = _from_payload(event, int(event_id), self.org)
        self.events = [remote if item.event_id == remote.event_id else item for item in self.events]
        return remote

    def publish_event(self, event_id: str) -> None:
        self.calls.append(f"publish:{event_id}")
        self._set_published(int(event_id), True)

    def unpublish_event(self, event_id: str) -> None:
        self.calls.append(f"unpublish:{event_id}")
        self._set_published(int(event_id), False)

    def delete_event(self, event_id: str) -> None:
        self.calls.append(f"delete:{event_id}")
        self.events = [event for event in self.events if str(event.event_id) != event_id]

    def galaxy_clusters(self, galaxy: str) -> tuple[GalaxyCluster, ...]:
        self.calls.append(f"galaxy:{galaxy}")
        if self.fail_galaxy is not None:
            raise self.fail_galaxy
        return self.clusters.get(galaxy, ())

    def _set_published(self, event_id: int, published: bool) -> None:
        updated: list[RemoteEvent] = []
        for event in self.events:
            if event.event_id == event_id:
                updated.append(
                    RemoteEvent(
                        event.event_id,
                        event.event_uuid,
                        event.orgc_uuid,
                        published,
                        event.opentide_uuids,
                        event.event_attribute_count,
                        event.objects,
                    )
                )
            else:
                updated.append(event)
        self.events = updated


def _from_payload(event: dict[str, object], event_id: int, org: str) -> RemoteEvent:
    body = event["Event"]
    assert isinstance(body, dict)
    uuids: list[str] = []
    objects = body.get("Object") or []
    assert isinstance(objects, list)
    for obj in objects:
        assert isinstance(obj, dict)
        attributes = obj.get("Attribute") or []
        assert isinstance(attributes, list)
        for attribute in attributes:
            assert isinstance(attribute, dict)
            relation = attribute.get("object_relation")
            value = attribute.get("value")
            if relation == "uuid" and isinstance(value, str):
                uuids.append(value)
    event_uuid = body.get("uuid")
    stored_objects = tuple(obj for obj in objects if isinstance(obj, dict))
    attributes = body.get("Attribute") or []
    return RemoteEvent(
        event_id=event_id,
        event_uuid=(
            event_uuid
            if isinstance(event_uuid, str)
            else f"22222222-2222-4222-8222-{event_id:012d}"
        ),
        orgc_uuid=org,
        published=bool(body.get("published")),
        opentide_uuids=tuple(uuids),
        event_attribute_count=len(attributes) if isinstance(attributes, list) else 0,
        objects=stored_objects,
    )


def _load(name: str) -> TideDocument:
    return load_document((FIXTURES / name).read_text(encoding="utf-8"))


def test_push_creates_and_records_a_synced_line(tmp_path: Path) -> None:
    fake = FakeMisp()
    ledger = ShareLedger.load(tmp_path / "sharing.jsonl")
    document = _load("rule.yaml")
    result = run_misp(
        [document],
        [_block(max_tlp="red", rule_statuses=("STAGING",))],
        mode="push",
        ledger=ledger,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert result.exit_code == 0
    assert result.records[0].action == "created"
    assert "add" in fake.calls
    assert not any(call.startswith("publish") for call in fake.calls)
    assert document.uuid is not None
    line = ledger.get(document.uuid, "misp", "misp-internal")
    assert line is not None
    assert line["state"] == "synced"
    assert line["content_hash"] == document.content_hash
    assert line["published"] is False
    assert line["shared_at"] == "2026-09-28T11:00:00Z"
    assert "secret" not in str(line)


def test_same_hash_is_unchanged_until_the_ledger_is_removed(tmp_path: Path) -> None:
    fake = FakeMisp()
    ledger = ShareLedger.load(tmp_path / "sharing.jsonl")
    document = _load("objective.yaml")
    created = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ledger,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert created.records[0].action == "created"
    fake.calls.clear()
    again = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ledger,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert again.records[0].action == "unchanged"
    assert not any(call.startswith("edit") for call in fake.calls)
    empty = ShareLedger.load(tmp_path / "missing.jsonl")
    updated = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="push",
        ledger=empty,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert updated.records[0].action == "updated"


def test_preview_makes_no_request(tmp_path: Path) -> None:
    fake = FakeMisp()
    document = _load("threat.yaml")
    result = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="preview",
        ledger=ShareLedger.load(tmp_path / "sharing.jsonl"),
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert fake.calls == []
    assert result.records[0].action == "created"
    assert "organisation_unverified" in result.records[0].notes
    assert "cluster_not_resolved" in result.records[0].notes
    assert not (tmp_path / "sharing.jsonl").exists()


def test_status_compares_the_ledger_without_a_key(tmp_path: Path) -> None:
    ledger = ShareLedger.load(tmp_path / "sharing.jsonl")
    document = _load("rule.yaml")
    assert document.uuid is not None
    ledger.put(
        {
            "state": "synced",
            "object_uuid": document.uuid,
            "integration": "misp",
            "target": "misp-internal",
            "content_hash": document.content_hash,
            "remote_event_uuid": "11111111-1111-4111-8111-111111111111",
            "remote_event_id": 9,
        }
    )
    result = run_misp(
        [document],
        [_block(api_key=None, api_key_unset=True, max_tlp="red", rule_statuses=("STAGING",))],
        mode="status",
        ledger=ledger,
        clock=lambda: CLOCK,
    )
    assert result.exit_code == 0
    assert result.records[0].action == "unchanged"
    assert result.records[0].remote_event_id == 9


def test_tlp_and_status_skips_are_not_failures(tmp_path: Path) -> None:
    red = load_document(
        (FIXTURES / "rule.yaml").read_text(encoding="utf-8").replace("tlp: clear", "tlp: red")
    )
    result = run_misp(
        [red, _load("objective.yaml")],
        [_block(max_tlp="green", object_types=("rule",), rule_statuses=("STAGING",))],
        mode="preview",
        ledger=ShareLedger.load(tmp_path / "sharing.jsonl"),
        clock=lambda: CLOCK,
    )
    actions = {record.object_uuid: record.action for record in result.records}
    assert actions[red.uuid or ""] == "skipped_tlp"
    assert actions[_load("objective.yaml").uuid or ""] == "skipped_type"
    assert result.exit_code == 0


def test_authentication_failure_exits_2(tmp_path: Path) -> None:
    class Denied(FakeMisp):
        def get_version(self) -> str:
            raise MispCallError("authentication", "authentication_failed", status=401)

    result = run_misp(
        [_load("objective.yaml")],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "sharing.jsonl"),
        client_for=lambda _block: Denied(),
        clock=lambda: CLOCK,
    )
    assert result.exit_code == 2
    assert result.records[0].reason == "authentication_failed"


def test_block_org_mismatch_is_preflight_and_writes_nothing(tmp_path: Path) -> None:
    fake = FakeMisp()
    fake.org = "00000000-0000-4000-8aaa-000000000099"
    result = run_misp(
        [_load("objective.yaml")],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "sharing.jsonl"),
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert result.preflight == "organisation_uuid_mismatch"
    assert result.exit_code == 1
    assert "add" not in fake.calls


def test_object_org_mismatch_does_not_stop_the_other_object(tmp_path: Path) -> None:
    fake = FakeMisp()
    objective = load_document(
        (FIXTURES / "objective.yaml")
        .read_text(encoding="utf-8")
        .replace(
            "tlp: clear\n",
            f"tlp: clear\n  organisation:\n    uuid: {ORG}\n    name: Ours\n",
        )
    )
    threat = load_document(
        (FIXTURES / "threat.yaml")
        .read_text(encoding="utf-8")
        .replace(
            "tlp: clear\n",
            "tlp: clear\n"
            "  organisation:\n"
            "    uuid: 00000000-0000-4000-8aaa-000000000099\n"
            "    name: Other\n",
        )
    )
    result = run_misp(
        [objective, threat],
        [_block(max_tlp="red", organisation_uuid=None)],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "sharing.jsonl"),
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    by_uuid = {record.object_uuid: record for record in result.records}
    assert objective.uuid is not None and threat.uuid is not None
    assert by_uuid[objective.uuid].action == "created"
    assert by_uuid[threat.uuid].reason == "organisation_uuid_mismatch"
    assert result.exit_code == 3


def test_ambiguous_and_foreign_events(tmp_path: Path) -> None:
    fake = FakeMisp()
    document = _load("objective.yaml")
    assert document.uuid is not None
    for event_id in (1, 2):
        fake.events.append(
            RemoteEvent(
                event_id,
                f"33333333-3333-4333-8333-{event_id:012d}",
                ORG,
                False,
                (document.uuid,),
                0,
                (),
            )
        )
    ambiguous = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "a.jsonl"),
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert ambiguous.records[0].reason == "ambiguous_remote_event"
    assert "add" not in fake.calls

    foreign = FakeMisp()
    foreign.events.append(
        RemoteEvent(
            4,
            "44444444-4444-4444-8444-444444444444",
            "00000000-0000-4000-8aaa-000000000099",
            False,
            (document.uuid,),
            0,
            (),
        )
    )
    created = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "b.jsonl"),
        client_for=lambda _block: foreign,
        clock=lambda: CLOCK,
    )
    assert created.records[0].action == "created"
    assert any(note.startswith("foreign_event:") for note in created.records[0].notes)


def test_galaxy_failure_and_resolved_tags(tmp_path: Path) -> None:
    failed = FakeMisp()
    failed.fail_galaxy = MispCallError("connectivity", "connectivity_failed")
    threat = _load("threat.yaml")
    ledger = ShareLedger.load(tmp_path / "sharing.jsonl")
    result = run_misp(
        [threat],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ledger,
        client_for=lambda _block: failed,
        clock=lambda: CLOCK,
    )
    assert result.records[0].reason == "galaxy_lookup_failed"
    assert result.exit_code == 2
    assert threat.uuid is not None
    assert ledger.get(threat.uuid, "misp", "misp-internal") is None

    tagged = FakeMisp()
    tagged.clusters["mitre-attack-pattern"] = (
        GalaxyCluster(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "Command and Scripting",
            ("T1059",),
            (),
            (),
        ),
    )
    tagged.clusters["threat-actor"] = (
        GalaxyCluster("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "Bravo", ("G0007",), (), ()),
        GalaxyCluster("5b4ee3ea-eee3-4c8e-8323-85ae32658754", "Alpha", (), (), ()),
    )
    created = run_misp(
        [threat],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "tags.jsonl"),
        client_for=lambda _block: tagged,
        clock=lambda: CLOCK,
    )
    assert created.records[0].action == "created"
    assert "cluster_not_found:T1059" not in created.records[0].notes
    assert "actor_unscoped" not in "".join(created.records[0].notes)


def test_missing_template_and_validation_block_the_write(tmp_path: Path) -> None:
    fake = FakeMisp()
    fake.template = _template(found=False)
    missing = run_misp(
        [_load("objective.yaml")],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "sharing.jsonl"),
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert missing.records[0].reason == "template_missing"
    assert "add" not in fake.calls
    blocked = run_misp(
        [_load("objective.yaml")],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "other.jsonl"),
        client_for=lambda _block: FakeMisp(),
        validate=lambda _document: "schema error",
        clock=lambda: CLOCK,
    )
    assert blocked.records[0].reason == "validation_error"


def test_retract_unpublish_then_delete(tmp_path: Path) -> None:
    fake = FakeMisp()
    ledger = ShareLedger.load(tmp_path / "sharing.jsonl")
    document = _load("objective.yaml")
    assert document.uuid is not None
    created = run_misp(
        [document],
        [_block(max_tlp="red", publish=True)],
        mode="push",
        ledger=ledger,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert created.records[0].action == "created"
    assert ledger.get(document.uuid, "misp", "misp-internal")["published"] is True
    retracted = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="retract",
        ledger=ledger,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert retracted.records[0].action == "retracted"
    assert any(call.startswith("unpublish:") for call in fake.calls)
    assert ledger.get(document.uuid, "misp", "misp-internal")["state"] == "retracted"
    removed = run_misp(
        [document],
        [_block(max_tlp="red")],
        mode="retract",
        ledger=ledger,
        delete=True,
        confirmed=True,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert removed.records[0].action == "retracted"
    assert ledger.get(document.uuid, "misp", "misp-internal") is None


def test_delete_without_confirmation_and_unset_key_are_preflight(tmp_path: Path) -> None:
    fake = FakeMisp()
    unconfirmed = run_misp(
        [_load("objective.yaml")],
        [_block()],
        mode="retract",
        ledger=ShareLedger.load(tmp_path / "sharing.jsonl"),
        delete=True,
        confirmed=False,
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert unconfirmed.preflight == "retract_unconfirmed"
    assert fake.calls == []
    unset = run_misp(
        [_load("rule.yaml")],
        [_block(api_key=None, api_key_unset=True)],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "sharing.jsonl"),
        clock=lambda: CLOCK,
    )
    assert unset.preflight == "api_key_unset"
    preview = run_misp(
        [_load("rule.yaml")],
        [_block(api_key=None, api_key_unset=True, max_tlp="red", rule_statuses=("STAGING",))],
        mode="preview",
        ledger=ShareLedger.load(tmp_path / "sharing.jsonl"),
        clock=lambda: CLOCK,
    )
    assert preview.preflight is None
    assert preview.exit_code == 0
    assert fake.calls == []


def test_failed_create_keeps_the_ledger_line(tmp_path: Path) -> None:
    document = _load("rule.yaml")
    assert document.uuid is not None
    path = tmp_path / "sharing.jsonl"
    ledger = ShareLedger.load(path)
    ledger.put(
        {
            "state": "synced",
            "object_uuid": document.uuid,
            "integration": "misp",
            "target": "misp-internal",
            "content_hash": "stale",
            "remote_event_id": 7,
        }
    )
    ledger.save()
    fake = FakeMisp()
    fake.fail_add = MispCallError("connectivity", "connectivity_failed")
    result = run_misp(
        [document],
        [_block(max_tlp="red", rule_statuses=("STAGING",))],
        mode="push",
        ledger=ShareLedger.load(path),
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert result.records[0].action == "failed"
    kept = ShareLedger.load(path)
    line = kept.get(document.uuid, "misp", "misp-internal")
    assert line is not None
    assert line["content_hash"] == "stale"
    assert line["remote_event_id"] == 7


def test_workers_do_not_change_the_outcome(tmp_path: Path) -> None:
    documents = [_load("objective.yaml"), _load("threat.yaml")]

    def once(workers: int) -> list[tuple[str, str]]:
        result = run_misp(
            documents,
            [_block(max_tlp="red")],
            mode="push",
            ledger=ShareLedger.load(tmp_path / f"{workers}.jsonl"),
            workers=workers,
            client_for=lambda _block: FakeMisp(),
            clock=lambda: CLOCK,
        )
        return [(record.object_uuid, record.action) for record in result.records]

    assert once(1) == once(2)


def test_attribute_too_large(tmp_path: Path) -> None:
    fake = FakeMisp()
    fake.fail_add = MispCallError("attribute_too_large", "attribute_too_large", status=400)
    result = run_misp(
        [_load("objective.yaml")],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "sharing.jsonl"),
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert result.records[0].reason == "attribute_too_large"
    assert result.exit_code == 1


def test_unknown_uuid_filter_is_scope_no_match(tmp_path: Path) -> None:
    result = run_misp(
        [_load("rule.yaml")],
        [_block()],
        mode="preview",
        ledger=ShareLedger.load(tmp_path / "sharing.jsonl"),
        filters=ShareFilters(uuids=frozenset({"00000000-0000-4000-8003-000000000099"})),
        clock=lambda: CLOCK,
    )
    assert result.preflight == "scope_no_match"


def test_unscoped_actor_is_a_note(tmp_path: Path) -> None:
    text = (FIXTURES / "threat.yaml").read_text(encoding="utf-8")
    text = text.replace("name: att&ck::G0007", "name: Bare Actor")
    fake = FakeMisp()
    result = run_misp(
        [load_document(text)],
        [_block(max_tlp="red")],
        mode="push",
        ledger=ShareLedger.load(tmp_path / "sharing.jsonl"),
        client_for=lambda _block: fake,
        clock=lambda: CLOCK,
    )
    assert result.records[0].action == "created"
    assert any(note.startswith("actor_unscoped:") for note in result.records[0].notes)
