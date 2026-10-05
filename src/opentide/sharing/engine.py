"""MISP push, preview, status, and retract.

Preview and status make no HTTP call. Push and retract talk to the instance
only through :class:`~opentide.sharing.client.MispClient`.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, TypeVar

from opentide.core.logging import get_logger
from opentide.sharing.client import (
    MispCallError,
    MispClient,
    PyMispClient,
    RemoteEvent,
    TemplateView,
)
from opentide.sharing.config import MispBlock
from opentide.sharing.constants import (
    CANONICAL_UUID_PATTERN,
    INTEGRATION_MISP,
    OPENTIDE_TEMPLATE_NAME,
    OPENTIDE_TEMPLATE_UUID,
    OPENTIDE_TEMPLATE_VERSION,
    REQUIRED_TEMPLATE_RELATIONS,
    TLP_ORDER,
)
from opentide.sharing.document import TideDocument
from opentide.sharing.galaxy import resolve_clusters
from opentide.sharing.ledger import ShareLedger
from opentide.sharing.payload import build_event
from opentide.sharing.report import ShareRecord, ShareRun

log = get_logger(__name__)
_UUID = re.compile(CANONICAL_UUID_PATTERN)
_Mode = Literal["push", "preview", "status", "retract"]


@dataclass(frozen=True)
class ShareFilters:
    """CLI filters. ``None`` means the flag was omitted. An empty set matches nothing."""

    uuids: frozenset[str] | None = None
    types: frozenset[str] | None = None
    files: frozenset[Path] | None = None


def run_misp(
    documents: Sequence[TideDocument],
    blocks: Sequence[MispBlock],
    *,
    mode: _Mode,
    ledger: ShareLedger,
    filters: ShareFilters | None = None,
    publish: bool | None = None,
    workers: int = 1,
    delete: bool = False,
    confirmed: bool = False,
    validate: Callable[[TideDocument], str | None] | None = None,
    client_for: Callable[[MispBlock], MispClient] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> ShareRun:
    """Run one MISP share command across *blocks*."""
    if workers < 1:
        raise ValueError("workers must be at least 1")
    active = tuple(blocks)
    if not active or any(not block.enabled for block in active):
        return ShareRun((), "scope_no_match")
    if delete and not confirmed:
        return ShareRun((), "retract_unconfirmed")
    selected = _selected(documents, filters)
    if mode != "retract" and not selected:
        return ShareRun((), "scope_no_match")
    # Preview is a local dry run. It does not contact the destination, so an
    # unset key is not a preflight failure. Push and retract need the key.
    needs_key = mode in {"push", "retract"}
    if needs_key and any(block.resolved_api_key() is None for block in active):
        return ShareRun((), "api_key_unset")
    if mode == "retract" and not selected and not _ledger_uuids(ledger, active, filters):
        return ShareRun((), "scope_no_match")

    factory = client_for or _default_client
    stamp = _timestamp(clock)
    if mode == "preview":
        return ShareRun(tuple(_preview(selected, active, ledger)))
    if mode == "status":
        return ShareRun(tuple(_status(selected, active, ledger)))

    probes, mismatch = _probe_all(active, factory)
    if mismatch:
        records = _mismatch_records(selected, probes)
        return ShareRun(tuple(records), "organisation_uuid_mismatch")

    records: list[ShareRecord] = []
    lock = threading.Lock()
    for probe in probes:
        if mode == "retract":
            records.extend(
                _retract_block(probe, selected, ledger, filters, delete, workers, lock, stamp)
            )
        else:
            records.extend(
                _push_block(
                    probe,
                    selected,
                    ledger,
                    publish,
                    workers,
                    lock,
                    stamp,
                    validate,
                )
            )
    return ShareRun(tuple(records))


def _default_client(block: MispBlock) -> MispClient:
    key = block.resolved_api_key()
    if key is None:
        raise MispCallError("other", "api_key_unset")
    return PyMispClient(block.url, key, verify_ssl=block.verify_ssl)


@dataclass
class _Probe:
    block: MispBlock
    client: MispClient | None = None
    org: str | None = None
    template: TemplateView | None = None
    error: MispCallError | None = None
    mismatch: bool = False


def _probe_all(
    blocks: Sequence[MispBlock],
    factory: Callable[[MispBlock], MispClient],
) -> tuple[list[_Probe], bool]:
    probes: list[_Probe] = []
    mismatch = False
    for block in blocks:
        probe = _Probe(block)
        log.info("share.misp.probe", target=block.name, url=block.url)
        try:
            client = factory(block)
            probe.client = client
            client.get_version()
            probe.org = client.current_organisation_uuid()
            probe.template = client.object_template()
        except MispCallError as exc:
            probe.error = exc
        else:
            configured = block.organisation_uuid
            if configured and probe.org and configured.casefold() != probe.org.casefold():
                probe.mismatch = True
                mismatch = True
        probes.append(probe)
    return probes, mismatch


def _push_block(
    probe: _Probe,
    documents: Sequence[TideDocument],
    ledger: ShareLedger,
    publish: bool | None,
    workers: int,
    lock: threading.Lock,
    stamp: str,
    validate: Callable[[TideDocument], str | None] | None,
) -> list[ShareRecord]:
    block = probe.block
    local, shareable = _split_local(documents, block, validate)
    if probe.error is not None or probe.client is None:
        reason, kind = _failure(probe.error)
        local.extend(_failed(doc, block, reason, kind) for doc in shareable)
        return local
    client = probe.client
    do_publish = block.publish if publish is None else publish

    def upsert(document: TideDocument) -> ShareRecord:
        return _upsert(document, probe, client, ledger, do_publish, lock, stamp, shareable)

    local.extend(_map(workers, shareable, upsert))
    return local


def _upsert(
    document: TideDocument,
    probe: _Probe,
    client: MispClient,
    ledger: ShareLedger,
    do_publish: bool,
    lock: threading.Lock,
    stamp: str,
    shareable: Sequence[TideDocument],
) -> ShareRecord:
    block = probe.block
    org, source = _organisation(block, document)
    if source == "missing":
        return _failed(document, block, "organisation_uuid_missing", "other")
    if source == "invalid" or org is None:
        return _failed(document, block, "organisation_uuid_invalid", "other")
    if probe.org and org.casefold() != probe.org.casefold():
        return _failed(document, block, "organisation_uuid_mismatch", "other")
    built = build_event(document)
    if built.event is None or built.reason is not None:
        return _failed(document, block, built.reason or "invalid_document", "other")
    template_reason, template_note = _template_problem(probe.template, document.family or "")
    if template_reason is not None:
        return _failed(document, block, template_reason, "other")
    try:
        resolved = resolve_clusters(client, built.cluster_sources)
    except MispCallError as exc:
        return _failed(document, block, "galaxy_lookup_failed", exc.kind)
    if resolved.error is not None:
        return _failed(document, block, "galaxy_lookup_failed", resolved.error.kind)
    built = build_event(document, resolved.tags)
    if built.event is None:
        return _failed(document, block, built.reason or "invalid_document", "other")
    notes = list(resolved.notes)
    if template_note:
        notes.append(template_note)
    notes.extend(_relation_notes(built.relations, shareable))
    assert document.uuid is not None
    try:
        found = client.search_opentide_events(document.uuid)
    except MispCallError as exc:
        return _failed(document, block, "remote_lookup_failed", exc.kind, tuple(notes))
    matched, foreign = _matched(found, org, document.uuid)
    notes.extend(f"foreign_event:{uuid}" for uuid in foreign)
    if len(matched) > 1:
        listed = ",".join(event.event_uuid for event in matched)
        notes.append(f"ambiguous_remote_event:{listed}")
        return _failed(document, block, "ambiguous_remote_event", "other", tuple(notes))
    line = ledger.get(document.uuid, INTEGRATION_MISP, block.name)
    stored = line.get("content_hash") if line else None
    # Preview and status treat only a synced line with the same bytes as
    # unchanged. A retracted line must be written again, or the event stays
    # unpublished while push reports success.
    if (
        len(matched) == 1
        and line is not None
        and line.get("state") == "synced"
        and stored == document.content_hash
    ):
        remote = matched[0]
        return _record(
            document,
            block,
            "unchanged",
            remote_event_uuid=remote.event_uuid,
            remote_event_id=remote.event_id,
            notes=tuple(notes),
        )
    if not matched:
        # A failed create must leave the ledger unchanged. The synced line, if
        # any, is replaced only after the event exists.
        try:
            remote = client.add_event(built.event)
        except MispCallError as exc:
            return _failed(
                document,
                block,
                _write_reason(exc, update=False),
                exc.kind,
                tuple(notes),
            )
        published = False
        if do_publish:
            try:
                _publish(client, remote)
                published = True
            except MispCallError as exc:
                return _failed(document, block, "publish_failed", exc.kind, tuple(notes))
        _remember(ledger, lock, document, block, remote, published, stamp, org)
        return _record(
            document,
            block,
            "created",
            remote_event_uuid=remote.event_uuid,
            remote_event_id=remote.event_id,
            notes=tuple(notes),
        )
    remote = matched[0]
    if remote.event_attribute_count or _foreign_objects(remote, document.uuid):
        notes.append("remote_extra_content")
    try:
        body = _edit_body(built.event, remote, document.uuid)
    except MispCallError as exc:
        return _failed(document, block, exc.reason, exc.kind, tuple(notes))
    address = str(remote.event_id) if remote.event_id is not None else remote.event_uuid
    try:
        remote = client.edit_event(address, body)
    except MispCallError as exc:
        return _failed(document, block, _write_reason(exc, update=True), exc.kind, tuple(notes))
    published = False
    if do_publish:
        try:
            _publish(client, remote)
            published = True
        except MispCallError as exc:
            return _failed(document, block, "publish_failed", exc.kind, tuple(notes))
    _remember(ledger, lock, document, block, remote, published, stamp, org)
    return _record(
        document,
        block,
        "updated",
        remote_event_uuid=remote.event_uuid,
        remote_event_id=remote.event_id,
        notes=tuple(notes),
    )


def _retract_block(
    probe: _Probe,
    documents: Sequence[TideDocument],
    ledger: ShareLedger,
    filters: ShareFilters | None,
    delete: bool,
    workers: int,
    lock: threading.Lock,
    stamp: str,
) -> list[ShareRecord]:
    block = probe.block
    by_uuid = {document.uuid: document for document in documents if document.uuid}
    candidates = list(by_uuid)
    for uuid in _ledger_uuids(ledger, (block,), filters):
        if uuid not in by_uuid:
            candidates.append(uuid)
    if probe.error is not None or probe.client is None:
        reason, kind = _failure(probe.error)
        return [_bare(uuid, block, "failed", reason, kind) for uuid in candidates]
    client = probe.client

    def once(uuid: str) -> ShareRecord | None:
        return _retract_one(
            uuid,
            by_uuid.get(uuid),
            probe,
            client,
            ledger,
            delete,
            lock,
            stamp,
        )

    return [record for record in _map(workers, candidates, once) if record is not None]


def _retract_one(
    uuid: str,
    document: TideDocument | None,
    probe: _Probe,
    client: MispClient,
    ledger: ShareLedger,
    delete: bool,
    lock: threading.Lock,
    stamp: str,
) -> ShareRecord | None:
    block = probe.block
    line = ledger.get(uuid, INTEGRATION_MISP, block.name)
    org = _retract_org(block, document, line)
    try:
        found = client.search_opentide_events(uuid)
    except MispCallError as exc:
        return _bare(uuid, block, "failed", "remote_lookup_failed", exc.kind)
    if org is None:
        if line is None and not found:
            return None
        return _bare(uuid, block, "failed", "organisation_uuid_missing", "other")
    matched, _foreign = _matched(found, org, uuid)
    if len(matched) > 1:
        return _bare(uuid, block, "failed", "ambiguous_remote_event", "other")
    if not matched:
        if line is not None:
            _discard(ledger, lock, uuid, block.name)
            return _bare(uuid, block, "retracted", notes=("remote_absent",))
        return None
    remote = matched[0]
    address = str(remote.event_id) if remote.event_id is not None else remote.event_uuid
    try:
        if delete:
            client.delete_event(address)
            _discard(ledger, lock, uuid, block.name)
        else:
            if remote.published:
                client.unpublish_event(address)
            _remember_retracted(ledger, lock, uuid, document, line, block, remote, stamp, org)
    except MispCallError as exc:
        return _bare(uuid, block, "failed", exc.reason, exc.kind)
    return _bare(
        uuid,
        block,
        "retracted",
        remote_event_uuid=remote.event_uuid,
        remote_event_id=remote.event_id,
    )


def _preview(
    documents: Sequence[TideDocument],
    blocks: Sequence[MispBlock],
    ledger: ShareLedger,
) -> list[ShareRecord]:
    records: list[ShareRecord] = []
    for block in blocks:
        _local, shareable = _split_local(documents, block, None)
        records.extend(_local)
        known = {document.uuid for document in shareable if document.uuid}
        for document in shareable:
            org, source = _organisation(block, document)
            if source == "missing":
                records.append(_failed(document, block, "organisation_uuid_missing", "other"))
                continue
            if source == "invalid" or org is None:
                records.append(_failed(document, block, "organisation_uuid_invalid", "other"))
                continue
            built = build_event(document)
            if built.event is None:
                records.append(
                    _failed(document, block, built.reason or "invalid_document", "other")
                )
                continue
            notes = ["organisation_unverified"]
            if built.cluster_sources:
                notes.append("cluster_not_resolved")
            notes.extend(
                f"relation_not_shared:{item}" for item in built.relations if item not in known
            )
            assert document.uuid is not None
            records.append(
                _record(
                    document,
                    block,
                    _predict(ledger, document, block.name),
                    notes=tuple(notes),
                )
            )
    return records


def _status(
    documents: Sequence[TideDocument],
    blocks: Sequence[MispBlock],
    ledger: ShareLedger,
) -> list[ShareRecord]:
    records: list[ShareRecord] = []
    for block in blocks:
        local, shareable = _split_local(documents, block, None)
        records.extend(local)
        for document in shareable:
            assert document.uuid is not None
            line = ledger.get(document.uuid, INTEGRATION_MISP, block.name)
            records.append(
                _record(
                    document,
                    block,
                    _predict(ledger, document, block.name),
                    remote_event_uuid=_text(line, "remote_event_uuid"),
                    remote_event_id=_integer(line.get("remote_event_id") if line else None),
                )
            )
    return records


def _split_local(
    documents: Sequence[TideDocument],
    block: MispBlock,
    validate: Callable[[TideDocument], str | None] | None,
) -> tuple[list[ShareRecord], list[TideDocument]]:
    local: list[ShareRecord] = []
    shareable: list[TideDocument] = []
    for document in documents:
        if document.parse_error is not None or document.uuid is None or document.family is None:
            local.append(_failed(document, block, "invalid_document", "other"))
            continue
        if document.family not in block.object_types:
            local.append(_record(document, block, "skipped_type", reason="object_type"))
            continue
        if document.family == "rule":
            status = document.body.get("status")
            if not isinstance(status, str) or status not in block.rule_statuses:
                local.append(_record(document, block, "skipped_status", reason="rule_status"))
                continue
        tlp = document.metadata.get("tlp")
        if isinstance(tlp, str) and tlp in TLP_ORDER and tlp not in _allowed(block.max_tlp):
            local.append(_record(document, block, "skipped_tlp", reason="max_tlp"))
            continue
        if validate is not None:
            message = validate(document)
            if message:
                local.append(_failed(document, block, "validation_error", "other", (message,)))
                continue
        shareable.append(document)
    return local, shareable


def _allowed(max_tlp: str) -> set[str]:
    if max_tlp not in TLP_ORDER:
        return set()
    ceiling = TLP_ORDER.index(max_tlp)
    return {name for name in TLP_ORDER if TLP_ORDER.index(name) <= ceiling}


def _organisation(block: MispBlock, document: TideDocument) -> tuple[str | None, str]:
    if block.organisation_uuid:
        return block.organisation_uuid.lower(), "block"
    org = document.metadata.get("organisation")
    if isinstance(org, Mapping):
        raw = org.get("uuid")
        if isinstance(raw, str) and raw.strip():
            text = raw.strip().lower()
            if _UUID.fullmatch(text):
                return text, "object"
            return None, "invalid"
    return None, "missing"


def _retract_org(
    block: MispBlock,
    document: TideDocument | None,
    line: Mapping[str, object] | None,
) -> str | None:
    if block.organisation_uuid:
        return block.organisation_uuid.lower()
    if document is not None:
        org, _source = _organisation(block, document)
        if org:
            return org
    if line is not None and isinstance(line.get("organisation_uuid"), str):
        return str(line["organisation_uuid"]).lower()
    return None


def _template_problem(template: TemplateView | None, family: str) -> tuple[str | None, str | None]:
    if template is None or not template.found:
        return "template_missing", None
    missing = [name for name in REQUIRED_TEMPLATE_RELATIONS if name not in template.relations]
    if missing or (template.type_values is not None and family not in template.type_values):
        return "template_relation_missing", None
    if template.version != OPENTIDE_TEMPLATE_VERSION:
        return None, f"template_version:{template.version}"
    return None, None


def _matched(
    events: Sequence[RemoteEvent],
    org: str,
    tide_uuid: str,
) -> tuple[list[RemoteEvent], list[str]]:
    matched: list[RemoteEvent] = []
    foreign: list[str] = []
    for event in events:
        if tide_uuid not in event.opentide_uuids:
            continue
        if event.orgc_uuid and event.orgc_uuid.casefold() == org.casefold():
            matched.append(event)
        else:
            foreign.append(event.event_uuid)
    return matched, foreign


def _edit_body(
    created: Mapping[str, Any],
    remote: RemoteEvent,
    tide_uuid: str,
) -> dict[str, Any]:
    raw = created["Event"]
    if not isinstance(raw, dict):
        raise MispCallError("rejected", "remote_update_rejected")
    event: dict[str, Any] = dict(raw)
    event["uuid"] = remote.event_uuid
    if remote.event_attribute_count:
        event.pop("Attribute", None)
    objects = event.get("Object")
    ours = list(objects) if isinstance(objects, list) else []
    kept = [obj for obj in remote.objects if not _is_ours(obj, tide_uuid)]
    event["Object"] = kept + ours
    return {"Event": event}


def _is_ours(obj: Mapping[str, object], tide_uuid: str) -> bool:
    name = obj.get("name")
    template = obj.get("template_uuid")
    if name != OPENTIDE_TEMPLATE_NAME and template != OPENTIDE_TEMPLATE_UUID:
        return False
    attributes = obj.get("Attribute")
    if not isinstance(attributes, list):
        return False
    for attribute in attributes:
        if not isinstance(attribute, Mapping):
            continue
        if attribute.get("object_relation") == "uuid" and attribute.get("value") == tide_uuid:
            return True
    return False


def _foreign_objects(remote: RemoteEvent, tide_uuid: str) -> bool:
    return any(not _is_ours(obj, tide_uuid) for obj in remote.objects)


def _publish(client: MispClient, remote: RemoteEvent) -> None:
    address = str(remote.event_id) if remote.event_id is not None else remote.event_uuid
    client.publish_event(address)


def _predict(ledger: ShareLedger, document: TideDocument, target: str) -> str:
    assert document.uuid is not None
    line = ledger.get(document.uuid, INTEGRATION_MISP, target)
    if line is None:
        return "created"
    if line.get("state") == "retracted":
        return "updated"
    if line.get("state") == "synced" and line.get("content_hash") == document.content_hash:
        return "unchanged"
    return "updated"


def _remember(
    ledger: ShareLedger,
    lock: threading.Lock,
    document: TideDocument,
    block: MispBlock,
    remote: RemoteEvent,
    published: bool,
    stamp: str,
    org: str,
) -> None:
    version = document.metadata.get("version")
    record = {
        "state": "synced",
        "object_uuid": document.uuid,
        "object_schema": document.schema_id,
        "object_version": (
            int(version) if isinstance(version, int) and not isinstance(version, bool) else version
        ),
        "content_hash": document.content_hash,
        "integration": INTEGRATION_MISP,
        "target": block.name,
        "organisation_uuid": org,
        "remote_event_uuid": remote.event_uuid,
        "remote_event_id": remote.event_id,
        "published": published,
        "shared_at": stamp,
    }
    with lock:
        ledger.put(record)
        ledger.save()


def _remember_retracted(
    ledger: ShareLedger,
    lock: threading.Lock,
    uuid: str,
    document: TideDocument | None,
    line: Mapping[str, object] | None,
    block: MispBlock,
    remote: RemoteEvent,
    stamp: str,
    org: str,
) -> None:
    record: dict[str, object] = dict(line) if line else {}
    record.update(
        {
            "state": "retracted",
            "object_uuid": uuid,
            "integration": INTEGRATION_MISP,
            "target": block.name,
            "organisation_uuid": org,
            "remote_event_uuid": remote.event_uuid,
            "remote_event_id": remote.event_id,
            "published": False,
            "shared_at": stamp,
        }
    )
    if document is not None:
        record["object_schema"] = document.schema_id
        record["content_hash"] = document.content_hash
        version = document.metadata.get("version")
        record["object_version"] = version
    with lock:
        ledger.put(record)
        ledger.save()


def _discard(ledger: ShareLedger, lock: threading.Lock, uuid: str, target: str) -> None:
    with lock:
        if ledger.discard(uuid, INTEGRATION_MISP, target):
            ledger.save()


def _mismatch_records(
    documents: Sequence[TideDocument], probes: Sequence[_Probe]
) -> list[ShareRecord]:
    records: list[ShareRecord] = []
    for probe in probes:
        if not probe.mismatch:
            continue
        _local, shareable = _split_local(documents, probe.block, None)
        records.extend(_local)
        records.extend(
            _failed(document, probe.block, "organisation_uuid_mismatch", "other")
            for document in shareable
        )
    return records


def _selected(
    documents: Sequence[TideDocument], filters: ShareFilters | None
) -> list[TideDocument]:
    if filters is None:
        return list(documents)
    chosen: list[TideDocument] = []
    for document in documents:
        if filters.uuids is not None and document.uuid not in filters.uuids:
            continue
        if filters.types is not None and document.family not in filters.types:
            continue
        if filters.files is not None and (
            document.path is None or document.path.resolve() not in filters.files
        ):
            continue
        chosen.append(document)
    return chosen


def _ledger_uuids(
    ledger: ShareLedger,
    blocks: Sequence[MispBlock],
    filters: ShareFilters | None,
) -> list[str]:
    names = {block.name for block in blocks}
    found: list[str] = []
    for line in ledger.records():
        if line.get("integration") != INTEGRATION_MISP or line.get("target") not in names:
            continue
        uuid = line.get("object_uuid")
        if not isinstance(uuid, str):
            continue
        if filters is not None and filters.uuids is not None and uuid not in filters.uuids:
            continue
        if uuid not in found:
            found.append(uuid)
    return found


_T = TypeVar("_T")
_R = TypeVar("_R")


def _map(workers: int, items: Sequence[_T], function: Callable[[_T], _R]) -> list[_R]:
    if workers == 1 or len(items) <= 1:
        return [function(item) for item in items]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(function, items))


def _write_reason(exc: MispCallError, *, update: bool) -> str:
    if exc.reason == "attribute_too_large":
        return exc.reason
    if exc.kind in {"authentication", "connectivity"}:
        return exc.reason
    if update:
        return "remote_update_rejected"
    return exc.reason


def _failure(exc: MispCallError | None) -> tuple[str, str]:
    if exc is None:
        return "connectivity_failed", "connectivity"
    if exc.kind == "authentication":
        return "authentication_failed", "authentication"
    if exc.reason == "organisation_uuid_unverified":
        return exc.reason, exc.kind
    if exc.kind == "connectivity":
        return "connectivity_failed", "connectivity"
    return exc.reason, exc.kind


def _relation_notes(relations: Sequence[str], shareable: Sequence[TideDocument]) -> list[str]:
    known = {document.uuid for document in shareable if document.uuid}
    return [f"relation_not_shared:{item}" for item in relations if item not in known]


def _failed(
    document: TideDocument,
    block: MispBlock,
    reason: str,
    kind: str,
    notes: tuple[str, ...] = (),
) -> ShareRecord:
    return _record(document, block, "failed", reason=reason, notes=notes, kind=kind)


def _record(
    document: TideDocument,
    block: MispBlock,
    action: str,
    *,
    reason: str | None = None,
    notes: tuple[str, ...] = (),
    kind: str | None = None,
    remote_event_uuid: str | None = None,
    remote_event_id: int | None = None,
) -> ShareRecord:
    return ShareRecord(
        object_uuid=document.uuid or "",
        target=block.name,
        action=action,
        integration=INTEGRATION_MISP,
        reason=reason,
        notes=notes,
        kind=kind,
        remote_event_uuid=remote_event_uuid,
        remote_event_id=remote_event_id,
    )


def _bare(
    uuid: str,
    block: MispBlock,
    action: str,
    reason: str | None = None,
    kind: str | None = None,
    *,
    notes: tuple[str, ...] = (),
    remote_event_uuid: str | None = None,
    remote_event_id: int | None = None,
) -> ShareRecord:
    return ShareRecord(
        object_uuid=uuid,
        target=block.name,
        action=action,
        integration=INTEGRATION_MISP,
        reason=reason,
        notes=notes,
        kind=kind,
        remote_event_uuid=remote_event_uuid,
        remote_event_id=remote_event_id,
    )


def _text(line: Mapping[str, object] | None, key: str) -> str | None:
    if line is None:
        return None
    value = line.get(key)
    if isinstance(value, str):
        return value
    return None


def _integer(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _timestamp(clock: Callable[[], datetime] | None) -> str:
    moment = clock() if clock is not None else datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
