"""Share report shape and the exit-code order from sharing 1.0."""

from __future__ import annotations

from opentide.sharing.report import ShareRecord, ShareRun


def test_record_omits_empty_optional_fields() -> None:
    bare = ShareRecord(object_uuid="abc", target="misp-internal", action="skipped_tlp")
    assert bare.as_dict() == {
        "object_uuid": "abc",
        "integration": "misp",
        "target": "misp-internal",
        "action": "skipped_tlp",
    }
    full = ShareRecord(
        object_uuid="abc",
        target="misp-internal",
        action="created",
        remote_event_uuid="11111111-1111-4111-8111-111111111111",
        remote_event_id=4,
        reason="note",
        notes=("organisation_unverified",),
    )
    rendered = full.as_dict()
    assert rendered["remote_event_id"] == 4
    assert rendered["notes"] == ["organisation_unverified"]
    assert rendered["reason"] == "note"


def test_exit_code_order() -> None:
    assert ShareRun((), "scope_no_match").exit_code == 1
    created = ShareRecord("a", "t", "created")
    failed = ShareRecord("b", "t", "failed", kind="other", reason="validation_error")
    auth = ShareRecord("c", "t", "failed", kind="authentication", reason="authentication_failed")
    skipped = ShareRecord("d", "t", "skipped_tlp")
    assert ShareRun((created, failed)).exit_code == 3
    assert ShareRun((skipped,)).exit_code == 0
    assert ShareRun((auth,)).exit_code == 2
    assert ShareRun((failed,)).exit_code == 1
    assert ShareRun((created, auth)).exit_code == 3
