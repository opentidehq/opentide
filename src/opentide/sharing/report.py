"""Share report records and the exit status from sharing 1.0."""

from __future__ import annotations

from dataclasses import dataclass

SUCCESS_ACTIONS = frozenset({"created", "updated", "unchanged", "retracted"})
SKIP_ACTIONS = frozenset({"skipped_tlp", "skipped_status", "skipped_type"})
AUTH_KINDS = frozenset({"authentication", "connectivity"})


@dataclass(frozen=True)
class ShareRecord:
    """One object on one block. ``action`` is exactly one of the spec values."""

    object_uuid: str
    target: str
    action: str
    integration: str = "misp"
    remote_event_uuid: str | None = None
    remote_event_id: int | None = None
    reason: str | None = None
    notes: tuple[str, ...] = ()
    kind: str | None = None

    def as_dict(self) -> dict[str, object]:
        """JSON-ready record. Secrets are never stored on a record."""
        payload: dict[str, object] = {
            "object_uuid": self.object_uuid,
            "integration": self.integration,
            "target": self.target,
            "action": self.action,
        }
        if self.remote_event_uuid is not None:
            payload["remote_event_uuid"] = self.remote_event_uuid
        if self.remote_event_id is not None:
            payload["remote_event_id"] = self.remote_event_id
        if self.reason is not None:
            payload["reason"] = self.reason
        if self.notes:
            payload["notes"] = list(self.notes)
        return payload


@dataclass(frozen=True)
class ShareRun:
    """Result of one share invocation."""

    records: tuple[ShareRecord, ...]
    preflight: str | None = None

    @property
    def exit_code(self) -> int:
        """The single exit status defined by sharing 1.0."""
        if self.preflight is not None:
            return 1
        successes = [record for record in self.records if record.action in SUCCESS_ACTIONS]
        failures = [record for record in self.records if record.action == "failed"]
        if successes and failures:
            return 3
        if not failures:
            return 0
        if all(record.kind in AUTH_KINDS for record in failures):
            return 2
        return 1
