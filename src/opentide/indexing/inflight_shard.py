"""Parse and compare inflight preview shard envelopes."""

from __future__ import annotations

from datetime import datetime
from typing import Any


def _object_version(body: dict[str, Any]) -> int:
    raw = (body.get("metadata") or {}).get("version")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def is_wrapped_shard(body: dict[str, Any]) -> bool:
    schema = body.get("schema")
    return isinstance(schema, str) and schema.startswith("inflight.shard")


def shard_object(body: dict[str, Any]) -> dict[str, Any]:
    """Return the embedded object document (legacy raw shards pass through)."""
    if is_wrapped_shard(body):
        obj = body.get("object")
        return obj if isinstance(obj, dict) else body
    return body


def shard_change(body: dict[str, Any]) -> dict[str, Any] | None:
    if not is_wrapped_shard(body):
        return None
    change = body.get("change")
    return change if isinstance(change, dict) else None


def shard_written_at(body: dict[str, Any]) -> str:
    if is_wrapped_shard(body):
        written = body.get("written_at")
        if isinstance(written, str):
            return written
        change = shard_change(body) or {}
        recorded = change.get("recorded_at")
        return recorded if isinstance(recorded, str) else ""
    return ""


def shard_precedence_key(body: dict[str, Any]) -> tuple[int, datetime]:
    """Sort key for choosing the winning shard when versions tie."""
    version = _object_version(shard_object(body))
    stamp = shard_written_at(body)
    try:
        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        parsed = datetime.min
    return version, parsed


def should_replace_object(
    existing: dict[str, Any],
    candidate_shard: dict[str, Any],
) -> bool:
    """Whether ``candidate_shard`` should replace ``existing`` in the objects index."""
    candidate_obj = shard_object(candidate_shard)
    existing_version = _object_version(existing)
    candidate_version = _object_version(candidate_obj)
    if candidate_version > existing_version:
        return True
    if candidate_version < existing_version:
        return False
    return is_wrapped_shard(candidate_shard)
