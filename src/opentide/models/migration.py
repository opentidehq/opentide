"""Helpers for schema revision data migrations."""

from __future__ import annotations

from typing import Any


def stamp_schema_identifier(body: dict[str, Any], schema_id: str) -> dict[str, Any]:
    """Set ``metadata.schema`` (or legacy ``meta.schema``) after a migration."""
    if not schema_id:
        return body
    result = dict(body)
    if "metadata" in result and isinstance(result["metadata"], dict):
        metadata = dict(result["metadata"])
        metadata["schema"] = schema_id
        result["metadata"] = metadata
        return result
    if "meta" in result and isinstance(result["meta"], dict):
        meta = dict(result["meta"])
        meta["schema"] = schema_id
        result["meta"] = meta
        return result
    result["metadata"] = {"schema": schema_id}
    return result
