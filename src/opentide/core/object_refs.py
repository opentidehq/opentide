"""Extract stable identifiers from raw Tide object bodies."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def object_uuid(body: Mapping[str, Any]) -> str:
    """Return the Tide object UUID from a raw YAML/dict body."""
    top_level = body.get("uuid")
    if top_level:
        return str(top_level)
    metadata = body.get("metadata")
    if isinstance(metadata, Mapping) and metadata.get("uuid"):
        return str(metadata["uuid"])
    raise KeyError("uuid")


def object_name(body: Mapping[str, Any]) -> str:
    """Return the Tide object display name from a raw YAML/dict body."""
    metadata = body.get("metadata")
    if isinstance(metadata, Mapping) and metadata.get("name"):
        return str(metadata["name"])
    if body.get("name"):
        return str(body["name"])
    raise KeyError("name")
