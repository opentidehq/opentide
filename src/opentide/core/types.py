"""Shared typed structures for index and runtime data."""

from __future__ import annotations

from typing import Any, TypedDict


class IndexSnapshot(TypedDict, total=False):
    """Shape of the repository index loaded from disk or built in memory."""

    objects: dict[str, dict[str, Any]]
    configurations: dict[str, Any]
    metaschemas: dict[str, Any]
    subschemas: dict[str, Any]
    definitions: dict[str, Any]
    templates: dict[str, Any]
    json_schemas: dict[str, Any]
    rules: dict[str, Any]
    objectives: dict[str, Any]
    threats: dict[str, Any]
    platforms: dict[str, Any]
    files: dict[str, str]
    paths: dict[str, Any]
