"""Catalog search and analysis helpers for the MCP server."""

from __future__ import annotations

import re
from typing import Any

from opentide.core.object_fields import (
    as_body,
    matches_actor,
    matches_platform,
    matches_technique,
    object_techniques,
    technique_covers,
)
from opentide.core.registry import OpenTide

_UUID_RE = re.compile(
    "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE
)


def ensure_initialised() -> None:
    OpenTide.initialise()


def object_summary(uuid: str, object_type: str, body: dict[str, Any]) -> dict[str, Any]:
    title = body.get("title") or body.get("name") or uuid
    return {"uuid": uuid, "type": object_type, "title": title, "status": body.get("status")}


def get_object(uuid: str) -> dict[str, Any] | None:
    """Look an object up by UUID; UUIDs compare case-insensitively (RFC 9562)."""
    ensure_initialised()
    needle = uuid.strip()
    folded = needle.lower()
    for object_type, bucket in (
        ("rule", OpenTide.Models.rules),
        ("threat", OpenTide.Models.threats),
        ("objective", OpenTide.Models.objectives),
    ):
        if needle in bucket:
            return {"type": object_type, "uuid": needle, "body": bucket[needle]}
        key = next((key for key in bucket if key.lower() == folded), None)
        if key is not None:
            return {"type": object_type, "uuid": key, "body": bucket[key]}
    return None


def search_catalog(
    query: str,
    *,
    object_type: str = "",
    platform: str = "",
    status: str = "",
    technique: str = "",
    actor: str = "",
) -> list[dict[str, Any]]:
    """Search catalogue by UUID, keyword, or ATT&CK technique.

    Always returns a list of summary dicts; a UUID query yields at most one hit.
    Filters apply to a UUID query as to a keyword one.
    """
    ensure_initialised()

    def wanted(bucket_type: str, body: dict[str, Any]) -> bool:
        return (
            (not object_type or object_type == bucket_type)
            and (not status or body.get("status") == status)
            and matches_technique(body, technique)
            and matches_actor(body, actor)
            and matches_platform(body, platform)
        )

    if _UUID_RE.match(query.strip()):
        found = get_object(query)
        if found is None:
            return []
        body = as_body(found["body"])
        if not wanted(found["type"], body):
            return []
        return [object_summary(found["uuid"], found["type"], body)]
    query_lower = query.lower()
    results: list[dict[str, Any]] = []
    for bucket_type, bucket in [
        ("rule", OpenTide.Models.rules),
        ("threat", OpenTide.Models.threats),
        ("objective", OpenTide.Models.objectives),
    ]:
        if object_type and object_type != bucket_type:
            continue
        for uuid, entry in bucket.items():
            body = as_body(entry)
            if not wanted(bucket_type, body):
                continue
            haystack = f"{uuid} {body.get('title', '')} {body.get('name', '')} {body.get('description', '')}".lower()
            if query_lower in haystack:
                results.append(object_summary(uuid, bucket_type, body))
    return results


def get_chaining_graph(uuid: str) -> dict[str, Any]:
    ensure_initialised()
    chains = OpenTide.Models.chaining
    node = get_object(uuid)
    if node is None:
        return {"uuid": uuid, "found": False, "graph": {}}
    return {
        "uuid": uuid,
        "found": True,
        "type": node["type"],
        "graph": chains.get(uuid, {}),
        "chaining_index": chains,
    }


def coverage_analysis(*, technique: str = "", tactic: str = "") -> dict[str, Any]:
    ensure_initialised()
    covered: dict[str, list[str]] = {}
    for uuid, entry in OpenTide.Models.rules.items():
        for tech in sorted(object_techniques(entry)):
            covered.setdefault(tech, []).append(uuid)
    if technique:
        needle = technique.strip()
        matched = sorted(key for key in covered if technique_covers(needle, key))
        rules = sorted({uuid for key in matched for uuid in covered[key]})
        return {
            "technique": needle,
            "covered": bool(rules),
            "matched_techniques": matched,
            "rules": rules,
        }
    return {"technique_count": len(covered), "matrix": covered, "tactic_filter": tactic or None}
