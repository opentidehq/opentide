"""Catalog search and analysis helpers for the MCP server."""

from __future__ import annotations

import re
from typing import Any

from opentide.core.registry import OpenTide

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def ensure_initialised() -> None:
    OpenTide.initialise()


def object_summary(uuid: str, object_type: str, body: dict[str, Any]) -> dict[str, Any]:
    title = body.get("title") or body.get("name") or uuid
    return {
        "uuid": uuid,
        "type": object_type,
        "title": title,
        "status": body.get("status"),
    }


def get_object(uuid: str) -> dict[str, Any] | None:
    ensure_initialised()
    if uuid in OpenTide.Models.rules:
        return {"type": "rule", "uuid": uuid, "body": OpenTide.Models.rules[uuid]}
    if uuid in OpenTide.Models.threats:
        return {"type": "threat", "uuid": uuid, "body": OpenTide.Models.threats[uuid]}
    if uuid in OpenTide.Models.objectives:
        return {"type": "objective", "uuid": uuid, "body": OpenTide.Models.objectives[uuid]}
    return None


def search_catalog(
    query: str,
    *,
    object_type: str = "",
    platform: str = "",
    status: str = "",
    technique: str = "",
    actor: str = "",
) -> list[dict[str, Any]] | dict[str, Any]:
    """Search catalogue by UUID, keyword, or ATT&CK technique."""
    ensure_initialised()

    if _UUID_RE.match(query.strip()):
        found = get_object(query.strip())
        return found if found is not None else []

    query_lower = query.lower()
    results: list[dict[str, Any]] = []

    for bucket_type, bucket in [
        ("rule", OpenTide.Models.rules),
        ("threat", OpenTide.Models.threats),
        ("objective", OpenTide.Models.objectives),
    ]:
        if object_type and object_type != bucket_type:
            continue
        for uuid, body in bucket.items():
            if not isinstance(body, dict):
                body = body.model_dump(by_alias=True) if hasattr(body, "model_dump") else {}
            if status and body.get("status") != status:
                continue
            if technique:
                tags = body.get("tags", {})
                techniques = tags.get("techniques", []) if isinstance(tags, dict) else []
                if technique not in techniques and technique not in body.get("techniques", []):
                    continue
            if actor:
                tags = body.get("tags", {})
                actors = tags.get("actors", []) if isinstance(tags, dict) else []
                if actor.lower() not in {str(a).lower() for a in actors}:
                    continue
            if platform and platform not in str(body.get("configurations", {})).lower():
                continue
            haystack = (
                f"{uuid} {body.get('title', '')} {body.get('name', '')} {body.get('description', '')}"
            ).lower()
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
    for uuid, body in OpenTide.Models.rules.items():
        if not isinstance(body, dict):
            body = body.model_dump(by_alias=True) if hasattr(body, "model_dump") else {}
        tags = body.get("tags", {})
        techniques = (
            tags.get("techniques", []) if isinstance(tags, dict) else body.get("techniques", [])
        )
        for tech in techniques or []:
            covered.setdefault(str(tech), []).append(uuid)

    if technique:
        return {
            "technique": technique,
            "covered": technique in covered,
            "rules": covered.get(technique, []),
        }
    return {"technique_count": len(covered), "matrix": covered, "tactic_filter": tactic or None}
