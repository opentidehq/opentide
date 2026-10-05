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


def _string_ids(value: object) -> list[str]:
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, list):
        return [item.strip() for item in value if isinstance(item, str) and item.strip()]
    return []


def _catalogue_family(uuid: str) -> str | None:
    if uuid in OpenTide.Models.threats:
        return "threats"
    if uuid in OpenTide.Models.objectives:
        return "objectives"
    if uuid in OpenTide.Models.rules:
        return "rules"
    return None


def _lineage_block(members: list[str], families: dict[str, str]) -> dict[str, list[str]]:
    return {
        "threats": sorted(uuid for uuid in members if families[uuid] == "threats"),
        "objectives": sorted(uuid for uuid in members if families[uuid] == "objectives"),
        "rules": sorted(uuid for uuid in members if families[uuid] == "rules"),
    }


def _lineage_by_uuid(relations: dict[str, Any]) -> dict[str, dict[str, list[str]]]:
    """Connected sets reached through objective.threats, detection_model, and threat.chaining.

    ``OpenTide.Models.chaining`` stays the threat-to-threat relation map. This
    index is only for MCP responses.
    """
    parent: dict[str, str] = {}
    families: dict[str, str] = {}

    def find(node: str) -> str:
        parent.setdefault(node, node)
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def unite(left: str, left_family: str, right: str, right_family: str) -> None:
        families[left] = _catalogue_family(left) or left_family
        families[right] = _catalogue_family(right) or right_family
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    for uuid, entry in OpenTide.Models.objectives.items():
        nested = as_body(entry).get("objective")
        threats = _string_ids(nested.get("threats")) if isinstance(nested, dict) else []
        for threat in threats:
            unite(str(uuid), "objectives", threat, "threats")

    for uuid, entry in OpenTide.Models.rules.items():
        for parent_id in _string_ids(as_body(entry).get("detection_model")):
            unite(str(uuid), "rules", parent_id, "objectives")

    for uuid, relation in relations.items():
        if not isinstance(relation, dict):
            continue
        for vectors in relation.values():
            for vector in _string_ids(vectors):
                unite(str(uuid), "threats", vector, "threats")

    groups: dict[str, list[str]] = {}
    for node in families:
        groups.setdefault(find(node), []).append(node)

    lineage: dict[str, dict[str, list[str]]] = {}
    for members in groups.values():
        block = _lineage_block(members, families)
        if not any(block.values()):
            continue
        for uuid in members:
            lineage[uuid] = block
    return lineage


def _mcp_chaining_index(
    relations: dict[str, Any],
    lineages: dict[str, dict[str, list[str]]],
) -> dict[str, Any]:
    index: dict[str, Any] = {}
    for uuid, relation in relations.items():
        if isinstance(relation, dict) and relation:
            index[str(uuid)] = relation
    for uuid, lineage in lineages.items():
        index.setdefault(uuid, lineage)
    return index


def get_chaining_graph(uuid: str) -> dict[str, Any]:
    ensure_initialised()
    node = get_object(uuid)
    if node is None:
        return {"uuid": uuid, "found": False, "graph": {}}
    relations = OpenTide.Models.chaining
    lineages = _lineage_by_uuid(relations if isinstance(relations, dict) else {})
    node_uuid = node["uuid"]
    relation = relations.get(node_uuid, {}) if isinstance(relations, dict) else {}
    if not isinstance(relation, dict):
        relation = {}
    lineage = lineages.get(node_uuid)
    graph: dict[str, Any] = relation if relation else (lineage or {})
    payload: dict[str, Any] = {
        "uuid": node_uuid,
        "found": True,
        "type": node["type"],
        "graph": graph,
        "chaining_index": _mcp_chaining_index(
            relations if isinstance(relations, dict) else {},
            lineages,
        ),
    }
    if lineage:
        payload["lineage"] = lineage
    return payload


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
