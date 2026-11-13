"""Catalog search and analysis helpers for the MCP server."""

from __future__ import annotations

import re
from typing import Any

from opentide.core.object_fields import (
    as_body,
    matches_actor,
    matches_platform,
    matches_technique,
)
from opentide.core.registry import Opentide

_UUID_RE = re.compile(
    "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE
)


def ensure_initialised() -> None:
    Opentide.initialise()


def block_statuses(body: dict[str, Any]) -> list[str]:
    """The ``status`` of each platform block of a rule body: what deploy and promotion read.

    A rule-level ``status`` is read by no command and drifts at the first
    promotion, so it is never a rule's status here.
    """
    configurations = body.get("configurations")
    if not isinstance(configurations, dict):
        return []
    return sorted(
        {
            block["status"]
            for block in configurations.values()
            if isinstance(block, dict) and isinstance(block.get("status"), str) and block["status"]
        }
    )


def object_summary(uuid: str, object_type: str, body: dict[str, Any]) -> dict[str, Any]:
    title = body.get("name") or uuid
    statuses = block_statuses(body) if object_type == "rule" else []
    return {
        "uuid": uuid,
        "type": object_type,
        "title": title,
        "status": ", ".join(statuses) or None,
    }


def get_object(uuid: str) -> dict[str, Any] | None:
    """Look an object up by UUID; UUIDs compare case-insensitively (RFC 9562)."""
    ensure_initialised()
    needle = uuid.strip()
    folded = needle.lower()
    for object_type, bucket in (
        ("rule", Opentide.Models.rules),
        ("threat", Opentide.Models.threats),
        ("objective", Opentide.Models.objectives),
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
            and (not status or status in block_statuses(body))
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
        ("rule", Opentide.Models.rules),
        ("threat", Opentide.Models.threats),
        ("objective", Opentide.Models.objectives),
    ]:
        if object_type and object_type != bucket_type:
            continue
        for uuid, entry in bucket.items():
            body = as_body(entry)
            if not wanted(bucket_type, body):
                continue
            haystack = (f"{uuid} {body.get('name', '')} {body.get('description', '')}").lower()
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
    if uuid in Opentide.Models.threats:
        return "threats"
    if uuid in Opentide.Models.objectives:
        return "objectives"
    if uuid in Opentide.Models.rules:
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

    ``Opentide.Models.chaining`` stays the threat-to-threat relation map. This
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

    for uuid, entry in Opentide.Models.objectives.items():
        nested = as_body(entry).get("objective")
        threats = _string_ids(nested.get("threats")) if isinstance(nested, dict) else []
        for threat in threats:
            unite(str(uuid), "objectives", threat, "threats")

    for uuid, entry in Opentide.Models.rules.items():
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
    relations = Opentide.Models.chaining
    lineages = _lineage_by_uuid(relations if isinstance(relations, dict) else {})
    node_uuid = node["uuid"]
    relation = relations.get(node_uuid, {}) if isinstance(relations, dict) else {}
    if not isinstance(relation, dict):
        relation = {}
    lineage = lineages.get(node_uuid)
    graph: dict[str, Any] = relation or (lineage or {})
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
    """Which rules cover a technique, or the whole matrix, counting inherited techniques.

    A rule covers what it lists and what it inherits from its objective
    (through a signal's objective) or that objective's threats, as
    ``opentide info catalog`` resolves them. ``own_rules`` and
    ``inherited_rules`` keep the two apart; ``rules`` holds both.
    """
    from opentide.core.technique_coverage import match_technique, rule_technique_index

    ensure_initialised()
    index = rule_technique_index(Opentide.Models)
    if technique:
        found = match_technique(technique, index)
        return {
            "technique": found.technique,
            "covered": bool(found.rules),
            "matched_techniques": list(found.matched),
            "rules": sorted(found.rules),
            "own_rules": sorted(found.own),
            "inherited_rules": sorted(found.inherited),
        }
    covered: dict[str, list[str]] = {}
    own: dict[str, list[str]] = {}
    for uuid, techniques in index.items():
        for tech in sorted(set(techniques.all)):
            covered.setdefault(tech, []).append(uuid)
            if tech in techniques.own:
                own.setdefault(tech, []).append(uuid)
    return {
        "technique_count": len(covered),
        "matrix": covered,
        "own_matrix": own,
        "tactic_filter": tactic or None,
    }


# --------------------------------------------------------------------------- graph

#: Chaining relations that order two threats in time, as (earlier, later) when the
#: relation is read from the threat that declares it: chaining_relations vocabulary.
SEQUENCE_RELATIONS = {"preceeds": "from", "succeeds": "to"}

#: How many uuids the summary lists per gap before it only counts them.
SUMMARY_LIST_LIMIT = 25


def _chaining_links(body: dict[str, Any]) -> list[dict[str, str]]:
    """A threat's ``threat.chaining`` entries as ``{to, relation}``."""
    section = body.get("threat")
    entries = section.get("chaining") if isinstance(section, dict) else None
    links: list[dict[str, str]] = []
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        vector, relation = entry.get("vector"), entry.get("relation")
        if isinstance(vector, str) and vector.strip() and isinstance(relation, str):
            links.append({"to": vector.strip(), "relation": relation.strip()})
    return links


def _section(body: dict[str, Any], key: str) -> dict[str, Any]:
    """``body[key]`` when it is a mapping, else ``{}``: an optional block may load as ``None``."""
    value = body.get(key)
    return value if isinstance(value, dict) else {}


def _threat_actors(section: dict[str, Any]) -> list[str]:
    """``threat.actors`` as written (``att&ck::G0006``); object_actors folds case for matching."""
    entries = section.get("actors")
    names: list[str] = []
    for entry in entries if isinstance(entries, list) else []:
        name = entry.get("name") if isinstance(entry, dict) else entry
        if isinstance(name, str) and name.strip() and name.strip() not in names:
            names.append(name.strip())
    return names


def _actor_labels(actors: set[str]) -> dict[str, str]:
    """Display names for actor ids, from the ``actors`` vocabulary (``G0006`` -> its name)."""
    vocabulary = Opentide.Vocabularies.Index.get("actors")
    entries = getattr(vocabulary, "entries", None)
    if not isinstance(entries, dict):
        return {}
    labels: dict[str, str] = {}
    for actor in actors:
        key = actor.split("::", 1)[-1]
        entry = entries.get(key) or entries.get(key.upper())
        name = getattr(entry, "name", None) if entry is not None else None
        if name is None and isinstance(entry, dict):
            name = entry.get("name")
        if isinstance(name, str) and name:
            labels[actor] = name
    return labels


def _rule_objective(body: dict[str, Any], signals: dict[str, Any]) -> tuple[str | None, str | None]:
    """The objective a rule's ``detection_model`` names, directly or through a signal."""
    target = body.get("detection_model")
    if not isinstance(target, str) or not target.strip():
        return None, None
    target = target.strip()
    signal = signals.get(target)
    if isinstance(signal, dict) and isinstance(signal.get("owner"), str):
        return signal["owner"], target
    return target, None


def _platform_statuses(body: dict[str, Any]) -> dict[str, str | None]:
    configurations = body.get("configurations")
    if not isinstance(configurations, dict):
        return {}
    return {
        str(name): (block.get("status") if isinstance(block.get("status"), str) else None)
        for name, block in configurations.items()
        if isinstance(block, dict)
    }


def _configured_statuses() -> list[dict[str, str]]:
    """``[[statuses]]`` of deployment.toml in lifecycle order, as ``{name, strategy}``.

    Read without validating the file, as ``validate`` reads the names: a typo in
    deployment.toml is the configuration check's finding, not a failure here.
    """
    try:
        entries = Opentide.Configurations.Deployment.Index.get("statuses")
    except (KeyError, AttributeError):
        return []
    statuses: list[dict[str, str]] = []
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict) and isinstance(entry.get("name"), str) and entry["name"]:
            strategy = entry.get("strategy")
            statuses.append({"name": entry["name"], "strategy": str(strategy or "")})
    return statuses


def _release_statuses(statuses: list[dict[str, str]]) -> set[str]:
    """The statuses deploy releases from the default branch: what "in production" means."""
    release = {status["name"] for status in statuses if status["strategy"] == "RELEASE"}
    return release or {"PRODUCTION"}


def catalogue_graph(*, detail: str = "summary") -> dict[str, Any]:
    """The catalogue as a graph: threats, objectives, rules and how they connect.

    ``detail="full"`` returns every node with the fields the graph view draws;
    ``"summary"`` (the default) returns counts and the gaps, small enough for a
    model's context however large the catalogue.
    """
    from opentide.core.technique_coverage import own_techniques, rule_technique_index

    ensure_initialised()
    signals_raw = getattr(Opentide.Models, "signals", None) or {}
    signals = {str(key): as_body(value) for key, value in signals_raw.items()}
    techniques = rule_technique_index()

    threats: list[dict[str, Any]] = []
    for uuid, entry in Opentide.Models.threats.items():
        body = as_body(entry)
        section = _section(body, "threat")
        threats.append(
            {
                "uuid": str(uuid),
                "title": body.get("name") or str(uuid),
                "criticality": body.get("criticality"),
                "severity": section.get("severity"),
                "viability": section.get("viability"),
                "actors": _threat_actors(section),
                "techniques": sorted(set(own_techniques(body))),
                "chaining": _chaining_links(body),
            }
        )

    objectives: list[dict[str, Any]] = []
    for uuid, entry in Opentide.Models.objectives.items():
        body = as_body(entry)
        section = _section(body, "objective")
        signals_list = section.get("signals")
        objectives.append(
            {
                "uuid": str(uuid),
                "title": body.get("name") or str(uuid),
                "priority": section.get("priority"),
                "threats": _string_ids(section.get("threats")),
                "signals": len(signals_list) if isinstance(signals_list, list) else 0,
            }
        )

    rules: list[dict[str, Any]] = []
    for uuid, entry in Opentide.Models.rules.items():
        body = as_body(entry)
        objective, signal = _rule_objective(body, signals)
        resolved = techniques.get(str(uuid))
        rules.append(
            {
                "uuid": str(uuid),
                "title": body.get("name") or str(uuid),
                "severity": body.get("severity"),
                "objective": objective,
                "signal": signal,
                "techniques": sorted(set(resolved.all)) if resolved else [],
                "platforms": _platform_statuses(body),
            }
        )

    statuses = _configured_statuses()
    if detail == "full":
        actors = {actor for threat in threats for actor in threat["actors"]}
        return {
            "threats": threats,
            "objectives": objectives,
            "rules": rules,
            "actor_names": _actor_labels(actors),
            "statuses": statuses,
        }
    return _graph_summary(threats, objectives, rules, _release_statuses(statuses))


def _graph_summary(
    threats: list[dict[str, Any]],
    objectives: list[dict[str, Any]],
    rules: list[dict[str, Any]],
    release: set[str],
) -> dict[str, Any]:
    rules_by_objective: dict[str, list[dict[str, Any]]] = {}
    for rule in rules:
        if rule["objective"]:
            rules_by_objective.setdefault(rule["objective"], []).append(rule)
    objectives_by_threat: dict[str, list[str]] = {}
    for objective in objectives:
        for threat in objective["threats"]:
            objectives_by_threat.setdefault(threat, []).append(objective["uuid"])

    threat_rules = {
        threat["uuid"]: [
            rule
            for objective in objectives_by_threat.get(threat["uuid"], [])
            for rule in rules_by_objective.get(objective, [])
        ]
        for threat in threats
    }

    by_status: dict[str, int] = {}
    by_platform: dict[str, dict[str, int]] = {}
    for rule in rules:
        for platform, status in rule["platforms"].items():
            key = status or "unset"
            by_status[key] = by_status.get(key, 0) + 1
            counts = by_platform.setdefault(platform, {})
            counts[key] = counts.get(key, 0) + 1

    def listed(items: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "count": len(items),
            "items": [
                {"uuid": item["uuid"], "title": item["title"]}
                for item in items[:SUMMARY_LIST_LIMIT]
            ],
        }

    no_objective = [t for t in threats if not objectives_by_threat.get(t["uuid"])]
    no_rule = [
        t for t in threats if objectives_by_threat.get(t["uuid"]) and not threat_rules[t["uuid"]]
    ]
    no_production = [
        t
        for t in threats
        if threat_rules[t["uuid"]]
        and not any(
            status in release
            for rule in threat_rules[t["uuid"]]
            for status in rule["platforms"].values()
        )
    ]
    idle_objectives = [o for o in objectives if not rules_by_objective.get(o["uuid"])]
    chained = {t["uuid"] for t in threats if t["chaining"]} | {
        link["to"] for t in threats for link in t["chaining"]
    }
    return {
        "counts": {
            "threats": len(threats),
            "objectives": len(objectives),
            "rules": len(rules),
            "chained_threats": len(chained),
            "actors": len({a for t in threats for a in t["actors"]}),
        },
        "rule_blocks_by_status": dict(sorted(by_status.items())),
        "rule_blocks_by_platform": {
            k: dict(sorted(v.items())) for k, v in sorted(by_platform.items())
        },
        "threats_without_objectives": listed(no_objective),
        "threats_without_rules": listed(no_rule),
        "threats_without_production_rules": listed(no_production),
        "objectives_without_rules": listed(idle_objectives),
    }
