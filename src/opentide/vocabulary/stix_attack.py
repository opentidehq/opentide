"""Parse MITRE ATT&CK STIX 2.1 bundles into vocabulary entry dicts."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

MITRE_SOURCE = "mitre-attack"


def _mitre_external_id(obj: Mapping[str, Any]) -> str | None:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == MITRE_SOURCE and ref.get("external_id"):
            return str(ref["external_id"])
    return None


def _mitre_url(obj: Mapping[str, Any]) -> str | None:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == MITRE_SOURCE and ref.get("url"):
            return str(ref["url"])
    return None


def load_stix_bundle(path: Path) -> list[dict[str, Any]]:
    """Load STIX objects from a JSON bundle file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("type") == "bundle":
        return list(data.get("objects") or [])
    if isinstance(data, dict) and "objects" in data:
        return list(data["objects"])
    if isinstance(data, list):
        return data
    raise ValueError(f"Unrecognised STIX bundle format: {path}")


def build_tactic_name_map(objects: list[Mapping[str, Any]]) -> dict[str, str]:
    """Map tactic shortnames to display names."""
    mapping: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        shortname = obj.get("x_mitre_shortname") or obj.get("x-mitre-shortname")
        name = obj.get("name")
        if shortname and name:
            mapping[str(shortname)] = str(name)
    return mapping


def _normalise_tactic_name(name: str) -> str:
    if name == "Evasion Ics":
        return "Defense Evasion"
    return name.replace("Ics", "").strip()


def _tactics_for_technique(obj: Mapping[str, Any], tactic_map: dict[str, str]) -> list[str]:
    stages: list[str] = []
    for phase in obj.get("kill_chain_phases") or []:
        phase_name = phase.get("phase_name", "")
        display = tactic_map.get(phase_name, phase_name.replace("-", " ").title())
        display = _normalise_tactic_name(display)
        if display and display not in stages:
            stages.append(display)
    return stages


def parse_techniques(
    objects: list[Mapping[str, Any]],
    *,
    prefix: str = "",
    tactic_map: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Extract technique entries from STIX attack-pattern objects."""
    if tactic_map is None:
        tactic_map = build_tactic_name_map(objects)
    name_prefix = f"{prefix} : " if prefix else ""
    entries: list[dict[str, Any]] = []

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        ext_id = _mitre_external_id(obj)
        if not ext_id or not ext_id.startswith("T"):
            continue
        entry: dict[str, Any] = {
            "id": ext_id,
            "name": name_prefix + str(obj.get("name", "")),
            "description": obj.get("description") or "",
        }
        url = _mitre_url(obj)
        if url:
            entry["link"] = url
        stages = _tactics_for_technique(obj, tactic_map)
        if stages:
            entry["tide.vocab.stages"] = stages
        entries.append(entry)

    return entries


def parse_groups(
    objects: list[Mapping[str, Any]],
    *,
    prefix: str = "",
) -> list[dict[str, Any]]:
    """Extract group entries from STIX intrusion-set objects."""
    name_prefix = f"[{prefix}] " if prefix else ""
    entries: list[dict[str, Any]] = []

    for obj in objects:
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("revoked"):
            continue
        ext_id = _mitre_external_id(obj)
        if not ext_id or not ext_id.startswith("G"):
            continue
        entry: dict[str, Any] = {
            "id": ext_id,
            "name": name_prefix + str(obj.get("name", "")),
            "description": obj.get("description") or "",
        }
        url = _mitre_url(obj)
        if url:
            entry["link"] = url
        aliases = obj.get("aliases") or []
        if aliases:
            entry["alias"] = list(aliases)
        entries.append(entry)

    return entries


def parse_mitigations(
    objects: list[Mapping[str, Any]],
    *,
    prefix: str = "",
) -> list[dict[str, Any]]:
    """Extract mitigation entries from STIX course-of-action objects."""
    name_prefix = f"{prefix} : " if prefix else ""
    entries: list[dict[str, Any]] = []

    for obj in objects:
        if obj.get("type") != "course-of-action":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        ext_id = _mitre_external_id(obj)
        if not ext_id or not ext_id.startswith("M"):
            continue
        entry: dict[str, Any] = {
            "id": ext_id,
            "name": name_prefix + str(obj.get("name", "")),
            "description": obj.get("description") or "",
        }
        url = _mitre_url(obj)
        if url:
            entry["link"] = url
        entries.append(entry)

    return entries


def parse_datasources(objects: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Extract data source and component entries from STIX objects."""
    sources: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if obj.get("type") != "x-mitre-data-source":
            continue
        ext_id = _mitre_external_id(obj)
        if not ext_id:
            continue
        sources[str(obj["id"])] = {
            "id": ext_id,
            "name": str(obj.get("name", "")),
            "description": obj.get("description") or "",
            "link": _mitre_url(obj) or "",
        }

    entries: list[dict[str, Any]] = []
    for obj in objects:
        obj_type = obj.get("type")
        if obj_type == "x-mitre-data-source":
            ext_id = _mitre_external_id(obj)
            if not ext_id:
                continue
            entry = {
                "id": ext_id,
                "name": str(obj.get("name", "")),
                "description": obj.get("description") or "",
            }
            url = _mitre_url(obj)
            if url:
                entry["link"] = url
            entries.append(entry)
        elif obj_type == "x-mitre-data-component":
            parent_ref = obj.get("x_mitre_data_source_ref") or obj.get("x-mitre-data-source-ref")
            parent = sources.get(str(parent_ref), {}) if parent_ref else {}
            component_name = str(obj.get("name", ""))
            parent_name = parent.get("name", "")
            full_name = f"{parent_name}: {component_name}" if parent_name else component_name
            entry = {
                "id": parent.get("id", ""),
                "name": component_name if parent_name else full_name,
                "description": obj.get("description") or "",
                "link": parent.get("link") or _mitre_url(obj) or "",
            }
            if parent_name and component_name != parent_name:
                entry["name"] = component_name
            entries.append({k: v for k, v in entry.items() if v})

    return entries


def merge_technique_bundles(
    bundles: list[tuple[Path, str]],
) -> list[dict[str, Any]]:
    """Merge techniques from multiple STIX bundles with optional name prefixes."""
    combined: list[dict[str, Any]] = []
    for path, prefix in bundles:
        objects = load_stix_bundle(path)
        tactic_map = build_tactic_name_map(objects)
        combined.extend(parse_techniques(objects, prefix=prefix, tactic_map=tactic_map))
    return combined
