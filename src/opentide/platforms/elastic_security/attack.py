"""MITRE ATT&CK threat mapping for Elastic Security Detection Engine."""

from __future__ import annotations

from typing import Any

from opentide.generation.framework import get_type, get_vocab_entry, techniques_resolver
from opentide.models.rule import DetectionRule

# Static mapping for the 14 MITRE Enterprise ATT&CK tactics
TACTIC_MAP: dict[str, dict[str, str]] = {
    "reconnaissance": {
        "id": "TA0043",
        "name": "Reconnaissance",
        "reference": "https://attack.mitre.org/tactics/TA0043/",
    },
    "resource development": {
        "id": "TA0042",
        "name": "Resource Development",
        "reference": "https://attack.mitre.org/tactics/TA0042/",
    },
    "initial access": {
        "id": "TA0001",
        "name": "Initial Access",
        "reference": "https://attack.mitre.org/tactics/TA0001/",
    },
    "execution": {
        "id": "TA0002",
        "name": "Execution",
        "reference": "https://attack.mitre.org/tactics/TA0002/",
    },
    "persistence": {
        "id": "TA0003",
        "name": "Persistence",
        "reference": "https://attack.mitre.org/tactics/TA0003/",
    },
    "privilege escalation": {
        "id": "TA0004",
        "name": "Privilege Escalation",
        "reference": "https://attack.mitre.org/tactics/TA0004/",
    },
    # Handle the misspelling present in some vocabulary headers
    "priviledge escalation": {
        "id": "TA0004",
        "name": "Privilege Escalation",
        "reference": "https://attack.mitre.org/tactics/TA0004/",
    },
    "defense evasion": {
        "id": "TA0005",
        "name": "Defense Evasion",
        "reference": "https://attack.mitre.org/tactics/TA0005/",
    },
    "credential access": {
        "id": "TA0006",
        "name": "Credential Access",
        "reference": "https://attack.mitre.org/tactics/TA0006/",
    },
    "discovery": {
        "id": "TA0007",
        "name": "Discovery",
        "reference": "https://attack.mitre.org/tactics/TA0007/",
    },
    "lateral movement": {
        "id": "TA0008",
        "name": "Lateral Movement",
        "reference": "https://attack.mitre.org/tactics/TA0008/",
    },
    "collection": {
        "id": "TA0009",
        "name": "Collection",
        "reference": "https://attack.mitre.org/tactics/TA0009/",
    },
    "command and control": {
        "id": "TA0011",
        "name": "Command and Control",
        "reference": "https://attack.mitre.org/tactics/TA0011/",
    },
    "exfiltration": {
        "id": "TA0010",
        "name": "Exfiltration",
        "reference": "https://attack.mitre.org/tactics/TA0010/",
    },
    "impact": {
        "id": "TA0040",
        "name": "Impact",
        "reference": "https://attack.mitre.org/tactics/TA0040/",
    },
}


def normalize_tactic(tactic_name: str) -> dict[str, str] | None:
    """Normalize tactic name and return tactic metadata (id, name, reference)."""
    key = tactic_name.strip().lower()
    return TACTIC_MAP.get(key)


def resolve_elastic_threat(data: DetectionRule) -> list[dict[str, Any]]:
    """Map rule techniques to Elastic Security threat array format."""
    cfg = getattr(data.configurations, "elastic_security", None) if data.configurations else None
    if cfg and cfg.threat:
        return list(cfg.threat)

    uuid = data.metadata.uuid if data.metadata else ""
    raw_techniques: list[str] = []
    if uuid and get_type(uuid, mute=True) is not None:
        try:
            raw_techniques = techniques_resolver(uuid)
        except Exception:
            if hasattr(data, "techniques") and data.techniques:
                raw_techniques = list(data.techniques)
    elif hasattr(data, "techniques") and data.techniques:
        raw_techniques = list(data.techniques)

    if not raw_techniques:
        return []

    # Deduplicate while preserving order
    unique_techniques = list(dict.fromkeys(raw_techniques))

    # Tactic ID -> list of technique dicts
    tactic_techniques: dict[str, dict[str, Any]] = {}
    # Track parent techniques per tactic: tactic_id -> {parent_id: technique_dict}
    tactic_parent_map: dict[str, dict[str, dict[str, Any]]] = {}

    for tech_id in unique_techniques:
        entry = get_vocab_entry("att&ck", tech_id)
        if not entry:
            continue

        raw_stages = get_vocab_entry("att&ck", tech_id, "tide.vocab.stages") or []
        if isinstance(raw_stages, str):
            raw_stages = [raw_stages]

        is_subtechnique = "." in tech_id
        parent_id = tech_id.split(".")[0] if is_subtechnique else tech_id
        parent_entry = (get_vocab_entry("att&ck", parent_id) if is_subtechnique else entry) or entry

        parent_name = (
            parent_entry.get("name", parent_id) if isinstance(parent_entry, dict) else parent_id
        )
        if ":" in parent_name:
            parent_name = parent_name.split(":", 1)[0].strip()
        parent_link = (
            parent_entry.get("link", f"https://attack.mitre.org/techniques/{parent_id}")
            if isinstance(parent_entry, dict)
            else f"https://attack.mitre.org/techniques/{parent_id}"
        )

        tech_name = entry.get("name", tech_id) if isinstance(entry, dict) else tech_id
        tech_link_fallback = f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}"
        tech_link = (
            entry.get("link", tech_link_fallback) if isinstance(entry, dict) else tech_link_fallback
        )

        subtechnique_name = tech_name
        if is_subtechnique and ": " in tech_name:
            subtechnique_name = tech_name.split(": ", 1)[1].strip()

        for stage in raw_stages:
            tactic_info = normalize_tactic(stage)
            if not tactic_info:
                continue

            tactic_id = tactic_info["id"]
            if tactic_id not in tactic_techniques:
                tactic_techniques[tactic_id] = {
                    "framework": "MITRE ATT&CK",
                    "tactic": dict(tactic_info),
                    "technique": [],
                }
                tactic_parent_map[tactic_id] = {}

            parents_in_tactic = tactic_parent_map[tactic_id]

            if is_subtechnique:
                if parent_id not in parents_in_tactic:
                    parent_obj: dict[str, Any] = {
                        "id": parent_id,
                        "name": parent_name,
                        "reference": parent_link,
                        "subtechnique": [],
                    }
                    parents_in_tactic[parent_id] = parent_obj
                    tactic_techniques[tactic_id]["technique"].append(parent_obj)

                # Add subtechnique if not already present
                parent_obj = parents_in_tactic[parent_id]
                existing_subs = {s["id"] for s in parent_obj["subtechnique"]}
                if tech_id not in existing_subs:
                    parent_obj["subtechnique"].append(
                        {
                            "id": tech_id,
                            "name": subtechnique_name,
                            "reference": tech_link,
                        }
                    )
            else:
                if parent_id not in parents_in_tactic:
                    parent_obj = {
                        "id": parent_id,
                        "name": parent_name,
                        "reference": parent_link,
                        "subtechnique": [],
                    }
                    parents_in_tactic[parent_id] = parent_obj
                    tactic_techniques[tactic_id]["technique"].append(parent_obj)

    return list(tactic_techniques.values())
