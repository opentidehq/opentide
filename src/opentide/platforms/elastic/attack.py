"""MITRE ATT&CK threat mapping for Elastic Security Detection Engine."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

import structlog

from opentide.generation.framework import get_type, get_vocab_entry, techniques_resolver
from opentide.models.rule import DetectionRule

logger = structlog.get_logger(__name__)

_cached_get_vocab_entry = lru_cache(maxsize=4096)(get_vocab_entry)

NON_ENTERPRISE_PREFIXES = ("Mobile : ", "Industrial : ")

TACTIC_ORDER = [
    ("Reconnaissance", "TA0043"),
    ("Resource Development", "TA0042"),
    ("Initial Access", "TA0001"),
    ("Execution", "TA0002"),
    ("Persistence", "TA0003"),
    ("Privilege Escalation", "TA0004"),
    ("Defense Evasion", "TA0005"),
    ("Credential Access", "TA0006"),
    ("Discovery", "TA0007"),
    ("Lateral Movement", "TA0008"),
    ("Collection", "TA0009"),
    ("Command and Control", "TA0011"),
    ("Exfiltration", "TA0010"),
    ("Impact", "TA0040"),
]

TACTIC_MAP: dict[str, tuple[str, str]] = {
    stage.lower(): (stage, tactic_id) for stage, tactic_id in TACTIC_ORDER
}
TACTIC_MAP["priviledge escalation"] = ("Privilege Escalation", "TA0004")


def resolve_elastic_threat(data: DetectionRule) -> list[dict[str, Any]]:
    """Map rule techniques to Elastic Security threat array format per RFC 0007."""
    raw_techniques: list[str] = []
    if hasattr(data, "techniques") and data.techniques:
        raw_techniques.extend(data.techniques)

    uuid = data.metadata.uuid if data.metadata else ""
    if getattr(data, "detection_model", None) and uuid and get_type(uuid, mute=True) is not None:
        try:
            inherited = techniques_resolver(uuid)
            if inherited:
                raw_techniques.extend(inherited)
        except Exception:
            pass

    if not raw_techniques:
        return []

    unique_techniques = list(dict.fromkeys(raw_techniques))

    # stage -> {parent_id: set_of_subtechniques}
    grouped: dict[str, dict[str, set[str]]] = {}

    for tech_id in unique_techniques:
        entry = _cached_get_vocab_entry("att&ck", tech_id)
        if not entry:
            continue

        name = entry.get("name", "")
        if name.startswith(NON_ENTERPRISE_PREFIXES):
            logger.warning("skipping_non_enterprise_technique", technique=tech_id, name=name)
            continue

        raw_stages = _cached_get_vocab_entry("att&ck", tech_id, "tide.vocab.stages") or []
        if isinstance(raw_stages, str):
            raw_stages = [raw_stages]

        parent_id = tech_id.split(".")[0]
        for stage in raw_stages:
            stage_key = stage.strip().lower()
            if stage_key not in TACTIC_MAP:
                continue
            canonical_stage, _ = TACTIC_MAP[stage_key]
            subs = grouped.setdefault(canonical_stage, {}).setdefault(parent_id, set())
            if "." in tech_id:
                subs.add(tech_id)

    threat: list[dict[str, Any]] = []

    for stage, tactic_id in TACTIC_ORDER:
        if stage not in grouped:
            continue

        techniques_out: list[dict[str, Any]] = []
        for parent_id in sorted(grouped[stage].keys()):
            parent_entry = _cached_get_vocab_entry("att&ck", parent_id)
            if not parent_entry:
                continue
            parent_name = parent_entry.get("name", parent_id)
            parent_link = parent_entry.get(
                "link", f"https://attack.mitre.org/techniques/{parent_id}"
            )

            tech_obj: dict[str, Any] = {
                "id": parent_id,
                "name": parent_name,
                "reference": parent_link,
            }

            subs = sorted(grouped[stage][parent_id])
            if subs:
                sub_list: list[dict[str, Any]] = []
                for sub_id in subs:
                    sub_entry = _cached_get_vocab_entry("att&ck", sub_id)
                    if not sub_entry:
                        continue
                    sub_name = sub_entry.get("name", sub_id)
                    prefix = f"{parent_name}: "
                    if sub_name.startswith(prefix):
                        sub_name = sub_name[len(prefix) :]
                    sub_link = sub_entry.get(
                        "link", f"https://attack.mitre.org/techniques/{sub_id.replace('.', '/')}"
                    )
                    sub_list.append(
                        {
                            "id": sub_id,
                            "name": sub_name,
                            "reference": sub_link,
                        }
                    )
                if sub_list:
                    tech_obj["subtechnique"] = sub_list

            techniques_out.append(tech_obj)

        if techniques_out:
            threat.append(
                {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": tactic_id,
                        "name": stage,
                        "reference": f"https://attack.mitre.org/tactics/{tactic_id}/",
                    },
                    "technique": techniques_out,
                }
            )

    return threat
