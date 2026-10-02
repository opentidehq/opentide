"""Build the MISP Event document for one Tide object.

The result is plain JSON. PyMISP transports it; it does not reshape it.
Galaxy cluster tags are supplied by the caller after a lookup. Preview passes
none.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from opentide.package.paths import bundled_data_root
from opentide.sharing.constants import (
    CANONICAL_UUID_PATTERN,
    OPENTIDE_META_CATEGORY,
    OPENTIDE_TEMPLATE_NAME,
    OPENTIDE_TEMPLATE_UUID,
    OPENTIDE_TEMPLATE_VERSION,
    TLP_ORDER,
)
from opentide.sharing.document import TideDocument

_UUID = re.compile(CANONICAL_UUID_PATTERN)
_INFO_LIMIT = 255

_CRITICALITY = {
    "Emergency": 1,
    "Severe": 1,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Baseline - Minor": 3,
    "Baseline - Negligible": 3,
}
_SEVERITY = {
    "National cyber emergency": 1,
    "Highly significant incident": 1,
    "Significant incident": 1,
    "Substantial incident": 2,
    "Moderate incident": 2,
    "Localised incident": 3,
}
_ALERT_SEVERITY = {
    "Critical": 1,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 3,
}

_VOCAB: dict[str, dict[str, str]] = {}


@dataclass(frozen=True)
class BuiltEvent:
    """A payload, or the field error that blocked it."""

    event: dict[str, Any] | None
    reason: str | None = None
    relations: tuple[str, ...] = ()
    cluster_sources: tuple[str, ...] = ()


def tlp_allows(object_tlp: str, max_tlp: str) -> bool:
    """True when *object_tlp* is at or below the block ceiling."""
    try:
        return TLP_ORDER.index(object_tlp) <= TLP_ORDER.index(max_tlp)
    except ValueError:
        return False


def distribution_for(tlp: str) -> int:
    """MISP distribution derived from TLP. Sharing groups are always off."""
    if tlp in {"clear", "green"}:
        return 1
    return 0


def build_event(document: TideDocument, cluster_tags: Sequence[str] = ()) -> BuiltEvent:
    """Return the Event envelope for *document*.

    ``cluster_tags`` are already formatted ``misp-galaxy:`` strings, ordered
    within each galaxy. They are appended after the TLP and PAP tags.
    """
    family = document.family
    if document.parse_error is not None or family is None:
        return BuiltEvent(None, "invalid_document")
    name = document.name
    if name is None or name.strip() == "":
        return BuiltEvent(None, "name")
    created = _created(document.metadata.get("created"))
    if created is None:
        return BuiltEvent(None, "metadata.created")
    uuid = document.uuid
    if uuid is None:
        return BuiltEvent(None, "metadata.uuid")
    schema = document.schema_id
    assert schema is not None
    version = _version(document.metadata.get("version"))
    if version is None:
        return BuiltEvent(None, "metadata.version")
    tlp = document.metadata.get("tlp")
    if not isinstance(tlp, str) or tlp not in _vocab_misp("tlp.vocab.toml"):
        return BuiltEvent(None, "unmapped_tlp")
    pap_tag, pap_error = _pap_tag(document.metadata)
    if pap_error is not None:
        return BuiltEvent(None, pap_error)
    relations, relation_error = _relations(document, family)
    if relation_error is not None:
        return BuiltEvent(None, relation_error)

    tags = [{"name": _vocab_misp("tlp.vocab.toml")[tlp]}]
    if pap_tag is not None:
        tags.append({"name": pap_tag})
    for tag in cluster_tags:
        if not any(existing["name"] == tag for existing in tags):
            tags.append({"name": tag})

    attributes = [
        _attribute("name", name, correlate=True),
        _attribute("uuid", uuid, correlate=True),
        _attribute("version", version, correlate=False),
        _attribute("opentide-type", family, correlate=False),
        _attribute("schema", schema, correlate=False),
        _attribute("opentide-object", document.document, correlate=True),
    ]
    attributes.extend(
        _attribute("opentide-relation", relation, correlate=True) for relation in relations
    )
    event = {
        "info": name[:_INFO_LIMIT],
        "date": created,
        "distribution": distribution_for(tlp),
        "sharing_group_id": 0,
        "threat_level_id": _threat_level(family, document.body),
        "analysis": 2,
        "published": False,
        "Attribute": [],
        "Tag": tags,
        "Object": [
            {
                "name": OPENTIDE_TEMPLATE_NAME,
                "meta-category": OPENTIDE_META_CATEGORY,
                "template_uuid": OPENTIDE_TEMPLATE_UUID,
                "template_version": OPENTIDE_TEMPLATE_VERSION,
                "distribution": 5,
                "Attribute": attributes,
            }
        ],
    }
    return BuiltEvent(
        {"Event": event},
        relations=relations,
        cluster_sources=_cluster_sources(document, family),
    )


def _attribute(relation: str, value: str, *, correlate: bool) -> dict[str, Any]:
    return {
        "object_relation": relation,
        "type": "text",
        "category": "Other",
        "to_ids": False,
        "distribution": 5,
        "disable_correlation": not correlate,
        "value": value,
    }


def _created(value: object) -> str | None:
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if not isinstance(value, str):
        return None
    text = value.strip()
    if len(text) < 10:
        return None
    try:
        return date.fromisoformat(text[:10]).isoformat()
    except ValueError:
        return None


def _version(value: object) -> str | None:
    if isinstance(value, (bool, float)):
        return None
    if isinstance(value, int):
        if value < 0:
            return None
        return str(value)
    if isinstance(value, str) and value.isdigit():
        return str(int(value))
    return None


def _pap_tag(metadata: Mapping[str, Any]) -> tuple[str | None, str | None]:
    if "pap" not in metadata or metadata.get("pap") is None:
        return None, None
    pap = metadata.get("pap")
    if not isinstance(pap, str):
        return None, "unmapped_pap"
    tag = _vocab_misp("pap.vocab.toml").get(pap)
    if tag is None:
        return None, "unmapped_pap"
    return tag, None


def _relations(document: TideDocument, family: str) -> tuple[tuple[str, ...], str | None]:
    if family == "threat":
        return (), None
    if family == "rule":
        raw = document.body.get("detection_model")
        if raw is None or raw == "":
            return (), None
        if not isinstance(raw, str) or _UUID.fullmatch(raw) is None:
            return (), "relation_uuid"
        return (raw,), None
    objective = document.body.get("objective")
    threats: object = []
    if isinstance(objective, Mapping):
        threats = objective.get("threats") or []
    if not isinstance(threats, list):
        return (), "relation_uuid"
    found: list[str] = []
    for item in threats:
        if item is None or item == "":
            continue
        if not isinstance(item, str) or _UUID.fullmatch(item) is None:
            return (), "relation_uuid"
        if item not in found:
            found.append(item)
    found.sort()
    return tuple(found), None


def _cluster_sources(document: TideDocument, family: str) -> tuple[str, ...]:
    """Technique and actor identifiers that need a galaxy lookup."""
    sources: list[str] = []
    for technique in _techniques(document, family):
        sources.append(f"technique:{technique}")
    if family == "threat":
        threat = document.body.get("threat")
        actors = threat.get("actors") if isinstance(threat, Mapping) else None
        if isinstance(actors, list):
            for actor in actors:
                name = actor.get("name") if isinstance(actor, Mapping) else None
                if isinstance(name, str) and name:
                    sources.append(f"actor:{name}")
    return tuple(sources)


def _techniques(document: TideDocument, family: str) -> tuple[str, ...]:
    if family == "rule":
        raw = document.body.get("techniques")
    elif family == "objective":
        objective = document.body.get("objective")
        raw = objective.get("attack") if isinstance(objective, Mapping) else None
    else:
        threat = document.body.get("threat")
        raw = threat.get("att&ck") if isinstance(threat, Mapping) else None
    if not isinstance(raw, list):
        return ()
    found: list[str] = []
    for item in raw:
        if isinstance(item, str) and item.strip() and item.strip() not in found:
            found.append(item.strip())
    return tuple(found)


def _threat_level(family: str, body: Mapping[str, Any]) -> int:
    if family == "objective":
        return 4
    if family == "threat":
        return _match_level(body.get("criticality"), (_CRITICALITY,))
    return _match_level(body.get("severity"), (_SEVERITY, _ALERT_SEVERITY))


def _match_level(value: object, tables: tuple[Mapping[str, int], ...]) -> int:
    if not isinstance(value, str):
        return 4
    for table in tables:
        if value in table:
            return table[value]
    folded = value.casefold()
    for table in tables:
        for name, level in table.items():
            if name.casefold() == folded:
                return level
    return 4


def _vocab_misp(filename: str) -> dict[str, str]:
    cached = _VOCAB.get(filename)
    if cached is not None:
        return cached
    path = bundled_data_root() / "vocabulary" / filename
    loaded = tomllib.loads(path.read_text(encoding="utf-8"))
    mapping: dict[str, str] = {}
    keys = loaded.get("keys")
    if isinstance(keys, list):
        for entry in keys:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            tag = entry.get("misp")
            if isinstance(name, str) and isinstance(tag, str):
                mapping[name] = tag
    _VOCAB[filename] = mapping
    return mapping
