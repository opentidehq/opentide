"""Generate actors vocabulary from ATT&CK STIX groups and MISP galaxy."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import urlopen

import toml

from opentide.core.files import resolve_paths
from opentide.vocabulary.io import read_vocab_document, write_vocab_file
from opentide.vocabulary.stix_attack import load_stix_bundle, parse_groups


def _vocab_dir() -> Path:
    return Path(resolve_paths()["vocabularies"])


def _stix_dir() -> Path:
    return Path(resolve_paths()["resources"]) / "attack" / "stix"


def _default_misp_url() -> str | None:
    config_dir = Path(resolve_paths()["configurations"])
    resources = toml.loads((config_dir / "resources.toml").read_text(encoding="utf-8"))
    return resources.get("misp", {}).get("galaxies", {}).get("threat_actors")


def _load_misp_galaxy(url: str) -> list[dict[str, Any]]:
    with urlopen(url, timeout=120) as response:
        galaxy = json.loads(response.read().decode("utf-8"))
    actors: list[dict[str, Any]] = []
    for actor in galaxy.get("values", []):
        entry: dict[str, Any] = {
            "id": actor["uuid"],
            "name": actor["value"],
            "description": actor.get("description") or "",
            "tide.vocab.stages": "misp",
        }
        synonyms = actor.get("meta", {}).get("synonyms")
        if synonyms:
            entry["alias"] = synonyms
        actors.append(entry)
    return actors


def generate_actors_vocabs(*, misp_url: str | None = None) -> int:
    """Regenerate actors.vocab.toml from STIX groups and MISP."""
    stix_dir = _stix_dir()
    doc = read_vocab_document(_vocab_dir() / "actors.vocab.toml")
    doc["key"] = "id"
    doc.pop("model", None)

    actors: list[dict[str, Any]] = []
    for path, prefix in [
        (stix_dir / "enterprise-attack.json", "Enterprise"),
        (stix_dir / "ics-attack.json", "ICS"),
        (stix_dir / "mobile-attack.json", "Mobile"),
    ]:
        if path.is_file():
            groups = parse_groups(load_stix_bundle(path), prefix=prefix)
            for group in groups:
                group["tide.vocab.stages"] = "att&ck"
            actors.extend(groups)

    url = misp_url or _default_misp_url()
    if url:
        actors.extend(_load_misp_galaxy(url))

    doc["keys"] = actors
    manifest_path = stix_dir / "manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        doc["source_version"] = manifest.get("version", "unknown")
        doc["source_fetched_at"] = manifest.get("fetched_at", "")
    doc["source"] = "mitre-attack+misp"
    doc["generated_at"] = datetime.now(timezone.utc).isoformat()

    write_vocab_file(_vocab_dir() / "actors.vocab.toml", doc)
    return len(actors)
