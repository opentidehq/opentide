"""Generate actors vocabulary from ATT&CK STIX groups and MISP galaxy."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any
from urllib.request import urlopen

from opentide.core.files import resolve_paths
from opentide.core.io import load_json, load_toml, parse_json
from opentide.core.time import utc_now_iso
from opentide.vocabulary.generate_attack import STIX_DIR_ENV, GenerateReport
from opentide.vocabulary.io import read_vocab_document, write_vocab_file
from opentide.vocabulary.lifecycle import merge_vocab_keys
from opentide.vocabulary.stix_attack import load_stix_bundle, parse_groups


def _vocab_dir() -> Path:
    return Path(resolve_paths()["vocabularies"])


def _resolve_vocab_dir(vocab_dir: Path | None) -> Path:
    return vocab_dir if vocab_dir is not None else _vocab_dir()


def _stix_dir() -> Path:
    override = os.environ.get(STIX_DIR_ENV)
    if override:
        return Path(override).expanduser().resolve()
    return Path(resolve_paths()["resources"]) / "attack" / "stix"


def _default_misp_url() -> str | None:
    config_dir = Path(resolve_paths()["configurations"])
    resources = load_toml(config_dir / "resources.toml")
    return resources.get("misp", {}).get("galaxies", {}).get("threat_actors")


def _load_misp_galaxy(url: str) -> tuple[list[dict[str, Any]], dict[str, str]]:
    with urlopen(url, timeout=120) as response:
        raw = response.read()
    galaxy = parse_json(raw)
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
    provenance = {
        "source_misp_url": url,
        "source_misp_sha256": hashlib.sha256(raw).hexdigest(),
    }
    return actors, provenance


def generate_actors_vocabs(
    *,
    misp_url: str | None = None,
    vocab_dir: Path | None = None,
    write: bool = True,
) -> GenerateReport:
    """Regenerate actors.vocab.toml from STIX groups and MISP with per-key lifecycle."""
    stix_dir = _stix_dir()
    output_dir = _resolve_vocab_dir(vocab_dir)
    doc = read_vocab_document(output_dir / "actors.vocab.toml")
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

    misp_provenance: dict[str, str] = {}
    url = misp_url or _default_misp_url()
    if url:
        misp_actors, misp_provenance = _load_misp_galaxy(url)
        actors.extend(misp_actors)

    previous_misp = doc.get("source_misp_sha256")
    previous_attack = doc.get("source_version")
    existing = list(doc.get("keys") or [])
    lifecycle = merge_vocab_keys(existing, actors, key_field="id")
    doc["keys"] = list(lifecycle.keys)
    doc.pop("version", None)
    manifest_path = stix_dir / "manifest.json"
    attack_version = "unknown"
    if manifest_path.is_file():
        manifest = load_json(manifest_path)
        attack_version = str(manifest.get("version", "unknown"))
        doc["source_version"] = attack_version
        doc["source_fetched_at"] = manifest.get("fetched_at", "")
    else:
        doc["source_fetched_at"] = utc_now_iso()
    doc["source"] = "mitre-attack+misp"
    doc["generated_at"] = utc_now_iso()
    doc.update(misp_provenance)

    if write:
        write_vocab_file(output_dir / "actors.vocab.toml", doc)
    source_changed = str(previous_attack or "") != str(doc.get("source_version", "unknown"))
    new_misp = misp_provenance.get("source_misp_sha256")
    if new_misp and str(previous_misp or "") != new_misp:
        source_changed = True
    return GenerateReport(lifecycles={"actors": lifecycle}, source_changed=source_changed)
